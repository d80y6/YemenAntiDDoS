// xsight-controller — DDoS detection controller.
//
// Usage:
//
//	xsight-controller -config config.yaml
//	xsight-controller -config config.yaml -migrate  # run migrations only
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof/* on default mux
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/config"
	"github.com/d80y6/YemenDDoS/controller/internal/configpub"
	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/baseline"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/classifier"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/threshold"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/d80y6/YemenDDoS/controller/internal/ingestion"
	"github.com/d80y6/YemenDDoS/controller/internal/l7store"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/netutil"
	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/retention"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/postgres"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/d80y6/YemenDDoS/controller/internal/watchdog"
	"github.com/d80y6/YemenDDoS/shared/decoder"
	"github.com/d80y6/YemenDDoS/shared/tlsconf"
)

var (
	configPath  = flag.String("config", "config.yaml", "path to config file")
	migrateOnly = flag.Bool("migrate", false, "run migrations and exit")
)

const withdrawingReconcileInterval = 2 * time.Minute
const announcingReconcileInterval = 2 * time.Minute

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	log.Printf("config loaded: grpc=%s http=%s db=%s",
		cfg.Listen.GRPC, cfg.Listen.HTTP, cfg.Database.Driver)
	reportRingEstimate(cfg)

	// Dump the decoder registry snapshot the binary was compiled against
	// (v1.3.4). A deployment regression (controller built before shared/
	// was updated) shows up here as a stale MaxDecoders or truncated
	// known-decoder list, making the cause visible without digging through
	// NULL extra_decoder_pps rows. See codex v1.3.x audit Gap 2.
	log.Printf("decoder registry: MaxDecoders=%d StandardCount=%d known=%s",
		decoder.MaxDecoders, decoder.StandardCount, knownDecoderList())

	// pprof server on localhost only (not exposed externally)
	go func() {
		log.Println("pprof listening on 127.0.0.1:6060")
		if err := http.ListenAndServe("127.0.0.1:6060", nil); err != nil {
			log.Printf("pprof server: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect database
	var db *postgres.PGStore
	switch cfg.Database.Driver {
	case "postgres":
		db, err = postgres.New(ctx, cfg.Database.DSN)
		if err != nil {
			log.Fatalf("database: %v", err)
		}
		defer db.Close()
		log.Println("PostgreSQL connected")
	case "sqlite":
		log.Fatal("SQLite driver not yet implemented")
	}

	// Run migrations (retention policies from config)
	if err := db.AutoMigrate(ctx, postgres.RetentionConfig{
		TSStatsDays:          cfg.Retention.TSStatsDays,
		TSStatsCompressDays:  cfg.Retention.TSStatsCompressDays,
		TSStatsCaggDays:      cfg.Retention.TSStatsCaggDays,
		TSStatsChunkDays:     cfg.Retention.TSStatsChunkDays,
		FlowLogsDays:         cfg.Retention.FlowLogsDays,
		FlowLogsCompressDays: cfg.Retention.FlowLogsCompressDays,
		FlowLogsChunkDays:    cfg.Retention.FlowLogsChunkDays,
	}); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Println("database migrations complete")

	if *migrateOnly {
		log.Println("migrate-only mode, exiting")
		return
	}

	if err := api.EnsureInitialAdmin(ctx, db.Users(), cfg.Auth.InitialAdminPassword); err != nil {
		log.Fatalf("initial admin: %v", err)
	}

	// --- Phase 2: Ring Buffer + DB writer ---

	ringLimits := ring.Limits{
		MaxPointsPerIP:  cfg.Ring.MaxPointsPerIP,
		MaxIPsPerPrefix: cfg.Ring.MaxIPsPerPrefix,
		MaxGlobalKeys:   cfg.Ring.MaxGlobalKeys,
	}
	log.Printf("ring: limits points_per_ip=%d ips_per_prefix=%d global_keys=%d",
		ringLimits.MaxPointsPerIP, ringLimits.MaxIPsPerPrefix, ringLimits.MaxGlobalKeys)
	rings := ring.New(ringLimits)
	statsWriter := ingestion.NewStatsWriter(rings)
	dbWriter := ingestion.NewDBWriter(rings, db.Stats(), 5*time.Second)
	go dbWriter.Run(ctx)

	// --- Phase 3: Detection engine ---

	// 3.1 Threshold inheritance tree
	threshTree := threshold.NewTree()
	if err := threshTree.Rebuild(ctx, db); err != nil {
		log.Fatalf("threshold tree: %v", err)
	}
	statsWriter.SetGlobalChecker(threshTree)

	// 3.2 Hard threshold detector
	detector := threshold.NewDetector(threshTree, rings)
	sustainWindow := threshold.SustainWindow(cfg.Detection.HardThresholdConfirmSeconds, cfg.Detection.DynamicThresholdConfirmSeconds, cfg.Ring.MaxPointsPerIP)
	detector.SetSustainWindow(sustainWindow)

	// 3.3 Dynamic baseline (beta)
	baselineCfg := baseline.DefaultConfig()
	baselineCalc := baseline.NewCalculator(db.Stats(), baselineCfg)

	// 3.3b Dynamic detection profile engine
	profileEngine := baseline.NewProfileEngine(rings, db.DynDetect(), db.Stats())
	if err := profileEngine.LoadFromDB(ctx); err != nil {
		log.Printf("profile engine load: %v", err)
	}

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				baselineCalc.Recompute()
				profileEngine.RefreshConfig(ctx)
			}
		}
	}()

	// Hourly profile updater
	go func() {
		// Wait until next hour boundary
		now := time.Now().UTC()
		nextHour := now.Truncate(time.Hour).Add(time.Hour)
		select {
		case <-ctx.Done():
			return
		case <-time.After(nextHour.Sub(now)):
		}
		profileEngine.UpdateHourly()
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				profileEngine.UpdateHourly()
			}
		}
	}()

	// 3.4 Attack classifier
	attackClassifier := classifier.New()

	// 3.5 Alert dedup
	alertDedup := dedup.New()

	// --- Phase 4: AttackTracker ---
	trackerCfg := tracker.Config{
		HardConfirmSeconds:      cfg.Detection.HardThresholdConfirmSeconds,
		DynamicConfirmSeconds:   cfg.Detection.DynamicThresholdConfirmSeconds,
		ExpiryIntervalSeconds:   cfg.Detection.ExpiryIntervalSeconds,
		ExpiryFunction:          cfg.Detection.ExpiryFunction,
		ExpiryScaleBaseSeconds:  cfg.Detection.ExpiryScaleBaseSeconds,
		ExpiryMaxScale:          cfg.Detection.ExpiryMaxScale,
		MaxActiveAttacks:        cfg.Detection.MaxActiveAttacks,
		ManualExpireHoldSeconds: cfg.Detection.ResolvedManualExpireHoldSeconds(),
		FastPathMultiplier:      cfg.Action.FastPathMultiplier,
	}
	// --- Phase 5: Action Engine ---
	// Wrap the concrete postgres store with a metrics-instrumented decorator
	// so every ActionExecLog().Create transparently increments
	// xsight_action_executions_total{action_type,status}. The wrapper is a
	// pass-through for every other repo, so subsequent code using `iStore`
	// behaves identically to `db` at the Store interface level.
	// Postgres-specific methods (AutoMigrate, Close) still use `db` directly.
	iStore := metrics.InstrumentStore(db)
	action.SetXDropShapeConfig(cfg.Action.XDropNarrowPct, cfg.Action.XDropMinSamplePackets)
	action.SetXDropAdaptiveSamples(cfg.Action.XDropAdaptiveSamples)
	action.SetXDropTopKConfig(cfg.Action.XDropTopKPct, cfg.Action.XDropTopKMax)
	actionEngine := action.NewEngine(iStore, cfg.Action.Mode)
	actionEngine.Start()

	attackTracker := tracker.New(trackerCfg, iStore, rings, alertDedup, actionEngine.EnqueueNonBlocking)
	attackTracker.SetRebreachCallback(actionEngine.EnqueueRebreach)

	// v4.0: inline scrubbing action plane. The pusher is bound to the gRPC
	// handler further down (once it exists); the mitigator itself is created
	// here so the tracker fast path can reach it from the CriticalEvent hook.
	var inlineMitigator *action.InlineMitigator

	// Restore FRR synchronously before reconciliation starts side-effect workers.
	var pre action.StartupScheduleSnapshot
	var preErr error
	recoverOnStartup(ctx,
		func(ctx context.Context) { action.RecoverBGPRoutes(ctx, iStore) },
		func(ctx context.Context) { pre, preErr = actionEngine.PrepareStartupCleanup(ctx) },
		actionEngine.ReconcileOnStartup,
		func(ctx context.Context) { actionEngine.CleanupEndedAttachments(ctx, pre, preErr) },
		attackTracker.RecoverFromDB,
		func(ctx context.Context) { action.BootstrapBGPOrphans(ctx, iStore) })
	go actionEngine.RunXDropReconcile(ctx, 2*time.Minute)
	go actionEngine.RunWithdrawingReconcile(ctx, withdrawingReconcileInterval)
	go actionEngine.RunAnnouncingReconcile(ctx, announcingReconcileInterval)

	// Prometheus metrics: register v1.2.1 custom collectors + counters with
	// the default registry (the /metrics HTTP route uses promhttp.Handler()
	// which reads from the default registry). Go runtime + process metrics
	// are auto-registered by the prometheus library.
	if err := metrics.Register(prometheus.DefaultRegisterer, iStore, attackTracker); err != nil {
		log.Fatalf("metrics register: %v", err)
	}

	// --- Phase 1: gRPC ingestion layer ---
	nodeState := ingestion.NewNodeState()

	// Detection tick loop (1s interval) → feed to AttackTracker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Hard threshold detection — per-node
				connectedNodes := nodeState.ConnectedNodes()
				exceeded := detector.Tick(connectedNodes)

				// Dynamic baseline detection: check prefix-level per-node
				exceeded = append(exceeded, dynamicBreaches(connectedNodes, threshTree.AllPrefixes(), rings, profileEngine, sustainWindow)...)

				// Filter through dedup
				var filtered []engine.ThresholdExceeded
				for _, evt := range exceeded {
					if !alertDedup.ShouldSuppress(evt) {
						filtered = append(filtered, evt)
					}
				}
				// Feed to AttackTracker state machine (MUST call every tick,
				// even when empty, so expiry timers advance)
				if cfg.Detection.DryRun {
					// Dry-run: log detections but don't create attacks
					for _, evt := range filtered {
						log.Printf("DRY-RUN: would trigger %s decoder=%s %s=%d (threshold=%d) prefix=%s",
							evt.DstIP, evt.Decoder, evt.Unit, evt.Actual, evt.Value, evt.Prefix)
					}
					filtered = nil // don't feed tracker
				}
				attackTracker.Feed(filtered)

				// Classifier: try to upgrade active attacks with sample data
				for _, dstIP := range attackTracker.ActiveDstIPs() {
					ip := net.ParseIP(dstIP)
					if ip == nil {
						continue
					}
					result := attackClassifier.Classify(ip)
					if result != nil {
						attackTracker.UpgradeType(ip, result.AttackType, result.Confidence, result.Reasons)
					}
				}
				attackClassifier.Sweep(time.Now())
			}
		}
	}()

	// Wire classifier to sample worker pool
	samplePool := ingestion.NewSampleWorkerPool(func(nodeID string, batch *pb.SampleBatch) {
		attackClassifier.Ingest(batch)
	})
	defer samplePool.Close()

	// Flow writer: top_flows → flow_logs table
	flowWriter := ingestion.NewFlowWriter(db.FlowLogs())

	// StatsStream → Ring Buffer + DB enqueue + detection + flow_logs
	onStats := func(nodeID string, report *pb.StatsReport) {
		statsWriter.HandleStats(nodeID, report)
		dbWriter.Enqueue(reportToStatPoints(nodeID, report))
		flowWriter.HandleFlows(nodeID, report)

		// Store flow metrics for API exposure
		// Proto field mapping for flow mode: dropped_user=unknown_exporter, dropped_kernel=template_misses
		if sm := report.GetSamplingMetrics(); sm != nil {
			nodeState.UpdateFlowMetrics(nodeID, sm.GetDecodeError(), sm.GetDroppedUser(), sm.GetDroppedKernel())
		}
		// Parse per-source and per-listener status from NodeHealth.Message (flow mode encodes JSON)
		if h := report.GetHealth(); h != nil && len(h.Message) > 1 && h.Message[0] == '{' {
			var parsed struct {
				Sources   []ingestion.SourceStatus   `json:"sources"`
				Listeners []ingestion.ListenerStatus `json:"listeners"`
			}
			if json.Unmarshal([]byte(h.Message), &parsed) == nil {
				nodeState.UpdateSourceStatuses(nodeID, parsed.Sources)
				nodeState.UpdateListenerStatuses(nodeID, parsed.Listeners)
			}
		}

		gs := report.GetGlobalStats()
		pc, ic, _ := rings.Stats()
		log.Printf("stats: node=%s ts=%d ips=%d prefixes=%d global={pkts=%d matched=%d} ring={prefixes=%d ips=%d}",
			nodeID, report.Timestamp, len(report.IpStats), len(report.PrefixStats),
			gs.GetTotalPkts(), gs.GetMatchedPkts(), pc, ic)
	}

	// Layer-7 aggregation: bounded in-memory view of HTTP flood, Slowloris and
	// TLS ClientHello events reported by Nodes over CriticalEventStream.
	l7Store := l7store.New(5000)

	onCritical := func(nodeID string, event *pb.CriticalEvent) {
		log.Printf("critical: node=%s type=%s dst=%v",
			nodeID, event.EventType, net.IP(event.DstIp))
		l7Store.Observe(nodeID, unixTime(event.Timestamp), event.EventType, net.IP(event.DstIp).String(), event.Counters)

		// v4.0 sub-second autonomous path: escalate to Active immediately and
		// push the broad inline rule set (<200ms) without waiting for the next
		// 1s StatsStream tick. Narrow-then-rebreadth refines it 750ms later.
		target := net.IP(event.GetTargetIp())
		if len(target) == 0 {
			target = net.IP(event.GetDstIp())
		}
		if len(target) == 0 || !isFastPathEvent(event) {
			return
		}
		decoder := event.GetDecoder()
		if decoder == "" {
			decoder = "ip"
		}
		sig := tracker.CriticalSignal{
			NodeID:     nodeID,
			TargetIP:   target,
			Decoder:    decoder,
			EventType:  event.GetEventType(),
			AttackType: event.GetAttackType(),
			CurrentPPS: event.GetCurrentPps(),
			CurrentBPS: event.GetCurrentBps(),
			At:         unixTime(event.GetTimestampNs()),
		}
		dbID, escalated := attackTracker.FastTrackConfirm(sig)
		if dbID == 0 {
			return
		}
		if inlineMitigator != nil {
			inlineMitigator.OnCritical(dbID, target.String(), decoder,
				event.GetEventType(), []string{nodeID},
				event.GetCurrentPps(), flowKeysFromProto(event.GetTopFlows()))
		}
		if escalated {
			log.Printf("critical: FAST-PATH escalated node=%s target=%s decoder=%s pps=%d db_id=%d",
				nodeID, target, decoder, event.GetCurrentPps(), dbID)
		}
	}

	handler := ingestion.NewGRPCHandler(ingestion.GRPCHandlerConfig{
		Store:      iStore,
		NodeState:  nodeState,
		SamplePool: samplePool,
		OnStats:    onStats,
		OnCritical: onCritical,
		OnControlOpen: func(nodeID string) {
			// Session recovery: a Node that (re)connects receives the
			// authoritative inline filter snapshot, reconciling any BPF map
			// state left over from before a Controller restart.
			if inlineMitigator != nil {
				if err := inlineMitigator.Reconcile(nodeID); err != nil {
					log.Printf("inline-mitigation: reconcile node=%s: %v", nodeID, err)
				}
			}
		},
	})

	// v4.0 inline action plane: pushes filter tables over ControlStream.
	inlineMitigator = action.NewInlineMitigator(inlineMitigatorConfig(cfg), handler)
	attackTracker.SetInlineMitigatorHook(func(attackID int) {
		inlineMitigator.Withdraw(attackID)
	})

	var grpcTLS *tls.Config
	if cfg.TLS.Enabled {
		tlsCfg, err := tlsconf.ServerConfig(tlsconf.FileConfig{
			CAFile:           cfg.TLS.CAFile,
			CertFile:         cfg.TLS.CertFile,
			KeyFile:          cfg.TLS.KeyFile,
			ServerName:       cfg.TLS.ServerName,
			AllowLegacyTLS12: cfg.TLS.AllowLegacyTLS12,
		})
		if err != nil {
			log.Fatalf("tls server config: %v", err)
		}
		grpcTLS = tlsCfg
		log.Println("tls: controller gRPC listener enabled (mTLS)")
	}
	grpcSrv := ingestion.NewServer(handler, grpcTLS)
	go func() {
		if err := grpcSrv.Serve(cfg.Listen.GRPC); err != nil {
			log.Fatalf("grpc server fatal: %v", err)
		}
	}()

	// --- Phase 6: Config Publisher ---
	configPub := configpub.New(iStore, handler, nodeState.ConnectedNodes)
	go configPub.RunDriftChecker(ctx)

	// --- Phase 7: REST API ---
	jwtSecret := cfg.Auth.APIKey + "-jwt" // derive JWT secret from API key
	tlsFileCfg := tlsconf.FileConfig{
		CAFile:           cfg.TLS.CAFile,
		CertFile:         cfg.TLS.CertFile,
		KeyFile:          cfg.TLS.KeyFile,
		ServerName:       cfg.TLS.ServerName,
		AllowLegacyTLS12: cfg.TLS.AllowLegacyTLS12,
	}
	tlsInfo := func() (tlsconf.CertInfo, string, bool) {
		if !cfg.TLS.Enabled {
			return tlsconf.CertInfo{}, "", false
		}
		info, err := tlsFileCfg.Describe()
		if err != nil {
			log.Printf("tls: describe server certificate: %v", err)
			return tlsconf.CertInfo{}, minTLSVersion(cfg.TLS.AllowLegacyTLS12), true
		}
		return info, minTLSVersion(cfg.TLS.AllowLegacyTLS12), true
	}
	router := api.NewRouter(api.Dependencies{
		Store:         iStore,
		ConfigPub:     configPub,
		NodeState:     nodeState,
		ThreshTree:    threshTree,
		Tracker:       attackTracker,
		ActionEngine:  actionEngine,
		BaselineCalc:  baselineCalc,
		ProfileEngine: profileEngine,
		APIKey:        cfg.Auth.APIKey,
		JWTSecret:     jwtSecret,
		FlowLogsDays:  cfg.Retention.FlowLogsDays,
		L7:            l7Store,
		Inline:        inlineMitigator,
		TLSInfo:       tlsInfo,
	})
	// Serve embedded Vue SPA (Phase 8)
	webFS, _ := fs.Sub(webDist, webRoot)
	api.ServeSPA(router, webFS)

	httpSrv := &http.Server{Addr: cfg.Listen.HTTP, Handler: router, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("http: listening on %s", cfg.Listen.HTTP)
		_ = serveHTTP(httpSrv)
	}()

	// Wait briefly for listeners to bind, then signal ready
	time.Sleep(500 * time.Millisecond)
	log.Printf("xsight-controller running (mode=%s)", cfg.Action.Mode)

	// Data retention cleaner
	if cfg.Retention.TSStatsDays > 0 || cfg.Retention.FlowLogsDays > 0 || cfg.Retention.AttacksDays > 0 || cfg.Retention.AuditLogDays > 0 {
		cleaner := retention.New(db.Pool(), retention.Config{
			TSStatsDays:        cfg.Retention.TSStatsDays,
			FlowLogsDays:       cfg.Retention.FlowLogsDays,
			AttacksDays:        cfg.Retention.AttacksDays,
			AuditLogDays:       cfg.Retention.AuditLogDays,
			IntervalHours:      cfg.Retention.IntervalHours,
			TSStatsHypertable:  db.IsHypertable("ts_stats"),
			FlowLogsHypertable: db.IsHypertable("flow_logs"),
		})
		go cleaner.Run(ctx)
		log.Printf("retention: ts_stats=%dd flow_logs=%dd attacks=%dd audit=%dd interval=%dh",
			cfg.Retention.TSStatsDays, cfg.Retention.FlowLogsDays, cfg.Retention.AttacksDays, cfg.Retention.AuditLogDays, cfg.Retention.IntervalHours)
	}

	// Systemd watchdog: signal ready + start heartbeat
	watchdog.Ready()
	watchdogDone := make(chan struct{})
	go watchdog.RunHeartbeat(watchdogDone)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	log.Printf("received %v, shutting down", sig)
	watchdog.Stopping()
	close(watchdogDone)
	cancel()
	shCtx, shCancel := context.WithTimeout(context.Background(), httpShutdownLimit)
	if err := httpSrv.Shutdown(shCtx); err != nil {
		log.Printf("WARN http: shutdown: %v", err)
	} else {
		log.Println("http: shutdown complete")
	}
	shCancel()
	grpcSrv.GracefulStop()
	const actionDrainLimit = 30 * time.Second
	actionEngine.Drain(actionDrainLimit)
}

const httpShutdownLimit = 5 * time.Second

var httpFatalf = log.Fatalf

func serveHTTP(srv *http.Server) error {
	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		httpFatalf("http server fatal: %v", err)
	}
	return err
}

func reportRingEstimate(cfg *config.Config) {
	estimate := config.RingEstimateBytes(cfg)
	metrics.RingEstimatedMemoryBytes.Set(float64(estimate))
	if estimate > 8192*1024*1024 {
		log.Printf("WARN ring: estimated memory %d bytes exceeds 8 GiB", estimate)
	}
}

func reportToStatPoints(nodeID string, report *pb.StatsReport) []store.StatPoint {
	ts := time.Unix(report.Timestamp, 0)
	// BPF counters are exact (every matched packet), only upstream sampling needs restoration.
	// local_sample_rate only affects ring buffer sampling, not ip_stats/prefix_stats counters.
	mul := uint64(1)
	if report.UpstreamSampleRate > 1 {
		mul = uint64(report.UpstreamSampleRate)
	}
	mul64 := int64(mul)

	var points []store.StatPoint

	// Inbound prefix stats (direction=receives)
	for _, ps := range report.PrefixStats {
		prefix, _, ok := netutil.CanonicalPrefix(ps.Prefix, ps.PrefixLen)
		if !ok {
			continue
		}
		sp := store.StatPoint{
			Time:      ts,
			NodeID:    nodeID,
			Prefix:    &prefix,
			Direction: "receives",
			PPS:       int64(ps.PktCount) * mul64,
			BPS:       int64(ps.ByteCount) * 8 * mul64,
		}
		counts := ps.GetDecoderCounts()
		if len(counts) > 0 {
			for j := 0; j < len(counts) && j < decoder.MaxDecoders; j++ {
				sp.DecoderPPS[j] = int32(int64(counts[j]) * mul64)
			}
		} else {
			sp.DecoderPPS[decoder.TCP] = int32(int64(ps.GetTcpCount()) * mul64)
			sp.DecoderPPS[decoder.TCPSyn] = int32(int64(ps.GetTcpSynCount()) * mul64)
			sp.DecoderPPS[decoder.UDP] = int32(int64(ps.GetUdpCount()) * mul64)
			sp.DecoderPPS[decoder.ICMP] = int32(int64(ps.GetIcmpCount()) * mul64)
			sp.DecoderPPS[decoder.Frag] = int32(int64(ps.GetFragCount()) * mul64)
		}
		byteCounts := ps.GetDecoderByteCounts()
		for j := 0; j < len(byteCounts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderBPS[j] = int64(byteCounts[j]) * 8 * mul64
		}
		points = append(points, sp)
	}
	// Inbound per-IP stats (direction=receives)
	for _, ip := range report.IpStats {
		dstIP, ok := netutil.CanonicalIP(ip.DstIp)
		if !ok {
			continue
		}
		sp := store.StatPoint{
			Time:      ts,
			NodeID:    nodeID,
			DstIP:     &dstIP,
			Direction: "receives",
			PPS:       int64(ip.PktCount) * mul64,
			BPS:       int64(ip.ByteCount) * 8 * mul64,
		}
		counts := ip.GetDecoderCounts()
		if len(counts) > 0 {
			for j := 0; j < len(counts) && j < decoder.MaxDecoders; j++ {
				sp.DecoderPPS[j] = int32(int64(counts[j]) * mul64)
			}
		} else {
			sp.DecoderPPS[0] = int32(int64(ip.GetTcpCount()) * mul64)
			sp.DecoderPPS[1] = int32(int64(ip.GetTcpSynCount()) * mul64)
			sp.DecoderPPS[2] = int32(int64(ip.GetUdpCount()) * mul64)
			sp.DecoderPPS[3] = int32(int64(ip.GetIcmpCount()) * mul64)
			sp.DecoderPPS[4] = int32(int64(ip.GetFragCount()) * mul64)
		}
		byteCounts := ip.GetDecoderByteCounts()
		for j := 0; j < len(byteCounts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderBPS[j] = int64(byteCounts[j]) * 8 * mul64
		}
		points = append(points, sp)
	}

	// Outbound prefix stats (direction=sends)
	for _, sps := range report.GetSrcPrefixStats() {
		prefix, _, ok := netutil.CanonicalPrefix(sps.Prefix, sps.PrefixLen)
		if !ok {
			continue
		}
		sp := store.StatPoint{
			Time:      ts,
			NodeID:    nodeID,
			Prefix:    &prefix,
			Direction: "sends",
			PPS:       int64(sps.PktCount) * mul64,
			BPS:       int64(sps.ByteCount) * 8 * mul64,
		}
		counts := sps.GetDecoderCounts()
		for j := 0; j < len(counts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderPPS[j] = int32(int64(counts[j]) * mul64)
		}
		byteCounts := sps.GetDecoderByteCounts()
		for j := 0; j < len(byteCounts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderBPS[j] = int64(byteCounts[j]) * 8 * mul64
		}
		points = append(points, sp)
	}

	// Outbound per-IP stats (direction=sends)
	for _, sip := range report.GetSrcIpStats() {
		srcIP, ok := netutil.CanonicalIP(sip.DstIp) // proto reuses dst_ip bytes for src_ip
		if !ok {
			continue
		}
		sp := store.StatPoint{
			Time:      ts,
			NodeID:    nodeID,
			DstIP:     &srcIP,
			Direction: "sends",
			PPS:       int64(sip.PktCount) * mul64,
			BPS:       int64(sip.ByteCount) * 8 * mul64,
		}
		counts := sip.GetDecoderCounts()
		for j := 0; j < len(counts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderPPS[j] = int32(int64(counts[j]) * mul64)
		}
		byteCounts := sip.GetDecoderByteCounts()
		for j := 0; j < len(byteCounts) && j < decoder.MaxDecoders; j++ {
			sp.DecoderBPS[j] = int64(byteCounts[j]) * 8 * mul64
		}
		points = append(points, sp)
	}

	return points
}

// knownDecoderList returns a "count:idx=name,…" string listing all
// non-empty decoder slots. Purely for the startup log in main() — when
// stale shared/decoder bindings are embedded in the controller binary
// (Gap 2 in the v1.3.3 test report), the log line prints a truncated list
// so the operator can spot the drift without waiting for NULL columns to
// appear in ts_stats rows.
func knownDecoderList() string {
	names := make([]string, 0, decoder.MaxDecoders)
	for i, n := range decoder.Names {
		if n != "" {
			names = append(names, fmt.Sprintf("%d=%s", i, n))
		}
	}
	return fmt.Sprintf("%d:[%s]", len(names), strings.Join(names, ","))
}

// recoverOnStartup is shared by main and the startup ordering behavior test.
func recoverOnStartup(ctx context.Context, routes, prepare, reconcile, cleanup func(context.Context), attacks func(context.Context) error, orphans func(context.Context)) {
	routes(ctx)
	prepare(ctx)
	reconcile(ctx)
	cleanup(ctx)
	if err := attacks(ctx); err != nil {
		log.Printf("tracker recovery: %v", err)
	}
	orphans(ctx)
}

func dynamicBreaches(nodes, prefixes []string, rings *ring.RingStore, pe *baseline.ProfileEngine, window int) []engine.ThresholdExceeded {
	if window < 1 {
		window = 1
	}
	var exceeded []engine.ThresholdExceeded
	for _, nodeID := range nodes {
		for _, prefix := range prefixes {
			if dp, ok := rings.LatestPrefix(nodeID, prefix, 5*time.Second); ok {
				if yes, reason := pe.IsExceeded(nodeID, prefix, dp.PPS, dp.BPS); yes {
					n := threshold.SustainedRun(rings.LatestNPrefix(nodeID, prefix, window), func(p ring.DataPoint) bool {
						y, _ := pe.IsExceeded(nodeID, prefix, p.PPS, p.BPS)
						return y
					})
					exceeded = append(exceeded, engine.ThresholdExceeded{
						Prefix:    prefix,
						Direction: "receives",
						Decoder:   "ip",
						Unit:      "pps",
						Value:     0,
						Actual:    dp.PPS,
						Domain:    "subnet",
						NodeID:    nodeID,
						Source:    "dynamic",
						Sustained: max(n, 1),
					})
					_ = reason
				}
			}
		}
	}
	return exceeded
}

// isFastPathEvent reports whether a CriticalEvent should bypass the 1s
// batching path and escalate an attack immediately.
func isFastPathEvent(event *pb.CriticalEvent) bool {
	switch event.GetEventType() {
	case "burst_emergency", "hard_threshold_exceeded", "syn_flood", "dns_amplification",
		"l7_flood", "http_flood", "tls_anomaly", "slowloris":
		return true
	}
	// Enriched events (v4.0 nodes) carry a decoder + rate even when the type
	// is deployment-specific.
	if event.GetDecoder() != "" && event.GetCurrentPps() > 0 {
		return true
	}
	return false
}

// flowKeysFromProto converts wire FlowSamples into mitigator flow keys.
func flowKeysFromProto(flows []*pb.FlowSample) []action.FlowKey {
	if len(flows) == 0 {
		return nil
	}
	out := make([]action.FlowKey, 0, len(flows))
	for _, f := range flows {
		out = append(out, action.FlowKey{
			SrcIP:    net.IP(f.GetSrcIp()).String(),
			DstIP:    net.IP(f.GetDstIp()).String(),
			SrcPort:  f.GetSrcPort(),
			DstPort:  f.GetDstPort(),
			Protocol: f.GetProtocol(),
			Packets:  f.GetPackets(),
		})
	}
	return out
}

// inlineMitigatorConfig maps controller config onto mitigator parameters,
// keeping the narrow-then-rebreadth timings inside the <500ms-1s target.
func inlineMitigatorConfig(cfg *config.Config) action.InlineMitigatorConfig {
	mic := action.DefaultInlineMitigatorConfig()
	mic.Enabled = cfg.Action.InlineEnabled
	if cfg.Action.InlineBroadRatePPS > 0 {
		mic.BroadRateLimitPPS = cfg.Action.InlineBroadRatePPS
	}
	if cfg.Action.InlineNarrowDelayMS > 0 {
		mic.NarrowDelay = time.Duration(cfg.Action.InlineNarrowDelayMS) * time.Millisecond
	}
	return mic
}

// unixTime converts a Node-reported unix timestamp (seconds, or nanoseconds
// when the Node sends them) to a time.Time. Mirrors the tolerance used by the
// ingestion path so a mis-scaled clock cannot push events outside the window.
func unixTime(ts int64) time.Time {
	if ts > 1e15 {
		return time.Unix(0, ts)
	}
	if ts > 1e12 {
		return time.UnixMilli(ts)
	}
	if ts <= 0 {
		return time.Now()
	}
	return time.Unix(ts, 0)
}

func minTLSVersion(allowLegacy bool) string {
	if allowLegacy {
		return "TLS 1.2"
	}
	return "TLS 1.3"
}
