// Package reporter manages gRPC connection to Controller with handshake,
// three reporting streams, and a bidirectional control channel.
package reporter

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"sync/atomic"

	"github.com/d80y6/YemenDDoS/node/internal/collector"
	"github.com/d80y6/YemenDDoS/node/internal/pb"
	"github.com/d80y6/YemenDDoS/node/internal/sampler"
)

// Config holds reporter configuration.
type Config struct {
	ControllerAddr string
	NodeID         string
	APIKey         string
	InterfaceName  string
	AgentVersion   string
	UpstreamRate   uint32
	Mode           string // "xdp" (default) | "flow" — v3.0

	// TLS is the optional mutual-TLS configuration. When nil the dial uses
	// insecure credentials (plaintext) for backward compatibility during
	// migration. When non-nil the Node dials over mTLS using the provided
	// config; the Controller must present a certificate verified by CAFile
	// and the Node must present its own identity certificate.
	TLS *tls.Config
}

// ApplyConfigFunc is called when the reporter receives a new watch config
// from the Controller (via handshake or ControlStream ConfigPush).
// The reporter passes the proto WatchConfig and delivery version;
// the caller is responsible for HotSwap + snapshot save.
type ApplyConfigFunc func(wc *pb.WatchConfig, deliveryVersion uint64) error

// Reporter manages gRPC streams to Controller.
type Reporter struct {
	cfg Config

	// Data sources (XDP mode uses reports, flow mode uses flowReports)
	reports     <-chan *collector.Report
	flowReports <-chan *pb.StatsReport // v3.0: direct protobuf input from FlowAggregator
	heartbeat   func() *pb.StatsReport
	batches     chan []sampler.PacketSample

	// Callback for applying config (HotSwap + snapshot)
	applyConfig     ApplyConfigFunc
	deliveryVersion uint64

	// Metrics source for SamplingMetrics (set via SetBatcher)
	batcher            *sampler.Batcher
	localRate          atomic.Uint32 // current sample rate, updated from StatsStream
	upstreamRate       atomic.Uint32 // follows the latest processed Stats report
	batchSendLatencyUs atomic.Int64  // last SampleStream.Send() latency in microseconds
	criticalDropped    atomic.Uint64 // CriticalEventStream queue overflows

	// critical carries L7 / threshold events to CriticalEventStream.
	critical chan *pb.CriticalEvent

	// State
	conn           *grpc.ClientConn
	client         pb.XSightServiceClient
	connected      bool
	lastDisconnect time.Time
	mu             sync.Mutex
}

// New creates a Reporter for XDP mode.
// applyConfig is called when Controller delivers a new watch config.
func New(cfg Config, reports <-chan *collector.Report, applyConfig ApplyConfigFunc) *Reporter {
	r := &Reporter{
		cfg:         cfg,
		reports:     reports,
		batches:     make(chan []sampler.PacketSample, 16),
		critical:    make(chan *pb.CriticalEvent, 64),
		applyConfig: applyConfig,
	}
	r.upstreamRate.Store(cfg.UpstreamRate)
	return r
}

// NewFlow creates a Reporter for flow mode.
// flowReports receives pre-built StatsReport protobufs from FlowAggregator.
func NewFlow(cfg Config, flowReports <-chan *pb.StatsReport, applyConfig ApplyConfigFunc) *Reporter {
	r := &Reporter{
		cfg:         cfg,
		flowReports: flowReports,
		batches:     make(chan []sampler.PacketSample, 16),
		critical:    make(chan *pb.CriticalEvent, 64),
		applyConfig: applyConfig,
	}
	r.upstreamRate.Store(cfg.UpstreamRate)
	return r
}

// SetDeliveryVersion sets the current delivery version from a loaded snapshot.
func (r *Reporter) SetDeliveryVersion(v uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deliveryVersion = v
}

// SetBatcher sets the batcher reference for SamplingMetrics.
// Must be called before Run().
func (r *Reporter) SetBatcher(b *sampler.Batcher) {
	r.batcher = b
}

// SetHeartbeat sets the constructor used after a second without a successful send.
// Must be called before Run().
func (r *Reporter) SetHeartbeat(fn func() *pb.StatsReport) {
	r.heartbeat = fn
}

// BatchSendLatencyMs returns the last SampleStream.Send() latency in milliseconds.
func (r *Reporter) BatchSendLatencyMs() float32 {
	return float32(r.batchSendLatencyUs.Load()) / 1000.0
}

// BatchHandler returns a function suitable for sampler.NewBatcher handler
// that forwards batches to the reporter's internal channel.
func (r *Reporter) BatchHandler() func([]sampler.PacketSample) {
	return func(batch []sampler.PacketSample) {
		select {
		case r.batches <- batch:
		default:
			// Drop if reporter can't keep up (brainstorm: samples are best-effort)
			if r.batcher != nil {
				r.batcher.Metrics.DroppedUser.Add(uint64(len(batch)))
			}
		}
	}
}

// SendCriticalEvent queues an L7 or threshold event for CriticalEventStream.
// It never blocks the capture path: when the queue is full the event is
// dropped and counted, matching the best-effort contract of SampleStream.
func (r *Reporter) SendCriticalEvent(ev *pb.CriticalEvent) {
	if ev == nil {
		return
	}
	select {
	case r.critical <- ev:
	default:
		r.criticalDropped.Add(1)
	}
}

// CriticalDropped reports how many critical events were dropped because the
// controller link could not keep up.
func (r *Reporter) CriticalDropped() uint64 { return r.criticalDropped.Load() }

// Run connects to Controller, performs handshake, and starts all streams.
// Blocks until ctx is cancelled. Handles reconnection with backoff.
func (r *Reporter) Run(ctx context.Context) {
	backoff := time.Second

	for {
		select {
		case <-ctx.Done():
			r.disconnect()
			return
		default:
		}

		start := time.Now()
		err := r.connectAndServe(ctx)
		elapsed := time.Since(start)
		backoff = nextBackoff(backoff, elapsed)
		if err != nil {
			log.Printf("reporter: %v (reconnecting in %v)", err, backoff)
		}

		r.disconnect()

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		// Exponential backoff capped at 30s
		backoff = backoff * 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func nextBackoff(cur, attempt time.Duration) time.Duration {
	if attempt >= 30*time.Second {
		return time.Second
	}
	return cur
}

// connectAndServe dials, handshakes, and runs all streams until error or ctx cancel.
func (r *Reporter) connectAndServe(ctx context.Context) error {
	log.Printf("reporter: connecting to %s", r.cfg.ControllerAddr)

	conn, err := grpc.NewClient(
		r.cfg.ControllerAddr,
		grpc.WithTransportCredentials(transportCredentials(r.cfg.TLS)),
	)
	if err != nil {
		return err
	}
	r.conn = conn
	r.client = pb.NewXSightServiceClient(conn)

	// Handshake
	resp, err := r.handshake(ctx)
	if err != nil {
		return err
	}
	if !resp.Accepted {
		log.Printf("reporter: handshake rejected: %s", resp.RejectReason)
		return errRejected
	}
	log.Printf("reporter: handshake accepted, delivery_version=%d, prefixes=%d",
		resp.DeliveryVersionCurrent,
		len(resp.GetWatchConfig().GetPrefixes()))

	// Apply watch_config from handshake (P6: reconciliation)
	initialAck := r.applyHandshakeConfig(resp)

	r.mu.Lock()
	r.connected = true
	r.mu.Unlock()

	// Calculate gap_seconds from last disconnect
	gapSeconds := uint32(0)
	if !r.lastDisconnect.IsZero() {
		gapSeconds = uint32(time.Since(r.lastDisconnect).Seconds())
	}

	// Start all streams in parallel; first error cancels all
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 4)
	var wg sync.WaitGroup

	// StatsStream
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- r.runStatsStream(streamCtx, gapSeconds)
	}()

	// SampleStream — skip in flow mode (no raw packet samples)
	if r.cfg.Mode != "flow" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- r.runSampleStream(streamCtx)
		}()
	}

	// CriticalEventStream — L7 and hard-threshold events
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- r.runCriticalStream(streamCtx)
	}()

	// ControlStream
	wg.Add(1)
	go func() {
		defer wg.Done()
		errCh <- r.runControlStream(streamCtx, initialAck)
	}()

	// Wait for first error
	select {
	case err := <-errCh:
		cancel()
		wg.Wait()
		r.mu.Lock()
		r.connected = false
		r.lastDisconnect = time.Now()
		r.mu.Unlock()
		return err
	case <-ctx.Done():
		cancel()
		wg.Wait()
		return ctx.Err()
	}
}

func (r *Reporter) applyHandshakeConfig(resp *pb.HandshakeResponse) *pb.ConfigAck {
	if wc := resp.GetWatchConfig(); wc != nil && r.applyConfig != nil {
		if err := r.applyConfig(wc, resp.DeliveryVersionCurrent); err != nil {
			log.Printf("reporter: apply handshake config: %v", err)
			return &pb.ConfigAck{DeliveryVersionApplied: resp.DeliveryVersionCurrent, Success: false, ErrorMessage: err.Error()}
		} else {
			r.mu.Lock()
			r.deliveryVersion = resp.DeliveryVersionCurrent
			r.mu.Unlock()
		}
	}
	r.mu.Lock()
	dv := r.deliveryVersion
	r.mu.Unlock()
	if dv > 0 {
		return &pb.ConfigAck{DeliveryVersionApplied: dv, Success: true}
	}
	return nil
}

func (r *Reporter) handshake(ctx context.Context) (*pb.HandshakeResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	r.mu.Lock()
	dv := r.deliveryVersion
	r.mu.Unlock()

	req := &pb.NodeHandshake{
		NodeId:                 r.cfg.NodeID,
		ApiKey:                 r.cfg.APIKey,
		Interfaces:             []string{r.cfg.InterfaceName},
		AgentVersion:           r.cfg.AgentVersion,
		DeliveryVersionApplied: dv,
		Mode:                   r.cfg.Mode,
	}

	resp, err := r.client.Handshake(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// sendWithTimeout wraps stream.SendMsg with a deadline to prevent blocking forever
// when the server is experiencing lock contention or network issues.
func sendWithTimeout(ctx context.Context, stream grpc.ClientStream, msg any) error {
	done := make(chan error, 1)
	go func() { done <- stream.SendMsg(msg) }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("stream send timeout (5s)")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Reporter) runStatsStream(ctx context.Context, initialGap uint32) error {
	stream, err := r.client.StatsStream(ctx)
	if err != nil {
		return err
	}

	gapSeconds := initialGap

	// Flow mode: receive pre-built StatsReport directly
	if r.flowReports != nil {
		idle := time.NewTimer(time.Second)
		defer idle.Stop()
		for {
			select {
			case <-ctx.Done():
				stream.CloseAndRecv()
				return nil
			case msg, ok := <-r.flowReports:
				if !ok {
					stream.CloseAndRecv()
					return nil
				}
				if err := sendFlow(ctx, stream, msg, &gapSeconds); err != nil {
					return err
				}
				idle.Reset(time.Second)
			case <-idle.C:
				closed, err := r.flowIdle(ctx, stream, &gapSeconds)
				if err != nil {
					return err
				}
				if closed {
					stream.CloseAndRecv()
					return nil
				}
				idle.Reset(time.Second)
			}
		}
	}

	// XDP mode: convert collector.Report to protobuf
	for {
		select {
		case <-ctx.Done():
			stream.CloseAndRecv()
			return nil
		case report, ok := <-r.reports:
			if !ok {
				stream.CloseAndRecv()
				return nil
			}
			r.localRate.Store(report.SampleRate)
			rate := report.UpstreamRate
			if rate == 0 {
				rate = r.cfg.UpstreamRate
			}
			r.upstreamRate.Store(rate)
			msg := reportToProto(report, r.cfg.NodeID, r.cfg.InterfaceName, rate, gapSeconds, r.batcher, r.BatchSendLatencyMs())
			if err := sendWithTimeout(ctx, stream, msg); err != nil {
				return err
			}
			gapSeconds = 0
		}
	}
}

func sendFlow(ctx context.Context, stream grpc.ClientStream, msg *pb.StatsReport, gap *uint32) error {
	msg.GapSeconds = *gap
	if err := sendWithTimeout(ctx, stream, msg); err != nil {
		return err
	}
	*gap = 0
	return nil
}

func (r *Reporter) flowIdle(ctx context.Context, stream grpc.ClientStream, gap *uint32) (closed bool, err error) {
	if ctx.Err() != nil {
		return true, nil
	}
	select {
	case msg, ok := <-r.flowReports:
		if !ok {
			return true, nil
		}
		return false, sendFlow(ctx, stream, msg, gap)
	default:
	}
	if r.heartbeat == nil {
		return false, nil
	}
	return false, sendFlow(ctx, stream, r.heartbeat(), gap)
}

func (r *Reporter) runSampleStream(ctx context.Context) error {
	stream, err := r.client.SampleStream(ctx)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			stream.CloseAndRecv()
			return nil
		case batch, ok := <-r.batches:
			if !ok {
				stream.CloseAndRecv()
				return nil
			}
			msg := batchToProto(batch, r.cfg.NodeID, r.cfg.InterfaceName, r.upstreamRate.Load(), r.localRate.Load())
			t0 := time.Now()
			if err := sendWithTimeout(ctx, stream, msg); err != nil {
				return err
			}
			r.batchSendLatencyUs.Store(time.Since(t0).Microseconds())
		}
	}
}

func (r *Reporter) runCriticalStream(ctx context.Context) error {
	stream, err := r.client.CriticalEventStream(ctx)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			_, _ = stream.CloseAndRecv()
			return nil
		case ev := <-r.critical:
			if err := sendWithTimeout(ctx, stream, ev); err != nil {
				return err
			}
		}
	}
}

func (r *Reporter) runControlStream(ctx context.Context, initial *pb.ConfigAck) error {
	stream, err := r.client.ControlStream(ctx)
	if err != nil {
		return err
	}

	// Report the handshake result before processing subsequent config pushes.
	if initial != nil {
		ack := &pb.ControlMessage{
			Payload: &pb.ControlMessage_ConfigAck{
				ConfigAck: initial,
			},
		}
		if err := sendWithTimeout(ctx, stream, ack); err != nil {
			return err
		}
		log.Printf("reporter: sent handshake config ACK version=%d success=%t", initial.DeliveryVersionApplied, initial.Success)
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch p := msg.Payload.(type) {
		case *pb.ControlMessage_ConfigPush:
			cp := p.ConfigPush
			log.Printf("reporter: received ConfigPush version=%d prefixes=%d",
				cp.DeliveryVersionCurrent,
				len(cp.GetWatchConfig().GetPrefixes()))

			// Apply config (HotSwap + snapshot)
			success := true
			errMsg := ""
			if r.applyConfig != nil {
				if err := r.applyConfig(cp.GetWatchConfig(), cp.DeliveryVersionCurrent); err != nil {
					success = false
					errMsg = err.Error()
					log.Printf("reporter: apply ConfigPush failed: %v", err)
				} else {
					r.mu.Lock()
					r.deliveryVersion = cp.DeliveryVersionCurrent
					r.mu.Unlock()
				}
			}

			ack := &pb.ControlMessage{
				Payload: &pb.ControlMessage_ConfigAck{
					ConfigAck: &pb.ConfigAck{
						DeliveryVersionApplied: cp.DeliveryVersionCurrent,
						Success:                success,
						ErrorMessage:           errMsg,
					},
				},
			}
			if err := sendWithTimeout(ctx, stream, ack); err != nil {
				return err
			}
		}
	}
}

func (r *Reporter) disconnect() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connected = false
	if r.conn != nil {
		r.conn.Close()
		r.conn = nil
	}
}

// Connected returns whether the reporter has an active gRPC connection.
func (r *Reporter) Connected() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connected
}

type rejectedError struct{}

func (rejectedError) Error() string { return "handshake rejected" }

var errRejected = rejectedError{}

// transportCredentials returns secure credentials when TLS is configured and
// insecure credentials otherwise, preserving backward compatibility for
// deployments that have not yet rolled out certificates.
func transportCredentials(tls *tls.Config) credentials.TransportCredentials {
	if tls != nil {
		return credentials.NewTLS(tls)
	}
	return insecure.NewCredentials()
}
