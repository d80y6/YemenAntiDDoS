package ingestion

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/shared/tlsconf"
)

// StatsCallback is invoked for each received StatsReport.
type StatsCallback func(nodeID string, report *pb.StatsReport)

// CriticalEventCallback is invoked for each CriticalEvent.
type CriticalEventCallback func(nodeID string, event *pb.CriticalEvent)

// GRPCHandler implements pb.XSightServiceServer.
type GRPCHandler struct {
	pb.UnimplementedXSightServiceServer

	store      store.Store
	nodeState  *NodeState
	samplePool *SampleWorkerPool
	onStats    StatsCallback
	onCritical CriticalEventCallback

	// Peer → nodeID mapping (set during Handshake, used by ControlStream)
	peerNodes   map[string]string // peer address → nodeID
	peerNodesMu sync.RWMutex
	handshaked  map[string]struct{} // Successful IDs retained for this process lifetime.

	// Metrics
	StatsReceived   atomic.Uint64
	StatsDropped    atomic.Uint64 // reports dropped due to processing queue full
	SamplesReceived atomic.Uint64
	EventsReceived  atomic.Uint64
}

type GRPCHandlerConfig struct {
	Store      store.Store
	NodeState  *NodeState
	SamplePool *SampleWorkerPool
	OnStats    StatsCallback
	OnCritical CriticalEventCallback
}

func NewGRPCHandler(cfg GRPCHandlerConfig) *GRPCHandler {
	return &GRPCHandler{
		store:      cfg.Store,
		nodeState:  cfg.NodeState,
		samplePool: cfg.SamplePool,
		onStats:    cfg.OnStats,
		onCritical: cfg.OnCritical,
		peerNodes:  make(map[string]string),
		handshaked: make(map[string]struct{}),
	}
}

// peerAddr extracts the remote address from the gRPC context.
func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return ""
}

// peerCertNodeID returns the node identity asserted by the verified client
// certificate, if the connection is mutually authenticated. In plaintext mode
// it reports ok=false, which keeps the historical peer-address mapping as the
// only available identity source.
func peerCertNodeID(ctx context.Context) (string, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", false
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", false
	}
	for _, cert := range info.State.PeerCertificates {
		if id, err := tlsconf.NodeIDFromCert(cert); err == nil && id != "" {
			return id, true
		}
	}
	return "", false
}

// peerCert returns the leaf client certificate of a mutually authenticated
// connection, or ok=false for plaintext/one-way TLS links.
func peerCert(ctx context.Context) (*x509.Certificate, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, false
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return nil, false
	}
	return info.State.PeerCertificates[0], true
}

// recordPeerTLS stores the client certificate for the node-management view.
func (h *GRPCHandler) recordPeerTLS(ctx context.Context, nodeID string) {
	cert, ok := peerCert(ctx)
	if !ok {
		return
	}
	desc := tlsconf.DescribeCert(cert)
	identity, _ := tlsconf.NodeIDFromCert(cert)
	info := PeerTLS{
		Verified:    identity != "" && identity == nodeID,
		Identity:    identity,
		Subject:     desc.Subject,
		Issuer:      desc.Issuer,
		Serial:      desc.SerialNumber,
		DNSNames:    desc.DNSNames,
		URIs:        desc.URIs,
		Fingerprint: desc.Fingerprint,
		IsCA:        desc.IsCA,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		SeenAt:      time.Now(),
	}
	h.nodeState.NotePeerTLS(nodeID, info)
}

// --- 1.2 Handshake ---

func (h *GRPCHandler) Handshake(ctx context.Context, req *pb.NodeHandshake) (*pb.HandshakeResponse, error) {
	log.Printf("grpc: handshake from node_id=%s interfaces=%v", req.NodeId, req.Interfaces)

	node, err := h.store.Nodes().Get(ctx, req.NodeId)
	if err != nil {
		log.Printf("grpc: handshake reject: node %q not found: %v", req.NodeId, err)
		return &pb.HandshakeResponse{Accepted: false, RejectReason: "node not found"}, nil
	}
	if node.APIKey != req.ApiKey {
		log.Printf("grpc: handshake reject: node %q bad api_key", req.NodeId)
		return &pb.HandshakeResponse{Accepted: false, RejectReason: "invalid api_key"}, nil
	}
	// When the link is mutually authenticated, the certificate identity is
	// authoritative. A node may only speak for the node_id baked into its URI
	// SAN, regardless of what the message claims.
	if certID, ok := peerCertNodeID(ctx); ok && certID != req.NodeId {
		metrics.GRPCIdentityRejects.WithLabelValues("handshake").Inc()
		log.Printf("grpc: handshake reject: certificate identity %q != node_id %q", certID, req.NodeId)
		return &pb.HandshakeResponse{Accepted: false, RejectReason: "certificate identity mismatch"}, nil
	}
	if !node.Enabled {
		return &pb.HandshakeResponse{Accepted: false, RejectReason: "node disabled"}, nil
	}

	// Register peer → nodeID mapping for ControlStream identification
	if addr := peerAddr(ctx); addr != "" {
		h.peerNodesMu.Lock()
		h.peerNodes[addr] = req.NodeId
		h.peerNodesMu.Unlock()
	}
	h.recordPeerTLS(ctx, req.NodeId)

	watchConfig, err := h.buildWatchConfig(ctx)
	if err != nil {
		log.Printf("grpc: handshake build watch config: %v", err)
		return &pb.HandshakeResponse{Accepted: false, RejectReason: fmt.Sprintf("internal error: %v", err)}, nil
	}
	// Update node mode from handshake (xdp nodes send "" or "xdp", flow nodes send "flow")
	mode := req.Mode
	if mode == "" {
		mode = "xdp"
	}
	if mode != "xdp" && mode != "flow" {
		return &pb.HandshakeResponse{Accepted: false, RejectReason: fmt.Sprintf("invalid mode: %q (must be xdp or flow)", mode)}, nil
	}
	_ = h.store.Nodes().UpdateMode(ctx, req.NodeId, mode)

	// Append per-node flow config (only for flow-mode nodes)
	if mode == "flow" {
		if err := h.appendFlowConfig(ctx, watchConfig, req.NodeId); err != nil {
			log.Printf("grpc: handshake flow config for %s failed: %v", req.NodeId, err)
			// Continue with handshake but without flow config — node will retry on next connect
		}
	}

	// If this node has never received a config publish (version=0),
	// catch it up to the current max version so it can ACK and become synced.
	version := node.DeliveryVersionCurrent
	if version == 0 {
		allNodes, _ := h.store.Nodes().List(ctx)
		var maxVer int64
		for _, n := range allNodes {
			if n.DeliveryVersionCurrent > maxVer {
				maxVer = n.DeliveryVersionCurrent
			}
		}
		if maxVer > 0 {
			version = maxVer
			_ = h.store.Nodes().UpdateDeliveryVersionCurrent(ctx, req.NodeId, version)
			log.Printf("grpc: handshake: caught up node %s to version=%d", req.NodeId, version)
		}
	}

	log.Printf("grpc: handshake accepted: node=%s prefixes=%d delivery_version=%d",
		req.NodeId, len(watchConfig.Prefixes), version)

	h.peerNodesMu.Lock()
	h.handshaked[req.NodeId] = struct{}{}
	h.peerNodesMu.Unlock()
	h.nodeState.NoteHandshake(req.NodeId, req.Interfaces)
	return &pb.HandshakeResponse{
		Accepted:               true,
		WatchConfig:            watchConfig,
		DeliveryVersionCurrent: uint64(version),
	}, nil
}

func (h *GRPCHandler) buildWatchConfig(ctx context.Context) (*pb.WatchConfig, error) {
	prefixes, err := h.store.Prefixes().List(ctx)
	if err != nil {
		return nil, err
	}

	var wp []*pb.WatchPrefix
	for _, p := range prefixes {
		if !p.Enabled {
			continue
		}
		// 0.0.0.0/0 is a virtual global prefix — do NOT push to BPF trie.
		if p.Prefix == "0.0.0.0/0" || p.Prefix == "::/0" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(p.Prefix)
		if err != nil {
			log.Printf("grpc: skip bad prefix %q: %v", p.Prefix, err)
			continue
		}
		ones, _ := ipnet.Mask.Size()
		wp = append(wp, &pb.WatchPrefix{
			Prefix:    ipnet.IP,
			PrefixLen: uint32(ones),
			Name:      p.Name,
		})
	}

	// Load aggregated hard thresholds from DB: lowest per-IP pps/bps
	allThresholds, err := h.store.Thresholds().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("load thresholds: %w", err)
	}
	var minPPS, minBPS int64
	for _, th := range allThresholds {
		if !th.Enabled || th.Comparison != "over" || th.Domain != "internal_ip" {
			continue
		}
		if th.Unit == "pps" && th.Value > 0 && (minPPS == 0 || th.Value < minPPS) {
			minPPS = th.Value
		}
		if th.Unit == "bps" && th.Value > 0 && (minBPS == 0 || th.Value < minBPS) {
			minBPS = th.Value
		}
	}
	if minPPS == 0 {
		minPPS = 1_000_000
	}
	if minBPS == 0 {
		minBPS = 10_000_000_000
	}

	return &pb.WatchConfig{
		Prefixes: wp,
		HardThresholds: &pb.HardThresholds{
			Pps: uint64(minPPS),
			Bps: uint64(minBPS),
		},
	}, nil
}

// appendFlowConfig adds per-node flow listener/source config to a WatchConfig.
// Returns error if DB read fails.
func (h *GRPCHandler) appendFlowConfig(ctx context.Context, wc *pb.WatchConfig, nodeID string) error {
	listeners, err := h.store.FlowListeners().List(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("load flow_listeners for %s: %w", nodeID, err)
	}
	for _, l := range listeners {
		if !l.Enabled {
			continue
		}
		flc := &pb.FlowListenerConfig{
			ListenAddress: l.ListenAddress,
			ProtocolMode:  l.ProtocolMode,
			Enabled:       l.Enabled,
		}
		sources, err := h.store.FlowSources().List(ctx, l.ID)
		if err != nil {
			return fmt.Errorf("load flow_sources for listener %d: %w", l.ID, err)
		}
		for _, s := range sources {
			if !s.Enabled {
				continue
			}
			flc.Sources = append(flc.Sources, &pb.FlowSourceConfig{
				DeviceIp:   s.DeviceIP,
				SampleMode: s.SampleMode,
				SampleRate: int32(s.SampleRate),
				Name:       s.Name,
				Enabled:    s.Enabled,
			})
		}
		wc.FlowListeners = append(wc.FlowListeners, flc)
	}
	return nil
}

// --- 1.3 StatsStream ---

func (h *GRPCHandler) requireHandshake(ctx context.Context, nodeID, stream string) error {
	// Certificate identity, when present, overrides the self-declared node_id.
	// This closes the Sybil hole where a peer that won one handshake could
	// report statistics for any node_id it typed into the message.
	if certID, ok := peerCertNodeID(ctx); ok && certID != nodeID {
		metrics.GRPCIdentityRejects.WithLabelValues(stream).Inc()
		log.Printf("WARN grpc: %s rejected node=%s: certificate identity %q mismatch", stream, nodeID, certID)
		return status.Error(codes.PermissionDenied, "certificate identity mismatch")
	}
	h.peerNodesMu.RLock()
	_, ok := h.handshaked[nodeID]
	h.peerNodesMu.RUnlock()
	if ok {
		return nil
	}
	metrics.GRPCIdentityRejects.WithLabelValues(stream).Inc()
	log.Printf("WARN grpc: %s rejected node=%s: handshake required", stream, nodeID)
	return status.Error(codes.Unauthenticated, "handshake required")
}

func (h *GRPCHandler) StatsStream(stream grpc.ClientStreamingServer[pb.StatsReport, emptypb.Empty]) error {
	// Decouple Recv from processing: Recv into a bounded queue,
	// process in a separate goroutine. This prevents slow onStats
	// (e.g. ring lock contention) from blocking gRPC stream Recv.
	const queueSize = 16
	queue := make(chan *pb.StatsReport, queueSize)
	hbQueue := make(chan *pb.StatsReport, 1)
	done := make(chan error, 1)
	handle := func(msg *pb.StatsReport) {
		if h.onStats != nil {
			h.onStats(msg.NodeId, msg)
		}
	}

	// Processing goroutine
	go func() {
		defer func() { done <- nil }()
	serve:
		for {
			select { // real reports first
			case msg, ok := <-queue:
				if !ok {
					break serve
				}
				handle(msg)
				continue
			default:
			}
			select {
			case msg, ok := <-queue:
				if !ok {
					break serve
				}
				handle(msg)
			case hb := <-hbQueue:
				handle(hb)
			}
		}
		select {
		case hb := <-hbQueue:
			handle(hb)
		default:
		}
	}()

	// Recv loop — fast, only touches lightweight fields
	var recvErr error
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			close(queue)
			<-done
			return stream.SendAndClose(&emptypb.Empty{})
		}
		if err != nil {
			recvErr = err
			break
		}

		if err := h.requireHandshake(stream.Context(), msg.NodeId, "stats"); err != nil {
			recvErr = err
			break
		}
		h.StatsReceived.Add(1)

		if msg.GapSeconds > 0 {
			log.Printf("grpc: stats node=%s gap=%ds (reconnect)", msg.NodeId, msg.GapSeconds)
		}
		if msg.IpStatsTruncated {
			log.Printf("grpc: stats node=%s ip_stats truncated (total_active=%d, reported=%d)",
				msg.NodeId, msg.TotalActiveIps, len(msg.IpStats))
		}

		if msg.GlobalStats == nil && len(msg.IpStats) == 0 && len(msg.PrefixStats) == 0 &&
			len(msg.SrcIpStats) == 0 && len(msg.SrcPrefixStats) == 0 && len(msg.TopFlows) == 0 {
			select {
			case hbQueue <- msg:
			default: // A heartbeat is already pending.
				h.StatsDropped.Add(1)
				log.Printf("grpc: stats heartbeat pending for node=%s, dropped heartbeat (total_dropped=%d)",
					msg.NodeId, h.StatsDropped.Load())
			}
			h.nodeState.TouchStats(msg.NodeId) // A dropped heartbeat still proves liveness.
			h.nodeState.NoteCapture(msg.NodeId, msg.InterfaceName, msg.UpstreamSampleRate)
			continue
		}
		select {
		case queue <- msg:
		default:
			// Queue full — drop oldest to keep Recv flowing
			h.StatsDropped.Add(1)
			select {
			case <-queue:
			default:
			}
			queue <- msg
			log.Printf("grpc: stats queue full for node=%s, dropped report (total_dropped=%d)",
				msg.NodeId, h.StatsDropped.Load())
		}
		// Always touch online status — msg is enqueued in both paths
		h.nodeState.TouchStats(msg.NodeId)
		h.nodeState.NoteCapture(msg.NodeId, msg.InterfaceName, msg.UpstreamSampleRate)
	}

	close(queue)
	<-done
	return recvErr
}

// --- 1.4 SampleStream ---

func (h *GRPCHandler) SampleStream(stream grpc.ClientStreamingServer[pb.SampleBatch, emptypb.Empty]) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&emptypb.Empty{})
		}
		if err != nil {
			return err
		}

		if err := h.requireHandshake(stream.Context(), msg.NodeId, "sample"); err != nil {
			return err
		}
		h.SamplesReceived.Add(uint64(len(msg.Samples)))

		if h.samplePool != nil {
			h.samplePool.Submit(msg.NodeId, msg)
		}
	}
}

// --- 1.5 CriticalEventStream ---

func (h *GRPCHandler) CriticalEventStream(stream grpc.ClientStreamingServer[pb.CriticalEvent, emptypb.Empty]) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&emptypb.Empty{})
		}
		if err != nil {
			return err
		}

		if err := h.requireHandshake(stream.Context(), msg.NodeId, "critical"); err != nil {
			return err
		}
		h.EventsReceived.Add(1)
		log.Printf("grpc: critical event node=%s type=%s dst=%v",
			msg.NodeId, msg.EventType, net.IP(msg.DstIp))

		if h.onCritical != nil {
			h.onCritical(msg.NodeId, msg)
		}
	}
}

// --- 1.6 ControlStream ---

func (h *GRPCHandler) ControlStream(stream grpc.BidiStreamingServer[pb.ControlMessage, pb.ControlMessage]) error {
	// Resolve nodeID: the verified certificate identity is authoritative when
	// the connection is mutually authenticated. Fall back to the peer-address
	// mapping registered during Handshake for plaintext deployments.
	addr := peerAddr(stream.Context())
	nodeID, certVerified := peerCertNodeID(stream.Context())
	if !certVerified {
		h.peerNodesMu.RLock()
		nodeID = h.peerNodes[addr]
		h.peerNodesMu.RUnlock()
	}

	if nodeID != "" {
		h.nodeState.SetControlStream(nodeID, stream)
		log.Printf("grpc: control stream opened for node=%s (peer=%s cert_verified=%t)", nodeID, addr, certVerified)
	} else {
		log.Printf("grpc: control stream opened from unknown peer=%s (no prior handshake?)", addr)
	}

	defer func() {
		if nodeID != "" {
			if h.nodeState.ClearControlStream(nodeID, stream) {
				log.Printf("grpc: control stream closed for node=%s", nodeID)
			} else {
				log.Printf("grpc: control stream closed for node=%s (superseded by a newer stream; state kept)", nodeID)
			}
		}
		// Clean up peer mapping
		if addr != "" {
			h.peerNodesMu.Lock()
			delete(h.peerNodes, addr)
			h.peerNodesMu.Unlock()
		}
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch p := msg.Payload.(type) {
		case *pb.ControlMessage_ConfigAck:
			ack := p.ConfigAck
			log.Printf("grpc: control ConfigAck node=%s version=%d success=%v",
				nodeID, ack.DeliveryVersionApplied, ack.Success)

			if nodeID == "" {
				continue
			}

			ctx := stream.Context()
			if ack.Success {
				if err := h.store.Nodes().UpdateACK(ctx, nodeID, int64(ack.DeliveryVersionApplied)); err != nil {
					log.Printf("grpc: update ACK for node %s: %v", nodeID, err)
				}
			} else {
				log.Printf("grpc: node %s config apply failed: %s", nodeID, ack.ErrorMessage)
				if err := h.store.Nodes().MarkConfigFailed(ctx, nodeID, int64(ack.DeliveryVersionApplied)); err != nil {
					log.Printf("grpc: mark config failed for node %s: %v", nodeID, err)
				}
			}
		}
	}
}

// SendConfigPush sends a ConfigPush to a specific node via its ControlStream.
func (h *GRPCHandler) SendConfigPush(nodeID string, config *pb.WatchConfig, version uint64) error {
	stream := h.nodeState.GetControlStream(nodeID)
	if stream == nil {
		return fmt.Errorf("node %s not connected", nodeID)
	}
	return stream.Send(&pb.ControlMessage{
		Payload: &pb.ControlMessage_ConfigPush{
			ConfigPush: &pb.ConfigPush{
				WatchConfig:            config,
				DeliveryVersionCurrent: version,
			},
		},
	})
}
