// Package ingestion handles gRPC data collection from XDP Nodes.
package ingestion

import (
	"fmt"
	"sync"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
)

// NodePosture is the console-facing snapshot of a Node's data-plane posture:
// which XDP mode is active, whether inline filtering is enabled, how many
// filter rules are installed, and the SYN-cookie / emergency-drop counters
// that prove the sub-second autonomous path is working.
type NodePosture struct {
	XDPMode          string    `json:"xdp_mode"`
	InlineEnabled    bool      `json:"inline_enabled"`
	FilterRules      uint64    `json:"filter_rules"`
	ValidatedClients uint64    `json:"validated_clients"`
	SYNReplies       uint64    `json:"syn_cookies_replied"`
	SYNValidated     uint64    `json:"syn_cookies_validated"`
	SYNDropped       uint64    `json:"syn_cookies_dropped"`
	EmergencyDrops   uint64    `json:"emergency_drops"`
	BurstAlerts      uint64    `json:"burst_alerts"`
	AFXDPActive      bool      `json:"af_xdp_active"`
	AFXDPUmemDrops   uint64    `json:"af_xdp_umem_drops"`
	AFXDPRX          uint64    `json:"af_xdp_rx"`
	CPUPins          []int64   `json:"cpu_pins,omitempty"`
	CleanpipeEgress  string    `json:"cleanpipe_egress,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// FlowMetrics holds the last-received flow node health metrics.
type FlowMetrics struct {
	DecodeErrors    uint64    `json:"decode_errors"`
	UnknownExporter uint64    `json:"unknown_exporter"`
	TemplateMisses  uint64    `json:"template_misses"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// SourceStatus represents the last-known status of a flow exporter device.
type SourceStatus struct {
	DeviceIP        string `json:"device_ip"`
	Active          bool   `json:"active"`
	LastSeenAt      int64  `json:"last_seen_at"` // unix timestamp
	RecordsReceived int64  `json:"records_received"`
}

// ListenerStatus represents per-listener runtime metrics.
type ListenerStatus struct {
	ListenAddr      string `json:"listen_addr"`
	ProtocolMode    string `json:"protocol_mode"`
	RecordsDecoded  int64  `json:"records_decoded"`
	DecodeErrors    int64  `json:"decode_errors"`
	UnknownExporter int64  `json:"unknown_exporter"`
	TemplateMisses  int64  `json:"template_misses"`
	SourceCount     int    `json:"source_count"`
}

// NodeState tracks runtime state of a connected Node.
// Online status is derived (not stored in DB) per brainstorm decision.
type NodeState struct {
	mu               sync.RWMutex
	interfaces       map[string][]string
	capture          map[string]map[string]uint32
	lastStatsAt      map[string]time.Time                            // nodeID → last StatsReport time
	connectedAt      map[string]time.Time                            // nodeID → handshake time (for uptime)
	controlStream    map[string]pb.XSightService_ControlStreamServer // nodeID → bidi stream
	flowMetrics      map[string]*FlowMetrics                         // nodeID → last flow metrics
	sourceStatuses   map[string][]SourceStatus                       // nodeID → per-source statuses
	listenerStatuses map[string][]ListenerStatus                     // nodeID → per-listener statuses
	peerTLS          map[string]PeerTLS                              // nodeID → last verified client certificate
	posture          map[string]NodePosture                          // nodeID → last data-plane posture
	// sendMu serializes Send calls per ControlStream: gRPC allows only one
	// concurrent SendMsg per stream. Entries are intentionally never deleted
	// so a send in flight can never race with a fresh mutex allocation.
	sendMu map[string]*sync.Mutex
}

// PeerTLS describes the client certificate a Node presented during the gRPC
// handshake. It is populated only when the Controller's gRPC listener runs
// with mutual TLS; plaintext deployments never set it.
type PeerTLS struct {
	Verified    bool      `json:"verified"`
	Identity    string    `json:"identity,omitempty"` // node id extracted from the URI SAN
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	Serial      string    `json:"serial,omitempty"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	URIs        []string  `json:"uris,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	IsCA        bool      `json:"is_ca,omitempty"`
	SeenAt      time.Time `json:"seen_at"`
}

func NewNodeState() *NodeState {
	return &NodeState{
		interfaces:       make(map[string][]string),
		capture:          make(map[string]map[string]uint32),
		lastStatsAt:      make(map[string]time.Time),
		connectedAt:      make(map[string]time.Time),
		controlStream:    make(map[string]pb.XSightService_ControlStreamServer),
		flowMetrics:      make(map[string]*FlowMetrics),
		sourceStatuses:   make(map[string][]SourceStatus),
		listenerStatuses: make(map[string][]ListenerStatus),
		peerTLS:          make(map[string]PeerTLS),
		posture:          make(map[string]NodePosture),
		sendMu:           make(map[string]*sync.Mutex),
	}
}

// UpdatePosture records the last data-plane posture reported by a Node.
func (ns *NodeState) UpdatePosture(nodeID string, p *pb.NodePosture) {
	if nodeID == "" || p == nil {
		return
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.posture[nodeID] = NodePosture{
		XDPMode:          p.GetXdpMode(),
		InlineEnabled:    p.GetInlineEnabled(),
		FilterRules:      p.GetFilterRules(),
		ValidatedClients: p.GetValidatedClients(),
		SYNReplies:       p.GetSynCookiesReply(),
		SYNValidated:     p.GetSynCookiesValidated(),
		SYNDropped:       p.GetSynCookiesDropped(),
		EmergencyDrops:   p.GetEmergencyDrops(),
		BurstAlerts:      p.GetBurstAlerts(),
		AFXDPActive:      p.GetAfXdpActive(),
		AFXDPUmemDrops:   p.GetAfXdpUmemDrops(),
		AFXDPRX:          p.GetAfXdpRx(),
		CPUPins:          append([]int64(nil), p.GetCpuPins()...),
		CleanpipeEgress:  p.GetCleanpipeEgress(),
		UpdatedAt:        time.Now(),
	}
}

// GetPosture returns the last posture snapshot for a Node.
func (ns *NodeState) GetPosture(nodeID string) (NodePosture, bool) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	p, ok := ns.posture[nodeID]
	return p, ok
}

// AllPosture returns a copy of every Node posture snapshot.
func (ns *NodeState) AllPosture() map[string]NodePosture {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	out := make(map[string]NodePosture, len(ns.posture))
	for k, v := range ns.posture {
		out[k] = v
	}
	return out
}

// NotePeerTLS records the client certificate seen at handshake time so the
// console can show mTLS status and certificate expiry per Node.
func (ns *NodeState) NotePeerTLS(nodeID string, info PeerTLS) {
	if nodeID == "" {
		return
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.peerTLS[nodeID] = info
}

// GetPeerTLS returns the last recorded client certificate for a Node.
func (ns *NodeState) GetPeerTLS(nodeID string) (PeerTLS, bool) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	info, found := ns.peerTLS[nodeID]
	return info, found
}

// AllPeerTLS returns a copy of every recorded Node certificate.
func (ns *NodeState) AllPeerTLS() map[string]PeerTLS {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	out := make(map[string]PeerTLS, len(ns.peerTLS))
	for k, v := range ns.peerTLS {
		out[k] = v
	}
	return out
}

// NoteHandshake replaces collection state after a handshake has been accepted.
func (ns *NodeState) NoteHandshake(nodeID string, interfaces []string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.interfaces[nodeID] = append([]string(nil), interfaces...)
	delete(ns.capture, nodeID)
}

// GetInterfaces returns an independent snapshot of the last accepted handshake.
func (ns *NodeState) GetInterfaces(nodeID string) []string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return append([]string(nil), ns.interfaces[nodeID]...)
}

// NoteCapture records the most recent sampling rate for an identified interface.
func (ns *NodeState) NoteCapture(nodeID, name string, rate uint32) {
	if name == "" {
		return
	}
	ns.mu.Lock()
	defer ns.mu.Unlock()
	if ns.capture[nodeID] == nil {
		ns.capture[nodeID] = make(map[string]uint32)
	}
	ns.capture[nodeID][name] = rate
}

// GetCapture copies the nested map while holding the lock: writers update it in place.
func (ns *NodeState) GetCapture(nodeID string) map[string]uint32 {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	result := make(map[string]uint32, len(ns.capture[nodeID]))
	for name, rate := range ns.capture[nodeID] {
		result[name] = rate
	}
	return result
}

// TouchStats records that a StatsReport was received from the node.
func (ns *NodeState) TouchStats(nodeID string) {
	ns.mu.Lock()
	ns.lastStatsAt[nodeID] = time.Now()
	ns.mu.Unlock()
}

// IsOnline returns true if a StatsReport was received within the last 10s.
func (ns *NodeState) IsOnline(nodeID string) bool {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	t, ok := ns.lastStatsAt[nodeID]
	return ok && time.Since(t) < 10*time.Second
}

// LastStatsAt returns the last stats time for a node (zero if never seen).
func (ns *NodeState) LastStatsAt(nodeID string) time.Time {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.lastStatsAt[nodeID]
}

// ConnectedAt returns the handshake time for a node (zero if not connected).
func (ns *NodeState) ConnectedAt(nodeID string) time.Time {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.connectedAt[nodeID]
}

// SetControlStream registers a bidirectional ControlStream for a node.
func (ns *NodeState) SetControlStream(nodeID string, stream pb.XSightService_ControlStreamServer) {
	ns.mu.Lock()
	ns.controlStream[nodeID] = stream
	ns.connectedAt[nodeID] = time.Now()
	ns.mu.Unlock()
}

// ClearControlStream clears ephemeral state only for the currently registered stream.
// It reports whether the stream was removed.
func (ns *NodeState) ClearControlStream(nodeID string, stream pb.XSightService_ControlStreamServer) bool {
	ns.mu.Lock()
	if ns.controlStream[nodeID] != stream {
		ns.mu.Unlock()
		return false
	}
	delete(ns.controlStream, nodeID)
	delete(ns.lastStatsAt, nodeID)
	delete(ns.connectedAt, nodeID)
	delete(ns.sourceStatuses, nodeID)
	delete(ns.listenerStatuses, nodeID)
	delete(ns.posture, nodeID)
	ns.mu.Unlock()
	return true
}

// GetControlStream returns the ControlStream for a node (nil if not connected).
func (ns *NodeState) GetControlStream(nodeID string) pb.XSightService_ControlStreamServer {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.controlStream[nodeID]
}

// SendControlMessage sends msg on the node's ControlStream, serializing
// concurrent senders (gRPC permits one concurrent SendMsg per stream).
func (ns *NodeState) SendControlMessage(nodeID string, msg *pb.ControlMessage) error {
	ns.mu.Lock()
	mu := ns.sendMu[nodeID]
	if mu == nil {
		mu = &sync.Mutex{}
		ns.sendMu[nodeID] = mu
	}
	ns.mu.Unlock()

	mu.Lock()
	defer mu.Unlock()

	ns.mu.RLock()
	stream := ns.controlStream[nodeID]
	ns.mu.RUnlock()
	if stream == nil {
		return fmt.Errorf("node %s not connected", nodeID)
	}
	return stream.Send(msg)
}

// ConnectedNodes returns a list of node IDs with active ControlStreams.
func (ns *NodeState) ConnectedNodes() []string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	ids := make([]string, 0, len(ns.controlStream))
	for id := range ns.controlStream {
		ids = append(ids, id)
	}
	return ids
}

// UpdateFlowMetrics stores the latest SamplingMetrics for a flow node.
// Proto field mapping: dropped_kernel = template_misses, dropped_user = unknown_exporter.
func (ns *NodeState) UpdateFlowMetrics(nodeID string, decodeErrors, unknownExporter, templateMisses uint64) {
	ns.mu.Lock()
	ns.flowMetrics[nodeID] = &FlowMetrics{
		DecodeErrors:    decodeErrors,
		UnknownExporter: unknownExporter,
		TemplateMisses:  templateMisses,
		UpdatedAt:       time.Now(),
	}
	ns.mu.Unlock()
}

// GetFlowMetrics returns the last-received flow metrics for a node (nil if none).
func (ns *NodeState) GetFlowMetrics(nodeID string) *FlowMetrics {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.flowMetrics[nodeID]
}

// UpdateSourceStatuses stores per-source status for a flow node.
func (ns *NodeState) UpdateSourceStatuses(nodeID string, statuses []SourceStatus) {
	ns.mu.Lock()
	ns.sourceStatuses[nodeID] = statuses
	ns.mu.Unlock()
}

// GetSourceStatuses returns the last-known source statuses for a node.
func (ns *NodeState) GetSourceStatuses(nodeID string) []SourceStatus {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.sourceStatuses[nodeID]
}

// UpdateListenerStatuses stores per-listener status for a flow node.
func (ns *NodeState) UpdateListenerStatuses(nodeID string, statuses []ListenerStatus) {
	ns.mu.Lock()
	ns.listenerStatuses[nodeID] = statuses
	ns.mu.Unlock()
}

// GetListenerStatuses returns the last-known listener statuses for a node.
func (ns *NodeState) GetListenerStatuses(nodeID string) []ListenerStatus {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.listenerStatuses[nodeID]
}
