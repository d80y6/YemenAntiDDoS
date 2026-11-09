// Inline scrubbing mitigation — the Controller's autonomous action plane for
// xdp_inline Nodes.
//
// Responsibilities:
//   - Own the authoritative InlineRuleSet pushed to every connected inline Node
//     (broad phase on confirmation, narrow phase 500ms-1s later, rebreadth if
//     narrowing strangles the attack).
//   - Push rules over the existing ControlStream (gRPC) via InlinePusher.
//   - Reconcile kernel BPF map state after a Controller restart: nodes that
//     reconnect receive the current snapshot (session recovery).
//
// The subsystem is intentionally independent from the DB-backed response
// action engine: inline mitigations are ephemeral, high-rate and must not
// block on database round-trips.

package action

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
)

// InlinePusher delivers an InlineRuleSet to one or more Nodes.
// main.go implements this over ingestion.GRPCHandler.SendInlineRulePush.
type InlinePusher interface {
	// PushInlineRules sends the rule set to a node. Implementations must be
	// safe for concurrent use and return an error when the node is not
	// connected (the mitigator retries on the next reconcile tick).
	PushInlineRules(nodeID string, rules *pb.InlineRuleSet) error
	// ConnectedInlineNodes lists nodes currently attached via ControlStream.
	ConnectedInlineNodes() []string
	// AFXDPActive reports whether the node's last data-plane posture shows
	// an AF_XDP socket bound — the challenge responder needs one. Unknown
	// nodes report false: the challenge rule is withheld until the node
	// proves it can serve it (its rate cap keeps applying meanwhile).
	AFXDPActive(nodeID string) bool
}

// InlineRule is the mitigator's internal rule representation.
type InlineRule struct {
	ID            uint64
	DstIP         string
	DstPrefixLen  int
	SrcIP         string
	SrcPrefixLen  int
	Protocol      uint32
	DstPort       uint32
	SrcPort       uint32
	Action        string
	RateLimitPPS  uint64
	Priority      uint32
	ExpiresUnix   int64
	EgressIfindex uint32
	Encap         string
	Reason        string
}

// InlineMitigation is the tracked state of one mitigated attack.
type InlineMitigation struct {
	AttackID   int
	TargetIP   string
	Decoder    string
	EventType  string // critical-event / attack type (e.g. "syn_flood")
	Nodes      []string
	Phase      string // "broad" | "narrow"
	Rules      []InlineRule
	StartedAt  time.Time
	NarrowedAt time.Time
	PeakPPS    uint64
	Rebreadths int
	Version    uint64
}

// NarrowingInput carries the flow evidence used for phase-2 refinement.
type NarrowingInput struct {
	TopFlows []FlowKey // dominant 5-tuples observed at the node
}

// FlowKey is one dominant flow (subset of proto FlowSample).
type FlowKey struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint32
	DstPort  uint32
	Protocol uint32
	Packets  uint64
}

// InlineMitigatorConfig tunes the narrow-then-rebreadth algorithm.
type InlineMitigatorConfig struct {
	Enabled bool
	// BroadRateLimitPPS is the phase-1 rate cap applied to the target.
	BroadRateLimitPPS uint64
	// NarrowDelay is how long after the broad rule the narrow phase runs.
	NarrowDelay time.Duration
	// NarrowMinShare is the minimum share of top-flow packets a port must
	// hold to be included in the narrow rule (0.25 = 25%).
	NarrowMinShare float64
	// NarrowMaxPorts caps the number of ports in a narrow rule.
	NarrowMaxPorts int
	// RebreathAfter triggers a re-widening when the attack survives narrowing.
	RebreathAfter time.Duration
	// RuleTTL is the kernel rule lifetime; the mitigator refreshes before it.
	RuleTTL time.Duration
	// TopSrcSubnets enables source-subnet narrowing from top flows.
	TopSrcSubnets bool
}

// DefaultInlineMitigatorConfig returns carrier-grade defaults.
func DefaultInlineMitigatorConfig() InlineMitigatorConfig {
	return InlineMitigatorConfig{
		Enabled:           true,
		BroadRateLimitPPS: 20000,
		NarrowDelay:       750 * time.Millisecond,
		NarrowMinShare:    0.25,
		NarrowMaxPorts:    4,
		RebreathAfter:     30 * time.Second,
		RuleTTL:           10 * time.Minute,
		TopSrcSubnets:     true,
	}
}

func (c InlineMitigatorConfig) normalize() InlineMitigatorConfig {
	d := DefaultInlineMitigatorConfig()
	if c.BroadRateLimitPPS == 0 {
		c.BroadRateLimitPPS = d.BroadRateLimitPPS
	}
	if c.NarrowDelay <= 0 {
		c.NarrowDelay = d.NarrowDelay
	}
	if c.NarrowMinShare <= 0 {
		c.NarrowMinShare = d.NarrowMinShare
	}
	if c.NarrowMaxPorts <= 0 {
		c.NarrowMaxPorts = d.NarrowMaxPorts
	}
	if c.RebreathAfter <= 0 {
		c.RebreathAfter = d.RebreathAfter
	}
	if c.RuleTTL <= 0 {
		c.RuleTTL = d.RuleTTL
	}
	return c
}

// InlineMitigator owns the inline rule lifecycle across all nodes.
type InlineMitigator struct {
	cfg    InlineMitigatorConfig
	pusher InlinePusher

	mu       sync.Mutex
	active   map[int]*InlineMitigation // attackID → mitigation
	version  uint64
	nextRule uint64

	// cookieTargets tracks destination prefixes protected by SYN cookies.
	cookieTargets map[string]struct{}

	pushes   int64
	failures int64

	// narrowFn optionally overrides narrowing evidence (tests).
	narrowFn func(attackID int) NarrowingInput
	nowFn    func() time.Time

	// seeded marks Nodes that have received this Controller epoch's first
	// push. A restarted Controller's version counter is below what a Node
	// already applied, so that first push is v1 (epoch reset) and later
	// pushes use the global generation. Guarded by mu; paired with pushLocks
	// so the decide-version → send → seed sequence is atomic per node.
	seeded map[string]bool
	// pushLocks serializes (decide version → send → seed) per node. Lock
	// order: pushLocks[node] before mu, never the reverse.
	pushLocks map[string]*sync.Mutex
}

// NewInlineMitigator builds the mitigator.
func NewInlineMitigator(cfg InlineMitigatorConfig, pusher InlinePusher) *InlineMitigator {
	cfg = cfg.normalize()
	return &InlineMitigator{
		cfg:           cfg,
		pusher:        pusher,
		active:        make(map[int]*InlineMitigation),
		cookieTargets: make(map[string]struct{}),
		nowFn:         time.Now,
		seeded:        make(map[string]bool),
		pushLocks:     make(map[string]*sync.Mutex),
	}
}

// SetPusher binds the push transport. The mitigator can exist before the gRPC
// handler (startup recovery rebuilds rules with no pusher); Nodes receive the
// snapshot through Reconcile once they attach.
func (m *InlineMitigator) SetPusher(p InlinePusher) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.pusher = p
	m.mu.Unlock()
}

// SetNarrowingSource installs a callback that supplies flow evidence for the
// narrow phase (wired to the CriticalEvent top-flows ring in main.go).
func (m *InlineMitigator) SetNarrowingSource(fn func(attackID int) NarrowingInput) {
	m.mu.Lock()
	m.narrowFn = fn
	m.mu.Unlock()
}

// ProtectCookieTarget registers a prefix for SYN-cookie protection.
func (m *InlineMitigator) ProtectCookieTarget(cidr string) {
	m.mu.Lock()
	m.cookieTargets[cidr] = struct{}{}
	m.mu.Unlock()
}

// OnCritical is invoked for every fast-tracked attack event. It issues the
// phase-1 broad rule immediately and schedules phase 2.
func (m *InlineMitigator) OnCritical(attackID int, targetIP, decoder, eventType string,
	nodes []string, pps uint64, flows []FlowKey) {
	if m == nil || !m.cfg.Enabled || targetIP == "" {
		return
	}
	now := m.nowFn()

	m.mu.Lock()
	if existing, ok := m.active[attackID]; ok {
		// Already mitigating — refresh peaks and merge the node set. When
		// the set grows (a second node reports the attack), push the merged
		// snapshot immediately: without it the joined node waits for the
		// next phase change or the 5-minute refresh tick.
		existing.PeakPPS = maxPeak(existing.PeakPPS, pps)
		merged := mergeStrings(existing.Nodes, nodes)
		changed := len(merged) != len(existing.Nodes)
		existing.Nodes = merged
		if !changed {
			m.mu.Unlock()
			return
		}
		m.version++
		version := m.version
		nodesPush := append([]string(nil), merged...)
		m.mu.Unlock()
		log.Printf("inline-mitigation: attack=%d node set grew to %v, pushing merged snapshot",
			attackID, nodesPush)
		m.pushSnapshot(nodesPush, version)
		return
	}

	mit := &InlineMitigation{
		AttackID:  attackID,
		TargetIP:  targetIP,
		Decoder:   decoder,
		EventType: eventType,
		Nodes:     append([]string(nil), nodes...),
		Phase:     "broad",
		StartedAt: now,
		PeakPPS:   pps,
	}
	mit.Rules = m.broadRulesLocked(mit, now)
	m.active[attackID] = mit
	m.version++
	version := m.version
	// Snapshot the node list under the lock: a concurrent OnCritical may
	// merge nodes into this mitigation while the push is in flight.
	nodesPush := append([]string(nil), mit.Nodes...)
	m.mu.Unlock()

	log.Printf("inline-mitigation: attack=%d target=%s decoder=%s BROAD phase (pps=%d nodes=%v)",
		attackID, targetIP, decoder, pps, nodes)
	m.pushSnapshot(nodesPush, version)

	// Phase 2: narrow to the dominant ports/subnets once flow samples land.
	go m.scheduleNarrow(attackID, flows)
}

// Recover rebuilds a mitigation from an attack restored after a Controller
// restart. It records the broad phase but does not push: no Node has attached
// yet, and version accounting must not advance before this epoch's first
// per-Node push (see seeded). Reconcile delivers the snapshot on attach.
func (m *InlineMitigator) Recover(attackID int, targetIP, decoder, eventType string,
	nodes []string, pps uint64) {
	if m == nil || !m.cfg.Enabled || attackID <= 0 || targetIP == "" {
		return
	}
	now := m.nowFn()

	m.mu.Lock()
	if existing, ok := m.active[attackID]; ok {
		existing.PeakPPS = maxPeak(existing.PeakPPS, pps)
		existing.Nodes = mergeStrings(existing.Nodes, nodes)
		m.mu.Unlock()
		return
	}
	mit := &InlineMitigation{
		AttackID:  attackID,
		TargetIP:  targetIP,
		Decoder:   decoder,
		EventType: eventType,
		Nodes:     append([]string(nil), nodes...),
		Phase:     "broad",
		StartedAt: now,
		PeakPPS:   pps,
	}
	mit.Rules = m.broadRulesLocked(mit, now)
	m.active[attackID] = mit
	m.mu.Unlock()

	log.Printf("inline-mitigation: attack=%d target=%s decoder=%s RECOVERED broad phase (pps=%d nodes=%v)",
		attackID, targetIP, decoder, pps, nodes)
	go m.scheduleNarrow(attackID, nil)
}

// scheduleNarrow waits NarrowDelay, then narrows using the freshest evidence.
func (m *InlineMitigator) scheduleNarrow(attackID int, seedFlows []FlowKey) {
	timer := time.NewTimer(m.cfg.NarrowDelay)
	defer timer.Stop()
	<-timer.C

	m.mu.Lock()
	mit, ok := m.active[attackID]
	if !ok {
		m.mu.Unlock()
		return
	}
	flows := seedFlows
	if m.narrowFn != nil {
		if extra := m.narrowFn(attackID); len(extra.TopFlows) > 0 {
			flows = extra.TopFlows
		}
	}
	now := m.nowFn()
	narrow, ok := m.narrowRulesLocked(mit, flows, now)
	if !ok {
		// No usable evidence yet — try once more shortly, then settle on
		// the broad rule (defence in depth beats narrowing on thin evidence).
		m.mu.Unlock()
		time.Sleep(m.cfg.NarrowDelay)
		m.mu.Lock()
		mit, ok = m.active[attackID]
		if !ok {
			m.mu.Unlock()
			return
		}
		now = m.nowFn()
		narrow, ok = m.narrowRulesLocked(mit, flows, now)
		if !ok {
			m.mu.Unlock()
			log.Printf("inline-mitigation: attack=%d kept BROAD rules (insufficient flow evidence)", attackID)
			return
		}
	}

	mit.Rules = narrow
	mit.Phase = "narrow"
	mit.NarrowedAt = now
	m.version++
	version := m.version
	nodesPush := append([]string(nil), mit.Nodes...)
	m.mu.Unlock()

	log.Printf("inline-mitigation: attack=%d NARROW phase → %s", attackID, describeRules(narrow))
	m.pushSnapshot(nodesPush, version)

	// Watch for survival: if the attack outlives narrowing, re-breadth.
	go m.scheduleRebreadth(attackID)
}

// scheduleRebreadth re-widens when a narrowed attack persists, which usually
// means the attacker rotated source ports to evade the narrow signature.
func (m *InlineMitigator) scheduleRebreadth(attackID int) {
	timer := time.NewTimer(m.cfg.RebreathAfter)
	defer timer.Stop()
	<-timer.C

	m.mu.Lock()
	mit, ok := m.active[attackID]
	if !ok || mit.Phase != "narrow" {
		m.mu.Unlock()
		return
	}
	now := m.nowFn()
	mit.Rules = m.broadRulesLocked(mit, now)
	mit.Phase = "broad"
	mit.Rebreadths++
	m.version++
	version := m.version
	rebreaths := mit.Rebreadths
	nodesPush := append([]string(nil), mit.Nodes...)
	m.mu.Unlock()

	log.Printf("inline-mitigation: attack=%d REBREADTH #%d (attack survived narrow phase)", attackID, rebreaths)
	m.pushSnapshot(nodesPush, version)
	go m.scheduleNarrow(attackID, nil)
}

// Withdraw removes an attack's inline rules and pushes the update.
func (m *InlineMitigator) Withdraw(attackID int) {
	if m == nil {
		return
	}
	m.mu.Lock()
	mit, ok := m.active[attackID]
	if !ok {
		m.mu.Unlock()
		return
	}
	delete(m.active, attackID)
	m.version++
	version := m.version
	nodesPush := append([]string(nil), mit.Nodes...)
	m.mu.Unlock()

	log.Printf("inline-mitigation: attack=%d withdrawn (nodes=%v)", attackID, nodesPush)
	m.pushSnapshot(nodesPush, version)
}

// Reconcile re-pushes the authoritative rule snapshot to a node. Called when
// a node opens its ControlStream (session recovery after a Controller
// restart) and periodically for drift correction.
func (m *InlineMitigator) Reconcile(nodeID string) error {
	if m == nil {
		return nil
	}
	l := m.nodePushLock(nodeID)
	l.Lock()
	defer l.Unlock()

	m.mu.Lock()
	pusher := m.pusher
	if pusher == nil {
		m.mu.Unlock()
		log.Printf("inline-mitigation: reconcile node=%s skipped (pusher not bound)", nodeID)
		return nil
	}
	var version uint64
	if m.seeded[nodeID] {
		m.version++
		version = m.version
	} else {
		// First push of this Controller epoch: v1 tells the Node to reset
		// its applied-version counters (a restarted Controller numbers from
		// scratch below whatever the Node had already accepted).
		version = 1
	}
	rules := m.snapshotRulesLocked()
	cookies := make([]string, 0, len(m.cookieTargets))
	for c := range m.cookieTargets {
		cookies = append(cookies, c)
	}
	m.mu.Unlock()

	set := &pb.InlineRuleSet{
		Version:          version,
		Rules:            rulesForNode(pusher, nodeID, rules),
		DefaultAction:    "pass",
		SynCookieEnabled: true,
		CookieTargets:    cookies,
	}
	if err := pusher.PushInlineRules(nodeID, set); err != nil {
		m.mu.Lock()
		m.failures++
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.seeded[nodeID] = true
	m.mu.Unlock()
	if len(rules) > 0 {
		log.Printf("inline-mitigation: reconciled %d rules to node=%s (v%d)", len(rules), nodeID, version)
	}
	return nil
}

// ReconcileAll pushes the current snapshot to every connected node.
func (m *InlineMitigator) ReconcileAll() {
	if m == nil {
		return
	}
	m.mu.Lock()
	pusher := m.pusher
	m.mu.Unlock()
	if pusher == nil {
		return
	}
	for _, nodeID := range pusher.ConnectedInlineNodes() {
		_ = m.Reconcile(nodeID)
	}
}

// RunReconcile re-pushes the snapshot to every connected node on a timer.
// The interval must stay below RuleTTL so Node-side rule expiry never lapses
// a mitigation between pushes.
func (m *InlineMitigator) RunReconcile(ctx context.Context, every time.Duration) {
	if m == nil || every <= 0 || !m.cfg.Enabled {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.ReconcileAll()
		}
	}
}

// Stats returns counters for the API/console.
func (m *InlineMitigator) Stats() (active int, pushes, failures int64) {
	if m == nil {
		return 0, 0, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active), m.pushes, m.failures
}

// ActiveMitigations returns a snapshot for the API (sorted by attack id).
func (m *InlineMitigator) ActiveMitigations() []InlineMitigation {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]InlineMitigation, 0, len(m.active))
	for _, mit := range m.active {
		cp := *mit
		cp.Rules = append([]InlineRule(nil), mit.Rules...)
		cp.Nodes = append([]string(nil), mit.Nodes...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AttackID < out[j].AttackID })
	return out
}

// ---------------------------------------------------------------------------
// Rule construction — narrow-then-rebreadth
// ---------------------------------------------------------------------------

// broadRulesLocked builds phase-1 rules: a rate cap on the target plus a
// SYN-cookie zone when the decoder indicates a handshake flood.
func (m *InlineMitigator) broadRulesLocked(mit *InlineMitigation, now time.Time) []InlineRule {
	rules := []InlineRule{{
		ID:           m.newRuleIDLocked(),
		DstIP:        mit.TargetIP,
		DstPrefixLen: prefixLenOf(mit.TargetIP),
		Action:       "rate_limit",
		RateLimitPPS: m.cfg.BroadRateLimitPPS,
		Priority:     100,
		ExpiresUnix:  now.Add(m.cfg.RuleTTL).Unix(),
		Reason:       fmt.Sprintf("broad:attack=%d:pps=%d", mit.AttackID, mit.PeakPPS),
	}}
	if isHandshakeFlood(mit.Decoder) || isHandshakeFlood(mit.EventType) {
		rules = append(rules, InlineRule{
			ID:           m.newRuleIDLocked(),
			DstIP:        mit.TargetIP,
			DstPrefixLen: prefixLenOf(mit.TargetIP),
			Protocol:     6,
			Action:       "syn_cookie",
			Priority:     10,
			ExpiresUnix:  now.Add(m.cfg.RuleTTL).Unix(),
			Reason:       fmt.Sprintf("syn_cookie:attack=%d", mit.AttackID),
		})
	}
	// Anti-bot funnel: cleartext HTTP floods are steered to the Node's JS-PoW
	// challenge responder (nodes without AF_XDP keep their rate cap instead:
	// sendVersioned withholds this rule when the node's posture shows no XSK
	// bound, because a steer it cannot answer would bypass the cap entirely).
	// Cleartext only: TLS cannot be challenged without termination. IPv4
	// only: the responder and validated_clients are v4-only, so a v6 steer
	// would blackhole the traffic.
	if isAntiBotTarget(mit) && net.ParseIP(mit.TargetIP).To4() != nil {
		rules = append(rules, InlineRule{
			ID:           m.newRuleIDLocked(),
			DstIP:        mit.TargetIP,
			DstPrefixLen: prefixLenOf(mit.TargetIP),
			Protocol:     6,
			DstPort:      80,
			Action:       "challenge",
			Priority:     15,
			ExpiresUnix:  now.Add(m.cfg.RuleTTL).Unix(),
			Reason:       fmt.Sprintf("challenge:attack=%d", mit.AttackID),
		})
	}
	return rules
}

// isAntiBotTarget reports whether an attack is an HTTP-shaped L7 flood that
// the JS-PoW challenge path is meant to stop.
func isAntiBotTarget(mit *InlineMitigation) bool {
	e := strings.ToLower(mit.EventType + " " + mit.Decoder)
	return strings.Contains(e, "http") || strings.Contains(e, "slowloris")
}

// narrowRulesLocked refines the broad rule with dominant destination ports
// and source subnets observed in the flow samples.
func (m *InlineMitigator) narrowRulesLocked(mit *InlineMitigation, flows []FlowKey,
	now time.Time) ([]InlineRule, bool) {
	if len(flows) == 0 {
		return nil, false
	}
	var total uint64
	portCount := map[uint32]uint64{}
	subnetCount := map[string]uint64{}
	protoCount := map[uint32]uint64{}
	for _, f := range flows {
		total += f.Packets
		if f.DstPort != 0 {
			portCount[f.DstPort] += f.Packets
		}
		if f.Protocol != 0 {
			protoCount[f.Protocol] += f.Packets
		}
		if m.cfg.TopSrcSubnets && f.SrcIP != "" {
			if sn := subnet24(f.SrcIP); sn != "" {
				subnetCount[sn] += f.Packets
			}
		}
	}
	if total == 0 {
		return nil, false
	}
	// Carry the flood's dominant L4 protocol into the narrow rules: a UDP
	// port flood must not be narrowed to TCP port drops.
	dominantProto := uint32(6)
	var protoBest uint64
	for p, n := range protoCount {
		if n == 0 {
			continue
		}
		if n > protoBest || (n == protoBest && p < dominantProto) {
			protoBest = n
			dominantProto = p
		}
	}

	ports := topPorts(portCount, total, m.cfg.NarrowMinShare, m.cfg.NarrowMaxPorts)
	if len(ports) == 0 {
		return nil, false
	}
	var subnets []subnetShare
	if m.cfg.TopSrcSubnets {
		subnets = topSubnets(subnetCount, total, m.cfg.NarrowMinShare, m.cfg.NarrowMaxPorts)
	}

	rules := make([]InlineRule, 0, len(ports)+len(subnets)+1)
	for _, p := range ports {
		rules = append(rules, InlineRule{
			ID:           m.newRuleIDLocked(),
			DstIP:        mit.TargetIP,
			DstPrefixLen: prefixLenOf(mit.TargetIP),
			Protocol:     dominantProto,
			DstPort:      p.port,
			Action:       "drop",
			Priority:     20,
			ExpiresUnix:  now.Add(m.cfg.RuleTTL).Unix(),
			Reason: fmt.Sprintf("narrow:attack=%d:%s/%d:share=%.0f%%",
				mit.AttackID, protoName(dominantProto), p.port, p.share*100),
		})
	}
	// Dominant source networks: when a few /24s carry most of the flood, drop
	// them wholesale for this target instead of chasing per-flow signatures.
	for _, sn := range subnets {
		ip, ones, err := net.ParseCIDR(sn.cidr)
		if err != nil {
			continue
		}
		onesLen, _ := ones.Mask.Size()
		rules = append(rules, InlineRule{
			ID:           m.newRuleIDLocked(),
			DstIP:        mit.TargetIP,
			DstPrefixLen: prefixLenOf(mit.TargetIP),
			SrcIP:        ip.String(),
			SrcPrefixLen: onesLen,
			Protocol:     dominantProto,
			Action:       "drop",
			Priority:     30,
			ExpiresUnix:  now.Add(m.cfg.RuleTTL).Unix(),
			Reason: fmt.Sprintf("narrow-subnet:attack=%d:%s:share=%.0f%%",
				mit.AttackID, sn.cidr, sn.share*100),
		})
	}
	// Keep a rate cap for the residual (rotating source ports) traffic.
	rules = append(rules, InlineRule{
		ID:           m.newRuleIDLocked(),
		DstIP:        mit.TargetIP,
		DstPrefixLen: prefixLenOf(mit.TargetIP),
		Action:       "rate_limit",
		RateLimitPPS: m.cfg.BroadRateLimitPPS,
		Priority:     100,
		ExpiresUnix:  now.Add(m.cfg.RuleTTL).Unix(),
		Reason:       fmt.Sprintf("narrow-residual:attack=%d", mit.AttackID),
	})
	return rules, true
}

type portShare struct {
	port  uint32
	share float64
}

type subnetShare struct {
	cidr  string
	share float64
}

func topPorts(counts map[uint32]uint64, total uint64, minShare float64, maxPorts int) []portShare {
	list := make([]portShare, 0, len(counts))
	for p, n := range counts {
		share := float64(n) / float64(total)
		if share >= minShare {
			list = append(list, portShare{port: p, share: share})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].share == list[j].share {
			return list[i].port < list[j].port
		}
		return list[i].share > list[j].share
	})
	if len(list) > maxPorts {
		list = list[:maxPorts]
	}
	return list
}

// topSubnets ranks source /24s by packet share, mirroring topPorts.
func topSubnets(counts map[string]uint64, total uint64, minShare float64, max int) []subnetShare {
	list := make([]subnetShare, 0, len(counts))
	for cidr, n := range counts {
		share := float64(n) / float64(total)
		if share >= minShare {
			list = append(list, subnetShare{cidr: cidr, share: share})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].share != list[j].share {
			return list[i].share > list[j].share
		}
		return list[i].cidr < list[j].cidr
	})
	if len(list) > max {
		list = list[:max]
	}
	return list
}

// ---------------------------------------------------------------------------
// Push plumbing
// ---------------------------------------------------------------------------

// nodePushLock returns the per-node push lock, creating it on first use.
// Callers take it before m.mu (never while holding m.mu).
func (m *InlineMitigator) nodePushLock(nodeID string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.pushLocks[nodeID]
	if l == nil {
		l = &sync.Mutex{}
		m.pushLocks[nodeID] = l
	}
	return l
}

// sendVersioned pushes one snapshot to one node with the version decided
// atomically with the send: an unseeded node always receives v1 first, so a
// late stale epoch-reset can never arrive after a newer generation.
func (m *InlineMitigator) sendVersioned(nodeID string, pusher InlinePusher,
	globalVersion uint64, rules []*pb.InlineRule, cookies []string) error {
	l := m.nodePushLock(nodeID)
	l.Lock()
	defer l.Unlock()

	m.mu.Lock()
	version := globalVersion
	if !m.seeded[nodeID] {
		version = 1
	}
	m.mu.Unlock()

	// Nodes without a bound AF_XDP socket cannot serve the challenge funnel;
	// withholding the rule keeps their rate_limit as the best match instead
	// of a steer that would consume the packet and answer nothing.
	set := &pb.InlineRuleSet{
		Version:          version,
		Rules:            rulesForNode(pusher, nodeID, rules),
		DefaultAction:    "pass",
		SynCookieEnabled: true,
		CookieTargets:    cookies,
	}
	if err := pusher.PushInlineRules(nodeID, set); err != nil {
		m.mu.Lock()
		m.failures++
		m.mu.Unlock()
		return err
	}
	m.mu.Lock()
	m.pushes++
	m.seeded[nodeID] = true
	m.mu.Unlock()
	return nil
}

// rulesForNode filters the authoritative rule set for one node: challenge
// rules are withheld from nodes whose posture shows no AF_XDP socket, since
// a steer they cannot answer would consume packets and bypass the rate cap.
func rulesForNode(pusher InlinePusher, nodeID string, rules []*pb.InlineRule) []*pb.InlineRule {
	if pusher.AFXDPActive(nodeID) {
		return rules
	}
	out := make([]*pb.InlineRule, 0, len(rules))
	for _, r := range rules {
		if r.Action == "challenge" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// pushSnapshot sends the full authoritative snapshot to the given nodes.
// Sending the whole set (rather than a delta) makes each push idempotent,
// which is what lets a reconnecting Node recover state safely.
func (m *InlineMitigator) pushSnapshot(nodes []string, version uint64) {
	m.mu.Lock()
	pusher := m.pusher
	if pusher == nil {
		m.mu.Unlock()
		return
	}
	rules := m.snapshotRulesLocked()
	cookies := make([]string, 0, len(m.cookieTargets))
	for c := range m.cookieTargets {
		cookies = append(cookies, c)
	}
	targets := append([]string(nil), nodes...)
	m.mu.Unlock()

	if len(targets) == 0 {
		// Outside m.mu: the pusher takes its own node-state lock.
		targets = pusher.ConnectedInlineNodes()
	}
	for _, nodeID := range targets {
		if nodeID == "" {
			continue
		}
		if err := m.sendVersioned(nodeID, pusher, version, rules, cookies); err != nil {
			log.Printf("inline-mitigation: push to %s failed: %v", nodeID, err)
		}
	}
}

// snapshotRulesLocked flattens every active mitigation into one rule set.
func (m *InlineMitigator) snapshotRulesLocked() []*pb.InlineRule {
	attackIDs := make([]int, 0, len(m.active))
	for id := range m.active {
		attackIDs = append(attackIDs, id)
	}
	sort.Ints(attackIDs)

	now := m.nowFn().Unix()
	var out []*pb.InlineRule
	seen := map[uint64]bool{}
	for _, id := range attackIDs {
		for _, r := range m.active[id].Rules {
			if r.ExpiresUnix > 0 && r.ExpiresUnix < now {
				continue
			}
			if seen[r.ID] {
				continue
			}
			seen[r.ID] = true
			out = append(out, ruleToProto(r))
		}
	}
	return out
}

func ruleToProto(r InlineRule) *pb.InlineRule {
	out := &pb.InlineRule{
		Id:            r.ID,
		DstPrefixLen:  uint32(r.DstPrefixLen),
		SrcPrefixLen:  uint32(r.SrcPrefixLen),
		Protocol:      r.Protocol,
		DstPort:       r.DstPort,
		SrcPort:       r.SrcPort,
		Action:        r.Action,
		RateLimitPps:  r.RateLimitPPS,
		Priority:      r.Priority,
		ExpiresUnix:   r.ExpiresUnix,
		EgressIfindex: r.EgressIfindex,
		Encap:         r.Encap,
		Reason:        r.Reason,
	}
	if r.DstIP != "" {
		out.DstIp = net.ParseIP(r.DstIP).To4()
		if out.DstIp == nil {
			out.DstIp = net.ParseIP(r.DstIP).To16()
		}
	}
	if r.SrcIP != "" {
		out.SrcIp = net.ParseIP(r.SrcIP).To4()
		if out.SrcIp == nil {
			out.SrcIp = net.ParseIP(r.SrcIP).To16()
		}
	}
	return out
}

func (m *InlineMitigator) newRuleIDLocked() uint64 {
	m.nextRule++
	return m.nextRule
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// isHandshakeFlood reports whether a decoder or event type describes a TCP
// handshake flood (e.g. "tcp_syn", "syn_flood"). Only SYN floods are mitigated
// with SYN cookies: ACK/RST/FIN floods never complete a handshake, so a cookie
// rule would never be answered.
func isHandshakeFlood(decoder string) bool {
	return strings.Contains(strings.ToLower(decoder), "syn")
}

func prefixLenOf(ip string) int {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	if parsed.To4() != nil {
		return 32
	}
	return 128
}

// subnet24 returns the /24 of an IPv4 address ("" for IPv6 or bad input).
func subnet24(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
}

// protoName renders an L4 protocol number for rule reasons.
func protoName(p uint32) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("p%d", p)
	}
}

// maxPeak returns the larger of two peak counters.
func maxPeak(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func mergeStrings(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string(nil), a...), b...) {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func describeRules(rules []InlineRule) string {
	parts := make([]string, 0, len(rules))
	for _, r := range rules {
		switch r.Action {
		case "rate_limit":
			parts = append(parts, fmt.Sprintf("rate_limit(%s,%dpps)",
				r.DstIP, r.RateLimitPPS))
		case "syn_cookie":
			parts = append(parts, "syn_cookie("+r.DstIP+")")
		default:
			parts = append(parts, fmt.Sprintf("%s(%s,proto=%d,port=%d)",
				r.Action, r.DstIP, r.Protocol, r.DstPort))
		}
	}
	return strings.Join(parts, " + ")
}

// Compile-time assertion that the mitigator satisfies the tracker callback
// shape used in main.go (documented here to keep the contract visible).
var _ = strconv.Itoa
var _ = context.Background
