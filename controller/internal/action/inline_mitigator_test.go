package action

import (
	"sync"
	"testing"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
)

// recordingPusher captures every rule set pushed to each node.
type recordingPusher struct {
	mu     sync.Mutex
	byNode map[string][]*pb.InlineRuleSet
	nodes  []string
	fail   bool
}

func newRecordingPusher(nodes ...string) *recordingPusher {
	return &recordingPusher{byNode: make(map[string][]*pb.InlineRuleSet), nodes: nodes}
}

func (p *recordingPusher) PushInlineRules(nodeID string, rules *pb.InlineRuleSet) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errPush
	}
	p.byNode[nodeID] = append(p.byNode[nodeID], rules)
	return nil
}

func (p *recordingPusher) ConnectedInlineNodes() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.nodes...)
}

func (p *recordingPusher) last(nodeID string) *pb.InlineRuleSet {
	p.mu.Lock()
	defer p.mu.Unlock()
	list := p.byNode[nodeID]
	if len(list) == 0 {
		return nil
	}
	return list[len(list)-1]
}

func (p *recordingPusher) count(nodeID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byNode[nodeID])
}

type pushError string

func (e pushError) Error() string { return string(e) }

const errPush = pushError("node not connected")

func testMitigatorConfig(delay time.Duration) InlineMitigatorConfig {
	return InlineMitigatorConfig{
		Enabled:           true,
		BroadRateLimitPPS: 50_000,
		NarrowDelay:       delay,
		NarrowMinShare:    0.25,
		NarrowMaxPorts:    2,
		RebreathAfter:     time.Hour,
		RuleTTL:           time.Minute,
		TopSrcSubnets:     true,
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func TestInlineMitigatorBroadThenNarrow(t *testing.T) {
	pusher := newRecordingPusher("edge-a")
	m := NewInlineMitigator(testMitigatorConfig(40*time.Millisecond), pusher)

	flows := []FlowKey{
		{SrcIP: "203.0.113.1", DstIP: "198.51.100.10", DstPort: 443, Protocol: 6, Packets: 800},
		{SrcIP: "203.0.113.2", DstIP: "198.51.100.10", DstPort: 443, Protocol: 6, Packets: 100},
		{SrcIP: "203.0.113.3", DstIP: "198.51.100.10", DstPort: 80, Protocol: 6, Packets: 100},
	}
	start := time.Now()
	m.OnCritical(7, "198.51.100.10", "tcp", "burst_emergency", []string{"edge-a"}, 9000, flows)
	if elapsed := time.Since(start); elapsed >= 200*time.Millisecond {
		t.Fatalf("broad phase took %v, want <200ms (sub-second autonomous detection budget)", elapsed)
	}

	// Phase 1 must land immediately (well under 500ms).
	broad := pusher.last("edge-a")
	if broad == nil {
		t.Fatal("no broad rule set pushed")
	}
	if !hasAction(broad, "rate_limit") {
		t.Fatalf("broad rules %+v missing rate_limit", broad.Rules)
	}
	active, pushes, failures := m.Stats()
	if active != 1 || pushes != 1 || failures != 0 {
		t.Fatalf("stats = (%d,%d,%d), want (1,1,0)", active, pushes, failures)
	}

	// Phase 2 narrows to the dominant port once the delay elapses.
	waitFor(t, func() bool { return m.ActiveMitigations()[0].Phase == "narrow" })
	waitFor(t, func() bool { return pusher.count("edge-a") >= 2 })
	narrow := pusher.last("edge-a")
	if !hasDropOnPort(narrow, 443) {
		t.Fatalf("narrow rules %+v missing drop on dominant port 443", narrow.Rules)
	}
	if hasDropOnPort(narrow, 80) {
		t.Fatalf("narrow rules %+v must not drop the minority port 80", narrow.Rules)
	}
	if !hasAction(narrow, "rate_limit") {
		t.Fatal("narrow phase must retain a residual rate cap")
	}
}

func TestInlineMitigatorWithdrawClearsRules(t *testing.T) {
	pusher := newRecordingPusher("edge-a")
	m := NewInlineMitigator(testMitigatorConfig(time.Hour), pusher)
	m.OnCritical(9, "198.51.100.20", "udp", "burst_emergency", []string{"edge-a"}, 100, nil)
	if pusher.last("edge-a") == nil || len(pusher.last("edge-a").Rules) == 0 {
		t.Fatal("expected rules after activation")
	}
	m.Withdraw(9)
	last := pusher.last("edge-a")
	if last == nil || len(last.Rules) != 0 {
		t.Fatalf("withdraw pushed %+v, want empty rule set", last)
	}
	if active, _, _ := m.Stats(); active != 0 {
		t.Fatalf("active = %d, want 0", active)
	}
}

func TestInlineMitigatorReconcileSendsSnapshot(t *testing.T) {
	pusher := newRecordingPusher("edge-a", "edge-b")
	m := NewInlineMitigator(testMitigatorConfig(time.Hour), pusher)
	m.ProtectCookieTarget("198.51.100.0/24")
	m.OnCritical(11, "198.51.100.30", "tcp", "burst_emergency", []string{"edge-a"}, 500, nil)

	pusher.mu.Lock()
	pusher.byNode = map[string][]*pb.InlineRuleSet{}
	pusher.mu.Unlock()

	if err := m.Reconcile("edge-b"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	set := pusher.last("edge-b")
	if set == nil || len(set.Rules) == 0 {
		t.Fatalf("reconcile pushed %+v, want the active snapshot", set)
	}
	if !set.SynCookieEnabled || len(set.CookieTargets) != 1 {
		t.Fatalf("syn cookie config = (%v, %v)", set.SynCookieEnabled, set.CookieTargets)
	}
}

func TestInlineMitigatorPushFailureCounts(t *testing.T) {
	pusher := newRecordingPusher("edge-a")
	pusher.fail = true
	m := NewInlineMitigator(testMitigatorConfig(time.Hour), pusher)
	m.OnCritical(12, "198.51.100.40", "udp", "burst_emergency", []string{"edge-a"}, 500, nil)
	_, _, failures := m.Stats()
	if failures == 0 {
		t.Fatal("expected a push failure counter")
	}
}

func TestInlineMitigatorSurvivesNarrowWithoutEvidence(t *testing.T) {
	pusher := newRecordingPusher("edge-a")
	m := NewInlineMitigator(testMitigatorConfig(20*time.Millisecond), pusher)
	m.OnCritical(13, "198.51.100.50", "tcp", "burst_emergency", []string{"edge-a"}, 500, nil)
	// Give both narrowing attempts time to finish; the broad rule must remain.
	time.Sleep(200 * time.Millisecond)
	mit := m.ActiveMitigations()
	if len(mit) != 1 {
		t.Fatalf("mitigations = %d, want 1", len(mit))
	}
	if mit[0].Phase != "broad" {
		t.Fatalf("phase = %q, want broad (insufficient evidence keeps the broad rule)", mit[0].Phase)
	}
	last := pusher.last("edge-a")
	if !hasAction(last, "rate_limit") {
		t.Fatal("broad rate cap must remain when narrowing has no evidence")
	}
}

func TestInlineMitigatorRebreathCycle(t *testing.T) {
	pusher := newRecordingPusher("edge-a")
	cfg := testMitigatorConfig(10 * time.Millisecond)
	cfg.RebreathAfter = 20 * time.Millisecond
	m := NewInlineMitigator(cfg, pusher)

	flows := []FlowKey{
		{SrcIP: "203.0.113.1", DstIP: "198.51.100.60", DstPort: 443, Protocol: 6, Packets: 900},
		{SrcIP: "203.0.113.2", DstIP: "198.51.100.60", DstPort: 80, Protocol: 6, Packets: 100},
	}
	m.OnCritical(21, "198.51.100.60", "tcp", "burst_emergency", []string{"edge-a"}, 9000, flows)

	waitFor(t, func() bool {
		mit := m.ActiveMitigations()
		return len(mit) == 1 && mit[0].Rebreadths >= 1
	})
	// After a rebreath the phase must be broad again (and the cycle re-narrows).
	sawBroadAfterRebreath := false
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mit := m.ActiveMitigations()
		if len(mit) == 1 && mit[0].Rebreadths >= 1 {
			if mit[0].Phase == "broad" {
				sawBroadAfterRebreath = true
				break
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	if !sawBroadAfterRebreath {
		t.Fatal("never observed the broad phase after a rebreath")
	}

	m.Withdraw(21)
	waitFor(t, func() bool {
		last := pusher.last("edge-a")
		return last != nil && len(last.Rules) == 0
	})
	if active, _, _ := m.Stats(); active != 0 {
		t.Fatalf("active = %d after withdraw, want 0", active)
	}
}

func TestTopPortsShareAndCap(t *testing.T) {
	counts := map[uint32]uint64{443: 700, 80: 200, 53: 100}
	got := topPorts(counts, 1000, 0.15, 2)
	if len(got) != 2 || got[0].port != 443 || got[1].port != 80 {
		t.Fatalf("topPorts = %+v, want [443 80]", got)
	}
	if len(topPorts(map[uint32]uint64{1: 10}, 100, 0.5, 2)) != 0 {
		t.Fatal("ports below the minimum share must be excluded")
	}
}

func hasAction(set *pb.InlineRuleSet, action string) bool {
	if set == nil {
		return false
	}
	for _, r := range set.Rules {
		if r.GetAction() == action {
			return true
		}
	}
	return false
}

func hasDropOnPort(set *pb.InlineRuleSet, port uint32) bool {
	if set == nil {
		return false
	}
	for _, r := range set.Rules {
		if r.GetAction() == "drop" && r.GetDstPort() == port {
			return true
		}
	}
	return false
}

func TestNarrowEmitsSrcSubnetRules(t *testing.T) {
	pusher := newRecordingPusher("edge-a")
	m := NewInlineMitigator(testMitigatorConfig(20*time.Millisecond), pusher)
	flows := []FlowKey{
		{SrcIP: "203.0.113.7", DstPort: 443, Protocol: 6, Packets: 70},
		{SrcIP: "203.0.113.9", DstPort: 444, Protocol: 6, Packets: 30},
		{SrcIP: "198.51.100.5", DstPort: 80, Protocol: 6, Packets: 5},
	}
	m.OnCritical(60, "192.0.2.60", "tcp", "syn_flood", []string{"edge-a"}, 1000, flows)
	time.Sleep(150 * time.Millisecond)

	mit := m.ActiveMitigations()
	if len(mit) != 1 {
		t.Fatalf("mitigations = %d, want 1", len(mit))
	}
	if mit[0].Phase != "narrow" {
		t.Fatalf("phase = %q, want narrow", mit[0].Phase)
	}
	var subnetOK, minorityOK bool
	for _, r := range mit[0].Rules {
		if r.Action != "drop" {
			continue
		}
		if r.SrcPrefixLen == 24 && r.SrcIP == "203.0.113.0" {
			subnetOK = true
		}
		if r.SrcPrefixLen == 24 && r.SrcIP == "198.51.100.0" {
			minorityOK = true
		}
	}
	if !subnetOK {
		t.Fatalf("rules %+v missing drop for dominant source subnet 203.0.113.0/24", mit[0].Rules)
	}
	if minorityOK {
		t.Fatalf("rules %+v drop the minority source subnet 198.51.100.0/24", mit[0].Rules)
	}
}

func TestRebreathReNarrows(t *testing.T) {
	pusher := newRecordingPusher("edge-a")
	cfg := testMitigatorConfig(20 * time.Millisecond)
	cfg.RebreathAfter = 60 * time.Millisecond
	m := NewInlineMitigator(cfg, pusher)
	m.SetNarrowingSource(func(int) NarrowingInput {
		return NarrowingInput{TopFlows: []FlowKey{
			{SrcIP: "203.0.113.7", DstPort: 443, Protocol: 6, Packets: 90},
			{SrcIP: "198.51.100.5", DstPort: 80, Protocol: 6, Packets: 10},
		}}
	})

	// No seed flows: narrowing must come from the wired narrowing source, the
	// rebreath must re-broaden, and the next narrow attempt must re-narrow.
	m.OnCritical(61, "192.0.2.61", "tcp", "syn_flood", []string{"edge-a"}, 1000, nil)
	time.Sleep(300 * time.Millisecond)

	mit := m.ActiveMitigations()
	if len(mit) != 1 {
		t.Fatalf("mitigations = %d, want 1", len(mit))
	}
	if mit[0].Phase != "narrow" {
		t.Fatalf("phase = %q after rebreath, want narrow", mit[0].Phase)
	}
	if mit[0].Rebreadths < 1 {
		t.Fatalf("rebreadths = %d, want >= 1", mit[0].Rebreadths)
	}
}
