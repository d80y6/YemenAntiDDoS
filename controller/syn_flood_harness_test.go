package main

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/d80y6/YemenDDoS/shared/cookie"
)

// --- inline pusher recorder -------------------------------------------------

type fakeInlinePusher struct {
	nodes   []string
	pushes  int
	lastLen int
}

func (p *fakeInlinePusher) PushInlineRules(nodeID string, rules *pb.InlineRuleSet) error {
	p.pushes++
	p.lastLen = len(rules.GetRules())
	return nil
}
func (p *fakeInlinePusher) ConnectedInlineNodes() []string { return p.nodes }

// --- minimal store (same pattern as tracker's dao6Store) -------------------

type harnessStore struct {
	store.Store
	next int64
}

type harnessAttackRepo struct {
	store.AttackRepo
	s *harnessStore
}

func (s *harnessStore) Attacks() store.AttackRepo { return harnessAttackRepo{s: s} }
func (r harnessAttackRepo) Create(context.Context, *store.Attack) (int, error) {
	return int(atomic.AddInt64(&r.s.next, 1)), nil
}
func (r harnessAttackRepo) Update(context.Context, *store.Attack) error { return nil }

// TestSynFloodHarnessFastPath runs the acceptance path for the synthetic
// 10Gbps/14.88Mpps SYN flood without needing a kernel:
//
//	100ms burst window → CriticalEvent(burst_emergency) → isFastPathEvent
//	gate → tracker.FastTrackConfirm → Active + inline broad rules
//	(rate_limit + syn_cookie), with the <200ms escalation and <500ms
//	rule-land budgets asserted on the wall clock.
func TestSynFloodHarnessFastPath(t *testing.T) {
	// Synthetic flood: 64-byte frames at 10Gbps is 14.88 Mpps; one 100ms
	// burst window carries ~1.488M packets.
	const burstPerTick = uint64(1_488_000)
	target := "198.51.100.7"

	// --- 1. CriticalEvent as the Node's ringbuf consumer emits it ---------
	ev := &pb.CriticalEvent{
		NodeId:      "edge-a",
		TimestampNs: time.Now().UnixNano(),
		TargetIp:    net.ParseIP(target).To4(),
		Decoder:     "tcp",
		EventType:   "burst_emergency",
		AttackType:  "syn_flood",
		CurrentPps:  burstPerTick,
		CurrentBps:  burstPerTick * 84 * 8,
	}
	if !isFastPathEvent(ev) {
		t.Fatal("burst_emergency must pass the fast-path gate")
	}
	if len(ev.GetTargetIp()) != 4 {
		t.Fatalf("target ip = %v, want IPv4 bytes", ev.GetTargetIp())
	}

	// --- 2. tracker escalation (<200ms budget) -----------------------------
	sig := buildCriticalSignal("edge-a", target, ev)
	tk := tracker.New(
		tracker.Config{HardConfirmSeconds: 3, ExpiryIntervalSeconds: 60, MaxActiveAttacks: 100},
		&harnessStore{},
		ring.New(ring.Limits{MaxPointsPerIP: 120, MaxIPsPerPrefix: 10000, MaxGlobalKeys: 100000}),
		dedup.New(),
		func(tracker.AttackEvent) {},
	)
	start := time.Now()
	id, escalated := tk.FastTrackConfirm(sig)
	elapsed := time.Since(start)
	if !escalated || id == 0 {
		t.Fatalf("FastTrackConfirm = (%d, %v), want active attack", id, escalated)
	}
	if elapsed >= 200*time.Millisecond {
		t.Fatalf("escalation took %v, want <200ms", elapsed)
	}

	// --- 3. inline broad rules land (<500ms budget) -----------------------
	pusher := &fakeInlinePusher{nodes: []string{"edge-a"}}
	cfg := action.DefaultInlineMitigatorConfig()
	cfg.Enabled = true
	cfg.NarrowDelay = time.Hour // pin phase 1 for this assertion
	mitigator := action.NewInlineMitigator(cfg, pusher)
	start = time.Now()
	mitigator.OnCritical(id, target, "tcp", "syn_flood",
		[]string{"edge-a"}, burstPerTick, harnessSynFlows(target, 500))
	if landed := time.Since(start); landed >= 500*time.Millisecond {
		t.Fatalf("inline rules took %v to push, want <500ms", landed)
	}
	if pusher.pushes != 1 || pusher.lastLen == 0 {
		t.Fatalf("pushes=%d rules=%d, want a non-empty broad set", pusher.pushes, pusher.lastLen)
	}
	mit := mitigatorList(mitigator)
	if len(mit) != 1 || mit[0].Phase != "broad" {
		t.Fatalf("mitigation = %+v, want one broad phase", mit)
	}
	if !hasActionNamed(mit, "syn_cookie") {
		t.Fatal("SYN flood must install a syn_cookie rule in the broad phase")
	}

	// --- 4. continued flood: refresh, no duplicate attacks, one mitigator -
	before := tk.CreatedTotal.Load()
	for i := 0; i < 9; i++ { // remaining 900ms of the flood at 100ms ticks
		tk.FastTrackConfirm(sig)
		mitigator.OnCritical(id, target, "tcp", "syn_flood",
			[]string{"edge-a"}, burstPerTick, nil)
	}
	if got := tk.CreatedTotal.Load(); got != before {
		t.Fatalf("sustained flood created %d extra attack rows, want 0", got-before)
	}
	if active, _, _ := mitigator.Stats(); active != 1 {
		t.Fatalf("active mitigations = %d, want 1 through the flood", active)
	}
}

// TestSynFloodCookieStatelessness checks the stateless half of the acceptance
// criteria: cookie validation depends only on the tuple, so a flood of spoofed
// SYNs allocates no per-source state — every handshake either presents the
// exact cookie for its tuple or is rejected, identically on repeat calls.
func TestSynFloodCookieStatelessness(t *testing.T) {
	var sip, dip [16]byte
	copy(sip[:], net.ParseIP("203.0.113.9").To4())
	copy(dip[:], net.ParseIP("198.51.100.7").To4())
	const lo, hi = uint64(0x0123456789abcdef), uint64(0xfedcba9876543210)

	seen := map[uint32]int{}
	for i := 0; i < 1000; i++ {
		sport := uint16(1024 + i%64000)
		isn := cookie.ISN(lo, hi, sip, dip, sport, 443)
		seen[isn]++
		if !cookie.ValidAck(isn, isn+1) {
			t.Fatalf("cookie for sport %d rejected by its own handshake", sport)
		}
		if cookie.ValidAck(isn, isn+2) {
			t.Fatal("forged ACK accepted")
		}
		// Deterministic — pure function of (secret, tuple), no hidden state.
		if again := cookie.ISN(lo, hi, sip, dip, sport, 443); again != isn {
			t.Fatalf("cookie not deterministic: %x vs %x", isn, again)
		}
	}
	// 32-bit truncated siphash over 1000 distinct ports: birthday collisions
	// are negligible (~0.01%), so nearly all ISNs must be distinct.
	if len(seen) < 990 {
		t.Fatalf("only %d distinct ISNs over 1000 syns — cookie entropy too low", len(seen))
	}
}

// --- helpers ---------------------------------------------------------------

func buildCriticalSignal(nodeID, target string, ev *pb.CriticalEvent) tracker.CriticalSignal {
	return tracker.CriticalSignal{
		NodeID:     nodeID,
		TargetIP:   net.ParseIP(target),
		Decoder:    ev.GetDecoder(),
		EventType:  ev.GetEventType(),
		AttackType: ev.GetAttackType(),
		CurrentPPS: ev.GetCurrentPps(),
		CurrentBPS: ev.GetCurrentBps(),
		At:         time.Now(),
	}
}

// harnessSynFlows builds dominant-port flow evidence for a SYN flood
// (handshake traffic on 443 from spoofed sources).
func harnessSynFlows(target string, n int) []action.FlowKey {
	flows := make([]action.FlowKey, 0, n)
	for i := 0; i < n; i++ {
		flows = append(flows, action.FlowKey{
			SrcIP:    fmt.Sprintf("203.0.113.%d", i%256),
			DstIP:    target,
			DstPort:  443,
			Protocol: 6,
			Packets:  30,
		})
	}
	return flows
}

func mitigatorList(m *action.InlineMitigator) []action.InlineMitigation {
	return m.ActiveMitigations()
}

func hasActionNamed(mit []action.InlineMitigation, action string) bool {
	for _, m := range mit {
		for _, r := range m.Rules {
			if r.Action == action {
				return true
			}
		}
	}
	return false
}
