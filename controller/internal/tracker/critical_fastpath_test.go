package tracker

import (
	"net"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
)

// criticalRig wires a Tracker to an in-memory store and records emitted events.
type criticalRig struct {
	tk     *Tracker
	events []AttackEvent
}

func newCriticalRig(t *testing.T) *criticalRig {
	t.Helper()
	r := &criticalRig{}
	r.tk = New(
		Config{HardConfirmSeconds: 3, ExpiryIntervalSeconds: 60, MaxActiveAttacks: 100},
		&dao6Store{next: 100},
		ring.New(ring.Limits{MaxPointsPerIP: 120, MaxIPsPerPrefix: 10000, MaxGlobalKeys: 100000}),
		dedup.New(),
		func(e AttackEvent) { r.events = append(r.events, e) },
	)
	return r
}

func TestCriticalSignalCreatesActiveAttack(t *testing.T) {
	r := newCriticalRig(t)

	id, escalated := r.tk.FastTrackConfirm(CriticalSignal{
		NodeID:     "edge-a",
		TargetIP:   net.ParseIP("203.0.113.7"),
		Decoder:    "tcp",
		EventType:  "burst_emergency",
		AttackType: "syn_flood",
		CurrentPPS: 4_500_000,
		CurrentBPS: 2_000_000_000,
	})
	if id == 0 || !escalated {
		t.Fatalf("FastTrackConfirm = (%d, %v), want id>0 and escalated", id, escalated)
	}

	r.tk.mu.Lock()
	a := r.tk.attacks[attackKey{DstIP: "203.0.113.7", Direction: "receives", DecoderFamily: "tcp"}]
	r.tk.mu.Unlock()
	if a == nil {
		t.Fatal("attack not registered under its key")
	}
	if a.State != StateActive {
		t.Fatalf("state = %v, want Active", a.State)
	}
	if a.PeakPPS != 4_500_000 || a.PeakBPS != 2_000_000_000 {
		t.Fatalf("peaks = (%d, %d), want (4500000, 2000000000)", a.PeakPPS, a.PeakBPS)
	}
	if a.AttackType != "syn_flood" {
		t.Fatalf("attack type = %q, want syn_flood", a.AttackType)
	}
	if len(r.events) != 1 || r.events[0].Type != "confirmed" || r.events[0].DBID != id {
		t.Fatalf("events = %+v, want one confirmed event for id %d", r.events, id)
	}
}

func TestCriticalSignalRefreshesActiveWithoutDuplicateEvent(t *testing.T) {
	r := newCriticalRig(t)
	sig := CriticalSignal{
		NodeID: "edge-a", TargetIP: net.ParseIP("203.0.113.8"), Decoder: "udp", CurrentPPS: 1000,
	}
	first, _ := r.tk.FastTrackConfirm(sig)
	sig.CurrentPPS = 2500
	second, escalated := r.tk.FastTrackConfirm(sig)

	if second != first {
		t.Fatalf("second confirm id = %d, want %d", second, first)
	}
	if escalated {
		t.Fatal("refreshing an active attack must not emit a second confirmation")
	}
	if len(r.events) != 1 {
		t.Fatalf("events = %d, want 1", len(r.events))
	}
	r.tk.mu.Lock()
	a := r.tk.attacks[attackKey{DstIP: "203.0.113.8", Direction: "receives", DecoderFamily: "udp"}]
	r.tk.mu.Unlock()
	if a.PeakPPS != 2500 {
		t.Fatalf("peak pps = %d, want 2500 (refreshed)", a.PeakPPS)
	}
}

func TestCriticalSignalDefaultsDecoderAndRejectsNilIP(t *testing.T) {
	r := newCriticalRig(t)
	if id, ok := r.tk.FastTrackConfirm(CriticalSignal{NodeID: "n"}); id != 0 || ok {
		t.Fatalf("nil IP = (%d, %v), want (0, false)", id, ok)
	}
	id, ok := r.tk.FastTrackConfirm(CriticalSignal{
		NodeID: "n", TargetIP: net.ParseIP("198.51.100.9"), CurrentPPS: 10,
	})
	if id == 0 || !ok {
		t.Fatal("default decoder signal should still activate")
	}
	r.tk.mu.Lock()
	_, found := r.tk.attacks[attackKey{DstIP: "198.51.100.9", Direction: "receives", DecoderFamily: "ip"}]
	r.tk.mu.Unlock()
	if !found {
		t.Fatal("expected default decoder family \"ip\"")
	}
}

func TestCriticalSignalRepeatKeepsSingleAttack(t *testing.T) {
	r := newCriticalRig(t)
	sig := CriticalSignal{NodeID: "n", TargetIP: net.ParseIP("203.0.113.30"), Decoder: "udp", CurrentPPS: 5000}
	sig.At = time.Now()
	r.tk.FastTrackConfirm(sig)
	before := r.tk.CreatedTotal.Load()
	r.tk.FastTrackConfirm(sig)
	if got := r.tk.CreatedTotal.Load(); got != before {
		t.Fatalf("CreatedTotal = %d, want unchanged %d", got, before)
	}
	r.tk.mu.Lock()
	a := r.tk.attacks[attackKey{DstIP: "203.0.113.30", Direction: "receives", DecoderFamily: "udp"}]
	r.tk.mu.Unlock()
	if a == nil || a.State != StateActive {
		t.Fatal("attack should remain active")
	}
}

func TestCriticalSignalExpiringReactivationFiresRebreach(t *testing.T) {
	r := newCriticalRig(t)
	rebreached := 0
	r.tk.SetRebreachCallback(func(int) { rebreached++ })
	sig := CriticalSignal{NodeID: "n", TargetIP: net.ParseIP("203.0.113.40"), Decoder: "udp", CurrentPPS: 7000}
	id, _ := r.tk.FastTrackConfirm(sig)

	r.tk.mu.Lock()
	a := r.tk.attacks[attackKey{DstIP: "203.0.113.40", Direction: "receives", DecoderFamily: "udp"}]
	a.State = StateExpiring
	r.tk.mu.Unlock()

	again, escalated := r.tk.FastTrackConfirm(sig)
	if again != id || escalated {
		t.Fatalf("reactivation = (%d, %v), want (%d, false)", again, escalated, id)
	}
	if rebreached != 1 {
		t.Fatalf("rebreach callbacks = %d, want 1", rebreached)
	}
	r.tk.mu.Lock()
	state := r.tk.attacks[attackKey{DstIP: "203.0.113.40", Direction: "receives", DecoderFamily: "udp"}].State
	r.tk.mu.Unlock()
	if state != StateActive {
		t.Fatalf("state after reactivation = %v, want Active", state)
	}
}
