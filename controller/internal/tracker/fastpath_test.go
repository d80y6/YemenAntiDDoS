package tracker

import (
	"net"
	"sync"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
)

func fastPathEvent(actual int64) []engine.ThresholdExceeded {
	rid := 7
	return []engine.ThresholdExceeded{{
		DstIP: net.ParseIP("192.0.2.10"), Prefix: "192.0.2.0/24",
		Direction: "receives", Decoder: "udp", Unit: "pps",
		Value: 10000, Actual: actual, ResponseID: &rid, NodeID: "n1",
	}}
}

func TestFastPathConfirmsOnFirstFeed(t *testing.T) {
	var mu sync.Mutex
	var events []string
	tk := New(Config{
		HardConfirmSeconds: 5, DynamicConfirmSeconds: 5, ExpiryIntervalSeconds: 300,
		FastPathMultiplier: 5,
	}, &dao6Store{}, nil, dedup.New(), func(e AttackEvent) {
		mu.Lock()
		events = append(events, e.Type)
		mu.Unlock()
	})

	tk.Feed(fastPathEvent(60000)) // 6x the threshold

	if got := tk.ActiveCount(); got != 1 {
		t.Fatalf("expected the attack active after one feed, got %d", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) == 0 || events[0] != "confirmed" {
		t.Fatalf("events=%v", events)
	}
}

func TestFastPathDisabledWaitsForConfirmWindow(t *testing.T) {
	tk := New(Config{
		HardConfirmSeconds: 5, DynamicConfirmSeconds: 5, ExpiryIntervalSeconds: 300,
		FastPathMultiplier: 0, // disabled
	}, &dao6Store{}, nil, dedup.New(), nil)

	for i := 0; i < 4; i++ {
		tk.Feed(fastPathEvent(1_000_000)) // still must not confirm early
		if got := tk.ActiveCount(); got != 0 {
			t.Fatalf("confirmed after %d ticks with fast path disabled", i+1)
		}
	}
	tk.Feed(fastPathEvent(1_000_000))
	if got := tk.ActiveCount(); got != 1 {
		t.Fatalf("expected confirmation on the fifth tick, got %d", got)
	}
}

func TestBelowMultiplierWaitsForConfirmWindow(t *testing.T) {
	tk := New(Config{
		HardConfirmSeconds: 5, DynamicConfirmSeconds: 5, ExpiryIntervalSeconds: 300,
		FastPathMultiplier: 5,
	}, &dao6Store{}, nil, dedup.New(), nil)

	tk.Feed(fastPathEvent(40000)) // 4x, below the 5x fast path
	if got := tk.ActiveCount(); got != 0 {
		t.Fatalf("4x must not trigger the fast path, active=%d", got)
	}
}
