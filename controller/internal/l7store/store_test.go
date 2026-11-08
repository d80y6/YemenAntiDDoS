package l7store

import (
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/shared/l7"
)

func TestObserveAndSnapshot(t *testing.T) {
	s := New(10)
	now := time.Now()

	s.Observe("node-1", now.Add(-30*time.Second), "l7_http_flood", "198.51.100.7", map[string]uint64{
		l7.KeyHTTPRequests:   4200,
		"http_method:POST":   1,
		"http_path:/login":   1,
		"src:203.0.113.9":    1,
		l7.KeyWindowSeconds:  1,
		l7.KeyAlertThreshold: 2000,
	})
	s.Observe("node-1", now.Add(-20*time.Second), "l7_tls_anomaly", "198.51.100.7", map[string]uint64{
		l7.KeyHandshakes:   900,
		l7.KeyMissingSNI:   900,
		"src:203.0.113.10": 1,
	})
	s.Observe("node-2", now.Add(-10*time.Second), "l7_slowloris", "198.51.100.8", map[string]uint64{
		l7.KeySlowlorisConns: 61,
		l7.KeyUniqueSources:  61,
		"src:203.0.113.11":   1,
	})

	snap := s.Snapshot(15*time.Minute, now)
	if snap.Totals[KindHTTPFlood] != 1 || snap.Totals[KindTLSAnomaly] != 1 || snap.Totals[KindSlowloris] != 1 {
		t.Fatalf("unexpected totals: %+v", snap.Totals)
	}
	if len(snap.Targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(snap.Targets))
	}
	if snap.Targets[0].DstIP != "198.51.100.7" || snap.Targets[0].Total != 2 {
		t.Fatalf("target aggregation wrong: %+v", snap.Targets[0])
	}
	var http, tls, slow uint64
	for _, p := range snap.Series {
		http += p.HTTP
		tls += p.TLS
		slow += p.Slowloris
	}
	if http != 1 || tls != 1 || slow != 1 {
		t.Fatalf("series not recorded: %+v", snap.Series)
	}
	if len(snap.Recent) != 3 || snap.Recent[0].Type != KindSlowloris {
		t.Fatalf("recent ordering wrong: %+v", snap.Recent)
	}
	if snap.Recent[1].Detail.MissingSNI != 900 {
		t.Fatalf("detail parse wrong: %+v", snap.Recent[1].Detail)
	}
	if len(snap.Sources) != 3 {
		t.Fatalf("want 3 sources, got %d", len(snap.Sources))
	}
}

func TestWindowFiltersOldEvents(t *testing.T) {
	s := New(10)
	now := time.Now()
	s.Observe("node-1", now.Add(-2*time.Hour), "l7_http_flood", "198.51.100.7", nil)

	snap := s.Snapshot(14*time.Minute, now)
	if len(snap.Recent) != 0 {
		t.Fatalf("old event leaked into the window: %+v", snap.Recent)
	}
	if len(snap.Targets) != 0 {
		t.Fatalf("old target leaked into the window: %+v", snap.Targets)
	}
}

func TestRingIsBounded(t *testing.T) {
	s := New(8)
	now := time.Now()
	for i := 0; i < 50; i++ {
		s.Observe("node-1", now, "l7_http_flood", "198.51.100.7", nil)
	}
	events, dropped := s.Stats()
	if events > 8 {
		t.Fatalf("ring exceeded its bound: %d", events)
	}
	if dropped == 0 {
		t.Fatal("expected dropped counter to advance")
	}
}

func TestCounterKeysAlignWithCollectorWire(t *testing.T) {
	s := New(10)
	now := time.Now()

	// Flat counters spelled exactly as the Node collector emits them
	// (shared/l7 constants): a renamed key must not zero a Console field.
	s.Observe("node-1", now.Add(-5*time.Second), "l7_tls_anomaly", "198.51.100.9", map[string]uint64{
		l7.KeyHandshakes:       1200,
		l7.KeyMissingSNI:       1100,
		l7.KeySlowlorisConns:   77,
		l7.KeySlowlorisSources: 12,
	})

	snap := s.Snapshot(15*time.Minute, now)
	if len(snap.Recent) != 1 {
		t.Fatalf("recent = %d, want 1", len(snap.Recent))
	}
	d := snap.Recent[0].Detail
	if d.MissingSNI == 0 {
		t.Errorf("MissingSNI = 0, want %d (key %q)", 1100, l7.KeyMissingSNI)
	}
	if d.Connections == 0 {
		t.Errorf("Connections = 0, want %d (key %q)", 77, l7.KeySlowlorisConns)
	}
	if d.UniqueSources == 0 {
		t.Errorf("UniqueSources = 0, want %d (key %q)", 12, l7.KeySlowlorisSources)
	}
}
