package action

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

type d2R8LatencyStore struct {
	*d2Store
	queryLatency time.Duration
}

type d2R8LatencyRules struct {
	store.XDropActiveRuleRepo
	latency time.Duration
}

func (s *d2R8LatencyStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2R8LatencyRules{s.d2Store.XDropActiveRules(), s.queryLatency}
}

func (r d2R8LatencyRules) ListByAttack(ctx context.Context, id int) ([]store.XDropActiveRule, error) {
	// Model the delay from the round's tick to its locked attempt. Without
	// this offset, zero-cost queries would not exercise reconcile tolerance.
	time.Sleep(r.latency)
	return r.XDropActiveRuleRepo.ListByAttack(ctx, id)
}

func TestD2A_B29_BackoffWithHTTPLatency(t *testing.T) {
	t.Run("reconcile_latency", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			const interval = time.Second
			s, _, _ := d2Fixture(t, "failed")
			f := &d2R8LatencyStore{d2Store: s, queryLatency: interval / 20}
			e := NewEngine(f, "auto")
			start := time.Now()
			var mu sync.Mutex
			var stamps []time.Duration
			d2HTTP(t, func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodDelete {
					t.Errorf("method=%s want DELETE", r.Method)
				}
				mu.Lock()
				stamps = append(stamps, time.Since(start))
				mu.Unlock()
				time.Sleep(4 * interval / 10)
				return d2Reply(503, `{"code":"unavailable"}`), nil
			})
			stop := d2Start(t, e)
			defer stop()
			time.Sleep(23*interval + 3*interval/4)
			synctest.Wait()
			stop()
			synctest.Wait()
			mu.Lock()
			defer mu.Unlock()
			want := []time.Duration{0, interval, 3 * interval, 7 * interval, 15 * interval, 23 * interval}
			if len(stamps) != len(want) {
				t.Fatalf("attempt times=%v want offset %s + %v", stamps, f.queryLatency, want)
			}
			for i, at := range want {
				if stamps[i] != f.queryLatency+at {
					t.Errorf("attempt %d=%s want %s", i+1, stamps[i], f.queryLatency+at)
				}
			}
			d2Status(t, s, "failed")
		})
	})
	t.Run("event_strict", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, sa := d2Fixture(t, "active")
			var calls atomic.Int32
			var healthy atomic.Bool
			d2HTTP(t, func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				if healthy.Load() {
					return d2Reply(204, ""), nil
				}
				return d2Reply(503, `{"code":"unavailable"}`), nil
			})
			a := v3Attack(101, "udp", "198.51.100.7")
			rid := 1
			a.ResponseID = &rid
			entries := []struct {
				name string
				run  func()
			}{
				{"recovered", func() { e.executeRecoveredXDropUnblock(context.Background(), sa) }},
				{"normal", func() { d2Immediate(s, e, context.Background()) }},
				{"ended_event", func() { e.HandleEvent(tracker.AttackEvent{Type: "expired", DBID: 101, Attack: a}) }},
			}
			started := time.Now()
			e.executeRecoveredXDropUnblock(context.Background(), sa)
			synctest.Wait()
			if calls.Load() != 1 {
				t.Fatalf("initial DELETE=%d want 1", calls.Load())
			}
			d2Status(t, s, "failed")
			next := started.Add(d2DefaultI)
			time.Sleep(time.Until(next.Add(-d2DefaultI / 20)))
			for _, en := range entries {
				before := calls.Load()
				en.run()
				synctest.Wait()
				if delta := calls.Load() - before; delta != 0 {
					t.Errorf("%s inside reconcile slack bypassed strict event eligibility: +%d DELETE", en.name, delta)
				}
				d2Status(t, s, "failed")
			}
			healthy.Store(true)
			time.Sleep(time.Until(next))
			before := calls.Load()
			for _, en := range entries {
				en.run()
				synctest.Wait()
			}
			if delta := calls.Load() - before; delta != 1 {
				t.Errorf("at nextAttempt DELETE increment=%d want exactly 1", delta)
			}
			d2Status(t, s, "withdrawn")
		})
	})
}
