package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/engine/dedup"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
)

var dao5Fault = errors.New("dao5 injected database failure")

// Observe the public metric family, including on HEAD where it is absent.
// This keeps baseline-red tests compilable without adding metric behavior.
func dao5Metrics(t *testing.T, s store.Store, tk *tracker.Tracker) func(string) float64 {
	t.Helper()
	if tk == nil {
		tk = dao4Tracker(s, nil)
	}
	r := prometheus.NewRegistry()
	if err := metrics.Register(r, s, tk); err != nil {
		t.Fatal(err)
	}
	return func(op string) float64 {
		families, err := r.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range families {
			if f.GetName() == "xsight_state_write_failures_total" {
				for _, m := range f.Metric {
					for _, label := range m.Label {
						if label.GetName() == "op" && label.GetValue() == op {
							return m.GetCounter().GetValue()
						}
					}
				}
			}
		}
		return 0
	}
}

type dao5AttackStore struct {
	*MockStore
	r         *dao5Attacks
	threshold store.ThresholdRepo
}

func (s *dao5AttackStore) Attacks() store.AttackRepo { return s.r }
func (s *dao5AttackStore) Thresholds() store.ThresholdRepo {
	if s.threshold != nil {
		return s.threshold
	}
	return s.MockStore.Thresholds()
}

type dao5Attacks struct {
	store.AttackRepo
	mu                                               sync.Mutex
	createFailures, updateFailures, creates, updates int
	commitThenFail                                   bool
	updateTime                                       time.Duration
}

func (r *dao5Attacks) Create(ctx context.Context, a *store.Attack) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.mu.Lock()
	r.creates++
	fail := r.createFailures > 0
	if fail {
		r.createFailures--
	}
	commit := r.commitThenFail
	r.mu.Unlock()
	if fail && !commit {
		return 0, dao5Fault
	}
	id, err := r.AttackRepo.Create(ctx, a)
	if fail && err == nil {
		return 0, dao5Fault
	}
	return id, err
}
func (r *dao5Attacks) Update(ctx context.Context, a *store.Attack) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	r.updates++
	fail := r.updateFailures > 0
	if fail {
		r.updateFailures--
	}
	delay := r.updateTime
	r.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if fail {
		return dao5Fault
	}
	return r.AttackRepo.Update(ctx, a)
}
func (r *dao5Attacks) failUpdates(n int, delay time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.updateFailures, r.updateTime = n, delay
}
func (r *dao5Attacks) failCreates(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.createFailures = n
}
func (r *dao5Attacks) counts() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.creates, r.updates
}

type dao5ThresholdDeadline struct{ store.ThresholdRepo }

func (dao5ThresholdDeadline) Get(ctx context.Context, _ int) (*store.Threshold, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func dao5Tracker(t *testing.T, confirm int, commit bool) (*dao5AttackStore, *tracker.Tracker, *dedup.Dedup, *[]tracker.AttackEvent, func(string) float64) {
	t.Helper()
	ms := NewMockStore()
	r := &dao5Attacks{AttackRepo: ms.Attacks(), commitThenFail: commit}
	s := &dao5AttackStore{MockStore: ms, r: r}
	d := dedup.New()
	events := new([]tracker.AttackEvent)
	tk := tracker.New(tracker.Config{HardConfirmSeconds: confirm, MaxActiveAttacks: 1, ExpiryIntervalSeconds: 10}, s, nil, d, func(e tracker.AttackEvent) { *events = append(*events, e) })
	return s, tk, d, events, dao5Metrics(t, s, tk)
}
func TestDao5_A4a_CreateRetriesNextTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, tk, d, events, metric := dao5Tracker(t, 1, false)
		s.r.failCreates(1)
		before := metric("attack_create")
		created := tk.CreatedTotal.Load()
		tk.Feed(dao4Threshold(false))
		broad := dao4Threshold(false)[0]
		broad.Decoder = "ip"
		if len(*events) != 0 || tk.CreatedTotal.Load() != created || tk.EvictedTotal.Load() != 0 || d.ShouldSuppress(broad) {
			t.Errorf("failed Create caused side effects: events=%+v created=%d evicted=%d dedup=%v", *events, tk.CreatedTotal.Load(), tk.EvictedTotal.Load(), d.ShouldSuppress(broad))
		}
		if delta := metric("attack_create") - before; delta != 1 {
			t.Errorf("attack_create delta=%v; want 1", delta)
		}
		tk.Feed(dao4Threshold(false))
		if len(*events) != 1 || (*events)[0].Type != "confirmed" || (*events)[0].DBID <= 0 {
			t.Fatalf("retry confirmed=%+v; want one positive DBID", *events)
		}
	})
}
func TestDao5_A4b_FailedCreateDoesNotEvict(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, tk, _, events, _ := dao5Tracker(t, 1, false)
		tk.Feed(dao4Threshold(false))
		s.r.failCreates(1)
		dao4Evict(tk)
		row, err := s.Attacks().Get(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(*events) != 1 || row.EndedAt != nil || tk.EvictedTotal.Load() != 0 || tk.ActiveCount() != 1 {
			t.Fatalf("failed replacement evicted original: events=%+v ended=%v evictions=%d", *events, row.EndedAt, tk.EvictedTotal.Load())
		}
	})
}
func TestDao5_A4c_StoppedTrafficResetsConfirmation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, tk, _, events, _ := dao5Tracker(t, 2, false)
		s.r.failCreates(1)
		tk.Feed(dao4Threshold(false))
		tk.Feed(dao4Threshold(false))
		tk.Feed(nil)
		if len(*events) != 0 {
			t.Errorf("failed Create/stopped traffic emitted events: %+v", *events)
		}
		tk.Feed(dao4Threshold(false))
		if n, _ := s.r.counts(); n != 1 {
			t.Errorf("first fresh tick Create calls=%d; want 1 total", n)
		}
		tk.Feed(dao4Threshold(false))
		if n, _ := s.r.counts(); n != 2 {
			t.Errorf("confirmation did not restart: Create calls=%d; want 2", n)
		}
		if len(*events) != 1 || (*events)[0].DBID <= 0 {
			t.Fatalf("fresh confirmation=%+v", *events)
		}
	})
}
func TestDao5_A4d_CreateHasIndependentDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, tk, _, events, _ := dao5Tracker(t, 1, false)
		s.threshold = dao5ThresholdDeadline{}
		tk.Feed(dao4Threshold(false))
		if len(*events) != 1 || (*events)[0].DBID <= 0 {
			t.Fatalf("threshold used deadline; confirmed=%+v; want persisted attack", *events)
		}
	})
}
func TestDao5_A4e_CommittedResponseLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, tk, _, events, _ := dao5Tracker(t, 1, true)
		s.r.failCreates(1)
		tk.Feed(dao4Threshold(false))
		tk.Feed(dao4Threshold(false))
		rows, err := s.Attacks().ListActive(context.Background(), 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || len(*events) != 1 || (*events)[0].DBID != rows[0].ID {
			t.Fatalf("lost response: rows=%+v confirmed=%+v; want one shared ID", rows, *events)
		}
	})
}
func dao5UpdateCase(t *testing.T, failures int, delay time.Duration, op string) {
	t.Helper()
	for _, kind := range []string{"expired", "evicted"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, tk, _, events, metric := dao5Tracker(t, 1, false)
				tk.Feed(dao4Threshold(false))
				s.r.failUpdates(failures, delay)
				label := "attack_update_" + kind
				before, start := metric(label), time.Now()
				if kind == "expired" {
					if !tk.ForceExpire(1) {
						t.Fatal("missing attack")
					}
				} else {
					dao4Evict(tk)
				}
				row, err := s.Attacks().Get(context.Background(), 1)
				if err != nil {
					t.Fatal(err)
				}
				n := 0
				for _, e := range *events {
					if e.Type == kind {
						n++
					}
				}
				if n != 1 {
					t.Errorf("%s events=%d; want 1", kind, n)
				}
				_, calls := s.r.counts()
				wantCalls := 2
				if failures == 0 {
					wantCalls = 1
				}
				if calls != wantCalls {
					t.Errorf("Update calls=%d; want %d", calls, wantCalls)
				}
				if failures < 2 && row.EndedAt == nil {
					t.Errorf("ended_at missing after %s", op)
				}
				wantDelta := float64(0)
				if failures == 2 {
					wantDelta = 1
				}
				if delta := metric(label) - before; delta != wantDelta {
					t.Errorf("%s delta=%v; want %v", label, delta, wantDelta)
				}
				if elapsed := time.Since(start); elapsed != delay {
					t.Errorf("retry inserted wait or changed deadline: elapsed=%v; want %v", elapsed, delay)
				}
			})
		})
	}
}
func TestDao5_A8a_UpdateRecovers(t *testing.T)        { dao5UpdateCase(t, 1, 0, "one failure") }
func TestDao5_A8b_UpdateFailuresVisible(t *testing.T) { dao5UpdateCase(t, 2, 0, "persistent failure") }
func TestDao5_A8c_FirstAttemptKeepsFiveSeconds(t *testing.T) {
	dao5UpdateCase(t, 0, 3*time.Second, "slow success")
}
