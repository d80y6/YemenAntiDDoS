package action

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Faults are changed only at synctest barriers. No listener or real DB is used.
type d2FaultStore struct {
	*d2Store
	listErr, ruleErr, liveErr, overrideErr, scheduleErr atomic.Bool
	completeFaults, logFaults, failedFaults             int
	completeCalls, logCalls, failedCalls                int
	override                                            atomic.Bool
	faultMu                                             sync.Mutex
	activeSnapshot                                      []store.XDropActiveRule
}
type d2FaultRules struct {
	d2Rules
	f *d2FaultStore
}
type d2FaultSchedules struct {
	d2Schedules
	f *d2FaultStore
}
type d2FaultLogs struct {
	v3Logs
	f *d2FaultStore
}
type d2FaultAttacks struct {
	d2Attacks
	f *d2FaultStore
}
type d2FaultOverrides struct {
	v3Overrides
	f *d2FaultStore
}
type d2EmptyAnns struct{ td104EmptyBGP }

func (d2EmptyAnns) ListActive(context.Context) ([]store.BGPAnnouncement, error) { return nil, nil }
func (s *d2FaultStore) BGPAnnouncements() store.BGPAnnouncementRepo             { return d2EmptyAnns{} }
func (s *d2FaultStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2FaultRules{d2Rules{v3Active{s: s.v3Store}, s.d2Store}, s}
}
func (s *d2FaultStore) ScheduledActions() store.ScheduledActionRepo {
	return d2FaultSchedules{d2Schedules{v3Schedules{s: s.v3Store}}, s}
}
func (s *d2FaultStore) ActionExecLog() store.ActionExecLogRepo {
	return d2FaultLogs{v3Logs{s: s.v3Store}, s}
}
func (s *d2FaultStore) Attacks() store.AttackRepo { return d2FaultAttacks{d2Attacks{d: s.d2Store}, s} }
func (s *d2FaultStore) ManualOverrides() store.ActionManualOverrideRepo {
	return d2FaultOverrides{v3Overrides{s: s.v3Store}, s}
}
func (r d2FaultRules) ListActive(c context.Context) ([]store.XDropActiveRule, error) {
	if r.f.listErr.Load() {
		return nil, errors.New("injected list failure")
	}
	r.f.faultMu.Lock()
	defer r.f.faultMu.Unlock()
	if r.f.activeSnapshot != nil {
		return append([]store.XDropActiveRule(nil), r.f.activeSnapshot...), nil
	}
	return r.d2Rules.ListActive(c)
}
func (r d2FaultRules) ListByAttack(c context.Context, id int) ([]store.XDropActiveRule, error) {
	if r.f.ruleErr.Load() {
		return nil, errors.New("injected locked read failure")
	}
	return r.d2Rules.ListByAttack(c, id)
}
func (r d2FaultRules) MarkFailed(c context.Context, a, b, d int, id, msg string) error {
	r.f.failedCalls++
	if r.f.failedFaults > 0 {
		r.f.failedFaults--
		return errors.New("injected MarkFailed failure")
	}
	return r.d2Rules.MarkFailed(c, a, b, d, id, msg)
}
func (r d2FaultSchedules) ListPending(c context.Context) ([]store.ScheduledAction, error) {
	if r.f.scheduleErr.Load() {
		return nil, errors.New("injected schedule query failure")
	}
	return r.d2Schedules.ListPending(c)
}
func (r d2FaultSchedules) Complete(c context.Context, id int) error {
	r.f.completeCalls++
	if r.f.completeFaults > 0 {
		r.f.completeFaults--
		return errors.New("injected Complete failure")
	}
	return r.d2Schedules.Complete(c, id)
}
func (r d2FaultSchedules) Cancel(_ context.Context, id int, _ string) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.schedules {
		if r.s.schedules[i].ID == id && r.s.schedules[i].Status == "pending" {
			r.s.schedules[i].Status = "cancelled"
		}
	}
	return nil
}
func (r d2FaultLogs) Create(c context.Context, row *store.ActionExecutionLog) (int, error) {
	r.f.logCalls++
	if r.f.logFaults > 0 {
		r.f.logFaults--
		return 0, errors.New("injected log failure")
	}
	return r.v3Logs.Create(c, row)
}
func (r d2FaultAttacks) LiveIDs(c context.Context, ids []int) (map[int]bool, error) {
	if r.f.liveErr.Load() {
		return nil, errors.New("injected live query failure")
	}
	return r.d2Attacks.LiveIDs(c, ids)
}
func (r d2FaultOverrides) ListByAttack(c context.Context, id int) ([]store.ActionManualOverride, error) {
	if r.f.overrideErr.Load() {
		return nil, errors.New("injected override query failure")
	}
	if r.f.override.Load() {
		return []store.ActionManualOverride{{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: "rule-draft"}}, nil
	}
	return r.v3Overrides.ListByAttack(c, id)
}
func d2FaultFixture(t *testing.T, status string) (*d2FaultStore, *Engine, store.ScheduledAction) {
	s, _, sa := d2Fixture(t, status)
	f := &d2FaultStore{d2Store: s}
	return f, NewEngine(f, "auto"), sa
}
func d2Metric(op string) float64 {
	return testutil.ToFloat64(metrics.StateWriteFailures.WithLabelValues(op))
}
func d2SeedSchedule(t *testing.T, s *d2FaultStore, sa store.ScheduledAction, executing bool) store.ScheduledAction {
	t.Helper()
	sa.ScheduledFor = time.Now().Add(-time.Minute)
	var err error
	sa.ID, err = s.ScheduledActions().Schedule(context.Background(), &sa)
	if err != nil {
		t.Fatal(err)
	}
	if executing {
		if err = s.ScheduledActions().MarkExecuting(context.Background(), sa.ID); err != nil {
			t.Fatal(err)
		}
	}
	return sa
}

func TestD2A_B06_WriteFailuresSupplement(t *testing.T) {
	for _, kind := range []string{"log_once", "schedule_exhausted", "mark_failed_exhausted"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, sa := d2FaultFixture(t, "active")
				code, op := 204, "xdrop_exec_log"
				switch kind {
				case "log_once":
					s.logFaults = 1
				case "schedule_exhausted":
					s.completeFaults = 3
					op = "xdrop_schedule_finish"
					sa = d2SeedSchedule(t, s, sa, false)
				case "mark_failed_exhausted":
					s.failedFaults = 3
					op = "xdrop_mark_failed"
					code = 503
				}
				before := d2Metric(op)
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return d2Reply(code, `{"code":"unavailable"}`), nil
				})
				e.executeRecoveredXDropUnblock(context.Background(), sa)
				if calls.Load() != 1 || d2Metric(op)-before != 1 {
					t.Fatalf("HTTP=%d metric delta=%v", calls.Load(), d2Metric(op)-before)
				}
				if kind == "mark_failed_exhausted" {
					d2Status(t, s.d2Store, "withdrawing")
					if s.failedCalls != 3 || d2LogCount(s.d2Store, "success") != 0 {
						t.Fatal("failed-state write budget or false success")
					}
				} else {
					d2Status(t, s.d2Store, "withdrawn")
					if kind == "log_once" && s.logCalls != 1 {
						t.Fatal("log insertion retried")
					}
					if kind == "schedule_exhausted" {
						if s.completeCalls != 3 || d2SchedStatus(s.d2Store, sa.ID) != "pending" || d2LogCount(s.d2Store, "success") != 0 {
							t.Fatal("schedule lost or false success")
						}
						stop := d2Start(t, e)
						defer stop()
						if calls.Load() != 1 || d2SchedStatus(s.d2Store, sa.ID) != "completed" {
							t.Fatal("terminal schedule repair repeated HTTP or failed")
						}
					}
				}
			})
		})
	}
}

func TestD2A_B12_ExactBackoffAndListFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _ := d2FaultFixture(t, "failed")
		start := time.Now()
		var stamps []time.Duration
		d2HTTP(t, func(*http.Request) (*http.Response, error) {
			stamps = append(stamps, time.Since(start))
			return d2Reply(503, `{"code":"unavailable"}`), nil
		})
		stop := d2Start(t, e)
		defer stop()
		for sec := 1; sec <= 31; sec++ {
			// A failed enumeration between 7I and 15I must not reset 8I backoff.
			s.listErr.Store(sec >= 8 && sec <= 14)
			time.Sleep(time.Second)
			synctest.Wait()
		}
		want := []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second, 15 * time.Second, 23 * time.Second, 31 * time.Second}
		if len(stamps) != len(want) {
			t.Fatalf("attempt times=%v want=%v", stamps, want)
		}
		for i := range want {
			if stamps[i] != want[i] {
				t.Fatalf("attempt %d=%v want %v", i, stamps[i], want[i])
			}
		}
		d2Status(t, s.d2Store, "failed")
	})
}

func TestD2A_B13_ScheduleRecoverySupplement(t *testing.T) {
	for _, kind := range []string{"lost_executing", "withdrawn_pending", "withdrawn_executing"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				status := "delayed"
				wantHTTP := int32(1)
				if kind != "lost_executing" {
					status = "withdrawn"
					wantHTTP = 0
				}
				s, e, sa := d2FaultFixture(t, status)
				sa = d2SeedSchedule(t, s, sa, kind != "withdrawn_pending")
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
				stop := d2Start(t, e)
				defer stop()
				if calls.Load() != wantHTTP || d2SchedStatus(s.d2Store, sa.ID) != "completed" {
					t.Fatalf("HTTP=%d schedule=%s", calls.Load(), d2SchedStatus(s.d2Store, sa.ID))
				}
				d2Status(t, s.d2Store, "withdrawn")
			})
		})
	}
}

func TestD2A_B17_SafetySupplement(t *testing.T) {
	for _, kind := range []string{"override", "override_query", "live_query", "locked_rule_query", "schedule_query", "ending_inflight"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, _ := d2FaultFixture(t, "active")
				s.override.Store(kind == "override")
				s.overrideErr.Store(kind == "override_query")
				s.liveErr.Store(kind == "live_query")
				s.ruleErr.Store(kind == "locked_rule_query")
				s.scheduleErr.Store(kind == "schedule_query")
				if kind == "ending_inflight" {
					e.endAction(101, 1)
				}
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
				stop := d2Start(t, e)
				defer stop()
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if calls.Load() != 0 {
					t.Fatal("unsafe HTTP")
				}
				d2Status(t, s.d2Store, "active")
				s.override.Store(false)
				s.overrideErr.Store(false)
				s.liveErr.Store(false)
				s.ruleErr.Store(false)
				s.scheduleErr.Store(false)
				if kind == "ending_inflight" {
					e.endAction(101, -1)
				}
				time.Sleep(time.Second)
				synctest.Wait()
				if calls.Load() != 1 {
					t.Fatalf("next round calls=%d", calls.Load())
				}
				d2Status(t, s.d2Store, "withdrawn")
			})
		})
	}
}

func TestD2A_B18_CleanupAndDueWorker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, sa := d2FaultFixture(t, "active")
		snapshot, _ := s.XDropActiveRules().ListActive(context.Background())
		gate := make(chan struct{})
		var calls atomic.Int32
		d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); <-gate; return d2Reply(204, ""), nil })
		stop := d2Start(t, e)
		defer stop()
		if calls.Load() != 1 {
			close(gate)
			t.Fatal("runtime did not reach HTTP barrier")
		}
		// Cleanup obtained an active snapshot before the runtime claim.
		s.faultMu.Lock()
		s.activeSnapshot = snapshot
		s.faultMu.Unlock()
		cleanupDone := make(chan struct{})
		go func() {
			e.CleanupEndedAttachments(context.Background(), StartupScheduleSnapshot{}, nil)
			close(cleanupDone)
		}()
		synctest.Wait()
		// The due worker already owns its persistent schedule but waits for this row.
		sa = d2SeedSchedule(t, s, sa, false)
		dueDone := make(chan struct{})
		go func() { e.runRecoveredAction(sa, 0); close(dueDone) }()
		synctest.Wait()
		e.xdropMu.Lock()
		refs := e.xdropLocks[xdropKeyFromSchedule(sa).String()].refs
		e.xdropMu.Unlock()
		if refs < 3 {
			close(gate)
			t.Fatalf("device: expected runtime + cleanup + due worker, refs=%d", refs)
		}
		if calls.Load() != 1 {
			t.Error("contender bypassed lock")
		}
		close(gate)
		synctest.Wait()
		<-cleanupDone
		<-dueDone
		if calls.Load() != 1 || d2SchedStatus(s.d2Store, sa.ID) != "completed" {
			t.Fatalf("HTTP=%d schedule=%s", calls.Load(), d2SchedStatus(s.d2Store, sa.ID))
		}
		d2Status(t, s.d2Store, "withdrawn")
	})
}

func TestD2A_B22_ScheduleRereadSupplement(t *testing.T) {
	for _, kind := range []string{"query_failure", "cancelled", "wrong_id", "wrong_key"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, sa := d2FaultFixture(t, "active")
				sa = d2NoRowSchedule(t, s.d2Store, sa, time.Now().Add(-time.Minute), false)
				original := sa
				switch kind {
				case "query_failure":
					s.scheduleErr.Store(true)
				case "cancelled":
					if err := s.ScheduledActions().Cancel(context.Background(), sa.ID, "test"); err != nil {
						t.Fatal(err)
					}
				case "wrong_id":
					sa.ID++
				case "wrong_key":
					sa.ActionID++
				}
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
				e.executeRecoveredXDropUnblock(context.Background(), sa)
				want := "pending"
				if kind == "cancelled" {
					want = "cancelled"
				}
				if calls.Load() != 0 || d2SchedStatus(s.d2Store, original.ID) != want || len(s.logSnapshot()) != 0 {
					t.Fatal("stale/unknown schedule had side effects")
				}
				if kind == "query_failure" {
					s.scheduleErr.Store(false)
					stop := d2Start(t, e)
					defer stop()
					if calls.Load() != 1 || d2SchedStatus(s.d2Store, original.ID) != "completed" {
						t.Fatal("next round did not take over")
					}
				}
				if rows, _ := s.XDropActiveRules().ListByAttack(context.Background(), 101); len(rows) != 0 {
					t.Fatal("fabricated rule row")
				}
			})
		})
	}
}

func TestD2A_B18_LockLifetime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, e, sa := d2Fixture(t, "active")
		k := xdropKeyFromSchedule(sa)
		unlock, ok := e.lockXDrop(context.Background(), k, false)
		if !ok {
			t.Fatal("first owner")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancelled := make(chan struct{})
		go func() {
			if release, ok := e.lockXDrop(ctx, k, false); ok {
				release()
				t.Error("cancelled waiter acquired")
			}
			close(cancelled)
		}()
		acquired, releaseSecond, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() {
			release, ok := e.lockXDrop(context.Background(), k, false)
			if !ok {
				t.Error("second waiter lost")
			}
			close(acquired)
			<-releaseSecond
			if ok {
				release()
			}
			close(done)
		}()
		synctest.Wait()
		e.xdropMu.Lock()
		original := e.xdropLocks[k.String()]
		refs := original.refs
		e.xdropMu.Unlock()
		if refs != 3 {
			t.Fatalf("holder + waiters=%d", refs)
		}
		cancel()
		<-cancelled
		e.xdropMu.Lock()
		same := e.xdropLocks[k.String()] == original
		e.xdropMu.Unlock()
		if !same {
			t.Error("cancelled waiter removed a live lock")
		}
		unlock()
		<-acquired
		if release, ok := e.lockXDrop(context.Background(), k, true); ok {
			release()
			t.Error("new arrival rebuilt lock while old waiter held it")
		}
		close(releaseSecond)
		<-done
		e.xdropMu.Lock()
		remaining := len(e.xdropLocks)
		e.xdropMu.Unlock()
		if remaining != 0 {
			t.Fatalf("unused lock retained: %d", remaining)
		}
	})
}

func TestD2A_B11_ReenableClearsBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _ := d2Fixture(t, "failed")
		var calls, code atomic.Int32
		code.Store(503)
		d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(int(code.Load()), ""), nil })
		stop := d2Start(t, e)
		defer stop()
		time.Sleep(7100 * time.Millisecond)
		synctest.Wait()
		if calls.Load() != 4 {
			t.Fatalf("device: attempts before pause=%d", calls.Load())
		}
		s.setEnabled(false)
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 4 {
			t.Fatal("disabled attempt")
		}
		s.setEnabled(true)
		code.Store(204)
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 5 {
			t.Fatalf("reenabled connector still in old 8I backoff: calls=%d", calls.Load())
		}
		d2Status(t, s, "withdrawn")
	})
}
