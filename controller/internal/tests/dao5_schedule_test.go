package tests

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

func (r *mockScheduledActionRepo) dao5Faults(errs []error, first chan struct{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.markErrors, r.firstMark = append([]error(nil), errs...), first
}
func (r *mockScheduledActionRepo) dao5Snapshot() (int, []store.ScheduledAction) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.markCalls, append([]store.ScheduledAction(nil), r.records...)
}
func TestDao5_A7a_DueWithdrawalRecovers(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				var ms *MockStore
				var record string
				sa := store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: "rule-1", ScheduledFor: time.Now().Add(time.Second)}
				d := dao4HTTP(t)
				if kind == "bgp" {
					var id int
					ms, id, record = dao4RecoveryFixture(t, "delayed")
					if _, _, err := ms.BGPAnnouncements().ForceWithdraw(ctx, id); err != nil {
						t.Fatal(err)
					}
					sa.ActionType, sa.AnnouncementID = "bgp_withdraw", &id
				} else {
					ms, _, _, _ = dao4XDrop()
					dao4SeedRule(t, ms, "delayed", "rule-1", true)
				}
				if _, err := ms.ScheduledActions().Schedule(ctx, &sa); err != nil {
					t.Fatal(err)
				}
				ms.scheduledActions.dao5Faults([]error{dao5Fault}, nil)
				e := action.NewEngine(ms, "auto")
				if err := e.RecoverScheduledActions(ctx); err != nil {
					t.Fatal(err)
				}
				// Timer advances fake time past due time and the one-second retry.
				<-time.After(4 * time.Second)
				synctest.Wait()
				calls, rows := ms.scheduledActions.dao5Snapshot()
				if calls != 2 || len(rows) != 1 || rows[0].Status != "completed" {
					t.Errorf("DB recovery: calls=%d schedules=%+v; want 2, completed", calls, rows)
				}
				if kind == "xdrop" {
					dao4WantCount(t, d, 1)
				} else if got := strings.Count(dao4Read(t, record), "no network"); got != 1 {
					t.Errorf("withdraw commands=%d; want 1", got)
				}
			})
		})
	}
}
func TestDao5_A7b_CancelledIsNotRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := NewMockStore()
		ms.scheduledActions.appendRecords(store.ScheduledAction{ID: 1, Status: "cancelled"})
		e := action.NewEngine(ms, "auto")
		if e.MarkExecutingDelay(context.Background(), 1) {
			t.Error("cancelled row executed")
		}
		calls, rows := ms.scheduledActions.dao5Snapshot()
		if calls != 1 || rows[0].Status != "cancelled" {
			t.Fatalf("cancelled: calls=%d rows=%+v; want 1 and cancelled", calls, rows)
		}
	})
}

func TestDao5_A7a_NormalDelayedWorkers(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := dao4HTTP(t)
				var ms *MockStore
				if kind == "xdrop" {
					var e *action.Engine
					var ev tracker.AttackEvent
					ms, _, e, ev = dao4XDrop()
					act, err := ms.Responses().GetAction(context.Background(), 10)
					if err != nil {
						t.Fatal(err)
					}
					act.UnblockDelayMinutes = 1
					if err := ms.Responses().UpdateAction(context.Background(), act); err != nil {
						t.Fatal(err)
					}
					dao4SeedRule(t, ms, "active", "rule-1", true)
					ms.scheduledActions.dao5Faults([]error{dao5Fault}, nil)
					ev.Type = "expired"
					e.HandleEvent(ev)
				} else {
					s, e, ev, _, _ := dao5BGPFixture(t, 1)
					ms = s.MockStore
					ms.scheduledActions.dao5Faults([]error{dao5Fault}, nil)
					e.HandleEvent(ev)
				}
				<-time.After(62 * time.Second)
				synctest.Wait()
				calls, rows := ms.scheduledActions.dao5Snapshot()
				if calls != 2 || len(rows) != 1 || rows[0].Status != "completed" {
					t.Errorf("normal delayed %s: calls=%d schedules=%+v; want 2 and completed", kind, calls, rows)
				}
				if kind == "xdrop" {
					dao4WantCount(t, d, 1)
				} else {
					row, err := ms.BGPAnnouncements().Get(context.Background(), 1)
					if err != nil || row.Status != "withdrawn" {
						t.Errorf("BGP timer: row=%+v err=%v; want withdrawn", row, err)
					}
				}
			})
		})
	}
}
func TestDao5_A7c_PersistentDBError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms := NewMockStore()
		ms.scheduledActions.appendRecords(store.ScheduledAction{ID: 1, Status: "pending"})
		ms.scheduledActions.dao5Faults([]error{dao5Fault, dao5Fault, dao5Fault}, nil)
		metric := dao5Metrics(t, ms, nil)
		before := metric("sched_mark_executing")
		start := time.Now()
		if action.NewEngine(ms, "auto").MarkExecutingDelay(context.Background(), 1) {
			t.Error("failed claim returned true")
		}
		calls, rows := ms.scheduledActions.dao5Snapshot()
		if calls != 3 || rows[0].Status != "pending" {
			t.Errorf("persistent failure: calls=%d rows=%+v; want 3 and pending", calls, rows)
		}
		if delta := metric("sched_mark_executing") - before; delta != 1 {
			t.Errorf("sched_mark_executing delta=%v; want 1", delta)
		}
		if elapsed := time.Since(start); elapsed != 2*time.Second {
			t.Errorf("retry interval sum=%v; want 2s", elapsed)
		}
	})
}

type dao5DeadlineSchedules struct {
	store.ScheduledActionRepo
	mu             sync.Mutex
	calls          int
	first          chan struct{}
	consumeAttempt bool
}

func (r *dao5DeadlineSchedules) MarkExecuting(ctx context.Context, _ int) error {
	r.mu.Lock()
	r.calls++
	if r.calls == 1 {
		close(r.first)
	}
	r.mu.Unlock()
	if r.consumeAttempt {
		<-ctx.Done()
		return fmt.Errorf("dao5 write deadline: %w", ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return dao5Fault
}

func (r *dao5DeadlineSchedules) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type dao5DeadlineStore struct {
	*MockStore
	schedules *dao5DeadlineSchedules
}

func (s dao5DeadlineStore) ScheduledActions() store.ScheduledActionRepo { return s.schedules }

func TestDao5_A7d_DeadlineDuringRetryWait(t *testing.T) {
	for _, tc := range []struct {
		name           string
		budget         time.Duration
		consumeAttempt bool
		lastError      string
	}{
		{"deadline_during_wait", 100 * time.Millisecond, false, dao5Fault.Error()},
		{"xdrop_first_write_exhausts_5s", 5 * time.Second, true, "dao5 write deadline: context deadline exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ms := NewMockStore()
				ms.scheduledActions.appendRecords(store.ScheduledAction{ID: 1, Status: "pending"})
				r := &dao5DeadlineSchedules{ScheduledActionRepo: ms.ScheduledActions(), first: make(chan struct{}), consumeAttempt: tc.consumeAttempt}
				s := dao5DeadlineStore{MockStore: ms, schedules: r}
				metric := dao5Metrics(t, s, nil)
				before := metric("sched_mark_executing")
				logs := dao5CaptureLog(t)
				ctx, cancel := context.WithTimeout(context.Background(), tc.budget)
				defer cancel()
				deadline, _ := ctx.Deadline()
				done := make(chan time.Time, 1)
				go func() {
					if action.NewEngine(s, "auto").MarkExecutingDelay(ctx, 1) {
						t.Error("error claim executed")
					}
					done <- time.Now()
				}()
				<-r.first // anchors cancellation to the actual first repository call
				returned := <-done
				calls := r.callCount()
				_, rows := ms.scheduledActions.dao5Snapshot()
				if returned.After(deadline) || calls != 1 {
					t.Errorf("returned=%v deadline=%v calls=%d; want no later and one call", returned, deadline, calls)
				}
				if len(rows) != 1 || rows[0].Status != "pending" {
					t.Errorf("failed claim changed pending row: %+v", rows)
				}
				delta := metric("sched_mark_executing") - before
				if delta != 1 {
					t.Errorf("sched_mark_executing delta=%v; want 1", delta)
				}
				wantLog := "ERROR action: MarkExecuting 1 failed: " + tc.lastError + "; caller ctx: context deadline exceeded"
				if !strings.Contains(logs.text(), wantLog) {
					t.Errorf("missing final failure ERROR with id, repository and caller errors: logs=%q want=%q", logs.text(), wantLog)
				}
				t.Logf("returned=%v deadline=%v calls=%d metric_delta=%v logs=%q", returned, deadline, calls, delta, logs.text())
			})
		})
	}
}
