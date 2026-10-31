package tests

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
)

type dao5bStore struct {
	store.Store
	anns  store.BGPAnnouncementRepo
	sched store.ScheduledActionRepo
}

func (s dao5bStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }
func (s dao5bStore) ScheduledActions() store.ScheduledActionRepo {
	if s.sched != nil {
		return s.sched
	}
	return s.Store.ScheduledActions()
}

type dao5bCallerKey struct{}
type dao5bWrite struct {
	op     string
	gen    int
	ctxErr error
	marked bool
	budget time.Duration
}
type dao5bObservedRepo struct {
	store.BGPAnnouncementRepo
	mu            sync.Mutex
	writes        []dao5bWrite
	before        func(context.Context, string, int, int, int) error
	getHook       func(*store.BGPAnnouncement, error) (*store.BGPAnnouncement, error)
	reconcileHook func()
}

func (r *dao5bObservedRepo) observe(ctx context.Context, op string, id, gen int) error {
	r.mu.Lock()
	n := 0
	for _, w := range r.writes {
		if w.op == op {
			n++
		}
	}
	budget := time.Duration(0)
	if d, ok := ctx.Deadline(); ok {
		budget = time.Until(d)
	}
	r.writes = append(r.writes, dao5bWrite{op, gen, ctx.Err(), ctx.Value(dao5bCallerKey{}) != nil, budget})
	r.mu.Unlock()
	if r.before != nil {
		return r.before(ctx, op, id, gen, n+1)
	}
	return ctx.Err()
}
func (r *dao5bObservedRepo) snapshot(op string) []dao5bWrite {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []dao5bWrite
	for _, w := range r.writes {
		if w.op == op {
			out = append(out, w)
		}
	}
	return out
}
func (r *dao5bObservedRepo) MarkWithdrawn(ctx context.Context, id, gen int) error {
	if err := r.observe(ctx, "withdrawn", id, gen); err != nil {
		return err
	}
	return r.BGPAnnouncementRepo.MarkWithdrawn(ctx, id, gen)
}
func (r *dao5bObservedRepo) MarkFailedWithdraw(ctx context.Context, id, gen int, msg string) error {
	if err := r.observe(ctx, "failed_withdraw", id, gen); err != nil {
		return err
	}
	return r.BGPAnnouncementRepo.MarkFailedWithdraw(ctx, id, gen, msg)
}
func (r *dao5bObservedRepo) MarkAnnounced(ctx context.Context, id, gen int) error {
	if err := r.observe(ctx, "announced", id, gen); err != nil {
		return err
	}
	return r.BGPAnnouncementRepo.MarkAnnounced(ctx, id, gen)
}
func (r *dao5bObservedRepo) MarkFailedAnnounce(ctx context.Context, id, gen int, msg string) error {
	if err := r.observe(ctx, "failed_announce", id, gen); err != nil {
		return err
	}
	return r.BGPAnnouncementRepo.MarkFailedAnnounce(ctx, id, gen, msg)
}
func (r *dao5bObservedRepo) MarkWithdrawing(ctx context.Context, id, gen int) (bool, error) {
	if err := r.observe(ctx, "withdrawing", id, gen); err != nil {
		return false, err
	}
	return r.BGPAnnouncementRepo.MarkWithdrawing(ctx, id, gen)
}
func (r *dao5bObservedRepo) Get(ctx context.Context, id int) (*store.BGPAnnouncement, error) {
	a, err := r.BGPAnnouncementRepo.Get(ctx, id)
	if r.getHook != nil {
		return r.getHook(a, err)
	}
	return a, err
}
func (r *dao5bObservedRepo) ReconcileAttachments(ctx context.Context, id int, ended []int, detach bool) (store.BGPReconcileResult, error) {
	if r.reconcileHook != nil {
		r.reconcileHook()
	}
	return r.BGPAnnouncementRepo.ReconcileAttachments(ctx, id, ended, detach)
}

func dao5bMetrics(t *testing.T, s store.Store) func(string, string) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg, s, dao4Tracker(s, nil)); err != nil {
		t.Fatal(err)
	}
	return func(name, op string) float64 {
		families, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range families {
			if f.GetName() == name {
				for _, m := range f.Metric {
					for _, l := range m.Label {
						if l.GetName() == "op" && l.GetValue() == op {
							return m.GetCounter().GetValue()
						}
					}
				}
			}
		}
		return 0
	}
}

const dao5bFailureMetric = "xsight_state_write_failures_total"
const dao5bStaleMetric = "xsight_bgp_stale_writes_total"

func dao5bCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func dao5bRow(t *testing.T, r store.BGPAnnouncementRepo, id int) *store.BGPAnnouncement {
	t.Helper()
	a, err := r.Get(context.Background(), id)
	if err != nil || a == nil {
		t.Fatalf("Get(%d)=%+v err=%v", id, a, err)
	}
	return a
}
func dao5bReceive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(15 * time.Second):
		t.Fatal("barrier completion did not arrive")
	}
	var zero T
	return zero
}
func dao5bForce(t *testing.T, s store.Store, id int) int {
	t.Helper()
	_, g, err := s.BGPAnnouncements().ForceWithdraw(context.Background(), id)
	dao5bCheck(t, err)
	return g
}
func dao5bWithdraw(ctx context.Context, s store.Store, c *store.BGPConnector, id, gen int) (*store.ActionExecutionLog, error) {
	return action.PerformBGPWithdrawForOrphan(ctx, s, c, store.ResponseAction{}, "192.0.2.10/32", "RTBH", id, gen)
}
func dao5bNewAttack(t *testing.T, s store.Store, attack int) store.BGPAttachResult {
	t.Helper()
	r, err := s.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: attack, ActionID: intPtr(10)})
	dao5bCheck(t, err)
	return r
}

func TestDao5b_B1a_VtyshDeadline(t *testing.T) {
	base, _, _, conn, id := dao5BGPFixture(t, 0)
	g := dao5bForce(t, base, id)
	r := &dao5bObservedRepo{BGPAnnouncementRepo: base.anns}
	s := dao5bStore{Store: base, anns: r}
	path, entered := dao5BlockedVtysh(t)
	conn.VtyshPath = path
	logs := dao5CaptureLog(t)
	metric := dao5bMetrics(t, s)
	before := metric(dao5bFailureMetric, "bgp_ann_state")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := dao5bWithdraw(ctx, s, conn, id, g); done <- err }()
	dao5bReceive(t, entered)
	if err := dao5bReceive(t, done); err == nil {
		t.Error("vtysh timeout unexpectedly succeeded")
	}
	a := dao5bRow(t, r, id)
	if a.Status != "failed" {
		t.Errorf("state=%s; want failed", a.Status)
	}
	if delta := metric(dao5bFailureMetric, "bgp_ann_state") - before; delta != 0 {
		t.Errorf("StateWriteFailures delta=%v; want 0", delta)
	}
	if strings.Contains(logs.text(), "ERROR") {
		t.Errorf("unexpected ERROR: %s", logs.text())
	}
	v, err := s.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{Prefix: a.Prefix, RouteMap: a.RouteMap, ConnectorID: a.ConnectorID, AttackID: 21})
	if err != nil || !v.NeedAnnounce {
		t.Errorf("new attack attach=%+v err=%v; want NeedAnnounce", v, err)
	}
}

func TestDao5b_B1b_SuccessWithExpiredCallerContext(t *testing.T) {
	base, _, _, conn, id := dao5BGPFixture(t, 0)
	g := dao5bForce(t, base, id)
	r := &dao5bObservedRepo{BGPAnnouncementRepo: base.anns, before: func(c context.Context, _ string, _, _, _ int) error {
		if c.Value(dao5bCallerKey{}) != nil {
			return context.DeadlineExceeded
		}
		return c.Err()
	}}
	s := dao5bStore{Store: base, anns: r}
	metric := dao5bMetrics(t, s)
	before := metric(dao5bFailureMetric, "bgp_ann_state")
	_, err := dao5bWithdraw(context.WithValue(context.Background(), dao5bCallerKey{}, true), s, conn, id, g)
	dao5bCheck(t, err)
	if a := dao5bRow(t, r, id); a.Status != "withdrawn" {
		t.Errorf("state=%s; want withdrawn", a.Status)
	}
	if delta := metric(dao5bFailureMetric, "bgp_ann_state") - before; delta != 0 {
		t.Errorf("StateWriteFailures delta=%v; want 0", delta)
	}
	for _, w := range r.snapshot("withdrawn") {
		if w.marked || w.ctxErr != nil || w.budget <= 0 || w.budget > 5*time.Second {
			t.Errorf("terminal context=%+v; want fresh 5s context", w)
		}
	}
}

func TestDao5b_B2_BoundedRetry(t *testing.T) {
	for _, failures := range []int{1, 3} {
		t.Run(fmt.Sprint(failures), func(t *testing.T) {
			base, _, _, conn, id := dao5BGPFixture(t, 0)
			g := dao5bForce(t, base, id)
			r := &dao5bObservedRepo{BGPAnnouncementRepo: base.anns, before: func(_ context.Context, _ string, _, _, n int) error {
				if n <= failures {
					return dao5Fault
				}
				return nil
			}}
			s := dao5bStore{Store: base, anns: r}
			logs := dao5CaptureLog(t)
			metric := dao5bMetrics(t, s)
			before := metric(dao5bFailureMetric, "bgp_ann_state")
			entry, err := dao5bWithdraw(context.Background(), s, conn, id, g)
			dao5bCheck(t, err)
			wantAttempts, wantState, wantFailures := 2, "withdrawn", float64(0)
			if failures == 3 {
				wantAttempts, wantState, wantFailures = 3, "withdrawing", 1
			}
			if n := len(r.snapshot("withdrawn")); n != wantAttempts {
				t.Errorf("attempts=%d; want %d", n, wantAttempts)
			}
			if a := dao5bRow(t, r, id); a.Status != wantState {
				t.Errorf("state=%s; want %s", a.Status, wantState)
			}
			if delta := metric(dao5bFailureMetric, "bgp_ann_state") - before; delta != wantFailures {
				t.Errorf("failure delta=%v; want %v", delta, wantFailures)
			}
			if n := strings.Count(logs.text(), "ERROR"); n != int(wantFailures) {
				t.Errorf("ERROR lines=%d; want %v", n, wantFailures)
			}
			if strings.Contains(entry.ErrorMessage, "state write failed") != (failures == 3) {
				t.Errorf("execution log=%+v", entry)
			}
		})
	}
}

func TestDao5b_B3_LateWithdrawal(t *testing.T) {
	base, _, _, conn, id := dao5BGPFixture(t, 0)
	g := dao5bForce(t, base, id)
	path, entered := dao5BlockedVtysh(t)
	conn.VtyshPath = path
	metric := dao5bMetrics(t, base)
	staleBefore, failBefore := metric(dao5bStaleMetric, "withdrawn"), metric(dao5bFailureMetric, "bgp_ann_state")
	type result struct {
		entry *store.ActionExecutionLog
		err   error
	}
	done := make(chan result, 1)
	go func() { e, err := dao5bWithdraw(context.Background(), base, conn, id, g); done <- result{e, err} }()
	dao5bReceive(t, entered)
	_, err := dao5bWithdraw(context.Background(), base, conn, id, g)
	dao5bCheck(t, err)
	next := dao5bNewAttack(t, base, 21)
	if next.Gen != g+1 {
		t.Errorf("resurrect Gen=%d; want %d", next.Gen, g+1)
	}
	if next.NeedAnnounce {
		dao5bCheck(t, base.BGPAnnouncements().MarkAnnounced(context.Background(), id, next.Gen))
	}
	dao5bCheck(t, os.WriteFile(filepath.Join(filepath.Dir(path), "block"), []byte("release\n"), 0600))
	got := dao5bReceive(t, done)
	dao5bCheck(t, got.err)
	a := dao5bRow(t, base.BGPAnnouncements(), id)
	if a.Status != "active" || a.Refcount != 1 || a.Gen != g+1 {
		t.Errorf("late write overwrote new lifecycle: %+v", a)
	}
	if delta := metric(dao5bStaleMetric, "withdrawn") - staleBefore; delta != 1 {
		t.Errorf("stale withdrawn delta=%v; want 1", delta)
	}
	if delta := metric(dao5bFailureMetric, "bgp_ann_state") - failBefore; delta != 0 {
		t.Errorf("StateWriteFailures delta=%v; want 0", delta)
	}
	if !strings.Contains(got.entry.Detail, "state write not applied (newer generation or already final)") || strings.Contains(got.entry.ErrorMessage, "state write failed") {
		t.Errorf("stale execution log=%+v", got.entry)
	}
}

// FIFO failure device: the announce process returns a deliberate nonzero exit
// only after the test releases it. No listener or time-based synchronization.
func dao5bFailedVtysh(t *testing.T) (string, <-chan struct{}, func()) {
	t.Helper()
	dir := t.TempDir()
	ready, gate := filepath.Join(dir, "ready"), filepath.Join(dir, "gate")
	for _, p := range []string{ready, gate} {
		dao5bCheck(t, unix.Mkfifo(p, 0600))
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	entered := make(chan struct{})
	go func() {
		f, err := os.Open(ready)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = io.Copy(io.Discard, f)
		f.Close()
		if err != nil {
			t.Error(err)
		}
		close(entered)
	}()
	path := filepath.Join(dir, "vtysh")
	dao5bCheck(t, os.WriteFile(path, []byte("#!/bin/sh\nprintf entered > "+quote(ready)+"\nread gate < "+quote(gate)+"\necho deliberate-announce-failure >&2\nexit 1\n"), 0700))
	return path, entered, func() { dao5bCheck(t, os.WriteFile(gate, []byte("release\n"), 0600)) }
}

func TestDao5b_B8_Labels(t *testing.T) {
	s := NewMockStore()
	reg := prometheus.NewRegistry()
	dao5bCheck(t, metrics.Register(reg, s, dao4Tracker(s, nil)))
	families, err := reg.Gather()
	dao5bCheck(t, err)
	got := map[string]bool{}
	for _, f := range families {
		if f.GetName() == dao5bStaleMetric {
			for _, m := range f.Metric {
				for _, l := range m.Label {
					if l.GetName() == "op" {
						got[l.GetValue()] = true
					}
				}
			}
		}
	}
	want := map[string]bool{"announced": true, "withdrawn": true, "failed_announce": true, "failed_withdraw": true, "schedule": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stale metric labels=%v; want %v", got, want)
	}
}

// Keep imports needed by the additional behavior cells below grouped here.
type dao5bSchedules struct {
	store.ScheduledActionRepo
	mu    sync.Mutex
	calls int
	after func(int)
	fail  func(context.Context) error
}

func (r *dao5bSchedules) Schedule(ctx context.Context, a *store.ScheduledAction) (int, error) {
	r.mu.Lock()
	r.calls++
	n := r.calls
	r.mu.Unlock()
	if r.fail != nil {
		return 0, r.fail(ctx)
	}
	id, err := r.ScheduledActionRepo.Schedule(ctx, a)
	if err == nil && r.after != nil {
		r.after(n)
	}
	return id, err
}
func (r *dao5bSchedules) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func TestDao5b_B4b_GenerationGuard(t *testing.T) {
	for _, name := range []string{"b1", "b2", "b3", "b4"} {
		t.Run(name, func(t *testing.T) {
			base := NewMockStore()
			sched := &dao5bSchedules{ScheduledActionRepo: base.ScheduledActions()}
			s := dao5bStore{Store: base, anns: base.BGPAnnouncements(), sched: sched}
			e := action.NewEngine(s, "auto")
			ctx := context.Background()
			at := time.Now().Add(time.Hour)
			const id, g = 91, 7
			if name == "b4" {
				_, a, err := e.ScheduleDelayForAnnouncement(ctx, id, g, at)
				dao5bCheck(t, err)
				_, b, err := e.ScheduleDelayForAnnouncement(ctx, id, g+1, at)
				dao5bCheck(t, err)
				if a.Err() != context.Canceled || b.Err() != nil {
					t.Errorf("replacement contexts A=%v B=%v", a.Err(), b.Err())
				}
				_, c, err := e.ScheduleDelayForAnnouncement(ctx, id, g+1, at)
				dao5bCheck(t, err)
				if b.Err() != context.Canceled || c.Err() != nil {
					t.Errorf("same-gen contexts B=%v C=%v", b.Err(), c.Err())
				}
				e.CancelAnnouncementDelay(id, g+1, "cleanup")
				return
			}
			var b context.Context
			var err error
			if name == "b2" {
				entered, release := make(chan struct{}), make(chan struct{})
				sched.after = func(n int) {
					if n == 1 {
						close(entered)
						<-release
					}
				}
				done := make(chan error, 1)
				go func() { _, _, err := e.ScheduleDelayForAnnouncement(ctx, id, g, at); done <- err }()
				dao5bReceive(t, entered)
				e.CancelAnnouncementDelay(id, g+1, "new generation")
				_, b, err = e.ScheduleDelayForAnnouncement(ctx, id, g+1, at)
				dao5bCheck(t, err)
				close(release)
				err = dao5bReceive(t, done)
			} else {
				if name == "b1" {
					_, b, err = e.ScheduleDelayForAnnouncement(ctx, id, g+1, at)
					dao5bCheck(t, err)
				} else {
					e.CancelAnnouncementDelay(id, g+1, "new generation")
				}
				before := sched.count()
				_, _, err = e.ScheduleDelayForAnnouncement(ctx, id, g, at)
				if n := sched.count() - before; n != 0 {
					t.Errorf("old generation Schedule calls delta=%d; want 0", n)
				}
			}
			if !errors.Is(err, store.ErrStaleAnnouncement) {
				t.Errorf("old schedule err=%v; want stale", err)
			}
			if b != nil {
				if b.Err() != nil {
					t.Errorf("new worker was cancelled: %v", b.Err())
				}
				e.CancelAnnouncementDelay(id, g+1, "map ownership probe")
				if b.Err() != context.Canceled {
					t.Errorf("pendingDelay no longer owns new worker: %v", b.Err())
				}
			}
		})
	}
}

type dao5bLogRepo struct {
	store.ActionExecLogRepo
	done chan store.ActionExecutionLog
}

func (r dao5bLogRepo) Create(ctx context.Context, a *store.ActionExecutionLog) (int, error) {
	id, err := r.ActionExecLogRepo.Create(ctx, a)
	r.done <- *a
	return id, err
}

type dao5bLogStore struct {
	dao5bStore
	logs store.ActionExecLogRepo
}

func (s dao5bLogStore) ActionExecLog() store.ActionExecLogRepo { return s.logs }

func TestDao5b_B6_Compensation(t *testing.T) {
	for _, name := range []string{"live", "expired", "active", "retry_three"} {
		t.Run(name, func(t *testing.T) {
			var behavior, generation func(*testing.T)
			synctest.Test(t, func(t *testing.T) {
				base, _, ev, _, id := dao5BGPFixture(t, 1)
				base.bgpAnnouncements.mu.Lock()
				base.bgpAnnouncements.findByIDLocked(id).Gen = 7
				base.bgpAnnouncements.mu.Unlock()
				r := &dao5bObservedRepo{BGPAnnouncementRepo: base.anns}
				if name == "retry_three" {
					r.before = func(_ context.Context, _ string, _, _, n int) error {
						if n < 3 {
							return dao5Fault
						}
						return nil
					}
				}
				sched := &dao5bSchedules{ScheduledActionRepo: base.ScheduledActions(), fail: func(ctx context.Context) error {
					if name == "expired" {
						<-ctx.Done()
						return ctx.Err()
					}
					if name == "active" {
						dao5bNewAttack(t, base, 21)
					}
					return dao5Fault
				}}
				done := make(chan store.ActionExecutionLog, 10)
				s := dao5bLogStore{dao5bStore{Store: base, anns: r, sched: sched}, dao5bLogRepo{base.ActionExecLog(), done}}
				metric := dao5bMetrics(t, s)
				before := metric(dao5bFailureMetric, "bgp_ann_state")
				e := action.NewEngine(s, "auto")
				e.HandleEvent(ev)
				entry := <-done
				synctest.Wait()
				want := "failed"
				if name == "active" {
					want = "active"
				}
				a := dao5bRow(t, r, id)

				writes := r.snapshot("failed_withdraw")
				attempts := 1
				if name == "retry_three" {
					attempts = 3
				}
				generation = func(t *testing.T) {
					if len(writes) != attempts {
						t.Errorf("compensation attempts=%d; want %d", len(writes), attempts)
					}
					{
						for _, w := range writes {
							if w.gen != 7 || w.ctxErr != nil || w.budget <= 0 || w.budget > 5*time.Second {
								t.Errorf("compensation write=%+v; want gen=7 fresh 5s context", w)
							}
						}
					}
				}
				delta := metric(dao5bFailureMetric, "bgp_ann_state") - before
				behavior = func(t *testing.T) {
					if a.Status != want || a.Gen != 7 {
						t.Errorf("compensation row=%+v; want %s gen=7", a, want)
					}
					if delta != 0 {
						t.Errorf("compensation failure metric delta=%v; want 0", delta)
					}
					if name == "active" {
						if a.Refcount != 1 {
							t.Errorf("new attachment refcount=%d; want 1", a.Refcount)
						}
						if !strings.Contains(entry.Detail, "state write not applied") {
							t.Errorf("stale compensation log=%+v", entry)
						}
					}
				}
			})
			if generation != nil {
				t.Run("generation_and_context", generation)
			}
			if behavior != nil {
				t.Run("behavior", behavior)
			}
		})
	}
}

func dao5bRecovered(t *testing.T, initial, change string, claimError bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ms, id, record := dao4RecoveryFixture(t, initial)
		ms.bgpAnnouncements.announcements[0].Gen = 7
		if change == "force" {
			dao5bForce(t, ms, id)
		}
		r := &dao5bObservedRepo{BGPAnnouncementRepo: ms.BGPAnnouncements()}
		if claimError {
			r.before = func(_ context.Context, op string, _, _, n int) error {
				if op == "withdrawing" && n == 1 {
					return dao5Fault
				}
				return nil
			}
		}
		entered, release := make(chan struct{}), make(chan struct{})
		getCalls := 0
		if change != "" && change != "force" {
			r.getHook = func(a *store.BGPAnnouncement, err error) (*store.BGPAnnouncement, error) {
				getCalls++
				if getCalls == 1 {
					close(entered)
					<-release
				}
				if getCalls == 2 && change == "get_error" {
					return nil, dao5Fault
				}
				if getCalls == 2 && change == "get_nil" {
					return nil, nil
				}
				return a, err
			}
		}
		done := make(chan string, 1)
		sched := dao5bWorkerSchedules{ms.ScheduledActions(), done}
		s := dao5bStore{Store: ms, anns: r, sched: sched}
		e := action.NewEngine(s, "auto")
		_, err := sched.Schedule(context.Background(), &store.ScheduledAction{ActionType: "bgp_withdraw", AnnouncementID: &id, ScheduledFor: time.Now().Add(-time.Second)})
		dao5bCheck(t, err)
		dao5bCheck(t, e.RecoverScheduledActions(context.Background()))
		if change != "" && change != "force" {
			<-entered
			switch change {
			case "new_generation":
				dao5bForce(t, ms, id)
			case "active":
				dao5bNewAttack(t, ms, 21)
			default:
				ok, err := ms.BGPAnnouncements().MarkWithdrawing(context.Background(), id, 7)
				dao5bCheck(t, err)
				if !ok {
					t.Fatal("other executor did not claim")
				}
				dao5bCheck(t, ms.BGPAnnouncements().MarkFailedWithdraw(context.Background(), id, 7, "other executor failed"))
			}
			close(release)
		}
		outcome := <-done
		synctest.Wait()
		wantCalls, wantState, wantSchedule := 1, "withdrawn", "completed"
		if initial == "orphan" || initial == "dismissed" || initial == "dismissed_on_upgrade" {
			wantCalls, wantState = 0, initial
		}
		if change == "new_generation" {
			wantCalls, wantState = 0, "withdrawing"
		}
		if change == "active" {
			wantCalls, wantState = 0, "active"
		}
		if change == "get_error" || change == "get_nil" {
			wantCalls, wantState, wantSchedule = 0, "failed", "failed"
		}
		if !strings.HasPrefix(outcome, wantSchedule) {
			t.Errorf("recovery outcome=%s; want %s", outcome, wantSchedule)
		}
		if n := strings.Count(dao4Read(t, record), "no network"); n != wantCalls {
			t.Errorf("vtysh count=%d; want %d", n, wantCalls)
		}
		a := dao5bRow(t, ms.BGPAnnouncements(), id)
		if a.Status != wantState {
			t.Errorf("recovered state=%s; want %s", a.Status, wantState)
		}
		_, rows := ms.scheduledActions.dao5Snapshot()
		if len(rows) != 1 || rows[0].Status != wantSchedule {
			t.Errorf("schedules=%+v; want %s", rows, wantSchedule)
		}
		if claimError {
			next := dao5bNewAttack(t, ms, 21)
			if !next.NeedAnnounce {
				t.Errorf("after claim error recovery NeedAnnounce=false")
			}
		}
	})
}
func TestDao5b_B9_WithdrawingRecovery(t *testing.T) { dao5bRecovered(t, "withdrawing", "", false) }
func TestDao5b_B10_ClaimErrorRecovery(t *testing.T) { dao5bRecovered(t, "delayed", "", true) }
func TestDao5b_B11_RecoveryStates(t *testing.T) {
	for _, status := range []string{"withdrawing", "orphan", "dismissed", "dismissed_on_upgrade"} {
		t.Run(status, func(t *testing.T) {
			change := ""
			if status == "withdrawing" {
				change = "force"
			}
			dao5bRecovered(t, status, change, false)
		})
	}
	t.Run("changed_generation", func(t *testing.T) { dao5bRecovered(t, "delayed", "new_generation", false) })
}
func TestDao5b_B13_TwoExecutors(t *testing.T) {
	for _, change := range []string{"failed", "active", "get_error", "get_nil"} {
		t.Run(change, func(t *testing.T) { dao5bRecovered(t, "delayed", change, false) })
	}
}

func dao5bAnnounceFailure(t *testing.T, when string) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		ms, _, ev := dao4Fixture("bgp", "once", "on_detected")
		ms.responses.actions[0].BGPConnectorID = intPtr(7)
		ms.responses.actions[0].BGPRouteMap = "RTBH"
		ms.responses.actions[0].BGPWithdrawDelayMinutes = 1
		path, entered, release := dao5bFailedVtysh(t)
		ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Enabled: true, VtyshPath: path, BGPASN: 64512}}
		r := &dao5bObservedRepo{BGPAnnouncementRepo: ms.BGPAnnouncements()}
		done := make(chan store.ActionExecutionLog, 10)
		s := dao5bLogStore{dao5bStore{Store: ms, anns: r}, dao5bLogRepo{ms.ActionExecLog(), done}}
		action.NewEngine(s, "auto").HandleEvent(ev)
		<-entered
		a, err := ms.BGPAnnouncements().FindByBusinessKey(context.Background(), "192.0.2.10/32", "RTBH", 7)
		dao5bCheck(t, err)
		if a == nil || a.Status != "announcing" {
			t.Fatalf("in-flight row=%+v", a)
		}
		id, g := a.ID, a.Gen
		if when != "before_detach" {
			d, err := ms.BGPAnnouncements().Detach(context.Background(), 20, a.Prefix, a.RouteMap, 7)
			dao5bCheck(t, err)
			if !d.Delayed {
				t.Errorf("detach=%+v; want delayed", d)
			}
			if when == "reattach" {
				b := dao5bNewAttack(t, ms, 21)
				if b.NeedAnnounce || b.Gen != g {
					t.Errorf("same-cycle reattach=%+v; want NeedAnnounce=false gen=%d", b, g)
				}
			}
		}
		release()
		entry := <-done
		synctest.Wait()
		if entry.Status != "failed" {
			t.Errorf("announce log=%+v; want failed", entry)
		}
		a, err = ms.BGPAnnouncements().Get(context.Background(), id)
		dao5bCheck(t, err)
		if when == "before_detach" {
			if a != nil {
				t.Errorf("announce-before-detach must delete refcount=1 row: %+v", a)
			}
			_, err = ms.BGPAnnouncements().Detach(context.Background(), 20, "192.0.2.10/32", "RTBH", 7)
			dao5bCheck(t, err)
			return
		}
		if a == nil || a.Status != "failed" {
			t.Fatalf("late announce failure row=%+v; want retained failed", a)
		}
		next := dao5bNewAttack(t, ms, 22)
		if !next.NeedAnnounce {
			t.Errorf("next attack=%+v; want NeedAnnounce", next)
		}
		if when == "reattach" && next.Gen != g+1 {
			t.Errorf("next generation=%d; want %d", next.Gen, g+1)
		}
	})
}
func TestDao5b_B12a_FailureAfterDetach(t *testing.T)        { dao5bAnnounceFailure(t, "after_detach") }
func TestDao5b_B12b_FailureAfterReattach(t *testing.T)      { dao5bAnnounceFailure(t, "reattach") }
func TestDao5b_B12_ControlFailureBeforeDetach(t *testing.T) { dao5bAnnounceFailure(t, "before_detach") }
