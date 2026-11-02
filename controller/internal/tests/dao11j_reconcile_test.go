package tests

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
)

type dao11jRepo struct {
	store.BGPAnnouncementRepo
	announced            chan struct{}
	claims, gets, forces atomic.Int64
	lists                atomic.Int64
	beforeClaim          func(int, int) error
	beforeGet            func(int)
	afterList            func(string, []store.BGPAnnouncement) ([]store.BGPAnnouncement, error)
	afterForce           func(int, int)
	afterWithdrawing     func(int)
}

func (r *dao11jRepo) MarkAnnounced(c context.Context, id, gen int) error {
	err := r.BGPAnnouncementRepo.MarkAnnounced(c, id, gen)
	r.announced <- struct{}{}
	return err
}

func (r *dao11jRepo) ClaimWithdrawing(c context.Context, id, gen int) (int, bool, error) {
	r.claims.Add(1)
	if r.beforeClaim != nil {
		if err := r.beforeClaim(id, gen); err != nil {
			return 0, false, err
		}
	}
	return r.BGPAnnouncementRepo.ClaimWithdrawing(c, id, gen)
}
func (r *dao11jRepo) Get(c context.Context, id int) (*store.BGPAnnouncement, error) {
	r.gets.Add(1)
	if r.beforeGet != nil {
		r.beforeGet(id)
	}
	return r.BGPAnnouncementRepo.Get(c, id)
}
func (r *dao11jRepo) ListByStatus(c context.Context, status string) ([]store.BGPAnnouncement, error) {
	rows, err := r.BGPAnnouncementRepo.ListByStatus(c, status)
	if err != nil {
		return nil, err
	}
	if status == "withdrawing" {
		r.lists.Add(1)
	}
	if r.afterList != nil {
		return r.afterList(status, rows)
	}
	return rows, nil
}
func (r *dao11jRepo) ForceWithdraw(c context.Context, id int) ([]store.BGPAnnouncementAttack, int, error) {
	r.forces.Add(1)
	rows, gen, err := r.BGPAnnouncementRepo.ForceWithdraw(c, id)
	if err == nil && r.afterForce != nil {
		r.afterForce(id, gen)
	}
	return rows, gen, err
}
func (r *dao11jRepo) MarkWithdrawing(c context.Context, id, gen int) (bool, error) {
	ok, err := r.BGPAnnouncementRepo.MarkWithdrawing(c, id, gen)
	if ok && r.afterWithdrawing != nil {
		r.afterWithdrawing(id)
	}
	return ok, err
}

type dao11jConnectors struct {
	store.BGPConnectorRepo
	calls  atomic.Int64
	before func(int64) error
}

func (r *dao11jConnectors) Get(c context.Context, id int) (*store.BGPConnector, error) {
	n := r.calls.Add(1)
	if r.before != nil {
		if err := r.before(n); err != nil {
			return nil, err
		}
	}
	return r.BGPConnectorRepo.Get(c, id)
}

type dao11jSchedules struct {
	store.ScheduledActionRepo
	marks       atomic.Int64
	cancelError bool
}

func (r *dao11jSchedules) MarkExecuting(c context.Context, id int) error {
	r.marks.Add(1)
	return r.ScheduledActionRepo.MarkExecuting(c, id)
}
func (r *dao11jSchedules) Cancel(c context.Context, id int, reason string) error {
	if r.cancelError {
		return dao5Fault
	}
	return r.ScheduledActionRepo.Cancel(c, id, reason)
}
func (r *dao11jSchedules) ListExecuting(c context.Context) ([]store.ScheduledAction, error) {
	return r.ScheduledActionRepo.(interface {
		ListExecuting(context.Context) ([]store.ScheduledAction, error)
	}).ListExecuting(c)
}

type dao11jStore struct {
	store.Store
	anns       *dao11jRepo
	connectors *dao11jConnectors
	schedules  *dao11jSchedules
}

func (s dao11jStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }
func (s dao11jStore) BGPConnectors() store.BGPConnectorRepo       { return s.connectors }
func (s dao11jStore) ScheduledActions() store.ScheduledActionRepo { return s.schedules }

type dao11jFixture struct {
	base             *dao5BGPStore
	r                *dao11jRepo
	c                *dao11jConnectors
	sched            *dao11jSchedules
	e                *action.Engine
	ev               tracker.AttackEvent
	id               int
	record, failPath string
	metric           func(string) float64
}

func dao11jNew(t *testing.T) *dao11jFixture {
	t.Helper()
	b, _, ev, conn, id := dao5BGPFixture(t, 0)
	path, record := dao4Vtysh(t)
	failPath := filepath.Join(filepath.Dir(path), "fail")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0700)
	dao5bCheck(t, err)
	_, err = fmt.Fprintf(f, "if [ -f '%s' ]; then exit 1; fi\n", strings.ReplaceAll(failPath, "'", "'\\''"))
	dao5bCheck(t, err)
	dao5bCheck(t, f.Close())
	conn.VtyshPath = path
	dao5bCheck(t, b.BGPConnectors().Update(context.Background(), conn))
	announce := b.responses.actions[0]
	announce.ID, announce.TriggerPhase = 11, "on_detected"
	b.responses.actions = append(b.responses.actions, announce)
	r := &dao11jRepo{BGPAnnouncementRepo: b.anns, announced: make(chan struct{}, 1)}
	c := &dao11jConnectors{BGPConnectorRepo: b.BGPConnectors()}
	sched := &dao11jSchedules{ScheduledActionRepo: b.ScheduledActions()}
	s := dao11jStore{b, r, c, sched}
	reg := prometheus.NewRegistry()
	dao5bCheck(t, metrics.Register(reg, s, dao4Tracker(s, nil)))
	metric := func(outcome string) float64 {
		families, err := reg.Gather()
		dao5bCheck(t, err)
		for _, family := range families {
			if family.GetName() != "xsight_bgp_withdrawing_reconcile_total" {
				continue
			}
			for _, m := range family.Metric {
				for _, l := range m.Label {
					if l.GetName() == "outcome" && l.GetValue() == outcome {
						return m.GetCounter().GetValue()
					}
				}
			}
		}
		t.Fatalf("missing registered reconcile outcome %s", outcome)
		return 0
	}
	return &dao11jFixture{b, r, c, sched, action.NewEngine(s, "auto"), ev, id, record, failPath, metric}
}
func dao11jWant[T comparable](t *testing.T, name string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("ASSERT %s FAIL got=%v want=%v", name, got, want)
	} else {
		t.Logf("ASSERT %s PASS got=%v", name, got)
	}
}
func dao11jAdvance(d time.Duration) { <-time.After(d); synctest.Wait() }
func dao11jClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
func (f *dao11jFixture) set(status string, gen int) {
	r := f.base.bgpAnnouncements
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.findByIDLocked(f.id)
	a.Status, a.Gen = status, gen
}
func (f *dao11jFixture) row(t *testing.T) *store.BGPAnnouncement {
	return dao5bRow(t, f.base.anns, f.id)
}
func (f *dao11jFixture) commands(t *testing.T) int {
	return strings.Count(dao4Read(t, f.record), "no network ")
}
func (f *dao11jFixture) start(interval time.Duration) (context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f.e.RunWithdrawingReconcile(ctx, interval) }()
	synctest.Wait()
	return cancel, done
}
func (f *dao11jFixture) schedule(t *testing.T, status string, delay time.Duration) int {
	id, err := f.base.ScheduledActions().Schedule(context.Background(), &store.ScheduledAction{ActionType: "bgp_withdraw", AnnouncementID: &f.id, ScheduledFor: time.Now().Add(delay)})
	dao5bCheck(t, err)
	if status == "executing" {
		dao5bCheck(t, f.base.ScheduledActions().MarkExecuting(context.Background(), id))
	}
	return id
}
func (f *dao11jFixture) scheduled(id int) string {
	r := f.base.scheduledActions
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.records {
		if row.ID == id {
			return row.Status
		}
	}
	return "missing"
}
func (f *dao11jFixture) revive(t *testing.T) {
	ev := f.ev
	a := *ev.Attack
	a.ID, ev.DBID, ev.Type = 21, 21, "confirmed"
	ev.Attack = &a
	f.e.HandleEvent(ev)
	select {
	case <-f.r.announced:
	case <-time.After(30 * time.Second):
		t.Error("new announcement did not reach its terminal write")
	}
}
func (f *dao11jFixture) lastRouteCommand(t *testing.T) string {
	last := ""
	for _, line := range strings.Split(dao4Read(t, f.record), "\n") {
		if strings.HasPrefix(line, "network ") || strings.HasPrefix(line, "no network ") {
			last = line
		}
	}
	return last
}

func TestDao11j_R1_HealsStuckWithdrawal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.base.anns.inject(3, 0, nil)
		f.e.HandleEvent(f.ev)
		synctest.Wait()
		dao11jWant(t, "R1.Stuck", f.row(t).Status, "withdrawing")
		before := f.metric("claimed")
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jWant(t, "R1.FirstRound", f.r.claims.Load(), int64(0))
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R1.Gen", f.row(t).Gen, 1)
		dao11jWant(t, "R1.Status", f.row(t).Status, "withdrawn")
		dao11jWant(t, "R1.Vtysh", f.commands(t), 2)
		dao11jWant(t, "R1.Metric", f.metric("claimed")-before, float64(1))
		dao11jWant(t, "R20.ClaimOK", f.e.AnnouncementTakeovers(f.id), 1)
		a := dao5bNewAttack(t, f.base, 21)
		dao11jWant(t, "R1.Attach", a.Gen == 2 && a.NeedAnnounce && f.row(t).Status == "announcing", true)
	})
}
func TestDao11j_R2_OneObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jWant(t, "R2.FirstRound", f.r.claims.Load(), int64(0))
		dao5bCheck(t, f.base.anns.MarkWithdrawn(context.Background(), f.id, 0))
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R2.Claims", f.r.claims.Load(), int64(0))
		dao11jWant(t, "R2.Vtysh", f.commands(t), 0)
	})
}
func TestDao11j_R3_GenerationChanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao5bForce(t, f.base, f.id)
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R3.SecondRound", f.r.claims.Load(), int64(0))
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R3.ThirdRound", f.row(t).Gen, 2)
	})
}
func TestDao11j_R4_ClaimLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		f.r.beforeClaim = func(int, int) error { dao5bForce(t, f.base, f.id); return nil }
		before := f.metric("claim_lost")
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R4.Vtysh", f.commands(t), 0)
		dao11jWant(t, "R4.Metric", f.metric("claim_lost")-before, float64(1))
		dao11jWant(t, "R20.ClaimLost", f.e.AnnouncementTakeovers(f.id), 0)
	})
}
func TestDao11j_R5_R6_OldWritesAndAttach(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		entered, release := make(chan struct{}), make(chan struct{})
		// A bubble-local repository barrier holds the claimed withdrawal before vtysh.
		f.c.before = func(int64) error { close(entered); <-release; return nil }
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R5.Entered", dao11jClosed(entered), true)
		dao11jWant(t, "R5.Withdrawn", errors.Is(f.base.anns.MarkWithdrawn(context.Background(), f.id, 0), store.ErrStaleAnnouncement), true)
		dao11jWant(t, "R5.Failed", errors.Is(f.base.anns.MarkFailedWithdraw(context.Background(), f.id, 0, "late"), store.ErrStaleAnnouncement), true)
		dao11jWant(t, "R5.Unchanged", f.row(t).Status == "withdrawing" && f.row(t).Gen == 1, true)
		_, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21})
		dao11jWant(t, "R6.Attach", err != nil, true)
		close(release)
		synctest.Wait()
		dao11jWant(t, "R5.Final", f.row(t).Status == "withdrawn" && f.row(t).Gen == 1, true)
	})
}
func TestDao11j_R7_VtyshFailure(t *testing.T) {
	// This fixture retains refcount=1 and an undetached attachment, so failed
	// withdrawal reconciliation must leave it for its current owners.
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		dao5bCheck(t, os.WriteFile(f.failPath, nil, 0600))
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R7.Failed", f.row(t).Status == "failed" && f.row(t).Gen == 1, true)
		dao11jAdvance(3 * time.Minute)
		dao11jWant(t, "R7.NoRetry", f.commands(t), 1)
		dao11jWant(t, "R7.Claims", f.r.claims.Load(), int64(1))
	})
}
func TestDao11j_R8_MissingConnector(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		f.c.before = func(int64) error { return errors.New("connector not found") }
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R8.Failed", f.row(t).Status == "failed" && f.row(t).Gen == 1, true)
		dao11jWant(t, "R8.Vtysh", f.commands(t), 0)
	})
}
func TestDao11j_R9_CancelsDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		id, waiting, err := f.e.ScheduleDelayForAnnouncement(context.Background(), f.id, 0, time.Now().Add(10*time.Minute))
		dao5bCheck(t, err)
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R9.Memory", dao11jClosed(waiting.Done()), true)
		dao11jWant(t, "R9.Pending", f.scheduled(id), "cancelled")
		_, _, err = f.e.ScheduleDelayForAnnouncement(context.Background(), f.id, 0, time.Now().Add(time.Hour))
		dao11jWant(t, "R9.Reject", errors.Is(err, store.ErrStaleAnnouncement), true)
	})
}
func TestDao11j_R10_CancelExits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		var rescue atomic.Bool
		f.r.afterList = func(_ string, rows []store.BGPAnnouncement) ([]store.BGPAnnouncement, error) {
			if rescue.Load() {
				runtime.Goexit()
			}
			return rows, nil
		}
		cancel, done := f.start(time.Minute)
		cancel()
		synctest.Wait()
		dao11jWant(t, "R10.Done", dao11jClosed(done), true)
		// Let the cancellation mutant terminate after the named assertion fails.
		if !dao11jClosed(done) {
			rescue.Store(true)
			dao11jAdvance(time.Minute)
		}
	})
}
func TestDao11j_R11_ListErrorRetainsObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		f.r.afterList = func(_ string, rows []store.BGPAnnouncement) ([]store.BGPAnnouncement, error) {
			if f.r.lists.Load() == 2 {
				return nil, dao5Fault
			}
			return rows, nil
		}
		before := f.metric("list_error")
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R11.Metric", f.metric("list_error")-before, float64(1))
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R11.Retained", f.row(t).Status, "withdrawn")
	})
}
func TestDao11j_R12_SerialRows(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		second, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.11/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 22})
		dao5bCheck(t, err)
		dao5bForce(t, f.base, second.AnnouncementID)
		entered, release := make(chan struct{}), make(chan struct{})
		f.c.before = func(n int64) error {
			if n == 1 {
				close(entered)
				<-release
			}
			return nil
		}
		cancel, _ := f.start(time.Minute)
		defer cancel()
		third, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.12/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 23})
		dao5bCheck(t, err)
		dao5bForce(t, f.base, third.AnnouncementID)
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R12.Serial", dao11jClosed(entered) && f.r.claims.Load() == 1 && f.c.calls.Load() == 1, true)
		dao5bCheck(t, f.base.anns.MarkWithdrawn(context.Background(), third.AnnouncementID, 1))
		close(release)
		synctest.Wait()
		dao11jWant(t, "R12.Claims", f.r.claims.Load(), int64(2))
		dao11jWant(t, "R12.Vtysh", f.commands(t), 2)
		dao11jWant(t, "R12.InFlight", dao5bRow(t, f.base.anns, third.AnnouncementID).Gen, 1)
	})
}
func TestDao11j_R13_ReobserveClaimedGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		f.base.anns.inject(3, 0, nil)
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R13.Stuck", f.row(t).Gen == 1 && f.row(t).Status == "withdrawing", true)
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R13.FirstSeenAgain", f.r.claims.Load(), int64(1))
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R13.Healed", f.row(t).Gen == 2 && f.row(t).Status == "withdrawn", true)
	})
}

func TestDao11j_R14_ForceRemoveWaits(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		release := make(chan struct{})
		f.c.before = func(n int64) error {
			if n == 1 {
				<-release
			}
			return nil
		}
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		done := make(chan error, 1)
		go func() { done <- f.e.ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH") }()
		synctest.Wait()
		dao11jWant(t, "R14.Wait", len(done), 0)
		dao11jWant(t, "R14.NoForce", f.r.forces.Load(), int64(0))
		dao11jWant(t, "R14.NoVtysh", f.commands(t), 0)
		dao11jWant(t, "R14.RowHeld", f.row(t).Status, "withdrawing")
		close(release)
		synctest.Wait()
		dao5bCheck(t, <-done)
		f.revive(t)
		dao11jWant(t, "R14.NoLateWithdraw", f.lastRouteCommand(t), "network 192.0.2.10/32 route-map RTBH")
		dao11jWant(t, "R14.Row", f.row(t).Status == "active" && f.row(t).Gen == 2, true)
	})
}
func TestDao11j_R14b_ForceNoopTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		release := make(chan struct{})
		f.c.before = func(n int64) error {
			if n == 1 {
				<-release
			}
			return nil
		}
		f.r.afterForce = func(_, gen int) {
			dao11jWant(t, "R14b.NoopGen", gen, 1)
			f.revive(t)
		}
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		takeovers := f.e.AnnouncementTakeovers(f.id)
		done := make(chan error, 1)
		go func() { done <- f.e.ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH") }()
		synctest.Wait()
		dao11jWant(t, "R14b.Wait", len(done), 0)
		close(release)
		synctest.Wait()
		dao11jWant(t, "R14b.Ret", <-done, error(nil))
		dao11jWant(t, "R14b.NoLateWithdraw", f.lastRouteCommand(t), "network 192.0.2.10/32 route-map RTBH")
		dao11jWant(t, "R14b.Row", f.row(t).Status == "active" && f.row(t).Gen == 2, true)
		dao11jWant(t, "R20.ForceNoop", f.e.AnnouncementTakeovers(f.id)-takeovers, 0)
	})
}
func TestDao11j_R15_SlowRound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		release, firstSeen := make(chan struct{}), make(chan time.Time, 1)
		var x int
		seen := false
		f.r.afterList = func(_ string, rows []store.BGPAnnouncement) ([]store.BGPAnnouncement, error) {
			for _, a := range rows {
				if a.ID == x && !seen {
					seen = true
					firstSeen <- time.Now()
				}
			}
			return rows, nil
		}
		f.c.before = func(n int64) error {
			if n == 1 {
				<-release
			}
			return nil
		}
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		a, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.99/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 99})
		dao5bCheck(t, err)
		x = a.AnnouncementID
		dao5bForce(t, f.base, x)
		dao11jAdvance(119 * time.Second)
		close(release)
		synctest.Wait()
		observedAt := <-firstSeen
		dao11jAdvance(time.Second)
		dao11jWant(t, "R15.BeforeInterval", dao5bRow(t, f.base.anns, x).Gen, 1)
		dao11jWant(t, "R15.ObservationAge", time.Since(observedAt), time.Second)
		dao11jAdvance(59 * time.Second)
		dao11jWant(t, "R15.Eventual", dao5bRow(t, f.base.anns, x).Status, "withdrawn")
	})
}
func TestDao11j_R16_ClaimErrorReleasesLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("withdrawing", 0)
		f.r.beforeClaim = func(int, int) error {
			if f.r.claims.Load() == 1 {
				return dao5Fault
			}
			return nil
		}
		before := f.metric("claim_error")
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R16.Metric", f.metric("claim_error")-before, float64(1))
		dao11jWant(t, "R16.Vtysh", f.commands(t), 0)
		locked := make(chan struct{})
		go func() { unlock := f.e.LockAnnouncement(f.id); defer unlock(); close(locked) }()
		synctest.Wait()
		dao11jWant(t, "R16.Unlocked", dao11jClosed(locked), true)
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R16.Retained", f.row(t).Status, "withdrawn")
	})
}
func TestDao11j_R17_ForceRemoveBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		entered, release := make(chan struct{}), make(chan struct{})
		// ForceWithdraw has committed its generation; the side effect is still gated.
		f.r.afterForce = func(int, int) { close(entered); <-release }
		done := make(chan error, 1)
		go func() { done <- f.e.ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH") }()
		synctest.Wait()
		dao11jWant(t, "R17.Entered", dao11jClosed(entered) && f.row(t).Gen == 1, true)
		before := f.metric("busy")
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R17.Busy", f.metric("busy")-before, float64(1))
		dao11jWant(t, "R17.NoClaim", f.r.claims.Load(), int64(0))
		dao11jWant(t, "R17.NoVtysh", f.commands(t), 0)
		close(release)
		synctest.Wait()
		dao5bCheck(t, <-done)
		dao11jWant(t, "R20.ForceAdvance", f.e.AnnouncementTakeovers(f.id), 1)
	})
}
func TestDao11j_R18a_PendingOwnsLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("delayed", 7)
		entered, release := make(chan struct{}), make(chan struct{})
		f.r.afterWithdrawing = func(int) { close(entered); <-release }
		f.schedule(t, "pending", time.Second)
		dao5bCheck(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao11jAdvance(time.Second)
		dao11jWant(t, "R18a.Entered", dao11jClosed(entered), true)
		before := f.metric("busy")
		cancel, _ := f.start(5 * time.Second)
		defer cancel()
		dao11jAdvance(5 * time.Second)
		dao11jWant(t, "R18a.Busy", f.metric("busy")-before, float64(1))
		dao11jWant(t, "R18a.NoClaim", f.r.claims.Load(), int64(0))
		close(release)
		synctest.Wait()
		dao11jWant(t, "R18a.Final", f.row(t).Status == "withdrawn" && f.row(t).Gen == 7, true)
	})
}
func TestDao11j_R18b_PendingWaitCancelled(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "Success"
		if fail {
			name = "CancelAndWithdrawFail"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao11jNew(t)
				f.set("withdrawing", 7)
				f.sched.cancelError = fail
				if fail {
					dao5bCheck(t, os.WriteFile(f.failPath, nil, 0600))
				}
				entered, release := make(chan struct{}), make(chan struct{})
				f.r.beforeClaim = func(int, int) error { close(entered); <-release; return nil }
				id := f.schedule(t, "pending", 90*time.Second)
				dao5bCheck(t, f.e.RecoverScheduledActions(context.Background()))
				synctest.Wait()
				cancel, _ := f.start(time.Minute)
				defer cancel()
				dao11jAdvance(time.Minute)
				dao11jWant(t, "R18b.ClaimBarrier", dao11jClosed(entered), true)
				// The recovered timer expires while Claim still owns the channel lock.
				dao11jAdvance(30 * time.Second)
				dao11jWant(t, "R18b.WaitNoMark", f.sched.marks.Load(), int64(0))
				dao11jWant(t, "R18b.WaitNoGet", f.r.gets.Load(), int64(0))
				dao11jWant(t, "R18b.WaitNoVtysh", f.commands(t), 0)
				close(release)
				synctest.Wait()
				dao11jWant(t, "R18b.NoGet", f.r.gets.Load(), int64(0))
				dao11jWant(t, "R18b.NoVtysh", f.commands(t), 1)
				if fail {
					dao11jWant(t, "R18b.Pending", f.scheduled(id), "pending")
					dao11jWant(t, "R18b.Failed", f.row(t).Status == "failed" && f.row(t).Gen == 8, true)
					dao5bCheck(t, os.Remove(f.failPath))
					f.revive(t)
					dao11jWant(t, "R18b.NoLateWithdraw", f.lastRouteCommand(t), "network 192.0.2.10/32 route-map RTBH")
					dao11jWant(t, "R18b.NewGen", f.row(t).Gen, 9)
				} else {
					dao11jWant(t, "R18b.Cancelled", f.scheduled(id), "cancelled")
					dao11jWant(t, "R18b.Withdrawn", f.row(t).Status == "withdrawn" && f.row(t).Gen == 8, true)
				}
			})
		})
	}
}
func TestDao11j_R18c_ExecutingOwnsLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("delayed", 7)
		scanned, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		f.r.beforeGet = func(int) { <-scanned }
		f.r.afterList = func(status string, rows []store.BGPAnnouncement) ([]store.BGPAnnouncement, error) {
			if status == "withdrawing" && f.r.lists.Load() == 1 {
				close(scanned)
			}
			return rows, nil
		}
		f.r.afterWithdrawing = func(int) { close(entered); <-release }
		f.schedule(t, "executing", 0)
		f.e.ReconcileOnStartup(context.Background())
		synctest.Wait()
		dao11jWant(t, "R18c.Isolated", dao11jClosed(scanned) && dao11jClosed(entered), true)
		before := f.metric("busy")
		cancel, _ := f.start(time.Minute)
		defer cancel()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "R18c.Busy", f.metric("busy")-before, float64(1))
		dao11jWant(t, "R18c.NoClaim", f.r.claims.Load(), int64(0))
		close(release)
		synctest.Wait()
		dao11jWant(t, "R18c.Final", f.row(t).Status == "withdrawn" && f.row(t).Gen == 7, true)
	})
}
func TestDao11j_R18_ExecutingWait(t *testing.T) {
	for _, scenario := range []string{"D_TakenOver", "E_InitialFailed", "F_ObservedSameGen"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao11jNew(t)
				f.set("delayed", 7)
				if scenario == "E_InitialFailed" {
					f.set("failed", 7)
				}
				unlock := f.e.LockAnnouncement(f.id)
				id := f.schedule(t, "executing", 0)
				f.e.ReconcileOnStartup(context.Background())
				synctest.Wait() // The executing goroutine is durably blocked at channel send.
				dao11jWant(t, "R18.ExecutingWait", f.r.gets.Load(), int64(0))
				if scenario != "E_InitialFailed" {
					if scenario == "F_ObservedSameGen" {
						f.e.CancelAnnouncementDelay(f.id, 7, "shared attach")
					}
					ok, err := f.base.anns.MarkWithdrawing(context.Background(), f.id, 7)
					dao5bCheck(t, err)
					dao11jWant(t, "R18.FixtureWithdrawing", ok, true)
					if scenario == "D_TakenOver" {
						gen, ok, err := f.base.anns.ClaimWithdrawing(context.Background(), f.id, 7)
						dao5bCheck(t, err)
						dao11jWant(t, "R18d.FixtureClaim", ok && gen == 8, true)
						f.e.NoteAnnouncementTakeover(f.id)
						f.e.CancelAnnouncementDelay(f.id, 8, "test takeover")
						dao5bCheck(t, f.base.anns.MarkFailedWithdraw(context.Background(), f.id, 8, "takeover failed"))
					} else {
						dao5bCheck(t, f.base.anns.MarkFailedWithdraw(context.Background(), f.id, 7, "original failure"))
					}
				}
				unlock()
				synctest.Wait()
				if scenario == "D_TakenOver" {
					dao11jWant(t, "R18d.NoGet", f.r.gets.Load(), int64(0))
					dao11jWant(t, "R18d.NoVtysh", f.commands(t), 0)
					dao11jWant(t, "R18d.Completed", f.scheduled(id), "completed")
				} else {
					name := "R18e"
					if scenario == "F_ObservedSameGen" {
						name = "R18f"
					}
					dao11jWant(t, name+".Get", f.r.gets.Load(), int64(1))
					dao11jWant(t, name+".Vtysh", f.commands(t), 1)
					dao11jWant(t, name+".Withdrawn", f.row(t).Status == "withdrawn" && f.row(t).Gen == 7, true)
				}
			})
		})
	}
}

func TestDao11j_R14c_ForceNoopSameStatusNewGen(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		_, gen, err := f.base.anns.ForceWithdraw(context.Background(), f.id)
		dao5bCheck(t, err)
		dao5bCheck(t, f.base.anns.MarkWithdrawn(context.Background(), f.id, gen))
		f.r.afterForce = func(_ int, oldGen int) {
			dao11jWant(t, "R14c.OldGen", oldGen, 1)
			a := dao5bNewAttack(t, f.base, 21)
			dao5bCheck(t, f.base.anns.MarkAnnounced(context.Background(), f.id, a.Gen))
			d, err := f.base.anns.Detach(context.Background(), 21, "192.0.2.10/32", "RTBH", 7)
			dao5bCheck(t, err)
			dao11jWant(t, "R14c.NewWithdrawing", d.NeedWithdraw && d.Gen == 2, true)
		}
		dao5bCheck(t, f.e.ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH"))
		dao11jWant(t, "R14c.NoOldWithdraw", f.commands(t), 0)
		dao11jWant(t, "R14c.NoFalseTakeover", f.e.AnnouncementTakeovers(f.id), 0)
	})
}

func TestDao11j_R18g_PendingLockWaitKeepsBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		f.set("delayed", 7)
		unlock := f.e.LockAnnouncement(f.id)
		id := f.schedule(t, "pending", time.Second)
		dao5bCheck(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao11jAdvance(time.Second)
		dao11jWant(t, "R18g.AtLock", f.sched.marks.Load(), int64(0))
		dao11jAdvance(31 * time.Second)
		unlock()
		synctest.Wait()
		dao11jWant(t, "R18g.Withdrawn", f.row(t).Status, "withdrawn")
		dao11jWant(t, "R18g.Vtysh", f.commands(t), 1)
		dao11jWant(t, "R18g.Completed", f.scheduled(id), "completed")
	})
}

func TestDao11j_R18h_SupersededKeepsNewCancelHandle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao11jNew(t)
		_, _, err := f.base.anns.ForceWithdraw(context.Background(), f.id)
		dao5bCheck(t, err)
		f.set("delayed", 7)
		unlock := f.e.LockAnnouncement(f.id)
		old := f.schedule(t, "executing", 0)
		f.e.ReconcileOnStartup(context.Background())
		synctest.Wait()
		ok, err := f.base.anns.MarkWithdrawing(context.Background(), f.id, 7)
		dao5bCheck(t, err)
		dao11jWant(t, "R18h.Fixture", ok, true)
		_, ok, err = f.base.anns.ClaimWithdrawing(context.Background(), f.id, 7)
		dao5bCheck(t, err)
		dao11jWant(t, "R18h.Claim", ok, true)
		f.e.NoteAnnouncementTakeover(f.id)
		f.e.CancelAnnouncementDelay(f.id, 8, "takeover")
		dao5bCheck(t, f.base.anns.MarkFailedWithdraw(context.Background(), f.id, 8, "failure"))
		a, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21, DelayMinutes: 1})
		dao5bCheck(t, err)
		dao11jWant(t, "R18h.NewGen", a.Gen, 9)
		dao5bCheck(t, f.base.anns.MarkAnnounced(context.Background(), f.id, 9))
		d, err := f.base.anns.Detach(context.Background(), 21, "192.0.2.10/32", "RTBH", 7)
		dao5bCheck(t, err)
		dao11jWant(t, "R18h.NewDelayed", d.Delayed && d.Gen == 9, true)
		_, pending, err := f.e.ScheduleDelayForAnnouncement(context.Background(), f.id, 9, time.Now().Add(time.Minute))
		dao5bCheck(t, err)
		unlock()
		synctest.Wait()
		dao11jWant(t, "R18h.OldCompleted", f.scheduled(old), "completed")
		f.e.CancelAnnouncementDelay(f.id, 9, "new cancellation")
		dao11jWant(t, "R18h.HandlePreserved", dao11jClosed(pending.Done()), true)
	})
}

// R18i: the executing-entry snapshot must be taken in the parent before dispatch,
// never inside the goroutine (a takeover between dispatch and goroutine start
// would otherwise become the baseline).
func TestDao11j_R18i_ExecutingSnapshotBeforeGo(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "../action/engine.go", nil, 0)
	dao5bCheck(t, err)
	snapshots := func(n ast.Node) int {
		count := 0
		ast.Inspect(n, func(n ast.Node) bool {
			a, ok := n.(*ast.AssignStmt)
			if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
				return true
			}
			if id, ok := a.Lhs[0].(*ast.Ident); !ok || id.Name != "snap" {
				return true
			}
			if call, ok := a.Rhs[0].(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "AnnouncementTakeovers" {
					count++
				}
			}
			return true
		})
		return count
	}
	found := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "reconcileExecutingSchedules" {
			continue
		}
		found = true
		inside := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if g, ok := n.(*ast.GoStmt); ok {
				inside += snapshots(g)
				return false
			}
			return true
		})
		dao11jWant(t, "R18i.ParentSnapshot", snapshots(fn.Body), 1)
		dao11jWant(t, "R18i.NotInsideGo", inside, 0)
	}
	dao11jWant(t, "R18i.FuncFound", found, true)
}
