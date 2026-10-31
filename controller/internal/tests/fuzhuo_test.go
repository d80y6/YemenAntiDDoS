package tests

import (
	"context"
	"errors"
	"fmt"
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
	dto "github.com/prometheus/client_model/go"
)

var fzCtx = context.Background()

type fzStore struct {
	*MockStore
	anns  *fzAnnouncements
	atks  *fzAttacks
	conns *fzConnectors
	sched *fzSchedules
	rules *fzRules
}

func (s *fzStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }
func (s *fzStore) Attacks() store.AttackRepo                   { return s.atks }
func (s *fzStore) BGPConnectors() store.BGPConnectorRepo       { return s.conns }
func (s *fzStore) ScheduledActions() store.ScheduledActionRepo { return s.sched }
func (s *fzStore) XDropActiveRules() store.XDropActiveRuleRepo { return s.rules }

type fzAnnouncements struct {
	store.BGPAnnouncementRepo
	mu        sync.Mutex
	calls     []bool
	listHook  func()
	withdrawn chan int
}

func (r *fzAnnouncements) MarkWithdrawn(ctx context.Context, id int, gen int) error {
	err := r.BGPAnnouncementRepo.MarkWithdrawn(ctx, id, gen)
	if r.withdrawn != nil {
		r.withdrawn <- id
	}
	return err
}
func (r *fzAnnouncements) ListActive(ctx context.Context) ([]store.BGPAnnouncement, error) {
	r.mu.Lock()
	h := r.listHook
	r.mu.Unlock()
	if h != nil {
		h()
	}
	return r.BGPAnnouncementRepo.ListActive(ctx)
}
func (r *fzAnnouncements) ReconcileAttachments(ctx context.Context, id int, ended []int, detach bool) (store.BGPReconcileResult, error) {
	r.mu.Lock()
	r.calls = append(r.calls, detach)
	r.mu.Unlock()
	return r.BGPAnnouncementRepo.ReconcileAttachments(ctx, id, ended, detach)
}
func (r *fzAnnouncements) snapshotCalls() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool{}, r.calls...)
}
func (r *fzAnnouncements) hook(h func()) { r.mu.Lock(); defer r.mu.Unlock(); r.listHook = h }

type fzAttacks struct {
	store.AttackRepo
	failID int
}

func (r *fzAttacks) LiveIDs(ctx context.Context, ids []int) (map[int]bool, error) {
	for _, id := range ids {
		if id == r.failID {
			return nil, errors.New("LiveIDs fixture failure")
		}
	}
	return r.AttackRepo.LiveIDs(ctx, ids)
}

type fzConnectors struct {
	store.BGPConnectorRepo
	mu    sync.Mutex
	calls map[int]int
	gate  <-chan struct{}
}

func (r *fzConnectors) Get(ctx context.Context, id int) (*store.BGPConnector, error) {
	r.mu.Lock()
	r.calls[id]++
	n, gate := r.calls[id], r.gate
	r.mu.Unlock()
	// G1: the first query belongs to cleanup, the second to retryBGPWithdraw.
	if n == 2 && gate != nil {
		<-gate
	}
	return r.BGPConnectorRepo.Get(ctx, id)
}

type fzSchedules struct {
	store.ScheduledActionRepo
	mu   sync.Mutex
	fail bool
}

func (r *fzSchedules) ListPending(ctx context.Context) ([]store.ScheduledAction, error) {
	r.mu.Lock()
	fail := r.fail
	r.mu.Unlock()
	if fail {
		return nil, errors.New("schedule snapshot fixture failure")
	}
	return r.ScheduledActionRepo.ListPending(ctx)
}
func (r *fzSchedules) setFail(v bool) { r.mu.Lock(); defer r.mu.Unlock(); r.fail = v }

type fzRules struct {
	store.XDropActiveRuleRepo
	mu       sync.Mutex
	claims   int
	deny     bool
	listHook func()
}

func (r *fzRules) ListActive(ctx context.Context) ([]store.XDropActiveRule, error) {
	r.mu.Lock()
	h := r.listHook
	r.mu.Unlock()
	if h != nil {
		h()
	}
	return r.XDropActiveRuleRepo.ListActive(ctx)
}
func (r *fzRules) MarkWithdrawing(ctx context.Context, a, b, c int, key string) (bool, error) {
	r.mu.Lock()
	r.claims++
	deny := r.deny
	r.mu.Unlock()
	if deny {
		return false, nil
	}
	return r.XDropActiveRuleRepo.MarkWithdrawing(ctx, a, b, c, key)
}
func (r *fzRules) claimCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.claims }
func (r *fzRules) hook(h func())   { r.mu.Lock(); defer r.mu.Unlock(); r.listHook = h }

func fzCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func fzEqual(t *testing.T, label string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: got %#v; want %#v", label, got, want)
	} else {
		t.Logf("PASS %s: %#v", label, got)
	}
}
func fzMetric(kind, outcome string) float64 {
	m := &dto.Metric{}
	_ = metrics.StartupCleanup.WithLabelValues(kind, outcome).Write(m)
	return m.GetCounter().GetValue()
}
func fzDelta(t *testing.T, kind, outcome string, before, want float64) {
	t.Helper()
	fzEqual(t, "metric "+kind+"/"+outcome, fzMetric(kind, outcome)-before, want)
}
func fzNew(t *testing.T) (*fzStore, string) {
	t.Helper()
	ms := NewMockStore()
	dir := t.TempDir()
	output := filepath.Join(dir, "calls")
	fzCheck(t, os.WriteFile(output, nil, 0600))
	script := filepath.Join(dir, "vtysh")
	quote := strings.ReplaceAll(output, "'", "'\\''")
	fzCheck(t, os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '"+quote+"'\nexit 0\n"), 0700))
	ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "fuzhuo", Enabled: true, VtyshPath: script, BGPASN: 64512, AddressFamily: "ipv4 unicast"}}
	ms.responses.responses = []store.Response{{ID: 1, Name: "fuzhuo", Enabled: true}}
	ms.responses.actions = []store.ResponseAction{{ID: 10, ResponseID: 1, ActionType: "bgp", TriggerPhase: "on_detected", Enabled: true, PairedWith: intPtr(11)}, {ID: 11, ResponseID: 1, ActionType: "bgp", TriggerPhase: "on_expired", Enabled: true}}
	ms.xdropConnectors.connectors = []store.XDropConnector{{ID: 7, Name: "fuzhuo", APIURL: "http://fuzhuo.invalid", Enabled: true}}
	s := &fzStore{MockStore: ms}
	s.anns = &fzAnnouncements{BGPAnnouncementRepo: ms.BGPAnnouncements()}
	s.atks = &fzAttacks{AttackRepo: ms.Attacks()}
	s.conns = &fzConnectors{BGPConnectorRepo: ms.BGPConnectors(), calls: map[int]int{}}
	s.sched = &fzSchedules{ScheduledActionRepo: ms.ScheduledActions()}
	s.rules = &fzRules{XDropActiveRuleRepo: ms.XDropActiveRules()}
	return s, output
}
func fzAttack(t *testing.T, s *fzStore, ended bool) int {
	t.Helper()
	n, err := s.Attacks().Count(fzCtx, store.AttackFilter{})
	fzCheck(t, err)
	a := store.Attack{DstIP: fmt.Sprintf("192.0.2.%d", n+1), Direction: "receives", DecoderFamily: "udp", StartedAt: time.Now().Add(time.Duration(n) * time.Second), ResponseID: intPtr(1)}
	id, err := s.Attacks().Create(fzCtx, &a)
	fzCheck(t, err)
	if ended {
		a.ID = id
		now := time.Now()
		a.EndedAt = &now
		fzCheck(t, s.Attacks().Update(fzCtx, &a))
	}
	return id
}
func (r *mockBGPAnnouncementRepo) fzSet(id, count int, status string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.findByIDLocked(id)
	a.Refcount = count
	a.Status = status
	a.AnnouncedAt = time.Now().Add(time.Duration(id) * time.Nanosecond)
}
func fzAnn(t *testing.T, s *fzStore, count int, status string, ids ...int) int {
	t.Helper()
	rows, err := s.BGPAnnouncements().ListActive(fzCtx)
	fzCheck(t, err)
	prefix := fmt.Sprintf("192.0.2.%d/32", 70+len(rows))
	var ann int
	for _, id := range ids {
		r, err := s.BGPAnnouncements().Attach(fzCtx, store.BGPAttachParams{Prefix: prefix, RouteMap: "RTBH", ConnectorID: 7, AttackID: id, ActionID: intPtr(10)})
		fzCheck(t, err)
		ann = r.AnnouncementID
	}
	s.bgpAnnouncements.fzSet(ann, count, status)
	return ann
}
func fzState(t *testing.T, s *fzStore, id, count int, status string, detached ...int) {
	t.Helper()
	a, err := s.BGPAnnouncements().Get(fzCtx, id)
	fzCheck(t, err)
	fzEqual(t, "refcount", a.Refcount, count)
	fzEqual(t, "status", a.Status, status)
	rows, err := s.BGPAnnouncements().ListAttacks(fzCtx, id)
	fzCheck(t, err)
	want := map[int]bool{}
	for _, id := range detached {
		want[id] = true
	}
	for _, r := range rows {
		fzEqual(t, fmt.Sprintf("attack %d detached", r.AttackID), r.DetachedAt != nil, want[r.AttackID])
	}
}
func fzCalls(t *testing.T, path string, want int) {
	t.Helper()
	b, err := os.ReadFile(path)
	fzCheck(t, err)
	fzEqual(t, "no network count", strings.Count(string(b), "no network"), want)
}
func fzCleanup(s *fzStore) {
	action.NewEngine(s, "auto").CleanupEndedAttachments(fzCtx, action.StartupScheduleSnapshot{}, nil)
}
func fzDetach(t *testing.T, s *fzStore, ann, id int) store.BGPDetachResult {
	t.Helper()
	a, err := s.BGPAnnouncements().Get(fzCtx, ann)
	fzCheck(t, err)
	r, err := s.BGPAnnouncements().Detach(fzCtx, id, a.Prefix, a.RouteMap, a.ConnectorID)
	fzCheck(t, err)
	return r
}

func fzWithdraw(t *testing.T, variant string) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		id := 999
		if variant != "deleted" {
			id = fzAttack(t, s, true)
		}
		mode := "auto"
		switch variant {
		case "child_disabled":
			s.responses.actions[1].Enabled = false
		case "parent_deleted":
			s.responses.actions = nil
		case "response_disabled":
			s.responses.responses[0].Enabled = false
		case "observe":
			mode = "observe"
		}
		ann := fzAnn(t, s, 1, "active", id)
		gate := make(chan struct{})
		s.conns.gate = gate
		before := fzMetric("bgp", "dispatched")
		done := make(chan struct{})
		go func() {
			action.NewEngine(s, mode).CleanupEndedAttachments(fzCtx, action.StartupScheduleSnapshot{}, nil)
			close(done)
		}()
		synctest.Wait()
		fzState(t, s, ann, 0, "withdrawing", id)
		fzDelta(t, "bgp", "dispatched", before, 1)
		fzCalls(t, path, 0)
		close(gate)
		<-done
		synctest.Wait()
		fzState(t, s, ann, 0, "withdrawn", id)
		fzCalls(t, path, 1)
	})
}
func TestFuzhuo_G16_WithdrawnBeforeCleanupReturns(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		id := fzAttack(t, s, true)
		ann := fzAnn(t, s, 1, "active", id)
		fzCleanup(s)
		// Inspect at return, before giving the asynchronous workers a wait point.
		fzState(t, s, ann, 0, "withdrawn", id)
		fzCalls(t, path, 1)
		synctest.Wait()
	})
}
func TestFuzhuo_G5_OwnerPolicy(t *testing.T) {
	for _, v := range []string{"child_disabled", "parent_deleted", "response_disabled", "observe"} {
		t.Run(v, func(t *testing.T) { fzWithdraw(t, v) })
	}
}
func TestFuzhuo_G6_DeletedAttack(t *testing.T)      { fzWithdraw(t, "deleted") }
func TestFuzhuo_G2_Shared(t *testing.T)             { fzShared(t, 2) }
func TestFuzhuo_G3_PhantomCleanupOnly(t *testing.T) { fzShared(t, 1) }
func fzShared(t *testing.T, count int) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		a, b := fzAttack(t, s, true), fzAttack(t, s, false)
		ann := fzAnn(t, s, count, "active", a, b)
		before := fzMetric("bgp", "detached_kept")
		fzCleanup(s)
		synctest.Wait()
		fzState(t, s, ann, 1, "active", a)
		fzCalls(t, path, 0)
		fzDelta(t, "bgp", "detached_kept", before, 1)
	})
}
func TestFuzhuo_G4_Overcount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		a := fzAttack(t, s, true)
		ann := fzAnn(t, s, 2, "active", a)
		before := fzMetric("bgp", "skipped_inconsistent")
		fzCleanup(s)
		synctest.Wait()
		fzArm(t, "Guard", func(t *testing.T) { fzState(t, s, ann, 2, "active"); fzCalls(t, path, 0) })
		fzArm(t, "Metric", func(t *testing.T) { fzDelta(t, "bgp", "skipped_inconsistent", before, 1) })
	})
}
func TestFuzhuo_G7_LiveOutsideTracker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		a := fzAttack(t, s, false)
		ann := fzAnn(t, s, 1, "active", a)
		fzCleanup(s)
		synctest.Wait()
		fzArm(t, "Guard", func(t *testing.T) { fzState(t, s, ann, 1, "active"); fzCalls(t, path, 0) })
		fzArm(t, "Consistent", func(t *testing.T) {
			r, err := s.BGPAnnouncements().ReconcileAttachments(fzCtx, ann, nil, true)
			fzCheck(t, err)
			fzEqual(t, "Skipped", r.Skipped, "consistent")
		})
	})
}
func TestFuzhuo_G8_NonActive(t *testing.T) {
	for _, status := range []string{"delayed", "announcing", "withdrawing", "failed"} {
		t.Run(status, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, path := fzNew(t)
				a := fzAttack(t, s, true)
				ann := fzAnn(t, s, 1, status, a)
				fzCleanup(s)
				synctest.Wait()
				fzEqual(t, "reconcile calls", len(s.anns.snapshotCalls()), 0)
				fzState(t, s, ann, 1, status)
				fzCalls(t, path, 0)
			})
		})
	}
}
func TestFuzhuo_G9_LiveQueryFailureContinues(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		a, b := fzAttack(t, s, true), fzAttack(t, s, true)
		good := fzAnn(t, s, 1, "active", b)
		bad := fzAnn(t, s, 1, "active", a)
		s.atks.failID = a
		before := fzMetric("bgp", "failed")
		fzCleanup(s)
		synctest.Wait()
		fzState(t, s, bad, 1, "active")
		fzState(t, s, good, 0, "withdrawn", b)
		fzCalls(t, path, 1)
		fzDelta(t, "bgp", "failed", before, 1)
	})
}
func TestFuzhuo_G12_UndercountCleanupOnly(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		c, b := fzAttack(t, s, false), fzAttack(t, s, false)
		ann := fzAnn(t, s, 1, "active", c, b)
		before := fzMetric("bgp", "recounted_up")
		fzCleanup(s)
		synctest.Wait()
		fzState(t, s, ann, 2, "active")
		fzDelta(t, "bgp", "recounted_up", before, 1)
		fzCalls(t, path, 0)
		r := fzDetach(t, s, ann, c)
		fzEqual(t, "NeedWithdraw", r.NeedWithdraw, false)
		fzState(t, s, ann, 1, "active", c)
	})
}
func fzSchedule(s *fzStore, kind, status string, ann *int, attack int) {
	s.scheduledActions.appendRecords(store.ScheduledAction{ID: 1, ActionType: kind, Status: status, AnnouncementID: ann, AttackID: attack, ActionID: 10, ConnectorID: 7, ExternalRuleID: "rule-1"})
}
func TestFuzhuo_G13_Scheduled(t *testing.T) {
	for _, status := range []string{"pending", "executing"} {
		for _, prepare := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/prepare=%t", status, prepare), func(t *testing.T) { fzScheduled(t, prepare, "") })
		}
	}
}
func TestFuzhuo_G13b_SnapshotBeforeAnnouncementList(t *testing.T) { fzScheduled(t, false, "list") }
func TestFuzhuo_G13c_PreSnapshotSurvivesCompletion(t *testing.T)  { fzScheduled(t, true, "pre") }
func fzScheduled(t *testing.T, prepare bool, finish string) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		a := fzAttack(t, s, true)
		ann := fzAnn(t, s, 1, "active", a)
		status := "pending"
		if strings.Contains(t.Name(), "executing") {
			status = "executing"
		}
		fzSchedule(s, "bgp_withdraw", status, &ann, a)
		e := action.NewEngine(s, "auto")
		var pre action.StartupScheduleSnapshot
		var err error
		if prepare {
			pre, err = e.PrepareStartupCleanup(fzCtx)
			fzCheck(t, err)
		}
		if finish == "pre" {
			fzCheck(t, s.ScheduledActions().Complete(fzCtx, 1))
		}
		if finish == "list" {
			s.anns.hook(func() { fzCheck(t, s.ScheduledActions().Complete(fzCtx, 1)) })
		}
		before := fzMetric("bgp", "skipped_scheduled")
		e.CleanupEndedAttachments(fzCtx, pre, err)
		synctest.Wait()
		fzArm(t, "Guard", func(t *testing.T) { fzState(t, s, ann, 1, "active"); fzCalls(t, path, 0) })
		fzArm(t, "Calls", func(t *testing.T) {
			want := []bool{}
			if prepare {
				want = []bool{false}
			}
			fzEqual(t, "reconcile calls", s.anns.snapshotCalls(), want)
		})
		fzArm(t, "Metric", func(t *testing.T) { fzDelta(t, "bgp", "skipped_scheduled", before, 1) })
	})
}
func TestFuzhuo_G14_PrepareBeforeLegacyDetach(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, path := fzNew(t)
		c, b, a := fzAttack(t, s, false), fzAttack(t, s, false), fzAttack(t, s, true)
		ann := fzAnn(t, s, 1, "active", c, b, a)
		fzSchedule(s, "bgp_withdraw", "pending", &ann, a)
		e := action.NewEngine(s, "auto")
		before := fzMetric("bgp", "recounted_up")
		pre, err := e.PrepareStartupCleanup(fzCtx)
		fzCheck(t, err)
		fzState(t, s, ann, 3, "active")
		fzDelta(t, "bgp", "recounted_up", before, 1)
		r := fzDetach(t, s, ann, a)
		fzEqual(t, "A NeedWithdraw", r.NeedWithdraw, false)
		fzState(t, s, ann, 2, "active", a)
		fzCheck(t, s.ScheduledActions().Complete(fzCtx, 1))
		before = fzMetric("bgp", "skipped_scheduled")
		e.CleanupEndedAttachments(fzCtx, pre, err)
		synctest.Wait()
		fzDelta(t, "bgp", "skipped_scheduled", before, 1)
		fzCalls(t, path, 0)
		r = fzDetach(t, s, ann, c)
		fzEqual(t, "C NeedWithdraw", r.NeedWithdraw, false)
		fzEqual(t, "C Delayed", r.Delayed, false)
		fzState(t, s, ann, 1, "active", a, c)
	})
}
func TestFuzhuo_G14b_PrepareAnnouncing(t *testing.T) {
	s, path := fzNew(t)
	b, c := fzAttack(t, s, false), fzAttack(t, s, false)
	ann := fzAnn(t, s, 1, "announcing", b, c)
	_, err := action.NewEngine(s, "auto").PrepareStartupCleanup(fzCtx)
	fzCheck(t, err)
	fzState(t, s, ann, 2, "announcing")
	fzCheck(t, s.BGPAnnouncements().MarkAnnounced(fzCtx, ann, dao5bCurrentGen(t, s.BGPAnnouncements(), ann)))
	r := fzDetach(t, s, ann, c)
	fzEqual(t, "NeedWithdraw", r.NeedWithdraw, false)
	fzState(t, s, ann, 1, "active", c)
	fzCalls(t, path, 0)
}
func TestFuzhuo_G15_PreErrorNotOverwritten(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		s, path := fzNew(t)
		a := fzAttack(t, s, true)
		ann := fzAnn(t, s, 1, "active", a)
		fzCheck(t, fzRule(s, a, "active", "rule-1"))
		s.sched.setFail(true)
		e := action.NewEngine(s, "auto")
		pre, err := e.PrepareStartupCleanup(fzCtx)
		s.sched.setFail(false)
		beforeB, beforeX := fzMetric("bgp", "failed"), fzMetric("xdrop", "failed")
		e.CleanupEndedAttachments(fzCtx, pre, err)
		synctest.Wait()
		fzArm(t, "Guard", func(t *testing.T) {
			fzEqual(t, "reconcile calls", len(s.anns.snapshotCalls()), 0)
			fzEqual(t, "claims", s.rules.claimCount(), 0)
			fzEqual(t, "HTTP", d.count(), 0)
			fzState(t, s, ann, 1, "active")
			fzCalls(t, path, 0)
		})
		fzArm(t, "Metric", func(t *testing.T) { fzDelta(t, "bgp", "failed", beforeB, 1); fzDelta(t, "xdrop", "failed", beforeX, 1) })
	})
}
func fzRule(s *fzStore, a int, status, key string) error {
	_, err := s.XDropActiveRules().Upsert(fzCtx, &store.XDropActiveRule{AttackID: a, ActionID: 10, ConnectorID: 7, ExternalRuleID: key, Status: status})
	return err
}

// G1 and G10 live in action/startup_cleanup_test.go to adjust the private wait limit.

func TestFuzhuo_X1_EndedRule(t *testing.T) { fzXDrop(t, "active", false, "", false, false) }
func TestFuzhuo_X1b_Observe(t *testing.T)  { fzXDrop(t, "active", false, "", true, false) }
func TestFuzhuo_X2_Scheduled(t *testing.T) {
	for _, status := range []string{"pending", "executing"} {
		t.Run(status, func(t *testing.T) { fzXDrop(t, "active", false, status, false, false) })
	}
}
func TestFuzhuo_X2b_SnapshotBeforeRuleList(t *testing.T) {
	fzXDrop(t, "active", false, "list", false, false)
}
func TestFuzhuo_X2c_PreSnapshotSurvivesCompletion(t *testing.T) {
	fzXDrop(t, "active", false, "pre", false, false)
}
func TestFuzhuo_X3_FailedExcluded(t *testing.T) {
	for _, key := range []string{"ordinary", "synthetic"} {
		t.Run(key, func(t *testing.T) { fzXDrop(t, "failed", false, "", false, key == "synthetic") })
	}
}
func TestFuzhuo_X4_LiveOrDelayed(t *testing.T) {
	t.Run("live", func(t *testing.T) { fzXDrop(t, "active", true, "", false, false) })
	t.Run("delayed", func(t *testing.T) { fzXDrop(t, "delayed", false, "", false, false) })
}
func TestFuzhuo_X5_ClaimLost(t *testing.T) { fzXDrop(t, "active", false, "claim", false, false) }
func fzXDrop(t *testing.T, status string, live bool, scheduled string, observe, synthetic bool) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		s, _ := fzNew(t)
		a := fzAttack(t, s, !live)
		key := "rule-1"
		if synthetic {
			key = "failed-create-1"
		}
		fzCheck(t, fzRule(s, a, status, key))
		s.rules.deny = scheduled == "claim"
		if scheduled != "" && scheduled != "claim" {
			phase := "pending"
			if scheduled == "pre" || scheduled == "executing" {
				phase = "executing"
			}
			fzSchedule(s, "xdrop_unblock", phase, nil, a)
		}
		mode := "auto"
		if observe {
			mode = "observe"
		}
		e := action.NewEngine(s, mode)
		var pre action.StartupScheduleSnapshot
		var err error
		if scheduled == "pre" {
			pre, err = e.PrepareStartupCleanup(fzCtx)
			fzCheck(t, err)
			fzCheck(t, s.ScheduledActions().Complete(fzCtx, 1))
		}
		if scheduled == "list" {
			s.rules.hook(func() { fzCheck(t, s.ScheduledActions().Complete(fzCtx, 1)) })
		}
		outcome := ""
		want := 0
		claims := 0
		if status == "active" && !live {
			switch scheduled {
			case "":
				outcome = "dispatched"
				want = 1
				claims = 1
			case "claim":
				outcome = "skipped_claimed"
				claims = 1
			default:
				outcome = "skipped_scheduled"
			}
		}
		before := 0.0
		if outcome != "" {
			before = fzMetric("xdrop", outcome)
		}
		e.CleanupEndedAttachments(fzCtx, pre, err)
		synctest.Wait()
		fzArm(t, "Behavior", func(t *testing.T) {
			fzEqual(t, "HTTP DELETE count", d.count(), want)
			fzEqual(t, "execution logs", len(s.actionExecLog.snapshotLogs()), want)
			rows, err := s.XDropActiveRules().ListByAttack(fzCtx, a)
			fzCheck(t, err)
			fzEqual(t, "rules", len(rows), 1)
			wantStatus := status
			if want == 1 {
				wantStatus = "withdrawn"
			}
			fzEqual(t, "rule status", rows[0].Status, wantStatus)
			// X5 counts differ on the empty baseline, but all skip guards demand zero DELETE.
			if scheduled != "claim" {
				fzEqual(t, "claim calls", s.rules.claimCount(), claims)
			}
		})
		if outcome != "" && scheduled != "list" {
			fzArm(t, "Metric", func(t *testing.T) { fzDelta(t, "xdrop", outcome, before, 1) })
		}
	})
}

func fzArm(t *testing.T, name string, f func(*testing.T)) { t.Helper(); t.Log("arm: " + name); f(t) }
