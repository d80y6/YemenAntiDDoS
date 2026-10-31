package tests

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Repository barriers run outside mock locks and work with both baseline and
// delivered code. The public entry points remain the subject of these tests.
type dao14c1Probe struct {
	mu    sync.Mutex
	calls map[string]int
	hooks map[string]func(context.Context, int) error
}

func (p *dao14c1Probe) hit(c context.Context, key string, id int) error {
	p.mu.Lock()
	p.calls[key]++
	h := p.hooks[key]
	p.mu.Unlock()
	if h != nil {
		return h(c, id)
	}
	return nil
}
func (p *dao14c1Probe) hook(key string, h func(context.Context, int) error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.hooks[key] = h
}
func (p *dao14c1Probe) count(key string) int { p.mu.Lock(); defer p.mu.Unlock(); return p.calls[key] }

type dao14c1Store struct {
	store.Store
	anns  store.BGPAnnouncementRepo
	conns store.BGPConnectorRepo
	atks  store.AttackRepo
	sched store.ScheduledActionRepo
	logs  store.ActionExecLogRepo
}

func (s dao14c1Store) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }
func (s dao14c1Store) BGPConnectors() store.BGPConnectorRepo       { return s.conns }
func (s dao14c1Store) Attacks() store.AttackRepo                   { return s.atks }
func (s dao14c1Store) ScheduledActions() store.ScheduledActionRepo { return s.sched }
func (s dao14c1Store) ActionExecLog() store.ActionExecLogRepo      { return s.logs }

type dao14c1Anns struct {
	store.BGPAnnouncementRepo
	p *dao14c1Probe
}

func (r dao14c1Anns) ListActive(c context.Context) ([]store.BGPAnnouncement, error) {
	if err := r.p.hit(c, "list_active", 0); err != nil {
		return nil, err
	}
	rows, err := r.BGPAnnouncementRepo.ListActive(c)
	if err == nil {
		err = r.p.hit(c, "listed_active", 0)
	}
	return rows, err
}
func (r dao14c1Anns) ListAttacks(c context.Context, id int) ([]store.BGPAnnouncementAttack, error) {
	if err := r.p.hit(c, "list_attacks", id); err != nil {
		return nil, err
	}
	return r.BGPAnnouncementRepo.ListAttacks(c, id)
}
func (r dao14c1Anns) ListAttachmentsForAttack(c context.Context, id int) ([]store.BGPAnnouncementAttack, error) {
	rows, err := r.BGPAnnouncementRepo.ListAttachmentsForAttack(c, id)
	if err == nil {
		err = r.p.hit(c, "listed_attachments", id)
	}
	return rows, err
}
func (r dao14c1Anns) ReconcileAttachments(c context.Context, id int, ended []int, detach bool) (store.BGPReconcileResult, error) {
	if err := r.p.hit(c, "reconcile", id); err != nil {
		return store.BGPReconcileResult{}, err
	}
	return r.BGPAnnouncementRepo.ReconcileAttachments(c, id, ended, detach)
}
func (r dao14c1Anns) Detach(c context.Context, a int, prefix, rm string, conn int) (store.BGPDetachResult, error) {
	if err := r.p.hit(c, "detach", a); err != nil {
		return store.BGPDetachResult{}, err
	}
	return r.BGPAnnouncementRepo.Detach(c, a, prefix, rm, conn)
}
func (r dao14c1Anns) FindByBusinessKey(c context.Context, prefix, rm string, conn int) (*store.BGPAnnouncement, error) {
	ann, err := r.BGPAnnouncementRepo.FindByBusinessKey(c, prefix, rm, conn)
	if err == nil {
		err = r.p.hit(c, "found", conn)
	}
	if err != nil {
		return nil, err
	}
	return ann, err
}
func (r dao14c1Anns) ListByStatus(c context.Context, status string) ([]store.BGPAnnouncement, error) {
	if err := r.p.hit(c, "status_"+status, 0); err != nil {
		return nil, err
	}
	return r.BGPAnnouncementRepo.ListByStatus(c, status)
}
func (r dao14c1Anns) Attach(c context.Context, v store.BGPAttachParams) (store.BGPAttachResult, error) {
	a, err := r.BGPAnnouncementRepo.Attach(c, v)
	_ = r.p.hit(c, "attached", v.AttackID)
	return a, err
}
func (r dao14c1Anns) MarkWithdrawn(c context.Context, id, gen int) error {
	err := r.BGPAnnouncementRepo.MarkWithdrawn(c, id, gen)
	_ = r.p.hit(c, "withdrawn", id)
	return err
}

type dao14c1Conns struct {
	store.BGPConnectorRepo
	p *dao14c1Probe
}

func (r dao14c1Conns) Get(c context.Context, id int) (*store.BGPConnector, error) {
	if err := r.p.hit(c, "get_connector", id); err != nil {
		return nil, err
	}
	v, err := r.BGPConnectorRepo.Get(c, id)
	if err == nil {
		err = r.p.hit(c, "got_connector", id)
	}
	return v, err
}
func (r dao14c1Conns) Update(c context.Context, v *store.BGPConnector) error {
	if err := r.p.hit(c, "update_connector", v.ID); err != nil {
		return err
	}
	return r.BGPConnectorRepo.Update(c, v)
}

type dao14c1Atks struct {
	store.AttackRepo
	p *dao14c1Probe
}

func (r dao14c1Atks) LiveIDs(c context.Context, ids []int) (map[int]bool, error) {
	if err := r.p.hit(c, "live", 0); err != nil {
		return nil, err
	}
	return r.AttackRepo.LiveIDs(c, ids)
}

type dao14c1Sched struct {
	store.ScheduledActionRepo
	p *dao14c1Probe
}

func (r dao14c1Sched) ListPending(c context.Context) ([]store.ScheduledAction, error) {
	if err := r.p.hit(c, "pending", 0); err != nil {
		return nil, err
	}
	return r.ScheduledActionRepo.ListPending(c)
}
func (r dao14c1Sched) Complete(c context.Context, id int) error {
	if err := r.p.hit(c, "complete", id); err != nil {
		return err
	}
	err := r.ScheduledActionRepo.Complete(c, id)
	_ = r.p.hit(c, "completed", id)
	return err
}

type dao14c1Logs struct {
	store.ActionExecLogRepo
	p *dao14c1Probe
}

func (r dao14c1Logs) Create(c context.Context, v *store.ActionExecutionLog) (int, error) {
	if err := r.p.hit(c, "log_"+v.Status, v.AttackID); err != nil {
		return 0, err
	}
	id, err := r.ActionExecLogRepo.Create(c, v)
	_ = r.p.hit(c, "logged", v.AttackID)
	return id, err
}

type dao14c1Rig struct {
	ms     *MockStore
	s      dao14c1Store
	p      *dao14c1Probe
	e      *action.Engine
	record string
	log    *dao5LogBuffer
}

func dao14c1New(t *testing.T, ended, enabled bool) *dao14c1Rig {
	t.Helper()
	ms, _, record := dao4RecoveryFixture(t, "active")
	ms.bgpConnectors.connectors[0].Enabled = enabled
	if ended {
		now := time.Now()
		ms.attacks.attacks[0].EndedAt = &now
	}
	p := &dao14c1Probe{calls: map[string]int{}, hooks: map[string]func(context.Context, int) error{}}
	s := dao14c1Store{ms, dao14c1Anns{ms.BGPAnnouncements(), p}, dao14c1Conns{ms.BGPConnectors(), p}, dao14c1Atks{ms.Attacks(), p}, dao14c1Sched{ms.ScheduledActions(), p}, dao14c1Logs{ms.ActionExecLog(), p}}
	return &dao14c1Rig{ms, s, p, action.NewEngine(s, "auto"), record, dao5CaptureLog(t)}
}
func dao14c1Check(t *testing.T, name string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ASSERT %s FAIL got=%v want=%v", name, got, want)
	} else {
		t.Logf("ASSERT %s PASS got=%v", name, got)
	}
}
func dao14c1Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("DEVICE %v", err)
	}
}
func (f *dao14c1Rig) request(t *testing.T, method, path, body string, engine *action.Engine) int {
	t.Helper()
	r := api.NewRouter(api.Dependencies{Store: f.s, ActionEngine: engine, JWTSecret: testJWTSecret})
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code
}
func (f *dao14c1Rig) put(t *testing.T, body string) int {
	return f.request(t, http.MethodPut, "/api/settings/bgp-connectors/7", body, f.e)
}
func (f *dao14c1Rig) row(t *testing.T, id int) *store.BGPAnnouncement {
	t.Helper()
	r, err := f.ms.BGPAnnouncements().Get(context.Background(), id)
	dao14c1Must(t, err)
	if r == nil {
		t.Fatalf("DEVICE missing announcement %d", id)
	}
	return r
}
func (f *dao14c1Rig) no(t *testing.T, prefix string) int {
	return strings.Count(dao4Read(t, f.record), "no network "+prefix+" route-map")
}
func (f *dao14c1Rig) connector(t *testing.T, enabled bool) {
	c, err := f.ms.BGPConnectors().Get(context.Background(), 7)
	dao14c1Must(t, err)
	c.Enabled = enabled
	dao14c1Must(t, f.ms.BGPConnectors().Update(context.Background(), c))
}
func (f *dao14c1Rig) ending(id int) {
	f.ms.attacks.mu.Lock()
	defer f.ms.attacks.mu.Unlock()
	for i := range f.ms.attacks.attacks {
		if f.ms.attacks.attacks[i].ID == id {
			now := time.Now()
			f.ms.attacks.attacks[i].EndedAt = &now
		}
	}
}
func (f *dao14c1Rig) actions() {
	f.ms.responses.responses = []store.Response{{ID: 1, Name: "dao14c1", Enabled: true}}
	f.ms.responses.actions = []store.ResponseAction{
		{ID: 10, ResponseID: 1, ActionType: "bgp", TriggerPhase: "on_detected", RunMode: "once", Enabled: true, Execution: "automatic", BGPConnectorID: intPtr(7), BGPRouteMap: "RTBH"},
		{ID: 11, ResponseID: 1, ActionType: "bgp", TriggerPhase: "on_expired", RunMode: "once", Enabled: true, Execution: "automatic", BGPConnectorID: intPtr(7), BGPRouteMap: "RTBH"},
	}
}
func (f *dao14c1Rig) event(kind string, id int) tracker.AttackEvent {
	return tracker.AttackEvent{Type: kind, DBID: id, Attack: &store.Attack{ID: id, DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", ResponseID: intPtr(1), StartedAt: time.Now()}}
}
func (f *dao14c1Rig) add(ann, attack, conn int, prefix string, ended bool) {
	a := store.Attack{ID: attack, DstIP: strings.Split(prefix, "/")[0], StartedAt: time.Now()}
	if ended {
		now := time.Now()
		a.EndedAt = &now
	}
	f.ms.attacks.mu.Lock()
	f.ms.attacks.attacks = append(f.ms.attacks.attacks, a)
	f.ms.attacks.mu.Unlock()
	f.ms.bgpAnnouncements.mu.Lock()
	defer f.ms.bgpAnnouncements.mu.Unlock()
	if ann != 1 {
		f.ms.bgpAnnouncements.announcements = append(f.ms.bgpAnnouncements.announcements, store.BGPAnnouncement{ID: ann, Prefix: prefix, RouteMap: "RTBH", ConnectorID: conn, Status: "active", Refcount: 1})
	} else {
		f.ms.bgpAnnouncements.announcements[0].Refcount++
	}
	f.ms.bgpAnnouncements.attacks = append(f.ms.bgpAnnouncements.attacks, store.BGPAnnouncementAttack{AnnouncementID: ann, AttackID: attack, ActionID: intPtr(10)})
}
func (f *dao14c1Rig) schedule(t *testing.T, executing bool) int {
	id, err := f.ms.ScheduledActions().Schedule(context.Background(), &store.ScheduledAction{ActionType: "bgp_withdraw", AnnouncementID: intPtr(1), ScheduledFor: time.Now().Add(-time.Second)})
	dao14c1Must(t, err)
	if executing {
		dao14c1Must(t, f.ms.ScheduledActions().MarkExecuting(context.Background(), id))
	}
	return id
}
func (f *dao14c1Rig) scheduled(id int) store.ScheduledAction {
	f.ms.scheduledActions.mu.Lock()
	defer f.ms.scheduledActions.mu.Unlock()
	for _, r := range f.ms.scheduledActions.records {
		if r.ID == id {
			return r
		}
	}
	return store.ScheduledAction{}
}
func dao14c1Metrics() map[string]float64 {
	ch := make(chan prometheus.Metric, 64)
	metrics.EndedSweep.Collect(ch)
	close(ch)
	v := map[string]float64{}
	for m := range ch {
		d := &dto.Metric{}
		_ = m.Write(d)
		kind, outcome := "", ""
		for _, l := range d.Label {
			if l.GetName() == "kind" {
				kind = l.GetValue()
			}
			if l.GetName() == "outcome" {
				outcome = l.GetValue()
			}
		}
		if kind == "bgp" {
			v[outcome] = d.GetCounter().GetValue()
		}
	}
	return v
}
func dao14c1Delta(before map[string]float64) map[string]float64 {
	after := dao14c1Metrics()
	delta := map[string]float64{}
	for k, v := range after {
		if v != before[k] {
			delta[k] = v - before[k]
		}
	}
	return delta
}
func (f *dao14c1Rig) detached(t *testing.T, id int) bool {
	rows, err := f.ms.BGPAnnouncements().ListAttacks(context.Background(), 1)
	dao14c1Must(t, err)
	for _, r := range rows {
		if r.AttackID == id {
			return r.DetachedAt != nil
		}
	}
	return false
}
func dao14c1Gate(p *dao14c1Probe, key string) (chan struct{}, chan struct{}) {
	entered, release := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	p.hook(key, func(context.Context, int) error {
		if first.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return nil
	})
	return entered, release
}

func TestDao14c1_PastEntryDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, true)
		f.add(2, 21, 7, "192.0.2.20/32", true)
		// The interface keeps this file compilable on HEAD, where the public
		// sweep entry is absent and this post-delivery guard reports DEVICE.
		sweeper, ok := any(f.e).(interface{ SweepEnabledBGPConnector(int) })
		if !ok {
			t.Fatal("DEVICE enabled sweep entry is absent on HEAD")
		}
		listed := make(chan context.Context, 1)
		f.p.hook("listed_active", func(c context.Context, _ int) error {
			listed <- c
			return nil
		})
		unlock := f.e.LockAnnouncement(1)
		released := false
		defer func() {
			if !released {
				unlock()
			}
		}()
		returned := make(chan struct{})
		go func() {
			sweeper.SweepEnabledBGPConnector(7)
			close(returned)
		}()
		entry := dao14c1Await(t, "entry queries finished", listed, 3*time.Second)
		synctest.Wait()
		if f.p.count("reconcile") != 0 {
			t.Fatal("DEVICE sweep did not wait at the first announcement lock")
		}
		// Advance virtual time while the first announcement lock remains held.
		// This timer is the input that exhausts the entry budget, not a guess
		// about completion; returned below is the actual completion signal.
		advance := time.NewTimer(61 * time.Second)
		<-advance.C
		synctest.Wait()
		dao14c1Check(t, "PastEntryDeadline.EntryExpired", entry.Err(), context.DeadlineExceeded)
		unlock()
		released = true
		dao14c1Await(t, "sweep returned after entry deadline", returned, 5*time.Second)
		synctest.Wait()
		dao14c1Check(t, "PastEntryDeadline.FirstRow", f.row(t, 1).Status, "withdrawn")
		dao14c1Check(t, "PastEntryDeadline.FirstCommands", f.no(t, "192.0.2.10/32"), 1)
		dao14c1Check(t, "PastEntryDeadline.SecondRow", f.row(t, 2).Status, "withdrawn")
		dao14c1Check(t, "PastEntryDeadline.SecondCommands", f.no(t, "192.0.2.20/32"), 1)
	})
}

func TestDao14c1_A1(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, false)
		before := dao14c1Metrics()
		dao14c1Check(t, "A1.HTTP", f.put(t, `{"enabled":true}`), 200)
		synctest.Wait()
		dao14c1Check(t, "A1.Commands", f.no(t, "192.0.2.10/32"), 1)
		r := f.row(t, 1)
		dao14c1Check(t, "A1.Row", r.Status == "withdrawn" && r.Refcount == 0 && f.detached(t, 20), true)
		dao14c1Check(t, "A1.Metric", dao14c1Delta(before), map[string]float64{"dispatched": 1})
		dao14c1Check(t, "A1.Log", strings.Contains(f.log.text(), "enabled connector sweep kind=bgp connector=7"), true)
	})
}
func TestDao14c1_A2(t *testing.T) {
	for _, body := range []string{`{"enabled":true}`, `{"name":"x"}`} {
		for _, behavior := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/Behavior=%v", body, behavior), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := dao14c1New(t, false, true)
					dao14c1Check(t, "A2.HTTP", f.put(t, body), 200)
					synctest.Wait()
					if behavior {
						dao14c1Check(t, "A2b.Sweeps", f.p.count("reconcile") >= 1 && strings.Contains(f.log.text(), "enabled connector sweep"), true)
					} else {
						r := f.row(t, 1)
						dao14c1Check(t, "A2a.LiveKept", f.no(t, "192.0.2.10/32") == 0 && r.Status == "active" && r.Refcount == 1, true)
					}
				})
			})
		}
	}
}
func TestDao14c1_A3(t *testing.T) {
	for _, body := range []string{`{"enabled":false}`, `{"name":"x"}`} {
		t.Run(body, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, false)
				f.put(t, body)
				synctest.Wait()
				dao14c1Check(t, "A3.StaysDisabled", []int{f.no(t, "192.0.2.10/32"), f.p.count("reconcile"), f.p.count("list_active")}, []int{0, 0, 0})
			})
		})
	}
}
func TestDao14c1_A4(t *testing.T) {
	for _, own := range []bool{false, true} {
		t.Run(fmt.Sprintf("Own=%v", own), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, false)
				c, _ := f.ms.BGPConnectors().Get(context.Background(), 7)
				c.ID = 8
				c.Enabled = true
				f.ms.bgpConnectors.appendConnectors(*c)
				f.add(2, 30, 8, "198.51.100.20/32", true)
				f.put(t, `{"enabled":true}`)
				synctest.Wait()
				if own {
					dao14c1Check(t, "A4a.ThisOneWithdrawn", f.no(t, "192.0.2.10/32") == 1 && f.row(t, 1).Status == "withdrawn", true)
				} else {
					dao14c1Check(t, "A4b.OtherUntouched", f.no(t, "198.51.100.20/32") == 0 && f.row(t, 2).Status == "active", true)
				}
			})
		})
	}
}
func TestDao14c1_A5(t *testing.T) {
	for _, metric := range []bool{false, true} {
		t.Run(fmt.Sprintf("Metric=%v", metric), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, false)
				_, err := f.ms.ScheduledActions().Schedule(context.Background(), &store.ScheduledAction{ActionType: "bgp_withdraw", AnnouncementID: intPtr(1), ScheduledFor: time.Now().Add(time.Hour)})
				dao14c1Must(t, err)
				before := dao14c1Metrics()
				f.put(t, `{"enabled":true}`)
				synctest.Wait()
				if metric {
					dao14c1Check(t, "A5b.Metric", dao14c1Delta(before), map[string]float64{"skipped_status": 1})
				} else {
					dao14c1Check(t, "A5a.Untouched", f.no(t, "192.0.2.10/32") == 0 && f.row(t, 1).Status == "active", true)
				}
			})
		})
	}
}
func TestDao14c1_A6(t *testing.T) {
	for _, mode := range []string{"Live", "PartialGuard", "PartialDetached"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, mode != "Live", false)
				if mode != "Live" {
					f.add(1, 21, 7, "192.0.2.10/32", false)
				}
				before := dao14c1Metrics()
				f.put(t, `{"enabled":true}`)
				synctest.Wait()
				if mode == "PartialDetached" {
					dao14c1Check(t, "A6b.Detached", f.detached(t, 20) && f.row(t, 1).Refcount == 1, true)
					dao14c1Check(t, "A6b.Metric", dao14c1Delta(before), map[string]float64{"detached_kept": 1})
				} else {
					dao14c1Check(t, "A6.Guard", f.no(t, "192.0.2.10/32") == 0 && f.row(t, 1).Status == "active", true)
					if mode == "Live" {
						dao14c1Check(t, "A6a.Refcount", f.row(t, 1).Refcount, 1)
					}
				}
			})
		})
	}
}

func dao14c1Inflight(t *testing.T, recovered bool) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, true)
		f.actions()
		f.ms.bgpAnnouncements.announcements[0].DelayMinutes = 1
		f.ms.bgpAnnouncements.attacks[0].DelayMinutes = 1
		entered, release := dao14c1Gate(f.p, "detach")
		f.e.HandleEvent(f.event("expired", 20))
		<-entered
		label := "A7"
		if recovered {
			label = "B4"
			id := f.schedule(t, false)
			dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
			synctest.Wait()
			dao14c1Check(t, label+".Schedule", f.scheduled(id).Status, "completed")
		} else {
			f.connector(t, false)
			f.put(t, `{"enabled":true}`)
			synctest.Wait()
		}
		dao14c1Check(t, label+".NoSweepDetach", f.no(t, "192.0.2.10/32"), 0)
		close(release)
		synctest.Wait()
		pending, _ := f.ms.ScheduledActions().ListPending(context.Background())
		dao14c1Check(t, label+".ChildOwns", f.row(t, 1).Status == "delayed" && len(pending) == 1 && f.no(t, "192.0.2.10/32") == 0, true)
		<-time.After(61 * time.Second)
		synctest.Wait()
		dao14c1Check(t, label+".EventuallyOnce", f.no(t, "192.0.2.10/32") == 1 && f.row(t, 1).Status == "withdrawn", true)
	})
}
func TestDao14c1_A7(t *testing.T) { dao14c1Inflight(t, false) }
func TestDao14c1_A7b(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, false)
		f.actions()
		entered, release := dao14c1Gate(f.p, "log_skipped")
		f.e.HandleEvent(f.event("expired", 20))
		<-entered
		synctest.Wait()
		f.put(t, `{"enabled":true}`)
		synctest.Wait()
		dao14c1Check(t, "A7b.Excluded", f.no(t, "192.0.2.10/32"), 0)
		close(release)
		synctest.Wait()
		dao14c1Check(t, "A7b.SweepCatches", f.no(t, "192.0.2.10/32") == 1 && f.row(t, 1).Status == "withdrawn", true)
	})
}
func TestDao14c1_A8(t *testing.T) {
	for _, enableFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("EnableFirst=%v", enableFirst), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, false)
				key := "listed_attachments"
				label := "A8a"
				if enableFirst {
					key = "reconcile"
					label = "A8b"
				}
				entered, release := dao14c1Gate(f.p, key)
				before := dao14c1Metrics()
				if enableFirst {
					f.put(t, `{"enabled":true}`)
				} else {
					f.e.HandleEvent(f.event("expired", 20))
				}
				synctest.Wait()
				select {
				case <-entered:
				default:
					close(release)
					t.Fatalf("DEVICE %s barrier not reached", label)
				}
				if enableFirst {
					f.e.HandleEvent(f.event("expired", 20))
				} else {
					f.put(t, `{"enabled":true}`)
				}
				synctest.Wait()
				close(release)
				synctest.Wait()
				dao14c1Check(t, label+".Commands", f.no(t, "192.0.2.10/32"), 1)
				dao14c1Check(t, label+".Row", f.row(t, 1).Status, "withdrawn")
				if enableFirst {
					dao14c1Check(t, label+".Metric", dao14c1Delta(before), map[string]float64{"dispatched": 1, "skipped_status": 1})
				}
			})
		})
	}
}
func TestDao14c1_A9(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("UpdateError=%v", fail), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, false)
				e := f.e
				want := 500
				if fail {
					f.p.hook("update_connector", func(context.Context, int) error { return errors.New("update unavailable") })
				} else {
					e = nil
					want = 200
				}
				dao14c1Check(t, "A9.HTTP", f.request(t, http.MethodPut, "/api/settings/bgp-connectors/7", `{"enabled":true}`, e), want)
				synctest.Wait()
				dao14c1Check(t, "A9.NoSweep", []int{f.no(t, "192.0.2.10/32"), f.p.count("list_active")}, []int{0, 0})
			})
		})
	}
}
func TestDao14c1_A10(t *testing.T) {
	for _, key := range []string{"pending", "list_active", "live"} {
		t.Run(key, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, false)
				f.p.hook(key, func(context.Context, int) error { return errors.New("sweep unavailable") })
				before := dao14c1Metrics()
				f.put(t, `{"enabled":true}`)
				synctest.Wait()
				dao14c1Check(t, "A10.Failed", dao14c1Delta(before), map[string]float64{"failed": 1})
				dao14c1Check(t, "A10.NoCommand", f.no(t, "192.0.2.10/32"), 0)
				dao14c1Check(t, "A10.Row", f.row(t, 1).Status, "active")
			})
		})
	}
}
func TestDao14c1_A11(t *testing.T) {
	for _, own := range []bool{false, true} {
		t.Run(fmt.Sprintf("Own=%v", own), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, false)
				f.ms.bgpConnectors.connectors[0].ID = 3
				f.ms.bgpAnnouncements.announcements[0].ConnectorID = 3
				c := f.ms.bgpConnectors.connectors[0]
				c.ID = 1
				c.Enabled = true
				f.ms.bgpConnectors.appendConnectors(c)
				f.ms.bgpAnnouncements.announcements = append(f.ms.bgpAnnouncements.announcements, store.BGPAnnouncement{ID: 2, Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 1, Status: "orphan", Gen: 4})
				before := *f.row(t, 2)
				f.request(t, http.MethodPut, "/api/settings/bgp-connectors/3", `{"enabled":true}`, f.e)
				synctest.Wait()
				if own {
					dao14c1Check(t, "A11a.Withdrawn", f.row(t, 1).Status == "withdrawn" && f.no(t, "192.0.2.10/32") == 1, true)
				} else {
					dao14c1Check(t, "A11b.OrphanUntouched", *f.row(t, 2), before)
				}
			})
		})
	}
}
func TestDao14c1_A12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, false, true)
		entered, release := dao14c1Gate(f.p, "got_connector")
		done := make(chan int, 1)
		go func() { done <- f.put(t, `{"name":"renamed"}`) }()
		<-entered
		dao14c1Check(t, "A12.DisableHTTP", f.put(t, `{"enabled":false}`), 200)
		f.ending(20)
		close(release)
		dao14c1Check(t, "A12.StaleHTTP", <-done, 200)
		synctest.Wait()
		dao14c1Check(t, "A12.Withdrawn", f.no(t, "192.0.2.10/32") == 1 && f.row(t, 1).Status == "withdrawn", true)
	})
}

func TestDao14c1_A13(t *testing.T) {
	for _, order := range []string{"SweepFirst", "ForceFirst", "ForceThenReannounceBeforeSweep"} {
		t.Run(order, func(t *testing.T) {
			f := dao14c1New(t, true, false)
			f.actions()
			contexts := dao14c1SignalContext(f)
			retries := make(chan context.Context, 4)
			f.p.hook("get_connector", func(c context.Context, _ int) error {
				if d, ok := c.Deadline(); ok && time.Until(d) > 10*time.Second && time.Until(d) <= 30*time.Second {
					retries <- c
				}
				return nil
			})
			gate := dao14c1Process(t, f, "192.0.2.10/32")
			defer gate.release()
			label := "A13." + order
			if order == "ForceThenReannounceBeforeSweep" {
				entered, release := dao14c1Gate(f.p, "pending")
				f.put(t, `{"enabled":true}`)
				dao14c1Await(t, "snapshot gate", entered, 5*time.Second)
				done := f.force(t, 20, "192.0.2.10/32")
				dao14c1Await(t, "force process", gate.entered, 5*time.Second)
				gate.release()
				dao14c1Must(t, dao14c1Await(t, "force", done, 2*time.Second))
				f.newAttack(t)
				close(release)
			} else if order == "ForceFirst" {
				done := f.force(t, 20, "192.0.2.10/32")
				dao14c1Await(t, "force process", gate.entered, 5*time.Second)
				f.put(t, `{"enabled":true}`)
				<-time.After(300 * time.Millisecond)
				// HEAD has no enable sweep. If dispatched, join its own completion.
				select {
				case c := <-contexts:
					dao14c1Finished(t, c, label+".SweepComplete")
				default:
				}
				gate.release()
				dao14c1Must(t, dao14c1Await(t, "force", done, 2*time.Second))
				f.newAttack(t)
				dao14c1AssertResurrected(t, f, label)
				return
			} else {
				f.put(t, `{"enabled":true}`)
				dao14c1Await(t, "sweep process", gate.entered, 5*time.Second)
				reached := dao14c1ForceReached(f)
				done := f.force(t, 20, "192.0.2.10/32")
				dao14c1Await(t, "force lookup", reached, 2*time.Second)
				early := false
				var err error
				select {
				case err = <-done:
					early = true
				case <-time.After(300 * time.Millisecond):
				}
				dao14c1Check(t, label+".ForceWaits", early, false)
				if early {
					dao14c1Must(t, err)
					f.newAttack(t)
				}
				gate.release()
				if !early {
					dao14c1Check(t, label+".ForceNoop", dao14c1Await(t, "force", done, 2*time.Second), nil)
					f.newAttack(t)
				}
			}
			c := dao14c1Await(t, "sweep context", contexts, 5*time.Second)
			dao14c1Finished(t, c, label+".SweepComplete")
			if order == "SweepFirst" {
				c := dao14c1Await(t, "sweep retry context", retries, 3*time.Second)
				dao14c1Finished(t, c, label+".RetryComplete")
			}
			dao14c1AssertResurrected(t, f, label)
		})
	}
}
