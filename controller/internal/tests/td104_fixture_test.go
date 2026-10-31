package tests

import (
	"context"
	"database/sql"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
)

// Hooks run outside repository locks. Fixture setters run at synctest barriers.
type td104Store struct {
	*MockStore
	mu     sync.Mutex
	calls  map[string]int
	hooks  map[string]func()
	faults map[string]bool
}

func (s *td104Store) hit(name string) bool {
	s.mu.Lock()
	s.calls[name]++
	h, fail := s.hooks[name], s.faults[name]
	s.mu.Unlock()
	if h != nil {
		h()
	}
	return fail
}
func (s *td104Store) count(name string) int      { s.mu.Lock(); defer s.mu.Unlock(); return s.calls[name] }
func (s *td104Store) hook(name string, h func()) { s.mu.Lock(); defer s.mu.Unlock(); s.hooks[name] = h }
func (s *td104Store) fail(name string)           { s.mu.Lock(); defer s.mu.Unlock(); s.faults[name] = true }

type td104Anns struct {
	store.BGPAnnouncementRepo
	s *td104Store
}
type td104Rules struct {
	store.XDropActiveRuleRepo
	s *td104Store
}
type td104Responses struct {
	store.ResponseRepo
	s *td104Store
}
type td104Schedules struct {
	store.ScheduledActionRepo
	s *td104Store
}

func (s *td104Store) BGPAnnouncements() store.BGPAnnouncementRepo {
	return td104Anns{s.MockStore.BGPAnnouncements(), s}
}
func (s *td104Store) XDropActiveRules() store.XDropActiveRuleRepo {
	return td104Rules{s.MockStore.XDropActiveRules(), s}
}
func (s *td104Store) Responses() store.ResponseRepo {
	return td104Responses{s.MockStore.Responses(), s}
}
func (s *td104Store) ScheduledActions() store.ScheduledActionRepo {
	return td104Schedules{s.MockStore.ScheduledActions(), s}
}
func (r td104Anns) ListAttachmentsForAttack(ctx context.Context, id int) ([]store.BGPAnnouncementAttack, error) {
	r.s.hit("attachments")
	return r.BGPAnnouncementRepo.ListAttachmentsForAttack(ctx, id)
}
func (r td104Anns) ReconcileAttachments(ctx context.Context, id int, ended []int, detach bool) (store.BGPReconcileResult, error) {
	r.s.hit("reconcile")
	return r.BGPAnnouncementRepo.ReconcileAttachments(ctx, id, ended, detach)
}
func (r td104Anns) Detach(ctx context.Context, a int, p, rm string, c int) (store.BGPDetachResult, error) {
	r.s.hit("detach")
	return r.BGPAnnouncementRepo.Detach(ctx, a, p, rm, c)
}
func (r td104Rules) ListByAttack(ctx context.Context, id int) ([]store.XDropActiveRule, error) {
	r.s.hit("rules")
	rows, err := r.XDropActiveRuleRepo.ListByAttack(ctx, id)
	r.s.hit("listed_rules")
	return rows, err
}
func (r td104Rules) ClaimActive(ctx context.Context, a, b, c int, key string) (bool, error) {
	if r.s.hit("claim_active") {
		return false, errors.New("TD104 narrow claim failure")
	}
	return r.XDropActiveRuleRepo.(interface {
		ClaimActive(context.Context, int, int, int, string) (bool, error)
	}).ClaimActive(ctx, a, b, c, key)
}

type td104BGPConnectors struct {
	store.BGPConnectorRepo
	s *td104Store
}
type td104XDropConnectors struct {
	store.XDropConnectorRepo
	s *td104Store
}

func (s *td104Store) BGPConnectors() store.BGPConnectorRepo {
	return td104BGPConnectors{s.MockStore.BGPConnectors(), s}
}
func (s *td104Store) XDropConnectors() store.XDropConnectorRepo {
	return td104XDropConnectors{s.MockStore.XDropConnectors(), s}
}
func (r td104BGPConnectors) Get(ctx context.Context, id int) (*store.BGPConnector, error) {
	if r.s.hit("bgp_connector") {
		return nil, errors.New("TD104 connector query failure")
	}
	c, err := r.BGPConnectorRepo.Get(ctx, id)
	// Main mock Get has only a not-found error; preserve pgx's errors.Is
	// contract without changing existing fixtures' error strings.
	if err != nil {
		err = errors.Join(err, sql.ErrNoRows)
	}
	return c, err
}
func (r td104XDropConnectors) Get(ctx context.Context, id int) (*store.XDropConnector, error) {
	if r.s.hit("xdrop_connector") {
		return nil, errors.New("TD104 connector query failure")
	}
	c, err := r.XDropConnectorRepo.Get(ctx, id)
	if err != nil {
		err = errors.Join(err, sql.ErrNoRows)
	}
	return c, err
}
func (r td104Rules) MarkWithdrawing(ctx context.Context, a, b, c int, key string) (bool, error) {
	if r.s.hit("mark_withdrawing") {
		return false, errors.New("TD104 claim write failure")
	}
	return r.XDropActiveRuleRepo.MarkWithdrawing(ctx, a, b, c, key)
}
func (r td104Rules) MarkWithdrawn(ctx context.Context, a, b, c int, key string) error {
	if r.s.hit("mark_withdrawn") {
		return errors.New("TD104 terminal write failure")
	}
	return r.XDropActiveRuleRepo.MarkWithdrawn(ctx, a, b, c, key)
}
func (r td104Rules) MarkDelayed(ctx context.Context, a, b, c int, key string, d int) error {
	if r.s.hit("mark_delayed") {
		return errors.New("TD104 delayed write failure")
	}
	return r.XDropActiveRuleRepo.MarkDelayed(ctx, a, b, c, key, d)
}
func (r td104Responses) Get(ctx context.Context, id int) (*store.Response, error) {
	// A test-only sentinel terminates the lifetime dispatcher after all work
	// has joined, without exporting or changing production shutdown behavior.
	if id == -104 {
		runtime.Goexit()
	}
	r.s.hit("response")
	return r.ResponseRepo.Get(ctx, id)
}

func (f *td104Fixture) stopQueue() {
	ev := f.event
	a := *ev.Attack
	a.ResponseID = intPtr(-104)
	ev.Attack, ev.Type = &a, "confirmed"
	f.e.Enqueue(ev)
	synctest.Wait()
}
func (r td104Responses) ListActions(ctx context.Context, id int) ([]store.ResponseAction, error) {
	if r.s.hit("actions") {
		return nil, errors.New("TD104 list actions failure")
	}
	return r.ResponseRepo.ListActions(ctx, id)
}
func (r td104Responses) GetAction(ctx context.Context, id int) (*store.ResponseAction, error) {
	a, err := r.ResponseRepo.GetAction(ctx, id)
	if id == 30 {
		r.s.hit("before_delay")
	}
	return a, err
}
func (r td104Schedules) Schedule(ctx context.Context, a *store.ScheduledAction) (int, error) {
	r.s.hit("schedule")
	return r.ScheduledActionRepo.Schedule(ctx, a)
}

type td104Fixture struct {
	s      *td104Store
	e      *action.Engine
	event  tracker.AttackEvent
	d      *dao4Transport
	path   string
	ann    int
	reg    *prometheus.Registry
	before map[string]float64
}

func td104New(t *testing.T, delay int) *td104Fixture {
	t.Helper()
	ms := NewMockStore()
	s := &td104Store{MockStore: ms, calls: map[string]int{}, hooks: map[string]func(){}, faults: map[string]bool{}}
	script, path := dao4Vtysh(t)
	ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "TD104", Enabled: true, VtyshPath: script, BGPASN: 64512}}
	ms.xdropConnectors.connectors = []store.XDropConnector{{ID: 7, Name: "TD104", Enabled: true, APIURL: "http://td104.invalid"}}
	ms.responses.responses = []store.Response{{ID: 1, Name: "TD104", Enabled: true}}
	ms.responses.actions = []store.ResponseAction{
		{ID: 10, ResponseID: 1, ActionType: "bgp", Enabled: true, TriggerPhase: "on_detected", RunMode: "once", BGPConnectorID: intPtr(7), BGPRouteMap: "RTBH"},
		{ID: 11, ResponseID: 1, ActionType: "bgp", Enabled: true, TriggerPhase: "on_expired", RunMode: "once", BGPConnectorID: intPtr(7), BGPRouteMap: "RTBH"},
		{ID: 30, ResponseID: 1, ActionType: "xdrop", Enabled: true, TriggerPhase: "on_detected", RunMode: "once", XDropAction: "drop", UnblockDelayMinutes: delay},
		{ID: 31, ResponseID: 1, ActionType: "xdrop", Enabled: true, TriggerPhase: "on_expired", RunMode: "once", XDropAction: "unblock"},
	}
	now := time.Now()
	a := store.Attack{ID: 20, ResponseID: intPtr(1), DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", StartedAt: now, EndedAt: &now}
	ms.attacks.attacks = []store.Attack{a}
	r, err := ms.BGPAnnouncements().Attach(fzCtx, store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 20, ActionID: intPtr(10), DelayMinutes: delay})
	fzCheck(t, err)
	fzCheck(t, ms.BGPAnnouncements().MarkAnnounced(fzCtx, r.AnnouncementID, dao5bCurrentGen(t, ms.BGPAnnouncements(), r.AnnouncementID)))
	_, err = ms.XDropActiveRules().Upsert(fzCtx, &store.XDropActiveRule{AttackID: 20, ActionID: 30, ConnectorID: 7, ExternalRuleID: "rule-1", Status: "active"})
	fzCheck(t, err)
	f := &td104Fixture{s: s, path: path, ann: r.AnnouncementID, event: tracker.AttackEvent{Type: "expired", DBID: 20, Attack: &a}, d: dao4HTTP(t), reg: prometheus.NewRegistry()}
	f.e = action.NewEngine(s, "auto")
	fzCheck(t, metrics.Register(f.reg, ms, dao4Tracker(ms, nil)))
	f.before = f.values(t)
	return f
}
func (f *td104Fixture) values(t *testing.T) map[string]float64 {
	t.Helper()
	fs, err := f.reg.Gather()
	fzCheck(t, err)
	out := map[string]float64{}
	for _, fam := range fs {
		if fam.GetName() == "xsight_ended_sweep_total" {
			for _, m := range fam.Metric {
				var k, o string
				for _, l := range m.Label {
					if l.GetName() == "kind" {
						k = l.GetValue()
					}
					if l.GetName() == "outcome" {
						o = l.GetValue()
					}
				}
				out[k+"/"+o] = m.GetCounter().GetValue()
			}
		}
	}
	return out
}
func (f *td104Fixture) delta(t *testing.T, want map[string]float64) {
	t.Helper()
	got := f.values(t)
	for k, v := range want {
		fzEqual(t, k, got[k]-f.before[k], v)
	}
	for k, v := range got {
		if _, ok := want[k]; !ok {
			fzEqual(t, k, v-f.before[k], float64(0))
		}
	}
}
func (f *td104Fixture) disable(t *testing.T) {
	t.Helper()
	fzCheck(t, f.s.responses.Update(fzCtx, &store.Response{ID: 1, Name: "TD104", Enabled: false}))
}
func (f *td104Fixture) run() { f.e.HandleEvent(f.event); synctest.Wait() }
func (f *td104Fixture) state(t *testing.T, bgp, rule string, network, deletes int) {
	t.Helper()
	a, err := f.s.MockStore.BGPAnnouncements().Get(fzCtx, f.ann)
	fzCheck(t, err)
	r, err := f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
	fzCheck(t, err)
	fzEqual(t, "BGP status", a.Status, bgp)
	if len(r) > 0 {
		fzEqual(t, "rule status", r[0].Status, rule)
	}
	fzEqual(t, "no network", strings.Count(dao4Read(t, f.path), "no network"), network)
	fzEqual(t, "DELETE", f.d.count(), deletes)
}
func (f *td104Fixture) cancel() {
	f.e.CancelAnnouncementDelay(f.ann, 0, "test cleanup")
	f.e.CancelDelaysForAttack(20)
	synctest.Wait()
}
func (f *td104Fixture) onlyBGP() {
	f.s.xdropActiveRules.records = nil
	f.s.responses.actions = f.s.responses.actions[:2]
}
func (f *td104Fixture) onlyXDrop() {
	f.s.bgpAnnouncements.attacks = nil
	f.s.responses.actions = f.s.responses.actions[2:]
}
