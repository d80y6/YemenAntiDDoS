package action

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

type dao4BGPStore struct {
	*v3Store
	connectors    *dao4BGPConnectors
	announcements *dao4BGPAnnouncements
}

func (s *dao4BGPStore) BGPConnectors() store.BGPConnectorRepo           { return s.connectors }
func (s *dao4BGPStore) BGPAnnouncements() store.BGPAnnouncementRepo     { return s.announcements }
func (s *dao4BGPStore) ManualOverrides() store.ActionManualOverrideRepo { return dao4BGPOverrides{} }

type dao4BGPOverrides struct{ store.ActionManualOverrideRepo }

func (dao4BGPOverrides) Exists(context.Context, int, int, int, string) (bool, error) {
	return false, nil
}

type dao4BGPConnectors struct {
	store.BGPConnectorRepo
	mu    sync.Mutex
	fail  bool
	calls int
}

func (r *dao4BGPConnectors) Get(context.Context, int) (*store.BGPConnector, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail {
		return nil, errors.New("dao4 missing connector")
	}
	return &store.BGPConnector{ID: 7, Enabled: true, BGPASN: 64512, VtyshPath: "/usr/bin/true"}, nil
}
func (r *dao4BGPConnectors) setFail(v bool) { r.mu.Lock(); defer r.mu.Unlock(); r.fail = v }
func (r *dao4BGPConnectors) count() int     { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

type dao4BGPAnnouncements struct{ store.BGPAnnouncementRepo }

func (*dao4BGPAnnouncements) Attach(context.Context, store.BGPAttachParams) (store.BGPAttachResult, error) {
	return store.BGPAttachResult{AnnouncementID: 1, NeedAnnounce: true}, nil
}
func (*dao4BGPAnnouncements) MarkAnnounced(context.Context, int, int) error { return nil }
func dao4BGPFixture() (*dao4BGPStore, *Engine, store.ResponseAction, tracker.AttackEvent) {
	s := &dao4BGPStore{v3Store: newV3Store("http://unused.invalid"), connectors: &dao4BGPConnectors{}, announcements: &dao4BGPAnnouncements{}}
	cid, rid := 7, 1
	a := store.ResponseAction{ID: 10, ResponseID: rid, ActionType: "bgp", BGPConnectorID: &cid, BGPRouteMap: "RTBH", TriggerPhase: "on_detected", RunMode: "retry_until_success", Enabled: true}
	s.actions = []store.ResponseAction{a}
	ev := tracker.AttackEvent{Type: "confirmed", DBID: 20, Attack: &store.Attack{ID: 20, DstIP: "192.0.2.10", DecoderFamily: "udp", ResponseID: &rid}}
	return s, NewEngine(s, "auto"), a, ev
}
func dao4PersistBGP(t *testing.T, s *dao4BGPStore, phase, status string, cid *int) {
	t.Helper()
	_, err := s.ActionExecLog().Create(context.Background(), &store.ActionExecutionLog{AttackID: 20, ActionID: 10, ActionType: "bgp", TriggerPhase: phase, Status: status, ConnectorID: cid, ExecutedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
}
func TestDao4_B3d_HistoricalNullFailureSuperseded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _, ev := dao4BGPFixture()
		cid := 7
		dao4PersistBGP(t, s, "on_detected", "failed", nil)
		dao4PersistBGP(t, s, "on_detected", "success", &cid)
		ev.Type = "updated"
		e.HandleEvent(ev)
		synctest.Wait()
		if n := s.connectors.count(); n != 0 {
			t.Fatalf("connector executions=%d; want 0", n)
		}
	})
}
func TestDao4_B3f_NewerNullFailureRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _, ev := dao4BGPFixture()
		cid := 7
		dao4PersistBGP(t, s, "on_detected", "success", &cid)
		dao4PersistBGP(t, s, "on_detected", "failed", nil)
		ev.Type = "updated"
		e.HandleEvent(ev)
		synctest.Wait()
		if n := s.connectors.count(); n != 1 {
			t.Fatalf("connector executions=%d; want 1", n)
		}
	})
}
func dao4BGPFailure(t *testing.T) (*dao4BGPStore, *Engine, tracker.AttackEvent) {
	t.Helper()
	s, e, a, ev := dao4BGPFixture()
	// Drive real workers synchronously: a retry already in flight may fail
	// after a previous worker succeeded (the documented asynchronous window).
	e.executeAction(context.Background(), ev, a, nil)
	s.connectors.setFail(true)
	e.executeAction(context.Background(), ev, a, nil)
	s.connectors.setFail(false)
	return s, e, ev
}
func TestDao4_B3e_ActualConnectorFailureRetries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, ev := dao4BGPFailure(t)
		ev.Type = "updated"
		e.HandleEvent(ev)
		synctest.Wait()
		if n := s.connectors.count(); n != 3 {
			t.Fatalf("connector executions=%d; want success, failure, retry", n)
		}
	})
}
func TestDao4_B3g_ActualFailurePersistsConnector(t *testing.T) {
	s, _, _ := dao4BGPFailure(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.logs) != 2 || s.logs[0].Status != "success" || s.logs[1].Status != "failed" {
		t.Fatalf("real worker logs=%+v", s.logs)
	}
	if cid := s.logs[1].ConnectorID; cid == nil || *cid != 7 {
		t.Fatalf("persisted failed ConnectorID=%v; want 7", cid)
	}
}
