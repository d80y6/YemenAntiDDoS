package tests

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// This fixture deliberately creates a new announcement through HandleEvent.
// It must also compile against the implementation baseline.
func dao12hR0(t *testing.T) (*MockStore, *action.Engine, int) {
	t.Helper()
	ms, _, ev := dao4Fixture("bgp", "once", "on_detected")
	path, _ := dao4Vtysh(t)
	ms.responses.actions[0].BGPConnectorID = intPtr(7)
	ms.responses.actions[0].BGPRouteMap = "RTBH"
	ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Enabled: true, VtyshPath: path, BGPASN: 64512}}
	r := &dao5bObservedRepo{BGPAnnouncementRepo: ms.BGPAnnouncements()}
	r.before = func(_ context.Context, op string, _, _, n int) error {
		if op == "announced" && n == 1 {
			return dao5Fault
		}
		return nil
	}
	done := make(chan store.ActionExecutionLog, 10)
	s := dao5bLogStore{dao5bStore{Store: ms, anns: r}, dao5bLogRepo{ms.ActionExecLog(), done}}
	e := action.NewEngine(s, "auto")
	e.HandleEvent(ev)
	<-done
	synctest.Wait()
	a, err := ms.BGPAnnouncements().FindByBusinessKey(context.Background(), "192.0.2.10/32", "RTBH", 7)
	dao5bCheck(t, err)
	if a == nil {
		t.Fatal("R0.NewAnnouncement: missing row")
	}
	dao11jWant(t, "R0.WriteBeforeFailure", len(r.snapshot("announced")), 1)
	dao11jWant(t, "R0.StillAnnouncing", a.Status, "announcing")
	return ms, e, a.ID
}

func TestDao12h_R0(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms, e, id := dao12hR0(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go e.RunWithdrawingReconcile(ctx, time.Minute)
		synctest.Wait()
		for range 3 {
			dao11jAdvance(time.Minute)
		}
		a, err := ms.BGPAnnouncements().Get(context.Background(), id)
		dao5bCheck(t, err)
		dao11jWant(t, "R0.BugPersists", a.Status, "announcing")
	})
}
