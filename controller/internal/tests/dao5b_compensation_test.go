package tests

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func TestDao5b_B6_StaleSchedule(t *testing.T) {
	var outcome, compensation func(*testing.T)
	synctest.Test(t, func(t *testing.T) {
		base, _, ev, _, id := dao5BGPFixture(t, 1)
		base.bgpAnnouncements.announcements[0].Gen = 7
		r := &dao5bObservedRepo{BGPAnnouncementRepo: base.anns}
		schedules := &dao5bSchedules{ScheduledActionRepo: base.ScheduledActions()}
		done := make(chan store.ActionExecutionLog, 4)
		s := dao5bLogStore{dao5bStore{Store: base, anns: r, sched: schedules}, dao5bLogRepo{base.ActionExecLog(), done}}
		metric := dao5bMetrics(t, s)
		before := metric(dao5bStaleMetric, "schedule")
		e := action.NewEngine(s, "auto")
		e.CancelAnnouncementDelay(id, 8, "new generation already observed")
		e.HandleEvent(ev)
		entry := <-done
		synctest.Wait()
		calls := schedules.count()
		writes := len(r.snapshot("failed_withdraw"))
		delta := metric(dao5bStaleMetric, "schedule") - before
		_, plans := base.scheduledActions.dao5Snapshot()
		e.CancelAnnouncementDelay(id, 8, "test cleanup")
		synctest.Wait()
		outcome = func(t *testing.T) {
			if entry.Status != "skipped" || entry.Detail != "superseded by newer announcement generation" {
				t.Errorf("stale schedule log=%+v; want skipped/superseded", entry)
			}
			if calls != 0 || len(plans) != 0 {
				t.Errorf("stale schedule calls=%d plans=%d; want 0/0", calls, len(plans))
			}
			if delta != 1 {
				t.Errorf("schedule stale delta=%v; want 1", delta)
			}
		}
		compensation = func(t *testing.T) {
			if writes != 0 {
				t.Errorf("stale schedule compensation attempts=%d; want 0", writes)
			}
		}
	})
	if outcome != nil {
		t.Run("outcome", outcome)
	}
	if compensation != nil {
		t.Run("compensation_not_attempted", compensation)
	}
}

type dao5bConnectorStore struct {
	dao5bStore
	connectors store.BGPConnectorRepo
}

func (s dao5bConnectorStore) BGPConnectors() store.BGPConnectorRepo { return s.connectors }

type dao5bExpiredConnector struct{ store.BGPConnectorRepo }

func (r dao5bExpiredConnector) Get(c context.Context, id int) (*store.BGPConnector, error) {
	<-c.Done()
	return nil, c.Err()
}

func TestDao5b_B6_ConnectorFailure(t *testing.T) {
	var r *dao5bObservedRepo
	var base *dao5BGPStore
	var id int
	synctest.Test(t, func(t *testing.T) {
		base, _, _, _, id = dao5BGPFixture(t, 0)
		base.bgpAnnouncements.announcements[0].Gen = 7
		_, err := base.anns.Detach(context.Background(), 20, "192.0.2.10/32", "RTBH", 7)
		dao5bCheck(t, err)
		writing := make(chan struct{})
		r = &dao5bObservedRepo{BGPAnnouncementRepo: base.anns, before: func(c context.Context, _ string, _, _, n int) error {
			if n == 1 {
				close(writing)
			}
			if err := c.Err(); err != nil {
				return err
			}
			if n < 3 {
				return dao5Fault
			}
			return nil
		}}
		s := dao5bConnectorStore{dao5bStore{Store: base, anns: r}, dao5bExpiredConnector{base.BGPConnectors()}}
		action.NewEngine(s, "auto").ReconcileOnStartup(context.Background())
		// Keep the main bubble goroutine waiting for the actual write attempt;
		// its clock can then reach the connector's caller deadline.
		<-writing
		synctest.Wait()
	})
	writes := r.snapshot("failed_withdraw")
	if len(writes) != 3 {
		t.Errorf("connector failure attempts=%d; want 3", len(writes))
	}
	for _, w := range writes {
		if w.gen != 7 || w.ctxErr != nil || w.budget <= 0 || w.budget > 5*time.Second {
			t.Errorf("connector failure write=%+v; want gen=7 fresh 5s", w)
		}
	}
	if row := dao5bRow(t, base.anns, id); row.Status != "failed" {
		t.Errorf("connector failure state=%s; want failed", row.Status)
	}
}
