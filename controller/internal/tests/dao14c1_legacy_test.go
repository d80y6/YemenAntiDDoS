package tests

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func dao14c1Legacy(t *testing.T, key string, enabled bool) (*dao14c1Rig, int) {
	t.Helper()
	f := dao14c1New(t, true, enabled)
	f.actions()
	f.ms.bgpAnnouncements.announcements = nil
	f.ms.bgpAnnouncements.attacks = nil
	id, err := f.ms.ScheduledActions().Schedule(context.Background(), &store.ScheduledAction{ActionType: "bgp_withdraw", AttackID: 20, ActionID: 11, ConnectorID: 7, ExternalRuleID: key, ScheduledFor: time.Now().Add(-time.Second)})
	dao14c1Must(t, err)
	return f, id
}
func dao14c1LegacyFailure(t *testing.T, f *dao14c1Rig, id int, key, label string, disabled bool) {
	t.Helper()
	s := f.scheduled(id)
	ls := f.ms.actionExecLog.snapshotLogs()
	dao14c1Check(t, label+".Failed", s.Status == "failed" && len(ls) == 2 && ls[len(ls)-1].Status == "failed", true)
	msg := ""
	if len(ls) > 1 {
		msg = ls[1].ErrorMessage
		dao14c1Check(t, label+".Fields", ls[1].AttackID == 20 && ls[1].ActionID == 11 && ls[1].ActionType == "bgp" && ls[1].TriggerPhase == "on_expired" && ls[1].ConnectorName == "dao4" && ls[1].ConnectorID != nil && *ls[1].ConnectorID == 7 && ls[1].ExternalRuleID == key, true)
	}
	prefix := strings.Split(key, "|")[0]
	if key == "192.0.2.10/32:RTBH" {
		prefix = "192.0.2.10/32"
	}
	for _, part := range []string{"legacy bgp_withdraw without announcement row", prefix + " route-map=RTBH", "connector=dao4 (id=7)", "Force Withdraw", "Un-dismiss"} {
		dao14c1Check(t, label+".Message."+part, strings.Contains(msg, part) && strings.Contains(s.ErrorMessage, part), true)
	}
	dao14c1Check(t, label+".Message.Same", msg, s.ErrorMessage)
	dao14c1Check(t, label+".Message.Disabled", strings.Contains(msg, "connector is disabled"), disabled)
	if disabled {
		for _, part := range []string{"restart the controller", "no network"} {
			dao14c1Check(t, label+".Message."+part, strings.Contains(msg, part), true)
		}
	}
	dao14c1Check(t, label+".Warn", strings.Contains(f.log.text(), "WARN action: legacy bgp_withdraw without announcement row") && strings.Contains(f.log.text(), "scheduled_id=1 attack=20"), true)
}
func TestDao14c1_C1(t *testing.T) {
	for _, kind := range []string{"NoCommand", "NoRowCreated", "FailedMessageWarn"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				key := "192.0.2.10/32|RTBH"
				f, id := dao14c1Legacy(t, key, true)
				dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
				synctest.Wait()
				switch kind {
				case "NoCommand":
					dao14c1Check(t, "C1.NoCommand", f.no(t, "192.0.2.10/32"), 0)
				case "NoRowCreated":
					rows, err := f.ms.BGPAnnouncements().ListActive(context.Background())
					dao14c1Must(t, err)
					dao14c1Check(t, "C1.NoRowCreated", len(rows), 0)
				default:
					dao14c1LegacyFailure(t, f, id, key, "C1", false)
				}
			})
		})
	}
}
func TestDao14c1_C1b(t *testing.T) {
	for _, key := range []string{"192.0.2.10/32:RTBH", "2001:db8::10/128|RTBH"} {
		t.Run(key, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, id := dao14c1Legacy(t, key, true)
				dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
				synctest.Wait()
				dao14c1LegacyFailure(t, f, id, key, "C1b", false)
				dao14c1Check(t, "C1b.NoCommand", dao4Read(t, f.record), "")
			})
		})
	}
}
func TestDao14c1_C1c(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := "192.0.2.10/32|RTBH"
		f, id := dao14c1Legacy(t, key, false)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao14c1LegacyFailure(t, f, id, key, "C1c", true)
		dao14c1Check(t, "C1c.NoCommand", dao4Read(t, f.record), "")
	})
}
func TestDao14c1_C2(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, id := dao14c1Legacy(t, "192.0.2.10/32|RTBH", true)
		f.add(2, 20, 7, "192.0.2.10/32", true)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao14c1Check(t, "C2.Commands", f.no(t, "192.0.2.10/32"), 1)
		dao14c1Check(t, "C2.Schedule", f.scheduled(id).Status, "completed")
		rows, err := f.ms.BGPAnnouncements().ListAttacks(context.Background(), 2)
		dao14c1Must(t, err)
		dao14c1Check(t, "C2.Detached", len(rows) == 1 && rows[0].AttackID == 20 && rows[0].DetachedAt != nil, true)
	})
}
func TestDao14c1_C3(t *testing.T) {
	for _, status := range []string{"orphan", "withdrawn", "dismissed", "dismissed_on_upgrade", "query_error"} {
		t.Run(status, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f, id := dao14c1Legacy(t, "192.0.2.10/32|RTBH", true)
				rowStatus := status
				if status == "query_error" {
					rowStatus = "orphan"
					f.p.hook("found", func(context.Context, int) error { return errors.New("lookup unavailable") })
				}
				f.ms.bgpAnnouncements.announcements = []store.BGPAnnouncement{{ID: 1, Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, Status: rowStatus, Gen: 3}}
				before := *f.row(t, 1)
				dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
				synctest.Wait()
				dao14c1Check(t, "C3.Commands", f.no(t, "192.0.2.10/32"), 0)
				dao14c1Check(t, "C3.Row", *f.row(t, 1), before)
				dao14c1Check(t, "C3.Schedule", f.scheduled(id).Status, "completed")
				ls := f.ms.actionExecLog.snapshotLogs()
				dao14c1Check(t, "C3.OldMessage", len(ls) == 2 && strings.Contains(ls[1].Detail, "refcount=0, kept active"), true)
			})
		})
	}
}
func TestDao14c1_C4(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, id := dao14c1Legacy(t, "", true)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		ls := f.ms.actionExecLog.snapshotLogs()
		dao14c1Check(t, "C4.OldPath", f.no(t, "192.0.2.10/32") == 0 && f.scheduled(id).Status == "completed" && len(ls) == 2 && strings.Contains(ls[1].Detail, "no announcement to detach (idempotent)"), true)
	})
}
func TestDao14c1_C5(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, id := dao14c1Legacy(t, "192.0.2.10/32|RTBH", true)
		f.ms.bgpConnectors.connectors = nil
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		logs := f.ms.actionExecLog.snapshotLogs()
		dao14c1Check(t, "C5.Schedule", f.scheduled(id).Status, "failed")
		dao14c1Check(t, "C5.OldMessage", len(logs) == 2 && strings.Contains(logs[1].ErrorMessage, "bgp connector 7 not found"), true)
	})
}
func TestDao14c1_C10(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := "192.0.2.10/32|RTBH"
		f, id := dao14c1Legacy(t, key, true)
		c, _ := f.ms.BGPConnectors().Get(context.Background(), 7)
		c.ID = 8
		c.Name = "rebound"
		f.ms.bgpConnectors.appendConnectors(*c)
		f.ms.responses.actions[1].BGPConnectorID = intPtr(8)
		f.ms.responses.actions[1].BGPRouteMap = "RTBH2"
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao14c1LegacyFailure(t, f, id, key, "C10", false)
		dao14c1Check(t, "C10.NoCommand", dao4Read(t, f.record), "")
	})
}
func TestDao14c1_C11(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, _ := dao14c1Legacy(t, "192.0.2.10/32|RTBH", true)
		entered, release := dao14c1Gate(f.p, "found")
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		reached := false
		select {
		case <-entered:
			reached = true
		default:
		}
		f.ms.attacks.mu.Lock()
		f.ms.attacks.attacks = append(f.ms.attacks.attacks, store.Attack{ID: 30, DstIP: "192.0.2.10"})
		f.ms.attacks.mu.Unlock()
		f.e.HandleEvent(f.event("confirmed", 30))
		synctest.Wait()
		close(release)
		synctest.Wait()
		text := dao4Read(t, f.record)
		r, err := f.ms.BGPAnnouncements().FindByBusinessKey(context.Background(), "192.0.2.10/32", "RTBH", 7)
		dao14c1Must(t, err)
		t.Logf("DEVICE observation C11.lookupReached=%v commands=%q", reached, text)
		dao14c1Check(t, "C11.Seq", !strings.Contains(text, "no network") && strings.Contains(text, "network 192.0.2.10/32 route-map RTBH"), true)
		dao14c1Check(t, "C11.Row", r != nil && r.Status == "active", true)
	})
}
