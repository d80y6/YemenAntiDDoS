package tests

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	dto "github.com/prometheus/client_model/go"
)

func dao13dAwait(t *testing.T, limit time.Duration, ready func() bool) {
	t.Helper()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-timer.C:
			t.Fatal("required observation did not arrive before deadline")
		case <-tick.C:
		}
	}
}
func dao13dVtyshFailed() float64 {
	var m dto.Metric
	_ = metrics.VtyshOps.WithLabelValues("announce", "failed").Write(&m)
	return m.GetCounter().GetValue()
}
func dao13dRetryAssert(t *testing.T, s store.Store, id int, before *store.BGPAnnouncement, attachments []store.BGPAnnouncementAttack, logs string, calls int, failureDelta float64, reason string) {
	t.Helper()
	row, err := s.BGPAnnouncements().Get(context.Background(), id)
	dao5bCheck(t, err)
	after, err := s.BGPAnnouncements().ListAttacks(context.Background(), id)
	dao5bCheck(t, err)
	dao11jWant(t, "Retry.ZeroCompensation", calls, 0)
	dao11jWant(t, "Retry.OwnershipUnchanged", row != nil && row.Status == "announcing" && reflect.DeepEqual(row, before) && reflect.DeepEqual(attachments, after), true)
	dao11jWant(t, "Retry.NoStateWriteFailure", failureDelta, float64(0))
	want := fmt.Sprintf("announcement_id=%d prefix=%q route_map=%q gen=%d:", id, before.Prefix, before.RouteMap, before.Gen)
	n := 0
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "WARN action: retry announce") {
			n++
			dao11jWant(t, "Retry.QuotedWarning", strings.Contains(line, want) && strings.Contains(line, reason), true)
		}
	}
	dao11jWant(t, "Retry.OneWarning", n, 1)
	if strings.Contains(reason, "unsafe vtysh token") {
		stripped := regexp.MustCompile("\"(?:\\\\.|[^\"\\\\])*\"").ReplaceAllString(logs, "")
		for _, token := range []string{before.Prefix, before.RouteMap} {
			if strings.ContainsAny(token, " \n") {
				dao11jWant(t, "Retry.NoUnquotedToken", !strings.Contains(stripped, token), true)
				dao11jWant(t, "Retry.QuotedToken", strings.Contains(logs, strconv.Quote(token)), true)
			}
		}
	}
}
func TestDao13d_F1(t *testing.T) {
	s := NewMockStore()
	c := context.Background()
	r := s.BGPAnnouncements()
	p := store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 1}
	a, err := r.Attach(c, p)
	dao5bCheck(t, err)
	dao11jWant(t, "F1.NewGen", a.Gen, 0)
	dao5bCheck(t, r.MarkFailedAnnounce(c, a.AnnouncementID, a.Gen, "definite failure"))
	row, err := r.Get(c, a.AnnouncementID)
	dao5bCheck(t, err)
	dao11jWant(t, "F1.NewDeleted", row == nil, true)
	a, err = r.Attach(c, p)
	dao5bCheck(t, err)
	dao5bCheck(t, r.MarkAnnounced(c, a.AnnouncementID, a.Gen))
	_, gen, err := r.ForceWithdraw(c, a.AnnouncementID)
	dao5bCheck(t, err)
	dao5bCheck(t, r.MarkWithdrawn(c, a.AnnouncementID, gen))
	p.AttackID = 2
	a, err = r.Attach(c, p)
	dao5bCheck(t, err)
	dao11jWant(t, "F1.Recycled", a.Gen > 0, true)
	attacks, err := r.ListAttacks(c, a.AnnouncementID)
	dao5bCheck(t, err)
	events, err := r.ListEvents(c, a.AnnouncementID)
	dao5bCheck(t, err)
	dao5bCheck(t, r.MarkFailedAnnounce(c, a.AnnouncementID, a.Gen, "recycled failure"))
	row, err = r.Get(c, a.AnnouncementID)
	dao5bCheck(t, err)
	later, err := r.ListEvents(c, a.AnnouncementID)
	dao5bCheck(t, err)
	attached, err := r.ListAttacks(c, a.AnnouncementID)
	dao5bCheck(t, err)
	dao11jWant(t, "F1.RecycledRetained", row != nil && row.Status == "failed" && row.Gen == a.Gen && reflect.DeepEqual(attacks, attached), true)
	dao11jWant(t, "F1.FailureEvent", len(later) == len(events)+1, true)
	found := false
	for _, e := range later {
		if e.EventType == store.BGPEventAnnounceFailed {
			found = true
		}
	}
	dao11jWant(t, "F1.FailureEventType", found, true)
	p.AttackID = 3
	b, err := r.Attach(c, p)
	dao5bCheck(t, err)
	dao11jWant(t, "F1.NextAnnounces", b.NeedAnnounce && b.Gen == a.Gen+1, true)
}
func TestDao13d_SR(t *testing.T) {
	for _, branch := range []string{"SR1", "SR2", "SR3", "SR4"} {
		t.Run(branch, func(t *testing.T) {
			for _, recycled := range []bool{false, true} {
				t.Run(fmt.Sprintf("Recycled=%t", recycled), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						f := dao11jNew(t)
						f.set("announcing", 0)
						c := context.Background()
						if recycled {
							dao5bCheck(t, f.base.anns.MarkAnnounced(c, f.id, 0))
							_, gen, err := f.base.anns.ForceWithdraw(c, f.id)
							dao5bCheck(t, err)
							dao5bCheck(t, f.base.anns.MarkWithdrawn(c, f.id, gen))
							_, err = f.base.anns.Attach(c, store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21})
							dao5bCheck(t, err)
						}
						reason := ""
						switch branch {
						case "SR1":
							f.base.bgpAnnouncements.announcements[0].ConnectorID = 999
							reason = "not found"
						case "SR2":
							f.base.bgpAnnouncements.announcements[0].Prefix = "BAD\nINJECT"
							reason = "unsafe vtysh token"
						case "SR3":
							dao5bCheck(t, os.WriteFile(f.failPath, nil, 0600))
							reason = "exit status 1"
						}
						before, err := f.base.anns.Get(c, f.id)
						dao5bCheck(t, err)
						attachments, err := f.base.anns.ListAttacks(c, f.id)
						dao5bCheck(t, err)
						r := &dao13cCompensation{BGPAnnouncementRepo: f.base.anns, id: f.id, gen: before.Gen}
						s := dao13cStore{dao11jStore{f.base, f.r, f.c, f.sched}, r}
						metric := dao5bMetrics(t, s)
						failureBefore := metric(dao5bFailureMetric, "bgp_ann_state")
						vtyshBefore := dao13dVtyshFailed()
						logs := dao5CaptureLog(t)
						action.NewEngine(s, "auto").ReconcileOnStartup(c)
						synctest.Wait()
						writes, _, _ := r.snapshot()
						if branch == "SR4" {
							row, err := f.base.anns.Get(c, f.id)
							dao5bCheck(t, err)
							dao11jWant(t, "SR4.Active", row != nil && row.Status == "active" && row.ID == before.ID && row.Gen == before.Gen, true)
						} else {
							dao13dRetryAssert(t, f.base, f.id, before, attachments, logs.text(), len(writes), metric(dao5bFailureMetric, "bgp_ann_state")-failureBefore, reason)
							if branch == "SR3" {
								dao11jWant(t, "SR3.VtyshFailed", dao13dVtyshFailed()-vtyshBefore, float64(1))
							}
						}
					})
				})
			}
		})
	}
}
