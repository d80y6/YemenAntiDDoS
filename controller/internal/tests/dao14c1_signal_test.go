package tests

import (
	"context"
	"os"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/littlewolf9527/xsight/controller/internal/action"
)

func dao14c1Signal(t *testing.T, script string, unknown, heal bool, label string) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, false, true)
		f.actions()
		f.ms.bgpAnnouncements.announcements = nil
		f.ms.bgpAnnouncements.attacks = nil
		f.ms.actionExecLog.logs = nil
		c, _ := f.ms.BGPConnectors().Get(context.Background(), 7)
		original, err := os.ReadFile(c.VtyshPath)
		dao14c1Must(t, err)
		dao14c1Must(t, os.WriteFile(c.VtyshPath, []byte("#!/bin/sh\n"+script+"\n"), 0700))
		r := &dao13cCompensation{BGPAnnouncementRepo: f.ms.BGPAnnouncements()}
		f.s.anns = r
		f.e = action.NewEngine(f.s, "auto")
		f.e.HandleEvent(f.event("confirmed", 20))
		synctest.Wait()
		writes, id, _ := r.snapshot()
		row, err := f.ms.BGPAnnouncements().Get(context.Background(), id)
		dao14c1Must(t, err)
		if !unknown {
			dao14c1Check(t, label+".Compensates", len(writes) == 1 && row == nil, true)
			return
		}
		dao14c1Check(t, label+".Row", row != nil && row.Status == "announcing" && row.Refcount == 1 && row.Gen == 0, true)
		rows, err := f.ms.BGPAnnouncements().ListAttacks(context.Background(), id)
		dao14c1Must(t, err)
		dao14c1Check(t, label+".Attachment", len(rows) == 1 && rows[0].DetachedAt == nil, true)
		dao14c1Check(t, label+".NoCompensation", len(writes), 0)
		ls := f.ms.actionExecLog.snapshotLogs()
		dao14c1Check(t, label+".ExecLog", len(ls) == 1 && ls[0].Status == "failed" && strings.Contains(ls[0].ErrorMessage, "outcome unknown (killed by signal)"), true)
		dao14c1Check(t, label+".Warn", strings.Contains(f.log.text(), "WARN bgp announce outcome unknown (killed by signal)") && strings.Contains(f.log.text(), "prefix=192.0.2.10/32 route_map=RTBH; leaving announcing for reconcile"), true)
		if heal {
			dao14c1Must(t, os.WriteFile(c.VtyshPath, original, 0700))
			f.e.ReconcileOnStartup(context.Background())
			synctest.Wait()
			row, _ = f.ms.BGPAnnouncements().Get(context.Background(), id)
			dao14c1Check(t, "D5.Reannounced", row != nil && row.Status == "active" && strings.Count(dao4Read(t, f.record), "network 192.0.2.10/32 route-map RTBH") == 1, true)
			f.ending(20)
			f.e.HandleEvent(f.event("expired", 20))
			synctest.Wait()
			row, _ = f.ms.BGPAnnouncements().Get(context.Background(), id)
			dao14c1Check(t, "D5.Withdrawn", row != nil && row.Status == "withdrawn" && f.no(t, "192.0.2.10/32") == 1, true)
		}
	})
}
func TestDao14c1_D1(t *testing.T) { dao14c1Signal(t, "kill -TERM $$", true, false, "D1") }
func TestDao14c1_D2(t *testing.T) { dao14c1Signal(t, "kill -KILL $$", true, false, "D2") }
func TestDao14c1_D3(t *testing.T) { dao14c1Signal(t, "exit 1", false, false, "D3") }
func TestDao14c1_D4(t *testing.T) { dao14c1Signal(t, "exit 143", false, false, "D4") }
func TestDao14c1_D5(t *testing.T) { dao14c1Signal(t, "kill -TERM $$", true, true, "D5") }
