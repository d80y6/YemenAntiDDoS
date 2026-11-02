package tests

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
)

func TestDao5b_B5_SnapshotGeneration(t *testing.T) {
	for _, entry := range []string{"sweepEndedBGP", "startupBGP"} {
		t.Run(entry, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				base, _, ev, _, id := dao5BGPFixture(t, 0)
				base.bgpAnnouncements.announcements[0].Gen = 7
				// The ended sweep must perform the detach itself, without an action child.
				base.responses.actions[0].Enabled = false
				entered, release := make(chan struct{}), make(chan struct{})
				r := &dao5bObservedRepo{BGPAnnouncementRepo: base.anns, reconcileHook: func() { close(entered); <-release }}
				s := dao5bStore{Store: base, anns: r}
				e := action.NewEngine(s, "auto")
				finished := make(chan struct{})
				if entry == "startupBGP" {
					go func() {
						e.CleanupEndedAttachments(context.Background(), action.StartupScheduleSnapshot{}, nil)
						close(finished)
					}()
				} else {
					e.HandleEvent(ev)
				}
				<-entered // The production snapshot has already been taken.
				g := dao5bForce(t, base, id)
				dao5bCheck(t, base.anns.MarkWithdrawn(context.Background(), id, g))
				next := dao5bNewAttack(t, base, 20)
				dao5bCheck(t, base.anns.MarkAnnounced(context.Background(), id, dao5bCurrentGen(t, base.anns, id)))
				reconciledGen := dao5bRow(t, base.anns, id).Gen
				if next.Gen != 9 || reconciledGen == 7 {
					t.Errorf("new lifecycle gen=%d/%d; snapshot was 7", next.Gen, reconciledGen)
				}
				close(release)
				if entry == "startupBGP" {
					<-finished
				}
				synctest.Wait()
				writes := r.snapshot("withdrawn")
				if len(writes) != 1 || writes[0].gen != reconciledGen {
					t.Errorf("terminal writes=%+v; want Reconcile generation %d (snapshot 7)", writes, reconciledGen)
				}
				if a := dao5bRow(t, base.anns, id); a.Status != "withdrawn" {
					t.Errorf("state=%s; want withdrawn", a.Status)
				}
			})
		})
	}
}

func TestDao5b_B7_OperatorGeneration(t *testing.T) {
	for _, entry := range []string{"ForceRemove", "orphanForceWithdraw"} {
		t.Run(entry, func(t *testing.T) {
			base, _, _, conn, id := dao5BGPFixture(t, 0)
			oldGen := dao5bForce(t, base, id)
			path, oldEntered := dao5BlockedVtysh(t)
			conn.VtyshPath = path
			dao5bCheck(t, base.BGPConnectors().Update(context.Background(), conn))
			entered, release := make(chan struct{}), make(chan struct{})
			r := &dao5bObservedRepo{BGPAnnouncementRepo: base.anns, before: func(_ context.Context, op string, _, _, n int) error {
				if op == "withdrawn" && n == 1 {
					close(entered)
					<-release
				}
				return nil
			}}
			s := dao5bStore{Store: base, anns: r}
			metric := dao5bMetrics(t, s)
			stale := metric(dao5bStaleMetric, "withdrawn")
			oldDone := make(chan error, 1)
			go func() { _, err := dao5bWithdraw(context.Background(), s, conn, id, oldGen); oldDone <- err }()
			dao5bReceive(t, oldEntered)
			if entry == "orphanForceWithdraw" {
				dao5bCheck(t, base.anns.MarkWithdrawn(context.Background(), id, oldGen))
				_, err := base.anns.UpsertOrphan(context.Background(), "192.0.2.10/32", "RTBH", 7, "orphan")
				dao5bCheck(t, err)
			}
			beforeForce := dao5bRow(t, base.anns, id).Gen
			operatorDone := make(chan error, 1)
			e := action.NewEngine(s, "auto")
			if entry == "ForceRemove" {
				go func() { operatorDone <- e.ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH") }()
			} else {
				router := setupRouterWithEngine(s, e)
				go func() {
					w := doPost(t, router, "/api/active-actions/bgp/orphan-force-withdraw", map[string]int{"announcement_id": id})
					if w.Code != 200 {
						operatorDone <- fmt.Errorf("orphan API: %d %s", w.Code, w.Body.String())
					} else {
						operatorDone <- nil
					}
				}()
			}
			dao5bReceive(t, entered)
			forced := dao5bRow(t, base.anns, id)
			if forced.Status != "withdrawing" || forced.Gen != beforeForce+1 {
				t.Errorf("ForceWithdraw row=%+v; want withdrawing gen=%d", forced, beforeForce+1)
			}
			dao5bCheck(t, os.WriteFile(filepath.Join(filepath.Dir(path), "block"), []byte("release\n"), 0600))
			dao5bCheck(t, dao5bReceive(t, oldDone))
			if a := dao5bRow(t, base.anns, id); a.Status != "withdrawing" || a.Gen != forced.Gen {
				t.Errorf("old write changed operator generation: %+v", a)
			}
			if delta := metric(dao5bStaleMetric, "withdrawn") - stale; delta != 1 {
				t.Errorf("old write stale delta=%v; want 1", delta)
			}
			close(release)
			dao5bCheck(t, dao5bReceive(t, operatorDone))
			if a := dao5bRow(t, base.anns, id); a.Status != "withdrawn" || a.Gen != forced.Gen {
				t.Errorf("operator terminal row=%+v; want withdrawn gen=%d", a, forced.Gen)
			}
		})
	}
}
