package tests

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao13cStore struct {
	store.Store
	anns store.BGPAnnouncementRepo
}

func (s dao13cStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }

type dao13cRepo struct {
	store.BGPAnnouncementRepo
	claims      atomic.Int64
	beforeClaim func(int, int) error
	beforeForce func()
}

func (r *dao13cRepo) ClaimFailedWithdraw(c context.Context, id, gen int) (int, bool, error) {
	r.claims.Add(1)
	if r.beforeClaim != nil {
		if err := r.beforeClaim(id, gen); err != nil {
			return 0, false, err
		}
	}
	return r.BGPAnnouncementRepo.ClaimFailedWithdraw(c, id, gen)
}

func (r *dao13cRepo) ForceWithdraw(c context.Context, id int) ([]store.BGPAnnouncementAttack, int, error) {
	if r.beforeForce != nil {
		r.beforeForce()
	}
	return r.BGPAnnouncementRepo.ForceWithdraw(c, id)
}

func dao13cNew(t *testing.T) (*dao11jFixture, *dao13cRepo) {
	t.Helper()
	f := dao11jNew(t)
	r := &dao13cRepo{BGPAnnouncementRepo: f.r}
	f.e = action.NewEngine(dao13cStore{dao11jStore{f.base, f.r, f.c, f.sched}, r}, "auto")
	return f, r
}

func dao13cWantFailed(t *testing.T, f *dao11jFixture, name string) {
	t.Helper()
	row := f.row(t)
	attachments, err := f.base.anns.ListAttacks(context.Background(), f.id)
	dao5bCheck(t, err)
	live := 0
	for _, a := range attachments {
		if a.DetachedAt == nil {
			live++
		}
	}
	dao11jWant(t, name+".Status", row.Status, "failed")
	dao11jWant(t, name+".Refcount", row.Refcount, 0)
	dao11jWant(t, name+".LiveAttachments", live, 0)
}

// The initial failure follows two real Detach calls, never a refcount-only seed.
func dao13cFailDetached(t *testing.T, f *dao11jFixture) {
	t.Helper()
	c := context.Background()
	_, err := f.base.anns.Attach(c, store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21, ActionID: intPtr(10)})
	dao5bCheck(t, err)
	first, err := f.base.anns.Detach(c, 21, "192.0.2.10/32", "RTBH", 7)
	dao5bCheck(t, err)
	dao11jWant(t, "Fixture.SharedFirstDetach", first.NeedWithdraw, false)
	last, err := f.base.anns.Detach(c, 20, "192.0.2.10/32", "RTBH", 7)
	dao5bCheck(t, err)
	dao11jWant(t, "Fixture.LastDetach", last.NeedWithdraw, true)
	dao5bCheck(t, os.WriteFile(f.failPath, nil, 0600))
	conn, err := f.base.BGPConnectors().Get(c, 7)
	dao5bCheck(t, err)
	_, err = action.PerformBGPWithdrawForOrphan(c, f.base, conn, store.ResponseAction{}, "192.0.2.10/32", "RTBH", f.id, last.Gen)
	dao11jWant(t, "Fixture.WithdrawFailed", err != nil, true)
}

func TestDao13c_F1(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, r := dao13cNew(t)
		dao13cFailDetached(t, f)
		dao13cWantFailed(t, f, "F1.Precondition")
		gen, commands := f.row(t).Gen, f.commands(t)
		before := f.metric("failed_claimed")
		dao5bCheck(t, os.Remove(f.failPath))
		cancel, done := f.start(time.Minute)
		defer func() { cancel(); <-done }()
		dao11jWant(t, "F1.FirstObservation.ZeroCommands", f.commands(t)-commands, 0)
		dao11jWant(t, "F1.FirstObservation.ZeroClaims", r.claims.Load(), int64(0))
		dao11jAdvance(time.Minute)
		dao11jWant(t, "F1.OneWithdraw", f.commands(t)-commands, 1)
		dao11jWant(t, "F1.Generation", f.row(t).Gen, gen+1)
		dao11jWant(t, "F1.FailedClaimedDelta", f.metric("failed_claimed")-before, float64(1))
		dao11jWant(t, "F1.Withdrawn", f.row(t).Status, "withdrawn")
	})
}

func TestDao13c_F2(t *testing.T) {
	t.Run("FailedClaimCancelsPendingDelay", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			dao13cFailDetached(t, f)
			dao13cWantFailed(t, f, "F2.PendingDelay.Precondition")
			gen := f.row(t).Gen
			id, waiting, err := f.e.ScheduleDelayForAnnouncement(context.Background(), f.id, gen, time.Now().Add(10*time.Minute))
			dao5bCheck(t, err)
			dao11jWant(t, "F2.PendingDelay.InitialContextLive", waiting.Err() == nil, true)
			dao11jWant(t, "F2.PendingDelay.InitialPending", f.scheduled(id), "pending")
			dao5bCheck(t, os.Remove(f.failPath))
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jWant(t, "F2.PendingDelay.FirstObservation", r.claims.Load(), int64(0))
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.PendingDelay.Claimed", r.claims.Load(), int64(1))
			dao11jWant(t, "F2.PendingDelay.ContextCancelled", errors.Is(waiting.Err(), context.Canceled), true)
			dao11jWant(t, "F2.PendingDelay.PendingCancelled", f.scheduled(id), "cancelled")
			_, _, err = f.e.ScheduleDelayForAnnouncement(context.Background(), f.id, gen, time.Now().Add(time.Hour))
			dao11jWant(t, "F2.PendingDelay.OldGenerationRejected", errors.Is(err, store.ErrStaleAnnouncement), true)
			// Also clean up the deliberately broken no-cancel mutation.
			f.e.CancelAnnouncementDelay(f.id, gen+1, "test cleanup")
		})
	})
	t.Run("SharedAnnounceFailure.NoClaim", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			_, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21})
			dao5bCheck(t, err)
			dao5bCheck(t, f.base.anns.MarkFailedAnnounce(context.Background(), f.id, 0, "shared announce failed"))
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(4 * time.Minute)
			dao11jWant(t, "F2.Shared.NoClaims", r.claims.Load(), int64(0))
			dao11jWant(t, "F2.Shared.NoCommands", f.commands(t), 0)
			dao11jWant(t, "F2.Shared.Failed", f.row(t).Status, "failed")
		})
	})
	t.Run("ResidualLiveAttachment.NoClaim", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			f.set("failed", 0)
			f.base.bgpAnnouncements.announcements[0].Refcount = 0
			before := f.metric("failed_claim_lost")
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.Residual.ClaimAttempt", r.claims.Load(), int64(1))
			dao11jWant(t, "F2.Residual.NoCommands", f.commands(t), 0)
			dao11jWant(t, "F2.Residual.NoClaim", f.row(t).Status, "failed")
			dao11jWant(t, "F2.Residual.Lost", f.metric("failed_claim_lost")-before, float64(1))
		})
	})
	t.Run("ObservationAndGeneration", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			dao13cFailDetached(t, f)
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(30 * time.Second)
			dao11jWant(t, "F2.BeforeInterval.NoClaim", r.claims.Load(), int64(0))
			f.set("failed", 7)
			dao11jAdvance(30 * time.Second)
			dao11jWant(t, "F2.NewGeneration.FirstSeen", r.claims.Load(), int64(0))
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.NewGeneration.Claims", r.claims.Load(), int64(1))
			dao11jWant(t, "F2.NewGeneration.Advances", f.row(t).Gen, 8)
		})
	})
	t.Run("AttachBeforeClaim.Lost", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			dao13cFailDetached(t, f)
			commands, before := f.commands(t), f.metric("failed_claim_lost")
			r.beforeClaim = func(_, _ int) error {
				res, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 22})
				dao5bCheck(t, err)
				dao11jWant(t, "F2.Attach.Revives", res.NeedAnnounce && res.Gen == 1, true)
				return nil
			}
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.Attach.Lost", f.metric("failed_claim_lost")-before, float64(1))
			dao11jWant(t, "F2.Attach.NoCommands", f.commands(t)-commands, 0)
		})
	})
	t.Run("ForceRemoveHoldsLock.Busy", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			dao13cFailDetached(t, f)
			entered, release, forceDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			r.beforeForce = func() { close(entered); <-release }
			go func() { forceDone <- f.e.ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH") }()
			<-entered
			dao13cWantFailed(t, f, "F2.Busy.Precondition")
			before, commands := f.metric("failed_busy"), f.commands(t)
			cancel, done := f.start(time.Minute)
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.Busy.Metric", f.metric("failed_busy")-before, float64(1))
			dao11jWant(t, "F2.Busy.NoClaims", r.claims.Load(), int64(0))
			dao11jWant(t, "F2.Busy.NoCommands", f.commands(t)-commands, 0)
			cancel()
			<-done
			close(release)
			<-forceDone
		})
	})
	t.Run("ClaimError", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			dao13cFailDetached(t, f)
			before, commands := f.metric("failed_claim_error"), f.commands(t)
			r.beforeClaim = func(int, int) error { return errors.New("claim unavailable") }
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.ClaimError.Metric", f.metric("failed_claim_error")-before, float64(1))
			dao11jWant(t, "F2.ClaimError.NoCommands", f.commands(t)-commands, 0)
		})
	})
	t.Run("FailedListError.PreservesObservation", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			dao13cFailDetached(t, f)
			dao5bCheck(t, os.Remove(f.failPath))
			c := context.Background()
			_, err := f.base.anns.Attach(c, store.BGPAttachParams{Prefix: "192.0.2.11/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 23})
			dao5bCheck(t, err)
			_, err = f.base.anns.Detach(c, 23, "192.0.2.11/32", "RTBH", 7)
			dao5bCheck(t, err)
			n := 0
			f.r.afterList = func(status string, rows []store.BGPAnnouncement) ([]store.BGPAnnouncement, error) {
				if status == "failed" {
					n++
					if n == 2 {
						return nil, errors.New("failed list unavailable")
					}
				}
				return rows, nil
			}
			before := f.metric("failed_list_error")
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.ListError.Metric", f.metric("failed_list_error")-before, float64(1))
			dao11jWant(t, "F2.ListError.WithdrawingContinues", f.r.claims.Load(), int64(1))
			dao11jWant(t, "F2.ListError.FailedNotClaimed", r.claims.Load(), int64(0))
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.ListError.ObservationRetained", r.claims.Load(), int64(1))
			dao11jWant(t, "F2.ListError.Withdrawn", f.row(t).Status, "withdrawn")
		})
	})
	t.Run("StatusChangedSameGen.FirstSeenAgain", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			dao13cFailDetached(t, f)
			f.set("withdrawing", 0)
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao5bCheck(t, f.base.anns.MarkFailedWithdraw(context.Background(), f.id, 0, "same generation changed"))
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.StatusChangedSameGen.FirstSeenAgain", r.claims.Load(), int64(0))
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.StatusChangedSameGen.NextObservation", r.claims.Load(), int64(1))
		})
	})
	t.Run("ExecutingSnapshotSuperseded.NoSecondWithdraw", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, r := dao13cNew(t)
			dao13cFailDetached(t, f)
			commands := f.commands(t)
			entered, release := make(chan struct{}), make(chan struct{})
			r.beforeClaim = func(int, int) error { close(entered); <-release; return nil }
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.Executing.AtClaimBarrier", dao11jClosed(entered), true)
			schedule := f.schedule(t, "executing", 0)
			f.e.ReconcileOnStartup(context.Background())
			synctest.Wait()
			dao11jWant(t, "F2.Executing.BlockedBeforeGet", f.r.gets.Load(), int64(0))
			close(release)
			synctest.Wait()
			dao11jWant(t, "F2.ExecutingSnapshotSuperseded.NoSecondWithdraw", f.commands(t)-commands, 1)
			dao11jWant(t, "F2.ExecutingSnapshotSuperseded.Completed", f.scheduled(schedule), "completed")
			dao11jWant(t, "F2.ExecutingSnapshotSuperseded.NoGet", f.r.gets.Load(), int64(0))
			dao13cWantFailed(t, f, "F2.Executing.NewGenerationFailed")
			dao11jWant(t, "F2.Executing.NewGeneration", f.row(t).Gen, 1)
		})
	})
	t.Run("ClaimBlocksAttach.StaleOldWrite.FinalAnnounce", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, _ := dao13cNew(t)
			dao13cFailDetached(t, f)
			dao5bCheck(t, os.Remove(f.failPath))
			entered, release := make(chan struct{}), make(chan struct{})
			f.c.before = func(n int64) error {
				if n == 1 {
					close(entered)
					<-release
				}
				return nil
			}
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(time.Minute)
			dao11jWant(t, "F2.Combined.AtWithdrawBarrier", dao11jClosed(entered), true)
			_, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21})
			dao11jWant(t, "F2.Combined.AttachRejected", err != nil, true)
			err = f.base.anns.MarkFailedWithdraw(context.Background(), f.id, 0, "old generation")
			dao11jWant(t, "F2.Combined.OldWriteStale", errors.Is(err, store.ErrStaleAnnouncement), true)
			close(release)
			synctest.Wait()
			f.revive(t)
			lines := strings.Split(strings.TrimSpace(dao4Read(t, f.record)), "\n")
			dao11jWant(t, "F2.Combined.FinalAnnounce", lines[len(lines)-1], "network 192.0.2.10/32 route-map RTBH")
			dao11jWant(t, "F2.Combined.Active", f.row(t).Status, "active")
		})
	})
}

func TestDao13c_F3(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, _ := dao13cNew(t)
		dao13cFailDetached(t, f)
		conn, err := f.base.BGPConnectors().Get(context.Background(), 7)
		dao5bCheck(t, err)
		script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '" + f.record + "'\nprintf \"Can't find static route\\n\"\nexit 1\n"
		dao5bCheck(t, os.WriteFile(conn.VtyshPath, []byte(script), 0700))
		cancel, done := f.start(time.Minute)
		defer func() { cancel(); <-done }()
		dao11jAdvance(time.Minute)
		dao11jWant(t, "F3.RouteAbsent.Withdrawn", f.row(t).Status, "withdrawn")
	})
}

func TestDao13c_F4(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f, r := dao13cNew(t)
		dao13cFailDetached(t, f)
		dao13cWantFailed(t, f, "F4.Precondition")
		commands := f.commands(t)
		cancel, done := f.start(time.Minute)
		defer func() { cancel(); <-done }()
		for round := 1; round <= 6; round++ {
			dao11jAdvance(time.Minute)
			want := (round + 1) / 2
			dao11jWant(t, "F4.NoStorm.Commands", f.commands(t)-commands, want)
			dao11jWant(t, "F4.NoStorm.Claims", r.claims.Load(), int64(want))
			dao11jWant(t, "F4.Generation", f.row(t).Gen, want)
			dao13cWantFailed(t, f, "F4.RetryFailed")
		}
	})
}

func TestDao13c_R0Fixed(t *testing.T) {
	t.Run("A_FailedWithdrawRecovers", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f, _ := dao13cNew(t)
			dao13cFailDetached(t, f)
			dao13cWantFailed(t, f, "R0.Fixed.A.Precondition")
			dao5bCheck(t, os.Remove(f.failPath))
			cancel, done := f.start(time.Minute)
			defer func() { cancel(); <-done }()
			dao11jAdvance(3 * time.Minute)
			dao11jWant(t, "R0.Fixed.A.OneRetry", f.commands(t), 2)
			dao11jWant(t, "R0.Fixed.A.Withdrawn", f.row(t).Status, "withdrawn")
		})
	})
	t.Run("B_NoExpiredCompensation", func(t *testing.T) { dao13cUnknown(t, false) })
	t.Run("C_BackgroundPipeReturns", func(t *testing.T) {
		path := dao13cProcess(t, "sleep 60 &\nexit 0")
		_, e, ev, done := dao13cShellFixture(t, path, 30000, "on_detected")
		var entry store.ActionExecutionLog
		_, timely := dao13cAwait(t, path, 5*time.Second, func() { e.HandleEvent(ev); entry = <-done })
		dao11jWant(t, "R0.Fixed.C.ReturnedWithin5Seconds", timely, true)
		dao11jWant(t, "R0.Fixed.C.Success", entry.Status, "success")
	})
	t.Run("D_DeleteConnectorBlocked", func(t *testing.T) {
		ms := NewMockStore()
		ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "dao13c", BGPASN: 65000}}
		ms.bgpAnnouncements.announcements = []store.BGPAnnouncement{{ID: 1, ConnectorID: 7, Prefix: "192.0.2.241/32", Status: "active"}}
		w := dao13cDeleteRequest(t, ms)
		dao11jWant(t, "R0.Fixed.D.Conflict", w.Code, 409)
	})
}
