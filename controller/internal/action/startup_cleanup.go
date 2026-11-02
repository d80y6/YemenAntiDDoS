package action

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

var cleanupStepTimeout, cleanupItemTimeout = 60 * time.Second, 10 * time.Second
var cleanupWithdrawWait = 30 * time.Second

// StartupScheduleSnapshot retains ownership assigned before recovery workers start.
type StartupScheduleSnapshot struct {
	rules         map[string]bool
	announcements map[int]bool
}

func startupRuleKey(attack, action, connector int, rule string) string {
	return fmt.Sprintf("%d/%d/%d/%s", attack, action, connector, rule)
}

func (e *Engine) startupSnapshot(ctx context.Context) (StartupScheduleSnapshot, error) {
	s := StartupScheduleSnapshot{rules: map[string]bool{}, announcements: map[int]bool{}}
	pending, err := e.store.ScheduledActions().ListPending(ctx)
	if err != nil {
		return s, err
	}
	executing, err := e.store.ScheduledActions().ListExecuting(ctx)
	if err != nil {
		return s, err
	}
	for _, a := range append(pending, executing...) {
		if a.ActionType == "xdrop_unblock" {
			s.rules[startupRuleKey(a.AttackID, a.ActionID, a.ConnectorID, a.ExternalRuleID)] = true
		}
		if a.ActionType == "bgp_withdraw" && a.AnnouncementID != nil {
			s.announcements[*a.AnnouncementID] = true
		}
	}
	return s, nil
}

func startupOutcome(kind, outcome string, id int, detached []int, err error) {
	if outcome != "" {
		metrics.StartupCleanup.WithLabelValues(kind, outcome).Inc()
	}
	log.Printf("INFO action: startup cleanup kind=%s id=%d outcome=%s detached=%v error=%v", kind, id, outcome, detached, err)
}

func (e *Engine) PrepareStartupCleanup(ctx context.Context) (StartupScheduleSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, cleanupStepTimeout)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			log.Printf("WARN action: startup cleanup preparation incomplete: %v", ctx.Err())
		}
	}()
	pre, err := e.startupSnapshot(ctx)
	if err == nil {
		e.startupBGP(ctx, pre, false)
	}
	return pre, err
}

func (e *Engine) CleanupEndedAttachments(ctx context.Context, pre StartupScheduleSnapshot, preErr error) {
	ctx, cancel := context.WithTimeout(ctx, cleanupStepTimeout)
	defer cancel()
	defer func() { log.Printf("INFO action: startup cleanup complete error=%v", ctx.Err()) }()
	now := StartupScheduleSnapshot{}
	err := preErr
	if err == nil {
		now, err = e.startupSnapshot(ctx)
	}
	if err != nil {
		metrics.StartupCleanup.WithLabelValues("bgp", "failed").Inc()
		metrics.StartupCleanup.WithLabelValues("xdrop", "failed").Inc()
		log.Printf("WARN action: startup cleanup skipped: %v", err)
		return
	}
	for key := range pre.rules {
		now.rules[key] = true
	}
	for id := range pre.announcements {
		now.announcements[id] = true
	}
	e.startupBGP(ctx, now, true)
	if ctx.Err() != nil {
		return
	}
	rows, err := e.store.XDropActiveRules().ListActive(ctx)
	if err != nil {
		startupOutcome("xdrop", "failed", 0, nil, err)
		return
	}
	var ids []int
	for _, r := range rows {
		if r.Status == "active" {
			ids = append(ids, r.AttackID)
		}
	}
	item, cancelBatch := context.WithTimeout(ctx, cleanupItemTimeout)
	live, err := e.store.Attacks().LiveIDs(item, ids)
	cancelBatch()
	if err != nil {
		startupOutcome("xdrop", "failed", 0, nil, err)
		return
	}
	for _, r := range rows {
		if ctx.Err() != nil {
			break
		}
		if r.Status != "active" {
			continue
		}
		outcome := ""
		key := startupRuleKey(r.AttackID, r.ActionID, r.ConnectorID, r.ExternalRuleID)
		if now.rules[key] {
			outcome = "skipped_scheduled"
		} else if !live[r.AttackID] {
			e.withdrawXDropRule(ctx, xdropScheduleForRule(r), "startup-cleanup", store.TriggerPhaseOnExpired)
			continue
		}
		startupOutcome("xdrop", outcome, r.ID, nil, nil)
	}
}

func (e *Engine) startupBGP(ctx context.Context, snapshot StartupScheduleSnapshot, detach bool) {
	var workers sync.WaitGroup
	var pending atomic.Int32
	rows, err := e.store.BGPAnnouncements().ListActive(ctx)
	if err != nil {
		startupOutcome("bgp", "failed", 0, nil, err)
		return
	}
	for _, ann := range rows {
		if ctx.Err() != nil {
			break
		}
		if ann.Status != "active" && (detach || ann.Status != "announcing") {
			continue
		}
		item, cancel := context.WithTimeout(ctx, cleanupItemTimeout)
		r, outcome, err := e.startupAnnouncement(item, ann, snapshot, detach)
		cancel()
		if err != nil {
			outcome = "failed"
		}
		if r.NeedWithdraw && err == nil {
			pending.Add(1)
			workers.Go(func() { defer pending.Add(-1); e.retryBGPWithdraw(ann, r.Gen) })
		}
		startupOutcome("bgp", outcome, ann.ID, r.Detached, err)
	}
	if detach {
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		waitCtx, cancel := context.WithTimeout(ctx, cleanupWithdrawWait)
		defer cancel()
		select {
		case <-done:
		case <-waitCtx.Done():
			log.Printf("WARN action: startup cleanup BGP withdrawal wait expired unfinished=%d", pending.Load())
		}
	}
}

func (e *Engine) startupAnnouncement(ctx context.Context, ann store.BGPAnnouncement, snapshot StartupScheduleSnapshot, detach bool) (store.BGPReconcileResult, string, error) {
	var result store.BGPReconcileResult
	var ended []int
	if detach {
		if snapshot.announcements[ann.ID] {
			return result, "skipped_scheduled", nil
		}
		conn, err := e.store.BGPConnectors().Get(ctx, ann.ConnectorID)
		if err != nil || conn == nil || !conn.Enabled {
			return result, "skipped_connector", nil
		}
		ended, err = e.endedAttachments(ctx, ann.ID)
		if err != nil {
			return result, "", err
		}
	}
	result, err := e.store.BGPAnnouncements().ReconcileAttachments(ctx, ann.ID, ended, detach)
	if err != nil {
		return result, "", err
	}
	outcome := ""
	switch {
	case result.NeedWithdraw:
		outcome = "dispatched"
	case len(result.Detached) > 0:
		outcome = "detached_kept"
	case result.RefcountAfter > result.RefcountBefore:
		outcome = "recounted_up"
	case result.Skipped != "" && result.Skipped != "consistent":
		outcome = "skipped_inconsistent"
	}
	return result, outcome, err
}

func (e *Engine) endedAttachments(ctx context.Context, annID int) ([]int, error) {
	rows, err := e.store.BGPAnnouncements().ListAttacks(ctx, annID)
	if err != nil {
		return nil, err
	}
	var ids []int
	for _, r := range rows {
		if r.DetachedAt == nil {
			ids = append(ids, r.AttackID)
		}
	}
	live, err := e.store.Attacks().LiveIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	var ended []int
	for _, id := range ids {
		if !live[id] && !e.endingInFlight(id) {
			ended = append(ended, id)
		}
	}
	return ended, nil
}

// SweepEnabledBGPConnector catches up ended attachments after an enabled update.
func (e *Engine) SweepEnabledBGPConnector(connID int) {
	e.sweepEnabledBGP(connID, 0)
}

// A recovery worker hands back only its announcement; API updates sweep all.
func (e *Engine) sweepEnabledBGP(connID, only int) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupStepTimeout)
	defer cancel()
	conn, err := e.store.BGPConnectors().Get(ctx, connID)
	if err != nil || conn == nil || !conn.Enabled {
		log.Printf("INFO action: enabled connector sweep kind=bgp connector=%d skipped: connector unavailable: %v", connID, err)
		return
	}
	snap, err := e.startupSnapshot(ctx)
	if err != nil {
		enabledSweepOutcome(connID, 0, "", nil, err)
		return
	}
	rows, err := e.store.BGPAnnouncements().ListActive(ctx)
	if err != nil {
		enabledSweepOutcome(connID, 0, "", nil, err)
		return
	}
	for _, ann := range rows {
		if ann.Status == "active" && ann.ConnectorID == connID && (only == 0 || ann.ID == only) {
			e.sweepEnabledAnnouncement(connID, ann, snap)
		}
	}
}

func (e *Engine) sweepEnabledAnnouncement(connID int, ann store.BGPAnnouncement, snap StartupScheduleSnapshot) {
	unlock := e.LockAnnouncement(ann.ID)
	defer unlock()
	item, cancel := context.WithTimeout(context.Background(), cleanupItemTimeout)
	defer cancel()
	r, outcome, err := e.startupAnnouncement(item, ann, snap, true)
	enabledSweepOutcome(connID, ann.ID, outcome, r.Detached, err)
	if r.NeedWithdraw && err == nil {
		e.retryBGPWithdraw(ann, r.Gen)
	}
}

func enabledSweepOutcome(connID, annID int, outcome string, detached []int, err error) {
	if err != nil {
		outcome = "failed"
	}
	label := outcome
	switch outcome {
	case "recounted_up":
		label = "detached_kept"
	case "skipped_inconsistent", "skipped_scheduled":
		label = "skipped_status"
	}
	if label != "" {
		metrics.EndedSweep.WithLabelValues("bgp", label).Inc()
	}
	log.Printf("INFO action: enabled connector sweep kind=bgp connector=%d id=%d outcome=%s detached=%v error=%v", connID, annID, outcome, detached, err)
}
