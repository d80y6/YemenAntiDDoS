package action

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

var sweepTimeout = 30 * time.Second

func (e *Engine) endAction(id, delta int) {
	e.endMu.Lock()
	defer e.endMu.Unlock()
	e.endInflight[id] += delta
	if e.endInflight[id] == 0 {
		delete(e.endInflight, id)
		e.endCond.Broadcast()
	}
}

func (e *Engine) endingInFlight(id int) bool {
	e.endMu.Lock()
	defer e.endMu.Unlock()
	return e.endInflight[id] > 0
}

func endedOutcome(kind string, attack, id int, outcome string, err error) {
	metrics.EndedSweep.WithLabelValues(kind, outcome).Inc()
	level := "INFO"
	if err != nil {
		level = "WARN"
	}
	log.Printf("%s action: ended sweep kind=%s attack=%d id=%d outcome=%s error=%v", level, kind, attack, id, outcome, err)
}

func (e *Engine) sweepEndedAttack(id int) {
	// Only this goroutine waits; the dispatcher merely accounts for children.
	e.endMu.Lock()
	for e.endInflight[id] > 0 {
		e.endCond.Wait()
	}
	e.endMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), sweepTimeout)
	defer cancel()
	e.sweepEndedBGP(ctx, id)
	e.sweepEndedXDrop(ctx, id)
}

func (e *Engine) sweepEndedBGP(ctx context.Context, id int) {
	rows, err := e.store.BGPAnnouncements().ListAttachmentsForAttack(ctx, id)
	if err != nil {
		endedOutcome("bgp", id, 0, "failed", err)
		return
	}
	seen := map[int]bool{}
	for _, row := range rows {
		if row.DetachedAt != nil || seen[row.AnnouncementID] {
			continue
		}
		seen[row.AnnouncementID] = true
		ann, err := e.store.BGPAnnouncements().Get(ctx, row.AnnouncementID)
		if err != nil || ann == nil {
			endedOutcome("bgp", id, row.AnnouncementID, "failed", fmt.Errorf("get announcement: %v", err))
			continue
		}
		conn, err := e.store.BGPConnectors().Get(ctx, ann.ConnectorID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			endedOutcome("bgp", id, ann.ID, "failed", err)
			continue
		}
		if err != nil || conn == nil || !conn.Enabled {
			endedOutcome("bgp", id, ann.ID, "skipped_connector", nil)
			continue
		}
		r, err := e.store.BGPAnnouncements().ReconcileAttachments(ctx, ann.ID, []int{id}, true)
		outcome := "detached_kept"
		if err != nil {
			outcome = "failed"
		} else if r.Skipped != "" {
			outcome = "skipped_status"
		} else if r.NeedWithdraw {
			go e.retryBGPWithdraw(*ann, r.Gen)
			outcome = "dispatched"
		}
		endedOutcome("bgp", id, ann.ID, outcome, err)
	}
}

func (e *Engine) sweepEndedXDrop(ctx context.Context, id int) {
	rows, err := e.store.XDropActiveRules().ListByAttack(ctx, id)
	if err != nil {
		endedOutcome("xdrop", id, 0, "failed", err)
		return
	}
	active := rows[:0]
	for _, r := range rows {
		if r.Status == "active" && !isSyntheticFailedXDropRuleID(r.ExternalRuleID) {
			active = append(active, r)
		}
	}
	if len(active) == 0 {
		return
	}
	for _, r := range active {
		e.withdrawXDropRule(ctx, xdropScheduleForRule(r), "ended-sweep", store.TriggerPhaseOnExpired)
	}
}
