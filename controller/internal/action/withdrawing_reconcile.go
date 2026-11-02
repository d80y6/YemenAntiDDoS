package action

import (
	"context"
	"log"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type withdrawingObservation struct {
	gen       int
	firstSeen time.Time
}

// RunWithdrawingReconcile retries withdrawals that persist across observations.
// Each round waits a full interval after the previous round finishes.
func (e *Engine) RunWithdrawingReconcile(ctx context.Context, interval time.Duration) {
	observed := make(map[int]withdrawingObservation)
	failedObserved := make(map[int]withdrawingObservation)
	for {
		if ctx.Err() != nil {
			return
		}
		rows, err := e.store.BGPAnnouncements().ListByStatus(ctx, "withdrawing")
		if err != nil {
			metrics.BGPWithdrawingReconcile.WithLabelValues("list_error").Inc()
			log.Printf("action: withdrawing reconcile list: %v", err)
		} else {
			now := time.Now()
			next := make(map[int]withdrawingObservation, len(rows))
			for _, ann := range rows {
				seen, exists := observed[ann.ID]
				same := exists && seen.gen == ann.Gen
				if !same {
					seen = withdrawingObservation{gen: ann.Gen, firstSeen: now}
				}
				next[ann.ID] = seen
				if same && now.Sub(seen.firstSeen) >= interval {
					if e.reconcileWithdrawing(ctx, ann) {
						delete(next, ann.ID)
					}
				}
			}
			observed = next
		}
		failedRows, err := e.store.BGPAnnouncements().ListByStatus(ctx, "failed")
		if err != nil {
			metrics.BGPWithdrawingReconcile.WithLabelValues("failed_list_error").Inc()
			log.Printf("action: failed withdraw reconcile list: %v", err)
		} else {
			now := time.Now()
			next := make(map[int]withdrawingObservation, len(failedRows))
			for _, ann := range failedRows {
				if ann.Refcount != 0 {
					continue
				}
				seen, exists := failedObserved[ann.ID]
				same := exists && seen.gen == ann.Gen
				if !same {
					seen = withdrawingObservation{gen: ann.Gen, firstSeen: now}
				}
				next[ann.ID] = seen
				if same && now.Sub(seen.firstSeen) >= interval {
					if e.reconcileFailedWithdraw(ctx, ann) {
						delete(next, ann.ID)
					}
				}
			}
			failedObserved = next
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Failed observations are separate from withdrawing observations: a state
// change starts a fresh observation even if its generation is unchanged.
func (e *Engine) reconcileFailedWithdraw(ctx context.Context, ann store.BGPAnnouncement) bool {
	unlock, locked := e.tryLockAnnouncement(ann.ID)
	if !locked {
		metrics.BGPWithdrawingReconcile.WithLabelValues("failed_busy").Inc()
		return false
	}
	defer unlock()
	newGen, ok, err := e.store.BGPAnnouncements().ClaimFailedWithdraw(ctx, ann.ID, ann.Gen)
	if err != nil {
		metrics.BGPWithdrawingReconcile.WithLabelValues("failed_claim_error").Inc()
		log.Printf("action: failed withdraw reconcile claim announcement_id=%d gen=%d: %v", ann.ID, ann.Gen, err)
		return false
	}
	if !ok {
		metrics.BGPWithdrawingReconcile.WithLabelValues("failed_claim_lost").Inc()
		return false
	}
	e.NoteAnnouncementTakeover(ann.ID)
	metrics.BGPWithdrawingReconcile.WithLabelValues("failed_claimed").Inc()
	log.Printf("action: failed withdraw reconcile claimed announcement_id=%d gen=%d->%d prefix=%s", ann.ID, ann.Gen, newGen, ann.Prefix)
	e.CancelAnnouncementDelay(ann.ID, newGen, "failed withdraw reconcile")
	e.retryBGPWithdraw(ann, newGen)
	return true
}

// One function scope per row ensures early returns and panics release its lock.
func (e *Engine) reconcileWithdrawing(ctx context.Context, ann store.BGPAnnouncement) bool {
	unlock, locked := e.tryLockAnnouncement(ann.ID)
	if !locked {
		metrics.BGPWithdrawingReconcile.WithLabelValues("busy").Inc()
		return false
	}
	defer unlock()
	newGen, ok, err := e.store.BGPAnnouncements().ClaimWithdrawing(ctx, ann.ID, ann.Gen)
	if err != nil {
		metrics.BGPWithdrawingReconcile.WithLabelValues("claim_error").Inc()
		log.Printf("action: withdrawing reconcile claim announcement_id=%d gen=%d: %v", ann.ID, ann.Gen, err)
		return false
	}
	if !ok {
		metrics.BGPWithdrawingReconcile.WithLabelValues("claim_lost").Inc()
		return false
	}
	e.NoteAnnouncementTakeover(ann.ID)
	metrics.BGPWithdrawingReconcile.WithLabelValues("claimed").Inc()
	log.Printf("action: withdrawing reconcile claimed announcement_id=%d gen=%d->%d prefix=%s", ann.ID, ann.Gen, newGen, ann.Prefix)
	e.CancelAnnouncementDelay(ann.ID, newGen, "withdrawing reconcile")
	e.retryBGPWithdraw(ann, newGen)
	return true
}
