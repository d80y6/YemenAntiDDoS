package action

import (
	"context"
	"log"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// RunXDropReconcile has the same lifetime as main's BGP reconcilers. Fixed
// ticks and independent workers prevent a slow connector delaying the round.
func (e *Engine) RunXDropReconcile(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = xdropReconcileInterval
	}
	e.xdropMu.Lock()
	e.xdropInterval, e.xdropContext = interval, ctx
	e.xdropMu.Unlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		e.reconcileXDropRound(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (e *Engine) reconcileXDropRound(ctx context.Context) {
	roundStart := time.Now()
	listError := func(err error) {
		metrics.XDropReconcile.WithLabelValues("list_error").Inc()
		log.Printf("WARN action: xdrop reconcile degraded/list_error: %v", err)
	}
	c, cancel := context.WithTimeout(ctx, dbOperationTimeout)
	active, err := e.store.XDropActiveRules().ListActive(c)
	cancel()
	if err != nil {
		listError(err)
		return
	}
	c, cancel = context.WithTimeout(ctx, dbOperationTimeout)
	withdrawing, err := e.store.XDropActiveRules().ListWithdrawing(c)
	cancel()
	if err != nil {
		listError(err)
		return
	}
	schedules, err := e.xdropSchedules(ctx)
	if err != nil {
		listError(err)
		return
	}
	candidates := make(map[xdropRuleKey]store.ScheduledAction)
	for _, r := range append(active, withdrawing...) {
		sa := xdropScheduleForRule(r)
		candidates[xdropKeyFromSchedule(sa)] = sa
	}
	for _, sa := range schedules {
		if sa.ActionType == "xdrop_unblock" {
			candidates[xdropKeyFromSchedule(sa)] = sa
		}
	}
	ids := make([]int, 0, len(candidates))
	for k := range candidates {
		ids = append(ids, k.attack)
	}
	c, cancel = context.WithTimeout(ctx, dbOperationTimeout)
	live, err := e.store.Attacks().LiveIDs(c, ids)
	cancel()
	if err != nil {
		listError(err)
		return
	}
	// The two status queries are not one snapshot: a withdrawing -> failed
	// transition may be absent from both. Never discard unexpired backoff.
	e.xdropMu.Lock()
	present, connectors := map[string]bool{}, map[int]bool{}
	for k := range candidates {
		present[k.String()] = true
		connectors[k.connector] = true
	}
	now := time.Now()
	for key, retry := range e.xdropRetries {
		if !present[key] && e.xdropLocks[key] == nil && !now.Before(retry.nextAttempt) {
			delete(e.xdropRetries, key)
		}
	}
	// A retained retry also retains its connector observation: otherwise a
	// missed key could erase false and hide the next false -> true transition.
	for _, retry := range e.xdropRetries {
		connectors[retry.connector] = true
	}
	for id := range e.xdropEnabled {
		if !connectors[id] {
			delete(e.xdropEnabled, id)
		}
	}
	e.xdropMu.Unlock()
	for k, sa := range candidates {
		if ctx.Err() != nil {
			return
		}
		metrics.XDropReconcile.WithLabelValues("candidate").Inc()
		if live[k.attack] || e.endingInFlight(k.attack) {
			metrics.XDropReconcile.WithLabelValues("skipped_live").Inc()
			continue
		}
		// Reserving the lock before dispatch also reserves the one in-flight
		// worker for this key. A busy row never holds up other candidates.
		unlock, ok := e.lockXDrop(ctx, k, true)
		if !ok {
			metrics.XDropReconcile.WithLabelValues("busy").Inc()
			continue
		}
		if ctx.Err() != nil {
			unlock()
			return
		}
		go func() {
			defer unlock()
			e.withdrawXDropLocked(ctx, sa, "reconcile", store.TriggerPhaseOnExpired, roundStart)
		}()
	}
}
