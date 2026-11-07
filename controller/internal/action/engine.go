// Package action implements the Action Engine that executes responses
// when attacks are detected.
package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

// v1.2 PR-1: Structured skip_reason values written to action_execution_log when
// an action is skipped instead of executed. Callers (mitigation-summary API,
// Mitigations UI, operator debugging) read these to explain why a given attack
// did not trigger a particular action.
const (
	SkipReasonPreconditionNotMatched = "precondition_not_matched"
	SkipReasonFirstMatchSuppressed   = "first_match_suppressed"
	SkipReasonModeObserve            = "mode_observe"
	SkipReasonManualOverride         = "manual_override"
	SkipReasonAlreadyExecuted        = "already_executed"
	// SkipReasonDecoderNotSupported: attack's decoder_family is an L3
	// aggregate (e.g. `ip`, `ip_other`) that has no clean mapping to xDrop's
	// L4 filter semantics. xDrop is gated at dispatch for these decoders to
	// avoid silent broadening (protocol=all + absent src_port ⇒ full-prefix
	// blackhole). Operators should mitigate L3 aggregates via BGP instead.
	SkipReasonDecoderNotSupported = "decoder_not_xdrop_compatible"
	// Historical value: no longer produced since v3; old log rows still carry it and the UI must still display it.
	SkipReasonXDropAnomalyRequiresDrop = "xdrop_anomaly_requires_drop"
	SkipReasonGlobalNoTarget           = "global_no_target"
	SkipReasonDeprecatedXDropAPI       = "deprecated_xdrop_api"
	SkipReasonUnknownActionType        = "unknown_action_type"
	SkipReasonNoConnector              = "no_connector"
	SkipReasonConnectorDisabled        = "connector_disabled"
	SkipReasonUnknownTriggerPhase      = "unknown_trigger_phase"
	SkipReasonStaleGeneration          = "stale_generation"
	SkipReasonIncompleteConfig         = "incomplete_config"
	SkipReasonConnectorLookupFailed    = "connector_lookup_failed"
	SkipReasonNoRulesToUnblock         = "no_rules_to_unblock"
	SkipReasonVendorExportOnly         = "vendor_export_only"
	// Non-ended outbound attacks must not block their internal source host.
	SkipReasonOutboundBlockForbidden = "outbound_block_forbidden"
)

// writeSkipLog records a skip event in action_execution_log with structured
// skip_reason + optional error_message detail (e.g. "domain eq internal_ip
// failed"). Non-fatal: errors are logged but do not block the caller.
func writeSkipLog(ctx context.Context, s store.Store, attackID int, act store.ResponseAction, respName, connName string, skipReason, detail string) {
	logEntry := &store.ActionExecutionLog{
		AttackID:      attackID,
		ActionID:      act.ID,
		ResponseName:  respName,
		ActionType:    act.ActionType,
		ConnectorName: connName,
		TriggerPhase:  act.TriggerPhase,
		Status:        "skipped",
		SkipReason:    skipReason,
		ErrorMessage:  detail,
		ExecutedAt:    time.Now(),
	}
	if _, err := s.ActionExecLog().Create(ctx, logEntry); err != nil {
		log.Printf("action: write skip log attack=%d action=%d reason=%s: %v", attackID, act.ID, skipReason, err)
	}
	// metrics.RecordAction counter increment happens transparently via the
	// metrics.InstrumentStore wrapper installed at startup (see main.go).
	// Do NOT add inline RecordAction here or we'd double-count.
	// xsight_action_skip_total is a separate counter broken out by
	// skip_reason — the wrapper covers the generic status=skipped bucket.
	metrics.RecordSkip(skipReason)
}

// recordSkip adds only reason and accounting to a handwritten skipped log.
// Callers preserve all other fields and the write path. Like writeSkipLog,
// it counts each skipped log once regardless of whether Create succeeds.
func recordSkip(l *store.ActionExecutionLog, reason string) *store.ActionExecutionLog {
	l.SkipReason = reason
	metrics.RecordSkip(reason)
	return l
}

// execLogContext gives each log write its own budget: the action may have
// exhausted its context on the side effect being recorded. Use only for
// execution logs, never for scheduled-action finalization.
func execLogContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), dbOperationTimeout)
}

func writeExecLog(s store.Store, l *store.ActionExecutionLog) (int, error) {
	ctx, cancel := execLogContext()
	defer cancel()
	return s.ActionExecLog().Create(ctx, l)
}

type onceKey struct {
	attackID, actionID int
	phase              string
}

// Engine evaluates and executes response actions when attacks change state.
type Engine struct {
	store store.Store
	mode  string // "observe" | "auto"

	// v1.1: Cancel channels for delayed unblock/withdraw goroutines.
	// Key: "attack:{attackID}:action:{actionID}" → cancel function.
	// When an attack re-breaches, all pending delays for that attack are cancelled.
	delayMu      sync.Mutex
	pendingDelay map[string]context.CancelFunc
	annGen       map[int]int // maximum generation observed; protected by delayMu
	queue        chan dispatchItem
	startOnce    sync.Once
	testStop     chan struct{} // only closed by the test-only stop method
	dispatchDone chan struct{}
	endMu        sync.Mutex
	endCond      *sync.Cond
	endInflight  map[int]int
	onceMu       sync.Mutex
	onceInflight map[onceKey]int

	xdropMu       sync.Mutex
	xdropLocks    map[string]*xdropRuleLock
	xdropRetries  map[string]xdropRetry
	xdropEnabled  map[int]bool
	xdropInterval time.Duration
	xdropContext  context.Context

	announcementMu    sync.Mutex
	announcementLocks map[int]*announcementLock

	// dropped counts events discarded by EnqueueNonBlocking when the queue is
	// full (detection must never block on a stalled dispatcher).
	dropped atomic.Uint64
}

type announcementLock struct {
	held      chan struct{}
	takeovers int // protected by announcementMu
}

// Mode returns the action mode fixed at construction time.
func (e *Engine) Mode() string { return e.mode }

func (e *Engine) announcementLockFor(id int) *announcementLock {
	e.announcementMu.Lock()
	defer e.announcementMu.Unlock()
	if e.announcementLocks == nil {
		e.announcementLocks = make(map[int]*announcementLock)
	}
	if e.announcementLocks[id] == nil {
		e.announcementLocks[id] = &announcementLock{held: make(chan struct{}, 1)}
	}
	return e.announcementLocks[id]
}

// LockAnnouncement serializes announcement takeover and recovery side effects.
func (e *Engine) LockAnnouncement(id int) (unlock func()) {
	l := e.announcementLockFor(id)
	l.held <- struct{}{}
	return func() { <-l.held }
}

func (e *Engine) tryLockAnnouncement(id int) (func(), bool) {
	l := e.announcementLockFor(id)
	select {
	case l.held <- struct{}{}:
		return func() { <-l.held }, true
	default:
		return nil, false
	}
}

// NoteAnnouncementTakeover records a real takeover. The caller must hold the announcement lock.
func (e *Engine) NoteAnnouncementTakeover(id int) {
	l := e.announcementLockFor(id)
	e.announcementMu.Lock()
	l.takeovers++
	e.announcementMu.Unlock()
}

// AnnouncementTakeovers returns the number of real takeovers in this process.
func (e *Engine) AnnouncementTakeovers(id int) int {
	l := e.announcementLockFor(id)
	e.announcementMu.Lock()
	defer e.announcementMu.Unlock()
	return l.takeovers
}

func NewEngine(s store.Store, mode string) *Engine {
	e := &Engine{store: s, mode: mode, pendingDelay: make(map[string]context.CancelFunc), annGen: make(map[int]int), endInflight: make(map[int]int),
		onceInflight: make(map[onceKey]int),
		queue:        make(chan dispatchItem, actionQueueCapacity), testStop: make(chan struct{}), dispatchDone: make(chan struct{})}
	e.endCond = sync.NewCond(&e.endMu)
	return e
}

func (e *Engine) onceInFlight(k onceKey) bool {
	e.onceMu.Lock()
	defer e.onceMu.Unlock()
	return e.onceInflight[k] > 0
}

func (e *Engine) onceAction(k onceKey, delta int) {
	e.onceMu.Lock()
	defer e.onceMu.Unlock()
	e.onceInflight[k] += delta
	if e.onceInflight[k] == 0 {
		delete(e.onceInflight, k)
	}
}

// Buffer bursts without dropping lifecycle events, especially expired events.
const actionQueueCapacity = 4096

type dispatchItem struct {
	event    tracker.AttackEvent
	rebreach bool
	attackID int
	done     chan struct{}
}

// Enqueue accepts events for the entire process lifetime, including after Drain.
// Callers hand over an immutable event snapshot. No dispatcher call may wait on
// the tracker: a full queue can block a producer while it holds the tracker lock.
func (e *Engine) Enqueue(event tracker.AttackEvent) {
	e.enqueue(dispatchItem{event: event})
}

func (e *Engine) EnqueueRebreach(attackDBID int) {
	e.enqueue(dispatchItem{rebreach: true, attackID: attackDBID})
}

// EnqueueNonBlocking is the detection-path entry point: the caller may hold the
// tracker lock, so it must never block. A full queue drops the event and bumps
// the drop counter; the periodic inline snapshot refresh re-derives mitigation
// state from the tracker, so a dropped lifecycle event cannot leave stale rules
// installed indefinitely.
func (e *Engine) EnqueueNonBlocking(event tracker.AttackEvent) {
	select {
	case e.queue <- dispatchItem{event: event}:
	default:
		n := e.dropped.Add(1)
		metrics.ActionQueueEvents.WithLabelValues("dropped").Inc()
		if n == 1 || n%1000 == 0 {
			log.Printf("action: queue full; dropped %d event(s) (dispatcher stalled)", n)
		}
	}
}

// DroppedEvents reports how many events EnqueueNonBlocking discarded.
func (e *Engine) DroppedEvents() uint64 { return e.dropped.Load() }

func (e *Engine) enqueue(item dispatchItem) {
	select {
	case e.queue <- item:
	default:
		metrics.ActionQueueEvents.WithLabelValues("full").Inc()
		log.Printf("action: queue full; waiting for dispatcher capacity")
		e.queue <- item
	}
}

// Start is independent of detection cancellation. Production never stops intake.
func (e *Engine) Start() {
	e.startOnce.Do(func() {
		go func() {
			defer close(e.dispatchDone)
			for {
				select {
				case <-e.testStop:
					return
				default:
				}
				select {
				case <-e.testStop:
					return
				case item := <-e.queue:
					if item.done != nil {
						close(item.done)
					} else if item.rebreach {
						e.CancelDelaysForAttack(item.attackID)
					} else {
						e.HandleEvent(item.event)
					}
				}
			}
		}()
	})
}

// Drain waits for a FIFO marker, not asynchronous actions or later producers.
// One timer bounds both queue insertion and marker processing; callers share no
// deadline or lock. A timeout never changes event acceptance.
func (e *Engine) Drain(limit time.Duration) {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	if !e.drain(timer.C) {
		metrics.ActionQueueEvents.WithLabelValues("drain_timeout").Inc()
		log.Printf("action: queue drain timed out after %s", limit)
	}
}

func (e *Engine) drain(deadline <-chan time.Time) bool {
	done := make(chan struct{})
	select {
	case e.queue <- dispatchItem{done: done}:
	case <-deadline:
		return false
	}
	select {
	case <-done:
		return true
	case <-deadline:
		return false
	}
}

func (e *Engine) sendGlobalWebhooks(event tracker.AttackEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	e.fireGlobalWebhooks(ctx, event)
}

// delayKey returns the map key for a pending delayed action (full business key).
func delayKey(attackID, actionID, connectorID int, externalRuleID string) string {
	return fmt.Sprintf("attack:%d:action:%d:conn:%d:rule:%s", attackID, actionID, connectorID, externalRuleID)
}

// announcementDelayKey returns the in-memory map key for a BGP delayed
// withdraw scheduled at the announcement level (v1.2 PR-5). Distinct from
// the per-artifact delayKey used by xDrop.
func announcementDelayKey(announcementID int) string {
	return fmt.Sprintf("announcement:%d", announcementID)
}

// ScheduleDelayForAnnouncement persists a bgp_withdraw schedule keyed on
// announcement_id (v1.2 PR-5). Mirrors ScheduleDelay but uses the PR-5 BGP
// identity (per-announcement) rather than the per-artifact four-tuple.
//
// Returns the row's DB ID, a cancelable context, and any error. The mocks /
// tests can inspect scheduled_actions.announcement_id to verify persistence.
func (e *Engine) ScheduleDelayForAnnouncement(ctx context.Context, announcementID int, gen int, scheduledFor time.Time) (int, context.Context, error) {
	e.delayMu.Lock()
	stale := e.annGen[announcementID] > gen
	e.delayMu.Unlock()
	if stale {
		return 0, nil, store.ErrStaleAnnouncement
	}
	id, err := e.store.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     "bgp_withdraw",
		AnnouncementID: &announcementID,
		// attack_id/action_id/connector_id/external_rule_id left zero/empty —
		// BGP schedules in PR-5 are announcement-scoped, not per-artifact.
		ScheduledFor: scheduledFor,
	})
	if err != nil {
		return 0, nil, err
	}
	e.delayMu.Lock()
	defer e.delayMu.Unlock()
	if e.annGen[announcementID] > gen {
		return 0, nil, store.ErrStaleAnnouncement
	}
	key := announcementDelayKey(announcementID)
	if oldCancel, ok := e.pendingDelay[key]; ok {
		oldCancel() // cancel stale goroutine before overwriting
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	e.pendingDelay[key] = cancel
	e.annGen[announcementID] = gen
	return id, cancelCtx, nil
}

// CompleteDelayForAnnouncement finalizes a successfully-withdrawn BGP delay
// and drops the in-memory cancel entry.
func (e *Engine) CompleteDelayForAnnouncement(ctx context.Context, scheduledID, announcementID int) {
	if scheduledID > 0 {
		if err := e.store.ScheduledActions().Complete(ctx, scheduledID); err != nil {
			log.Printf("action: complete scheduled_action %d: %v", scheduledID, err)
		}
	}
	e.delayMu.Lock()
	defer e.delayMu.Unlock()
	delete(e.pendingDelay, announcementDelayKey(announcementID))
}

// FailDelayForAnnouncement marks a BGP delay row as failed.
func (e *Engine) FailDelayForAnnouncement(ctx context.Context, scheduledID, announcementID int, errMsg string) {
	if scheduledID > 0 {
		if err := e.store.ScheduledActions().Fail(ctx, scheduledID, errMsg); err != nil {
			log.Printf("action: fail scheduled_action %d: %v", scheduledID, err)
		}
	}
	e.delayMu.Lock()
	defer e.delayMu.Unlock()
	delete(e.pendingDelay, announcementDelayKey(announcementID))
}

// CancelAnnouncementDelay is called by Attach when a new attack resurrects
// a delayed announcement (re-breach analog). Cancels the in-memory timer
// and marks the scheduled_actions row as cancelled.
func (e *Engine) CancelAnnouncementDelay(announcementID int, gen int, reason string) {
	e.delayMu.Lock()
	e.annGen[announcementID] = max(e.annGen[announcementID], gen)
	key := announcementDelayKey(announcementID)
	if cancel, ok := e.pendingDelay[key]; ok {
		cancel()
		delete(e.pendingDelay, key)
	}
	e.delayMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancel()
	// Find and cancel by announcement_id.
	pending, err := e.store.ScheduledActions().ListPending(ctx)
	if err != nil {
		log.Printf("action: CancelAnnouncementDelay list pending: %v", err)
		return
	}
	for _, sa := range pending {
		if sa.ActionType == "bgp_withdraw" && sa.AnnouncementID != nil && *sa.AnnouncementID == announcementID {
			if err := e.store.ScheduledActions().Cancel(ctx, sa.ID, reason); err != nil {
				log.Printf("action: cancel scheduled_action %d: %v", sa.ID, err)
			}
		}
	}
}

// ScheduleDelay registers a cancelable delayed action and persists it to
// scheduled_actions so the timer survives controller restart (v1.2 PR-3).
//
// Returns the row's DB ID, a context.Context cancelled on force-remove /
// re-breach, and any DB error. The caller should use the returned context in
// its `time.After` goroutine and call CompleteDelay(id) / Fail(id) on exit.
//
// Callers pass actionType ('xdrop_unblock' or 'bgp_withdraw'). Both types
// currently use the per-artifact four-tuple as the business key; v1.2 PR-5
// will migrate BGP to per-announcement identity via announcement_id.
func (e *Engine) ScheduleDelay(ctx context.Context, actionType string, attackID, actionID, connectorID int, externalRuleID string, scheduledFor time.Time) (int, context.Context, error) {
	id, err := e.store.ScheduledActions().Schedule(ctx, &store.ScheduledAction{
		ActionType:     actionType,
		AttackID:       attackID,
		ActionID:       actionID,
		ConnectorID:    connectorID,
		ExternalRuleID: externalRuleID,
		ScheduledFor:   scheduledFor,
	})
	if err != nil {
		return 0, nil, err
	}
	e.delayMu.Lock()
	defer e.delayMu.Unlock()
	cancelCtx, cancel := context.WithCancel(context.Background())
	e.pendingDelay[delayKey(attackID, actionID, connectorID, externalRuleID)] = cancel
	return id, cancelCtx, nil
}

// CompleteDelay marks the scheduled_actions row as completed and drops the
// in-memory cancel entry. Called after the action executes successfully.
func (e *Engine) CompleteDelay(ctx context.Context, id, attackID, actionID, connectorID int, externalRuleID string) {
	if id > 0 {
		if err := e.store.ScheduledActions().Complete(ctx, id); err != nil {
			log.Printf("action: complete scheduled_action %d: %v", id, err)
		}
	}
	e.delayMu.Lock()
	defer e.delayMu.Unlock()
	delete(e.pendingDelay, delayKey(attackID, actionID, connectorID, externalRuleID))
}

// FailDelay marks the scheduled_actions row as failed with an error message.
// Called when the delayed action executes but the underlying side effect
// (vtysh / xDrop API) failed. The in-memory entry is also removed.
func (e *Engine) FailDelay(ctx context.Context, id, attackID, actionID, connectorID int, externalRuleID, errMsg string) {
	if id > 0 {
		if err := e.store.ScheduledActions().Fail(ctx, id, errMsg); err != nil {
			log.Printf("action: fail scheduled_action %d: %v", id, err)
		}
	}
	e.delayMu.Lock()
	defer e.delayMu.Unlock()
	delete(e.pendingDelay, delayKey(attackID, actionID, connectorID, externalRuleID))
}

// MarkExecutingDelay guards against a recovery goroutine racing the normal
// dispatch goroutine — only the first MarkExecuting call succeeds. Returns
// true if this caller should proceed; false if another goroutine already took
// the task.
func (e *Engine) MarkExecutingDelay(ctx context.Context, id int) bool {
	if id <= 0 {
		return true // no DB id (legacy / no persistence); assume caller owns it
	}
	var err error
attempts:
	for attempt := 0; attempt < 3; attempt++ {
		writeCtx, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
		err = e.store.ScheduledActions().MarkExecuting(writeCtx, id)
		cancel()
		if err == nil {
			return true
		}
		if errors.Is(err, store.ErrNotPending) {
			return false
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				break attempts
			case <-time.After(time.Second):
			}
		}
	}
	metrics.StateWriteFailures.WithLabelValues("sched_mark_executing").Inc()
	log.Printf("ERROR action: MarkExecuting %d failed: %v; caller ctx: %v", id, err, ctx.Err())
	return false
}

// CancelDelay cancels a specific pending delayed action (per-artifact) in
// both the in-memory map and the scheduled_actions DB row.
func (e *Engine) CancelDelay(attackID, actionID, connectorID int, externalRuleID string) {
	e.delayMu.Lock()
	key := delayKey(attackID, actionID, connectorID, externalRuleID)
	if cancel, ok := e.pendingDelay[key]; ok {
		cancel()
		delete(e.pendingDelay, key)
		log.Printf("action: cancelled delayed action %s (force remove)", key)
	}
	e.delayMu.Unlock()

	// DB cancel outside the map lock — non-blocking for other goroutines.
	ctx, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancel()
	// actionType is not part of the key, but cancel-by-key across both types
	// is safe because the partial unique index on pending state guarantees at
	// most one row per four-tuple regardless of type.
	for _, t := range []string{"xdrop_unblock", "bgp_withdraw"} {
		if err := e.store.ScheduledActions().CancelByBusinessKey(ctx, t, attackID, actionID, connectorID, externalRuleID, "force_remove"); err != nil {
			log.Printf("action: CancelByBusinessKey type=%s: %v", t, err)
		}
	}
}

// ReconcileOnStartup runs all PR-3/PR-4/PR-5 crash recovery paths once at
// controller startup, BEFORE serving traffic. Order matters:
//  1. `executing` scheduled_actions (PR-3 leftover) — the process may have
//     died between MarkExecuting and Complete. Retry the side effect;
//     idempotency handles the "already done" case.
//  2. `withdrawing` xdrop_active_rules (PR-4) — DELETE in flight, state
//     update not persisted. Retry (only HTTP 204 confirms release).
//  3. `announcing` bgp_announcements (PR-5) — vtysh announce not confirmed;
//     retry it (idempotent — FRR just re-accepts the command).
//  4. `withdrawing` bgp_announcements (PR-5) — vtysh no network not confirmed;
//     retry ("Can't find" = idempotent success).
//  5. `pending` scheduled_actions — re-arm timers for surviving tasks
//     (xdrop_unblock per-artifact + bgp_withdraw per-announcement).
func (e *Engine) ReconcileOnStartup(ctx context.Context) {
	owned := e.reconcileExecutingSchedules(ctx)
	e.reconcileXDropWithdrawing(ctx)
	e.reconcileBGPAnnouncing(ctx)
	e.reconcileBGPWithdrawing(ctx, owned)
	if err := e.RecoverScheduledActions(ctx); err != nil {
		log.Printf("action: RecoverScheduledActions: %v", err)
	}
}

// reconcileBGPAnnouncing retries announce for rows stuck in 'announcing'
// (process crashed between Attach and MarkAnnounced). vtysh network is
// idempotent — FRR simply re-accepts the command for a route that's
// already present.
// Startup retry failures retain announcing: this generation may already be in FRR
// after a successful announce whose state write failed. RunAnnouncingReconcile only probes it.
func (e *Engine) reconcileBGPAnnouncing(ctx context.Context) {
	rows, err := e.store.BGPAnnouncements().ListByStatus(ctx, "announcing")
	if err != nil {
		log.Printf("action: reconcile bgp announcing list: %v", err)
		return
	}
	if len(rows) == 0 {
		return
	}
	log.Printf("action: reconciling %d bgp_announcements stuck in announcing", len(rows))
	for _, r := range rows {
		r := r
		go e.retryBGPAnnounce(r)
	}
}

// reconcileBGPWithdrawing retries withdraw for rows stuck in 'withdrawing'.
// vtysh no network on an already-gone route returns "Can't find" which our
// performBGPWithdraw treats as idempotent success.
func (e *Engine) reconcileBGPWithdrawing(ctx context.Context, owned map[int]bool) {
	rows, err := e.store.BGPAnnouncements().ListByStatus(ctx, "withdrawing")
	if err != nil {
		log.Printf("action: reconcile bgp withdrawing list: %v", err)
		return
	}
	if len(rows) == 0 {
		return
	}
	log.Printf("action: reconciling %d bgp_announcements stuck in withdrawing", len(rows))
	for _, r := range rows {
		if owned[r.ID] {
			log.Printf("INFO action: bgp withdrawing announcement_id=%d owned by executing schedule — skipped", r.ID)
			continue
		}
		r := r
		go e.retryBGPWithdraw(r, r.Gen)
	}
}

// retryBGPAnnounce runs vtysh network for a stuck announcement.
// Startup retry failures retain announcing: this generation may already be in FRR
// after a successful announce whose state write failed. RunAnnouncingReconcile only probes it.
func (e *Engine) retryBGPAnnounce(ann store.BGPAnnouncement) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := e.store.BGPConnectors().Get(ctx, ann.ConnectorID)
	if err != nil {
		log.Printf("action: retry announce lookup connector %d: %v", ann.ConnectorID, err)
		log.Printf("WARN action: retry announce announcement_id=%d prefix=%q route_map=%q gen=%d: %v; leaving announcing for runtime reconcile", ann.ID, ann.Prefix, ann.RouteMap, ann.Gen, err)
		return
	}
	if err := vtyshTokens(ann.Prefix, ann.RouteMap); err != nil {
		log.Printf("WARN action: retry announce announcement_id=%d prefix=%q route_map=%q gen=%d: %v; leaving announcing for runtime reconcile", ann.ID, ann.Prefix, ann.RouteMap, ann.Gen, err)
		return
	}
	af := addressFamilyForPrefix(ann.Prefix)
	cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nnetwork %s route-map %s",
		conn.BGPASN, af, ann.Prefix, ann.RouteMap)
	out, vErr := runVtysh(ctx, conn.VtyshPath, cmd)
	if vErr != nil {
		metrics.RecordVtysh("announce", "failed")
		log.Printf("action: retry announce announcement_id=%d failed: %v output=%s", ann.ID, vErr, out)
		if ctx.Err() != nil {
			log.Printf("WARN bgp announce outcome unknown (ctx ended) announcement_id=%d prefix=%s route_map=%s; leaving announcing for reconcile",
				ann.ID, ann.Prefix, ann.RouteMap)
			return
		}
		log.Printf("WARN action: retry announce announcement_id=%d prefix=%q route_map=%q gen=%d: %v; leaving announcing for runtime reconcile", ann.ID, ann.Prefix, ann.RouteMap, ann.Gen, vErr)
		return
	}
	metrics.RecordVtysh("announce", "success")
	if err := e.store.BGPAnnouncements().MarkAnnounced(ctx, ann.ID, ann.Gen); err != nil && !bgpStateNotApplied(err, ann.ID, ann.Gen, "announced") {
		log.Printf("action: retry announce MarkAnnounced announcement_id=%d: %v", ann.ID, err)
	}
	log.Printf("action: reconciled bgp announcing announcement_id=%d prefix=%s", ann.ID, ann.Prefix)
}

// retryBGPWithdraw runs vtysh no network for a stuck withdrawal.
func (e *Engine) retryBGPWithdraw(ann store.BGPAnnouncement, gen int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := e.store.BGPConnectors().Get(ctx, ann.ConnectorID)
	if err != nil {
		log.Printf("action: retry withdraw lookup connector %d: %v", ann.ConnectorID, err)
		if wErr := retryBGPStateWrite(func(writeCtx context.Context) error {
			return e.store.BGPAnnouncements().MarkFailedWithdraw(writeCtx, ann.ID, gen, err.Error())
		}); wErr != nil && !bgpStateNotApplied(wErr, ann.ID, gen, "failed_withdraw") {
			metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
			log.Printf("ERROR action: bgp MarkFailedWithdraw announcement_id=%d: %v", ann.ID, wErr)
		}
		return
	}
	// Minimal ResponseAction — performBGPWithdraw only needs ID for logs.
	synthAct := store.ResponseAction{ID: 0, ActionType: store.ActionTypeBGP, BGPRouteMap: ann.RouteMap}
	synthAct.BGPConnectorID = &ann.ConnectorID
	_, _ = performBGPWithdraw(ctx, e.store, conn, synthAct, ann.Prefix, ann.RouteMap,
		0 /* attackDBID — no single attack for reconcile */, ann.ID, gen, "", store.TriggerPhaseOnExpired)
	log.Printf("action: reconciled bgp withdrawing announcement_id=%d prefix=%s", ann.ID, ann.Prefix)
}

// reconcileExecutingSchedules handles PR-3 leftover: a scheduled action was
// marked executing but the process crashed before the side effect finished.
// We retry the side effect (idempotent via 404 / "Can't find") and transition
// the row to the right terminal state.
func (e *Engine) reconcileExecutingSchedules(ctx context.Context) map[int]bool {
	owned := make(map[int]bool)
	// Query by direct SQL since ListPending filters to pending only.
	// Use a dedicated lookup method on the repo.
	// For now, lift rows by scanning "executing" via ListPending's opposite —
	// but we actually need a new repo method. Implement inline here via a
	// helper that falls back gracefully if not supported.
	rows, err := e.listExecutingSchedules(ctx)
	if err != nil {
		log.Printf("action: reconcile executing schedules: %v", err)
		return owned
	}
	if len(rows) == 0 {
		return owned
	}
	log.Printf("action: reconciling %d executing scheduled_actions (crash recovery)", len(rows))
	for _, sa := range rows {
		sa := sa
		// Re-run the side effect as if this were a fresh recovery. The
		// underlying executeBGP / xDrop DELETE paths handle idempotency
		// (vtysh "Can't find", HTTP 204) so double-execution is safe.
		metrics.RecordRecovered("executing_retried")
		switch sa.ActionType {
		case "bgp_withdraw":
			if sa.AnnouncementID == nil {
				go e.executeRecoveredBGPWithdraw(ctx, sa)
				continue
			}
			annID := *sa.AnnouncementID
			owned[annID] = true
			snap := e.AnnouncementTakeovers(annID)
			go func() {
				unlock := e.LockAnnouncement(annID)
				defer unlock()
				if e.AnnouncementTakeovers(annID) != snap {
					log.Printf("action: recovered executing schedule_id=%d superseded while waiting for announcement lock", sa.ID)
					if err := e.store.ScheduledActions().Complete(ctx, sa.ID); err != nil {
						log.Printf("action: complete superseded scheduled_action %d: %v", sa.ID, err)
					}
					return
				}
				e.executeRecoveredBGPWithdraw(ctx, sa)
			}()
		case "xdrop_unblock":
			go e.executeRecoveredXDropUnblock(ctx, sa)
		default:
			log.Printf("action: reconcile unknown action_type=%q scheduled_id=%d — marking failed", sa.ActionType, sa.ID)
			e.store.ScheduledActions().Fail(ctx, sa.ID, "unknown action_type during reconcile")
		}
	}
	return owned
}

// listExecutingSchedules fetches scheduled_actions rows stuck in 'executing'.
// Implemented as a direct query on ScheduledActions().ListPending helper —
// we extend the mock/repo to expose this via a new method below.
func (e *Engine) listExecutingSchedules(ctx context.Context) ([]store.ScheduledAction, error) {
	if lister, ok := e.store.ScheduledActions().(interface {
		ListExecuting(context.Context) ([]store.ScheduledAction, error)
	}); ok {
		return lister.ListExecuting(ctx)
	}
	return nil, nil // repo doesn't support it yet (no-op for safety)
}

// reconcileXDropWithdrawing retries DELETE for xDrop rules stuck in
// withdrawing state. Uses the same underlying DELETE code as normal unblock,
// with only HTTP 204 treated as confirmed release.
func (e *Engine) reconcileXDropWithdrawing(ctx context.Context) {
	rows, err := e.store.XDropActiveRules().ListWithdrawing(ctx)
	if err != nil {
		log.Printf("action: reconcile xdrop withdrawing: %v", err)
		return
	}
	if len(rows) == 0 {
		return
	}
	log.Printf("action: reconciling %d xdrop_active_rules stuck in withdrawing", len(rows))
	for _, r := range rows {
		r := r
		go func() {
			// Wrap the retry as a synthetic scheduled_action so we can reuse
			// executeRecoveredXDropUnblock (which already does DELETE + state
			// transitions + audit log).
			sa := store.ScheduledAction{
				ID:             0, // no scheduled row — pass 0 so FailDelay/CompleteDelay no-op on DB
				ActionType:     "xdrop_unblock",
				AttackID:       r.AttackID,
				ActionID:       r.ActionID,
				ConnectorID:    r.ConnectorID,
				ExternalRuleID: r.ExternalRuleID,
			}
			rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			e.executeRecoveredXDropUnblock(rctx, sa)
		}()
	}
}

// RecoverScheduledActions re-hydrates timers for pending scheduled_actions
// rows at controller startup (v1.2 PR-3 — fixes the critical v1.1 bug where
// restart silently lost all delayed withdraw/unblock tasks).
//
// For each pending row:
//   - scheduled_for > now: arm a timer that fires after the remaining delay
//   - scheduled_for ≤ now: execute immediately (compensation for downtime)
//
// Race safety: each recovery goroutine calls MarkExecutingDelay before doing
// the side effect. Only one goroutine per row can win the pending→executing
// transition, so normal dispatch goroutines (if any are running in parallel)
// and recovery goroutines cannot both execute.
//
// Call exactly once, before the engine starts accepting new events.
func (e *Engine) RecoverScheduledActions(ctx context.Context) error {
	pending, err := e.store.ScheduledActions().ListPending(ctx)
	if err != nil {
		return fmt.Errorf("list pending scheduled actions: %w", err)
	}
	var overdue, armed int
	for _, sa := range pending {
		sa := sa // capture
		remaining := time.Until(sa.ScheduledFor)
		if remaining <= 0 {
			overdue++
			metrics.RecordRecovered("overdue_fired")
			go e.runRecoveredAction(sa, 0)
		} else {
			armed++
			metrics.RecordRecovered("armed")
			go e.runRecoveredAction(sa, remaining)
		}
	}
	log.Printf("action: recovered %d pending scheduled actions (%d armed, %d overdue)", len(pending), armed, overdue)
	return nil
}

// runRecoveredAction is the goroutine body for a recovered task. Arms a
// timer (or skips directly to execution if overdue), then dispatches to the
// action-type-appropriate executor. On completion, marks the row in DB.
func (e *Engine) runRecoveredAction(sa store.ScheduledAction, delay time.Duration) {
	// Register a cancel context so re-breach / force-remove can cancel the
	// recovered task same as a normal scheduled one.
	e.delayMu.Lock()
	cancelCtx, cancel := context.WithCancel(context.Background())
	key := delayKey(sa.AttackID, sa.ActionID, sa.ConnectorID, sa.ExternalRuleID)
	if sa.ActionType == "bgp_withdraw" && sa.AnnouncementID != nil {
		key = announcementDelayKey(*sa.AnnouncementID)
	}
	e.pendingDelay[key] = cancel
	e.delayMu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-cancelCtx.Done():
			log.Printf("action: recovered task cancelled scheduled_id=%d", sa.ID)
			return
		}
	}

	if sa.ActionType == "bgp_withdraw" && sa.AnnouncementID != nil {
		unlock := e.LockAnnouncement(*sa.AnnouncementID)
		defer unlock()
		if cancelCtx.Err() != nil {
			log.Printf("action: recovered task cancelled while waiting for announcement lock scheduled_id=%d", sa.ID)
			return
		}
	}

	execCtx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()

	// Race guard: atomic pending→executing. If another goroutine got here
	// first (shouldn't happen, but be defensive), we bail.
	if !e.MarkExecutingDelay(execCtx, sa.ID) {
		log.Printf("action: recovered task scheduled_id=%d no longer pending — skipping", sa.ID)
		return
	}

	switch sa.ActionType {
	case "bgp_withdraw":
		e.executeRecoveredBGPWithdraw(execCtx, sa)
	case "xdrop_unblock":
		e.executeRecoveredXDropUnblock(execCtx, sa)
	default:
		log.Printf("action: recovered task scheduled_id=%d has unknown action_type=%q", sa.ID, sa.ActionType)
		e.FailDelay(execCtx, sa.ID, sa.AttackID, sa.ActionID, sa.ConnectorID, sa.ExternalRuleID,
			fmt.Sprintf("unknown action_type: %s", sa.ActionType))
	}
}

// executeRecoveredBGPWithdraw re-runs a persisted BGP withdraw at startup
// or during reconciliation of an 'executing' schedule. Two modes:
//
//   - announcement_id != nil (v1.2 PR-5): look up the announcement,
//     MarkWithdrawing + performBGPWithdraw + MarkWithdrawn/Failed. This is
//     the path all new BGP delays take.
//   - announcement_id == nil (v1.1/PR-3 legacy): per-artifact schedule with
//     attack_id + action_id. Re-run executeBGP via the normal dispatch.
func (e *Engine) executeRecoveredBGPWithdraw(ctx context.Context, sa store.ScheduledAction) {
	if sa.AnnouncementID != nil {
		e.executeRecoveredBGPWithdrawByAnnouncement(ctx, sa)
		return
	}
	// Legacy per-artifact path — kept for safety during upgrade window.
	act, err := e.store.Responses().GetAction(ctx, sa.ActionID)
	if err != nil {
		e.FailDelay(ctx, sa.ID, sa.AttackID, sa.ActionID, sa.ConnectorID, sa.ExternalRuleID,
			fmt.Sprintf("lookup action: %v", err))
		return
	}
	attack, err := e.store.Attacks().Get(ctx, sa.AttackID)
	if err != nil {
		e.FailDelay(ctx, sa.ID, sa.AttackID, sa.ActionID, sa.ConnectorID, sa.ExternalRuleID,
			fmt.Sprintf("lookup attack: %v", err))
		return
	}
	prefixStr := attack.DstIP
	if attack.PrefixID != nil {
		if p, perr := e.store.Prefixes().Get(ctx, *attack.PrefixID); perr == nil {
			prefixStr = p.Prefix
		}
	}
	responseName := ""
	if resp, rerr := e.store.Responses().Get(ctx, act.ResponseID); rerr == nil {
		responseName = resp.Name
	}
	execLog, err, handled := e.legacyNoRowFailure(ctx, sa, responseName)
	if !handled {
		execLog, err = executeBGP(ctx, e.store, e, *act, attack, "expired", prefixStr, responseName, store.TriggerPhaseOnExpired, sa.AttackID, nil)
	}
	if err != nil {
		log.Printf("action: recovered bgp withdraw failed scheduled_id=%d: %v", sa.ID, err)
		e.FailDelay(ctx, sa.ID, sa.AttackID, sa.ActionID, sa.ConnectorID, sa.ExternalRuleID, err.Error())
	} else {
		e.CompleteDelay(ctx, sa.ID, sa.AttackID, sa.ActionID, sa.ConnectorID, sa.ExternalRuleID)
	}
	if execLog != nil {
		if _, lerr := writeExecLog(e.store, execLog); lerr != nil {
			log.Printf("action: recovered bgp withdraw log create: %v", lerr)
		}
	}
}

// executeRecoveredBGPWithdrawByAnnouncement is the PR-5 announcement-level
// recovery path. Transitions active/delayed → withdrawing and runs vtysh.
func (e *Engine) executeRecoveredBGPWithdrawByAnnouncement(ctx context.Context, sa store.ScheduledAction) {
	annID := *sa.AnnouncementID
	ann, err := e.store.BGPAnnouncements().Get(ctx, annID)
	if err != nil || ann == nil {
		e.FailDelayForAnnouncement(ctx, sa.ID, annID, fmt.Sprintf("lookup announcement %d: %v", annID, err))
		return
	}
	// Active announcements need an attachment check before completing recovery.
	gen := ann.Gen
	switch ann.Status {
	case "active":
		var ok bool
		if gen, ok = e.recoveredActiveEnded(ctx, sa, ann); !ok {
			return
		}
	case "withdrawn", "announcing":
		log.Printf("action: recovered bgp withdraw announcement_id=%d no longer needs withdraw (status=%s) — completing", annID, ann.Status)
		e.CompleteDelayForAnnouncement(ctx, sa.ID, annID)
		return
	case "orphan", "dismissed", "dismissed_on_upgrade":
		log.Printf("action: recovered bgp withdraw announcement_id=%d announcement is operator-managed", annID)
		e.CompleteDelayForAnnouncement(ctx, sa.ID, annID)
		return
	}

	conn, err := e.store.BGPConnectors().Get(ctx, ann.ConnectorID)
	if err != nil {
		e.FailDelayForAnnouncement(ctx, sa.ID, annID, fmt.Sprintf("lookup connector: %v", err))
		return
	}
	// Ensure status=withdrawing before side effect.
	if ann.Status == "delayed" {
		if claimed, err := e.store.BGPAnnouncements().MarkWithdrawing(ctx, annID, ann.Gen); err != nil {
			log.Printf("action: recovered MarkWithdrawing announcement_id=%d: %v", annID, err)
		} else if !claimed {
			current, err := e.store.BGPAnnouncements().Get(ctx, annID)
			if err != nil || current == nil {
				e.FailDelayForAnnouncement(ctx, sa.ID, annID, fmt.Sprintf("lookup announcement %d: %v", annID, err))
				return
			}
			if current.Gen != ann.Gen || (current.Status != "withdrawing" && current.Status != "failed") {
				e.CompleteDelayForAnnouncement(ctx, sa.ID, annID)
				return
			}
		}
	}

	synthAct := store.ResponseAction{ID: 0, ActionType: store.ActionTypeBGP, BGPRouteMap: ann.RouteMap}
	synthAct.BGPConnectorID = &ann.ConnectorID
	execLog, wErr := performBGPWithdraw(ctx, e.store, conn, synthAct, ann.Prefix, ann.RouteMap,
		0 /* attackDBID — announcement-level, no single attack */, annID, gen, "", store.TriggerPhaseOnExpired)
	if wErr != nil {
		e.FailDelayForAnnouncement(ctx, sa.ID, annID, wErr.Error())
	} else {
		e.CompleteDelayForAnnouncement(ctx, sa.ID, annID)
	}
	if execLog != nil {
		if _, lerr := writeExecLog(e.store, execLog); lerr != nil {
			log.Printf("action: recovered bgp withdraw log create: %v", lerr)
		}
	}
}

// recoveredActiveEnded is called with the announcement lock held.
func (e *Engine) recoveredActiveEnded(ctx context.Context, sa store.ScheduledAction, ann *store.BGPAnnouncement) (int, bool) {
	item, cancel := context.WithTimeout(ctx, cleanupItemTimeout)
	defer cancel()
	conn, err := e.store.BGPConnectors().Get(item, ann.ConnectorID)
	if err != nil || conn == nil || !conn.Enabled {
		log.Printf("action: recovered bgp withdraw announcement_id=%d no longer needs withdraw (status=active, connector unavailable: %v) — completing", ann.ID, err)
		e.CompleteDelayForAnnouncement(ctx, sa.ID, ann.ID)
		go e.sweepEnabledBGP(ann.ConnectorID, ann.ID)
		return 0, false
	}
	ended, err := e.endedAttachments(item, ann.ID)
	var r store.BGPReconcileResult
	if err == nil && len(ended) > 0 {
		r, err = e.store.BGPAnnouncements().ReconcileAttachments(item, ann.ID, ended, true)
	}
	if err != nil {
		e.FailDelayForAnnouncement(ctx, sa.ID, ann.ID, fmt.Sprintf("reconcile ended attachments: %v", err))
		go e.sweepEnabledBGP(ann.ConnectorID, ann.ID)
		return 0, false
	}
	if !r.NeedWithdraw {
		log.Printf("action: recovered bgp withdraw announcement_id=%d no longer needs withdraw (status=active, detached=%v) — completing", ann.ID, r.Detached)
		e.CompleteDelayForAnnouncement(ctx, sa.ID, ann.ID)
		return 0, false
	}
	log.Printf("action: recovered bgp withdraw announcement_id=%d active with only ended attachments detached=%v — withdrawing", ann.ID, r.Detached)
	return r.Gen, true
}

const legacyNoRowPrefix = "legacy bgp_withdraw without announcement row"

func legacyNoRowMessage(prefix, routeMap string, conn *store.BGPConnector) string {
	msg := fmt.Sprintf("%s: %s route-map=%s connector=%s (id=%d) may remain in FRR and was not withdrawn automatically; Active Mitigations > BGP Routing > orphan banner > Force Withdraw; if listed under dismissed orphans (incl. Dismissed on upgrade), Un-dismiss first, then Force Withdraw", legacyNoRowPrefix, prefix, routeMap, conn.Name, conn.ID)
	if !conn.Enabled {
		msg += "; connector is disabled: enable it and restart the controller (startup orphan scan), or run `no network` on the FRR host"
	}
	return msg
}

func (e *Engine) legacyNoRowFailure(ctx context.Context, sa store.ScheduledAction, responseName string) (*store.ActionExecutionLog, error, bool) {
	parts := splitExternalRuleID(sa.ExternalRuleID)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || sa.ConnectorID <= 0 {
		return nil, nil, false
	}
	conn, err := e.store.BGPConnectors().Get(ctx, sa.ConnectorID)
	if err != nil || conn == nil {
		return nil, nil, false
	}
	ann, err := e.store.BGPAnnouncements().FindByBusinessKey(ctx, parts[0], parts[1], sa.ConnectorID)
	if err != nil || ann != nil {
		return nil, nil, false
	}
	msg := legacyNoRowMessage(parts[0], parts[1], conn)
	log.Printf("WARN action: %s (scheduled_id=%d attack=%d)", msg, sa.ID, sa.AttackID)
	return &store.ActionExecutionLog{
		AttackID: sa.AttackID, ActionID: sa.ActionID, ActionType: "bgp",
		TriggerPhase: store.TriggerPhaseOnExpired, ResponseName: responseName,
		ConnectorName: conn.Name, ConnectorID: &sa.ConnectorID,
		ExternalRuleID: sa.ExternalRuleID, Status: "failed", ErrorMessage: msg,
		ExecutedAt: time.Now(),
	}, errors.New(msg), true
}

// executeRecoveredXDropUnblock re-runs a persisted xDrop unblock by calling
// the connector's DELETE /rules/{id} endpoint. Keeps the success/failure and
// audit log semantics identical to the normal delayed unblock path in
// xdrop.go — writes a per-rule action_execution_log entry so the attack timeline
// reflects the recovery outcome. Mitigations state comes from xdrop_active_rules;
// the log only supplements original request fields.
func (e *Engine) executeRecoveredXDropUnblock(ctx context.Context, sa store.ScheduledAction) {
	e.withdrawXDropRule(ctx, sa, "recovered", store.TriggerPhaseOnExpired)
}

// CancelDelaysForAttack cancels all pending delayed actions for a given attack.
// Called when an attack re-breaches (Active→Expiring→Active transition).
func (e *Engine) CancelDelaysForAttack(attackID int) {
	e.delayMu.Lock()
	prefix := fmt.Sprintf("attack:%d:", attackID)
	for key, cancel := range e.pendingDelay {
		if strings.HasPrefix(key, prefix) {
			cancel()
			delete(e.pendingDelay, key)
			log.Printf("action: cancelled delayed action %s (attack re-breached)", key)
		}
	}
	e.delayMu.Unlock()

	ctx, cancelFn := context.WithTimeout(context.Background(), dbOperationTimeout)
	defer cancelFn()
	if n, err := e.store.ScheduledActions().CancelAllForAttack(ctx, attackID, "rebreach"); err != nil {
		log.Printf("action: CancelAllForAttack attack=%d: %v", attackID, err)
	} else if n > 0 {
		log.Printf("action: cancelled %d persisted scheduled actions for attack=%d (re-breach)", n, attackID)
	}
}

// ForceRemove executes the actual xDrop rule deletion or BGP route withdrawal for a single artifact.
func (e *Engine) ForceRemove(ctx context.Context, attackID, actionID, connectorID int, externalRuleID string) error {
	act, err := e.store.Responses().GetAction(ctx, actionID)
	if err != nil {
		return fmt.Errorf("action %d not found: %w", actionID, err)
	}

	switch act.ActionType {
	case store.ActionTypeXDrop:
		connectors, err := e.store.XDropConnectors().ListEnabled(ctx)
		if err != nil {
			return fmt.Errorf("list xdrop connectors: %w", err)
		}
		for _, conn := range connectors {
			if conn.ID != connectorID {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			k := xdropRuleKey{attackID, actionID, connectorID, externalRuleID}
			// gin's context need not have a deadline. Bound the key wait
			// independently of both it and the subsequent remote operation.
			lockCtx, cancel := context.WithTimeout(context.Background(), xdropTimeout(conn))
			unlock, ok := e.lockXDrop(lockCtx, k, false)
			cancel()
			if !ok {
				if e.xdropStopped(context.Background()) {
					return fmt.Errorf("xdrop rule %s busy: engine stopping", k.rule)
				}
				return fmt.Errorf("xdrop rule %s busy: lock wait exceeded", k.rule)
			}
			defer unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			if isSyntheticFailedXDropRuleID(k.rule) {
				bodies, count, err := e.xdropSyntheticBodies(ctx, k)
				if err != nil {
					return err
				}
				if count == 0 {
					log.Printf("WARN action: xdrop force-remove synthetic rule=%s no create execution logs", k.rule)
				} else {
					part := e.recoverSyntheticXDrop(ctx, conn, k, bodies, true, true)
					if part.result.Error != nil {
						return part.result.Error
					}
				}
			} else {
				result := deleteXDropClaim(conn, k)
				if result.Error != nil {
					return result.Error
				}
			}
			// Publish operator intent and terminal state before a late create
			// can acquire this key for readback. API repeats these idempotent
			// writes to retain its existing warnings and metrics.
			writeCtx, writeCancel := context.WithTimeout(context.Background(), dbOperationTimeout)
			_, err = e.store.ManualOverrides().Create(writeCtx, &store.ActionManualOverride{
				AttackID: attackID, ActionID: actionID, ConnectorID: connectorID, ExternalRuleID: externalRuleID,
			})
			writeCancel()
			if err != nil {
				log.Printf("WARN action: xdrop force-remove rule=%s manual override write failed: %v", k.rule, err)
			}
			writeCtx, writeCancel = context.WithTimeout(context.Background(), dbOperationTimeout)
			err = e.store.XDropActiveRules().MarkWithdrawn(writeCtx, attackID, actionID, connectorID, externalRuleID)
			writeCancel()
			if err != nil {
				log.Printf("WARN action: xdrop force-remove rule=%s MarkWithdrawn failed: %v", k.rule, err)
			}
			log.Printf("action: force-removed xdrop rule %s (connector=%s attack=%d)", externalRuleID, conn.Name, attackID)
			return nil
		}
		return fmt.Errorf("xdrop connector %d not found or disabled", connectorID)

	case store.ActionTypeBGP:
		// v1.2 PR-5: Force Remove on BGP means "take this route down now,
		// regardless of other attached attacks". Maps to announcement-level
		// ForceWithdraw: detaches all attached attacks, transitions to
		// withdrawing, then we run vtysh no network.
		conn, err := e.store.BGPConnectors().Get(ctx, connectorID)
		if err != nil {
			return fmt.Errorf("bgp connector %d: %w", connectorID, err)
		}
		parts := splitExternalRuleID(externalRuleID)
		if len(parts) != 2 {
			return fmt.Errorf("invalid external_rule_id: %s", externalRuleID)
		}
		prefix, routeMap := parts[0], parts[1]

		// Find the announcement to force withdraw.
		ann, lerr := e.store.BGPAnnouncements().FindByBusinessKey(ctx, prefix, routeMap, connectorID)
		if lerr != nil {
			return fmt.Errorf("lookup announcement: %w", lerr)
		}
		if ann == nil {
			// No announcement row but route may still be in FRR (legacy / pre-PR-5).
			// Fall back to direct vtysh no network for backward compat.
			if err := vtyshTokens(prefix, routeMap); err != nil {
				return err
			}
			af := addressFamilyForPrefix(prefix)
			cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nno network %s route-map %s",
				conn.BGPASN, af, prefix, routeMap)
			out, err := runVtysh(ctx, conn.VtyshPath, cmd)
			if err != nil {
				if errors.Is(err, errVtyshTimeout) {
					return fmt.Errorf("vtysh: %w", err)
				}
				if strings.Contains(out, "Can't find") || strings.Contains(out, "no network") {
					return nil
				}
				return fmt.Errorf("vtysh: %v (%s)", err, out)
			}
			log.Printf("action: force-removed bgp route %s (no announcement row, direct vtysh, connector=%s attack=%d)",
				externalRuleID, conn.Name, attackID)
			return nil
		}

		// Announcement exists — go through the manager.
		unlock := e.LockAnnouncement(ann.ID)
		defer unlock()
		detached, gen, err := e.store.BGPAnnouncements().ForceWithdraw(ctx, ann.ID)
		if err != nil {
			return fmt.Errorf("announcement force withdraw: %w", err)
		}
		// Persist operator intent for every claim detached by the committed transaction.
		for _, attachment := range detached {
			actionID := 0
			if attachment.ActionID != nil {
				actionID = *attachment.ActionID
			}
			if _, err := e.store.ManualOverrides().Create(ctx, &store.ActionManualOverride{
				AttackID: attachment.AttackID, ActionID: actionID, ConnectorID: connectorID, ExternalRuleID: externalRuleID,
			}); err != nil {
				metrics.StateWriteFailures.WithLabelValues("force_remove_override").Inc()
				log.Printf("ERROR action: bgp manual_override index: %v", err)
			}
			if _, err := e.store.ActionExecLog().Create(ctx, &store.ActionExecutionLog{
				AttackID: attachment.AttackID, ActionID: actionID, ActionType: "manual_override", TriggerPhase: "manual_override",
				ConnectorID: &connectorID, ExternalRuleID: externalRuleID, Status: "success", ExecutedAt: time.Now(),
			}); err != nil {
				metrics.StateWriteFailures.WithLabelValues("force_remove_override").Inc()
				log.Printf("ERROR action: bgp manual_override log: %v", err)
			}
		}
		cur, err := e.store.BGPAnnouncements().Get(ctx, ann.ID)
		if err != nil || cur == nil {
			return fmt.Errorf("re-read announcement after force withdraw: %w", err)
		}
		if cur.Status != "withdrawing" || cur.Gen != gen {
			log.Printf("action: force remove announcement_id=%d already %s (gen %d), skipping vtysh", ann.ID, cur.Status, cur.Gen)
			return nil
		}
		e.NoteAnnouncementTakeover(ann.ID)
		// Also cancel any delay timer that might be armed for this announcement.
		e.CancelAnnouncementDelay(ann.ID, gen, "force remove by operator")

		synthAct := store.ResponseAction{ID: 0, ActionType: store.ActionTypeBGP, BGPRouteMap: routeMap}
		synthAct.BGPConnectorID = &connectorID
		_, wErr := performBGPWithdraw(ctx, e.store, conn, synthAct, prefix, routeMap,
			attackID, ann.ID, gen, "", "manual_override")
		if wErr != nil {
			return fmt.Errorf("vtysh: %w", wErr)
		}
		log.Printf("action: force-removed bgp route %s (announcement_id=%d connector=%s attack=%d)",
			externalRuleID, ann.ID, conn.Name, attackID)
		return nil

	default:
		return fmt.Errorf("unsupported action type for force remove: %s", act.ActionType)
	}
}

// HandleEvent is the callback wired to AttackTracker.
// It evaluates preconditions and executes matching actions.
func (e *Engine) HandleEvent(event tracker.AttackEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	attack := event.Attack
	if attack == nil || event.DBID == 0 {
		return
	}
	ended := event.Type == "expired" || event.Type == "evicted"
	if ended {
		defer func() { go e.sweepEndedAttack(event.DBID) }()
	}

	// Find the response associated with this attack
	// Priority: rule-level response_id → template-level response_id
	var responseID int
	if attack.ResponseID != nil {
		responseID = *attack.ResponseID
	}
	if responseID == 0 && attack.PrefixID != nil && attack.Direction != "sends" {
		// Fallback: check template-level response binding
		// v2.11: sends attacks do NOT fallback to template default response (Decision 7)
		// because the default response may contain xDrop/BGP actions intended for inbound only.
		if p, err := e.store.Prefixes().Get(ctx, *attack.PrefixID); err == nil && p.ThresholdTemplateID != nil {
			if tmpl, err := e.store.ThresholdTemplates().Get(ctx, *p.ThresholdTemplateID); err == nil && tmpl.ResponseID != nil {
				responseID = *tmpl.ResponseID
			}
		}
	}
	if responseID == 0 {
		// No response configured — still send to global webhooks
		go e.sendGlobalWebhooks(event)
		return
	}

	// Check if response is enabled — disabled response = record attack but skip all actions
	resp, err := e.store.Responses().Get(ctx, responseID)
	if err != nil || !resp.Enabled {
		go e.sendGlobalWebhooks(event)
		return
	}

	// Load response actions
	actions, err := e.store.Responses().ListActions(ctx, responseID)
	if err != nil {
		log.Printf("action: list actions for response %d: %v", responseID, err)
		return
	}

	// Resolve owning prefix for precondition checks and dynamic params
	prefixStr := attack.DstIP
	if attack.PrefixID != nil {
		if p, err := e.store.Prefixes().Get(ctx, *attack.PrefixID); err == nil {
			prefixStr = p.Prefix
		}
	}

	// Lazy-load FlowAnalysis: computed once on first need, shared across all actions.
	var fa *FlowAnalysis
	var faLoaded bool
	getFA := func() *FlowAnalysis {
		if !faLoaded {
			faLoaded = true
			fa = analyzeFlows(ctx, e.store, attack)
		}
		return fa
	}

	// First-match tracking: for non-webhook action types (xdrop, bgp, shell),
	// only the first matching action per type is executed (ACL-style).
	// Webhook actions always all execute (multi-channel notification).
	// Actions are already sorted by (trigger_phase, priority) from DB query.
	firstMatchTypes := map[string]bool{} // tracks which types already matched

	for _, act := range actions {
		var dedup *onceKey
		if !act.Enabled {
			continue
		}

		// v1.2 PR-1 note: order of gates below matters for skip_reason semantics.
		// Silent gates (phase / run_mode / execution=manual) come first — they
		// filter out actions that do not apply to THIS event at all, so writing
		// a skip log for them would be noise.
		// Logged gates (precondition / already_executed / mode_observe /
		// first_match_suppressed) come after — they describe actions that WOULD
		// apply but are being suppressed, which is what operators need to see.

		// v2 lifecycle: use trigger_phase + run_mode if set; else fallback to legacy ExecutionPolicy
		if act.TriggerPhase != "" {
			// New model: trigger_phase decides when, run_mode decides how
			// Constraint: on_expired only supports run_mode=once (tracker doesn't emit periodic events post-expiry)
			if act.TriggerPhase == store.TriggerPhaseOnExpired && act.RunMode != store.RunModeOnce && act.RunMode != "" {
				continue
			}
			if !phaseMatchesEvent(act.TriggerPhase, event.Type) {
				continue
			}
			// run_mode gating for "updated" events (periodic ticks)
			if event.Type == "updated" && act.RunMode == store.RunModeOnce {
				continue
			}
			if act.TriggerPhase == store.TriggerPhaseOnDetected && act.RunMode == store.RunModeRetryUntilSuccess {
				k := onceKey{event.DBID, act.ID, act.TriggerPhase}
				busy := e.onceInFlight(k)
				if alreadyExecutedV2(ctx, e.store, event.DBID, act.ID, act.TriggerPhase) {
					writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonAlreadyExecuted, "retry_until_success: prior success found")
					continue
				}
				if busy {
					writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonAlreadyExecuted, "retry_until_success: prior attempt in flight")
					continue
				}
				dedup = &k
			}
			// Preconditions: lazy-load FlowAnalysis if any flow-dependent attribute exists
			if ok, failedReason := e.checkAllPreconditions(ctx, act, attack, prefixStr, getFA); !ok {
				writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonPreconditionNotMatched, failedReason)
				continue
			}
			if act.RunMode == store.RunModeOnce {
				k := onceKey{event.DBID, act.ID, act.TriggerPhase}
				// Snapshot before querying: a prior action may finish during the query.
				busy := e.onceInFlight(k)
				if alreadyExecutedV2(ctx, e.store, event.DBID, act.ID, act.TriggerPhase) {
					writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonAlreadyExecuted, "run_mode=once: already executed")
					continue
				}
				if busy {
					writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonAlreadyExecuted, "run_mode=once: already dispatched (in flight)")
					continue
				}
				dedup = &k
			}
			// Manual override suppression: per-artifact checks happen inside
			// executeXDrop/executeBGP, not here — allows partial suppress when
			// only some artifacts were force-removed (P2-3).
		} else {
			// Legacy model
			if !policyMatchesEvent(act.ExecutionPolicy, event.Type) {
				continue
			}
			if ok, failedReason := e.checkAllPreconditions(ctx, act, attack, prefixStr, getFA); !ok {
				writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonPreconditionNotMatched, failedReason)
				continue
			}
			busy := false
			switch act.ExecutionPolicy {
			case "once_on_enter", "once_on_exit", "retry_until_success":
				k := onceKey{event.DBID, act.ID, act.ExecutionPolicy}
				busy = e.onceInFlight(k)
				dedup = &k
			}
			if shouldSkip(ctx, e.store, event.DBID, act.ID, act.ExecutionPolicy) {
				writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonAlreadyExecuted, "legacy execution_policy: already matched")
				continue
			}
			if busy {
				writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonAlreadyExecuted, "legacy execution_policy: already dispatched (in flight)")
				continue
			}
		}

		// Mode check: xdrop/xdrop_api only runs in auto mode
		if (act.ActionType == store.ActionTypeXDropAPI || act.ActionType == store.ActionTypeXDrop) && e.mode != "auto" {
			writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonModeObserve, "action_engine.mode=observe")
			continue
		}

		// Manual actions need explicit UI trigger (not implemented yet).
		// Checked BEFORE first_match so manual actions don't contend for
		// first-match slot and don't get misattributed as first_match_suppressed.
		if act.Execution == store.ExecutionManual {
			continue
		}

		if attack.Direction == "sends" && (act.ActionType == store.ActionTypeXDrop || act.ActionType == store.ActionTypeBGP) && !ended {
			writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonOutboundBlockForbidden,
				"direction=sends: xDrop/BGP would block the internal source host")
			continue
		}

		// First-match ACL (v1.2 PR-1 P1 fix): must be checked AFTER all other
		// gates so that phase-mismatched or precondition-failed actions are not
		// misattributed as first_match_suppressed. Only actions that WOULD have
		// executed in this dispatch are suppressed by this ACL.
		if act.ActionType != store.ActionTypeWebhook && firstMatchTypes[act.ActionType] {
			writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "", SkipReasonFirstMatchSuppressed, "")
			continue
		}

		// Mark this type as matched (first-match for non-webhook types)
		if act.ActionType != store.ActionTypeWebhook {
			firstMatchTypes[act.ActionType] = true
		}

		// v1.2.1: xDrop decoder compatibility gate. Runs AFTER manual /
		// first_match gates so manual and first-match-suppressed actions
		// don't get spurious decoder skip logs. Runs BEFORE the goroutine
		// spawn so the skip log is visible to callers that check
		// immediately after HandleEvent returns.
		//
		// xDrop is an L4 filter tool; L3-aggregate decoders (e.g. `ip`)
		// have no clean 5-tuple mapping and would silently broaden into
		// full-prefix blackhole when flow analysis fails to populate
		// src_ip/src_port. Route those attacks to BGP null-route by
		// skipping the xDrop action.
		if act.ActionType == store.ActionTypeXDrop && !IsXDropCompatibleDecoder(attack.DecoderFamily) {
			writeSkipLog(ctx, e.store, event.DBID, act, resp.Name, "",
				SkipReasonDecoderNotSupported,
				fmt.Sprintf("decoder=%s is an L3 aggregate; xDrop is L4-only. Use BGP null-route for this attack class.",
					attack.DecoderFamily))
			continue
		}
		// Only query flow_logs if the action actually uses flow-derived data.
		// If getFA() was already called (e.g. by precondition evaluation), reuse cached result.
		var flowData *FlowAnalysis
		if faLoaded {
			flowData = fa // already computed, free to pass
		} else if actionNeedsFlowData(act) {
			flowData = getFA()
		}
		actCtx, actCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if ended {
			e.endAction(event.DBID, 1)
		}
		if dedup != nil {
			e.onceAction(*dedup, 1)
		}
		go func(a store.ResponseAction, fd *FlowAnalysis, k *onceKey) {
			defer actCancel()
			if k != nil {
				// Release only after executeAction has written its execution log.
				defer e.onceAction(*k, -1)
			}
			if ended {
				defer e.endAction(event.DBID, -1)
			}
			e.executeAction(actCtx, event, a, fd)
		}(act, flowData, dedup)
	}

	// Always fire global webhooks regardless of response actions
	go e.sendGlobalWebhooks(event)
}

// phaseMatchesEvent checks if a v2 trigger_phase + run_mode matches the tracker event type.
func phaseMatchesEvent(phase, eventType string) bool {
	switch phase {
	case store.TriggerPhaseOnDetected:
		// confirmed/type_upgrade = attack just started → once/periodic/retry all fire
		// updated = periodic 5min tick → only periodic/retry fire (handled by run_mode check in caller)
		return eventType == "confirmed" || eventType == "type_upgrade" || eventType == "updated"
	case store.TriggerPhaseOnExpired:
		return eventType == "expired" || eventType == "evicted"
	}
	return false
}

// alreadyExecutedV2 checks action_execution_log for v2 idempotency.
func alreadyExecutedV2(ctx context.Context, s store.Store, attackID, actionID int, triggerPhase string) bool {
	done, err := s.ActionExecLog().AllTargetsDone(ctx, attackID, actionID, triggerPhase)
	return err == nil && done
}

func policyMatchesEvent(policy, eventType string) bool {
	switch policy {
	case "once_on_enter":
		return eventType == "confirmed" || eventType == "type_upgrade"
	case "periodic":
		return eventType == "confirmed" || eventType == "updated" || eventType == "type_upgrade"
	case "retry_until_success":
		return eventType == "confirmed" || eventType == "type_upgrade"
	case "once_on_exit":
		return eventType == "expired" || eventType == "evicted"
	}
	return false
}

// checkAllPreconditions checks preconditions against the attack context.
// If structured preconditions exist in DB, they are authoritative and legacy JSONB is ignored.
// If no structured preconditions exist, falls back to legacy JSONB evaluation.
// getFA is a lazy loader for FlowAnalysis — only called if a flow-dependent attribute is encountered.
// checkAllPreconditions returns (ok, failedDescription). When ok=false,
// failedDescription is a short human-readable reason (e.g. "domain eq internal_ip failed")
// suitable for action_execution_log.error_message. When ok=true, failedDescription is empty.
func (e *Engine) checkAllPreconditions(ctx context.Context, act store.ResponseAction, attack *store.Attack, prefixStr string, getFA func() *FlowAnalysis) (bool, string) {
	// Try structured preconditions from DB
	structured, err := e.store.Preconditions().List(ctx, act.ID)
	if err != nil {
		log.Printf("ERROR action: preconditions lookup action=%d attack=%d: %v; falling back to legacy preconditions", act.ID, attack.ID, err)
		metrics.PreconditionLookupErrors.Inc()
	}
	if err == nil && len(structured) > 0 {
		// Structured preconditions exist — they are the single source of truth
		for _, p := range structured {
			if !evaluateStructuredPrecondition(p, attack, prefixStr, getFA) {
				return false, fmt.Sprintf("%s %s %s failed", p.Attribute, p.Operator, p.Value)
			}
		}
		return true, "" // all structured conditions passed, ignore legacy JSONB
	}

	// No structured preconditions — fall back to legacy JSONB
	if evaluatePreconditions(act.Preconditions, attack, prefixStr) {
		return true, ""
	}
	return false, "legacy precondition failed"
}

// evaluateStructuredPrecondition checks one structured precondition row.
// getFA is a lazy loader — only called for flow-dependent attributes. If it returns nil, flow attributes fail closed.
func evaluateStructuredPrecondition(p store.ActionPrecondition, attack *store.Attack, prefixStr string, getFA func() *FlowAnalysis) bool {
	switch p.Attribute {
	case "cidr":
		// Extract prefix length from attack's DstIP (not owning prefix).
		// For subnet attacks: DstIP = "10.0.0.0/24" → 24
		// Bare hosts use /32 or /128; invalid IPs retain the legacy /32 fallback.
		prefixLen := int64(32)
		if idx := strings.IndexByte(attack.DstIP, '/'); idx >= 0 {
			if pl, err := strconv.ParseInt(attack.DstIP[idx+1:], 10, 64); err == nil {
				prefixLen = pl
			}
		} else if ip := net.ParseIP(attack.DstIP); ip != nil && ip.To4() == nil {
			prefixLen = 128
		}
		return compareIntOp(p.Operator, p.Value, prefixLen)
	case "decoder":
		return matchStringOp(p.Operator, p.Value, attack.DecoderFamily)
	case "attack_type":
		return matchStringOp(p.Operator, p.Value, attack.AttackType)
	case "severity":
		return matchStringOp(p.Operator, p.Value, attack.Severity)
	case "pps", "peak_pps":
		return compareIntOp(p.Operator, p.Value, attack.PeakPPS)
	case "bps", "peak_bps":
		return compareIntOp(p.Operator, p.Value, attack.PeakBPS)
	case "node":
		return matchStringInSlice(p.Operator, p.Value, attack.NodeSources)
	case "domain":
		return matchStringOp(p.Operator, p.Value, attackDomain(attack.DstIP))
	case "carpet_bomb":
		// v1.3 Phase 1c: semantic alias for subnet-scope attacks. Equivalent to
		// `domain eq subnet` but named after the attack pattern it targets, for
		// readability in Response configs ("precondition: carpet_bomb eq true").
		//
		// Value is "true" / "false". Operators: eq / neq.
		isCarpet := attackDomain(attack.DstIP) == "subnet"
		wantStr := strings.ToLower(strings.TrimSpace(p.Value))
		want := wantStr == "true" || wantStr == "1" || wantStr == "yes"
		switch p.Operator {
		case "eq":
			return isCarpet == want
		case "neq":
			return isCarpet != want
		default:
			log.Printf("action: carpet_bomb precondition only supports eq/neq, got %q", p.Operator)
			return false
		}
	case "dominant_src_port":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.DominantSrcPort))
	case "dominant_src_port_pct":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.DominantSrcPortPct))
	case "dominant_dst_port":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.DominantDstPort))
	case "dominant_dst_port_pct":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.DominantDstPortPct))
	case "unique_src_ips":
		fa := getFA()
		if fa == nil {
			log.Printf("action: precondition %q: no flow data available, blocking", p.Attribute)
			return false
		}
		return compareIntOp(p.Operator, p.Value, int64(fa.UniqueSrcIPs))
	default:
		log.Printf("action: unknown precondition attribute %q, blocking (fail closed)", p.Attribute)
		return false
	}
}

// attackDomain returns "internal_ip" for single-IP attacks (/32 IPv4, /128 IPv6, or bare IP)
// and "subnet" for CIDR attacks. Handles both in-memory format ("10.0.0.1") and
// DB-read format ("10.0.0.1/32") from postgres inet::TEXT.
func attackDomain(dstIP string) string {
	if idx := strings.IndexByte(dstIP, '/'); idx >= 0 {
		pl, err := strconv.ParseInt(dstIP[idx+1:], 10, 64)
		if err != nil {
			return "internal_ip"
		}
		host := dstIP[:idx]
		if strings.Contains(host, ":") {
			// IPv6: single IP = /128
			if pl != 128 {
				return "subnet"
			}
		} else {
			// IPv4: single IP = /32
			if pl != 32 {
				return "subnet"
			}
		}
	}
	return "internal_ip"
}

// matchStringOp handles eq/neq/in/not_in operators for string values.
func matchStringOp(op, expected, actual string) bool {
	switch op {
	case "eq":
		return actual == expected
	case "neq":
		return actual != expected
	case "in", "not_in":
		found := false
		for _, v := range strings.Split(expected, ",") {
			if strings.TrimSpace(v) == actual {
				found = true
				break
			}
		}
		if op == "in" {
			return found
		}
		return !found
	}
	return false
}

// matchStringInSlice checks if any element in the slice matches.
func matchStringInSlice(op, expected string, actual []string) bool {
	switch op {
	case "eq", "in":
		targets := strings.Split(expected, ",")
		for _, a := range actual {
			for _, t := range targets {
				if strings.TrimSpace(t) == a {
					return true
				}
			}
		}
		return false
	}
	return false
}

// compareIntOp handles gt/lt/gte/lte/eq/in operators for int64 values.
func compareIntOp(op, valStr string, actual int64) bool {
	if op == "in" || op == "not_in" {
		found := false
		for _, s := range strings.Split(valStr, ",") {
			v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
			if err == nil && v == actual {
				found = true
				break
			}
		}
		if op == "in" {
			return found
		}
		return !found
	}
	val, err := strconv.ParseInt(strings.TrimSpace(valStr), 10, 64)
	if err != nil {
		return false
	}
	switch op {
	case "gt":
		return actual > val
	case "gte":
		return actual >= val
	case "lt":
		return actual < val
	case "lte":
		return actual <= val
	case "eq":
		return actual == val
	case "neq":
		return actual != val
	}
	return false
}

// evaluatePreconditions checks AND-logic preconditions against attack context (legacy JSONB).
func evaluatePreconditions(raw json.RawMessage, attack *store.Attack, prefixStr string) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true // no preconditions = always match
	}

	var conds map[string]string
	if err := json.Unmarshal(raw, &conds); err != nil {
		log.Printf("action: invalid precondition JSON, blocking action (fail closed): %v", err)
		return false // fail closed: invalid preconditions = block
	}

	for field, expr := range conds {
		if !checkCondition(field, expr, attack, prefixStr) {
			return false
		}
	}
	return true
}

func checkCondition(field, expr string, attack *store.Attack, prefixStr string) bool {
	switch field {
	case "peak_pps":
		return compareInt(expr, attack.PeakPPS)
	case "peak_bps":
		return compareInt(expr, attack.PeakBPS)
	case "severity":
		return attack.Severity == expr
	case "attack_type":
		return attack.AttackType == expr
	case "domain":
		return attackDomain(attack.DstIP) == expr
	case "prefix_len":
		return comparePrefixLen(expr, prefixStr)
	case "duration":
		if attack.StartedAt.IsZero() {
			return false
		}
		dur := int64(time.Since(attack.StartedAt).Seconds())
		return compareInt(expr, dur)
	default:
		log.Printf("action: unknown precondition field %q, blocking (fail closed)", field)
		return false // fail closed: unknown field = block
	}
}

func compareInt(expr string, actual int64) bool {
	expr = strings.TrimSpace(expr)
	if len(expr) < 2 {
		return false // fail closed
	}
	var op string
	var valStr string
	// Parse operator: >=, <=, >, <
	if len(expr) >= 2 && (expr[:2] == ">=" || expr[:2] == "<=") {
		op = expr[:2]
		valStr = expr[2:]
	} else {
		op = string(expr[0])
		valStr = expr[1:]
	}
	val, err := strconv.ParseInt(strings.TrimSpace(valStr), 10, 64)
	if err != nil {
		return false // fail closed
	}
	switch op {
	case ">":
		return actual > val
	case ">=":
		return actual >= val
	case "<":
		return actual < val
	case "<=":
		return actual <= val
	}
	return false // unknown operator = fail closed
}

func extractPrefixLen(dstIP string) string {
	if idx := strings.IndexByte(dstIP, '/'); idx >= 0 {
		return dstIP[idx+1:]
	}
	if ip := net.ParseIP(dstIP); ip != nil && ip.To4() == nil {
		return "128"
	}
	// Invalid IPs retain the legacy /32 fallback.
	return "32"
}

func comparePrefixLen(expr, dstIP string) bool {
	// Extract prefix length from CIDR notation (e.g. "10.2.0.0/24" → 24)
	// Bare hosts use /32 or /128; invalid IPs retain the legacy /32 fallback.
	prefixLen := int64(32)
	if idx := strings.IndexByte(dstIP, '/'); idx >= 0 {
		if pl, err := strconv.ParseInt(dstIP[idx+1:], 10, 64); err == nil {
			prefixLen = pl
		}
	} else if ip := net.ParseIP(dstIP); ip != nil && ip.To4() == nil {
		prefixLen = 128
	}
	return compareInt(expr, prefixLen)
}

// shouldSkip checks ActionsLog and ActionExecLog for idempotency.
func shouldSkip(ctx context.Context, s store.Store, attackID, actionID int, policy string) bool {
	// Check legacy ActionsLog
	existing, err := s.ActionsLog().FindByAttackAndAction(ctx, attackID, actionID)
	if err == nil && existing != nil {
		switch policy {
		case "once_on_enter", "once_on_exit":
			if existing.Status == "success" {
				return true
			}
		case "retry_until_success":
			if existing.Status == "success" {
				return true
			}
		}
	}

	// Check new ActionExecLog (v2)
	triggerPhase := ""
	switch policy {
	case "once_on_enter":
		triggerPhase = store.TriggerPhaseOnDetected
	case "once_on_exit":
		triggerPhase = store.TriggerPhaseOnExpired
	}
	if triggerPhase != "" {
		done, err := s.ActionExecLog().AllTargetsDone(ctx, attackID, actionID, triggerPhase)
		if err == nil && done {
			return true
		}
	}

	return false
}

// executeAction dispatches to the appropriate action handler.
// fa is pre-computed FlowAnalysis (may be nil if no flow data available).
func (e *Engine) executeAction(ctx context.Context, event tracker.AttackEvent, act store.ResponseAction, fa *FlowAnalysis) {
	attack := event.Attack

	// Resolve owning prefix for dynamic parameters
	prefixStr := attack.DstIP
	if attack.PrefixID != nil {
		if p, err := e.store.Prefixes().Get(ctx, *attack.PrefixID); err == nil {
			prefixStr = p.Prefix
		}
	}

	// Resolve response name for logging
	responseName := ""
	if resp, err := e.store.Responses().Get(ctx, act.ResponseID); err == nil {
		responseName = resp.Name
	}

	// Expand dynamic parameters in action config (includes flow-derived variables)
	configStr := expandParams(string(act.Config), attack, event.Type, prefixStr, fa)

	// Determine trigger phase
	triggerPhase := act.TriggerPhase
	if triggerPhase == "" {
		triggerPhase = event.Type
	}

	switch act.ActionType {
	case store.ActionTypeWebhook:
		execLog := &store.ActionExecutionLog{
			AttackID:     event.DBID,
			ActionID:     act.ID,
			ResponseName: responseName,
			ActionType:   store.ActionTypeWebhook,
			TriggerPhase: triggerPhase,
			ExecutedAt:   time.Now(),
		}

		// If webhook_connector_id is set, use the connector; otherwise fall back to old config-based webhook
		if act.WebhookConnectorID != nil {
			wc, err := e.store.WebhookConnectors().Get(ctx, *act.WebhookConnectorID)
			if err != nil {
				execLog.Status = "failed"
				execLog.ErrorMessage = safeWebhookError(0, err)
				log.Printf("action: %s", execLog.ErrorMessage)
			} else {
				execLog.ConnectorName = wc.Name
				start := time.Now()
				result, err := postConnectorWebhook(ctx, *wc, attack, event.Type, fa)
				execLog.DurationMs = int(time.Since(start).Milliseconds())
				if err != nil {
					execLog.Status = "failed"
					execLog.ErrorMessage = err.Error()
					log.Printf("action: webhook connector %d failed for attack %d: %v", wc.ID, event.DBID, err)
				} else {
					execLog.Status = "success"
					execLog.ResponseBody = result
				}
			}
		} else {
			// Legacy: config-based webhook
			start := time.Now()
			result, err := executeWebhook(ctx, []byte(configStr), attack, event.Type)
			execLog.DurationMs = int(time.Since(start).Milliseconds())
			execLog.ConnectorName = "legacy-config"
			if err != nil {
				execLog.Status = "failed"
				execLog.ErrorMessage = err.Error()
				log.Printf("action: webhook failed for attack %d: %v", event.DBID, err)
			} else {
				execLog.Status = "success"
				execLog.ResponseBody = result
			}
		}

		if _, err := writeExecLog(e.store, execLog); err != nil {
			log.Printf("action: create action_execution_log: %v", err)
		}

	case store.ActionTypeXDrop:
		// NOTE: decoder compatibility gate (v1.2.1) runs in the main
		// dispatch loop (HandleEvent) BEFORE reaching this goroutine, so
		// by the time we're here the decoder is guaranteed compatible.
		// Defense-in-depth: skip xDrop for global attacks (no concrete IP to block)
		if attack.DstIP == "0.0.0.0/0" {
			log.Printf("action: xdrop skipped for global attack %d (0.0.0.0/0 has no concrete target)", event.DBID)
			skipLog := &store.ActionExecutionLog{
				AttackID:     event.DBID,
				ActionID:     act.ID,
				ActionType:   store.ActionTypeXDrop,
				TriggerPhase: triggerPhase,
				ResponseName: responseName,
				Status:       "skipped",
				ErrorMessage: "global attack (0.0.0.0/0) has no concrete IP target for xDrop",
			}
			recordSkip(skipLog, SkipReasonGlobalNoTarget)
			if _, err := writeExecLog(e.store, skipLog); err != nil {
				log.Printf("action: create skip log: %v", err)
			}
			break
		}
		// Manual override suppression: per-artifact checks inside executeXDrop
		// Delay scheduling: per-artifact inside executeXDrop (each rule gets its own cancel context)
		execLog, err := executeXDrop(ctx, e.store, act, attack, event.Type, prefixStr, responseName, triggerPhase, event.DBID, fa, e)
		if err != nil {
			log.Printf("action: xdrop failed for attack %d: %v", event.DBID, err)
		}
		if execLog != nil {
			if _, err := writeExecLog(e.store, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
		}

	case store.ActionTypeShell:
		execLog, err := executeShell(ctx, e.store, act, attack, event.Type, prefixStr, responseName, triggerPhase, event.DBID, fa)
		if err != nil {
			log.Printf("action: shell failed for attack %d: %v", event.DBID, err)
		}
		if execLog != nil {
			if _, err := writeExecLog(e.store, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
		}

	case store.ActionTypeBGP:
		// Defense-in-depth: skip BGP for global attacks (no concrete target)
		if attack.DstIP == "0.0.0.0/0" {
			log.Printf("action: bgp skipped for global attack %d (0.0.0.0/0 has no concrete target)", event.DBID)
			skipLog := &store.ActionExecutionLog{
				AttackID:     event.DBID,
				ActionID:     act.ID,
				ActionType:   store.ActionTypeBGP,
				TriggerPhase: triggerPhase,
				ResponseName: responseName,
				Status:       "skipped",
				ErrorMessage: "global attack (0.0.0.0/0) has no concrete target for BGP",
			}
			recordSkip(skipLog, SkipReasonGlobalNoTarget)
			if _, err := writeExecLog(e.store, skipLog); err != nil {
				log.Printf("action: create skip log: %v", err)
			}
			break
		}
		if act.BGPConnectorID == nil {
			log.Printf("action: bgp action %d has no connector_id, skipping", act.ID)
			skipLog := &store.ActionExecutionLog{
				AttackID:     event.DBID,
				ActionID:     act.ID,
				ResponseName: responseName,
				ActionType:   store.ActionTypeBGP,
				TriggerPhase: triggerPhase,
				Status:       "skipped",
				ErrorMessage: "bgp action has no connector_id",
				ExecutedAt:   time.Now(),
			}
			recordSkip(skipLog, SkipReasonNoConnector)
			if _, err := writeExecLog(e.store, skipLog); err != nil {
				log.Printf("action: create skip log: %v", err)
			}
			break
		}
		// v1.2 PR-5: BGP delay logic moved inside bgpWithdraw (the announcement
		// manager owns delay decisions now). Just call executeBGP — it handles
		// Attach/Detach internally, arms the delay timer if needed, and returns
		// the appropriate log for the immediate / scheduled / shared paths.
		execLog, err := executeBGP(ctx, e.store, e, act, attack, event.Type, prefixStr, responseName, triggerPhase, event.DBID, nil)
		if err != nil {
			log.Printf("action: bgp failed for attack %d: %v", event.DBID, err)
		}
		if execLog != nil {
			if _, err := writeExecLog(e.store, execLog); err != nil {
				log.Printf("action: create action_execution_log: %v", err)
			}
		}

	case store.ActionTypeXDropAPI:
		// Legacy placeholder — log as skipped
		execLog := &store.ActionExecutionLog{
			AttackID:     event.DBID,
			ActionID:     act.ID,
			ResponseName: responseName,
			ActionType:   store.ActionTypeXDropAPI,
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			ErrorMessage: "xdrop_api deprecated, use action_type=xdrop",
			ExecutedAt:   time.Now(),
		}
		recordSkip(execLog, SkipReasonDeprecatedXDropAPI)
		if _, err := writeExecLog(e.store, execLog); err != nil {
			log.Printf("action: create action_execution_log: %v", err)
		}

	default:
		execLog := &store.ActionExecutionLog{
			AttackID:     event.DBID,
			ActionID:     act.ID,
			ResponseName: responseName,
			ActionType:   act.ActionType,
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			ErrorMessage: fmt.Sprintf("unknown action type: %s", act.ActionType),
			ExecutedAt:   time.Now(),
		}
		recordSkip(execLog, SkipReasonUnknownActionType)
		if _, err := writeExecLog(e.store, execLog); err != nil {
			log.Printf("action: create action_execution_log: %v", err)
		}
	}
}

// fireGlobalWebhooks sends notifications to all enabled global webhook connectors.
func (e *Engine) fireGlobalWebhooks(ctx context.Context, event tracker.AttackEvent) {
	eventName := eventToWebhookEvent(event.Type)
	if eventName == "" {
		return
	}

	connectors, err := e.store.WebhookConnectors().ListGlobal(ctx)
	if err != nil {
		log.Printf("action: list global webhook connectors: %s", safeWebhookError(0, err))
		return
	}

	for _, wc := range connectors {
		if !wc.Enabled {
			continue
		}

		result, err := postConnectorWebhook(ctx, wc, event.Attack, eventName, nil)
		if err != nil {
			log.Printf("action: global webhook connector %d failed: %v", wc.ID, err)
		} else {
			log.Printf("action: global webhook connector %d sent: %s event=%s attack=%d",
				wc.ID, result, eventName, event.DBID)
		}
	}
}

func eventToWebhookEvent(eventType string) string {
	switch eventType {
	case "confirmed":
		return "attack_start"
	case "expired", "evicted":
		return "attack_end"
	case "type_upgrade":
		return "attack_update"
	}
	return ""
}

// SupportedTemplateVars enumerates every placeholder expandParams +
// flowAnalysisReplacements substitute. The API layer validates user-supplied
// payloads (xdrop_custom_payload and shell_extra_args) against
// this set so misspellings like {attack_dst_ip} fail loud at API time rather
// than silently leaking through expandParams as literals (and surfacing only
// later as a connector rejection / failed badge).
var SupportedTemplateVars = map[string]struct{}{
	"ip": {}, "dst_ip": {}, "prefix": {}, "prefix_len": {},
	"attack_type": {}, "decoder": {}, "severity": {},
	"peak_pps": {}, "peak_bps": {}, "event": {}, "attack_id": {},
	"started_at": {}, "duration": {}, "node_sources": {}, "reason_codes": {},
	"top_src_ips": {}, "top_src_ports": {}, "top_dst_ports": {},
	"dominant_src_port": {}, "dominant_src_port_pct": {},
	"dominant_dst_port": {}, "dominant_dst_port_pct": {},
	"src_ip": {}, "unique_src_ips": {}, "flow_summary_json": {},
}

// templateVarRegex extracts {name} placeholders. Only matches identifier-shaped
// names so JSON braces like `{"foo":"bar"}` (whose contents include `:` etc.)
// are not flagged.
var templateVarRegex = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// ValidateTemplateVars returns an error if payload references any {var} not in
// SupportedTemplateVars. Empty payload is allowed (no-op). Placeholders
// preceded by `$` are treated as shell variable expansion (`${HOSTNAME}`) and
// skipped — they are a shell-layer construct, not an xSight template variable.
func ValidateTemplateVars(field, payload string) error {
	if payload == "" {
		return nil
	}
	for _, m := range templateVarRegex.FindAllStringSubmatchIndex(payload, -1) {
		start := m[0]
		if start > 0 && payload[start-1] == '$' {
			continue
		}
		name := payload[m[2]:m[3]]
		if _, ok := SupportedTemplateVars[name]; !ok {
			return fmt.Errorf("%s contains unknown template variable {%s}", field, name)
		}
	}
	return nil
}

// expandParams replaces {ip} {prefix} {attack_type} {top_src_ips} etc. in a template string.
func expandParams(template string, attack *store.Attack, eventType string, prefixStr string, fa *FlowAnalysis) string {
	duration := "0"
	if !attack.StartedAt.IsZero() {
		duration = strconv.FormatInt(int64(time.Since(attack.StartedAt).Seconds()), 10)
	}
	nodeSources := strings.Join(attack.NodeSources, ",")
	reasonCodes := strings.Join(attack.ReasonCodes, ",")

	pairs := []string{
		"{ip}", attack.DstIP,
		"{dst_ip}", attack.DstIP,
		"{prefix}", prefixStr,
		"{prefix_len}", extractPrefixLen(prefixStr),
		"{attack_type}", attack.AttackType,
		"{decoder}", attack.DecoderFamily,
		"{severity}", attack.Severity,
		"{peak_pps}", strconv.FormatInt(attack.PeakPPS, 10),
		"{peak_bps}", strconv.FormatInt(attack.PeakBPS, 10),
		"{event}", eventType,
		"{attack_id}", strconv.Itoa(attack.ID),
		"{started_at}", attack.StartedAt.Format(time.RFC3339),
		"{duration}", duration,
		"{node_sources}", nodeSources,
		"{reason_codes}", reasonCodes,
	}
	// Append flow analysis replacements (Phase 4)
	pairs = append(pairs, flowAnalysisReplacements(fa)...)

	return strings.NewReplacer(pairs...).Replace(template)
}
