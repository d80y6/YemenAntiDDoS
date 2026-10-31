// Package metrics exposes xSight controller state as Prometheus metrics.
//
// Design principles:
//   - Only expose metrics an operator can actually alert on or dashboard
//     (see roadmap v1.2.1 Scope). No speculative metrics.
//   - Gauges that read DB state use Prometheus custom collectors so the
//     value is fresh-at-scrape-time. No background refresh goroutine
//     (simpler, no staleness window).
//   - Counters (vtysh ops, action executions) are incremented inline at
//     call sites. Single source of truth is the Go variable — DB state
//     is NOT re-derived from counters.
//   - /metrics endpoint is unauthenticated, matching industry convention
//     for Prometheus scraping (relies on network-level isolation).
//
// Layer A (v1.2 Action State gauges — custom collectors):
//
//	xsight_bgp_announcements{status}       current announcements by status
//	xsight_xdrop_rules{status}             current xDrop rules by status
//	xsight_scheduled_actions{status}       current scheduled actions by status
//
// Layer A (inline counters):
//
//	xsight_vtysh_ops_total{operation,result}  vtysh announce/withdraw outcomes
//	xsight_action_executions_total{action_type,status}  action engine dispatch outcomes
//
// Layer B (attack tracker — wrap existing atomic counters):
//
//	xsight_attacks_active                   current active attacks (gauge)
//	xsight_attacks_created_total            lifetime attacks created
//	xsight_attacks_suppressed_total         lifetime attacks suppressed (dedup)
//	xsight_attacks_evicted_total            lifetime attacks evicted (cap hit)
//
// Layer C: Go runtime metrics are auto-registered by promhttp default (free).

package metrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

// ─────────────────────────────────────────────────────────────────────────────
// Layer A — inline counters
// ─────────────────────────────────────────────────────────────────────────────

// StateWriteFailures counts exhausted state writes by their bounded operation.
var StateWriteFailures = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "xsight_state_write_failures_total", Help: "Failed state writes by operation."}, []string{"op"},
)

var BGPStaleWrites = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "xsight_bgp_stale_writes_total", Help: "BGP state writes not applied."}, []string{"op"})

var BGPWithdrawingReconcile = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "xsight_bgp_withdrawing_reconcile_total", Help: "Runtime BGP withdrawing reconciliation outcomes; claimed does not imply terminal success."}, []string{"outcome"})

var BGPAnnouncingReconcile = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "xsight_bgp_announcing_reconcile_total", Help: "Runtime BGP announcing label reconciliation outcomes."}, []string{"outcome"})

var ConfigPublishFailures = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "xsight_config_publish_failures_total", Help: "Config changes saved but publishAfterChange got an error: threshold tree rebuild, or node publish (build config / list nodes) failed."}, []string{"stage"})

var StartupCleanup = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "xsight_startup_cleanup_total", Help: "Startup cleanup outcomes."}, []string{"kind", "outcome"})

var XDropReconcile = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "xsight_xdrop_reconcile_total", Help: "Automatic xDrop withdrawal and reconciliation outcomes."}, []string{"outcome"})

var EndedSweep = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "xsight_ended_sweep_total", Help: "Ended attack sweep outcomes."}, []string{"kind", "outcome"})

var GRPCIdentityRejects = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "xsight_grpc_identity_rejects_total", Help: "Reports rejected for missing handshake."}, []string{"stream"},
)
var RingEstimatedMemoryBytes = prometheus.NewGauge(prometheus.GaugeOpts{Name: "xsight_ring_estimated_memory_bytes", Help: "Estimated memory for both ring directions."})

// VtyshOps counts outcomes of vtysh commands xSight issues for BGP state
// changes. Incremented by bgp.go at each performBGPAnnounce / performBGPWithdraw
// / retry / recovery call site.
//
// Labels:
//   - operation: "announce" | "withdraw"
//   - result:    "success" | "failed" | "idempotent"
//     ("idempotent" = vtysh returned a "route-absent" error on
//     withdraw that xSight treats as success; tracked separately
//     so operators can see how often FRR drift is absorbed).
var VtyshOps = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xsight_vtysh_ops_total",
		Help: "Total vtysh operations by operation and result.",
	},
	[]string{"operation", "result"},
)

// ActionExecutions counts action engine dispatch outcomes.
//
// Labels:
//   - action_type: "bgp" | "xdrop" | "webhook" | "shell" | "xdrop_api" | "manual_override"
//     or other unknown action_type values on the skip path
//   - status:      "success" | "failed" | "timeout" | "skipped" | "scheduled"
//     "scheduled" = action was queued for delayed execution
//     (not yet run). "success" is fired when the delayed action
//     completes. Operator can rate-monitor any dimension.
var ActionExecutions = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xsight_action_executions_total",
		Help: "Total action engine dispatches by action type and outcome status.",
	},
	[]string{"action_type", "status"},
)

// ActionSkip breaks out action_executions_total{status="skipped"} by the
// specific skip_reason. Lets operators alert on precondition_not_matched
// spikes, decoder_not_xdrop_compatible surges (misconfiguration signal),
// or first_match_suppressed rates without having to pull log rows.
//
// Labels:
//   - skip_reason: one of SkipReason* enum values in action.engine.go
//
// Values: precondition_not_matched, first_match_suppressed, mode_observe,
// manual_override, already_executed, decoder_not_xdrop_compatible,
// xdrop_anomaly_requires_drop (historical), global_no_target, deprecated_xdrop_api,
// unknown_action_type, no_connector, connector_disabled, unknown_trigger_phase,
// stale_generation, incomplete_config, connector_lookup_failed, no_rules_to_unblock,
// outbound_block_forbidden.
// Cardinality: bounded by the enum (currently 18 values).
var ActionSkip = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xsight_action_skip_total",
		Help: "Total actions skipped by dispatch gate, broken down by skip_reason.",
	},
	[]string{"skip_reason"},
)

// PreconditionLookupErrors counts structured lookup errors that fall back to legacy fields.
var PreconditionLookupErrors = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "xsight_action_precondition_lookup_errors_total",
	Help: "Structured precondition lookup errors; evaluation falls back to the legacy preconditions field.",
})

// ActionQueueEvents exposes producer backpressure and bounded drain failures.
var ActionQueueEvents = prometheus.NewCounterVec(
	prometheus.CounterOpts{Name: "xsight_action_queue_total", Help: "Action queue backpressure and drain timeouts."},
	[]string{"outcome"}, // full | drain_timeout
)

// ScheduledActionsRecovered counts outcomes of the startup reconciliation
// for persisted scheduled_actions rows. A non-zero rate of
// outcome="overdue_fired" after restart is the expected tail of the v1.2
// persistence model (delayed tasks whose schedule time passed during
// downtime). "executing_retried" counts rows stuck in the executing state
// from a crash between MarkExecuting and Complete/Fail — should stay at 0
// in steady state; a non-zero reading is an incident signal.
//
// Labels:
//   - outcome: "armed" | "overdue_fired" | "executing_retried"
var ScheduledActionsRecovered = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xsight_scheduled_actions_recovered_total",
		Help: "Total scheduled_actions rows processed by startup recovery, by outcome.",
	},
	[]string{"outcome"},
)

// RecordVtysh is a small helper so the action package doesn't need to
// import the prometheus namespace directly.
func RecordVtysh(operation, result string) {
	VtyshOps.WithLabelValues(operation, result).Inc()
}

// RecordAction increments the action-execution counter. Mirrors the status
// strings already written to action_execution_log.
func RecordAction(actionType, status string) {
	ActionExecutions.WithLabelValues(actionType, status).Inc()
}

// RecordSkip increments xsight_action_skip_total for the given skip_reason.
// Called from writeSkipLog and recordSkip in the action package once per
// skipped log attempt, including attempts where Create fails.
func RecordSkip(skipReason string) {
	ActionSkip.WithLabelValues(skipReason).Inc()
}

// RecordRecovered increments xsight_scheduled_actions_recovered_total.
// Called from ReconcileOnStartup paths when a scheduled row transitions
// under recovery.
func RecordRecovered(outcome string) {
	ScheduledActionsRecovered.WithLabelValues(outcome).Inc()
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer A — custom collectors (fresh-at-scrape gauges)
// ─────────────────────────────────────────────────────────────────────────────

// statusCountFunc queries a state table for (status → count) pairs. Each
// v1.2 state repo implements this via a CountByStatus method.
type statusCountFunc func(ctx context.Context) (map[string]int, error)

// statusGaugeCollector is a Prometheus collector that emits one gauge per
// status value returned by the count function, as of scrape time.
//
// Why not a GaugeVec with background refresh: the background approach
// leaves a staleness window (up to refresh interval) and requires reasoning
// about reset semantics when a status disappears. Scrape-time collection
// is always fresh and the "status disappeared" case is handled naturally
// (we simply don't emit that labelset).
type statusGaugeCollector struct {
	desc    *prometheus.Desc
	countFn statusCountFunc
}

func newStatusGaugeCollector(name, help string, fn statusCountFunc) *statusGaugeCollector {
	return &statusGaugeCollector{
		desc:    prometheus.NewDesc(name, help, []string{"status"}, nil),
		countFn: fn,
	}
}

func (c *statusGaugeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *statusGaugeCollector) Collect(ch chan<- prometheus.Metric) {
	// Bound every scrape to 5s so a slow DB can't pile up scrape goroutines.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	counts, err := c.countFn(ctx)
	if err != nil {
		// Swallow — metrics endpoint must never return 500. Operators will
		// see that the expected timeseries went blank in Prometheus, which
		// is the standard signal for "collector error".
		return
	}
	for status, count := range counts {
		ch <- prometheus.MustNewConstMetric(
			c.desc, prometheus.GaugeValue, float64(count), status,
		)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Layer B — attack tracker wrappers
// ─────────────────────────────────────────────────────────────────────────────

// trackerCollector emits the four attack-tracker counters as Prometheus
// metrics. The tracker already maintains atomic Int64 counters that
// /api/stats/summary consumes — we just expose them in Prometheus format.
type trackerCollector struct {
	tracker *tracker.Tracker

	activeDesc     *prometheus.Desc
	createdDesc    *prometheus.Desc
	suppressedDesc *prometheus.Desc
	evictedDesc    *prometheus.Desc
}

func newTrackerCollector(t *tracker.Tracker) *trackerCollector {
	return &trackerCollector{
		tracker: t,
		activeDesc: prometheus.NewDesc(
			"xsight_attacks_active",
			"Current active attacks tracked in memory.",
			nil, nil,
		),
		createdDesc: prometheus.NewDesc(
			"xsight_attacks_created_total",
			"Lifetime count of attacks created.",
			nil, nil,
		),
		suppressedDesc: prometheus.NewDesc(
			"xsight_attacks_suppressed_total",
			"Lifetime count of attacks suppressed by dedup.",
			nil, nil,
		),
		evictedDesc: prometheus.NewDesc(
			"xsight_attacks_evicted_total",
			"Lifetime count of attacks evicted due to tracker capacity. "+
				"Non-zero indicates capacity limit reached — increase cap or investigate.",
			nil, nil,
		),
	}
}

func (c *trackerCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.activeDesc
	ch <- c.createdDesc
	ch <- c.suppressedDesc
	ch <- c.evictedDesc
}

func (c *trackerCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(c.activeDesc, prometheus.GaugeValue,
		float64(c.tracker.ActiveCount()))
	ch <- prometheus.MustNewConstMetric(c.createdDesc, prometheus.CounterValue,
		float64(c.tracker.CreatedTotal.Load()))
	ch <- prometheus.MustNewConstMetric(c.suppressedDesc, prometheus.CounterValue,
		float64(c.tracker.SuppressedTotal.Load()))
	ch <- prometheus.MustNewConstMetric(c.evictedDesc, prometheus.CounterValue,
		float64(c.tracker.EvictedTotal.Load()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────────────

// Register wires every xSight metric into the given registry. Call once at
// startup. The default Prometheus registry (used by promhttp.Handler()) is
// the typical choice; tests pass a fresh registry to isolate state.
//
// The Go runtime collector is already auto-registered in the default
// registry, so callers using promhttp.Handler() get it for free.
func Register(reg prometheus.Registerer, s store.Store, t *tracker.Tracker) error {
	for _, stage := range []string{"rebuild", "publish"} {
		ConfigPublishFailures.WithLabelValues(stage)
	}
	if err := reg.Register(ConfigPublishFailures); err != nil {
		return err
	}
	for _, outcome := range []string{"claimed", "claim_lost", "claim_error", "list_error", "busy", "failed_claimed", "failed_busy", "failed_claim_lost", "failed_claim_error", "failed_list_error"} {
		BGPWithdrawingReconcile.WithLabelValues(outcome)
	}
	if err := reg.Register(BGPWithdrawingReconcile); err != nil {
		return err
	}
	for _, outcome := range []string{"list_error", "lookup_error", "skipped_disabled", "probe_error", "absent", "config_only", "announced", "stale", "state_write_error"} {
		BGPAnnouncingReconcile.WithLabelValues(outcome)
	}
	if err := reg.Register(BGPAnnouncingReconcile); err != nil {
		return err
	}
	for _, op := range []string{"announced", "withdrawn", "failed_announce", "failed_withdraw", "schedule"} {
		BGPStaleWrites.WithLabelValues(op)
	}
	if err := reg.Register(BGPStaleWrites); err != nil {
		return err
	}
	for kind, outcomes := range map[string][]string{
		"bgp":   {"dispatched", "detached_kept", "skipped_status", "skipped_connector", "failed"},
		"xdrop": {"dispatched", "skipped_connector", "skipped_override", "skipped_scheduled", "skipped_claimed", "failed"},
	} {
		for _, outcome := range outcomes {
			EndedSweep.WithLabelValues(kind, outcome)
		}
	}
	if err := reg.Register(EndedSweep); err != nil {
		return err
	}
	for _, collector := range []prometheus.Collector{GRPCIdentityRejects, RingEstimatedMemoryBytes} {
		if err := reg.Register(collector); err != nil {
			return err
		}
	}
	for _, outcome := range []string{"candidate", "busy", "backoff", "skipped_live", "skipped_scheduled", "skipped_connector", "skipped_override", "skipped_synthetic", "list_error", "claimed", "withdrawn", "failed", "state_write_error", "synthetic_unrecoverable", "synthetic_identity_not_found", "late_create_leak"} {
		XDropReconcile.WithLabelValues(outcome)
	}
	if err := reg.Register(XDropReconcile); err != nil {
		return err
	}
	t.StateWriteFailure = func(op string) { StateWriteFailures.WithLabelValues(op).Inc() }
	for _, op := range []string{"attack_create", "attack_update_expired", "attack_update_evicted", "bgp_ann_state", "sched_mark_executing", "force_remove_override", "force_remove_mark_withdrawn", "xdrop_mark_withdrawn", "xdrop_mark_failed", "xdrop_schedule_finish", "xdrop_exec_log", "xdrop_claim"} {
		StateWriteFailures.WithLabelValues(op)
	}
	if err := reg.Register(StateWriteFailures); err != nil {
		return err
	}
	// Inline counters
	for kind, outcomes := range map[string][]string{
		"bgp":   {"dispatched", "detached_kept", "recounted_up", "skipped_inconsistent", "skipped_scheduled", "skipped_connector", "failed"},
		"xdrop": {"dispatched", "skipped_scheduled", "skipped_claimed", "failed"},
	} {
		for _, outcome := range outcomes {
			StartupCleanup.WithLabelValues(kind, outcome)
		}
	}
	if err := reg.Register(StartupCleanup); err != nil {
		return err
	}
	if err := reg.Register(ActionQueueEvents); err != nil {
		return err
	}
	if err := reg.Register(VtyshOps); err != nil {
		return err
	}
	if err := reg.Register(ActionExecutions); err != nil {
		return err
	}
	if err := reg.Register(PreconditionLookupErrors); err != nil {
		return err
	}
	if err := reg.Register(ActionSkip); err != nil {
		return err
	}
	if err := reg.Register(ScheduledActionsRecovered); err != nil {
		return err
	}
	// State-table gauges (one query per scrape per collector)
	if err := reg.Register(newStatusGaugeCollector(
		"xsight_bgp_announcements",
		"Current BGP announcements by lifecycle status.",
		s.BGPAnnouncements().CountByStatus,
	)); err != nil {
		return err
	}
	if err := reg.Register(newStatusGaugeCollector(
		"xsight_xdrop_rules",
		"Current xDrop filter rules by lifecycle status.",
		s.XDropActiveRules().CountByStatus,
	)); err != nil {
		return err
	}
	if err := reg.Register(newStatusGaugeCollector(
		"xsight_scheduled_actions",
		"Current scheduled actions by status.",
		s.ScheduledActions().CountByStatus,
	)); err != nil {
		return err
	}
	// Attack tracker
	if err := reg.Register(newTrackerCollector(t)); err != nil {
		return err
	}
	return nil
}
