package action

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// addressFamilyForPrefix returns the FRR address-family string based on the prefix's IP version.
// Uses net.ParseCIDR / net.ParseIP for robust detection — not string heuristics.
func addressFamilyForPrefix(prefix string) string {
	if isIPv6(prefix) {
		return "ipv6 unicast"
	}
	return "ipv4 unicast"
}

// isFRRRouteAbsentError returns true if vtysh stderr indicates "there's
// nothing here to remove" — a withdraw against a route that's already gone.
// xSight treats this as idempotent success.
//
// We intentionally match ONLY specific, verified phrases observed in the wild
// for this exact case. Broader patterns like "No such" or "does not exist"
// would also catch legitimate FRR config errors (e.g., `No such route-map
// entry` from a typo in route-map name, or `address-family ... does not
// exist`) and mask them as success — leaving announcements falsely marked
// withdrawn while FRR still holds the route. Per PR-7 audit P1.
//
// Known idempotent phrases:
//   - "Can't find static route"
//     Classic: `no network X route-map Y` when that exact network never
//     existed.
//   - "route-map name doesn't match static route"
//     Surfaces when `network X route-map Y` was rejected during origination
//     (e.g., two different route-maps for the same prefix — BGP keeps only
//     one) and xSight later tries to withdraw the rejected one. See L14.
//
// If other genuinely-idempotent FRR phrasings are observed, add them here
// with a concrete case; do not re-broaden to generic "not found" wording.
func isFRRRouteAbsentError(output string) bool {
	if output == "" {
		return false
	}
	for _, pat := range []string{
		"Can't find static route",
		"route-map name doesn't match static route",
	} {
		if strings.Contains(output, pat) {
			return true
		}
	}
	return false
}

// isIPv6 determines whether a prefix or IP string is IPv6.
// Handles both CIDR ("2001:db8::/32") and plain IP ("2001:db8::1") forms.
func isIPv6(s string) bool {
	if _, cidr, err := net.ParseCIDR(s); err == nil {
		return cidr.IP.To4() == nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() == nil
	}
	return false
}

// splitExternalRuleID splits "{prefix}|{route_map}" into (prefix, routeMap).
// Uses "|" as separator to avoid collision with ":" in IPv6 addresses.
// Falls back to ":" for backward compatibility with pre-v1.1.1 records.
func splitExternalRuleID(ruleID string) []string {
	if idx := strings.LastIndex(ruleID, "|"); idx >= 0 {
		return []string{ruleID[:idx], ruleID[idx+1:]}
	}
	// Backward compat: old records used ":" separator.
	// Use LastIndex to handle IPv6 addresses like "2001:db8::1/128:RTBH".
	if idx := strings.LastIndex(ruleID, ":"); idx >= 0 {
		return []string{ruleID[:idx], ruleID[idx+1:]}
	}
	return []string{ruleID}
}

// executeBGP runs a vtysh command to inject or withdraw a BGP route.
// on_detected: Attach to announcement; run vtysh network if refcount→1
// on_expired:  Detach from announcement; run vtysh no network if refcount→0 and delay=0
//
// The `engine` parameter is required for the delayed-withdraw path (PR-5
// arms timers via engine.ScheduleDelay with announcement_id). Can be nil
// when called from recovery/tests that drive timers externally.
func executeBGP(ctx context.Context, s store.Store, engine *Engine, act store.ResponseAction,
	attack *store.Attack, eventType, prefixStr, responseName, triggerPhase string,
	attackDBID int, fa func() *FlowAnalysis) (*store.ActionExecutionLog, error) {

	conn, err := s.BGPConnectors().Get(ctx, *act.BGPConnectorID)
	if err != nil {
		return &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     act.ID,
			ActionType:   "bgp",
			TriggerPhase: triggerPhase,
			ResponseName: responseName,
			Status:       "failed",
			ConnectorID:  act.BGPConnectorID,
			ErrorMessage: fmt.Sprintf("bgp connector %d not found: %v", *act.BGPConnectorID, err),
			ExecutedAt:   time.Now(),
		}, err
	}

	if !conn.Enabled {
		return recordSkip(&store.ActionExecutionLog{
			AttackID:      attackDBID,
			ActionID:      act.ID,
			ActionType:    "bgp",
			TriggerPhase:  triggerPhase,
			ResponseName:  responseName,
			ConnectorName: conn.Name,
			Status:        "skipped",
			ErrorMessage:  "bgp connector disabled",
			ExecutedAt:    time.Now(),
		}, SkipReasonConnectorDisabled), nil
	}

	// Determine the target prefix/IP to announce or withdraw
	dstIP := attack.DstIP
	// Ensure mask suffix for plain IPs (internal_ip domain): /32 for IPv4, /128 for IPv6
	if !strings.Contains(dstIP, "/") {
		if isIPv6(dstIP) {
			dstIP = dstIP + "/128"
		} else {
			dstIP = dstIP + "/32"
		}
	}

	if conn.FlowspecEnabled {
		return executeBGPFlowspec(ctx, s, conn, act, attack, dstIP, attackDBID, responseName, triggerPhase)
	}

	// RTBH below injects routes into a local FRR through vtysh. Any other
	// vendor is export-only (see executeBGPFlowspec), so refuse instead of
	// pushing FRR syntax at a Cisco/Juniper/Arista box.
	if vendor, vErr := flowspec.ParseVendor(conn.Vendor); vErr != nil || vendor != flowspec.VendorFRR {
		return recordSkip(&store.ActionExecutionLog{
			AttackID:      attackDBID,
			ActionID:      act.ID,
			ActionType:    "bgp",
			TriggerPhase:  triggerPhase,
			ResponseName:  responseName,
			ConnectorName: conn.Name,
			Status:        "skipped",
			ErrorMessage:  fmt.Sprintf("vendor %q is export-only for RTBH; enable flowspec_enabled on this connector", conn.Vendor),
			ExecutedAt:    time.Now(),
		}, SkipReasonVendorExportOnly), nil
	}

	switch triggerPhase {
	case "on_detected":
		return bgpAnnounce(ctx, s, engine, conn, act, dstIP, attackDBID, responseName, triggerPhase)
	case "on_expired":
		return bgpWithdraw(ctx, s, engine, conn, act, dstIP, attackDBID, responseName, triggerPhase)
	default:
		return recordSkip(&store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     act.ID,
			ActionType:   "bgp",
			TriggerPhase: triggerPhase,
			ResponseName: responseName,
			Status:       "skipped",
			ErrorMessage: fmt.Sprintf("unknown trigger_phase: %s", triggerPhase),
			ExecutedAt:   time.Now(),
		}, SkipReasonUnknownTriggerPhase), nil
	}
}

// bgpAnnounce attaches this attack to an announcement (creating one if
// necessary) and invokes vtysh network only when the refcount-based manager
// tells us this is a new announcement.
//
// v1.2 PR-5: replaces per-attack vtysh announce. Multiple attacks sharing
// the same (prefix, route_map, connector) will all attach to a single
// announcement — only the first attack triggers vtysh, subsequent attaches
// just bump the refcount.
//
// `engine` is used to cancel any in-memory delay timer if this attach
// resurrected a delayed announcement. Can be nil in tests / recovery paths
// that don't care about the timer.
func bgpAnnounce(ctx context.Context, s store.Store, engine *Engine, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	routeMap := act.BGPRouteMap
	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	actID := act.ID
	connID := conn.ID

	if overridden, err := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID); err != nil {
		log.Printf("action: bgp announce override lookup: %v", err)
	} else if overridden {
		logCtx, cancel := execLogContext()
		writeSkipLog(logCtx, s, attackDBID, act, responseName, conn.Name, SkipReasonManualOverride, "")
		cancel()
		return nil, nil
	}

	// Look up the attack's per-action bgp_withdraw_delay — this attack's
	// contribution to the announcement's effective delay. The announcement's
	// final delay is MAX across all attached attacks.
	delayMinutes := act.BGPWithdrawDelayMinutes

	attachResult, err := s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID:     attackDBID,
		ActionID:     &actID,
		ResponseName: responseName,
		DelayMinutes: delayMinutes,
		Prefix:       dstIP,
		RouteMap:     routeMap,
		ConnectorID:  connID,
	})
	if err != nil {
		log.Printf("action: bgp attach failed attack=%d prefix=%s: %v", attackDBID, dstIP, err)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("attach: %v", err),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, err
	}

	if !attachResult.NeedAnnounce {
		// Shared attach (refcount++ on existing active announcement) OR
		// delay-cancelling attach (refcount 0→1 resurrecting a delayed
		// announcement). In either case, no vtysh needed. If the announcement
		// was in delayed state, the Attach already transitioned status back
		// to active in DB — but we ALSO need to cancel the in-memory timer
		// goroutine so it doesn't fire withdrawal. Idempotent: if no timer is
		// armed the map lookup is a miss and CancelAnnouncementDelay no-ops.
		if engine != nil {
			engine.CancelAnnouncementDelay(attachResult.AnnouncementID, attachResult.Gen, "rebreach: attack attached during delay")
		}
		log.Printf("action: bgp attach shared prefix=%s announcement_id=%d attack=%d",
			dstIP, attachResult.AnnouncementID, attackDBID)
		detail := fmt.Sprintf("attached to announcement_id=%d (shared)", attachResult.AnnouncementID)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         detail,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// First attach — execute vtysh network.
	af := addressFamilyForPrefix(dstIP)
	var cmd, out string
	t0 := time.Now()
	vErr := vtyshTokens(dstIP, routeMap)
	if vErr == nil {
		cmd = fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nnetwork %s route-map %s",
			conn.BGPASN, af, dstIP, routeMap)
		out, vErr = runVtysh(ctx, conn.VtyshPath, cmd)
	}
	durationMs := int(time.Since(t0).Milliseconds())

	if vErr != nil {
		metrics.RecordVtysh("announce", "failed")
		log.Printf("action: bgp announce failed announcement_id=%d: %v output=%s",
			attachResult.AnnouncementID, vErr, out)
		detail := ""
		errorMessage := fmt.Sprintf("vtysh: %v", vErr)
		var exitErr *exec.ExitError
		if cmd != "" && ctx.Err() != nil {
			log.Printf("WARN bgp announce outcome unknown (ctx ended) announcement_id=%d prefix=%s route_map=%s; leaving announcing for reconcile",
				attachResult.AnnouncementID, dstIP, routeMap)
			errorMessage += "; outcome unknown (ctx ended)"
		} else if cmd != "" && errors.As(vErr, &exitErr) && !exitErr.Exited() {
			log.Printf("WARN bgp announce outcome unknown (killed by signal) announcement_id=%d prefix=%s route_map=%s; leaving announcing for reconcile",
				attachResult.AnnouncementID, dstIP, routeMap)
			errorMessage += "; outcome unknown (killed by signal)"
		} else {
			// Definite failures compensate within the original generation.
			cErr := retryBGPStateWrite(func(writeCtx context.Context) error {
				return s.BGPAnnouncements().MarkFailedAnnounce(writeCtx, attachResult.AnnouncementID, attachResult.Gen, vErr.Error())
			})
			if bgpStateNotApplied(cErr, attachResult.AnnouncementID, attachResult.Gen, "failed_announce") {
				detail = bgpNotAppliedDetail
			} else if cErr != nil {
				metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
				log.Printf("ERROR action: bgp compensate announce failure announcement_id=%d: %v",
					attachResult.AnnouncementID, cErr)
			}
		}
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   errorMessage,
			Detail:         detail,
			RequestBody:    cmd,
			ResponseBody:   out,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, vErr
	}

	metrics.RecordVtysh("announce", "success")
	detail := fmt.Sprintf("triggered announcement_id=%d", attachResult.AnnouncementID)
	if mErr := s.BGPAnnouncements().MarkAnnounced(ctx, attachResult.AnnouncementID, attachResult.Gen); bgpStateNotApplied(mErr, attachResult.AnnouncementID, attachResult.Gen, "announced") {
		detail += "; " + bgpNotAppliedDetail
	} else if mErr != nil {
		log.Printf("action: bgp MarkAnnounced announcement_id=%d: %v", attachResult.AnnouncementID, mErr)
	}
	log.Printf("action: bgp announce %s route-map=%s connector=%s announcement_id=%d",
		dstIP, routeMap, conn.Name, attachResult.AnnouncementID)
	return &store.ActionExecutionLog{
		AttackID:       attackDBID,
		ActionID:       act.ID,
		ActionType:     "bgp",
		TriggerPhase:   triggerPhase,
		ResponseName:   responseName,
		ConnectorName:  conn.Name,
		ConnectorID:    &connID,
		Status:         "success",
		Detail:         detail,
		RequestBody:    cmd,
		ResponseBody:   out,
		ExternalRuleID: externalRuleID,
		DurationMs:     durationMs,
		ExecutedAt:     t0,
	}, nil
}

// bgpWithdraw detaches this attack from the announcement. Depending on
// refcount/delay the manager tells us whether to run vtysh immediately,
// arm a delay timer, or do nothing (shared detach).
//
// v1.2 PR-5: replaces per-attack vtysh withdraw. When multiple attacks
// share an announcement, only the LAST detach triggers vtysh. Eliminates
// the withdraw race that plagued v1.1.x.
//
// `engine` must be non-nil when the delayed-withdraw path can trigger (i.e.
// when any attached attack carries a non-zero bgp_withdraw_delay). Recovery
// paths that already hold the timer state can pass nil.
func bgpWithdraw(ctx context.Context, s store.Store, engine *Engine, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	routeMap := act.BGPRouteMap
	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	connID := conn.ID
	actID := act.ID

	// Per-artifact manual_override: if operator already force-removed this
	// attack's artifact, emit a skip log and return. Detach is idempotent
	// anyway, but an explicit skip log keeps the audit trail clean.
	overridden, err := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID)
	if err != nil {
		log.Printf("action: bgp withdraw override lookup: %v", err)
	}
	if overridden {
		log.Printf("action: bgp withdraw skipping %s (manual override, attack=%d)", externalRuleID, attackDBID)
		return recordSkip(&store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "skipped",
			SkipReason:     SkipReasonManualOverride,
			ErrorMessage:   "force-removed by operator",
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, SkipReasonManualOverride), nil
	}

	result, err := s.BGPAnnouncements().Detach(ctx, attackDBID, dstIP, routeMap, connID)
	if err != nil {
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("detach: %v", err),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, err
	}

	if result.AnnouncementID == 0 {
		// No announcement found — attack never attached. Idempotent success.
		log.Printf("action: bgp detach no-op (no announcement) attack=%d prefix=%s", attackDBID, dstIP)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         "no announcement to detach (idempotent)",
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// Shared detach: refcount > 0 after decrement, nothing to do.
	if !result.NeedWithdraw && !result.Delayed {
		log.Printf("action: bgp detach shared announcement_id=%d refcount=%d attack=%d",
			result.AnnouncementID, result.RefcountAfter, attackDBID)
		detail := fmt.Sprintf("detached from announcement_id=%d (refcount=%d, kept active)",
			result.AnnouncementID, result.RefcountAfter)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         detail,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// Delayed path: the announcement is already in 'delayed' status.
	// Arm a persistent delay timer keyed on announcement_id. When the timer
	// fires (or is cancelled by re-breach), perform or skip the withdraw.
	if result.Delayed {
		delay := time.Duration(result.DelayMinutes) * time.Minute
		scheduledFor := time.Now().Add(delay)
		annID := result.AnnouncementID

		if engine == nil {
			// No engine reference — recovery path manages its own timer.
			// Just return the scheduled log.
			detail := fmt.Sprintf("delayed withdraw in %dm (announcement_id=%d, timer externally managed)",
				result.DelayMinutes, annID)
			return &store.ActionExecutionLog{
				AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
				TriggerPhase: triggerPhase, ResponseName: responseName,
				ConnectorName: conn.Name, ConnectorID: &connID,
				Status:         "scheduled",
				Detail:         detail,
				ScheduledFor:   &scheduledFor,
				ExternalRuleID: externalRuleID,
				ExecutedAt:     time.Now(),
			}, nil
		}

		schedID, cancelCtx, perr := engine.ScheduleDelayForAnnouncement(ctx, annID, result.Gen, scheduledFor)
		if bgpStateNotApplied(perr, annID, result.Gen, "schedule") {
			return recordSkip(&store.ActionExecutionLog{AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp", TriggerPhase: triggerPhase,
				ResponseName: responseName, ConnectorName: conn.Name, ConnectorID: &connID, ExternalRuleID: externalRuleID,
				Status: "skipped", Detail: "superseded by newer announcement generation", ExecutedAt: time.Now()}, SkipReasonStaleGeneration), nil
		}
		if perr != nil {
			log.Printf("action: bgp ScheduleDelay persist failed announcement_id=%d: %v", annID, perr)
			// Compensate: mark announcement failed so it doesn't linger in delayed forever.
			detail := ""
			if err := retryBGPStateWrite(func(writeCtx context.Context) error {
				return s.BGPAnnouncements().MarkFailedWithdraw(writeCtx, annID, result.Gen, fmt.Sprintf("schedule persist failed: %v", perr))
			}); bgpStateNotApplied(err, annID, result.Gen, "failed_withdraw") {
				detail = bgpNotAppliedDetail
			} else if err != nil {
				metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
				log.Printf("ERROR action: bgp MarkFailedWithdraw announcement_id=%d: %v", annID, err)
			}
			return &store.ActionExecutionLog{
				AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
				TriggerPhase: triggerPhase, ResponseName: responseName,
				ConnectorName: conn.Name, ConnectorID: &connID,
				Status:         "failed",
				ErrorMessage:   fmt.Sprintf("schedule persist failed: %v", perr),
				Detail:         detail,
				ExternalRuleID: externalRuleID,
				ExecutedAt:     time.Now(),
			}, perr
		}

		// Goroutine waits for timer or cancellation.
		go bgpDelayedWithdrawWorker(s, engine, conn, act, dstIP, routeMap, attackDBID,
			annID, schedID, result.Gen, cancelCtx, delay, responseName)

		detail := fmt.Sprintf("delayed withdraw in %dm (announcement_id=%d, scheduled_id=%d)",
			result.DelayMinutes, annID, schedID)
		return &store.ActionExecutionLog{
			AttackID: attackDBID, ActionID: act.ID, ActionType: "bgp",
			TriggerPhase: triggerPhase, ResponseName: responseName,
			ConnectorName: conn.Name, ConnectorID: &connID,
			Status:         "scheduled",
			Detail:         detail,
			ErrorMessage:   fmt.Sprintf("delayed withdraw in %dm", result.DelayMinutes),
			ScheduledFor:   &scheduledFor,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	// Immediate withdraw: refcount=0, delay=0. Detach already transitioned
	// the announcement to 'withdrawing'. Run vtysh now and finalize.
	return performBGPWithdraw(ctx, s, conn, act, dstIP, routeMap, attackDBID, result.AnnouncementID, result.Gen, responseName, triggerPhase)
}

// bgpDelayedWithdrawWorker is the goroutine body that waits for the delay
// timer, then executes the actual BGP withdraw — or bails cleanly if the
// announcement was cancelled (re-breach, force-remove, or explicit cancel).
//
// v1.2 PR-5: all lifecycle bookkeeping (MarkExecuting, MarkWithdrawing,
// MarkWithdrawn, MarkFailedWithdraw, CompleteDelay, FailDelay) flows through
// the Engine so recovery can pick up from any interruption.
func bgpDelayedWithdrawWorker(s store.Store, engine *Engine, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, attackDBID, announcementID, schedID int, gen int,
	cancelCtx context.Context, delay time.Duration, responseName string) {

	log.Printf("action: bgp delayed withdraw scheduled in %v announcement_id=%d scheduled_id=%d",
		delay, announcementID, schedID)

	select {
	case <-time.After(delay):
		// Race guard — only one goroutine may execute this task.
		execCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if !engine.MarkExecutingDelay(execCtx, schedID) {
			log.Printf("action: bgp delayed withdraw skipped scheduled_id=%d (no longer pending)", schedID)
			return
		}

		// Claim this generation's delayed announcement before vtysh.
		// Returns false if concurrent attach cancelled (refcount now > 0).
		ok, mErr := s.BGPAnnouncements().MarkWithdrawing(execCtx, announcementID, gen)
		if mErr != nil {
			log.Printf("action: bgp delayed MarkWithdrawing announcement_id=%d: %v", announcementID, mErr)
			engine.FailDelayForAnnouncement(execCtx, schedID, announcementID, mErr.Error())
			return
		}
		if !ok {
			// Announcement is no longer in active/delayed — likely re-breached
			// and back to active with refcount > 0. Don't withdraw.
			log.Printf("action: bgp delayed withdraw bailing announcement_id=%d (no longer in delayed/active — likely re-breached)", announcementID)
			engine.CompleteDelayForAnnouncement(execCtx, schedID, announcementID)
			return
		}

		// Run the actual vtysh withdraw and finalize.
		execLog, wErr := performBGPWithdraw(execCtx, s, conn, act, dstIP, routeMap, attackDBID, announcementID, gen, responseName, "on_expired")
		if wErr != nil {
			engine.FailDelayForAnnouncement(execCtx, schedID, announcementID, wErr.Error())
		} else {
			engine.CompleteDelayForAnnouncement(execCtx, schedID, announcementID)
		}
		if execLog != nil {
			if _, err := writeExecLog(s, execLog); err != nil {
				log.Printf("action: create delayed bgp withdraw log: %v", err)
			}
		}

	case <-cancelCtx.Done():
		log.Printf("action: bgp delayed withdraw cancelled announcement_id=%d scheduled_id=%d", announcementID, schedID)
		// Cancel context was triggered by CancelAnnouncementDelay (re-breach)
		// or by ScheduleDelayForAnnouncement (reschedule). The caller already
		// manages the pendingDelay map entry — do NOT delete here, because a
		// reschedule may have already stored a new cancel func under the same
		// key, and deleting it would orphan the replacement timer.
	}
}

// PerformBGPWithdrawForOrphan is the exported wrapper over performBGPWithdraw
// used by the API layer's orphanForceWithdraw handler. Writes a
// manual_override audit log (not a normal on_expired) since there's no
// attack attached.
func PerformBGPWithdrawForOrphan(ctx context.Context, s store.Store, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, announcementID int, gen int) (*store.ActionExecutionLog, error) {
	return performBGPWithdraw(ctx, s, conn, act, dstIP, routeMap,
		0 /* no attack */, announcementID, gen, "" /* no response name */, "manual_override")
}

const bgpNotAppliedDetail = "state write not applied (newer generation or already final)"

func bgpStateNotApplied(err error, id, gen int, op string) bool {
	if !errors.Is(err, store.ErrStaleAnnouncement) {
		return false
	}
	log.Printf("INFO bgp state write not applied announcement_id=%d gen=%d op=%s", id, gen, op)
	metrics.BGPStaleWrites.WithLabelValues(op).Inc()
	return true
}

func retryBGPStateWrite(write func(context.Context) error) (err error) {
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
		err = write(ctx)
		cancel()
		if err == nil || errors.Is(err, store.ErrStaleAnnouncement) {
			return err
		}
	}
	return err
}

// performBGPWithdraw runs the actual vtysh no network command for a
// withdrawing-state announcement and transitions to withdrawn/failed.
// Called from bgpWithdraw's immediate branch and from the delayed goroutine.
func performBGPWithdraw(ctx context.Context, s store.Store, conn *store.BGPConnector,
	act store.ResponseAction, dstIP, routeMap string, attackDBID, announcementID int, gen int,
	responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	stateError := ""
	stateDetail := fmt.Sprintf("announcement_id=%d", announcementID)
	recordStateError := func(err error, op string) {
		if bgpStateNotApplied(err, announcementID, gen, op) {
			stateDetail += "; " + bgpNotAppliedDetail
			return
		}
		metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
		log.Printf("ERROR action: bgp state write announcement_id=%d: %v", announcementID, err)
		stateError = fmt.Sprintf("; state write failed: %v", err)
	}
	externalRuleID := fmt.Sprintf("%s|%s", dstIP, routeMap)
	connID := conn.ID

	waf := addressFamilyForPrefix(dstIP)
	var cmd, out string
	t0 := time.Now()
	vErr := vtyshTokens(dstIP, routeMap)
	if vErr == nil {
		cmd = fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nno network %s route-map %s",
			conn.BGPASN, waf, dstIP, routeMap)
		out, vErr = runVtysh(ctx, conn.VtyshPath, cmd)
	}
	durationMs := int(time.Since(t0).Milliseconds())

	if vErr != nil {
		outStr := strings.TrimSpace(out)
		if isFRRRouteAbsentError(outStr) {
			// Idempotent success — route already gone.
			metrics.RecordVtysh("withdraw", "idempotent")
			log.Printf("action: bgp withdraw %s already gone (idempotent, announcement_id=%d)", externalRuleID, announcementID)
			if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
				return s.BGPAnnouncements().MarkWithdrawn(writeCtx, announcementID, gen)
			}); mErr != nil {
				recordStateError(mErr, "withdrawn")
			}
			return &store.ActionExecutionLog{
				AttackID:       attackDBID,
				ActionID:       act.ID,
				ActionType:     "bgp",
				TriggerPhase:   triggerPhase,
				ResponseName:   responseName,
				ConnectorName:  conn.Name,
				ConnectorID:    &connID,
				Status:         "success",
				ErrorMessage:   "idempotent: route already withdrawn" + stateError,
				Detail:         stateDetail,
				RequestBody:    cmd,
				ResponseBody:   out,
				ExternalRuleID: externalRuleID,
				DurationMs:     durationMs,
				ExecutedAt:     t0,
			}, nil
		}
		// Real failure.
		metrics.RecordVtysh("withdraw", "failed")
		if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
			return s.BGPAnnouncements().MarkFailedWithdraw(writeCtx, announcementID, gen, vErr.Error())
		}); mErr != nil {
			recordStateError(mErr, "failed_withdraw")
		}
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("%v (%s)", vErr, outStr) + stateError,
			Detail:         stateDetail,
			RequestBody:    cmd,
			ResponseBody:   out,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, vErr
	}

	// Success.
	metrics.RecordVtysh("withdraw", "success")
	log.Printf("action: bgp withdraw %s route-map=%s connector=%s announcement_id=%d", dstIP, routeMap, conn.Name, announcementID)
	if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
		return s.BGPAnnouncements().MarkWithdrawn(writeCtx, announcementID, gen)
	}); mErr != nil {
		recordStateError(mErr, "withdrawn")
	}
	return &store.ActionExecutionLog{
		AttackID:       attackDBID,
		ActionID:       act.ID,
		ActionType:     "bgp",
		TriggerPhase:   triggerPhase,
		ResponseName:   responseName,
		ConnectorName:  conn.Name,
		ConnectorID:    &connID,
		Status:         "success",
		ErrorMessage:   strings.TrimPrefix(stateError, "; "),
		Detail:         stateDetail,
		RequestBody:    cmd,
		ResponseBody:   out,
		ExternalRuleID: externalRuleID,
		DurationMs:     durationMs,
		ExecutedAt:     t0,
	}, nil
}

// RecoverBGPRoutes restores ephemeral FRR configuration from announcement state.
// It is synchronous and independent of tracker and startup reconciliation.
func RecoverBGPRoutes(ctx context.Context, s store.Store) {
	announcements, err := s.BGPAnnouncements().ListActive(ctx)
	if err != nil {
		log.Printf("bgp recovery: list announcements: %v", err)
		return
	}
	for _, ann := range announcements {
		if ann.Status != "active" && ann.Status != "delayed" {
			continue
		}
		conn, err := s.BGPConnectors().Get(ctx, ann.ConnectorID)
		if err != nil || conn == nil || !conn.Enabled {
			log.Printf("bgp recovery: connector %d unavailable: %v", ann.ConnectorID, err)
			continue
		}
		if err := vtyshTokens(ann.Prefix, ann.RouteMap); err != nil {
			metrics.RecordVtysh("announce", "failed")
			log.Printf("bgp recovery: announcement_id=%d: %v", ann.ID, err)
			continue
		}
		cmd := fmt.Sprintf("configure terminal\nrouter bgp %d\naddress-family %s\nnetwork %s route-map %s",
			conn.BGPASN, addressFamilyForPrefix(ann.Prefix), ann.Prefix, ann.RouteMap)
		if _, err := runVtysh(ctx, conn.VtyshPath, cmd); err != nil {
			metrics.RecordVtysh("announce", "failed")
			log.Printf("bgp recovery: re-inject %s route-map=%s failed: %v", ann.Prefix, ann.RouteMap, err)
		} else {
			metrics.RecordVtysh("announce", "success")
		}
	}
}

var vtyshTimeout = 60 * time.Second
var vtyshWaitDelay = 2 * time.Second
var errVtyshTimeout = errors.New("vtysh timed out")

// runVtysh executes vtysh with the given commands (newline-separated).
func runVtysh(ctx context.Context, vtyshPath, commands string) (string, error) {
	args := []string{}
	for _, line := range strings.Split(commands, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			args = append(args, "-c", line)
		}
	}
	cmdCtx, cancel := context.WithTimeout(ctx, vtyshTimeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, vtyshPath, args...)
	dl, _ := cmdCtx.Deadline()
	budget := time.Until(dl)
	cmd.WaitDelay = budget + vtyshWaitDelay
	out, err := cmd.CombinedOutput()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success() {
		err = nil
	} else if cmdCtx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("%w after %s: %w", errVtyshTimeout, budget, err)
	}
	return strings.TrimSpace(string(out)), err
}
