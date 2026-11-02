package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

const dbOperationTimeout = 5 * time.Second

func overrideKey(actionID, connectorID int, ruleID string) string {
	return fmt.Sprintf("%d:%d:%s", actionID, connectorID, ruleID)
}

// xDropCompatibleDecoders keeps the existing dispatch eligibility table.
// ADR-0004 #8: ip/ip_other have no faithful protocol mapping and remain
// excluded. IPv4 fragments use an explicit fragment condition; IPv6 keeps
// protocol=all. New protocol and sample-filter mappings live in xdropDecoderSpec.
var xDropCompatibleDecoders = map[string]bool{
	// L4 standard
	"tcp":      true,
	"tcp_syn":  true,
	"udp":      true,
	"icmp":     true,
	"fragment": true,
	// TCP flag family (v1.3) — protocol=tcp + tcp_flags specialization
	"tcp_ack": true,
	"tcp_rst": true,
	"tcp_fin": true,
	// Other IP protocols (v1.3) — xdrop proto-agnostic lookup matches on
	// IANA number; tcp_flags / ports degrade to wildcards.
	"gre":  true,
	"esp":  true,
	"igmp": true,
	// Anomaly families use v3 match_anomaly; drop and rate_limit are allowed.
	"bad_fragment": true,
	"invalid":      true,
	// "ip" / "ip_other" intentionally excluded — see doc comment above.
}

// IsXDropCompatibleDecoder reports whether an attack with the given
// decoder_family is eligible for xDrop rule creation. Exposed so the
// action engine dispatch path can gate xDrop actions without reaching
// into xdrop.go internals.
func IsXDropCompatibleDecoder(decoder string) bool {
	return xDropCompatibleDecoders[decoder]
}

// isAnomalyDecoder identifies families matched by v3 anomaly bits.
// IPv6 bad_fragment is rejected by v3, not by a local dispatch gate.
func isAnomalyDecoder(decoder string) bool {
	return decoder == "bad_fragment" || decoder == "invalid"
}

// tcpFlagDecoderMap maps TCP-flag family decoders to their canonical
// tcp_flags pattern. Patterns chosen to minimize false positives:
//
//	tcp_syn → "SYN,!ACK": pure SYN (handshake opener), excludes SYN+ACK
//	tcp_ack → "ACK,!SYN": ACK-flood / established traffic, excludes handshake
//	tcp_rst → "RST":       connection reset flood
//	tcp_fin → "FIN":       half-open close flood
//
// Used by both the default payload builder and injectTcpFlags (custom
// payload path).
var tcpFlagDecoderMap = map[string]string{
	"tcp_syn": "SYN,!ACK",
	"tcp_ack": "ACK,!SYN",
	"tcp_rst": "RST",
	"tcp_fin": "FIN",
}

// specializeXDropDecoder pins protocol to the attack per ADR-0004.
func specializeXDropDecoder(payload *xdropRuleRequest, decoder string) {
	payload.Protocol, _ = expectedXDropProtocol(decoder, xdropAddressFamily(payload.DstIP+payload.DstCIDR))
	payload.MatchAnomaly = xdropAnomalyBit(decoder)
	if flags := tcpFlagDecoderMap[decoder]; flags != "" {
		payload.TcpFlags = &flags
	}
}

// specializeXDropDecoderBody fills anomaly bits and missing IP protocols.
// finalizeXDropV3Body subsequently pins protocol to the attack.
func specializeXDropDecoderBody(body []byte, attack *store.Attack) []byte {
	decoderName := attack.DecoderFamily
	dc := decoder.GetDispatchClass(decoderName)
	isAnomaly := dc == decoder.Anomaly
	isIPProto := dc == decoder.PortlessProto && decoderName != "icmp" && decoderName != "fragment"
	if !isAnomaly && !isIPProto {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	if isAnomaly {
		if _, has := m["match_anomaly"]; !has {
			name, _ := m["decoder"].(string)
			if name == "" {
				name = decoderName
			}
			m["match_anomaly"] = xdropAnomalyBit(name)
		}
		if proto, _ := m["protocol"].(string); isAnomalyDecoder(proto) {
			delete(m, "protocol")
		}
	}
	if isIPProto {
		if _, has := m["protocol"]; !has {
			m["protocol"] = decoderName
		}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// sanitizeXDropPayloadForDecoder is the dispatch-boundary enforcement point:
// it strips fields from the final xDrop HTTP body that are illegal for the
// attack's decoder DispatchClass. Called as the LAST step in the custom-payload
// pipeline (after specializeXDropDecoderBody) and after the default-payload
// marshal, so it sees the final shape before POST.
//
// DispatchClass rules:
//
//	Ported       → no-op (src_port/dst_port/tcp_flags all legal)
//	PortlessProto → delete src_port, dst_port, tcp_flags
//	Anomaly      → delete protocol, src_port, dst_port, tcp_flags
//	Unsupported  → no-op (engine.go gate prevents reaching here)
//
// See fix-plan-xdrop-port-bgp-schedule-2026-05-02.md §Bug 1.
func sanitizeXDropPayloadForDecoder(body []byte, decoderFamily string) []byte {
	dc := decoder.GetDispatchClass(decoderFamily)
	if dc == decoder.Ported || dc == decoder.Unsupported {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	switch dc {
	case decoder.PortlessProto:
		delete(m, "src_port")
		delete(m, "dst_port")
		delete(m, "tcp_flags")
	case decoder.Anomaly:
		delete(m, "protocol")
		delete(m, "src_port")
		delete(m, "dst_port")
		delete(m, "tcp_flags")
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// xDropSyntheticFailedRuleIDPrefix is attached to a rule row when xDrop's
// POST /rules failed before any real rule ID was returned (connect refused,
// timeout, 4xx/5xx, etc.). Surfaces the failure in `xdrop_active_rules` so
// Mitigations UI can show a "failed" badge, while letting the later unblock
// path recognize there's no real rule on the xDrop side to DELETE.
const xDropSyntheticFailedRuleIDPrefix = "failed-create-"

// syntheticFailedXDropRuleID returns a deterministic synthetic rule ID for a
// failed xDrop create. Deterministic on (attack, action) so retries upsert
// the same row (idempotent), and distinguishable via the prefix so the
// unblock path can skip the DELETE.
func syntheticFailedXDropRuleID(attackID, actionID int) string {
	return fmt.Sprintf("%s%d-%d", xDropSyntheticFailedRuleIDPrefix, attackID, actionID)
}

func isSyntheticFailedXDropRuleID(ruleID string) bool {
	return strings.HasPrefix(ruleID, xDropSyntheticFailedRuleIDPrefix)
}

// CloseSyntheticXDropRuleLocal honors the "no real rule to DELETE" contract
// for synthetic "failed-create-*" IDs: writes an audit log, marks the
// xdrop_active_rules row withdrawn, and (if `engine` is non-nil and
// scheduledActionID > 0) completes the corresponding scheduled_action.
//
// Called by both immediate and delayed unblock code paths. Keeping a single
// function guarantees the two paths can never drift — which is what the
// PR-8 audit specifically asked to lock down.
//
// Exported for focused integration testing from the tests package.
func CloseSyntheticXDropRuleLocal(
	ctx context.Context,
	s store.Store,
	engine *Engine,
	attackID, actionID, connectorID int,
	connectorName, triggerPhase, ruleID string,
	scheduledActionID int,
) {
	connID := connectorID
	s.ActionExecLog().Create(ctx, &store.ActionExecutionLog{
		AttackID:       attackID,
		ActionID:       actionID,
		ActionType:     "xdrop",
		ConnectorName:  connectorName,
		ConnectorID:    &connID,
		TriggerPhase:   triggerPhase,
		ExternalRuleID: ruleID,
		Status:         "success",
		ErrorMessage:   "synthetic failed-create rule; no xDrop DELETE needed",
		ExecutedAt:     time.Now(),
	})
	s.XDropActiveRules().MarkWithdrawn(ctx, attackID, actionID, connectorID, ruleID)
	if engine != nil && scheduledActionID > 0 {
		engine.CompleteDelay(ctx, scheduledActionID, attackID, actionID, connectorID, ruleID)
	}
}

// xdropRuleRequest is the default request body sent to xDrop API.
// Empty optional fields are omitted; finalize adds the v3 claim identity.
type xdropRuleRequest struct {
	DstIP        string  `json:"dst_ip,omitempty"`
	DstCIDR      string  `json:"dst_cidr,omitempty"` // v1.3: subnet-scope rule (carpet bombing)
	SrcIP        string  `json:"src_ip,omitempty"`
	SrcCIDR      string  `json:"src_cidr,omitempty"`
	DstPort      int     `json:"dst_port,omitempty"`
	SrcPort      int     `json:"src_port,omitempty"`
	Protocol     string  `json:"protocol,omitempty"`
	TcpFlags     *string `json:"tcp_flags,omitempty"` // e.g. "SYN,!ACK"; requires protocol=tcp
	MatchAnomaly int     `json:"match_anomaly,omitempty"`
	Fragment     string  `json:"fragment,omitempty"`
	Action       string  `json:"action"`               // "drop" or "rate_limit"
	RateLimit    int     `json:"rate_limit,omitempty"` // PPS, required if action=rate_limit
	Comment      string  `json:"comment,omitempty"`
}

// splitIPOrCIDR separates "10.0.0.1" vs "10.0.0.0/24".
// Returns (ip, cidr) where exactly one is populated: ip for /32|/128|bare,
// cidr for anything shorter. Used to route subnet-scope attacks (carpet bombing)
// to xDrop's dst_cidr match field instead of exact dst_ip.
func splitIPOrCIDR(s string) (ip, cidr string) {
	idx := strings.IndexByte(s, '/')
	if idx < 0 {
		return s, ""
	}
	host := s[:idx]
	plStr := s[idx+1:]
	// IPv4 /32 and IPv6 /128 are effectively exact IPs; route to dst_ip.
	if strings.Contains(host, ":") {
		if plStr == "128" {
			return host, ""
		}
	} else {
		if plStr == "32" {
			return host, ""
		}
	}
	return "", s
}

// executeXDrop executes an xDrop action by calling the xDrop Controller API.
func executeXDrop(
	ctx context.Context,
	s store.Store,
	action store.ResponseAction,
	attack *store.Attack,
	eventType string,
	prefixStr string,
	responseName string,
	triggerPhase string,
	attackDBID int,
	fa *FlowAnalysis,
	engine *Engine, // nil-safe: if non-nil, used to schedule per-artifact cancelable delays
) (*store.ActionExecutionLog, error) {
	skipLog := func(reason, message string) *store.ActionExecutionLog {
		row := &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     action.ID,
			ResponseName: responseName,
			ActionType:   "xdrop",
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			ErrorMessage: message,
			ExecutedAt:   time.Now(),
		}
		recordSkip(row, reason)
		return row
	}
	xdropAction := action.XDropAction
	if xdropAction == "" {
		log.Printf("action: xdrop action %d skipped: xdrop action type is empty", action.ID)
		return skipLog(SkipReasonIncompleteConfig, "xdrop action type is empty"), nil
	}

	// Resolve target connectors: action-specific targets first, fall back to all enabled
	connectors, err := s.XDropTargets().List(ctx, action.ID)
	if err != nil {
		err = fmt.Errorf("list xdrop targets for action %d: %w", action.ID, err)
		return skipLog(SkipReasonConnectorLookupFailed, err.Error()), err
	}
	if len(connectors) == 0 {
		connectors, err = s.XDropConnectors().ListEnabled(ctx)
		if err != nil {
			err = fmt.Errorf("list enabled xdrop connectors: %w", err)
			return skipLog(SkipReasonConnectorLookupFailed, err.Error()), err
		}
	}
	if len(connectors) == 0 {
		execLog := &store.ActionExecutionLog{
			AttackID:     attackDBID,
			ActionID:     action.ID,
			ResponseName: responseName,
			ActionType:   "xdrop",
			TriggerPhase: triggerPhase,
			Status:       "skipped",
			ErrorMessage: "no xdrop connectors available",
			ExecutedAt:   time.Now(),
		}
		recordSkip(execLog, SkipReasonNoConnector)
		log.Printf("action: xdrop action %d skipped: no xdrop connectors available", action.ID)
		return execLog, nil
	}

	// Filter after target resolution so an explicitly disabled target set
	// cannot fall through to global connectors or payload validation.
	if xdropAction != "unblock" {
		enabled := make([]store.XDropConnector, 0, len(connectors))
		for _, conn := range connectors {
			if !conn.Enabled {
				entry := skipLog(SkipReasonConnectorDisabled, "connector disabled")
				connID := conn.ID
				entry.ConnectorID, entry.ConnectorName = &connID, conn.Name
				if _, err := writeExecLog(s, entry); err != nil {
					xdropStateWriteFailure("xdrop_exec_log", err)
				}
				continue
			}
			enabled = append(enabled, conn)
		}
		connectors = enabled
		if len(connectors) == 0 {
			return nil, nil
		}
	}

	// Build request body
	var body []byte
	var shapeHints, itemHints []string
	var bodies [][]byte
	if len(action.XDropCustomPayload) > 0 && string(action.XDropCustomPayload) != "null" {
		// Preserve narrowing permissions before expanding the template. Invalid
		// template JSON keeps the legacy behavior with no narrowing permissions.
		var tpl map[string]any
		if json.Unmarshal(action.XDropCustomPayload, &tpl) != nil {
			tpl = nil
		}
		// Use custom payload with {var} expansion
		expanded := expandParams(string(action.XDropCustomPayload), attack, eventType, prefixStr, fa)
		// Fix JSON types: port and rate_limit fields must be integers, not strings.
		// expandParams does string replacement, so "src_port": "{dominant_src_port}" becomes "src_port": "53".
		// We parse and re-marshal to fix types.
		body, err = fixPayloadTypes([]byte(expanded))
		if err != nil {
			body = []byte(expanded) // fallback to raw string if fixup fails
		}
		// Normalize protocol field: xSight decoder_family values like "ip"
		// and "fragment" are not in xDrop's protocol enum; translate them
		// (e.g. "ip" → "all") so custom payloads with `{decoder}` work
		// across all threshold rule types without operator translation.
		body = normalizeXDropProtocol(body)
		// Auto-inject tcp_flags for TCP-flag-family attacks if not already
		// specified. Runs AFTER normalize so its protocol rewrite still
		// wins when protocol=<tcp_flag_decoder> expanded from {decoder}.
		body = injectTcpFlags(body, attack)
		// Auto-fill decoder / protocol for anomaly + gre/esp/igmp attacks
		// when operator's custom payload omitted them (parallel to
		// specializeXDropDecoder on the default-payload path). Runs last
		// so it sees the post-normalize + post-inject shape.
		body = specializeXDropDecoderBody(body, attack)
		// Final enforcement: strip fields illegal for this decoder's
		// DispatchClass (e.g. src_port/dst_port on GRE attacks). Runs
		// last so it catches any stray fields from expandParams or
		// fixPayloadTypes that the earlier steps did not remove.
		body = sanitizeXDropPayloadForDecoder(body, attack.DecoderFamily)
		var shaped map[string]any
		if json.Unmarshal(body, &shaped) == nil && shaped != nil {
			var shapedBodies []map[string]any
			shapedBodies, shapeHints, itemHints = shapeXDropBodies(tpl, shaped, fa, attack, attack.DecoderFamily, xdropAction == "rate_limit", func(id int) (*store.Threshold, error) {
				return s.Thresholds().Get(ctx, id)
			})
			for _, shapedBody := range shapedBodies {
				itemBody, err := json.Marshal(shapedBody)
				if err != nil {
					return nil, fmt.Errorf("marshal shaped xdrop payload: %w", err)
				}
				bodies = append(bodies, itemBody)
			}
		}
	} else {
		// Default payload: dst_ip drop/rate_limit based on xdrop_action.
		// v1.3 Phase 1c.1: subnet-scope attacks (carpet bombing) use dst_cidr
		// instead of dst_ip so xDrop matches on the whole subnet.
		actionStr := "drop"
		if xdropAction == "rate_limit" {
			actionStr = "rate_limit"
		}
		dstIP, dstCIDR := splitIPOrCIDR(attack.DstIP)
		payload := xdropRuleRequest{
			DstIP:   dstIP,
			DstCIDR: dstCIDR,
			Action:  actionStr,
			Comment: fmt.Sprintf("attack #%d %s", attack.ID, attack.AttackType),
		}
		specializeXDropDecoder(&payload, attack.DecoderFamily)
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal xdrop payload: %w", err)
		}
		// Defense-in-depth: the typed struct never sets ports for non-L4
		// decoders, but run the sanitizer anyway so the invariant holds
		// regardless of future struct changes.
		body = sanitizeXDropPayloadForDecoder(body, attack.DecoderFamily)
	}

	if len(bodies) == 0 {
		bodies = [][]byte{body}
	}
	type dispatchItem struct {
		body  []byte
		hints []string
	}
	var items []dispatchItem
	var rejected []*store.ActionExecutionLog
	for i, raw := range bodies {
		body, finalizeHints := finalizeXDropV3Body(raw, attack, xdropClaimRef(attackDBID, action.ID))
		hints := append([]string(nil), shapeHints...)
		if len(itemHints) > 0 {
			hints = append(hints, itemHints[i])
		}
		hints = append(hints, finalizeHints...)
		// Runtime sanity: every final rate_limit action needs a rate in the v3 range.
		// API validation should prevent this, but guard against malformed DB rows.
		//
		// v1.3.4: previously returned (nil, err), which caused the caller to skip
		// writing an action_execution_log row — operator saw nothing in UI/timeline
		// despite the dispatch being rejected. Now returns a populated failed log
		// so the reason is visible in the execution history.
		var check map[string]any
		if json.Unmarshal(body, &check) == nil {
			if xdropAction == "rate_limit" || check["action"] == "rate_limit" {
				rl, _ := check["rate_limit"].(float64)
				if rl <= 0 || rl > 4294967295 {
					errMsg := "xdrop rate_limit action has no valid rate_limit value in payload"
					failLog := &store.ActionExecutionLog{
						AttackID:     attackDBID,
						ActionID:     action.ID,
						ResponseName: responseName,
						ActionType:   "xdrop",
						TriggerPhase: triggerPhase,
						Status:       "failed",
						ErrorMessage: strings.Join(append([]string{errMsg}, hints...), "; "),
						RequestBody:  truncateStr(string(body), 1024),
						ExecutedAt:   time.Now(),
					}
					if len(bodies) == 1 {
						return failLog, fmt.Errorf("%s", errMsg)
					}
					rejected = append(rejected, failLog)
					continue
				}
			}
		}

		items = append(items, dispatchItem{body: body, hints: hints})
	}

	// For "unblock" action, we need the external rule ID from a previous execution
	httpMethod := "POST"
	if xdropAction == "unblock" {
		httpMethod = "DELETE"
	}

	// Execute the selected items on each connector, then commit its failures.
	var lastLog *store.ActionExecutionLog
	overrideFiltered := false
	for _, conn := range connectors {
		if len(items) == 0 {
			continue
		}
		connID := conn.ID // capture for pointer

		if xdropAction != "unblock" {
			overrides, err := s.ManualOverrides().ListByAttack(ctx, attackDBID)
			if err != nil {
				log.Printf("action: xdrop create override lookup: %v", err)
			}
			blocked := false
			for _, override := range overrides {
				if override.ActionID == action.ID && override.ConnectorID == conn.ID {
					blocked = true
					break
				}
			}
			if blocked {
				writeSkipLog(ctx, s, attackDBID, action, responseName, conn.Name, SkipReasonManualOverride, "")
				continue
			}
		}

		apiURL := strings.TrimRight(conn.APIURL, "/") + "/rules"

		// Create HTTP client with connector timeout
		timeout := 10 * time.Second
		if conn.TimeoutMs > 0 {
			timeout = time.Duration(conn.TimeoutMs) * time.Millisecond
		}
		client := &http.Client{Timeout: timeout}

		// For unblock, select owned artifacts from xdrop_active_rules.
		// Each rule may have a different unblock_delay_minutes from its originating on_detected action.
		// Rules with delay=0 are deleted immediately; rules with delay>0 are scheduled for later deletion.
		// NOTE: ScheduleDelay persists delayed deletions; RecoverScheduledActions re-arms them at startup.
		// Persistence failure calls MarkFailed and starts no goroutine; that status write may also fail.
		// Calls without an Engine use a local Engine to preserve the same withdrawal contract.
		if xdropAction == "unblock" {
			execLog := &store.ActionExecutionLog{
				AttackID:      attackDBID,
				ActionID:      action.ID,
				ResponseName:  responseName,
				ActionType:    "xdrop",
				ConnectorName: conn.Name,
				ConnectorID:   &connID,
				TriggerPhase:  triggerPhase,
				ErrorMessage:  strings.Join(items[0].hints, "; "),
				RequestBody:   truncateStr(string(items[0].body), 1024),
				ExecutedAt:    time.Now(),
			}
			allRules, err := s.XDropActiveRules().ListByAttack(ctx, attackDBID)
			if err != nil || len(allRules) == 0 {
				execLog.Status = "skipped"
				execLog.ErrorMessage = "no active, delayed or failed rules to unblock"
				if err != nil {
					execLog.Status = "failed"
					execLog.ErrorMessage = fmt.Sprintf("list xdrop_active_rules: %v", err)
				} else {
					recordSkip(execLog, SkipReasonNoRulesToUnblock)
				}
				lastLog = execLog
				if _, err := writeExecLog(s, execLog); err != nil {
					xdropStateWriteFailure("xdrop_exec_log", err)
				}
				continue
			}

			// Filter: only delete rules that were created on THIS connector.
			// Prevents cross-connector deletion when multiple xDrop connectors are used.
			var rulesWithActions []store.RuleWithAction
			for _, ra := range allRules {
				if ra.ConnectorID == conn.ID && (ra.Status == "active" || ra.Status == "delayed" || ra.Status == "failed") {
					// Synthetic IDs share the recovery and withdrawal helper below.
					rulesWithActions = append(rulesWithActions, store.RuleWithAction{RuleID: ra.ExternalRuleID, ActionID: ra.ActionID, ConnectorID: ra.ConnectorID})
				}
			}
			if len(rulesWithActions) == 0 {
				continue // no rules for this connector
			}

			// Per-artifact manual_override suppression: v1.2 PR-2 uses the
			// indexed action_manual_overrides table instead of scanning
			// execution logs. Pre-fetch set for the attack, then O(1)
			// membership check per rule.
			//
			// Key must include action_id — two different actions on the same
			// attack may share connector+rule, but operator force-removing one
			// must NOT suppress the other. Matches the UNIQUE business key on
			// the action_manual_overrides table.
			overrides, err := s.ManualOverrides().ListByAttack(ctx, attackDBID)
			if err != nil {
				log.Printf("action: xdrop unblock override lookup failed (attack=%d): %v — proceeding without override filter", attackDBID, err)
			}
			overrideSet := make(map[string]bool, len(overrides))
			for _, o := range overrides {
				overrideSet[overrideKey(o.ActionID, o.ConnectorID, o.ExternalRuleID)] = true
			}
			var filteredRules []store.RuleWithAction
			for _, ra := range rulesWithActions {
				key := overrideKey(ra.ActionID, conn.ID, ra.RuleID)
				if overrideSet[key] {
					overrideFiltered = true
					log.Printf("action: xdrop unblock skipping rule %s (manual override, attack=%d action=%d)", ra.RuleID, attackDBID, ra.ActionID)
					continue
				}
				filteredRules = append(filteredRules, ra)
			}
			rulesWithActions = filteredRules
			if len(rulesWithActions) == 0 {
				continue // all rules on this connector were force-removed
			}

			// Build action ID → delay map by looking up the originating actions
			actionDelays := make(map[int]int) // action_id → unblock_delay_minutes
			for _, ra := range rulesWithActions {
				if _, seen := actionDelays[ra.ActionID]; !seen {
					if act, err := s.Responses().GetAction(ctx, ra.ActionID); err == nil {
						actionDelays[ra.ActionID] = act.UnblockDelayMinutes
					}
				}
			}

			// Group rules by delay
			immediateRules := []store.RuleWithAction{}
			type delayedRule struct {
				rule  store.RuleWithAction
				delay time.Duration
			}
			var delayedRules []delayedRule
			for _, ra := range rulesWithActions {
				delay := actionDelays[ra.ActionID]
				if delay <= 0 {
					immediateRules = append(immediateRules, ra)
				} else {
					delayedRules = append(delayedRules, delayedRule{ra, time.Duration(delay) * time.Minute})
				}
			}

			// All automatic withdrawals share the Engine's business-key lock.
			if engine == nil {
				engine = NewEngine(s, "auto")
			}
			deleted, skipped := 0, 0
			deferred := map[string]int{}
			var lastErr string
			for _, ra := range immediateRules {
				sa := store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: attackDBID, ActionID: ra.ActionID, ConnectorID: connID, ExternalRuleID: ra.RuleID}
				result := engine.withdrawXDropRule(ctx, sa, "normal", triggerPhase)
				switch result {
				case "withdrawn":
					deleted++
				case "failed", "state_write_error", "list_error":
					lastErr = result
				default:
					skipped++
					switch result {
					case "backoff":
						deferred["backoff"]++
					case "skipped_connector":
						deferred["connector_disabled"]++
					case "busy", "cancelled":
						deferred["busy"]++
					case "skipped_claimed":
						deferred["claimed"]++
					}
				}
			}
			scheduled, scheduleFailed := 0, false
			for _, dr := range delayedRules {
				sa := store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: attackDBID, ActionID: dr.rule.ActionID, ConnectorID: connID, ExternalRuleID: dr.rule.RuleID, ScheduledFor: time.Now().Add(dr.delay)}
				persisted, err := engine.scheduleXDrop(ctx, sa, triggerPhase, responseName)
				if persisted {
					scheduled++
				}
				if err != nil {
					scheduleFailed = true
				}
			}

			totalRules := len(immediateRules) + len(delayedRules)
			execLog.DurationMs = int(time.Since(execLog.ExecutedAt).Milliseconds())
			if scheduleFailed {
				execLog.Status = "failed"
				execLog.ErrorMessage = xdropScheduleFailure
			} else if deleted+skipped == len(immediateRules) {
				execLog.Status = "success"
			} else if deleted > 0 {
				execLog.Status = "success"
				execLog.ErrorMessage = fmt.Sprintf("deleted %d/%d immediate rules, last error: %s", deleted, len(immediateRules), lastErr)
			} else if scheduled > 0 {
				execLog.Status = "success"
				execLog.ErrorMessage = fmt.Sprintf("0 immediate, %d delayed rules scheduled", scheduled)
			} else {
				execLog.Status = "failed"
				execLog.ErrorMessage = fmt.Sprintf("deleted 0/%d rules: %s", totalRules, lastErr)
			}
			if !scheduleFailed && deleted < len(immediateRules) {
				var parts []string
				n := 0
				for _, reason := range []string{"backoff", "connector_disabled", "busy", "claimed"} {
					if count := deferred[reason]; count > 0 {
						n += count
						parts = append(parts, fmt.Sprintf("%s=%d", reason, count))
					}
				}
				if n > 0 {
					execLog.ErrorMessage = fmt.Sprintf("deferred %d: %s", n, strings.Join(parts, ", "))
				}
			}
			sc := 200
			execLog.StatusCode = &sc
			lastLog = execLog
			if _, err := writeExecLog(s, execLog); err != nil {
				xdropStateWriteFailure("xdrop_exec_log", err)
			}
			log.Printf("action: xdrop unblock connector %d (%s) immediate=%d/%d delayed=%d attack=%d",
				conn.ID, conn.Name, deleted, len(immediateRules), scheduled, attackDBID)
			continue // skip the normal single-request path below
		}

		// Each closure owns its item log and immutable serialized body. Successes
		// commit immediately; failures commit last so partial success stays retryable.
		var failures []func(context.Context)
		deferFailure := func(commit func(context.Context)) {
			failures = append(failures, commit)
		}
		for _, item := range items {
			body, hints := item.body, item.hints
			execLog := &store.ActionExecutionLog{
				AttackID:      attackDBID,
				ActionID:      action.ID,
				ResponseName:  responseName,
				ActionType:    "xdrop",
				ConnectorName: conn.Name,
				ConnectorID:   &connID,
				TriggerPhase:  triggerPhase,
				ErrorMessage:  strings.Join(hints, "; "),
				RequestBody:   truncateStr(string(body), 1024),
				ExecutedAt:    time.Now(),
			}
			req, err := http.NewRequestWithContext(ctx, httpMethod, apiURL, bytes.NewReader(body))
			if err != nil {
				execLog.Status = "failed"
				execLog.ErrorMessage = redactXDropError(strings.Join(append([]string{fmt.Sprintf("create request: %v", err)}, hints...), "; "), conn.APIKey)
				deferFailure(func(ctx context.Context) {
					// v1.2 PR-4 bug fix: surface create failures in xdrop_active_rules
					// via a synthetic rule ID so Mitigations UI shows a failed badge
					// instead of silently dropping the failure on the floor.
					if xdropAction != "unblock" {
						execLog.ExternalRuleID = syntheticFailedXDropRuleID(attackDBID, action.ID)
						s.XDropActiveRules().Upsert(ctx, &store.XDropActiveRule{
							AttackID: attackDBID, ActionID: action.ID, ConnectorID: conn.ID,
							ExternalRuleID: execLog.ExternalRuleID,
							Status:         "failed",
							ErrorMessage:   execLog.ErrorMessage,
						})
					}
					lastLog = execLog
					if _, err := s.ActionExecLog().Create(ctx, execLog); err != nil {
						log.Printf("action: create action_execution_log: %v", err)
					}
				})
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", "xsight-controller/1.0")
			SetXDropAuth(req, conn.APIKey)

			start := time.Now()
			resp, err := client.Do(req)
			execLog.DurationMs = int(time.Since(start).Milliseconds())

			if err != nil {
				execLog.Status = "failed"
				execLog.ErrorMessage = redactXDropError(strings.Join(append([]string{xdropTransportError(httpMethod, err).Error()}, hints...), "; "), conn.APIKey)
				deferFailure(func(ctx context.Context) {
					// v1.2 PR-4 bug fix: see above — synthetic ID keeps failed state
					// visible in Mitigations even when the HTTP layer never completed.
					if xdropAction != "unblock" {
						execLog.ExternalRuleID = syntheticFailedXDropRuleID(attackDBID, action.ID)
						s.XDropActiveRules().Upsert(ctx, &store.XDropActiveRule{
							AttackID: attackDBID, ActionID: action.ID, ConnectorID: conn.ID,
							ExternalRuleID: execLog.ExternalRuleID,
							Status:         "failed",
							ErrorMessage:   execLog.ErrorMessage,
						})
					}
					if engine == nil {
						engine = NewEngine(s, "auto")
					}
					lastLog = execLog
					if _, err := s.ActionExecLog().Create(ctx, execLog); err != nil {
						log.Printf("action: create action_execution_log: %v", err)
					}
					engine.xdropAfterCreate(conn, execLog, body)
				})
				continue
			}

			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()

			statusCode := resp.StatusCode
			execLog.StatusCode = &statusCode
			execLog.ResponseBody = truncateStr(redactXDropError(string(respBody), conn.APIKey), 1024)

			if statusCode >= 400 {
				execLog.Status = "failed"
				execLog.ErrorMessage = redactXDropError(strings.Join(append([]string{XDropHTTPError(statusCode, respBody)}, hints...), "; "), conn.APIKey)
				// v1.2 PR-4 bug fix: no real rule ID returned on 4xx/5xx — use a
				// synthetic one so the failure lands in xdrop_active_rules.
				if xdropAction != "unblock" {
					execLog.ExternalRuleID = syntheticFailedXDropRuleID(attackDBID, action.ID)
				}
			} else {
				var response struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(respBody, &response) == nil && response.ID != "" && (statusCode == 200 || statusCode == 201) {
					execLog.Status = "success"
					execLog.ExternalRuleID = response.ID
				} else {
					execLog.Status = "failed"
					execLog.ErrorMessage = strings.Join(append([]string{"v3 created but id missing"}, hints...), "; ")
					execLog.ExternalRuleID = syntheticFailedXDropRuleID(attackDBID, action.ID)
				}
			}

			commit := func(ctx context.Context) {
				// v1.2 PR-4: record xdrop rule state. Written for both success and
				// failure so Mitigations UI can surface 'failed' state from the table
				// rather than reverse-engineering from execution log. Failure paths
				// above populate a synthetic ExternalRuleID — see
				// syntheticFailedXDropRuleID.
				if xdropAction != "unblock" && execLog.ExternalRuleID != "" {
					ruleState := &store.XDropActiveRule{
						AttackID:       attackDBID,
						ActionID:       action.ID,
						ConnectorID:    conn.ID,
						ExternalRuleID: execLog.ExternalRuleID,
						Status:         "active",
					}
					if execLog.Status == "failed" {
						ruleState.Status = "failed"
						ruleState.ErrorMessage = execLog.ErrorMessage
					}
					if _, err := s.XDropActiveRules().Upsert(ctx, ruleState); err != nil {
						log.Printf("action: xdrop_active_rules upsert rule=%s: %v", execLog.ExternalRuleID, err)
					}
					if engine == nil {
						engine = NewEngine(s, "auto")
					}
				}

				lastLog = execLog
				if _, err := s.ActionExecLog().Create(ctx, execLog); err != nil {
					log.Printf("action: create action_execution_log: %v", err)
				}
				if xdropAction != "unblock" && execLog.ExternalRuleID != "" {
					engine.xdropAfterCreate(conn, execLog, body)
				}
			}
			if execLog.Status == "failed" {
				deferFailure(commit)
			} else {
				commit(ctx)
			}

			log.Printf("action: xdrop %s connector %d (%s) %s attack=%d",
				xdropAction, conn.ID, conn.Name, execLog.Status, attackDBID)
		}
		for _, commit := range failures {
			dbCtx, cancel := context.WithTimeout(context.Background(), dbOperationTimeout)
			commit(dbCtx)
			cancel()
		}
	}

	// Rate rejections have no connector identity. Write each rejected item once,
	// after all connectors, using writeExecLog's independent database budget.
	for _, entry := range rejected {
		lastLog = entry
		if _, err := writeExecLog(s, entry); err != nil {
			xdropStateWriteFailure("xdrop_exec_log", err)
		}
	}

	if xdropAction == "unblock" && lastLog == nil {
		reason, msg := SkipReasonNoRulesToUnblock, "no active, delayed or failed rules to unblock"
		if overrideFiltered {
			reason, msg = SkipReasonManualOverride, "all remaining rules were force-removed by operator"
		}
		log.Printf("action: xdrop action %d skipped: %s (attack=%d)", action.ID, msg, attackDBID)
		return skipLog(reason, msg), nil
	}

	// Return nil for the log since we already persisted per-connector logs
	if lastLog != nil && lastLog.Status == "failed" {
		return nil, fmt.Errorf("xdrop action failed: %s", lastLog.ErrorMessage)
	}
	return nil, nil
}

// fixPayloadTypes converts string values to proper JSON types for xDrop RuleRequest.
// After expandParams, numeric fields like src_port/dst_port/rate_limit are strings ("53").
// xDrop expects them as integers. This function parses the JSON, converts known numeric
// fields from string to int, and removes fields with empty string values (wildcard).
func fixPayloadTypes(raw []byte) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	intFields := []string{"src_port", "dst_port", "rate_limit"}
	for _, f := range intFields {
		v, ok := m[f]
		if !ok {
			continue
		}
		switch val := v.(type) {
		case string:
			if val == "" || val == "0" {
				delete(m, f) // empty/zero = wildcard, remove from payload
			} else {
				n, err := strconv.Atoi(val)
				if err != nil {
					delete(m, f) // unparseable, remove
				} else {
					m[f] = n
				}
			}
		}
	}

	return json.Marshal(m)
}

// decoderToXDropProtocol maps xSight decoder_family values to xDrop's
// protocol field.
//
//	xSight decoder_family (protocol path):
//	  tcp / tcp_syn / tcp_ack / tcp_rst / tcp_fin → "tcp"
//	  udp                                         → "udp"
//	  icmp                                        → "icmp"
//	  gre / esp / igmp                            → "gre" / "esp" / "igmp"
//	  ip / fragment                               → "all"
//	  "" / unknown                                → ""  (caller leaves field alone)
//
// Anomaly decoders (bad_fragment/invalid) do NOT appear here — they
// dispatch through xdrop's `decoder` field (see isAnomalyDecoder +
// default-payload builder); trying to set protocol would either collapse
// to "all" (ambiguous) or duplicate the anomaly bit that Controller
// derives from `decoder`.
//
// TCP-flag-family decoders collapse to "tcp"; the flag specialization
// is injected separately by injectTcpFlags / the default payload builder.
func decoderToXDropProtocol(decoder string) string {
	switch decoder {
	case "tcp", "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin":
		return "tcp"
	case "udp":
		return "udp"
	case "icmp":
		return "icmp"
	case "gre":
		return "gre"
	case "esp":
		return "esp"
	case "igmp":
		return "igmp"
	case "ip", "fragment":
		return "all"
	default:
		return ""
	}
}

// normalizeXDropProtocol rewrites the `protocol` field in a custom xDrop
// payload to a value the xDrop API accepts. Runs unconditionally for every
// custom-payload xDrop request (after expandParams + fixPayloadTypes, before
// injectTcpFlags).
//
// Why this exists: operators configure payloads like
// `"protocol": "{decoder}"` for convenience. `{decoder}` expands to xSight's
// decoder_family name, which xDrop rejects as-is because its protocol enum
// is narrower. Without this normalization the rule create fails with HTTP
// 400 and the attack's xdrop_active_rules row goes to the failed state.
//
// Rewrite rules:
//   - protocol already a valid xDrop value (all/tcp/udp/icmp/icmpv6/gre/
//     esp/igmp) → no change
//   - protocol is an anomaly decoder (bad_fragment/invalid): MOVE the
//     value to the `decoder` field (anomaly rules are protocol-wildcard +
//     decoder-bit in xdrop v2.6.1) and delete `protocol`. Idempotent if
//     `decoder` is already set.
//   - protocol maps via decoderToXDropProtocol (tcp_syn/tcp_ack/tcp_rst/
//     tcp_fin → tcp, fragment → all, ip → all) → rewrite protocol
//   - protocol is something else → no change (let xDrop surface error)
//
// Not reached paths (kept for defense-in-depth): `ip` / `ip_other` are
// gated out at the engine dispatch layer before executeXDrop runs (see
// IsXDropCompatibleDecoder), but decoderToXDropProtocol still maps `ip`
// → `all` so an operator who hand-crafts a payload with literal
// "protocol":"ip" gets a working rule instead of a 400.
func normalizeXDropProtocol(body []byte) []byte {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	proto, ok := m["protocol"].(string)
	if !ok || proto == "" {
		return body
	}
	// Already valid xDrop value — leave alone. Include gre/esp/igmp so
	// custom payloads with literal `"protocol":"gre"` don't get rewritten.
	switch proto {
	case "all", "tcp", "udp", "icmp", "icmpv6", "gre", "esp", "igmp":
		return body
	}
	// Anomaly decoder expanded from {decoder}: move to the xdrop `decoder`
	// field. xdrop anomaly rules are protocol-wildcard + decoder-bit; keeping
	// protocol set to a non-enum value would be rejected.
	if isAnomalyDecoder(proto) {
		delete(m, "protocol")
		bits, _ := m["match_anomaly"].(float64)
		m["match_anomaly"] = int(bits) | xdropAnomalyBit(proto)
		if out, err := json.Marshal(m); err == nil {
			return out
		}
		return body
	}
	if mapped := decoderToXDropProtocol(proto); mapped != "" && mapped != proto {
		m["protocol"] = mapped
		if out, err := json.Marshal(m); err == nil {
			return out
		}
	}
	return body
}

// injectTcpFlags auto-injects tcp_flags and normalizes protocol for the
// TCP-flag family (tcp_syn/tcp_ack/tcp_rst/tcp_fin). Pass-through for
// non-TCP-flag decoders.
//
// Rules:
//   - TCP-flag attack without tcp_flags → inject canonical pattern from
//     tcpFlagDecoderMap + protocol=tcp
//   - TCP-flag attack with tcp_flags already set → keep operator's flags,
//     still ensure protocol=tcp
//   - TCP-flag attack with protocol=<decoder> (from {decoder} expansion) → tcp
//   - non-TCP-flag attack → no changes
func injectTcpFlags(body []byte, attack *store.Attack) []byte {
	canonicalFlags, ok := tcpFlagDecoderMap[attack.DecoderFamily]
	if !ok {
		return body
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	if value, has := m["tcp_flags"]; !has || value == "" {
		m["tcp_flags"] = canonicalFlags
	}
	// Always normalize protocol to tcp (covers bare + {decoder}-expanded cases)
	proto, _ := m["protocol"].(string)
	if proto == "" || proto == attack.DecoderFamily {
		m["protocol"] = "tcp"
	}
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// SetXDropAuth applies the v3 machine credential shared by action and API callers.
func SetXDropAuth(req *http.Request, apiKey string) {
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
}

func xdropClaimRef(attackID, actionID int) string {
	return fmt.Sprintf("a%d.x%d", attackID, actionID)
}

type xdropDecoderSpecRow struct {
	ExpectedV4, ExpectedV6    string
	Pin                       bool
	ProtocolV4, ProtocolV6    int
	TCPFlagsAll, TCPFlagsNone uint8
}

var xdropDecoderSpec = map[string]xdropDecoderSpecRow{
	"tcp":          {"tcp", "tcp", true, 6, 6, 0, 0},
	"tcp_syn":      {"tcp", "tcp", true, 6, 6, 2, 16},
	"tcp_ack":      {"tcp", "tcp", true, 6, 6, 16, 2},
	"tcp_rst":      {"tcp", "tcp", true, 6, 6, 4, 0},
	"tcp_fin":      {"tcp", "tcp", true, 6, 6, 1, 0},
	"udp":          {"udp", "udp", true, 17, 17, 0, 0},
	"icmp":         {"icmp", "icmpv6", true, 1, 58, 0, 0},
	"gre":          {"gre", "gre", true, 47, 47, 0, 0},
	"esp":          {"esp", "esp", true, 50, 50, 0, 0},
	"igmp":         {"igmp", "igmp", true, 2, 2, 0, 0},
	"fragment":     {"all", "all", true, 0, 0, 0, 0},
	"bad_fragment": {"", "", false, 0, 0, 0, 0},
	"invalid":      {"", "", false, 0, 0, 0, 0},
}

func expectedXDropProtocol(decoder string, dstFamily int) (string, bool) {
	spec := xdropDecoderSpec[decoder]
	if dstFamily == 6 {
		return spec.ExpectedV6, spec.Pin
	}
	return spec.ExpectedV4, spec.Pin
}

func xdropAddressFamily(address string) int {
	ip := net.ParseIP(strings.SplitN(address, "/", 2)[0])
	if ip != nil && ip.To4() == nil {
		return 6
	}
	if ip != nil {
		return 4
	}
	return 0
}

func xdropAnomalyBit(name string) int {
	switch name {
	case "bad_fragment":
		return 1
	case "invalid":
		return 2
	}
	return 0
}

func finalizeXDropV3Body(body []byte, attack *store.Attack, claimRef string) ([]byte, []string) {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil || m == nil {
		return body, nil
	}
	var hints, dropped []string
	drop := func(key string) {
		if _, exists := m[key]; exists {
			delete(m, key)
			dropped = append(dropped, key)
		}
	}
	proto, pin := expectedXDropProtocol(attack.DecoderFamily, xdropAddressFamily(attack.DstIP))
	if pin {
		previous, exists := m["protocol"]
		if previous != proto {
			if !exists {
				previous = "absent"
			}
			hints = append(hints, fmt.Sprintf("protocol pinned: %v→%s", previous, proto))
			m["protocol"] = proto
		}
	} else if isAnomalyDecoder(attack.DecoderFamily) {
		drop("protocol")
	}
	if attack.DecoderFamily == "fragment" && xdropAddressFamily(attack.DstIP) == 4 {
		if value, exists := m["fragment"]; !exists || value == "" {
			m["fragment"] = "frag"
		}
	}
	if name, ok := m["decoder"].(string); ok && xdropAnomalyBit(name) != 0 {
		bits, _ := m["match_anomaly"].(float64)
		m["match_anomaly"] = int(bits) | xdropAnomalyBit(name)
	}
	drop("decoder")
	for _, side := range []string{"dst", "src"} {
		key, cidrKey := side+"_ip", side+"_cidr"
		value, _ := m[key].(string)
		if ip := net.ParseIP(value); ip != nil && (ip.String() == "0.0.0.0" || ip.String() == "::") {
			drop(key)
			continue
		}
		if strings.Contains(value, "/") {
			if cidr, _ := m[cidrKey].(string); cidr != "" {
				drop(key)
			} else if ip, cidr := splitIPOrCIDR(value); cidr != "" {
				m[cidrKey] = cidr
				delete(m, key)
			} else {
				m[key] = ip
			}
		}
	}
	dstCIDR, _ := m["dst_cidr"].(string)
	srcCIDR, _ := m["src_cidr"].(string)
	if dstCIDR != "" || srcCIDR != "" {
		for _, side := range []string{"dst", "src"} {
			if cidr, _ := m[side+"_cidr"].(string); cidr != "" {
				continue
			}
			key := side + "_ip"
			value, _ := m[key].(string)
			if ip := net.ParseIP(value); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				m[side+"_cidr"] = fmt.Sprintf("%s/%d", ip.String(), bits)
				delete(m, key)
			}
		}
	}
	allowed := " src_ip dst_ip src_cidr dst_cidr src_port dst_port protocol ttl dscp icmp_type icmp_code fragment pkt_len tcp_flags match_anomaly action rate_limit enabled comment claim_ref "
	for key, value := range m {
		if value == "" || !strings.Contains(allowed, " "+key+" ") {
			drop(key)
		}
	}
	m["claim_ref"] = claimRef
	if len(dropped) > 0 {
		sort.Strings(dropped)
		hints = append(hints, "dropped: "+strings.Join(dropped, ", "))
	}
	out, _ := json.Marshal(m)
	return out, hints
}

// XDropHTTPError preserves the v3 code and field in user-visible failures.
func XDropHTTPError(status int, body []byte) string {
	var detail struct{ Code, Field, Message string }
	if status >= 400 && json.Unmarshal(body, &detail) == nil && detail.Code != "" {
		field := ""
		if detail.Field != "" {
			field = " field=" + detail.Field
		}
		return fmt.Sprintf("HTTP %d %s%s: %s", status, detail.Code, field, detail.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", status, truncateStr(string(body), 1024))
}

type XDropDelivery struct {
	RuleID    string `json:"rule_id"`
	TargetGen uint64 `json:"target_gen"`
	Epoch     string `json:"epoch"`
	Nodes     []struct {
		Name  string `json:"name"`
		State string `json:"state"`
		Code  string `json:"code,omitempty"`
		Error string `json:"error,omitempty"`
	} `json:"nodes"`
}

// QueryXDropDelivery returns nil for an absent rule and retries one stale epoch.
func QueryXDropDelivery(ctx context.Context, conn store.XDropConnector, ruleID string) (*XDropDelivery, error) {
	timeout := 10 * time.Second
	if conn.TimeoutMs > 0 {
		timeout = time.Duration(conn.TimeoutMs) * time.Millisecond
	}
	client := &http.Client{Timeout: timeout}
	get := func(path string) ([]byte, int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(conn.APIURL, "/")+path, nil)
		if err != nil {
			return nil, 0, err
		}
		SetXDropAuth(req, conn.APIKey)
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return body, resp.StatusCode, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		body, status, err := get("/nodes")
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("%s", XDropHTTPError(status, body))
		}
		var nodes struct{ Epoch string }
		if err := json.Unmarshal(body, &nodes); err != nil {
			return nil, err
		}
		if nodes.Epoch == "" {
			return nil, fmt.Errorf("v3 nodes epoch missing")
		}
		body, status, err = get("/rules/" + url.PathEscape(ruleID) + "/delivery?gen=0&epoch=" + url.QueryEscape(nodes.Epoch))
		if err != nil {
			return nil, err
		}
		var detail struct{ Code string }
		_ = json.Unmarshal(body, &detail)
		if status == http.StatusConflict && detail.Code == "gen_epoch_mismatch" && attempt == 0 {
			continue
		}
		if status == http.StatusNotFound {
			return nil, nil
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("%s", XDropHTTPError(status, body))
		}
		var delivery XDropDelivery
		if err := json.Unmarshal(body, &delivery); err != nil {
			return nil, err
		}
		return &delivery, nil
	}
	return nil, fmt.Errorf("gen_epoch_mismatch")
}
