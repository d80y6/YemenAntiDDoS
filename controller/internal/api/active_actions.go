package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func queryXDropDelivery(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		connectorID, err := strconv.Atoi(c.Query("connector_id"))
		ruleID := c.Query("rule_id")
		if err != nil || connectorID <= 0 || ruleID == "" {
			errResponse(c, http.StatusBadRequest, "invalid connector_id or rule_id")
			return
		}
		conn, err := deps.Store.XDropConnectors().Get(c, connectorID)
		if err != nil || conn == nil || !conn.Enabled {
			errResponse(c, http.StatusNotFound, "xdrop connector not found")
			return
		}
		delivery, err := action.QueryXDropDelivery(c.Request.Context(), *conn, ruleID)
		if err != nil {
			errResponse(c, http.StatusBadGateway, err.Error())
			return
		}
		if delivery == nil {
			ok(c, gin.H{"found": false})
			return
		}
		ok(c, delivery)
	}
}

// ActiveResponseAction is the aggregated view of an active xDrop rule or BGP route.
type ActiveResponseAction struct {
	AttackID       int        `json:"attack_id"`
	AttackDstIP    string     `json:"attack_dst_ip"`
	ActionID       int        `json:"action_id"`
	ActionType     string     `json:"action_type"` // "xdrop" | "bgp"
	ConnectorName  string     `json:"connector_name"`
	ConnectorID    int        `json:"connector_id"`
	ExternalRuleID string     `json:"external_rule_id"`
	CreatedAt      time.Time  `json:"created_at"`
	Status         string     `json:"status"` // active | delayed | pending | failed
	ScheduledFor   *time.Time `json:"scheduled_for,omitempty"`
	// xDrop-specific (parsed from request_body)
	DstIP     string `json:"dst_ip,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	TcpFlags  string `json:"tcp_flags,omitempty"`
	Action    string `json:"action,omitempty"` // drop | rate_limit
	SrcPort   int    `json:"src_port,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	RateLimit int    `json:"rate_limit,omitempty"`
	// BGP-specific (parsed from external_rule_id)
	Prefix   string `json:"prefix,omitempty"`
	RouteMap string `json:"route_map,omitempty"`
	// v1.2 PR-5: flag orphan BGP announcements — FRR route exists without a
	// matching active attack. Frontend shows these in a warning banner and
	// operator uses dedicated endpoints (orphan-force-withdraw / orphan-dismiss)
	// rather than the per-artifact force-remove flow.
	IsOrphan       bool `json:"is_orphan,omitempty"`
	AnnouncementID int  `json:"announcement_id,omitempty"` // BGP: PR-5 announcement row ID
	// BGP: "rtbh" (whole-prefix blackhole) or "flowspec" (narrower match).
	// Flowspec rows also carry the rendered CLI so the operator can inspect
	// and copy the exact rule that is live in FRR.
	Kind     string   `json:"kind,omitempty"`
	Vendor   string   `json:"vendor,omitempty"`
	Commands []string `json:"commands,omitempty"`
	// BGP: list of all attacks that have attached to this announcement (history
	// + currently attached). Operators need this to see which attack(s) are
	// referencing a shared announcement when refcount > 1. attack_id in the
	// outer field remains the single "representative" (first active) for
	// backward compat; AttachedAttacks carries the complete picture.
	AttachedAttacks []AttachedAttackInfo `json:"attached_attacks,omitempty"`
}

// AttachedAttackInfo is a compact per-attack view attached to a BGP
// announcement, surfaced in Mitigations detail so the operator can see who
// else references a shared announcement.
type AttachedAttackInfo struct {
	AttackID     int        `json:"attack_id"`
	DstIP        string     `json:"dst_ip"`
	Decoder      string     `json:"decoder,omitempty"` // decoder_family from attacks
	ResponseName string     `json:"response_name,omitempty"`
	DelayMinutes int        `json:"delay_minutes"` // per-attack config snapshot
	AttachedAt   time.Time  `json:"attached_at"`
	DetachedAt   *time.Time `json:"detached_at,omitempty"` // nil = currently attached
}

func listActiveBGPRoutes(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		// v1.2 PR-5: BGP Mitigations now reads from bgp_announcements state
		// table (refcount-managed, authoritative) instead of reverse-engineering
		// state from action_execution_log.
		actions, err := buildActiveBGPFromAnnouncements(c, deps.Store)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, actions)
	}
}

// buildActiveBGPFromAnnouncements queries bgp_announcements directly.
// Each announcement maps to one UI row. Status mapping:
//
//	active / announcing    → "active"
//	delayed                → "delayed" (UI shows countdown via delay_started_at + delay_minutes)
//	withdrawing            → hidden (internal recovery state; rare)
//	failed                 → "failed" (UI surfaces for operator retry)
//	orphan                 → "orphan" (UI surfaces in warning banner)
//
// Multiple attacks sharing the same announcement collapse into one row,
// matching the refcount-based lifecycle. This is the Wanguard-style view
// that replaces the per-attack log-derivation of v1.1.x.
func buildActiveBGPFromAnnouncements(ctx *gin.Context, s store.Store) ([]ActiveResponseAction, error) {
	anns, err := s.BGPAnnouncements().ListActive(ctx)
	if err != nil {
		return nil, err
	}
	var result []ActiveResponseAction
	for _, ann := range anns {
		// Skip internal/transient states that shouldn't appear in the UI.
		if ann.Status == "withdrawing" || ann.Status == "announcing" {
			// Only hide 'announcing' if it's stale — but during normal
			// operation the transition to 'active' is sub-second, so hide
			// both. reconcile will clean up long-stuck rows.
			continue
		}

		// Map to UI status.
		apiStatus := "active"
		isOrphan := false
		switch ann.Status {
		case "active":
			apiStatus = "active"
		case "delayed":
			apiStatus = "delayed"
		case "failed":
			apiStatus = "failed"
		case "orphan":
			apiStatus = "orphan"
			isOrphan = true
		default:
			log.Printf("WARN api: buildActiveBGPFromAnnouncements unknown status %q id=%d; row hidden from Mitigations", ann.Status, ann.ID)
			continue
		}

		// Compute ScheduledFor for delayed rows.
		var scheduledFor *time.Time
		if ann.Status == "delayed" && ann.DelayStartedAt != nil && ann.DelayMinutes > 0 {
			sf := ann.DelayStartedAt.Add(time.Duration(ann.DelayMinutes) * time.Minute)
			scheduledFor = &sf
		}

		// For non-orphan: look up attack attachment for display.
		// For orphan: attack_id/action_id stay 0 — operator acts on the
		// announcement directly via orphan-force-withdraw / orphan-dismiss.
		attackID := 0
		attackDstIP := ""
		actionID := 0
		var attachedAttacks []AttachedAttackInfo
		if !isOrphan {
			attacks, _ := s.BGPAnnouncements().ListAttacks(ctx, ann.ID)
			if ann.FirstActionID != nil {
				actionID = *ann.FirstActionID
			}
			// Build full attack list (currently attached + history) so the
			// Mitigations detail drawer can show which attacks reference this
			// announcement. Currently-attached rows (detached_at IS NULL) come
			// first; detached rows follow in most-recent order.
			// Split into active (detached_at IS NULL) and detached lists so we
			// can show ALL active (operator must see who currently references
			// this announcement) while capping detached history at a sensible
			// size for the drawer. Also filter to the CURRENT cycle: attacks
			// whose attached_at predates the most recent announced_at belong
			// to a prior cycle (announcement was resurrected) and would only
			// clutter the operator view — look them up in DB if needed.
			atkCache := map[int]*store.Attack{}
			var activeInfos, detachedInfos []AttachedAttackInfo
			for _, a := range attacks {
				// Skip prior-cycle attaches.
				if a.AttachedAt.Before(ann.AnnouncedAt) {
					continue
				}
				if a.DetachedAt == nil && attackID == 0 {
					attackID = a.AttackID
					if a.ActionID != nil {
						actionID = *a.ActionID
					}
				}
				info := AttachedAttackInfo{
					AttackID:     a.AttackID,
					DelayMinutes: a.DelayMinutes,
					AttachedAt:   a.AttachedAt,
					DetachedAt:   a.DetachedAt,
					ResponseName: a.ResponseName,
				}
				atk, cached := atkCache[a.AttackID]
				if !cached {
					atk, _ = s.Attacks().Get(ctx, a.AttackID)
					atkCache[a.AttackID] = atk
				}
				if atk != nil {
					info.DstIP = atk.DstIP
					info.Decoder = atk.DecoderFamily
				}
				if a.DetachedAt == nil {
					activeInfos = append(activeInfos, info)
				} else {
					detachedInfos = append(detachedInfos, info)
				}
			}
			// Cap detached history at 30, sorted by detached_at DESC (most
			// recent first). attached_at order is not equivalent when a
			// long-running attack detaches after shorter ones, so sort
			// explicitly.
			sort.SliceStable(detachedInfos, func(i, j int) bool {
				a, b := detachedInfos[i].DetachedAt, detachedInfos[j].DetachedAt
				if a == nil || b == nil {
					return false
				}
				return a.After(*b)
			})
			const detachedCap = 30
			if len(detachedInfos) > detachedCap {
				detachedInfos = detachedInfos[:detachedCap]
			}
			attachedAttacks = append(activeInfos, detachedInfos...)
			// Fallback: when no active attack remains (delayed/failed), take
			// the most recently-detached one as display anchor so the top-level
			// attack_id still resolves.
			if attackID == 0 && len(attacks) > 0 {
				attackID = attacks[0].AttackID
				if attacks[0].ActionID != nil {
					actionID = *attacks[0].ActionID
				}
			}
			if attackID > 0 {
				if atk, ok := atkCache[attackID]; ok && atk != nil {
					attackDstIP = atk.DstIP
				}
			}
		}
		// Connector name.
		connName := ""
		var connRef *store.BGPConnector
		if conn, err := s.BGPConnectors().Get(ctx, ann.ConnectorID); err == nil && conn != nil {
			connName = conn.Name
			connRef = conn
		}
		externalRuleID := ann.Prefix + "|" + ann.RouteMap

		kind := ann.Kind
		if kind == "" {
			kind = "rtbh"
		}
		vendor := ""
		var commands []string
		if kind == "flowspec" {
			view := buildFlowspecView(ann, connRef)
			vendor = view.Vendor
			commands = view.Commands
		}

		result = append(result, ActiveResponseAction{
			AttackID:        attackID,
			AttackDstIP:     attackDstIP,
			ActionID:        actionID,
			ActionType:      "bgp",
			ConnectorName:   connName,
			ConnectorID:     ann.ConnectorID,
			ExternalRuleID:  externalRuleID,
			CreatedAt:       ann.AnnouncedAt,
			Status:          apiStatus,
			ScheduledFor:    scheduledFor,
			Prefix:          ann.Prefix,
			RouteMap:        ann.RouteMap,
			IsOrphan:        isOrphan,
			AnnouncementID:  ann.ID,
			Kind:            kind,
			Vendor:          vendor,
			Commands:        commands,
			AttachedAttacks: attachedAttacks,
		})
	}
	return result, nil
}

func listActiveXDropRules(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		// v1.2 PR-4: xDrop Mitigations now reads from xdrop_active_rules state
		// table (authoritative) instead of reverse-engineering state from
		// action_execution_log. BGP still uses the log-based path until PR-5.
		actions, err := buildActiveXDropFromTable(c, deps.Store)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, actions)
	}
}

// buildActiveXDropFromTable queries xdrop_active_rules directly. Status
// mapping:
//
//	table.status='active'      → "active"
//	table.status='delayed'     → "delayed" (Mitigations UI shows countdown)
//	table.status='failed'      → "failed"  (Mitigations UI surfaces for retry)
//
// Rows in 'withdrawing' and 'withdrawn' are hidden (withdrawing is an internal
// recovery state; withdrawn is audit-only).
func buildActiveXDropFromTable(ctx *gin.Context, s store.Store) ([]ActiveResponseAction, error) {
	rules, err := s.XDropActiveRules().ListActive(ctx)
	if err != nil {
		return nil, err
	}
	// Cache attack + action lookups to avoid N round-trips — most rules
	// cluster onto a small number of attacks.
	attackCache := map[int]*store.Attack{}
	// For the xDrop request_body parsing (protocol/action/ports), we still
	// need the original execution log's request body. Fetch per-attack once.
	logsByAttack := map[int][]store.ActionExecutionLog{}

	var result []ActiveResponseAction
	for _, r := range rules {
		atk, ok := attackCache[r.AttackID]
		if !ok {
			a, err := s.Attacks().Get(ctx, r.AttackID)
			if err != nil {
				// Attack disappeared (DB FK SET NULL etc.) — skip gracefully.
				continue
			}
			attackCache[r.AttackID] = a
			atk = a
		}
		// Fetch the original on_detected log once per attack for request_body.
		logs, cached := logsByAttack[r.AttackID]
		if !cached {
			if fetched, err := s.ActionExecLog().ListByAttack(ctx, r.AttackID); err == nil {
				logs = fetched
			}
			logsByAttack[r.AttackID] = logs
		}
		var origLog *store.ActionExecutionLog
		for i := range logs {
			l := &logs[i]
			if l.ActionType == "xdrop" && l.TriggerPhase == "on_detected" && l.Status == "success" &&
				l.ExternalRuleID == r.ExternalRuleID && l.ActionID == r.ActionID &&
				l.ConnectorID != nil && *l.ConnectorID == r.ConnectorID {
				origLog = l
				break
			}
		}

		connectorName := ""
		if origLog != nil {
			connectorName = origLog.ConnectorName
		}
		// Map state table status → API status enum
		var apiStatus string
		switch r.Status {
		case "active":
			apiStatus = "active"
		case "delayed":
			apiStatus = "delayed"
		case "failed":
			apiStatus = "failed"
		default:
			log.Printf("WARN api: buildActiveXDropFromTable unknown status %q id=%d; row hidden from Mitigations", r.Status, r.ID)
			continue // shouldn't happen: ListActive filters these
		}

		item := ActiveResponseAction{
			AttackID:       r.AttackID,
			AttackDstIP:    atk.DstIP,
			ActionID:       r.ActionID,
			ActionType:     "xdrop",
			ConnectorName:  connectorName,
			ConnectorID:    r.ConnectorID,
			ExternalRuleID: r.ExternalRuleID,
			CreatedAt:      r.CreatedAt,
			Status:         apiStatus,
			DstIP:          atk.DstIP,
		}
		// Compute ScheduledFor from delay_started_at + delay_minutes when delayed.
		if r.Status == "delayed" && r.DelayStartedAt != nil && r.DelayMinutes > 0 {
			sf := r.DelayStartedAt.Add(time.Duration(r.DelayMinutes) * time.Minute)
			item.ScheduledFor = &sf
		}
		if origLog != nil && origLog.RequestBody != "" {
			parseXDropRequestBody(origLog.RequestBody, &item)
		}
		result = append(result, item)
	}
	return result, nil
}

func parseXDropRequestBody(body string, item *ActiveResponseAction) {
	// Simple JSON field extraction without full unmarshal
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return
	}
	if v, ok := m["action"].(string); ok {
		item.Action = v
	}
	if v, ok := m["protocol"].(string); ok {
		item.Protocol = v
	}
	if v, ok := m["tcp_flags"].(string); ok {
		item.TcpFlags = v
	}
	if v, ok := m["dst_ip"].(string); ok {
		item.DstIP = v
	} else if v, ok := m["dst_cidr"].(string); ok {
		item.DstIP = v
	}
	item.SrcPort = xdropRequestInt(m["src_port"])
	item.DstPort = xdropRequestInt(m["dst_port"])
	item.RateLimit = xdropRequestInt(m["rate_limit"])
}

func xdropRequestInt(value any) int {
	var text string
	switch v := value.(type) {
	case float64:
		text = strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		for _, digit := range v {
			if digit < '0' || digit > '9' {
				return 0
			}
		}
		text = v
	default:
		return 0
	}
	result, err := strconv.Atoi(text)
	if err != nil {
		return 0
	}
	return result
}

func forceRemoveAction(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AttackID       int    `json:"attack_id" binding:"required"`
			ActionID       int    `json:"action_id" binding:"required"`
			ConnectorID    int    `json:"connector_id" binding:"required"`
			ExternalRuleID string `json:"external_rule_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}

		// Cancel pending delay for this specific artifact (full business key)
		if deps.ActionEngine != nil {
			deps.ActionEngine.CancelDelay(req.AttackID, req.ActionID, req.ConnectorID, req.ExternalRuleID)
		}

		// Execute the removal first, then write log with actual result
		removeErr := deps.ActionEngine.ForceRemove(c, req.AttackID, req.ActionID, req.ConnectorID, req.ExternalRuleID)

		warning := ""
		overrideLog := &store.ActionExecutionLog{
			AttackID:       req.AttackID,
			ActionID:       req.ActionID,
			ActionType:     "manual_override",
			TriggerPhase:   "manual_override",
			ConnectorID:    &req.ConnectorID,
			ExternalRuleID: req.ExternalRuleID,
			ExecutedAt:     time.Now(),
		}
		if removeErr != nil {
			overrideLog.Status = "failed"
			overrideLog.ErrorMessage = removeErr.Error()
			overrideLog.ResponseBody = "force remove failed"
		} else {
			overrideLog.Status = "success"
			overrideLog.ResponseBody = "force removed by user"
		}
		// v1.2 PR-2: write to indexed action_manual_overrides table for O(1)
		// lookup after success. BGP ForceRemove already persists overrides
		// for every detached attachment before vtysh, even if withdrawal fails.
		// Idempotent via ON CONFLICT in repo.Create.
		if removeErr == nil {
			override := &store.ActionManualOverride{
				AttackID:       req.AttackID,
				ActionID:       req.ActionID,
				ConnectorID:    req.ConnectorID,
				ExternalRuleID: req.ExternalRuleID,
			}
			if _, mErr := deps.Store.ManualOverrides().Create(c, override); mErr != nil {
				metrics.StateWriteFailures.WithLabelValues("force_remove_override").Inc()
				warning += "override not saved; periodic actions may recreate this rule. "
				log.Printf("action: manual_override index insert failed (artifact removed but suppression not indexed): %v", mErr)
			}
			// v1.2 PR-4: the xDrop Mitigations tab now queries xdrop_active_rules
			// authoritatively. Force Unblock must also transition the state row
			// to withdrawn so the rule disappears from the UI. UPDATE is a no-op
			// for BGP artifacts (no matching row), so this call is safe to make
			// unconditionally for any action type.
			if mwErr := deps.Store.XDropActiveRules().MarkWithdrawn(c, req.AttackID, req.ActionID, req.ConnectorID, req.ExternalRuleID); mwErr != nil {
				metrics.StateWriteFailures.WithLabelValues("force_remove_mark_withdrawn").Inc()
				warning += "xDrop MarkWithdrawn not saved; rule may remain visible as active. "
				log.Printf("action: force-remove xdrop_active_rules MarkWithdrawn failed: %v", mwErr)
			}
		}
		if _, err := deps.Store.ActionExecLog().Create(c, overrideLog); err != nil {
			if removeErr != nil {
				errResponse(c, http.StatusInternalServerError, forceRemoveFailure(c, removeErr))
				return
			}
			// External removal already executed — log write failed but artifact is gone
			log.Printf("action: force-remove audit log write failed (artifact already removed externally): %v", err)
			ok(c, gin.H{
				"ok":      true,
				"warning": warning + "force remove succeeded but audit log write failed — artifact was removed externally",
			})
			return
		}

		// Write audit log
		auditDiff, _ := json.Marshal(map[string]any{
			"user":             c.GetString("username"),
			"attack_id":        req.AttackID,
			"action_id":        req.ActionID,
			"connector_id":     req.ConnectorID,
			"external_rule_id": req.ExternalRuleID,
			"result":           overrideLog.Status,
		})
		publishAfterChange(c, deps, "active_action", fmt.Sprintf("attack:%d:rule:%s", req.AttackID, req.ExternalRuleID),
			"force_remove", json.RawMessage(auditDiff))

		if removeErr != nil {
			errResponse(c, http.StatusInternalServerError, forceRemoveFailure(c, removeErr))
			return
		}

		result := gin.H{
			"ok":      true,
			"message": fmt.Sprintf("force removed %s (attack #%d)", req.ExternalRuleID, req.AttackID),
		}
		if warning != "" {
			result["warning"] = warning
		}
		ok(c, result)
	}
}

// v1.2 PR-5: orphanForceWithdraw triggers ForceWithdraw on a BGP announcement
// that has no attack attached (typically discovered by bootstrap when a stale
// FRR route had no matching active attack). Unlike force-remove, this endpoint
// does NOT require attack_id/action_id — it operates purely at the
// announcement level.
func orphanForceWithdraw(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AnnouncementID int `json:"announcement_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if deps.ActionEngine != nil {
			unlock := deps.ActionEngine.LockAnnouncement(req.AnnouncementID)
			defer unlock()
		}
		ann, err := deps.Store.BGPAnnouncements().Get(c, req.AnnouncementID)
		if err != nil || ann == nil {
			errResponse(c, http.StatusNotFound, "announcement not found")
			return
		}
		if ann.Status != "orphan" {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf("announcement %d status=%s is not orphan; use /force-remove instead", ann.ID, ann.Status))
			return
		}
		// Look up connector for vtysh command.
		conn, cErr := deps.Store.BGPConnectors().Get(c, ann.ConnectorID)
		if cErr != nil {
			dbError(c, "lookup connector: ", cErr)
			return
		}
		// Force withdraw transitions the announcement to withdrawing; no
		// refcount dance (there are no attached attacks for orphan).
		_, gen, err := deps.Store.BGPAnnouncements().ForceWithdraw(c, ann.ID)
		if err != nil {
			dbError(c, "", err)
			return
		}
		// Cancel any delay timer (shouldn't be armed for orphan, but idempotent).
		if deps.ActionEngine != nil {
			if gen != ann.Gen {
				deps.ActionEngine.NoteAnnouncementTakeover(ann.ID)
			}
			deps.ActionEngine.CancelAnnouncementDelay(ann.ID, gen, "orphan force withdraw")
		}
		// Run vtysh no network directly via action.performBGPWithdraw by
		// constructing a synthetic ResponseAction (no real action row exists).
		// Leverage the existing PR-5 code path for logging + MarkWithdrawn/Failed.
		synthAct := store.ResponseAction{ID: 0, ActionType: "bgp", BGPRouteMap: ann.RouteMap}
		connID := ann.ConnectorID
		synthAct.BGPConnectorID = &connID
		_, wErr := action.PerformBGPWithdrawForOrphan(c, deps.Store, conn, synthAct, ann.Prefix, ann.RouteMap, ann.ID, gen)
		if wErr != nil {
			log.Printf("api: orphan force withdraw announcement_id=%d vtysh failed: %v", ann.ID, wErr)
			ok(c, gin.H{"ok": true, "warning": fmt.Sprintf("vtysh error: %v (row marked failed)", wErr)})
			return
		}
		diff, _ := json.Marshal(map[string]any{"announcement_id": ann.ID, "prefix": ann.Prefix, "route_map": ann.RouteMap})
		publishAfterChange(c, deps, "bgp_orphan_force_withdraw", fmt.Sprintf("%d", ann.ID), "force_withdraw", diff)
		ok(c, gin.H{"ok": true, "announcement_id": ann.ID})
	}
}

// DismissedOrphan is the read model for the "View dismissed orphans" list.
// Fields are intentionally narrow — operator only needs identity and time
// to decide whether to un-dismiss.
type DismissedOrphan struct {
	AnnouncementID int       `json:"announcement_id"`
	Prefix         string    `json:"prefix"`
	RouteMap       string    `json:"route_map"`
	ConnectorID    int       `json:"connector_id"`
	ConnectorName  string    `json:"connector_name"`
	Status         string    `json:"status"` // "dismissed" | "dismissed_on_upgrade"
	DetectedAt     time.Time `json:"detected_at"`
}

// listDismissedOrphans returns announcements that were dismissed either by an
// operator (status=dismissed) or auto-dismissed during a first-upgrade
// bootstrap (status=dismissed_on_upgrade). Used by the Mitigations UI
// "View dismissed orphans" collapsible section.
func listDismissedOrphans(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		anns, err := deps.Store.BGPAnnouncements().ListDismissed(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		connCache := map[int]string{}
		out := make([]DismissedOrphan, 0, len(anns))
		for _, a := range anns {
			name, cached := connCache[a.ConnectorID]
			if !cached {
				if conn, err := deps.Store.BGPConnectors().Get(c, a.ConnectorID); err == nil && conn != nil {
					name = conn.Name
				}
				connCache[a.ConnectorID] = name
			}
			out = append(out, DismissedOrphan{
				AnnouncementID: a.ID,
				Prefix:         a.Prefix,
				RouteMap:       a.RouteMap,
				ConnectorID:    a.ConnectorID,
				ConnectorName:  name,
				Status:         a.Status,
				DetectedAt:     a.AnnouncedAt,
			})
		}
		ok(c, out)
	}
}

// orphanUndismiss moves a dismissed / dismissed_on_upgrade row back to orphan
// so it re-surfaces in the warning banner. Used when the operator dismissed
// by mistake or wants to re-review. FRR is not touched; the next orphan-pass
// will reconcile based on current FRR state.
func orphanUndismiss(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AnnouncementID int `json:"announcement_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		ann, err := deps.Store.BGPAnnouncements().Get(c, req.AnnouncementID)
		if err != nil || ann == nil {
			errResponse(c, http.StatusNotFound, "announcement not found")
			return
		}
		if ann.Status != "dismissed" && ann.Status != "dismissed_on_upgrade" {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf("announcement %d status=%s cannot be undismissed", ann.ID, ann.Status))
			return
		}
		if err := deps.Store.BGPAnnouncements().Undismiss(c, ann.ID); err != nil {
			dbError(c, "", err)
			return
		}
		diff, _ := json.Marshal(map[string]any{"announcement_id": ann.ID, "prefix": ann.Prefix, "route_map": ann.RouteMap})
		publishAfterChange(c, deps, "bgp_orphan_undismiss", fmt.Sprintf("%d", ann.ID), "undismiss", diff)
		ok(c, gin.H{"ok": true, "announcement_id": ann.ID})
	}
}

// v1.2 PR-5: orphanDismiss marks an orphan announcement as dismissed.
// Operator uses this when they've confirmed the FRR route is managed by
// another system and xSight should stop showing it in the banner.
// Does NOT touch FRR.
func orphanDismiss(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			AnnouncementID int `json:"announcement_id" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		ann, err := deps.Store.BGPAnnouncements().Get(c, req.AnnouncementID)
		if err != nil || ann == nil {
			errResponse(c, http.StatusNotFound, "announcement not found")
			return
		}
		if ann.Status != "orphan" {
			errResponse(c, http.StatusBadRequest, fmt.Sprintf("announcement %d status=%s is not orphan; can only dismiss orphans", ann.ID, ann.Status))
			return
		}
		if err := deps.Store.BGPAnnouncements().Dismiss(c, ann.ID); err != nil {
			dbError(c, "", err)
			return
		}
		diff, _ := json.Marshal(map[string]any{"announcement_id": ann.ID, "prefix": ann.Prefix, "route_map": ann.RouteMap})
		publishAfterChange(c, deps, "bgp_orphan_dismiss", fmt.Sprintf("%d", ann.ID), "dismiss", diff)
		ok(c, gin.H{"ok": true, "announcement_id": ann.ID})
	}
}

// getArtifactTimeline returns the full execution log timeline for a single mitigation artifact.
func getArtifactTimeline(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		attackID, _ := strconv.Atoi(c.Query("attack_id"))
		connectorID, _ := strconv.Atoi(c.Query("connector_id"))
		externalRuleID := c.Query("external_rule_id")
		if attackID == 0 || externalRuleID == "" {
			errResponse(c, http.StatusBadRequest, "attack_id and external_rule_id are required")
			return
		}

		logs, err := deps.Store.ActionExecLog().ListByAttack(c, attackID)
		if err != nil {
			dbError(c, "", err)
			return
		}

		// Filter logs matching this artifact's business key
		var timeline []store.ActionExecutionLog
		for _, l := range logs {
			if l.ExternalRuleID != externalRuleID {
				continue
			}
			cid := 0
			if l.ConnectorID != nil {
				cid = *l.ConnectorID
			}
			if connectorID > 0 && cid > 0 && cid != connectorID {
				continue
			}
			timeline = append(timeline, l)
		}

		// Reverse to chronological order (ListByAttack returns DESC)
		for i, j := 0, len(timeline)-1; i < j; i, j = i+1, j-1 {
			timeline[i], timeline[j] = timeline[j], timeline[i]
		}

		atk, _ := deps.Store.Attacks().Get(c, attackID)

		ok(c, gin.H{
			"attack": atk,
			"logs":   timeline,
		})
	}
}

// forceRemoveFailure hides both database and upstream error details from HTTP.
func forceRemoveFailure(c *gin.Context, removeErr error) string {
	log.Printf("ERROR api: %s %s: force remove failed: %v", c.Request.Method, c.FullPath(), removeErr)
	return "force remove failed"
}
