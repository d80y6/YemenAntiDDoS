package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/gin-gonic/gin"
)

func listAttacks(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		filter := store.AttackFilter{
			Limit:  50,
			Offset: 0,
		}
		if s := c.Query("sort"); s != "" {
			if s != "started_at" && s != "peak_pps" {
				errResponse(c, http.StatusBadRequest, "sort must be 'started_at' or 'peak_pps'")
				return
			}
			filter.Sort = s
		}
		if dstIP, present := c.Request.URL.Query()["dst_ip"]; present {
			value := dstIP[0]
			if net.ParseIP(value) == nil {
				if _, _, err := net.ParseCIDR(value); err != nil {
					errResponse(c, http.StatusBadRequest, "invalid dst_ip")
					return
				}
			}
			filter.DstIP = value
		}
		if endedAfter, present := c.Request.URL.Query()["ended_after"]; present {
			value, err := time.Parse(time.RFC3339, endedAfter[0])
			if err != nil {
				errResponse(c, http.StatusBadRequest, "invalid ended_after")
				return
			}
			filter.EndedAfter = &value
		}
		if s := c.Query("status"); s != "" {
			filter.Status = s
		}
		if d := c.Query("direction"); d != "" {
			if d != "receives" && d != "sends" {
				errResponse(c, http.StatusBadRequest, "direction must be 'receives' or 'sends'")
				return
			}
			filter.Direction = d
		}
		if pid := c.Query("prefix_id"); pid != "" {
			id, _ := strconv.Atoi(pid)
			filter.PrefixID = &id
		}
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				filter.TimeFrom = &t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				filter.TimeTo = &t
			}
		}
		if lim := c.Query("limit"); lim != "" {
			filter.Limit, _ = strconv.Atoi(lim)
		}
		if off := c.Query("offset"); off != "" {
			filter.Offset, _ = strconv.Atoi(off)
		}
		// Hard cap to prevent oversized responses
		if filter.Limit > 200 {
			filter.Limit = 200
		}

		attacks, err := deps.Store.Attacks().List(c, filter)
		if err != nil {
			dbError(c, "", err)
			return
		}
		total, err := deps.Store.Attacks().Count(c, filter)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, gin.H{
			"attacks": attacks,
			"total":   total,
		})
	}
}

func listActiveAttacks(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 100
		if l := c.Query("limit"); l != "" {
			limit, _ = strconv.Atoi(l)
		}
		attacks, err := deps.Store.Attacks().ListActive(c, limit)
		if err != nil {
			dbError(c, "", err)
			return
		}
		activeCount, _ := deps.Store.Attacks().CountActive(c)
		// Only return timers for the attacks in this result set
		allTimers := deps.Tracker.ActiveTimers()
		resultTimers := make(map[int]tracker.AttackTimer, len(attacks))
		current := make(map[int]attackCurrent)
		for _, a := range attacks {
			if t, ok := allTimers[a.ID]; ok {
				resultTimers[a.ID] = t
				if deps.ProfileEngine != nil && deps.ProfileEngine.Rings() != nil {
					if value, found := currentAttackTraffic(c, deps.ProfileEngine.Rings(), deps.Store.Prefixes(), a, t); found {
						current[a.ID] = value
					}
				}
			}
		}
		resp := gin.H{
			"attacks":       attacks,
			"active_count":  activeCount,
			"returned":      len(attacks),
			"tracker_count": deps.Tracker.ActiveCount(),
			"timers":        resultTimers,
		}
		if len(current) > 0 {
			resp["current"] = current
		}
		ok(c, resp)
	}
}

type attackTrafficRings interface {
	AllNodePrefixes() []ring.NodePrefix
	AllOutboundNodePrefixes() []ring.NodePrefix
	LatestIPByKey(string, string, string, time.Duration) (ring.DataPoint, bool)
	LatestSrcIPByKey(string, string, string, time.Duration) (ring.DataPoint, bool)
	LatestPrefix(string, string, time.Duration) (ring.DataPoint, bool)
	LatestSrcPrefix(string, string, time.Duration) (ring.DataPoint, bool)
}

type attackCurrent struct {
	PPS int64 `json:"pps"`
	BPS int64 `json:"bps"`
}

// Call only after ActiveTimers has released the tracker lock.
func currentAttackTraffic(ctx context.Context, rings attackTrafficRings, prefixes store.PrefixRepo, attack store.Attack, timer tracker.AttackTimer) (attackCurrent, bool) {
	var current attackCurrent
	if rings == nil || attack.EndedAt != nil {
		return current, false
	}
	target, err := netip.ParsePrefix(attack.DstIP)
	var ip string
	var prefix string
	if err == nil {
		if target.Bits() == target.Addr().BitLen() {
			ip = target.Addr().String()
		} else {
			prefix = target.Masked().String()
		}
	} else {
		addr, addrErr := netip.ParseAddr(attack.DstIP)
		if addrErr != nil {
			return current, false
		}
		ip = addr.String()
	}
	if ip != "" {
		prefix = timer.Prefix
		if prefix == "" {
			if attack.PrefixID == nil || prefixes == nil {
				return current, false
			}
			row, getErr := prefixes.Get(ctx, *attack.PrefixID)
			if getErr != nil || row == nil {
				return current, false
			}
			parsed, parseErr := netip.ParsePrefix(row.Prefix)
			if parseErr != nil {
				return current, false
			}
			prefix = parsed.Masked().String()
		}
	}
	nodes := rings.AllNodePrefixes()
	latestIP, latestPrefix := rings.LatestIPByKey, rings.LatestPrefix
	if attack.Direction == "sends" {
		nodes = rings.AllOutboundNodePrefixes()
		latestIP, latestPrefix = rings.LatestSrcIPByKey, rings.LatestSrcPrefix
	}
	foundAny := false
	for _, np := range nodes {
		if np.Prefix != prefix {
			continue
		}
		var point ring.DataPoint
		var found bool
		if ip != "" {
			point, found = latestIP(np.NodeID, prefix, ip, 10*time.Second)
		} else {
			point, found = latestPrefix(np.NodeID, prefix, 10*time.Second)
		}
		if found {
			foundAny = true
			current.PPS += point.PPS
			current.BPS += point.BPS
		}
	}
	return current, foundAny
}

// ActionExecutionLogView wraps store.ActionExecutionLog with v1.2.1 API
// enrichments that the frontend needs but don't belong in the persisted
// schema. BGPRole lets the Attack Detail page show whether this attack
// triggered the BGP route or attached to an existing one (shared).
// AnnouncementID/Refcount let the per-attack Force Remove popconfirm show
// a route-withdraw prompt that warns about every other attached
// attack losing protection, without a second round-trip.
type ActionExecutionLogView struct {
	store.ActionExecutionLog
	// BGPRole is populated for action_type=bgp on_detected entries. Values:
	//   "triggered"       — this attack was the first to attach to the
	//                       announcement (the vtysh announce call was its
	//                       side effect).
	//   "attached_shared" — this attack joined an existing announcement
	//                       (no vtysh announce; refcount incremented).
	//   ""                — either not BGP, not on_detected, or the
	//                       announcement row could not be found.
	BGPRole string `json:"bgp_role,omitempty"`
	// AnnouncementID is the bgp_announcements.id that this BGP log row
	// ultimately attached to. Zero if not a BGP row / announcement lookup
	// failed.
	AnnouncementID int `json:"announcement_id,omitempty"`
	// AnnouncementRefcount is the announcement's refcount at query time.
	// Frontend uses this to pick popconfirm wording (simple force-withdraw
	// when refcount<=1, full shared-route withdrawal warning when refcount>1).
	AnnouncementRefcount int `json:"announcement_refcount,omitempty"`
}

func getAttackActionLog(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid attack id"})
			return
		}
		logs, err := deps.Store.ActionExecLog().ListByAttack(c, id)
		if err != nil {
			dbError(c, "", err)
			return
		}
		if logs == nil {
			logs = []store.ActionExecutionLog{}
		}
		// Pre-compute BGP role for every BGP on_detected success entry in
		// one pass (one query per unique announcement, not per log row).
		views := enrichActionLogsWithBGPRole(c, deps.Store, id, logs)
		c.JSON(http.StatusOK, views)
	}
}

// enrichActionLogsWithBGPRole computes `bgp_role` for each BGP on_detected
// success entry by comparing this attack's attached_at with the earliest
// attach on the same announcement. Bounded queries: one
// ListAttachmentsForAttack + at most one ListAttacks per unique
// announcement. Ignores entries where the announcement lookup fails (best-
// effort enrichment).
func enrichActionLogsWithBGPRole(ctx context.Context, s store.Store, attackID int, logs []store.ActionExecutionLog) []ActionExecutionLogView {
	views := make([]ActionExecutionLogView, len(logs))
	for i, l := range logs {
		views[i] = ActionExecutionLogView{ActionExecutionLog: safeWebhookLog(l)}
	}

	// Which announcements has this attack attached to.
	attachments, err := s.BGPAnnouncements().ListAttachmentsForAttack(ctx, attackID)
	if err != nil || len(attachments) == 0 {
		return views
	}
	seenAnns := make(map[int]struct{}, len(attachments))
	for _, a := range attachments {
		seenAnns[a.AnnouncementID] = struct{}{}
	}

	// For each announcement, determine the IDENTITY of the attach that
	// actually triggered the vtysh announce FOR THE CURRENT CYCLE. Three
	// things at play:
	//
	//   1. Time equality is unstable — Postgres timestamp precision can
	//      collide for attaches inside the same transaction window, which
	//      would tag multiple rows as "triggered" despite only one vtysh
	//      side-effect firing. Sort tie-breaks by attack_id ASC (Attach's
	//      SELECT FOR UPDATE serializes, so earliest attached_at + lowest
	//      attack_id matches the actual insert order).
	//
	//   2. bgp_announcement_attacks is append-only across resurrects. A
	//      long-lived announcement that has cycled active → withdrawn →
	//      active accumulates prior-cycle attach rows with detached_at
	//      set. Picking MIN(attached_at) globally would always pin the
	//      role on a ghost attack from the very first cycle. Anchor on
	//      ann.AnnouncedAt (reset by the refcount model on each resurrect)
	//      and consider only this cycle's attaches — mirrors PR-7's
	//      attached_attacks cycle-filter on the Mitigations drawer.
	//
	//   3. We need ann.AnnouncedAt here, so fetch the announcement row
	//      once per unique annID inside the loop.
	triggerPerAnn := make(map[int]triggerIdentity, len(seenAnns))
	for annID := range seenAnns {
		ann, err := s.BGPAnnouncements().Get(ctx, annID)
		if err != nil || ann == nil {
			continue
		}
		atts, err := s.BGPAnnouncements().ListAttacks(ctx, annID)
		if err != nil || len(atts) == 0 {
			continue
		}
		cycleAtts := make([]store.BGPAnnouncementAttack, 0, len(atts))
		for _, a := range atts {
			if !a.AttachedAt.Before(ann.AnnouncedAt) {
				cycleAtts = append(cycleAtts, a)
			}
		}
		if len(cycleAtts) == 0 {
			continue
		}
		sort.SliceStable(cycleAtts, func(i, j int) bool {
			if !cycleAtts[i].AttachedAt.Equal(cycleAtts[j].AttachedAt) {
				return cycleAtts[i].AttachedAt.Before(cycleAtts[j].AttachedAt)
			}
			return cycleAtts[i].AttackID < cycleAtts[j].AttackID
		})
		first := cycleAtts[0]
		id := triggerIdentity{AttackID: first.AttackID}
		if first.ActionID != nil {
			id.ActionID = *first.ActionID
		}
		triggerPerAnn[annID] = id
	}

	// Match logs to announcements via external_rule_id ("prefix|route_map")
	// + connector_id. A log row inherits "triggered" iff its (attack_id,
	// action_id) matches the trigger identity of the CURRENT cycle on that
	// announcement. Cycle scoping matters because bgp_announcement_attacks
	// is append-only: prior-cycle rows (from attacks before the most recent
	// resurrect) persist with detached_at set, and naively picking the
	// minimum attached_at across all rows would always pin the role on a
	// ghost attack from a long-expired cycle.
	//
	// The cycle anchor is ann.AnnouncedAt (reset by the refcount model on
	// each resurrect); we filter the attach set by attached_at >= that
	// anchor and determine trigger identity from the cycle-scoped slice.
	// Mirrors the same cycle-filter used by buildActiveBGPFromAnnouncements
	// for the attached_attacks drawer list.
	for i := range views {
		entry := &views[i].ActionExecutionLog
		if entry.ActionType != "bgp" || entry.TriggerPhase != "on_detected" ||
			entry.Status != "success" || entry.ConnectorID == nil || entry.ExternalRuleID == "" {
			continue
		}
		parts := strings.SplitN(entry.ExternalRuleID, "|", 2)
		if len(parts) != 2 {
			continue
		}
		ann, err := s.BGPAnnouncements().FindByBusinessKey(ctx, parts[0], parts[1], *entry.ConnectorID)
		if err != nil || ann == nil {
			continue
		}
		trigger, ok := triggerPerAnn[ann.ID]
		if !ok {
			continue
		}
		if entry.AttackID == trigger.AttackID && entry.ActionID == trigger.ActionID {
			views[i].BGPRole = "triggered"
		} else {
			views[i].BGPRole = "attached_shared"
		}
		views[i].AnnouncementID = ann.ID
		views[i].AnnouncementRefcount = ann.Refcount
	}
	return views
}

// triggerIdentity is the (attack_id, action_id) tuple of the attach that
// triggered the vtysh announce for an announcement's current cycle.
type triggerIdentity struct {
	AttackID int
	ActionID int // 0 if attach carried nil action_id (rare, recovery paths)
}

func statsSummary(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		activeCount, err := deps.Store.Attacks().CountActive(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, storeInternal(c, "stats summary: attacks: ", err))
			return
		}

		// Count-oriented: don't pull full lists just to len()
		nodes, err := deps.Store.Nodes().List(c) // small table, OK
		if err != nil {
			errResponse(c, http.StatusInternalServerError, storeInternal(c, "stats summary: nodes: ", err))
			return
		}
		onlineCount := 0
		for _, n := range nodes {
			if deps.NodeState.IsOnline(n.ID) {
				onlineCount++
			}
		}

		prefixCount, err := deps.Store.Prefixes().Count(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, storeInternal(c, "stats summary: prefixes: ", err))
			return
		}
		thresholdCount, err := deps.Store.Thresholds().Count(c)
		if err != nil {
			errResponse(c, http.StatusInternalServerError, storeInternal(c, "stats summary: thresholds: ", err))
			return
		}

		resp := gin.H{
			"active_attacks":     activeCount,
			"total_nodes":        len(nodes),
			"online_nodes":       onlineCount,
			"total_prefixes":     prefixCount,
			"total_thresholds":   thresholdCount,
			"tracker_count":      deps.Tracker.ActiveCount(),
			"attacks_created":    deps.Tracker.CreatedTotal.Load(),
			"attacks_suppressed": deps.Tracker.SuppressedTotal.Load(),
			"attacks_evicted":    deps.Tracker.EvictedTotal.Load(),
		}
		if deps.ActionEngine != nil {
			resp["action_mode"] = deps.ActionEngine.Mode()
		}
		ok(c, resp)
	}
}

func getAttack(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		attack, err := deps.Store.Attacks().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "attack not found")
			return
		}
		// Include action execution logs (Response System v2)
		logs, err := deps.Store.ActionExecLog().ListByAttack(c, id)
		if err != nil {
			dbError(c, "failed to load action logs: ", err)
			return
		}
		logs = append([]store.ActionExecutionLog(nil), logs...)
		for i := range logs {
			logs[i] = safeWebhookLog(logs[i])
		}
		resp := gin.H{"attack": attack, "actions_log": logs}
		// Attach timer info for active attacks
		if attack.EndedAt == nil {
			timers := deps.Tracker.ActiveTimers()
			if t, ok := timers[id]; ok {
				resp["timer"] = t
				if deps.ProfileEngine != nil && deps.ProfileEngine.Rings() != nil {
					if value, found := currentAttackTraffic(c, deps.ProfileEngine.Rings(), deps.Store.Prefixes(), *attack, t); found {
						resp["current"] = value
					}
				}
			}
		}
		ok(c, resp)
	}
}

// expireAttack accepts hold_seconds to override the global in-memory manual expiry hold.
func expireAttack(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid attack id")
			return
		}
		raw, hasHold := c.GetQuery("hold_seconds")
		hold := 0
		if hasHold {
			hold, err = strconv.Atoi(raw)
			if err != nil || hold < 0 || hold > 86400 {
				errResponse(c, http.StatusBadRequest, "hold_seconds must be an integer between 0 and 86400")
				return
			}
		}
		attack, err := deps.Store.Attacks().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "attack not found")
			return
		}
		if attack.EndedAt != nil {
			errResponse(c, http.StatusConflict, "attack already expired")
			return
		}
		// Try tracker first (in-memory active attack)
		var found bool
		if hasHold {
			found = deps.Tracker.ForceExpireHold(id, time.Duration(hold)*time.Second)
		} else {
			found = deps.Tracker.ForceExpire(id)
		}
		if found {
			ok(c, gin.H{"ok": true, "method": "tracker"})
			return
		}
		// Fallback: attack not in tracker memory (degraded recovery / stale DB row).
		// Update DB + notify action engine for on_expired cleanup (unblock etc.)
		now := time.Now()
		attack.EndedAt = &now
		if err := deps.Store.Attacks().Update(c, attack); err != nil {
			dbError(c, "", err)
			return
		}
		deps.Tracker.NotifyExpired(attack)
		ok(c, gin.H{"ok": true, "method": "db"})
	}
}

func getAttackSensorLogs(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid attack id")
			return
		}

		attack, err := deps.Store.Attacks().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "attack not found")
			return
		}

		// Global attacks (0.0.0.0/0) have no per-flow detail
		if attack.DstIP == "0.0.0.0/0" {
			ok(c, gin.H{"flows": []store.FlowLog{}, "total": 0, "expired": false})
			return
		}

		// Time window: attack start → end (or now if still active)
		// For active attacks, cap query window to last 1 hour to avoid timeout on long-running attacks
		to := time.Now()
		from := attack.StartedAt
		window := "full"
		if attack.EndedAt != nil {
			to = *attack.EndedAt
		} else {
			// Active attack: only query last 1 hour
			oneHourAgo := to.Add(-1 * time.Hour)
			if from.Before(oneHourAgo) {
				from = oneHourAgo
				window = "last_1h"
			}
		}

		limit := 1000
		if l := c.Query("limit"); l != "" {
			limit, _ = strconv.Atoi(l)
		}
		if limit > 10000 {
			limit = 10000
		}

		filter := store.FlowLogFilter{
			DstIP: attack.DstIP,
			From:  from,
			To:    to,
			Limit: limit,
		}

		// Outbound attacks: query by src_ip instead of dst_ip
		var flows []store.FlowLog
		if attack.Direction == "sends" {
			flows, err = deps.Store.FlowLogs().QueryBySrcIP(c, filter)
		} else {
			flows, err = deps.Store.FlowLogs().QueryByDstIP(c, filter)
		}
		if err != nil {
			dbError(c, "", err)
			return
		}
		if flows == nil {
			flows = []store.FlowLog{}
		}

		// Determine if flow data is expired (attack started before retention cutoff)
		expired := false
		if len(flows) == 0 && attack.EndedAt != nil && deps.FlowLogsDays > 0 {
			cutoff := time.Now().AddDate(0, 0, -deps.FlowLogsDays)
			if attack.StartedAt.Before(cutoff) {
				expired = true
			}
		}

		ok(c, gin.H{
			"flows":   flows,
			"total":   len(flows),
			"expired": expired,
			"window":  window,
		})
	}
}

// getMitigationSummary aggregates the per-attack mitigation state from the
// three v1.2 sources of truth (action_execution_log, bgp_announcements +
// attachments, xdrop_active_rules) into a single response so the frontend
// doesn't need to fan out N requests per attack to render the Mitigations
// drawer / attack detail page.
func getMitigationSummary(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid attack id")
			return
		}
		attack, err := deps.Store.Attacks().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "attack not found")
			return
		}

		execs, err := deps.Store.ActionExecLog().ListByAttack(c, id)
		if err != nil {
			dbError(c, "load executions: ", err)
			return
		}
		if execs == nil {
			execs = []store.ActionExecutionLog{}
		}
		// Enrich each BGP on_detected success row with bgp_role so the
		// Attack Detail page can show triggered vs attached_shared without
		// re-deriving state from announcement events.
		execViews := enrichActionLogsWithBGPRole(c, deps.Store, id, execs)

		xrules, err := deps.Store.XDropActiveRules().ListByAttack(c, id)
		if err != nil {
			dbError(c, "load xdrop rules: ", err)
			return
		}
		if xrules == nil {
			xrules = []store.XDropActiveRule{}
		}

		attachments, err := deps.Store.BGPAnnouncements().ListAttachmentsForAttack(c, id)
		if err != nil {
			dbError(c, "load bgp attachments: ", err)
			return
		}
		bgpView := make([]gin.H, 0, len(attachments))
		for _, att := range attachments {
			ann, err := deps.Store.BGPAnnouncements().Get(c, att.AnnouncementID)
			if err != nil || ann == nil {
				continue
			}
			bgpView = append(bgpView, gin.H{
				"announcement":         ann,
				"attached_at":          att.AttachedAt,
				"detached_at":          att.DetachedAt,
				"attack_delay_minutes": att.DelayMinutes,
				"attack_action_id":     att.ActionID,
			})
		}

		summary := gin.H{
			"total_evaluated": len(execs),
			"success":         0,
			"failed":          0,
			"skipped":         0,
			"timeout":         0,
		}
		skipReasons := map[string]int{}
		for _, l := range execs {
			switch l.Status {
			case "success":
				summary["success"] = summary["success"].(int) + 1
			case "failed":
				summary["failed"] = summary["failed"].(int) + 1
			case "skipped":
				summary["skipped"] = summary["skipped"].(int) + 1
				if l.SkipReason != "" {
					skipReasons[l.SkipReason]++
				}
			case "timeout":
				summary["timeout"] = summary["timeout"].(int) + 1
			}
		}
		summary["skip_reasons"] = skipReasons

		ok(c, gin.H{
			"attack":            attack,
			"executions":        execViews,
			"xdrop_rules":       xrules,
			"bgp_announcements": bgpView,
			"summary":           summary,
		})
	}
}

type mitigationBriefXDrop struct {
	ExternalRuleID string     `json:"external_rule_id"`
	Status         string     `json:"status"`
	ScheduledFor   *time.Time `json:"scheduled_for,omitempty"`
}

type mitigationBriefBGP struct {
	Prefix       string     `json:"prefix"`
	RouteMap     string     `json:"route_map"`
	Status       string     `json:"status"`
	AttachedAt   time.Time  `json:"attached_at"`
	DetachedAt   *time.Time `json:"detached_at,omitempty"`
	DelayMinutes int        `json:"delay_minutes"`
}

type mitigationBrief struct {
	XDropRules []mitigationBriefXDrop `json:"xdrop_rules"`
	BGP        []mitigationBriefBGP   `json:"bgp"`
}

func getMitigationBrief(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		parts := strings.Split(c.Query("ids"), ",")
		if len(parts) > 50 {
			errResponse(c, http.StatusBadRequest, "ids must contain at most 50 unique positive integers")
			return
		}
		ids := make([]int, 0, len(parts))
		seen := make(map[int]bool, len(parts))
		for _, part := range parts {
			// attack IDs are INT in the database; larger values would fail in the store as 500.
			parsed, err := strconv.ParseInt(part, 10, 32)
			id := int(parsed)
			if err != nil || id <= 0 || seen[id] {
				errResponse(c, http.StatusBadRequest, "ids must contain at most 50 unique positive integers")
				return
			}
			seen[id] = true
			ids = append(ids, id)
		}
		result := make(map[int]mitigationBrief, len(ids))
		for _, id := range ids {
			brief := mitigationBrief{XDropRules: []mitigationBriefXDrop{}, BGP: []mitigationBriefBGP{}}
			rules, err := deps.Store.XDropActiveRules().ListByAttack(c, id)
			if err != nil {
				errResponse(c, http.StatusInternalServerError, storeInternal(c, "load xdrop rules: ", err))
				return
			}
			for _, rule := range rules {
				item := mitigationBriefXDrop{ExternalRuleID: rule.ExternalRuleID, Status: rule.Status}
				if rule.Status == "delayed" && rule.DelayStartedAt != nil && rule.DelayMinutes > 0 {
					scheduled := rule.DelayStartedAt.Add(time.Duration(rule.DelayMinutes) * time.Minute)
					item.ScheduledFor = &scheduled
				}
				brief.XDropRules = append(brief.XDropRules, item)
			}
			attachments, err := deps.Store.BGPAnnouncements().ListAttachmentsForAttack(c, id)
			if err != nil {
				errResponse(c, http.StatusInternalServerError, storeInternal(c, "load bgp attachments: ", err))
				return
			}
			for _, attachment := range attachments {
				ann, err := deps.Store.BGPAnnouncements().Get(c, attachment.AnnouncementID)
				if err != nil {
					errResponse(c, http.StatusInternalServerError, storeInternal(c, "load bgp announcement: ", err))
					return
				}
				if ann == nil {
					errResponse(c, http.StatusInternalServerError, storeInternal(c, "load bgp announcement: ", errors.New("announcement not found")))
					return
				}
				brief.BGP = append(brief.BGP, mitigationBriefBGP{
					Prefix: ann.Prefix, RouteMap: ann.RouteMap, Status: ann.Status,
					AttachedAt: attachment.AttachedAt, DetachedAt: attachment.DetachedAt, DelayMinutes: attachment.DelayMinutes,
				})
			}
			result[id] = brief
		}
		ok(c, result)
	}
}

func listAuditLog(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		filter := store.AuditFilter{
			Limit:  50,
			Offset: 0,
		}
		if et := c.Query("entity_type"); et != "" {
			filter.EntityType = et
		}
		if uid := c.Query("user_id"); uid != "" {
			id, _ := strconv.Atoi(uid)
			filter.UserID = &id
		}
		if from := c.Query("from"); from != "" {
			if t, err := time.Parse(time.RFC3339, from); err == nil {
				filter.TimeFrom = &t
			}
		}
		if to := c.Query("to"); to != "" {
			if t, err := time.Parse(time.RFC3339, to); err == nil {
				filter.TimeTo = &t
			}
		}
		if lim := c.Query("limit"); lim != "" {
			filter.Limit, _ = strconv.Atoi(lim)
		}
		if off := c.Query("offset"); off != "" {
			filter.Offset, _ = strconv.Atoi(off)
		}
		if filter.Limit > 200 {
			filter.Limit = 200
		}

		logs, err := deps.Store.AuditLog().List(c, filter)
		if err != nil {
			dbError(c, "", err)
			return
		}
		logs = append([]store.AuditLog(nil), logs...)
		for i, row := range logs {
			if row.EntityType == "webhook_connector" || row.EntityType == "webhook" || row.EntityType == "response_action" {
				logs[i].Diff = maskWebhookValue(row.Diff)
			}
		}
		ok(c, logs)
	}
}
