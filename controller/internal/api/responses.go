package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

// validateActionTemplateVars rejects unknown {var} placeholders in any action
// field that flows through expandParams at execution time, so misspellings
// surface at API time rather than as silent literal forwarding.
func validateActionTemplateVars(dto actionDTO) error {
	if err := action.ValidateTemplateVars("xdrop_custom_payload", string(dto.XDropPayload)); err != nil {
		return err
	}
	if err := action.ValidateTemplateVars("shell_extra_args", dto.ShellExtraArgs); err != nil {
		return err
	}
	return nil
}

// --- Responses ---

func listResponses(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		responses, err := deps.Store.Responses().List(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, responses)
	}
}

func createResponse(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name        string `json:"name" binding:"required"`
			Description string `json:"description"`
			Enabled     *bool  `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		id, err := deps.Store.Responses().Create(c, &store.Response{
			Name: req.Name, Description: req.Description, Enabled: enabled,
		})
		if err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "response", strconv.Itoa(id), "create", makeDiff(nil, store.Response{ID: id, Name: req.Name, Description: req.Description, Enabled: enabled}))
		created(c, gin.H{"id": id})
	}
}

// actionView is the enriched read DTO for actions (includes connector_name, target_node_ids).
type actionView struct {
	store.ResponseAction
	ConnectorName  string   `json:"connector_name"`
	ConnectorID    *int     `json:"connector_id"`     // generic ID for UI
	TargetNodeIDs  []int    `json:"target_node_ids"`  // xDrop targets
	XDropFields    []string `json:"xdrop_fields"`     // derived from xdrop_custom_payload for UI
	XDropRateLimit *int     `json:"xdrop_rate_limit"` // derived from xdrop_custom_payload for UI
}

func getResponse(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		r, err := deps.Store.Responses().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "response not found")
			return
		}
		// Include enriched actions
		actions, _ := deps.Store.Responses().ListActions(c, id)
		views := make([]actionView, len(actions))
		for i, act := range actions {
			v := actionView{ResponseAction: act}
			// Resolve connector name + generic ID
			switch act.ActionType {
			case store.ActionTypeWebhook:
				if act.WebhookConnectorID != nil {
					v.ConnectorID = act.WebhookConnectorID
					if wc, err := deps.Store.WebhookConnectors().Get(c, *act.WebhookConnectorID); err == nil {
						v.ConnectorName = wc.Name
					}
				}
			case store.ActionTypeShell:
				if act.ShellConnectorID != nil {
					v.ConnectorID = act.ShellConnectorID
					if sc, err := deps.Store.ShellConnectors().Get(c, *act.ShellConnectorID); err == nil {
						v.ConnectorName = sc.Name
					}
				}
			case store.ActionTypeXDrop:
				targets, _ := deps.Store.XDropTargets().List(c, act.ID)
				ids := make([]int, len(targets))
				for j, t := range targets {
					ids[j] = t.ID
				}
				v.TargetNodeIDs = ids
				if len(targets) > 0 {
					v.ConnectorName = targets[0].Name
					if len(targets) > 1 {
						v.ConnectorName += fmt.Sprintf(" (+%d)", len(targets)-1)
					}
				} else {
					v.ConnectorName = "(all)"
				}
				// Derive xdrop_fields and xdrop_rate_limit from xdrop_custom_payload for UI
				v.XDropFields, v.XDropRateLimit = parseXDropPayloadFields(act.XDropCustomPayload)
			case store.ActionTypeBGP:
				if act.BGPConnectorID != nil {
					v.ConnectorID = act.BGPConnectorID
					if bc, err := deps.Store.BGPConnectors().Get(c, *act.BGPConnectorID); err == nil {
						v.ConnectorName = bc.Name
					}
				}
			}
			views[i] = v
		}
		ok(c, maskWebhookValue(gin.H{"response": r, "actions": views}))
	}
}

func updateResponse(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, err := deps.Store.Responses().Get(c, id)
		if err != nil {
			errResponse(c, http.StatusNotFound, "response not found")
			return
		}
		var req struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Enabled     *bool  `json:"enabled"`
		}
		req.Name, req.Description = old.Name, old.Description
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.Name == "" {
			errResponse(c, http.StatusBadRequest, "name is required")
			return
		}
		enabled := old.Enabled
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if err := deps.Store.Responses().Update(c, &store.Response{
			ID: id, Name: req.Name, Description: req.Description, Enabled: enabled,
		}); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "response", strconv.Itoa(id), "update", makeDiff(old, store.Response{ID: id, Name: req.Name, Description: req.Description, Enabled: enabled}))
		ok(c, gin.H{"ok": true})
	}
}

func deleteResponse(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		// Check if any template is using this response (fail closed on error)
		templates, err := deps.Store.ThresholdTemplates().List(c)
		if err != nil {
			dbError(c, "failed to check response usage: ", err)
			return
		}
		for _, t := range templates {
			if t.ResponseID != nil && *t.ResponseID == id {
				errResponse(c, http.StatusConflict,
					fmt.Sprintf("response in use by template %q (id=%d)", t.Name, t.ID))
				return
			}
		}
		// Check if any threshold rule is using this response
		thresholds, err := deps.Store.Thresholds().List(c)
		if err != nil {
			dbError(c, "failed to check response usage: ", err)
			return
		}
		for _, t := range thresholds {
			if t.ResponseID != nil && *t.ResponseID == id {
				errResponse(c, http.StatusConflict,
					fmt.Sprintf("response in use by threshold rule id=%d", t.ID))
				return
			}
		}
		old, _ := deps.Store.Responses().Get(c, id)
		if err := deps.Store.Responses().Delete(c, id); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "response", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

// Note: response/action create/update also go through audit via publishAfterChange
// Response changes affect action execution but don't need Node config push

// --- Response Actions ---

func listActions(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		respID, _ := strconv.Atoi(c.Param("id"))
		actions, err := deps.Store.Responses().ListActions(c, respID)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, maskWebhookValue(actions))
	}
}

// actionDTO is the API request/response shape for actions.
// Maps generic UI fields to typed backend fields.
type actionDTO struct {
	ActionType              string          `json:"action_type"`
	TriggerPhase            string          `json:"trigger_phase"`
	RunMode                 string          `json:"run_mode"`
	PeriodSeconds           int             `json:"period_seconds"`
	Execution               string          `json:"execution"`
	Priority                int             `json:"priority"`
	Enabled                 *bool           `json:"enabled"`
	ConnectorID             *int            `json:"connector_id"`    // generic: UI sends this
	TargetNodeIDs           []int           `json:"target_node_ids"` // xDrop targets from UI
	XDropAction             string          `json:"xdrop_action"`
	XDropPayload            json.RawMessage `json:"xdrop_custom_payload"`
	ShellExtraArgs          string          `json:"shell_extra_args"`
	UnblockDelayMinutes     int             `json:"unblock_delay_minutes"`
	BGPRouteMap             string          `json:"bgp_route_map"`
	BGPWithdrawDelayMinutes int             `json:"bgp_withdraw_delay_minutes"`
}

func dtoToAction(dto actionDTO, respID int) store.ResponseAction {
	enabled := true
	if dto.Enabled != nil {
		enabled = *dto.Enabled
	}
	act := store.ResponseAction{
		ResponseID:              respID,
		ActionType:              dto.ActionType,
		TriggerPhase:            dto.TriggerPhase,
		RunMode:                 dto.RunMode,
		PeriodSeconds:           dto.PeriodSeconds,
		Execution:               dto.Execution,
		Priority:                dto.Priority,
		Enabled:                 enabled,
		Config:                  json.RawMessage(`{}`), // default empty JSON for legacy compat
		XDropAction:             dto.XDropAction,
		XDropCustomPayload:      dto.XDropPayload,
		ShellExtraArgs:          dto.ShellExtraArgs,
		UnblockDelayMinutes:     dto.UnblockDelayMinutes,
		BGPRouteMap:             dto.BGPRouteMap,
		BGPWithdrawDelayMinutes: dto.BGPWithdrawDelayMinutes,
	}
	// Map generic connector_id to typed FK based on action_type
	if dto.ConnectorID != nil {
		switch dto.ActionType {
		case store.ActionTypeWebhook:
			act.WebhookConnectorID = dto.ConnectorID
		case store.ActionTypeShell:
			act.ShellConnectorID = dto.ConnectorID
		case store.ActionTypeBGP:
			act.BGPConnectorID = dto.ConnectorID
		}
	}
	// Map legacy execution_policy from new fields for backward compat
	switch {
	case dto.TriggerPhase == store.TriggerPhaseOnDetected && dto.RunMode == store.RunModeOnce:
		act.ExecutionPolicy = "once_on_enter"
	case dto.TriggerPhase == store.TriggerPhaseOnExpired && dto.RunMode == store.RunModeOnce:
		act.ExecutionPolicy = "once_on_exit"
	case dto.RunMode == store.RunModePeriodic:
		act.ExecutionPolicy = "periodic"
	case dto.RunMode == store.RunModeRetryUntilSuccess:
		act.ExecutionPolicy = "retry_until_success"
	default:
		act.ExecutionPolicy = "once_on_enter"
	}
	return act
}

// actionToDTO snapshots an existing action into the DTO shape used by the API,
// so updateAction can pre-populate the merge target before applying a partial
// PUT body. Mirrors dtoToAction's typed-FK → generic ConnectorID mapping.
func actionToDTO(a *store.ResponseAction) actionDTO {
	enabled := a.Enabled
	dto := actionDTO{
		ActionType:              a.ActionType,
		TriggerPhase:            a.TriggerPhase,
		RunMode:                 a.RunMode,
		PeriodSeconds:           a.PeriodSeconds,
		Execution:               a.Execution,
		Priority:                a.Priority,
		Enabled:                 &enabled,
		XDropAction:             a.XDropAction,
		XDropPayload:            a.XDropCustomPayload,
		ShellExtraArgs:          a.ShellExtraArgs,
		UnblockDelayMinutes:     a.UnblockDelayMinutes,
		BGPRouteMap:             a.BGPRouteMap,
		BGPWithdrawDelayMinutes: a.BGPWithdrawDelayMinutes,
	}
	switch a.ActionType {
	case store.ActionTypeWebhook:
		dto.ConnectorID = a.WebhookConnectorID
	case store.ActionTypeShell:
		dto.ConnectorID = a.ShellConnectorID
	case store.ActionTypeBGP:
		dto.ConnectorID = a.BGPConnectorID
	}
	return dto
}

func validateActionEnums(dto actionDTO) error {
	switch dto.ActionType {
	case store.ActionTypeXDrop, store.ActionTypeBGP, store.ActionTypeWebhook, store.ActionTypeShell:
	default:
		return fmt.Errorf("action_type must be one of: xdrop, bgp, webhook, shell; got %q", dto.ActionType)
	}
	switch dto.RunMode {
	case "", store.RunModeOnce, store.RunModePeriodic, store.RunModeRetryUntilSuccess:
	default:
		return fmt.Errorf("run_mode must be one of: '', once, periodic, retry_until_success; got %q", dto.RunMode)
	}
	return nil
}

func validateActionCommon(c *gin.Context, deps Dependencies, dto actionDTO, respID int, onExpiredVerb string) (int, string) {
	if dto.TriggerPhase != store.TriggerPhaseOnDetected && dto.TriggerPhase != store.TriggerPhaseOnExpired {
		return http.StatusBadRequest, "trigger_phase must be on_detected or on_expired"
	}
	if dto.TriggerPhase == store.TriggerPhaseOnExpired && (dto.ActionType == store.ActionTypeXDrop || dto.ActionType == store.ActionTypeBGP) {
		article := "an"
		if onExpiredVerb == "edit" {
			article = "the"
		}
		return http.StatusBadRequest, "xDrop/BGP on_expired actions are auto-generated — " + onExpiredVerb + " " + article + " on_detected action instead"
	}
	if dto.TriggerPhase == store.TriggerPhaseOnExpired && dto.RunMode != "" && dto.RunMode != store.RunModeOnce {
		return http.StatusBadRequest, "on_expired only supports run_mode=once"
	}
	if (dto.ActionType == store.ActionTypeWebhook || dto.ActionType == store.ActionTypeShell || dto.ActionType == store.ActionTypeBGP) && dto.ConnectorID == nil {
		return http.StatusBadRequest, dto.ActionType + " action requires connector_id"
	}
	if dto.ActionType == store.ActionTypeBGP && dto.TriggerPhase == store.TriggerPhaseOnDetected && dto.BGPRouteMap == "" {
		return http.StatusBadRequest, "bgp action (on_detected) requires bgp_route_map"
	}
	if dto.BGPRouteMap != "" && !validRouteMapName(dto.BGPRouteMap) {
		return http.StatusBadRequest, "bgp_route_map may only contain letters, digits, '_', '-', '.'"
	}
	if dto.BGPWithdrawDelayMinutes < 0 || dto.BGPWithdrawDelayMinutes > 1440 {
		return http.StatusBadRequest, "bgp_withdraw_delay_minutes must be between 0 and 1440"
	}
	if msg := validateXDropAction(dto); msg != "" {
		return http.StatusBadRequest, msg
	}
	if err := validateActionTemplateVars(dto); err != nil {
		return http.StatusBadRequest, err.Error()
	}
	if dto.ActionType == store.ActionTypeXDrop || dto.ActionType == store.ActionTypeBGP {
		referenced, err := isResponseReferencedByGlobalPrefix(c, deps.Store, respID)
		if err != nil {
			return storeFailure(c, "failed to check global prefix references: ", err)
		}
		if referenced {
			return http.StatusBadRequest, "This response is referenced by global prefix (0.0.0.0/0) rules — cannot add xDrop/BGP action"
		}
		referenced, err = isResponseReferencedBySendsRule(c, deps.Store, respID)
		if err != nil {
			return storeFailure(c, "failed to check outbound rule references: ", err)
		}
		if referenced {
			return http.StatusBadRequest, "This response is referenced by outbound (sends) rules — cannot add xDrop/BGP action"
		}
	}
	return 0, ""
}

func createAction(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		respID, _ := strconv.Atoi(c.Param("id"))
		var dto actionDTO
		if err := c.ShouldBindJSON(&dto); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateActionEnums(dto); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if status, msg := validateActionCommon(c, deps, dto, respID, "create"); status != 0 {
			errResponse(c, status, msg)
			return
		}
		act := dtoToAction(dto, respID)
		id, err := deps.Store.Responses().CreateAction(c, &act)
		if err != nil {
			dbError(c, "", err)
			return
		}
		// Save xDrop targets if provided
		if act.ActionType == store.ActionTypeXDrop && len(dto.TargetNodeIDs) > 0 {
			if err := deps.Store.XDropTargets().Set(c, id, dto.TargetNodeIDs); err != nil {
				// Rollback: delete the action we just created
				_ = deps.Store.Responses().DeleteAction(c, id)
				dbError(c, "set xdrop targets: ", err)
				return
			}
		}
		var pairedID int
		// Auto-pair: create matching on_expired action for xDrop/BGP
		if (dto.ActionType == store.ActionTypeXDrop || dto.ActionType == store.ActionTypeBGP) && dto.TriggerPhase == store.TriggerPhaseOnDetected {
			pairedID, err = createPairedOnExpired(c, deps.Store, &act, id, respID, dto.TargetNodeIDs)
			if err != nil {
				// Rollback: delete the on_detected action we just created
				_ = deps.Store.Responses().DeleteAction(c, id)
				dbError(c, "failed to create paired on_expired action: ", err)
				return
			}
			// Set paired_with on the on_detected action
			if err := deps.Store.Responses().SetPairedWith(c, id, &pairedID); err != nil {
				// Rollback both actions
				_ = deps.Store.Responses().DeleteAction(c, pairedID)
				_ = deps.Store.Responses().DeleteAction(c, id)
				dbError(c, "failed to link paired action: ", err)
				return
			}
		}
		act.ID = id
		if (dto.ActionType == store.ActionTypeXDrop || dto.ActionType == store.ActionTypeBGP) && dto.TriggerPhase == store.TriggerPhaseOnDetected {
			act.PairedWith = &pairedID
		}
		publishAfterChange(c, deps, "response_action", strconv.Itoa(id), "create", makeDiff(nil, auditAction(&act, dto.TargetNodeIDs, true)))
		created(c, gin.H{"id": id})
	}
}

// createPairedOnExpired auto-generates the matching on_expired action for an xDrop/BGP on_detected action.
func createPairedOnExpired(ctx context.Context, s store.Store, parent *store.ResponseAction, parentID, respID int, xdropTargets []int) (int, error) {
	child := store.ResponseAction{
		ResponseID:      respID,
		ActionType:      parent.ActionType,
		ExecutionPolicy: "once_on_exit",
		Priority:        parent.Priority,
		Config:          json.RawMessage(`{}`),
		Enabled:         parent.Enabled,
		TriggerPhase:    store.TriggerPhaseOnExpired,
		RunMode:         store.RunModeOnce,
		Execution:       store.ExecutionAutomatic,
		AutoGenerated:   true,
	}
	switch parent.ActionType {
	case store.ActionTypeXDrop:
		child.XDropAction = "unblock"
		child.UnblockDelayMinutes = parent.UnblockDelayMinutes
	case store.ActionTypeBGP:
		child.BGPConnectorID = parent.BGPConnectorID
		child.BGPWithdrawDelayMinutes = parent.BGPWithdrawDelayMinutes
		child.BGPRouteMap = parent.BGPRouteMap
	}
	childID, err := s.Responses().CreateAction(ctx, &child)
	if err != nil {
		return 0, err
	}
	// Copy xDrop targets to the paired action
	if parent.ActionType == store.ActionTypeXDrop && len(xdropTargets) > 0 {
		if err := s.XDropTargets().Set(ctx, childID, xdropTargets); err != nil {
			// Rollback: delete the child action
			_ = s.Responses().DeleteAction(ctx, childID)
			return 0, fmt.Errorf("set xdrop targets for paired action %d: %w", childID, err)
		}
	}
	return childID, nil
}

// cloneAction keeps rollback snapshots independent of DTO binding and repository aliases.
func cloneAction(a *store.ResponseAction) *store.ResponseAction {
	copy := *a
	copy.Config, copy.Preconditions, copy.XDropCustomPayload = slices.Clone(a.Config), slices.Clone(a.Preconditions), slices.Clone(a.XDropCustomPayload)
	for _, p := range []**int{&copy.WebhookConnectorID, &copy.ShellConnectorID, &copy.BGPConnectorID, &copy.PairedWith} {
		if *p != nil {
			v := **p
			*p = &v
		}
	}
	return &copy
}

// actionAudit is the audit shape of an action row plus its xDrop targets.
type actionAudit struct {
	store.ResponseAction
	TargetNodeIDs *[]int `json:"target_node_ids,omitempty"`
}

// auditAction snapshots an action for the audit diff; targets are recorded only
// for xDrop actions whose target list is known.
func auditAction(a *store.ResponseAction, targets []int, known bool) actionAudit {
	view := actionAudit{ResponseAction: *cloneAction(a)}
	if a.ActionType == store.ActionTypeXDrop && known {
		ids := append([]int{}, targets...)
		view.TargetNodeIDs = &ids
	}
	return view
}

func updateAction(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Responses().GetAction(c, id)
		if old == nil {
			errResponse(c, http.StatusNotFound, "action not found")
			return
		}
		before := cloneAction(old)
		// Reject editing auto-generated actions directly
		if old.AutoGenerated {
			errResponse(c, http.StatusBadRequest, "auto-generated on_expired actions cannot be edited directly — edit the on_detected action instead")
			return
		}
		// Merge semantics: pre-populate the DTO from the existing action so a
		// partial PUT (e.g. only bgp_withdraw_delay_minutes) doesn't clobber
		// unset fields. JSON Unmarshal only overwrites keys present in the body.
		dto := actionToDTO(old)
		var beforeTargets []int
		var targetsErr error
		beforeTargetsKnown := false
		if old.ActionType == store.ActionTypeXDrop {
			targets, err := deps.Store.XDropTargets().List(c, id)
			targetsErr = err
			if err == nil {
				ids := make([]int, len(targets))
				for j, t := range targets {
					ids[j] = t.ID
				}
				dto.TargetNodeIDs = ids
				beforeTargets, beforeTargetsKnown = slices.Clone(ids), true
			}
		}
		var body bytes.Buffer
		if original := c.Request.Body; original != nil {
			c.Request.Body = struct {
				io.Reader
				io.Closer
			}{io.TeeReader(original, &body), original}
		}
		if err := c.ShouldBindJSON(&dto); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		var probe struct {
			TargetNodeIDs json.RawMessage `json:"target_node_ids"`
		}
		if err := json.NewDecoder(bytes.NewReader(body.Bytes())).Decode(&probe); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		hasTargets := probe.TargetNodeIDs != nil
		if targetsErr != nil && !hasTargets {
			dbError(c, "load xdrop targets: ", targetsErr)
			return
		}
		// Reject cross-type updates: with merge semantics, the old row's typed
		// connector FK (webhook/shell/bgp) gets carried over via actionToDTO →
		// dtoToAction. Re-binding that old connector ID to a new action_type's
		// FK field silently points the action at a connector of the wrong type,
		// or an ID that doesn't exist at all. Safer to force delete+recreate.
		if dto.ActionType != "" && dto.ActionType != old.ActionType {
			errResponse(c, http.StatusBadRequest,
				"cannot change action_type via PUT — delete this action and create a new one instead")
			return
		}
		if err := validateActionEnums(dto); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if status, msg := validateActionCommon(c, deps, dto, old.ResponseID, "edit"); status != 0 {
			errResponse(c, status, msg)
			return
		}
		act := dtoToAction(dto, old.ResponseID)
		act.ID = id
		act.PairedWith = old.PairedWith // preserve pairing
		// The DTO omits legacy conditions; clearing them would fail open.
		act.Preconditions = old.Preconditions
		if err := deps.Store.Responses().UpdateAction(c, &act); err != nil {
			dbError(c, "", err)
			return
		}
		rollback := func(msg string, child *store.ResponseAction, targetsWritten bool) string {
			var failures []string
			record := func(step string, err error) {
				if err != nil {
					log.Printf("action: rollback %s for action %d failed: %v", step, id, err)
					failures = append(failures, step)
				}
			}
			if child != nil {
				record("child row", deps.Store.Responses().UpdateAction(c, child))
			}
			if targetsWritten {
				if beforeTargetsKnown {
					record("parent targets", deps.Store.XDropTargets().Set(c, id, beforeTargets))
				} else {
					record("parent targets", fmt.Errorf("previous value unknown"))
					failures[len(failures)-1] = "parent targets: previous value unknown"
				}
			}
			record("parent row", deps.Store.Responses().UpdateAction(c, before))
			if len(failures) > 0 {
				msg += "; rollback incomplete: " + strings.Join(failures, "; ")
			}
			return msg
		}
		// Update xDrop targets
		if act.ActionType == store.ActionTypeXDrop {
			if err := deps.Store.XDropTargets().Set(c, id, dto.TargetNodeIDs); err != nil {
				errResponse(c, http.StatusInternalServerError, rollback(storeInternal(c, "set xdrop targets: ", err), nil, false))
				return
			}
		} else {
			_ = deps.Store.XDropTargets().Set(c, id, nil)
		}
		// Sync paired on_expired action if this is an on_detected xDrop/BGP
		if old.PairedWith != nil && (act.ActionType == store.ActionTypeXDrop || act.ActionType == store.ActionTypeBGP) {
			if child, err := syncPairedOnExpired(c, deps.Store, &act, *old.PairedWith, dto.TargetNodeIDs); err != nil {
				errResponse(c, http.StatusInternalServerError, rollback(storeInternal(c, "failed to sync paired action: ", err), child, act.ActionType == store.ActionTypeXDrop))
				return
			}
		}
		publishAfterChange(c, deps, "response_action", strconv.Itoa(id), "update", makeDiff(auditAction(before, beforeTargets, beforeTargetsKnown), auditAction(&act, dto.TargetNodeIDs, true)))
		ok(c, gin.H{"ok": true})
	}
}

// syncPairedOnExpired propagates changes from on_detected to its paired on_expired action.
func syncPairedOnExpired(ctx context.Context, s store.Store, parent *store.ResponseAction, pairedID int, xdropTargets []int) (*store.ResponseAction, error) {
	child, err := s.Responses().GetAction(ctx, pairedID)
	if err != nil || child == nil {
		return nil, fmt.Errorf("get paired action %d: %w", pairedID, err)
	}
	beforeChild := cloneAction(child)
	child.Enabled = parent.Enabled
	child.Priority = parent.Priority
	switch parent.ActionType {
	case store.ActionTypeXDrop:
		child.UnblockDelayMinutes = parent.UnblockDelayMinutes
	case store.ActionTypeBGP:
		child.BGPConnectorID = parent.BGPConnectorID
		child.BGPWithdrawDelayMinutes = parent.BGPWithdrawDelayMinutes
		child.BGPRouteMap = parent.BGPRouteMap
	}
	if err := s.Responses().UpdateAction(ctx, child); err != nil {
		return nil, fmt.Errorf("update paired action %d: %w", pairedID, err)
	}
	// Sync xDrop targets
	if parent.ActionType == store.ActionTypeXDrop {
		if err := s.XDropTargets().Set(ctx, pairedID, xdropTargets); err != nil {
			return beforeChild, fmt.Errorf("sync xdrop targets for paired action %d: %w", pairedID, err)
		}
	}
	return nil, nil
}

func deleteAction(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		old, _ := deps.Store.Responses().GetAction(c, id)
		if old == nil {
			errResponse(c, http.StatusNotFound, "action not found")
			return
		}
		// Reject deleting auto-generated actions directly
		if old.AutoGenerated {
			errResponse(c, http.StatusBadRequest, "auto-generated on_expired actions cannot be deleted directly — delete the on_detected action instead")
			return
		}
		// Delete paired on_expired child first
		if old.PairedWith != nil {
			if err := deps.Store.Responses().DeleteAction(c, *old.PairedWith); err != nil {
				dbError(c, fmt.Sprintf("failed to delete paired action %d: ", *old.PairedWith), err)
				return
			}
		}
		if err := deps.Store.Responses().DeleteAction(c, id); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "response_action", strconv.Itoa(id), "delete", makeDiff(old, nil))
		ok(c, gin.H{"ok": true})
	}
}

func listPreconditions(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid action id")
			return
		}
		list, err := deps.Store.Preconditions().List(c, id)
		if err != nil {
			dbError(c, "", err)
			return
		}
		if list == nil {
			list = []store.ActionPrecondition{}
		}
		ok(c, list)
	}
}

func replacePreconditions(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid action id")
			return
		}
		var req struct {
			Preconditions []store.ActionPrecondition `json:"preconditions"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		// Validate preconditions
		validAttrs := map[string]bool{
			"cidr": true, "decoder": true, "attack_type": true, "severity": true,
			"pps": true, "bps": true, "peak_pps": true, "peak_bps": true,
			"node": true, "domain": true, "carpet_bomb": true,
			"dominant_src_port": true, "dominant_src_port_pct": true,
			"dominant_dst_port": true, "dominant_dst_port_pct": true,
			"unique_src_ips": true,
		}
		validOps := map[string]bool{
			"eq": true, "neq": true, "gt": true, "gte": true, "lt": true, "lte": true, "in": true, "not_in": true,
		}
		for _, p := range req.Preconditions {
			if !validAttrs[p.Attribute] {
				errResponse(c, http.StatusBadRequest, fmt.Sprintf("unsupported precondition attribute: %s", p.Attribute))
				return
			}
			if !validOps[p.Operator] {
				errResponse(c, http.StatusBadRequest, fmt.Sprintf("unsupported precondition operator: %s", p.Operator))
				return
			}
			if p.Value == "" {
				errResponse(c, http.StatusBadRequest, "precondition value cannot be empty")
				return
			}
			if p.Attribute == "carpet_bomb" {
				if p.Operator != "eq" && p.Operator != "neq" {
					errResponse(c, http.StatusBadRequest, "carpet_bomb precondition only supports eq/neq")
					return
				}
				switch strings.ToLower(strings.TrimSpace(p.Value)) {
				case "true", "false", "1", "0", "yes", "no":
				default:
					errResponse(c, http.StatusBadRequest, "unsupported carpet_bomb precondition value")
					return
				}
			}
			if msg := validatePreconditionValue(p); msg != "" {
				errResponse(c, http.StatusBadRequest, msg)
				return
			}
		}
		old, err := deps.Store.Preconditions().List(c, id)
		if err != nil {
			dbError(c, "", err)
			return
		}
		if old == nil {
			old = []store.ActionPrecondition{}
		}
		if err := deps.Store.Preconditions().ReplaceAll(c, id, req.Preconditions); err != nil {
			dbError(c, "", err)
			return
		}
		publishAfterChange(c, deps, "action_precondition", strconv.Itoa(id), "update", makeDiff(old, req.Preconditions))
		ok(c, gin.H{"ok": true})
	}
}

// validatePreconditionValue follows the engine's parsing rules without changing
// the stored value. Numeric ranges and attack_type enumeration are not checked.
func validatePreconditionValue(p store.ActionPrecondition) string {
	invalid := func() string {
		return fmt.Sprintf("invalid precondition value for %s: %q", p.Attribute, p.Value)
	}
	unsupported := func() string {
		return fmt.Sprintf("precondition operator %s is not supported for attribute %s", p.Operator, p.Attribute)
	}
	switch p.Attribute {
	case "carpet_bomb":
		return "" // Validated by the existing handler branch.
	case "node":
		if p.Operator != "eq" && p.Operator != "in" {
			return unsupported()
		}
		for _, item := range strings.Split(p.Value, ",") {
			if strings.TrimSpace(item) == "" {
				return invalid()
			}
		}
	case "decoder", "severity", "domain", "attack_type":
		switch p.Operator {
		case "eq", "neq", "in", "not_in":
		default:
			return unsupported()
		}
		if p.Attribute == "attack_type" {
			return ""
		}
		var allowed map[string]bool
		switch p.Attribute {
		case "decoder":
			allowed = validThresholdDecoders()
		case "severity":
			allowed = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		case "domain":
			allowed = map[string]bool{"internal_ip": true, "subnet": true}
		}
		if p.Operator == "in" || p.Operator == "not_in" {
			for _, item := range strings.Split(p.Value, ",") {
				if !allowed[strings.TrimSpace(item)] {
					return invalid()
				}
			}
		} else if !allowed[p.Value] {
			return invalid()
		}
	default:
		values := []string{p.Value}
		if p.Operator == "in" || p.Operator == "not_in" {
			values = strings.Split(p.Value, ",")
		}
		for _, item := range values {
			if _, err := strconv.ParseInt(strings.TrimSpace(item), 10, 64); err != nil {
				return invalid()
			}
		}
	}
	return ""
}

func getXDropTargets(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid action id")
			return
		}
		targets, err := deps.Store.XDropTargets().List(c, id)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ids := make([]int, len(targets))
		for i, t := range targets {
			ids[i] = t.ID
		}
		ok(c, ids)
	}
}

func setXDropTargets(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid action id")
			return
		}
		var req struct {
			ConnectorIDs []int `json:"connector_ids"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := deps.Store.XDropTargets().Set(c, id, req.ConnectorIDs); err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, gin.H{"ok": true})
	}
}

// validateXDropAction checks xdrop-specific action semantics.
// Returns an error message if invalid, or empty string if OK.
func validateXDropAction(dto actionDTO) string {
	if dto.ActionType != store.ActionTypeXDrop {
		return ""
	}
	// Validate xdrop_action enum
	switch dto.XDropAction {
	case "filter_l4", "rate_limit", "unblock":
		// ok
	case "":
		return "xdrop_action is required"
	default:
		return "xdrop_action must be one of: filter_l4, rate_limit, unblock"
	}
	// filter_l4 and rate_limit require at least one match field in the payload
	if dto.XDropAction == "filter_l4" || dto.XDropAction == "rate_limit" {
		fields, rl := parseXDropPayloadFields(dto.XDropPayload)
		if len(fields) == 0 {
			return "xDrop filter/rate_limit action requires at least one match field (dst_ip, src_ip, dst_port, src_port, or protocol)"
		}
		if dto.XDropAction == "rate_limit" && (rl == nil || *rl <= 0) {
			return "xDrop rate_limit action requires a positive rate_limit value"
		}
	}
	// Unblock delay: must be 0-1440 minutes, only valid on on_detected filter_l4/rate_limit
	if dto.UnblockDelayMinutes != 0 {
		if dto.UnblockDelayMinutes < 0 || dto.UnblockDelayMinutes > 1440 {
			return "unblock_delay_minutes must be between 0 and 1440"
		}
		if dto.TriggerPhase != store.TriggerPhaseOnDetected {
			return "unblock_delay_minutes is only valid for on_detected actions"
		}
		if dto.XDropAction != "filter_l4" && dto.XDropAction != "rate_limit" {
			return "unblock_delay_minutes is only valid for filter_l4 or rate_limit actions"
		}
	}
	return ""
}

// parseXDropPayloadFields extracts the checked filter fields and rate_limit
// from xdrop_custom_payload JSON, so the frontend can reconstruct checkbox state.
func parseXDropPayloadFields(payload json.RawMessage) (fields []string, rateLimit *int) {
	if len(payload) == 0 || string(payload) == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, nil
	}
	fiveTuple := []string{"dst_ip", "src_ip", "dst_port", "src_port", "protocol"}
	for _, f := range fiveTuple {
		if _, ok := m[f]; ok {
			fields = append(fields, f)
		}
	}
	if rl, ok := m["rate_limit"]; ok {
		switch v := rl.(type) {
		case float64:
			n := int(v)
			rateLimit = &n
		}
	}
	return fields, rateLimit
}

// --- Webhooks ---

func listWebhooks(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		webhooks, err := deps.Store.Webhooks().List(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		ok(c, maskWebhookValue(webhooks))
	}
}

func retiredLegacyWebhookWrite(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		errResponse(c, http.StatusGone, "legacy /api/webhooks is read-only; manage global webhooks via /api/settings/webhook-connectors")
	}
}
