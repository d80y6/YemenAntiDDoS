package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// flowspecRuleName derives the stable rule identifier for a destination
// prefix. It must be deterministic so that two attacks against the same
// prefix share one announcement (refcounted) instead of fighting over the
// rule, and so that withdraw can rebuild the rule from the announcement.
func flowspecRuleName(prefix string) string {
	var b strings.Builder
	b.WriteString("xsight-")
	for _, r := range prefix {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// protocolForDecoder maps the attack's decoder family to an IP protocol
// number so the Flowspec match stays as narrow as the detector allows.
// Returning nil omits the protocol match (whole-destination rule).
func protocolForDecoder(family string) *uint8 {
	f := strings.ToLower(family)
	tcp, udp, icmp := uint8(6), uint8(17), uint8(1)
	switch {
	case strings.Contains(f, "tcp"), strings.Contains(f, "syn"), strings.Contains(f, "http"),
		strings.Contains(f, "slowloris"), strings.Contains(f, "tls"):
		return &tcp
	case strings.Contains(f, "udp"), strings.Contains(f, "dns"), strings.Contains(f, "ntp"),
		strings.Contains(f, "ssdp"), strings.Contains(f, "memcached"), strings.Contains(f, "chargen"),
		strings.Contains(f, "snmp"), strings.Contains(f, "quic"):
		return &udp
	case strings.Contains(f, "icmp"):
		return &icmp
	default:
		return nil
	}
}

func flowspecRuleFor(dstIP string, attack *store.Attack) flowspec.Rule {
	r := flowspec.Rule{
		Name:   flowspecRuleName(dstIP),
		Prefix: dstIP,
		Action: flowspec.ActionDrop,
	}
	if attack != nil {
		r.Protocol = protocolForDecoder(attack.DecoderFamily)
	}
	return r
}

func connectorVendor(conn *store.BGPConnector) flowspec.Vendor {
	v, err := flowspec.ParseVendor(conn.Vendor)
	if err != nil {
		return flowspec.VendorFRR
	}
	return v
}

// executeBGPFlowspec is the Flowspec counterpart of bgpAnnounce/bgpWithdraw.
// It shares the refcounted announcement lifecycle with RTBH but stores
// Kind="flowspec" plus the rendered rule so the console can inspect and
// force-withdraw it. Only the FRR vendor is executed automatically; the
// Cisco/Juniper/Arista templates are generated for manual application.
func executeBGPFlowspec(ctx context.Context, s store.Store, conn *store.BGPConnector, act store.ResponseAction,
	attack *store.Attack, dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	switch triggerPhase {
	case "on_detected":
		return flowspecAnnounce(ctx, s, conn, act, attack, dstIP, attackDBID, responseName, triggerPhase)
	case "on_expired":
		return flowspecWithdraw(ctx, s, conn, act, dstIP, attackDBID, responseName, triggerPhase)
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

func flowspecAnnounce(ctx context.Context, s store.Store, conn *store.BGPConnector, act store.ResponseAction,
	attack *store.Attack, dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	rule := flowspecRuleFor(dstIP, attack)
	ruleJSON, _ := json.Marshal(rule)
	externalRuleID := fmt.Sprintf("%s|%s", rule.Prefix, rule.Name)
	actID := act.ID
	connID := conn.ID

	if overridden, err := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID); err != nil {
		log.Printf("action: flowspec announce override lookup: %v", err)
	} else if overridden {
		logCtx, cancel := execLogContext()
		writeSkipLog(logCtx, s, attackDBID, act, responseName, conn.Name, SkipReasonManualOverride, "")
		cancel()
		return nil, nil
	}

	attachResult, err := s.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{
		AttackID:     attackDBID,
		ActionID:     &actID,
		ResponseName: responseName,
		DelayMinutes: 0,
		Prefix:       rule.Prefix,
		RouteMap:     rule.Name,
		ConnectorID:  connID,
		Kind:         "flowspec",
		RuleSpec:     string(ruleJSON),
	})
	if err != nil {
		log.Printf("action: flowspec attach failed attack=%d prefix=%s: %v", attackDBID, rule.Prefix, err)
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
		detail := fmt.Sprintf("attached to flowspec announcement_id=%d (shared)", attachResult.AnnouncementID)
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

	vendor := connectorVendor(conn)
	lines, rErr := flowspec.Render(vendor, rule)
	if rErr != nil {
		markFlowspecAnnounceFailed(ctx, s, attachResult, rErr)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("render: %v", rErr),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, rErr
	}
	cmd := strings.Join(lines, "\n")

	if vendor != flowspec.VendorFRR {
		errMsg := fmt.Sprintf("vendor %s is export-only: rule generated for manual application", vendor)
		markFlowspecAnnounceFailed(ctx, s, attachResult, errors.New(errMsg))
		log.Printf("action: flowspec export-only announcement_id=%d vendor=%s rule=%s",
			attachResult.AnnouncementID, vendor, rule.Name)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   errMsg,
			RequestBody:    cmd,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	if err := vtyshTokens(rule.Prefix, rule.Name); err != nil {
		markFlowspecAnnounceFailed(ctx, s, attachResult, err)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   err.Error(),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, err
	}

	t0 := time.Now()
	out, vErr := runVtysh(ctx, conn.VtyshPath, cmd)
	durationMs := int(time.Since(t0).Milliseconds())
	if vErr != nil {
		metrics.RecordVtysh("announce", "failed")
		markFlowspecAnnounceFailed(ctx, s, attachResult, vErr)
		log.Printf("action: flowspec announce failed announcement_id=%d: %v output=%s",
			attachResult.AnnouncementID, vErr, out)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("vtysh: %v", vErr),
			RequestBody:    cmd,
			ResponseBody:   out,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, vErr
	}

	metrics.RecordVtysh("announce", "success")
	detail := fmt.Sprintf("flowspec rule %s announced (announcement_id=%d)", rule.Name, attachResult.AnnouncementID)
	if mErr := s.BGPAnnouncements().MarkAnnounced(ctx, attachResult.AnnouncementID, attachResult.Gen); mErr != nil {
		log.Printf("action: flowspec MarkAnnounced announcement_id=%d: %v", attachResult.AnnouncementID, mErr)
		detail += "; state write failed"
	}
	log.Printf("action: flowspec announce %s rule=%s vendor=%s connector=%s announcement_id=%d",
		rule.Prefix, rule.Name, vendor, conn.Name, attachResult.AnnouncementID)
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

func markFlowspecAnnounceFailed(ctx context.Context, s store.Store, res store.BGPAttachResult, cause error) {
	if err := retryBGPStateWrite(func(writeCtx context.Context) error {
		return s.BGPAnnouncements().MarkFailedAnnounce(writeCtx, res.AnnouncementID, res.Gen, cause.Error())
	}); err != nil {
		metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
		log.Printf("ERROR action: flowspec compensate announce failure announcement_id=%d: %v", res.AnnouncementID, err)
	}
}

func flowspecWithdraw(ctx context.Context, s store.Store, conn *store.BGPConnector, act store.ResponseAction,
	dstIP string, attackDBID int, responseName, triggerPhase string) (*store.ActionExecutionLog, error) {

	rule := flowspec.Rule{Name: flowspecRuleName(dstIP), Prefix: dstIP, Action: flowspec.ActionDrop}
	externalRuleID := fmt.Sprintf("%s|%s", rule.Prefix, rule.Name)
	connID := conn.ID
	actID := act.ID

	if overridden, err := s.ManualOverrides().Exists(ctx, attackDBID, actID, connID, externalRuleID); err != nil {
		log.Printf("action: flowspec withdraw override lookup: %v", err)
	} else if overridden {
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

	result, err := s.BGPAnnouncements().Detach(ctx, attackDBID, rule.Prefix, rule.Name, connID)
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
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "success",
			Detail:         "no flowspec announcement to detach (idempotent)",
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	if !result.NeedWithdraw {
		detail := fmt.Sprintf("detached from flowspec announcement_id=%d (refcount=%d, kept active)",
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

	vendor := connectorVendor(conn)
	lines, rErr := flowspec.RenderWithdraw(vendor, rule)
	if rErr != nil {
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("render withdraw: %v", rErr),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, rErr
	}
	cmd := strings.Join(lines, "\n")

	if vendor != flowspec.VendorFRR {
		if mErr := s.BGPAnnouncements().MarkWithdrawn(ctx, result.AnnouncementID, result.Gen); mErr != nil {
			log.Printf("action: flowspec MarkWithdrawn announcement_id=%d: %v", result.AnnouncementID, mErr)
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
			Detail:         fmt.Sprintf("vendor %s is export-only: withdraw command generated for manual application", vendor),
			RequestBody:    cmd,
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, nil
	}

	if err := vtyshTokens(rule.Prefix, rule.Name); err != nil {
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   err.Error(),
			ExternalRuleID: externalRuleID,
			ExecutedAt:     time.Now(),
		}, err
	}

	t0 := time.Now()
	out, vErr := runVtysh(ctx, conn.VtyshPath, cmd)
	durationMs := int(time.Since(t0).Milliseconds())
	if vErr != nil {
		metrics.RecordVtysh("withdraw", "failed")
		if mErr := retryBGPStateWrite(func(writeCtx context.Context) error {
			return s.BGPAnnouncements().MarkFailedWithdraw(writeCtx, result.AnnouncementID, result.Gen, vErr.Error())
		}); mErr != nil {
			metrics.StateWriteFailures.WithLabelValues("bgp_ann_state").Inc()
			log.Printf("ERROR action: flowspec compensate withdraw failure announcement_id=%d: %v", result.AnnouncementID, mErr)
		}
		log.Printf("action: flowspec withdraw failed announcement_id=%d: %v output=%s",
			result.AnnouncementID, vErr, out)
		return &store.ActionExecutionLog{
			AttackID:       attackDBID,
			ActionID:       act.ID,
			ActionType:     "bgp",
			TriggerPhase:   triggerPhase,
			ResponseName:   responseName,
			ConnectorName:  conn.Name,
			ConnectorID:    &connID,
			Status:         "failed",
			ErrorMessage:   fmt.Sprintf("vtysh: %v", vErr),
			RequestBody:    cmd,
			ResponseBody:   out,
			ExternalRuleID: externalRuleID,
			DurationMs:     durationMs,
			ExecutedAt:     t0,
		}, vErr
	}

	metrics.RecordVtysh("withdraw", "success")
	detail := fmt.Sprintf("flowspec rule %s withdrawn (announcement_id=%d)", rule.Name, result.AnnouncementID)
	if mErr := s.BGPAnnouncements().MarkWithdrawn(ctx, result.AnnouncementID, result.Gen); mErr != nil {
		log.Printf("action: flowspec MarkWithdrawn announcement_id=%d: %v", result.AnnouncementID, mErr)
		detail += "; state write failed"
	}
	log.Printf("action: flowspec withdraw %s rule=%s connector=%s announcement_id=%d",
		rule.Prefix, rule.Name, conn.Name, result.AnnouncementID)
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
