package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// jsonOrNil marshals a change payload for the audit publisher.
func jsonOrNil(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// normalizeVendor maps operator input to a Flowspec CLI dialect.
func normalizeVendor(v string) (flowspec.Vendor, error) {
	return flowspec.ParseVendor(v)
}

// supportedVendors is echoed to the console so its dropdown cannot drift from
// the generator's actual capabilities.
func supportedVendors() []gin.H {
	return []gin.H{
		{"id": string(flowspec.VendorFRR), "name": "FRR", "executable": true},
		{"id": string(flowspec.VendorCisco), "name": "Cisco IOS-XR", "executable": false},
		{"id": string(flowspec.VendorJuniper), "name": "Juniper Junos", "executable": false},
		{"id": string(flowspec.VendorArista), "name": "Arista EOS", "executable": false},
	}
}

// flowspecView is the console read model for one Flowspec announcement: the
// stored rule plus the exact CLI the connector's vendor expects, so an
// operator can audit or copy it without reading the generator.
type flowspecView struct {
	AnnouncementID   int             `json:"announcement_id"`
	Prefix           string          `json:"prefix"`
	RuleName         string          `json:"rule_name"`
	ConnectorID      int             `json:"connector_id"`
	ConnectorName    string          `json:"connector_name"`
	Vendor           string          `json:"vendor"`
	Executable       bool            `json:"executable"`
	Status           string          `json:"status"`
	Refcount         int             `json:"refcount"`
	ErrorMessage     string          `json:"error_message,omitempty"`
	AnnouncedAt      time.Time       `json:"announced_at"`
	DelayStartedAt   *time.Time      `json:"delay_started_at,omitempty"`
	DelayMinutes     int             `json:"delay_minutes"`
	Rule             *flowspec.Rule  `json:"rule,omitempty"`
	Commands         []string        `json:"commands,omitempty"`
	WithdrawCommands []string        `json:"withdraw_commands,omitempty"`
	Attacks          []flowspecActor `json:"attacks,omitempty"`
}

type flowspecActor struct {
	AttackID   int        `json:"attack_id"`
	ActionID   *int       `json:"action_id,omitempty"`
	DetachedAt *time.Time `json:"detached_at,omitempty"`
	AttachedAt time.Time  `json:"attached_at"`
}

func vendorIsExecutable(v flowspec.Vendor) bool { return v == flowspec.VendorFRR }

func ruleFromAnnouncement(a store.BGPAnnouncement) flowspec.Rule {
	var rule flowspec.Rule
	if strings.TrimSpace(a.RuleSpec) != "" {
		_ = json.Unmarshal([]byte(a.RuleSpec), &rule)
	}
	if rule.Name == "" {
		rule.Name = a.RouteMap
	}
	if rule.Prefix == "" {
		rule.Prefix = a.Prefix
	}
	if rule.Action == "" {
		rule.Action = flowspec.ActionDrop
	}
	return rule
}

func buildFlowspecView(a store.BGPAnnouncement, conn *store.BGPConnector) flowspecView {
	vendor := flowspec.VendorFRR
	name := ""
	if conn != nil {
		name = conn.Name
		if v, err := flowspec.ParseVendor(conn.Vendor); err == nil {
			vendor = v
		}
	}
	rule := ruleFromAnnouncement(a)
	cmds, _ := flowspec.Render(vendor, rule)
	wcmds, _ := flowspec.RenderWithdraw(vendor, rule)
	return flowspecView{
		AnnouncementID:   a.ID,
		Prefix:           a.Prefix,
		RuleName:         rule.Name,
		ConnectorID:      a.ConnectorID,
		ConnectorName:    name,
		Vendor:           string(vendor),
		Executable:       vendorIsExecutable(vendor),
		Status:           a.Status,
		Refcount:         a.Refcount,
		ErrorMessage:     a.ErrorMessage,
		AnnouncedAt:      a.AnnouncedAt,
		DelayStartedAt:   a.DelayStartedAt,
		DelayMinutes:     a.DelayMinutes,
		Rule:             &rule,
		Commands:         cmds,
		WithdrawCommands: wcmds,
	}
}

// listFlowspecAnnouncements returns every in-flight Flowspec rule with its
// rendered CLI and the attacks that keep it alive.
func listFlowspecAnnouncements(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		anns, err := deps.Store.BGPAnnouncements().ListActive(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		conns, err := deps.Store.BGPConnectors().List(c)
		if err != nil {
			dbError(c, "", err)
			return
		}
		byID := make(map[int]*store.BGPConnector, len(conns))
		for i := range conns {
			byID[conns[i].ID] = &conns[i]
		}

		views := make([]flowspecView, 0, len(anns))
		for _, a := range anns {
			if a.Kind != "flowspec" {
				continue
			}
			v := buildFlowspecView(a, byID[a.ConnectorID])
			if attacks, aErr := deps.Store.BGPAnnouncements().ListAttacks(c, a.ID); aErr == nil {
				for _, at := range attacks {
					v.Attacks = append(v.Attacks, flowspecActor{
						AttackID:   at.AttackID,
						ActionID:   at.ActionID,
						DetachedAt: at.DetachedAt,
						AttachedAt: at.AttachedAt,
					})
				}
			}
			views = append(views, v)
		}
		ok(c, gin.H{"announcements": views, "vendors": supportedVendors()})
	}
}

// previewFlowspecRule renders a rule without touching FRR. The console uses it
// for the "inspect" drawer and for pre-flight checks before enabling Flowspec
// on a connector.
func previewFlowspecRule(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Vendor   string  `json:"vendor"`
			Name     string  `json:"name"`
			Prefix   string  `json:"prefix" binding:"required"`
			Protocol *uint8  `json:"protocol"`
			DstPort  *uint16 `json:"dst_port"`
			SrcPort  *uint16 `json:"src_port"`
			Action   string  `json:"action"`
			Rate     uint64  `json:"rate_limit"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		vendor, err := normalizeVendor(req.Vendor)
		if err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		rule := flowspec.Rule{
			Name:      strings.TrimSpace(req.Name),
			Prefix:    strings.TrimSpace(req.Prefix),
			Protocol:  req.Protocol,
			DstPort:   req.DstPort,
			SrcPort:   req.SrcPort,
			Action:    flowspec.Action(req.Action),
			RateLimit: req.Rate,
		}
		if rule.Name == "" {
			rule.Name = "preview-rule"
		}
		cmds, err := flowspec.Render(vendor, rule)
		if err != nil {
			errResponse(c, http.StatusBadRequest, err.Error())
			return
		}
		wcmds, _ := flowspec.RenderWithdraw(vendor, rule)
		ok(c, gin.H{
			"vendor":            vendor,
			"rule":              rule,
			"commands":          cmds,
			"withdraw_commands": wcmds,
			"executable":        vendorIsExecutable(vendor),
		})
	}
}

// forceWithdrawFlowspec removes a Flowspec rule from FRR regardless of the
// announcement's refcount, mirroring the RTBH orphan force-withdraw path. Every
// attached attack is detached first so the refcount manager cannot resurrect
// the rule on its next reconcile.
func forceWithdrawFlowspec(deps Dependencies) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			errResponse(c, http.StatusBadRequest, "invalid announcement id")
			return
		}
		if deps.ActionEngine != nil {
			unlock := deps.ActionEngine.LockAnnouncement(id)
			defer unlock()
		}

		ann, err := deps.Store.BGPAnnouncements().Get(c, id)
		if err != nil || ann == nil {
			errResponse(c, http.StatusNotFound, "announcement not found")
			return
		}
		if ann.Kind != "flowspec" {
			errResponse(c, http.StatusBadRequest,
				fmt.Sprintf("announcement %d is kind=%s; use the RTBH force-remove endpoint", ann.ID, ann.Kind))
			return
		}
		if ann.Status == "withdrawn" {
			ok(c, gin.H{"ok": true, "announcement_id": ann.ID, "already_withdrawn": true})
			return
		}

		conn, cErr := deps.Store.BGPConnectors().Get(c, ann.ConnectorID)
		if cErr != nil {
			errResponse(c, http.StatusNotFound, "bgp connector not found")
			return
		}

		rule := ruleFromAnnouncement(*ann)
		vendor, vErr := flowspec.ParseVendor(conn.Vendor)
		if vErr != nil {
			errResponse(c, http.StatusBadRequest, vErr.Error())
			return
		}
		lines, rErr := flowspec.RenderWithdraw(vendor, rule)
		if rErr != nil {
			errResponse(c, http.StatusBadRequest, rErr.Error())
			return
		}

		_, gen, err := deps.Store.BGPAnnouncements().ForceWithdraw(c, ann.ID)
		if err != nil {
			dbError(c, "", err)
			return
		}
		if deps.ActionEngine != nil {
			if gen != ann.Gen {
				deps.ActionEngine.NoteAnnouncementTakeover(ann.ID)
			}
			deps.ActionEngine.CancelAnnouncementDelay(ann.ID, gen, "flowspec force withdraw")
		}

		if !vendorIsExecutable(vendor) {
			if mErr := deps.Store.BGPAnnouncements().MarkWithdrawn(c, ann.ID, gen); mErr != nil {
				dbError(c, "", mErr)
				return
			}
			publishAfterChange(c, deps, "flowspec_force_withdraw", fmt.Sprintf("%d", ann.ID), "force_withdraw",
				jsonOrNil(map[string]any{"announcement_id": ann.ID, "rule": rule.Name, "vendor": vendor}))
			ok(c, gin.H{
				"ok":              true,
				"announcement_id": ann.ID,
				"executable":      false,
				"commands":        lines,
				"warning":         fmt.Sprintf("vendor %s is export-only: apply the generated withdraw manually", vendor),
			})
			return
		}

		ctx, cancel := context.WithTimeout(c, vtyshHTTPTimeout)
		defer cancel()
		args := make([]string, 0, len(lines)*2)
		for _, line := range lines {
			if line = strings.TrimSpace(line); line != "" {
				args = append(args, "-c", line)
			}
		}
		out, vErr2 := runVtyshHTTP(ctx, conn.VtyshPath, args...)
		if vErr2 != nil {
			if mErr := deps.Store.BGPAnnouncements().MarkFailedWithdraw(c, ann.ID, gen, vErr2.Error()); mErr != nil {
				dbError(c, "", mErr)
				return
			}
			log.Printf("api: flowspec force withdraw announcement_id=%d vtysh failed: %v", ann.ID, vErr2)
			ok(c, gin.H{
				"ok":              true,
				"announcement_id": ann.ID,
				"warning":         fmt.Sprintf("vtysh error: %v (row marked failed)", vErr2),
				"output":          strings.TrimSpace(string(out)),
			})
			return
		}

		if mErr := deps.Store.BGPAnnouncements().MarkWithdrawn(c, ann.ID, gen); mErr != nil {
			dbError(c, "", mErr)
			return
		}
		publishAfterChange(c, deps, "flowspec_force_withdraw", fmt.Sprintf("%d", ann.ID), "force_withdraw",
			jsonOrNil(map[string]any{"announcement_id": ann.ID, "rule": rule.Name, "vendor": vendor}))
		log.Printf("api: flowspec force withdraw announcement_id=%d rule=%s vendor=%s", ann.ID, rule.Name, vendor)
		ok(c, gin.H{
			"ok":              true,
			"announcement_id": ann.ID,
			"commands":        lines,
			"output":          strings.TrimSpace(string(out)),
		})
	}
}
