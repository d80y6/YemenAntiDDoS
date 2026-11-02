package tests

import (
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func td104Fallback(t *testing.T, variant string) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		switch variant {
		case "disabled", "evicted":
			f.disable(t)
		case "deleted", "stale_end":
			fzCheck(t, f.s.responses.Delete(fzCtx, 1))
			if variant == "stale_end" {
				f.s.attacks.attacks[0].EndedAt = nil
				live, err := f.s.Attacks().LiveIDs(fzCtx, []int{20})
				fzCheck(t, err)
				fzEqual(t, "LiveIDs still active", live, map[int]bool{20: true})
			}
		case "children_disabled":
			f.s.responses.actions[1].Enabled = false
			f.s.responses.actions[3].Enabled = false
		case "actions_deleted":
			f.s.responses.actions = nil
		case "observe":
			f.e = action.NewEngine(f.s, "observe")
		case "unbound":
			f.event.Attack.ResponseID = nil
		case "list_error":
			f.s.fail("actions")
		}
		if variant == "evicted" {
			f.event.Type = "evicted"
		}
		f.run()
		f.state(t, "withdrawn", "withdrawn", 1, 1)
		want := map[string]float64{"bgp/dispatched": 1, "xdrop/dispatched": 1}
		if variant == "observe" {
			want["bgp/dispatched"] = 0
		}
		f.delta(t, want)
	})
}
func TestTD104_E1_ResponseDisabled(t *testing.T)             { td104Fallback(t, "disabled") }
func TestTD104_E2_ResponseDeleted(t *testing.T)              { td104Fallback(t, "deleted") }
func TestTD104_E2b_DeletedResponseStaleEndedAt(t *testing.T) { td104Fallback(t, "stale_end") }
func TestTD104_E2c_NoResponseBinding(t *testing.T)           { td104Fallback(t, "unbound") }
func TestTD104_E3_ChildrenDisabled(t *testing.T)             { td104Fallback(t, "children_disabled") }
func TestTD104_E4_ActionsDeleted(t *testing.T)               { td104Fallback(t, "actions_deleted") }
func TestTD104_E4b_ListActionsError(t *testing.T)            { td104Fallback(t, "list_error") }
func TestTD104_E5_Observe(t *testing.T)                      { td104Fallback(t, "observe") }
func TestTD104_E6_Evicted(t *testing.T)                      { td104Fallback(t, "evicted") }

func TestTD104_E7_NormalImmediate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		logs := dao5CaptureLog(t)
		f.run()
		f.state(t, "withdrawn", "withdrawn", 1, 1)
		f.delta(t, nil)
		fzEqual(t, "sweep log lines", strings.Count(logs.text(), "ended sweep"), 0)
		fzEqual(t, "recovered execution logs", strings.Count(logs.text(), "recovered xdrop"), 0)
		byAction := map[int]int{}
		for _, l := range f.s.actionExecLog.snapshotLogs() {
			byAction[l.ActionID]++
		}
		// Normal execution writes one BGP log, one rule log and one xDrop
		// summary. A recovered scan would add another rule log at 30.
		fzEqual(t, "execution logs contain only normal actions", byAction, map[int]int{11: 1, 30: 1, 31: 1})
	})
}
func TestTD104_E8_NormalDelayed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 1)
		f.run()
		f.state(t, "delayed", "delayed", 0, 0)
		f.delta(t, nil)
		f.cancel()
	})
}
func TestTD104_E8b_AlreadyDelayedRule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyXDrop()
		f.disable(t)
		fzCheck(t, f.s.MockStore.XDropActiveRules().MarkDelayed(fzCtx, 20, 30, 7, "rule-1", 1))
		f.run()
		fzEqual(t, "ClaimActive calls", f.s.count("claim_active"), 0)
		fzEqual(t, "DELETE", f.d.count(), 0)
		f.delta(t, nil)
	})
}
func TestTD104_E9_SharedAnnouncement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyBGP()
		f.disable(t)
		f.s.attacks.attacks = append(f.s.attacks.attacks, store.Attack{ID: 21})
		_, err := f.s.BGPAnnouncements().Attach(fzCtx, store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21, ActionID: intPtr(10)})
		fzCheck(t, err)
		f.run()
		f.state(t, "active", "", 0, 0)
		a, err := f.s.BGPAnnouncements().Get(fzCtx, f.ann)
		fzCheck(t, err)
		fzEqual(t, "shared refcount", a.Refcount, 1)
		rows, err := f.s.MockStore.BGPAnnouncements().ListAttacks(fzCtx, f.ann)
		fzCheck(t, err)
		for _, r := range rows {
			fzEqual(t, "detached only ended attack", r.DetachedAt != nil, r.AttackID == 20)
		}
		f.delta(t, map[string]float64{"bgp/detached_kept": 1})
	})
}
func TestTD104_E10_DisabledConnectors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.disable(t)
		f.s.bgpConnectors.connectors[0].Enabled = false
		f.s.xdropConnectors.connectors[0].Enabled = false
		f.run()
		f.state(t, "active", "active", 0, 0)
		f.delta(t, map[string]float64{"bgp/skipped_connector": 1, "xdrop/skipped_connector": 1})
	})
}
func TestTD104_E11_ManualOverride(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyXDrop()
		f.disable(t)
		_, err := f.s.ManualOverrides().Create(fzCtx, &store.ActionManualOverride{AttackID: 20, ActionID: 30, ConnectorID: 7, ExternalRuleID: "rule-1"})
		fzCheck(t, err)
		f.run()
		fzEqual(t, "DELETE", f.d.count(), 0)
		f.delta(t, map[string]float64{"xdrop/skipped_override": 1})
	})
}
func TestTD104_E12_DispatcherNotBlocked(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyBGP()
		f.disable(t)
		release := make(chan struct{})
		f.s.hook("attachments", func() { <-release })
		f.e.Start()
		f.e.Enqueue(f.event)
		synctest.Wait()
		second := f.event
		second.Type = "confirmed"
		entered := make(chan struct{}, 1)
		f.s.hook("response", func() { entered <- struct{}{} })
		f.e.Enqueue(second)
		select {
		case <-entered:
			t.Log("second event entered within 5s")
		case <-time.After(5 * time.Second):
			t.Error("second event blocked by sweep")
		}
		close(release)
		synctest.Wait()
		f.state(t, "withdrawn", "", 1, 0)
		f.stopQueue()
	})
}
func TestTD104_E13_OnlyEndEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.disable(t)
		for _, kind := range []string{"confirmed", "updated"} {
			f.event.Type = kind
			f.run()
		}
		fzEqual(t, "attachment scans", f.s.count("attachments"), 0)
		fzEqual(t, "rule scans", f.s.count("rules"), 0)
	})
}
func td104Drift(t *testing.T, kind string) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyBGP()
		switch kind {
		case "route_map":
			f.s.responses.actions[0].BGPRouteMap = "RM2"
			f.s.responses.actions[1].BGPRouteMap = "RM2"
		case "connector":
			c := f.s.bgpConnectors.connectors[0]
			c.ID = 8
			f.s.bgpConnectors.connectors = append(f.s.bgpConnectors.connectors, c)
			f.s.responses.actions[0].BGPConnectorID = intPtr(8)
			f.s.responses.actions[1].BGPConnectorID = intPtr(8)
		case "precondition":
			_, err := f.s.Preconditions().Create(fzCtx, &store.ActionPrecondition{ActionID: 11, Attribute: "pps", Operator: "gt", Value: "999999"})
			fzCheck(t, err)
		case "first_match":
			// The second parent owns the attachment. At exit the first child wins ACL.
			p, c := f.s.responses.actions[0], f.s.responses.actions[1]
			p.ID = 12
			c.ID = 13
			f.s.responses.actions[0].BGPRouteMap = "RM2"
			f.s.responses.actions[1].BGPRouteMap = "RM2"
			f.s.responses.actions = append(f.s.responses.actions, p, c)
			_, err := f.s.Preconditions().Create(fzCtx, &store.ActionPrecondition{ActionID: 10, Attribute: "pps", Operator: "gt", Value: "999999"})
			fzCheck(t, err)
			detected := f.event
			detected.Type = "confirmed"
			f.e.HandleEvent(detected)
			synctest.Wait()
			rows, err := f.s.MockStore.BGPAnnouncements().ListAttacks(fzCtx, f.ann)
			fzCheck(t, err)
			fzEqual(t, "second detected action owns attachment", *rows[0].ActionID, 12)
		}
		f.run()
		f.state(t, "withdrawn", "", 1, 0)
		f.delta(t, map[string]float64{"bgp/dispatched": 1})
	})
}
func TestTD104_E14_RouteMapDrift(t *testing.T)            { td104Drift(t, "route_map") }
func TestTD104_E14b_ConnectorDrift(t *testing.T)          { td104Drift(t, "connector") }
func TestTD104_E14c_PreconditionBlocksChild(t *testing.T) { td104Drift(t, "precondition") }
func TestTD104_E14d_FirstMatchMismatch(t *testing.T)      { td104Drift(t, "first_match") }
func TestTD104_E15_WaitsForChild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyBGP()
		gate := make(chan struct{})
		f.s.hook("detach", func() { <-gate })
		f.run()
		fzEqual(t, "child entered Detach", f.s.count("detach"), 1)
		fzEqual(t, "reconcile before child", f.s.count("reconcile"), 0)
		close(gate)
		synctest.Wait()
		f.state(t, "withdrawn", "", 1, 0)
		f.delta(t, nil)
	})
}
func TestTD104_E16_MetricLabelSet(t *testing.T) {
	f := td104New(t, 0)
	got := map[string]bool{}
	for k := range f.values(t) {
		got[k] = true
	}
	want := map[string]bool{}
	for kind, outcomes := range map[string][]string{"bgp": {"dispatched", "detached_kept", "skipped_status", "skipped_connector", "failed"}, "xdrop": {"dispatched", "skipped_connector", "skipped_override", "skipped_scheduled", "skipped_claimed", "failed"}} {
		for _, o := range outcomes {
			want[kind+"/"+o] = true
		}
	}
	fzEqual(t, "labels gathered before WithLabelValues", got, want)
}
