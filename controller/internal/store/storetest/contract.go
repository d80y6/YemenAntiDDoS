// Package storetest contains shared repository contracts, imported only by tests.
package storetest

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Backend permits explicit timestamp fixtures without changing production APIs.
type Backend interface {
	Store() store.Store
	SetTime(table, idColumn string, id int, column string, value time.Time) error
}

var ctx = context.Background()

func stamp(second int) time.Time { return time.Date(2025, 1, 2, 3, 4, second, 0, time.UTC) }
func ptr[T any](v T) *T          { return &v }
func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func equal(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}
func seedAttack(t *testing.T, s store.Store, a store.Attack) int {
	t.Helper()
	if a.DstIP == "" {
		a.DstIP = "192.0.2.1"
	}
	if a.Direction == "" {
		a.Direction = "receives"
	}
	if a.DecoderFamily == "" {
		a.DecoderFamily = "udp"
	}
	if a.StartedAt.IsZero() {
		n, err := s.Attacks().Count(ctx, store.AttackFilter{})
		check(t, err)
		a.StartedAt = stamp(0).Add(time.Duration(n) * time.Microsecond)
	}
	ended := a.EndedAt
	a.EndedAt = nil
	id, err := s.Attacks().Create(ctx, &a)
	check(t, err)
	if ended != nil {
		a.ID = id
		a.EndedAt = ended
		check(t, s.Attacks().Update(ctx, &a))
	}
	return id
}
func seedResponse(t *testing.T, s store.Store, name string) int {
	t.Helper()
	id, err := s.Responses().Create(ctx, &store.Response{Name: name, Enabled: true})
	check(t, err)
	return id
}
func seedAction(t *testing.T, s store.Store, responseID int) int {
	t.Helper()
	a := action(responseID)
	id, err := s.Responses().CreateAction(ctx, &a)
	check(t, err)
	return id
}
func action(responseID int) store.ResponseAction {
	return store.ResponseAction{ResponseID: responseID, ActionType: "webhook", ExecutionPolicy: "once_on_enter", Config: []byte(`{}`), Preconditions: []byte(`[]`), Enabled: true, TriggerPhase: "on_detected", RunMode: "once", Execution: "automatic"}
}
func attackIDs(rows []store.Attack) []int {
	out := []int{}
	for _, r := range rows {
		out = append(out, r.ID)
	}
	return out
}
func setTime(t *testing.T, b Backend, table, key string, id int, column string, second int) {
	t.Helper()
	check(t, b.SetTime(table, key, id, column, stamp(second)))
}

// verifyTimes verifies persistence independently of returned order. It never sorts rows.
func verifyTimes(t *testing.T, got map[int]time.Time, ids []int) {
	t.Helper()
	equal(t, len(got), 3)
	for i, second := range []int{20, 40, 10} {
		equal(t, got[ids[i]].Equal(stamp(second)), true)
	}
}

// RunContract opens an empty backend for each leaf; both runners share names and assertions.
func RunContract(t *testing.T, open func(*testing.T) Backend) {
	runFuzhuoContract(t, open)
	runDao5Contract(t, open)
	run := func(name string, f func(*testing.T, Backend)) { t.Run(name, func(t *testing.T) { f(t, open(t)) }) }
	run("ActionExecLog/ListByAttack/OrderExecutedAtDesc", func(t *testing.T, b Backend) {
		s := b.Store()
		ids := []int{}
		for _, sec := range []int{20, 40, 10} {
			id, err := s.ActionExecLog().Create(ctx, &store.ActionExecutionLog{AttackID: 10, ActionID: 20, Status: "success"})
			check(t, err)
			ids = append(ids, id)
			setTime(t, b, "action_execution_log", "id", id, "executed_at", sec)
		}
		_, err := s.ActionExecLog().Create(ctx, &store.ActionExecutionLog{AttackID: 11, Status: "success"})
		check(t, err)
		rows, err := s.ActionExecLog().ListByAttack(ctx, 10)
		check(t, err)
		times := map[int]time.Time{}
		got := []int{}
		for _, r := range rows {
			times[r.ID] = r.ExecutedAt
			got = append(got, r.ID)
		}
		verifyTimes(t, times, ids)
		// postgres/action_exec_log.go: actionExecLogRepo.ListByAttack WHERE attack_id, executed_at DESC.
		equal(t, got, []int{ids[1], ids[0], ids[2]})
	})
	run("Attacks/ListActive/OrderPeakPPSDesc", func(t *testing.T, b Backend) {
		s := b.Store()
		ids := []int{}
		for _, pps := range []int64{20, 40, 10} {
			ids = append(ids, seedAttack(t, s, store.Attack{PeakPPS: pps}))
		}
		seedAttack(t, s, store.Attack{PeakPPS: 100, EndedAt: ptr(stamp(50))})
		rows, err := s.Attacks().ListActive(ctx, 2)
		check(t, err)
		// postgres/attack.go: attackRepo.ListActive excludes ended rows, orders peak_pps DESC before LIMIT.
		equal(t, attackIDs(rows), []int{ids[1], ids[0]})
	})
	for _, tc := range []struct {
		name           string
		limit, n, want int
	}{{"DefaultZero", 0, 101, 100}, {"DefaultNegative", -1, 101, 100}, {"Cap1000", 1001, 1001, 1000}} {
		run("Attacks/ListActive/"+tc.name, func(t *testing.T, b Backend) {
			s := b.Store()
			for i := 0; i < tc.n; i++ {
				seedAttack(t, s, store.Attack{PeakPPS: int64(i)})
			}
			rows, err := s.Attacks().ListActive(ctx, tc.limit)
			check(t, err)
			// postgres/attack.go: attackRepo.ListActive defaults to 100 and caps at 1000 (current behavior, see TD-114 / D-17).
			equal(t, len(rows), tc.want)
		})
	}
	// TD-009: ListAllActive is the recovery-only read; no cap, active rows only, id order.
	run("Attacks/ListAllActive/NoCap", func(t *testing.T, b Backend) {
		s := b.Store()
		for i := 0; i < 1001; i++ {
			seedAttack(t, s, store.Attack{PeakPPS: int64(i)})
		}
		rows, err := s.Attacks().ListAllActive(ctx)
		check(t, err)
		// postgres/attack.go: attackRepo.ListAllActive has no LIMIT (TD-114's 1000 cap stays on ListActive).
		equal(t, len(rows), 1001)
	})
	run("Attacks/ListAllActive/OnlyActive", func(t *testing.T, b Backend) {
		s := b.Store()
		a := seedAttack(t, s, store.Attack{PeakPPS: 10})
		ended := seedAttack(t, s, store.Attack{PeakPPS: 100, EndedAt: ptr(stamp(50))})
		c := seedAttack(t, s, store.Attack{PeakPPS: 20})
		got, err := s.Attacks().Get(ctx, ended)
		check(t, err)
		if got.EndedAt == nil {
			t.Fatal("device: ended seed still active (seedAttack must Create then Update)")
		}
		rows, err := s.Attacks().ListAllActive(ctx)
		check(t, err)
		// postgres/attack.go: attackRepo.ListAllActive WHERE ended_at IS NULL.
		byID := map[int]store.Attack{}
		for _, r := range rows {
			byID[r.ID] = r
		}
		equal(t, len(rows), 2)
		equal(t, len(byID), 2)
		// Same column set and scan shape as ListActive (dst_ip text etc.).
		ref, err := s.Attacks().ListActive(ctx, 1000)
		check(t, err)
		equal(t, len(ref), 2)
		for _, r := range ref {
			equal(t, byID[r.ID], r)
		}
		_, okA := byID[a]
		_, okC := byID[c]
		equal(t, okA && okC, true)
	})
	run("Attacks/ListAllActive/OrderID", func(t *testing.T, b Backend) {
		s := b.Store()
		ids := []int{}
		for _, pps := range []int64{10, 20, 30} {
			ids = append(ids, seedAttack(t, s, store.Attack{PeakPPS: pps}))
		}
		rows, err := s.Attacks().ListAllActive(ctx)
		check(t, err)
		// postgres/attack.go: attackRepo.ListAllActive ORDER BY id (peak rises with id, opposite of ListActive).
		equal(t, attackIDs(rows), ids)
	})
	for _, name := range []string{"Direction", "Prefix", "TimeRangeInclusive", "OrderStartedAtDesc", "Pagination", "Status"} {
		run("Attacks/List/"+name, func(t *testing.T, b Backend) {
			s := b.Store()
			var prefixID *int
			if name == "Prefix" {
				id, err := s.Prefixes().Create(ctx, &store.WatchPrefix{Prefix: "192.0.2.0/24", Name: "contract", Enabled: true})
				check(t, err)
				prefixID = &id
			}
			a := seedAttack(t, s, store.Attack{Direction: "receives", StartedAt: stamp(20), PrefixID: prefixID})
			c := seedAttack(t, s, store.Attack{Direction: "sends", StartedAt: stamp(40), EndedAt: ptr(stamp(50))})
			d := seedAttack(t, s, store.Attack{Direction: "receives", StartedAt: stamp(10), PrefixID: prefixID})
			f := store.AttackFilter{}
			want := []int{c, a, d}
			switch name {
			case "Direction":
				f.Direction = "receives"
				want = []int{a, d}
			case "Prefix":
				f.PrefixID = prefixID
				want = []int{a, d}
			case "TimeRangeInclusive":
				seedAttack(t, s, store.Attack{StartedAt: stamp(5)})
				f.TimeFrom = ptr(stamp(10))
				f.TimeTo = ptr(stamp(20))
				want = []int{a, d}
			case "Pagination":
				f.Limit = 1
				f.Offset = 1
				want = []int{a}
			case "Status":
				f.Status = "expired"
				want = []int{c}
			}
			rows, err := s.Attacks().List(ctx, f)
			check(t, err)
			// postgres/attack.go: attackRepo.List + buildAttackWhere; inclusive started_at endpoints, ORDER DESC, LIMIT/OFFSET.
			equal(t, attackIDs(rows), want)
		})
	}
	for _, tc := range []struct {
		name           string
		limit, n, want int
	}{{"DefaultLimit", 0, 101, 100}, {"NegativeDefaultLimit", -1, 101, 100}, {"NoCap1000", 1001, 1001, 1001}} {
		run("Attacks/List/"+tc.name, func(t *testing.T, b Backend) {
			s := b.Store()
			for i := 0; i < tc.n; i++ {
				seedAttack(t, s, store.Attack{StartedAt: stamp(i)})
			}
			rows, err := s.Attacks().List(ctx, store.AttackFilter{Limit: tc.limit})
			check(t, err)
			// postgres/attack.go: attackRepo.List defaults nonpositive limits to 100, with no upper cap.
			equal(t, len(rows), tc.want)
		})
	}
	run("Attacks/Count/FiltersWithoutPagination", func(t *testing.T, b Backend) {
		s := b.Store()
		id, err := s.Prefixes().Create(ctx, &store.WatchPrefix{Prefix: "192.0.2.0/24", Name: "count", Enabled: true})
		check(t, err)
		for _, a := range []store.Attack{
			{Direction: "receives", PrefixID: &id, StartedAt: stamp(10)}, {Direction: "receives", PrefixID: &id, StartedAt: stamp(20)},
			{Direction: "sends", PrefixID: &id, StartedAt: stamp(15)}, {Direction: "receives", StartedAt: stamp(15)},
			{Direction: "receives", PrefixID: &id, StartedAt: stamp(5)}, {Direction: "receives", PrefixID: &id, StartedAt: stamp(25)},
			{Direction: "receives", PrefixID: &id, StartedAt: stamp(16), EndedAt: ptr(stamp(50))},
		} {
			seedAttack(t, s, a)
		}
		n, err := s.Attacks().Count(ctx, store.AttackFilter{Status: "active", Direction: "receives", PrefixID: &id, TimeFrom: ptr(stamp(10)), TimeTo: ptr(stamp(20)), Limit: 1, Offset: 99})
		check(t, err)
		// postgres/attack.go: attackRepo.Count uses buildAttackWhere and ignores pagination.
		equal(t, n, 2)
	})
	run("Attacks/Create/IgnoresEndedAt", func(t *testing.T, b Backend) {
		s := b.Store()
		id, err := s.Attacks().Create(ctx, &store.Attack{DstIP: "192.0.2.1", Direction: "receives", DecoderFamily: "udp", StartedAt: stamp(10), EndedAt: ptr(stamp(20))})
		check(t, err)
		a, err := s.Attacks().Get(ctx, id)
		check(t, err)
		// postgres/attack.go: attackRepo.Create INSERT omits ended_at.
		equal(t, a.EndedAt == nil, true)
	})
	run("Attacks/Update/MutableColumnsOnly", func(t *testing.T, b Backend) {
		s := b.Store()
		id := seedAttack(t, s, store.Attack{StartedAt: stamp(10), TemplateName: ptr("original"), RuleSummary: ptr("rule")})
		a, err := s.Attacks().Get(ctx, id)
		check(t, err)
		a.DstIP = "198.51.100.2"
		a.Direction = "sends"
		a.PrefixID = ptr(-1)
		a.DecoderFamily = "tcp"
		a.StartedAt = stamp(20)
		a.TemplateName = ptr("changed")
		a.RuleSummary = ptr("changed")
		a.ThresholdRuleID = ptr(-1)
		a.AttackType = "flood"
		a.Severity = "critical"
		a.Confidence = .75
		a.PeakPPS = 42
		a.PeakBPS = 84
		a.ReasonCodes = []string{"rate"}
		a.NodeSources = []string{"node"}
		a.EndedAt = ptr(stamp(50))
		check(t, s.Attacks().Update(ctx, a))
		got, err := s.Attacks().Get(ctx, id)
		check(t, err)
		// postgres/attack.go: attackRepo.Update SET explicitly enumerates mutable columns, leaving identity/snapshots unchanged.
		equal(t, got.Direction, "receives")
		// INET::TEXT may include a host mask; the stored destination address must stay unchanged.
		equal(t, strings.Split(got.DstIP, "/")[0], "192.0.2.1")
		equal(t, got.PrefixID == nil, true)
		equal(t, got.DecoderFamily, "udp")
		equal(t, got.StartedAt.Equal(stamp(10)), true)
		equal(t, *got.TemplateName, "original")
		equal(t, *got.RuleSummary, "rule")
		equal(t, got.ThresholdRuleID == nil, true)
		equal(t, got.AttackType, "flood")
		equal(t, got.Severity, "critical")
		equal(t, got.Confidence, float32(.75))
		equal(t, got.PeakPPS, int64(42))
		equal(t, got.PeakBPS, int64(84))
		equal(t, got.ReasonCodes, []string{"rate"})
		equal(t, got.NodeSources, []string{"node"})
		equal(t, got.EndedAt.Equal(stamp(50)), true)
	})
	run("Attacks/Create/ArrayNilness", func(t *testing.T, b Backend) {
		s := b.Store()
		emptyID := seedAttack(t, s, store.Attack{ReasonCodes: []string{}, NodeSources: []string{}})
		nilID := seedAttack(t, s, store.Attack{})
		empty, err := s.Attacks().Get(ctx, emptyID)
		check(t, err)
		nilArrays, err := s.Attacks().Get(ctx, nilID)
		check(t, err)
		// postgres/attack.go: attackRepo.Create passes reason_codes/node_sources directly to pgx TEXT[].
		// Empty arrays and SQL NULL are distinct; Get scans them into nonnil-empty and nil slices respectively.
		equal(t, empty.ReasonCodes, []string{})
		equal(t, empty.NodeSources, []string{})
		equal(t, nilArrays.ReasonCodes, []string(nil))
		equal(t, nilArrays.NodeSources, []string(nil))
	})
	for _, name := range []string{"EmptyArrays", "NilArrays"} {
		run("Attacks/Update/"+name, func(t *testing.T, b Backend) {
			s := b.Store()
			id := seedAttack(t, s, store.Attack{ReasonCodes: []string{"old"}, NodeSources: []string{"node"}})
			a, err := s.Attacks().Get(ctx, id)
			check(t, err)
			var want []string
			if name == "EmptyArrays" {
				want = []string{}
			}
			a.ReasonCodes, a.NodeSources = want, want
			check(t, s.Attacks().Update(ctx, a))
			got, err := s.Attacks().Get(ctx, id)
			check(t, err)
			// postgres/attack.go: attackRepo.Update writes TEXT[] parameters $6/$7 without collapsing empty arrays to NULL.
			equal(t, got.ReasonCodes, want)
			equal(t, got.NodeSources, want)
		})
	}
	run("Attacks/Update/ResponseID", func(t *testing.T, b Backend) {
		s := b.Store()
		r1, r2 := seedResponse(t, s, "r1"), seedResponse(t, s, "r2")
		id := seedAttack(t, s, store.Attack{ResponseID: &r1})
		a, err := s.Attacks().Get(ctx, id)
		check(t, err)
		equal(t, a.ResponseID, &r1)
		a.ResponseID = &r2
		check(t, s.Attacks().Update(ctx, a))
		got, err := s.Attacks().Get(ctx, id)
		check(t, err)
		// postgres/attack.go: attackRepo.Update SET response_id=$8, validated by two existing response rows.
		equal(t, got.ResponseID, &r2)
	})
	responseContracts(run)
	scheduleContracts(run)
	bgpContracts(run)
	ruleContracts(run)
	connectorContracts(run)
	preconditionContracts(run)
	dao4Contracts(run)
}

type runner func(string, func(*testing.T, Backend))

func responseContracts(run runner) {
	run("Responses/Create/PersistsFields", func(t *testing.T, b Backend) {
		s := b.Store()
		id, err := s.Responses().Create(ctx, &store.Response{Name: "response", Description: "description", Enabled: true})
		// postgres/response.go: responseRepo.Create inserts name, description, enabled.
		check(t, err)
		r, err := s.Responses().Get(ctx, id)
		check(t, err)
		equal(t, r.Name, "response")
		equal(t, r.Description, "description")
		equal(t, r.Enabled, true)
	})
	run("Responses/List/RowsAndActionCounts", func(t *testing.T, b Backend) {
		s := b.Store()
		ids := []int{seedResponse(t, s, "third"), seedResponse(t, s, "first"), seedResponse(t, s, "second")}
		seedAction(t, s, ids[1])
		seedAction(t, s, ids[1])
		seedAction(t, s, ids[2])
		rows, err := s.Responses().List(ctx)
		check(t, err)
		counts := map[int]int{}
		for _, r := range rows {
			counts[r.ID] = r.ActionCount
			equal(t, r.BoundTemplateCount, 0)
		}
		// postgres/response.go: responseRepo.List returns all responses with action/template count LEFT JOINs.
		// SERIAL allocation already follows insertion order; this is a membership/count contract, not a sort fixture.
		equal(t, len(rows), 3)
		equal(t, counts, map[int]int{ids[0]: 0, ids[1]: 2, ids[2]: 1})
	})
	run("Responses/Update/PersistsFields", func(t *testing.T, b Backend) {
		s := b.Store()
		id := seedResponse(t, s, "before")
		check(t, s.Responses().Update(ctx, &store.Response{ID: id, Name: "after", Description: "new", Enabled: false}))
		r, err := s.Responses().Get(ctx, id)
		check(t, err)
		// postgres/response.go: responseRepo.Update changes name, description, enabled.
		equal(t, r.Name, "after")
		equal(t, r.Description, "new")
		equal(t, r.Enabled, false)
	})
	run("Responses/Delete/RemovesOnlyTargetAndActions", func(t *testing.T, b Backend) {
		s := b.Store()
		id := seedResponse(t, s, "delete")
		other := seedResponse(t, s, "keep")
		removedAction := seedAction(t, s, id)
		keptAction := seedAction(t, s, other)
		unrelatedAction := seedAction(t, s, other)
		check(t, s.Responses().SetPairedWith(ctx, keptAction, &removedAction))
		check(t, s.Responses().SetPairedWith(ctx, unrelatedAction, &keptAction))
		for _, aid := range []int{removedAction, keptAction} {
			_, err := s.Preconditions().Create(ctx, &store.ActionPrecondition{ActionID: aid, Attribute: "pps", Operator: "gt", Value: "10"})
			check(t, err)
		}
		cid, err := s.XDropConnectors().Create(ctx, &store.XDropConnector{Name: "cascade", APIURL: "http://example.invalid"})
		check(t, err)
		check(t, s.XDropTargets().Set(ctx, removedAction, []int{cid}))
		check(t, s.XDropTargets().Set(ctx, keptAction, []int{cid}))
		attackID := seedAttack(t, s, store.Attack{ResponseID: &id})
		keptAttackID := seedAttack(t, s, store.Attack{ResponseID: &other})
		templateID, err := s.ThresholdTemplates().Create(ctx, &store.ThresholdTemplate{Name: "cascade", ResponseID: &id})
		check(t, err)
		keptTemplateID, err := s.ThresholdTemplates().Create(ctx, &store.ThresholdTemplate{Name: "keep", ResponseID: &other})
		check(t, err)
		threshold := store.Threshold{TemplateID: &templateID, ResponseID: &id, Domain: "subnet", Direction: "receives", Decoder: "udp", Unit: "pps", Comparison: "over", Value: 100, Enabled: true}
		thresholdID, err := s.Thresholds().Create(ctx, &threshold)
		check(t, err)
		threshold.TemplateID, threshold.ResponseID = &keptTemplateID, &other
		keptThresholdID, err := s.Thresholds().Create(ctx, &threshold)
		check(t, err)
		check(t, s.Responses().Delete(ctx, id))
		rows, err := s.Responses().List(ctx)
		check(t, err)
		actions, err := s.Responses().ListActions(ctx, id)
		check(t, err)
		// postgres/response.go: responseRepo.Delete; postgres.go migrations response_actions ON DELETE CASCADE.
		equal(t, len(rows), 1)
		equal(t, rows[0].ID, other)
		// postgres/response.go: responseRepo.List counts the surviving template bound to the other response.
		equal(t, rows[0].BoundTemplateCount, 1)
		equal(t, len(actions), 0)
		// postgres.go: migrations action_preconditions.action_id and response_action_xdrop_targets.action_id ON DELETE CASCADE.
		conditions, err := s.Preconditions().List(ctx, removedAction)
		check(t, err)
		equal(t, len(conditions), 0)
		targets, err := s.XDropTargets().List(ctx, removedAction)
		check(t, err)
		equal(t, len(targets), 0)
		conditions, err = s.Preconditions().List(ctx, keptAction)
		check(t, err)
		equal(t, len(conditions), 1)
		targets, err = s.XDropTargets().List(ctx, keptAction)
		check(t, err)
		equal(t, len(targets), 1)
		equal(t, targets[0].ID, cid)
		// postgres.go: migrations attacks/thresholds/threshold_templates.response_id ON DELETE SET NULL; unrelated references survive.
		for _, tc := range []struct {
			attack, template, threshold int
			response                    *int
		}{{attackID, templateID, thresholdID, nil}, {keptAttackID, keptTemplateID, keptThresholdID, &other}} {
			a, err := s.Attacks().Get(ctx, tc.attack)
			check(t, err)
			equal(t, a.ResponseID, tc.response)
			template, err := s.ThresholdTemplates().Get(ctx, tc.template)
			check(t, err)
			equal(t, template.ResponseID, tc.response)
			rule, err := s.Thresholds().Get(ctx, tc.threshold)
			check(t, err)
			equal(t, rule.ResponseID, tc.response)
		}
		// postgres.go: migrations response_actions.paired_with self-FK ON DELETE SET NULL.
		paired, err := s.Responses().GetAction(ctx, keptAction)
		check(t, err)
		equal(t, paired.PairedWith, (*int)(nil))
		unrelated, err := s.Responses().GetAction(ctx, unrelatedAction)
		check(t, err)
		equal(t, unrelated.PairedWith, &keptAction)
	})
	run("Responses/Delete/ActionsLogSetNullReadBehavior", func(t *testing.T, b Backend) {
		s := b.Store()
		rid := seedResponse(t, s, "delete-log-action")
		aid := seedAction(t, s, rid)
		attackID := seedAttack(t, s, store.Attack{})
		logID, err := s.ActionsLog().Create(ctx, &store.ActionLog{AttackID: attackID, ActionID: aid, ExecutionPolicy: "once_on_enter", Status: "success", FirstAttemptAt: stamp(10), LastAttemptAt: stamp(20)})
		check(t, err)
		seed, err := s.ActionsLog().FindByAttackAndAction(ctx, attackID, aid)
		check(t, err)
		if seed == nil {
			t.Fatal("seed: action log missing")
		}
		equal(t, seed.ID, logID)
		check(t, s.Responses().Delete(ctx, rid))
		// postgres.go: migrations actions_log.action_id ON DELETE SET NULL, not CASCADE.
		// postgres/actions_log.go: actionsLogRepo.FindByAttackAndAction no longer matches the deleted action ID.
		got, err := s.ActionsLog().FindByAttackAndAction(ctx, attackID, aid)
		check(t, err)
		equal(t, got, (*store.ActionLog)(nil))
		// Current behavior, see TD-115: actionsLogRepo.ListByAttack retains the row but scans NULL action_id into ActionLog.ActionID (int), which pgx rejects.
		// Assert the scan failure to distinguish SET NULL from incorrectly deleting the log row.
		_, err = s.ActionsLog().ListByAttack(ctx, attackID)
		if err == nil || !strings.Contains(err.Error(), "cannot scan NULL") {
			t.Fatalf("retained log with NULL action_id: got error %v; want cannot scan NULL", err)
		}
	})
	for _, kind := range []string{"Webhook", "Shell", "BGP"} {
		run("Responses/CountActionsBy"+kind+"Connector/CountsDisabledAndOtherTypes", func(t *testing.T, b Backend) {
			s := b.Store()
			rid := seedResponse(t, s, "count")
			var cid int
			var err error
			switch kind {
			case "Webhook":
				cid, err = s.WebhookConnectors().Create(ctx, &store.WebhookConnector{Name: "web", URL: "http://example.invalid", Method: "POST"})
			case "Shell":
				cid, err = s.ShellConnectors().Create(ctx, &store.ShellConnector{Name: "shell", Command: "true"})
			case "BGP":
				cid, err = s.BGPConnectors().Create(ctx, &store.BGPConnector{Name: "bgp", BGPASN: 64512, AddressFamily: "auto"})
			}
			check(t, err)
			for i := 0; i < 3; i++ {
				a := action(rid)
				a.Enabled = i == 0
				if kind == "Webhook" {
					a.WebhookConnectorID = &cid
					a.ActionType = "shell"
				}
				if kind == "Shell" {
					a.ShellConnectorID = &cid
					a.ActionType = "webhook"
				}
				if kind == "BGP" {
					a.BGPConnectorID = &cid
					a.ActionType = "webhook"
				}
				_, err = s.Responses().CreateAction(ctx, &a)
				check(t, err)
			}
			seedAction(t, s, rid)
			var n int
			switch kind {
			case "Webhook":
				n, err = s.Responses().CountActionsByWebhookConnector(ctx, cid)
			case "Shell":
				n, err = s.Responses().CountActionsByShellConnector(ctx, cid)
			case "BGP":
				n, err = s.Responses().CountActionsByBGPConnector(ctx, cid)
			}
			check(t, err)
			// postgres/response.go: responseRepo.CountActionsByWebhookConnector,
			// CountActionsByShellConnector and CountActionsByBGPConnector filter only connector ID, neither enabled nor action_type.
			equal(t, n, 3)
		})
	}
}

func scheduleContracts(run runner) {
	run("ScheduledActions/ListPending/OrderScheduledForAsc", func(t *testing.T, b Backend) {
		s := b.Store()
		ids := []int{}
		for i, sec := range []int{20, 40, 10} {
			id, err := s.ScheduledActions().Schedule(ctx, &store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: i + 1, ScheduledFor: stamp(sec)})
			check(t, err)
			ids = append(ids, id)
		}
		id, err := s.ScheduledActions().Schedule(ctx, &store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: 99, ScheduledFor: stamp(0)})
		check(t, err)
		check(t, s.ScheduledActions().Cancel(ctx, id, "contract"))
		rows, err := s.ScheduledActions().ListPending(ctx)
		check(t, err)
		times := map[int]time.Time{}
		got := []int{}
		for _, r := range rows {
			times[r.ID] = r.ScheduledFor
			got = append(got, r.ID)
		}
		verifyTimes(t, times, ids)
		// postgres/scheduled_actions.go: scheduledActionRepo.ListPending/listByStatus pending only, scheduled_for ASC.
		equal(t, got, []int{ids[2], ids[0], ids[1]})
	})
	run("ScheduledActions/Schedule/DisjointArtifactIdentity", func(t *testing.T, b Backend) {
		s := b.Store()
		ann := 77
		a, err := s.ScheduledActions().Schedule(ctx, &store.ScheduledAction{ActionType: "bgp_withdraw", AnnouncementID: &ann, ScheduledFor: stamp(10)})
		check(t, err)
		artifact := store.ScheduledAction{ActionType: "bgp_withdraw", ScheduledFor: stamp(20)}
		id, err := s.ScheduledActions().Schedule(ctx, &artifact)
		check(t, err)
		// postgres/scheduled_actions.go: scheduledActionRepo.Schedule artifact conflict predicate requires announcement_id IS NULL.
		equal(t, id != a, true)
		artifact.ScheduledFor = stamp(40)
		again, err := s.ScheduledActions().Schedule(ctx, &artifact)
		check(t, err)
		equal(t, again, id)
		rows, err := s.ScheduledActions().ListPending(ctx)
		check(t, err)
		equal(t, len(rows), 2)
		for _, r := range rows {
			if r.ID == a {
				equal(t, r.ScheduledFor.Equal(stamp(10)), true)
			} else {
				equal(t, r.ScheduledFor.Equal(stamp(40)), true)
			}
		}
	})
	run("ScheduledActions/Schedule/AnnouncementZeroesArtifact", func(t *testing.T, b Backend) {
		s := b.Store()
		id, err := s.ScheduledActions().Schedule(ctx, &store.ScheduledAction{ActionType: "bgp_withdraw", AnnouncementID: ptr(77), AttackID: 11, ActionID: 22, ConnectorID: 33, ExternalRuleID: "discard", ScheduledFor: stamp(10)})
		check(t, err)
		rows, err := s.ScheduledActions().ListPending(ctx)
		check(t, err)
		// postgres/scheduled_actions.go: scheduledActionRepo.Schedule announcement INSERT hardcodes 0,0,0,''.
		equal(t, len(rows), 1)
		equal(t, rows[0].ID, id)
		equal(t, rows[0].AttackID, 0)
		equal(t, rows[0].ActionID, 0)
		equal(t, rows[0].ConnectorID, 0)
		equal(t, rows[0].ExternalRuleID, "")
	})
}

func bgpContracts(run runner) {
	for _, delay := range []int{0, 5} {
		run(fmt.Sprintf("BGPAnnouncements/Detach/GuardFailedDelay%d", delay), func(t *testing.T, b Backend) {
			r := b.Store().BGPAnnouncements()
			a, err := r.Attach(ctx, store.BGPAttachParams{AttackID: 10, Prefix: "192.0.2.0/24", ConnectorID: 1, DelayMinutes: delay})
			check(t, err)
			fuzhuoSet(t, b, a.AnnouncementID, 1, "failed")
			result, err := r.Detach(ctx, 10, "192.0.2.0/24", "", 1)
			check(t, err)
			got, err := r.Get(ctx, a.AnnouncementID)
			check(t, err)
			// postgres/bgp_announcements.go: bgpAnnouncementRepo.Detach guards only status UPDATE, not attachment/refcount/event writes.
			equal(t, got.Status, "failed")
			equal(t, got.Refcount, 0)
			equal(t, got.DelayStartedAt == nil, true)
			attachments, err := r.ListAttacks(ctx, a.AnnouncementID)
			check(t, err)
			equal(t, len(attachments), 1)
			equal(t, attachments[0].DetachedAt != nil, true)
			events, err := r.ListEvents(ctx, a.AnnouncementID)
			check(t, err)
			detached, delayed := 0, 0
			for _, e := range events {
				if e.EventType == store.BGPEventAttackDetached {
					detached++
				}
				if e.EventType == store.BGPEventDelayStarted {
					delayed++
				}
			}
			equal(t, detached, 1)
			// Current behavior, see TD-116 / D-18: Detach ignores affected-row count and still reports intent after a guarded no-op.
			equal(t, result.NeedWithdraw, delay == 0)
			equal(t, result.Delayed, delay > 0)
			equal(t, result.RefcountAfter, 0)
			if delay > 0 {
				equal(t, delayed, 1)
				equal(t, result.DelayMinutes, 5)
			}
		})
	}
	for _, method := range []string{"ListActive", "ListDismissed", "ListByStatus"} {
		run("BGPAnnouncements/"+method+"/OrderAnnouncedAtDesc", func(t *testing.T, b Backend) {
			r := b.Store().BGPAnnouncements()
			ids := []int{}
			for i, sec := range []int{20, 40, 10} {
				status := "orphan"
				if method == "ListDismissed" {
					status = "dismissed"
				}
				_, err := r.UpsertOrphan(ctx, fmt.Sprintf("192.0.%d.0/24", i), "", 1, status)
				check(t, err)
				a, err := r.FindByBusinessKey(ctx, fmt.Sprintf("192.0.%d.0/24", i), "", 1)
				check(t, err)
				ids = append(ids, a.ID)
				setTime(t, b, "bgp_announcements", "id", a.ID, "announced_at", sec)
			}
			var rows []store.BGPAnnouncement
			var err error
			switch method {
			case "ListActive":
				rows, err = r.ListActive(ctx)
			case "ListDismissed":
				rows, err = r.ListDismissed(ctx)
			case "ListByStatus":
				rows, err = r.ListByStatus(ctx, "orphan")
			}
			check(t, err)
			times := map[int]time.Time{}
			got := []int{}
			for _, a := range rows {
				times[a.ID] = a.AnnouncedAt
				got = append(got, a.ID)
			}
			verifyTimes(t, times, ids)
			// postgres/bgp_announcements.go: bgpAnnouncementRepo.list ORDER BY announced_at DESC; ListActive includes orphan.
			equal(t, got, []int{ids[1], ids[0], ids[2]})
		})
	}
	for _, method := range []string{"ListAttacks", "ListAttachmentsForAttack"} {
		run("BGPAnnouncements/"+method+"/OrderAttachedAt", func(t *testing.T, b Backend) {
			r := b.Store().BGPAnnouncements()
			ids := []int{}
			annID := 0
			for i, sec := range []int{20, 40, 10} {
				prefix := "192.0.2.0/24"
				attackID := i + 10
				if method == "ListAttachmentsForAttack" {
					prefix = fmt.Sprintf("192.0.%d.0/24", i)
					attackID = 10
				}
				a, err := r.Attach(ctx, store.BGPAttachParams{AttackID: attackID, Prefix: prefix, ConnectorID: 1})
				check(t, err)
				annID = a.AnnouncementID
				key := "attack_id"
				id := attackID
				if method == "ListAttachmentsForAttack" {
					key = "announcement_id"
					id = annID
				}
				ids = append(ids, id)
				setTime(t, b, "bgp_announcement_attacks", key, id, "attached_at", sec)
			}
			var rows []store.BGPAnnouncementAttack
			var err error
			if method == "ListAttacks" {
				rows, err = r.ListAttacks(ctx, annID)
			} else {
				rows, err = r.ListAttachmentsForAttack(ctx, 10)
			}
			check(t, err)
			times := map[int]time.Time{}
			got := []int{}
			for _, a := range rows {
				id := a.AttackID
				if method == "ListAttachmentsForAttack" {
					id = a.AnnouncementID
				}
				times[id] = a.AttachedAt
				got = append(got, id)
			}
			verifyTimes(t, times, ids)
			// postgres/bgp_announcements.go: ListAttacks DESC; ListAttachmentsForAttack ASC (not DESC).
			want := []int{ids[1], ids[0], ids[2]}
			if method == "ListAttachmentsForAttack" {
				want = []int{ids[2], ids[0], ids[1]}
			}
			equal(t, got, want)
		})
	}
	run("BGPAnnouncements/ListEvents/OrderCreatedAtAsc", func(t *testing.T, b Backend) {
		r := b.Store().BGPAnnouncements()
		a, err := r.Attach(ctx, store.BGPAttachParams{AttackID: 10, Prefix: "192.0.2.0/24", ConnectorID: 1})
		check(t, err)
		check(t, r.AppendEvent(ctx, a.AnnouncementID, "custom1", nil, ""))
		check(t, r.AppendEvent(ctx, a.AnnouncementID, "custom2", nil, ""))
		rows, err := r.ListEvents(ctx, a.AnnouncementID)
		check(t, err)
		// postgres/bgp_announcements.go: Attach creates one attack_attached event; AppendEvent inserts one row.
		equal(t, len(rows), 3)
		byType := map[string]int{}
		for _, e := range rows {
			byType[e.EventType] = e.ID
		}
		ids := []int{byType[store.BGPEventAttackAttached], byType["custom1"], byType["custom2"]}
		for i, sec := range []int{20, 40, 10} {
			setTime(t, b, "bgp_announcement_events", "id", ids[i], "created_at", sec)
		}
		rows, err = r.ListEvents(ctx, a.AnnouncementID)
		check(t, err)
		times := map[int]time.Time{}
		got := []int{}
		for _, e := range rows {
			times[e.ID] = e.CreatedAt
			got = append(got, e.ID)
		}
		verifyTimes(t, times, ids)
		// postgres/bgp_announcements.go: bgpAnnouncementRepo.ListEvents created_at ASC, id ASC; no ties in fixture.
		equal(t, got, []int{ids[2], ids[0], ids[1]})
	})
	run("BGPAnnouncements/UpsertOrphan/InitialTimestampsPresent", func(t *testing.T, b Backend) {
		r := b.Store().BGPAnnouncements()
		created, err := r.UpsertOrphan(ctx, "192.0.2.0/24", "", 1, "orphan")
		check(t, err)
		a, err := r.FindByBusinessKey(ctx, "192.0.2.0/24", "", 1)
		check(t, err)
		// postgres/bgp_announcements.go: UpsertOrphan INSERT; postgres.go migrations DEFAULT now(). Presence only, never default-time ordering.
		equal(t, created, true)
		equal(t, a.AnnouncedAt.IsZero(), false)
		equal(t, a.CreatedAt.IsZero(), false)
	})
	run("BGPAnnouncements/UpsertOrphan/WithdrawnPreservesRefcount", func(t *testing.T, b Backend) {
		r := b.Store().BGPAnnouncements()
		a, err := r.Attach(ctx, store.BGPAttachParams{AttackID: 10, Prefix: "192.0.2.0/24", ConnectorID: 1})
		check(t, err)
		fuzhuoSet(t, b, a.AnnouncementID, 1, "withdrawn")
		created, err := r.UpsertOrphan(ctx, "192.0.2.0/24", "", 1, "orphan")
		check(t, err)
		got, err := r.Get(ctx, a.AnnouncementID)
		check(t, err)
		// postgres/bgp_announcements.go: MarkWithdrawn leaves refcount; UpsertOrphan conflict SET changes status only.
		equal(t, created, true)
		equal(t, got.Status, "orphan")
		equal(t, got.Refcount, 1)
	})
}

func ruleContracts(run runner) {
	run("ManualOverrides/ListByAttack/OrderCreatedAtDesc", func(t *testing.T, b Backend) {
		r := b.Store().ManualOverrides()
		ids := []int{}
		for i, sec := range []int{20, 40, 10} {
			id, err := r.Create(ctx, &store.ActionManualOverride{AttackID: 10, ActionID: i})
			check(t, err)
			ids = append(ids, id)
			setTime(t, b, "action_manual_overrides", "id", id, "created_at", sec)
		}
		_, err := r.Create(ctx, &store.ActionManualOverride{AttackID: 11})
		check(t, err)
		rows, err := r.ListByAttack(ctx, 10)
		check(t, err)
		times := map[int]time.Time{}
		got := []int{}
		for _, a := range rows {
			times[a.ID] = a.CreatedAt
			got = append(got, a.ID)
		}
		verifyTimes(t, times, ids)
		// postgres/manual_overrides.go: manualOverrideRepo.ListByAttack WHERE attack_id, created_at DESC.
		equal(t, got, []int{ids[1], ids[0], ids[2]})
	})
	for _, method := range []string{"ListActive", "ListWithdrawing", "ListByAttack"} {
		run("XDropActiveRules/"+method+"/OrderCreatedAtDesc", func(t *testing.T, b Backend) {
			r := b.Store().XDropActiveRules()
			ids := []int{}
			for i, sec := range []int{20, 40, 10} {
				status := []string{"active", "delayed", "failed"}[i]
				if method == "ListWithdrawing" {
					status = "withdrawing"
				}
				id, err := r.Upsert(ctx, &store.XDropActiveRule{AttackID: 10, ActionID: i, Status: status})
				check(t, err)
				ids = append(ids, id)
				setTime(t, b, "xdrop_active_rules", "id", id, "created_at", sec)
			}
			var rows []store.XDropActiveRule
			var err error
			switch method {
			case "ListActive":
				rows, err = r.ListActive(ctx)
			case "ListWithdrawing":
				rows, err = r.ListWithdrawing(ctx)
			case "ListByAttack":
				rows, err = r.ListByAttack(ctx, 10)
			}
			check(t, err)
			times := map[int]time.Time{}
			got := []int{}
			for _, a := range rows {
				times[a.ID] = a.CreatedAt
				got = append(got, a.ID)
			}
			verifyTimes(t, times, ids)
			// postgres/xdrop_active_rules.go: ListByAttack/listByStatus created_at DESC; ListActive retains active/delayed/failed.
			equal(t, got, []int{ids[1], ids[0], ids[2]})
		})
	}
	run("XDropActiveRules/Upsert/InsertIgnoresWithdrawnAt", func(t *testing.T, b Backend) {
		r := b.Store().XDropActiveRules()
		_, err := r.Upsert(ctx, &store.XDropActiveRule{AttackID: 10, Status: "active", WithdrawnAt: ptr(stamp(50))})
		check(t, err)
		rows, err := r.ListByAttack(ctx, 10)
		check(t, err)
		// postgres/xdrop_active_rules.go: xdropActiveRuleRepo.Upsert INSERT omits withdrawn_at.
		equal(t, len(rows), 1)
		equal(t, rows[0].WithdrawnAt == nil, true)
	})
}

func connectorContracts(run runner) {
	for _, kind := range []string{"BGP", "XDrop"} {
		run(kind+"Connectors/Create/IDAfterDelete", func(t *testing.T, b Backend) {
			s := b.Store()
			create := func(name string) int {
				var id int
				var err error
				if kind == "BGP" {
					id, err = s.BGPConnectors().Create(ctx, &store.BGPConnector{Name: name, BGPASN: 64512, AddressFamily: "auto"})
				} else {
					id, err = s.XDropConnectors().Create(ctx, &store.XDropConnector{Name: name, APIURL: "http://example.invalid"})
				}
				check(t, err)
				return id
			}
			a := create("first")
			alive := create("alive")
			if kind == "BGP" {
				check(t, s.BGPConnectors().Delete(ctx, a))
			} else {
				check(t, s.XDropConnectors().Delete(ctx, a))
			}
			next := create("next")
			// postgres/bgp_connector.go: bgpConnectorRepo.Create; postgres/xdrop_connector.go: xdropConnectorRepo.Create.
			// Both use SERIAL RETURNING id (postgres.go migrations); no contiguous-number assertion.
			equal(t, next != a && next != alive, true)
			if kind == "BGP" {
				c, err := s.BGPConnectors().Get(ctx, alive)
				check(t, err)
				equal(t, c.Name, "alive")
			} else {
				c, err := s.XDropConnectors().Get(ctx, alive)
				check(t, err)
				equal(t, c.Name, "alive")
			}
		})
	}
	for _, name := range []string{"OrderConnectorIDAsc", "DuplicateRollback"} {
		run("XDropTargets/Set/"+name, func(t *testing.T, b Backend) {
			s := b.Store()
			aid := seedAction(t, s, seedResponse(t, s, "target"))
			ids := []int{}
			for i := 0; i < 3; i++ {
				id, err := s.XDropConnectors().Create(ctx, &store.XDropConnector{Name: fmt.Sprint(i), APIURL: "http://example.invalid"})
				check(t, err)
				ids = append(ids, id)
			}
			check(t, s.XDropTargets().Set(ctx, aid, []int{ids[1], ids[2], ids[0]}))
			if name == "DuplicateRollback" {
				err := s.XDropTargets().Set(ctx, aid, []int{ids[0], ids[0]})
				// postgres/xdrop_targets.go: xdropTargetRepo.Set transaction rolls back DELETE/INSERT on composite primary-key violation (postgres.go migrations).
				equal(t, err != nil, true)
			}
			rows, err := s.XDropTargets().List(ctx, aid)
			check(t, err)
			got := []int{}
			for _, c := range rows {
				got = append(got, c.ID)
			}
			// postgres/xdrop_targets.go: xdropTargetRepo.List ORDER BY c.id; failed Set preserves the previous set.
			equal(t, got, ids)
		})
	}
}

func preconditionContracts(run runner) {
	for _, name := range []string{"Create", "Delete", "DeleteByAction", "ReplaceAll"} {
		run("Preconditions/"+name+"/PersistsAndScopes", func(t *testing.T, b Backend) {
			s := b.Store()
			rid := seedResponse(t, s, "conditions")
			aid := seedAction(t, s, rid)
			other := seedAction(t, s, rid)
			p := store.ActionPrecondition{ActionID: aid, Attribute: "pps", Operator: "gt", Value: "10"}
			id, err := s.Preconditions().Create(ctx, &p)
			check(t, err)
			p.ActionID = other
			p.Value = "keep"
			_, err = s.Preconditions().Create(ctx, &p)
			check(t, err)
			rows, err := s.Preconditions().List(ctx, aid)
			check(t, err)
			// postgres/precondition.go: preconditionRepo.Create inserts supplied fields; List filters action_id and orders id.
			if name == "Create" {
				equal(t, len(rows), 1)
				equal(t, rows[0].ID, id)
				equal(t, rows[0].Value, "10")
				equal(t, rows[0].Attribute, "pps")
				equal(t, rows[0].Operator, "gt")
				return
			}
			// Validate seed before testing deletion/replacement; seed failures do not count for K3.
			if len(rows) != 1 {
				t.Fatalf("seed: Preconditions.Create persisted %d rows; want 1", len(rows))
			}
			switch name {
			case "Delete":
				check(t, s.Preconditions().Delete(ctx, id))
			case "DeleteByAction":
				check(t, s.Preconditions().DeleteByAction(ctx, aid))
			case "ReplaceAll":
				check(t, s.Preconditions().ReplaceAll(ctx, aid, []store.ActionPrecondition{{ActionID: other, Attribute: "bps", Operator: "gt", Value: "20"}, {ActionID: other, Attribute: "pps", Operator: "lt", Value: "30"}}))
			}
			rows, err = s.Preconditions().List(ctx, aid)
			check(t, err)
			// postgres/precondition.go: Delete by id, DeleteByAction by action_id; ReplaceAll deletes then inserts using argument actionID, not p.ActionID.
			if name == "ReplaceAll" {
				equal(t, len(rows), 2)
				equal(t, rows[0].ActionID, aid)
				equal(t, rows[1].ActionID, aid)
				equal(t, rows[0].Value, "20")
				equal(t, rows[1].Value, "30")
			} else {
				equal(t, len(rows), 0)
			}
			keep, err := s.Preconditions().List(ctx, other)
			check(t, err)
			equal(t, len(keep), 1)
			equal(t, keep[0].Value, "keep")
		})
	}
}
