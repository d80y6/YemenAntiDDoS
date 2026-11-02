package tests

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	dto "github.com/prometheus/client_model/go"
)

func dao12fCheck(t *testing.T, name string, ok bool, format string, args ...any) {
	t.Helper()
	detail := fmt.Sprintf(format, args...)
	if !ok {
		t.Errorf("ASSERT %s FAIL: %s", name, detail)
		return
	}
	t.Logf("ASSERT %s PASS: %s", name, detail)
}

// Select new rows by attack and action, never by the phase being asserted.
func dao12fRows(ms *MockStore, before int) []store.ActionExecutionLog {
	var rows []store.ActionExecutionLog
	for _, row := range ms.actionExecLog.snapshotLogs()[before:] {
		if row.AttackID == 20 && row.ActionID == 11 {
			rows = append(rows, row)
		}
	}
	return rows
}

func dao12fFields(t *testing.T, name string, rows []store.ActionExecutionLog, phase, reason, message string) {
	t.Helper()
	present := len(rows) == 1
	dao12fCheck(t, name+".Rows", present, "new rows=%d; want 1", len(rows))
	var row store.ActionExecutionLog
	if present {
		row = rows[0]
	}
	for _, field := range []struct {
		name string
		ok   bool
		got  any
		want any
	}{
		{"AttackID", row.AttackID == 20, row.AttackID, 20},
		{"ActionID", row.ActionID == 11, row.ActionID, 11},
		{"ResponseName", row.ResponseName == "dao4", row.ResponseName, "dao4"},
		{"ActionType", row.ActionType == "xdrop", row.ActionType, "xdrop"},
		{"TriggerPhase", row.TriggerPhase == phase, row.TriggerPhase, phase},
		{"Status", row.Status == "skipped", row.Status, "skipped"},
		{"SkipReason", row.SkipReason == reason, row.SkipReason, reason},
		{"ConnectorID", row.ConnectorID == nil, row.ConnectorID, nil},
		{"ExternalRuleID", row.ExternalRuleID == "", row.ExternalRuleID, ""},
		{"Message", row.ErrorMessage == message, row.ErrorMessage, message},
		{"ExecutedAt", !row.ExecutedAt.IsZero(), row.ExecutedAt, "nonzero"},
	} {
		dao12fCheck(t, name+"."+field.name, present && field.ok, "present=%t got=%v; want %v", present, field.got, field.want)
	}
}

// dao4Emit rewrites executed_at for ordering tests; field gates must read
// the rows exactly as executeAction wrote them.
func dao12fEmit(e *action.Engine, ev tracker.AttackEvent) {
	ev.Type = "expired"
	e.HandleEvent(ev)
	synctest.Wait()
}

// dao12fPartialOverrides returns the matching overrides together with an
// error, as manualOverrideRepo.ListByAttack can after a mid-scan row error.
type dao12fPartialOverrides struct {
	store.ActionManualOverrideRepo
}

func (r dao12fPartialOverrides) ListByAttack(ctx context.Context, id int) ([]store.ActionManualOverride, error) {
	rows, err := r.ActionManualOverrideRepo.ListByAttack(ctx, id)
	if err != nil {
		return rows, err
	}
	return rows, errors.New("dao12f partial override read")
}

type dao12fPartialStore struct {
	store.Store
}

func (s dao12fPartialStore) ManualOverrides() store.ActionManualOverrideRepo {
	return dao12fPartialOverrides{s.Store.ManualOverrides()}
}

func dao12fExecutions(t *testing.T) float64 {
	t.Helper()
	var metric dto.Metric
	if err := metrics.ActionExecutions.WithLabelValues("xdrop", "skipped").Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetCounter().GetValue()
}

func dao12fOverride(t *testing.T, ms *MockStore) {
	t.Helper()
	_, err := ms.ManualOverrides().Create(context.Background(), &store.ActionManualOverride{
		AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: "rule-1",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func dao12fSecondConnector(ms *MockStore, reverse bool) {
	first := ms.xdropConnectors.connectors[0]
	second := first
	second.ID, second.Name = 8, "dao12f-empty"
	ms.xdropConnectors.connectors = []store.XDropConnector{first, second}
	if reverse {
		ms.xdropConnectors.connectors = []store.XDropConnector{second, first}
	}
}

func TestDao12f_G1_Exit1(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, logs := dao4HTTP(t), dao5CaptureLog(t)
		ms, rules, _, ev := dao4XDrop()
		e := action.NewEngine(metrics.InstrumentStore(dao4RuleStore{ms, rules}), "auto")
		dao4SeedRule(t, ms, "withdrawn", "rule-1", true)
		before := len(ms.actionExecLog.snapshotLogs())
		readSkip := dao11iMetric(t)
		skipBefore, _ := readSkip("no_rules_to_unblock")
		execBefore := dao12fExecutions(t)
		dao12fEmit(e, ev)
		dao12fFields(t, "G1.Exit1", dao12fRows(ms, before), "on_expired", "no_rules_to_unblock", "no active, delayed or failed rules to unblock")
		skipAfter, _ := readSkip("no_rules_to_unblock")
		dao12fCheck(t, "G1.Exit1.SkipMetric", skipAfter-skipBefore == 1, "delta=%g; want 1", skipAfter-skipBefore)
		execDelta := dao12fExecutions(t) - execBefore
		dao12fCheck(t, "G1.Exit1.ExecutionMetric", execDelta == 1, "delta=%g; want 1", execDelta)
		dao12fCheck(t, "G1.Exit1.MarkWithdrawing", rules.markCount() == 0, "calls=%d; want 0", rules.markCount())
		dao12fCheck(t, "G1.Exit1.HTTP", d.count() == 0, "requests=%d; want 0", d.count())
		text := logs.text()
		n := strings.Count(text, "xdrop action 11 skipped")
		dao12fCheck(t, "G1.Exit1.SummaryLog", n == 1, "count=%d; want 1; log=%q", n, text)
		dao12fCheck(t, "G1.Exit1.NoFailedLog", !strings.Contains(text, "xdrop failed"), "log=%q", text)
	})
}

func TestDao12f_G1_Exit1_Legacy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		ms.responses.actions[1].TriggerPhase = ""
		ms.responses.actions[1].ExecutionPolicy = "once_on_exit"
		dao4SeedRule(t, ms, "withdrawn", "rule-1", true)
		before := len(ms.actionExecLog.snapshotLogs())
		dao12fEmit(e, ev)
		dao12fFields(t, "G1.Exit1.Legacy", dao12fRows(ms, before), "expired", "no_rules_to_unblock", "no active, delayed or failed rules to unblock")
		dao12fCheck(t, "G1.Exit1.Legacy.HTTP", d.count() == 0, "requests=%d; want 0", d.count())
	})
}

func TestDao12f_G1_Exit2(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, logs := dao4HTTP(t), dao5CaptureLog(t)
		ms, _, e, ev := dao4XDrop()
		dao4SeedRule(t, ms, "active", "rule-1", true)
		dao12fOverride(t, ms)
		before := len(ms.actionExecLog.snapshotLogs())
		dao12fEmit(e, ev)
		dao12fFields(t, "G1.Exit2", dao12fRows(ms, before), "on_expired", "manual_override", "all remaining rules were force-removed by operator")
		text := logs.text()
		dao12fCheck(t, "G1.Exit2.RuleLog", strings.Contains(text, "skipping rule rule-1 (manual override"), "log=%q", text)
		dao12fCheck(t, "G1.Exit2.HTTP", d.count() == 0, "requests=%d; want 0", d.count())
	})
}

func TestDao12f_G1_Exit2_PartialError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, logs := dao4HTTP(t), dao5CaptureLog(t)
		ms, rules, _, ev := dao4XDrop()
		dao4SeedRule(t, ms, "active", "rule-1", true)
		dao12fOverride(t, ms)
		e := action.NewEngine(dao12fPartialStore{dao4RuleStore{ms, rules}}, "auto")
		before := len(ms.actionExecLog.snapshotLogs())
		dao12fEmit(e, ev)
		dao12fFields(t, "G1.Exit2.PartialError", dao12fRows(ms, before), "on_expired", "manual_override", "all remaining rules were force-removed by operator")
		text := logs.text()
		dao12fCheck(t, "G1.Exit2.PartialError.RuleLog", strings.Contains(text, "skipping rule rule-1 (manual override"), "log=%q", text)
		dao12fCheck(t, "G1.Exit2.PartialError.HTTP", d.count() == 0, "requests=%d; want 0", d.count())
	})
}

func TestDao12f_G1_MixedNoRow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		dao12fSecondConnector(ms, false)
		dao4SeedRule(t, ms, "active", "rule-1", true)
		before := len(ms.actionExecLog.snapshotLogs())
		dao4Emit(t, ms, e, ev, "expired")
		rows := ms.actionExecLog.snapshotLogs()[before:]
		var perRule, summary, noRules int
		for _, row := range rows {
			if row.AttackID == 20 && row.TriggerPhase == "on_expired" && row.Status == "success" && row.ConnectorID != nil && *row.ConnectorID == 7 {
				if row.ActionID == 10 && row.ExternalRuleID == "rule-1" {
					perRule++
				}
				if row.ActionID == 11 && row.ExternalRuleID == "" {
					summary++
				}
			}
			if row.SkipReason == "no_rules_to_unblock" {
				noRules++
			}
		}
		dao12fCheck(t, "G1.MixedNoRow.HTTP", d.count() == 1, "requests=%d; want 1", d.count())
		dao12fCheck(t, "G1.MixedNoRow.PerRuleSuccess", perRule == 1, "rows=%d; want 1", perRule)
		dao12fCheck(t, "G1.MixedNoRow.ConnectorSuccess", summary == 1, "rows=%d; want 1", summary)
		dao12fCheck(t, "G1.MixedNoRow.NoSkip", noRules == 0, "no_rules_to_unblock rows=%d; want 0", noRules)
		dao12fCheck(t, "G1.MixedNoRow.TotalRows", len(rows) == 2, "new rows=%d; want 2", len(rows))
	})
}

func TestDao12f_G1_Dedup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		dao4SeedRule(t, ms, "withdrawn", "rule-1", true)
		ctx := context.Background()
		before, err := ms.ActionExecLog().AllTargetsDone(ctx, 20, 11, "on_expired")
		if err != nil {
			t.Fatal(err)
		}
		dao4Emit(t, ms, e, ev, "expired")
		after, err := ms.ActionExecLog().AllTargetsDone(ctx, 20, 11, "on_expired")
		if err != nil {
			t.Fatal(err)
		}
		dao12fCheck(t, "G1.Dedup.Once", ms.responses.actions[1].RunMode == "once", "run mode=%q; want once", ms.responses.actions[1].RunMode)
		dao12fCheck(t, "G1.Dedup.AllTargetsDone", !before && after == before, "before=%t after=%t; want false/false for action 11/on_expired", before, after)
	})
}

func TestDao12f_G1_ListFailStillFailed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, rules, e, ev := dao4XDrop()
		rules.listErr = errors.New("dao12f list failure")
		before := len(ms.actionExecLog.snapshotLogs())
		dao4Emit(t, ms, e, ev, "expired")
		rows := dao12fRows(ms, before)
		dao12fCheck(t, "G1.ListFailStillFailed.Rows", len(rows) == 1, "new rows=%d; want 1", len(rows))
		var failed, skipped int
		for _, row := range rows {
			if row.Status == "failed" && row.ErrorMessage == "list xdrop_active_rules: dao12f list failure" {
				failed++
			}
			if row.Status == "skipped" {
				skipped++
			}
		}
		dao12fCheck(t, "G1.ListFailStillFailed.Failed", failed == 1, "original failed rows=%d; want 1", failed)
		dao12fCheck(t, "G1.ListFailStillFailed.NoSkip", skipped == 0, "skipped rows=%d; want 0", skipped)
		dao12fCheck(t, "G1.ListFailStillFailed.HTTP", d.count() == 0, "requests=%d; want 0", d.count())
	})
}

func TestDao12f_G1_AllSilentMixed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reverse bool
	}{{"Exit2ThenExit1", false}, {"Exit1ThenExit2", true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := dao4HTTP(t)
				ms, _, e, ev := dao4XDrop()
				dao12fSecondConnector(ms, tc.reverse)
				dao4SeedRule(t, ms, "active", "rule-1", true)
				dao12fOverride(t, ms)
				before := len(ms.actionExecLog.snapshotLogs())
				dao12fEmit(e, ev)
				name := "G1.AllSilentMixed." + tc.name
				dao12fFields(t, name, dao12fRows(ms, before), "on_expired", "manual_override", "all remaining rules were force-removed by operator")
				dao12fCheck(t, name+".HTTP", d.count() == 0, "requests=%d; want 0", d.count())
			})
		})
	}
}
