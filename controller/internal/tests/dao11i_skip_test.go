package tests

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
)

type dao11iStore struct {
	*MockStore
	shell      *dao11iShell
	targets    *dao11iTargets
	connectors *dao11iConnectors
	logs       *dao11iLogs
}

func (s *dao11iStore) ShellConnectors() store.ShellConnectorRepo { return s.shell }
func (s *dao11iStore) XDropTargets() store.XDropTargetRepo       { return s.targets }
func (s *dao11iStore) XDropConnectors() store.XDropConnectorRepo { return s.connectors }
func (s *dao11iStore) ActionExecLog() store.ActionExecLogRepo    { return s.logs }

type dao11iShell struct {
	store.ShellConnectorRepo
	connector store.ShellConnector
	err       error
	calls     int
}

func (r *dao11iShell) Get(context.Context, int) (*store.ShellConnector, error) {
	r.calls++
	return &r.connector, r.err
}

type dao11iTargets struct {
	store.XDropTargetRepo
	err   error
	calls int
}

func (r *dao11iTargets) List(ctx context.Context, id int) ([]store.XDropConnector, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return r.XDropTargetRepo.List(ctx, id)
}

type dao11iConnectors struct {
	store.XDropConnectorRepo
	err   error
	calls int
}

func (r *dao11iConnectors) ListEnabled(ctx context.Context) ([]store.XDropConnector, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	return r.XDropConnectorRepo.ListEnabled(ctx)
}

type dao11iLogs struct {
	store.ActionExecLogRepo
	failNext bool
	consumed int
}

func (r *dao11iLogs) AllTargetsDone(ctx context.Context, attack, act int, phase string) (bool, error) {
	if r.failNext {
		r.failNext = false
		r.consumed++
		return false, errors.New("dao11i dedup lookup unavailable")
	}
	return r.ActionExecLogRepo.AllTargetsDone(ctx, attack, act, phase)
}

type dao11iCase struct {
	name, kind, reason, message, log string
}

var dao11iCases = []dao11iCase{
	{"G1-1", "bgp", "no_connector", "bgp action has no connector_id", "has no connector_id, skipping"},
	{"G1-2", "shell", "no_connector", "shell action has no shell_connector_id", "skipped: no shell_connector_id"},
	{"G1-3", "shell", "connector_lookup_failed", "get shell connector 7: dao11i shell lookup unavailable", "shell failed for attack 20: get shell connector 7: dao11i shell lookup unavailable"},
	{"G1-4", "xdrop", "incomplete_config", "xdrop action type is empty", "skipped: xdrop action type is empty"},
	{"G1-5", "xdrop", "connector_lookup_failed", "list xdrop targets for action 10: dao11i targets lookup unavailable", "xdrop failed for attack 20: list xdrop targets for action 10: dao11i targets lookup unavailable"},
	{"G1-6", "xdrop", "connector_lookup_failed", "list enabled xdrop connectors: dao11i enabled lookup unavailable", "xdrop failed for attack 20: list enabled xdrop connectors: dao11i enabled lookup unavailable"},
	{"G2", "xdrop", "no_connector", "no xdrop connectors available", "skipped: no xdrop connectors available"},
}

// The returned engine must be built from the wrapped store, after fault setup.
func dao11iFixture(t *testing.T, cell int) (*dao11iStore, tracker.AttackEvent, []string, *dao4Transport) {
	t.Helper()
	base, _, ev := dao4Fixture(dao11iCases[cell-1].kind, "once", "on_detected")
	bgpScript, bgpMark := dao4Vtysh(t)
	shellScript, shellMark := dao4Vtysh(t)
	base.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "dao11i-bgp", Enabled: true, VtyshPath: bgpScript, BGPASN: 64512}}
	s := &dao11iStore{
		MockStore:  base,
		shell:      &dao11iShell{ShellConnectorRepo: base.ShellConnectors(), connector: store.ShellConnector{ID: 7, Name: "dao11i-shell", Enabled: true, Command: shellScript}},
		targets:    &dao11iTargets{XDropTargetRepo: base.XDropTargets()},
		connectors: &dao11iConnectors{XDropConnectorRepo: base.XDropConnectors()},
		logs:       &dao11iLogs{ActionExecLogRepo: base.ActionExecLog()},
	}
	switch cell {
	case 3:
		base.responses.actions[0].ShellConnectorID = intPtr(7)
		s.shell.err = errors.New("dao11i shell lookup unavailable")
	case 4:
		base.responses.actions[0].XDropAction = ""
	case 5:
		s.targets.err = errors.New("dao11i targets lookup unavailable")
	case 6:
		s.connectors.err = errors.New("dao11i enabled lookup unavailable")
	}
	return s, ev, []string{bgpMark, shellMark}, dao4HTTP(t)
}

func dao11iAssert(t *testing.T, name string, ok bool, detail string) {
	t.Helper()
	if !ok {
		t.Errorf("ASSERT %s FAIL: %s", name, detail)
		return
	}
	t.Logf("ASSERT %s PASS: %s", name, detail)
}

func dao11iMissing(t *testing.T, name string) {
	t.Helper()
	t.Errorf("ASSERT %s NOT_RUN: no execution log row", name)
}

// Sum every reason series; a missing requested series contributes zero.
func dao11iMetric(t *testing.T) func(string) (float64, float64) {
	t.Helper()
	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.ActionSkip)
	return func(reason string) (float64, float64) {
		families, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		var selected, total float64
		for _, family := range families {
			if family.GetName() != "xsight_action_skip_total" {
				continue
			}
			for _, metric := range family.Metric {
				total += metric.GetCounter().GetValue()
				for _, label := range metric.Label {
					if label.GetName() == "skip_reason" && label.GetValue() == reason {
						selected += metric.GetCounter().GetValue()
					}
				}
			}
		}
		return selected, total
	}
}

func dao11iRows(s *dao11iStore) []store.ActionExecutionLog {
	var rows []store.ActionExecutionLog
	for _, row := range s.actionExecLog.snapshotLogs() {
		if row.AttackID == 20 && row.ActionID == 10 && row.TriggerPhase == "on_detected" {
			rows = append(rows, row)
		}
	}
	return rows
}

func dao11iFields(row store.ActionExecutionLog, want dao11iCase) bool {
	nonzeroTime := !row.ExecutedAt.IsZero()
	row.ID, row.ExecutedAt = 0, time.Time{}
	expected := store.ActionExecutionLog{
		AttackID: 20, ActionID: 10, ResponseName: "dao4", ActionType: want.kind,
		TriggerPhase: "on_detected", Status: "skipped", ErrorMessage: want.message,
		SkipReason: want.reason, ConnectorID: nil, ConnectorName: "", ExternalRuleID: "", Detail: "",
	}
	return nonzeroTime && reflect.DeepEqual(row, expected)
}

func dao11iSkip(t *testing.T, cell int) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		want := dao11iCases[cell-1]
		s, ev, marks, http := dao11iFixture(t, cell)
		capture, metric := dao5CaptureLog(t), dao11iMetric(t)
		before, beforeTotal := metric(want.reason)
		action.NewEngine(s, "auto").HandleEvent(ev)
		synctest.Wait()
		rows := dao11iRows(s)
		dao11iAssert(t, want.name+".Rows", len(rows) == 1, fmt.Sprintf("rows=%d; want 1", len(rows)))
		checks := []string{"Fields"}
		if cell != 7 {
			checks = []string{"Status", "Reason", "Fields"}
		}
		for _, check := range checks {
			name := want.name + "." + check
			if len(rows) == 0 {
				dao11iMissing(t, name)
				continue
			}
			row := rows[0]
			switch check {
			case "Status":
				dao11iAssert(t, name, row.Status == "skipped", fmt.Sprintf("status=%q; want skipped", row.Status))
			case "Reason":
				dao11iAssert(t, name, row.SkipReason == want.reason, fmt.Sprintf("reason=%q; want %q", row.SkipReason, want.reason))
			case "Fields":
				dao11iAssert(t, name, dao11iFields(row, want), fmt.Sprintf("row=%+v; want attack=20 action=10 response=dao4 phase=on_detected status=skipped kind=%s reason=%s message=%q, empty connector/artifact fields, nonzero time", row, want.kind, want.reason, want.message))
			}
		}
		after, afterTotal := metric(want.reason)
		dao11iAssert(t, want.name+".Metric", after-before == 1 && afterTotal-beforeTotal == 1, fmt.Sprintf("reason delta=%v total delta=%v; want 1/1", after-before, afterTotal-beforeTotal))
		if cell != 7 {
			bgp, shell := dao4Read(t, marks[0]), dao4Read(t, marks[1])
			dao11iAssert(t, want.name+".NoSideEffect", bgp == "" && shell == "" && http.count() == 0, fmt.Sprintf("vtysh=%q shell=%q HTTP=%d; want empty/empty/0", bgp, shell, http.count()))
		}
		text := capture.text()
		ok := strings.Contains(text, want.log)
		if cell == 2 || cell == 4 || cell == 7 {
			ok = ok && !strings.Contains(text, want.kind+" failed")
		}
		dao11iAssert(t, want.name+".Log", ok, fmt.Sprintf("log=%q; required=%q", text, want.log))
	})
}

func TestDao11i_G1_01_BGPNoConnector(t *testing.T)   { dao11iSkip(t, 1) }
func TestDao11i_G1_02_ShellNoConnector(t *testing.T) { dao11iSkip(t, 2) }
func TestDao11i_G1_03_ShellLookup(t *testing.T)      { dao11iSkip(t, 3) }
func TestDao11i_G1_04_XDropEmptyAction(t *testing.T) { dao11iSkip(t, 4) }
func TestDao11i_G1_05_XDropTargets(t *testing.T)     { dao11iSkip(t, 5) }
func TestDao11i_G1_06_XDropEnabled(t *testing.T)     { dao11iSkip(t, 6) }
func TestDao11i_G2_NoXDropConnector(t *testing.T)    { dao11iSkip(t, 7) }

func dao11iRepeat(t *testing.T, cell int, name, mode, second, needle string) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		s, ev, _, _ := dao11iFixture(t, cell)
		s.responses.actions[0].RunMode = mode
		capture := dao5CaptureLog(t)
		e := action.NewEngine(s, "auto")
		e.HandleEvent(ev)
		synctest.Wait()
		first := len(dao11iRows(s))
		ev.Type = second
		e.HandleEvent(ev)
		synctest.Wait()
		count := strings.Count(capture.text(), needle)
		dao11iAssert(t, "G3a."+name+".Decision", count == 2, fmt.Sprintf("entry lines=%d; want 2; log=%q", count, capture.text()))
		rows := dao11iRows(s)
		dao11iAssert(t, "G3c."+name+".Rows", first == 1 && len(rows)-first == 1, fmt.Sprintf("first=%d second=%d total=%d; want 1/1/2", first, len(rows)-first, len(rows)))
		if len(rows) == 0 {
			dao11iMissing(t, "G3c."+name+".Fields")
		} else {
			ok := true
			for _, row := range rows {
				ok = ok && dao11iFields(row, dao11iCases[cell-1])
			}
			dao11iAssert(t, "G3c."+name+".Fields", ok, fmt.Sprintf("rows=%+v; want skipped fields", rows))
		}
	})
}

func TestDao11i_G3_OnceBGP(t *testing.T) {
	dao11iRepeat(t, 1, "BGP", "once", "type_upgrade", "has no connector_id, skipping")
}
func TestDao11i_G3_RetryShell(t *testing.T) {
	dao11iRepeat(t, 3, "Shell", "retry_until_success", "updated", "shell failed")
}

func dao11iOrder(t *testing.T, cell int, name string, connector *int) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		s, ev, _, _ := dao11iFixture(t, cell)
		_, err := s.MockStore.ActionExecLog().Create(context.Background(), &store.ActionExecutionLog{
			AttackID: 20, ActionID: 10, ActionType: dao11iCases[cell-1].kind, TriggerPhase: "on_detected",
			Status: "success", ConnectorID: connector, ExecutedAt: time.Now().Add(-time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		s.logs.failNext = true
		action.NewEngine(s, "auto").HandleEvent(ev)
		synctest.Wait()
		calls := s.shell.calls
		if cell == 5 {
			calls = s.targets.calls
		}
		dao11iAssert(t, "G3b."+name+".Arrival", s.logs.consumed == 1 && !s.logs.failNext && calls == 1, fmt.Sprintf("dedup errors consumed=%d connector queries=%d; want 1/1", s.logs.consumed, calls))
		done, err := s.ActionExecLog().AllTargetsDone(context.Background(), 20, 10, "on_detected")
		dao11iAssert(t, "G3b."+name+".Done", err == nil && done, fmt.Sprintf("done=%v err=%v; want true/nil", done, err))
	})
}

func TestDao11i_G3b_Shell(t *testing.T) { dao11iOrder(t, 3, "Shell", nil) }
func TestDao11i_G3b_XDrop(t *testing.T) { dao11iOrder(t, 5, "XDrop", intPtr(7)) }
