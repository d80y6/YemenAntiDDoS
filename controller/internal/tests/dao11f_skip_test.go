package tests

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

// Name-based lookup keeps these gates compilable against the implementation baseline.
// Missing series read as zero; package counters require before/after deltas.
func dao11fMetric(t *testing.T, s store.Store) func(string, string) float64 {
	t.Helper()
	reg := prometheus.NewRegistry()
	if err := metrics.Register(reg, s, dao4Tracker(s, nil)); err != nil {
		t.Fatal(err)
	}
	return func(name, reason string) float64 {
		families, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range families {
			if f.GetName() != name {
				continue
			}
			for _, m := range f.Metric {
				if reason == "" && len(m.Label) == 0 {
					return m.GetCounter().GetValue()
				}
				for _, label := range m.Label {
					if label.GetName() == "skip_reason" && label.GetValue() == reason {
						return m.GetCounter().GetValue()
					}
				}
			}
		}
		return 0
	}
}

type dao11fStore struct {
	*MockStore
	lookupErr error
}

func (s dao11fStore) ShellConnectors() store.ShellConnectorRepo {
	return dao11fShell{s.MockStore.ShellConnectors()}
}
func (s dao11fStore) Preconditions() store.PreconditionRepo {
	return dao11fPreconditions{s.MockStore.Preconditions(), s.lookupErr}
}

type dao11fShell struct{ store.ShellConnectorRepo }

func (dao11fShell) Get(context.Context, int) (*store.ShellConnector, error) {
	return &store.ShellConnector{ID: 7, Name: "disabled-shell", Enabled: false}, nil
}

type dao11fPreconditions struct {
	store.PreconditionRepo
	err error
}

func (r dao11fPreconditions) List(ctx context.Context, id int) ([]store.ActionPrecondition, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.PreconditionRepo.List(ctx, id)
}

type dao11fFields struct {
	status, message, detail string
	connector               *int
	external, phase, kind   string
}

func dao11fSkip(t *testing.T, cell int) {
	t.Helper()
	cases := []struct {
		reason string
		fields dao11fFields
	}{
		{"global_no_target", dao11fFields{"skipped", "global attack (0.0.0.0/0) has no concrete IP target for xDrop", "", nil, "", "on_detected", "xdrop"}},
		{"global_no_target", dao11fFields{"skipped", "global attack (0.0.0.0/0) has no concrete target for BGP", "", nil, "", "on_detected", "bgp"}},
		{"deprecated_xdrop_api", dao11fFields{"skipped", "xdrop_api deprecated, use action_type=xdrop", "", nil, "", "on_detected", "xdrop_api"}},
		{"unknown_action_type", dao11fFields{"skipped", "unknown action type: unknown-fixture", "", nil, "", "on_detected", "unknown-fixture"}},
		{"no_connector", dao11fFields{"skipped", "no xdrop connectors available", "", nil, "", "on_detected", "xdrop"}},
		{"connector_disabled", dao11fFields{"skipped", "bgp connector disabled", "", nil, "", "on_expired", "bgp"}},
		{"unknown_trigger_phase", dao11fFields{"skipped", "unknown trigger_phase: confirmed", "", nil, "", "confirmed", "bgp"}},
		{"manual_override", dao11fFields{"skipped", "force-removed by operator", "", intPtr(7), "192.0.2.10/32|RTBH", "on_expired", "bgp"}},
		{"stale_generation", dao11fFields{"skipped", "", "superseded by newer announcement generation", intPtr(7), "192.0.2.10/32|RTBH", "on_expired", "bgp"}},
		{"connector_disabled", dao11fFields{"skipped", "shell connector is disabled", "", nil, "", "on_detected", "shell"}},
	}
	want := cases[cell-1]
	synctest.Test(t, func(t *testing.T) {
		base, _, ev := dao4Fixture(want.fields.kind, "once", "on_detected")
		var s store.Store = base
		var announcementID int
		if cell == 9 {
			fixture, _, event, _, id := dao5BGPFixture(t, 1)
			fixture.bgpAnnouncements.announcements[0].Gen = 7
			base, s, ev, announcementID = fixture.MockStore, fixture, event, id
		}
		act := &base.responses.actions[0]
		switch cell {
		case 1, 2:
			ev.Attack.DstIP = "0.0.0.0/0"
		case 6, 7, 8:
			act.BGPConnectorID, act.BGPRouteMap = intPtr(7), "RTBH"
			base.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "fixture-bgp", Enabled: cell != 6}}
			if cell == 7 {
				act.TriggerPhase, act.ExecutionPolicy = "", "once_on_enter"
			} else {
				act.TriggerPhase, ev.Type = "on_expired", "expired"
			}
			if cell == 8 {
				_, err := base.ManualOverrides().Create(context.Background(), &store.ActionManualOverride{AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: "192.0.2.10/32|RTBH"})
				if err != nil {
					t.Fatal(err)
				}
			}
		case 10:
			act.ShellConnectorID = intPtr(7)
			s = dao11fStore{MockStore: base}
		}
		metric := dao11fMetric(t, s)
		before := metric("xsight_action_skip_total", want.reason)
		e := action.NewEngine(s, "auto")
		if cell == 9 {
			e.CancelAnnouncementDelay(announcementID, 8, "new generation already observed")
		}
		if cell == 6 {
			// Exercise the public legacy recovery entry and its separate Create caller.
			base.attacks.attacks = []store.Attack{*ev.Attack}
			base.scheduledActions.appendRecords(store.ScheduledAction{ID: 1, AttackID: 20, ActionID: 10, ConnectorID: 7, ActionType: "bgp_withdraw", Status: "pending", ScheduledFor: time.Now().Add(-time.Minute)})
			if err := e.RecoverScheduledActions(context.Background()); err != nil {
				t.Fatal(err)
			}
		} else {
			e.HandleEvent(ev)
		}
		synctest.Wait()
		logs := base.actionExecLog.snapshotLogs()
		if len(logs) != 1 {
			t.Fatalf("log rows=%d; want 1: %+v", len(logs), logs)
		}
		row := logs[0]
		fields := dao11fFields{row.Status, row.ErrorMessage, row.Detail, row.ConnectorID, row.ExternalRuleID, row.TriggerPhase, row.ActionType}
		if !reflect.DeepEqual(fields, want.fields) {
			t.Errorf("preserved fields=%+v; want %+v", fields, want.fields)
		} else {
			t.Log("preserved fields and skipped row count=1: PASS")
		}
		if row.SkipReason != want.reason {
			t.Errorf("skip_reason=%q; want %q", row.SkipReason, want.reason)
		} else {
			t.Logf("skip_reason=%q: PASS", row.SkipReason)
		}
		if delta := metric("xsight_action_skip_total", want.reason) - before; delta != 1 {
			t.Errorf("skip counter delta=%v; want 1", delta)
		} else {
			t.Log("skip counter delta=1: PASS")
		}
	})
}

func TestDao11f_G1_01_GlobalXDrop(t *testing.T)         { dao11fSkip(t, 1) }
func TestDao11f_G1_02_GlobalBGP(t *testing.T)           { dao11fSkip(t, 2) }
func TestDao11f_G1_03_Deprecated(t *testing.T)          { dao11fSkip(t, 3) }
func TestDao11f_G1_04_UnknownAction(t *testing.T)       { dao11fSkip(t, 4) }
func TestDao11f_G1_05_NoConnector(t *testing.T)         { dao11fSkip(t, 5) }
func TestDao11f_G1_06_DisabledBGPRecovery(t *testing.T) { dao11fSkip(t, 6) }
func TestDao11f_G1_07_UnknownPhase(t *testing.T)        { dao11fSkip(t, 7) }
func TestDao11f_G1_08_ManualOverride(t *testing.T)      { dao11fSkip(t, 8) }
func TestDao11f_G1_09_StaleGeneration(t *testing.T)     { dao11fSkip(t, 9) }
func TestDao11f_G1_10_DisabledShell(t *testing.T)       { dao11fSkip(t, 10) }

func dao11fLookup(t *testing.T, fail, blocked bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		base, _, ev := dao4Fixture("webhook", "once", "on_detected")
		s := dao11fStore{MockStore: base}
		if fail {
			s.lookupErr = errors.New("dao11f lookup unavailable")
		}
		if blocked {
			base.responses.actions[0].Preconditions = []byte(`{"severity":"critical"}`)
		}
		capture := dao5CaptureLog(t)
		metric := dao11fMetric(t, s)
		before := metric("xsight_action_precondition_lookup_errors_total", "")
		action.NewEngine(s, "auto").HandleEvent(ev)
		synctest.Wait()
		rows := base.actionExecLog.snapshotLogs()
		if len(rows) != 1 {
			t.Fatalf("decision rows=%+v; want one", rows)
		}
		wantStatus, wantReason, wantRequests := "success", "", 1
		if blocked {
			wantStatus, wantReason, wantRequests = "skipped", "precondition_not_matched", 0
		}
		if rows[0].Status != wantStatus || rows[0].SkipReason != wantReason || d.count() != wantRequests {
			t.Errorf("legacy decision: status=%q reason=%q requests=%d; want %q/%q/%d", rows[0].Status, rows[0].SkipReason, d.count(), wantStatus, wantReason, wantRequests)
		} else {
			t.Logf("legacy decision: status=%s reason=%q requests=%d: PASS", wantStatus, wantReason, wantRequests)
		}
		wantCount := 0
		if fail {
			wantCount = 1
		}
		text := capture.text()
		needle := "ERROR action: preconditions lookup"
		if count := strings.Count(text, needle); count != wantCount {
			t.Errorf("lookup ERROR lines=%d; want %d; log=%q", count, wantCount, text)
		} else if fail && !strings.Contains(text, "action=10 attack=20: dao11f lookup unavailable; falling back to legacy preconditions") {
			t.Errorf("lookup ERROR missing identity or fallback detail: %q", text)
		} else {
			t.Logf("lookup ERROR lines=%d: PASS", count)
		}
		if delta := metric("xsight_action_precondition_lookup_errors_total", "") - before; delta != float64(wantCount) {
			t.Errorf("lookup counter delta=%v; want %d", delta, wantCount)
		} else {
			t.Logf("lookup counter delta=%v: PASS", delta)
		}
	})
}

func TestDao11f_G3_A_LookupErrorEmptyLegacy(t *testing.T) { dao11fLookup(t, true, false) }
func TestDao11f_G3_B_LookupErrorUnmetLegacy(t *testing.T) { dao11fLookup(t, true, true) }
func TestDao11f_G3_C_LookupSuccess(t *testing.T)          { dao11fLookup(t, false, false) }
