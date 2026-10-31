package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
)

// Immutable, pre-seeded failure switches. No listener and no mutable row data.
type dao5APIStore struct {
	store.Store
	overrideFail, withdrawnFail, auditFail bool
}
type dao5APIResponses struct{ store.ResponseRepo }

func (dao5APIResponses) GetAction(context.Context, int) (*store.ResponseAction, error) {
	return &store.ResponseAction{ID: 10, ActionType: "xdrop"}, nil
}

type dao5APIConnectors struct{ store.XDropConnectorRepo }

func (dao5APIConnectors) ListEnabled(context.Context) ([]store.XDropConnector, error) {
	return []store.XDropConnector{{ID: 7, APIURL: "http://dao5.invalid", Enabled: true}}, nil
}

type dao5APIOverrides struct {
	store.ActionManualOverrideRepo
	fail bool
}

func (r dao5APIOverrides) Create(ctx context.Context, _ *store.ActionManualOverride) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if r.fail {
		return 0, errors.New("dao5 override")
	}
	return 1, nil
}

type dao5APIRules struct {
	store.XDropActiveRuleRepo
	fail bool
}

func (r dao5APIRules) MarkWithdrawn(ctx context.Context, _, _, _ int, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.fail {
		return errors.New("dao5 MarkWithdrawn")
	}
	return nil
}
func (dao5APIRules) CountByStatus(context.Context) (map[string]int, error) { return nil, nil }

type dao5APILogs struct {
	store.ActionExecLogRepo
	fail bool
}

func (r dao5APILogs) Create(ctx context.Context, _ *store.ActionExecutionLog) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if r.fail {
		return 0, errors.New("dao5 audit")
	}
	return 1, nil
}

type dao5APISchedules struct{ store.ScheduledActionRepo }

func (dao5APISchedules) CancelByBusinessKey(context.Context, string, int, int, int, string, string) error {
	return nil
}
func (dao5APISchedules) CountByStatus(context.Context) (map[string]int, error) { return nil, nil }

type dao5APIAnnouncements struct{ store.BGPAnnouncementRepo }

func (dao5APIAnnouncements) CountByStatus(context.Context) (map[string]int, error) { return nil, nil }
func (s dao5APIStore) Responses() store.ResponseRepo                               { return dao5APIResponses{} }
func (s dao5APIStore) XDropConnectors() store.XDropConnectorRepo                   { return dao5APIConnectors{} }
func (s dao5APIStore) ManualOverrides() store.ActionManualOverrideRepo {
	return dao5APIOverrides{fail: s.overrideFail}
}
func (s dao5APIStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return dao5APIRules{fail: s.withdrawnFail}
}
func (s dao5APIStore) ActionExecLog() store.ActionExecLogRepo      { return dao5APILogs{fail: s.auditFail} }
func (s dao5APIStore) ScheduledActions() store.ScheduledActionRepo { return dao5APISchedules{} }
func (s dao5APIStore) BGPAnnouncements() store.BGPAnnouncementRepo { return dao5APIAnnouncements{} }

type dao5APITransport int

func (status dao5APITransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: int(status), Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}
func dao5APICase(t *testing.T, failure bool, s dao5APIStore, op string, want []string) {
	t.Helper()
	r := prometheus.NewRegistry()
	if err := metrics.Register(r, s, tracker.New(tracker.Config{}, s, nil, nil, nil)); err != nil {
		t.Fatal(err)
	}
	metric := func() float64 {
		fs, err := r.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fs {
			if f.GetName() == "xsight_state_write_failures_total" {
				for _, m := range f.Metric {
					for _, l := range m.Label {
						if l.GetName() == "op" && l.GetValue() == op {
							return m.GetCounter().GetValue()
						}
					}
				}
			}
		}
		return 0
	}
	before := metric()
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	status := 204
	if failure {
		status = 500
	}
	http.DefaultTransport = dao5APITransport(status)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/force-remove", strings.NewReader(`{"attack_id":20,"action_id":10,"connector_id":7,"external_rule_id":"rule-1"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	forceRemoveAction(Dependencies{Store: s, ActionEngine: action.NewEngine(s, "auto")})(c)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if failure {
		if w.Code != 500 || !strings.Contains(w.Body.String(), "force remove failed") {
			t.Fatalf("withdraw and audit failed: status=%d body=%s; want 500 force remove failed", w.Code, w.Body.String())
		}
		return
	}
	data := apiV3Data(out)
	if w.Code != 200 || data["ok"] != true {
		t.Fatalf("removed rule: status=%d data=%v; want 200 ok", w.Code, data)
	}
	warning, _ := data["warning"].(string)
	for _, step := range want {
		if !strings.Contains(strings.ToLower(warning), strings.ToLower(step)) {
			t.Errorf("warning=%q missing %s", warning, step)
		}
	}
	if delta := metric() - before; delta != 1 {
		t.Errorf("%s delta=%v; want 1", op, delta)
	}
}
func TestDao5_F1_RemoveAndAuditFailure(t *testing.T) {
	dao5APICase(t, true, dao5APIStore{auditFail: true}, "", nil)
}
func TestDao5_F2_OverrideWarning(t *testing.T) {
	dao5APICase(t, false, dao5APIStore{overrideFail: true}, "force_remove_override", []string{"override"})
}
func TestDao5_F3_AllWarningsAccumulate(t *testing.T) {
	dao5APICase(t, false, dao5APIStore{overrideFail: true, withdrawnFail: true, auditFail: true}, "force_remove_mark_withdrawn", []string{"override", "MarkWithdrawn", "audit"})
}
