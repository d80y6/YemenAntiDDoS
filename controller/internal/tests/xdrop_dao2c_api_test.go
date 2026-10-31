package tests

// C13 tests the force-removal API contract.
// Uses the real engine, MockStore, and an in-memory XDrop fake replacing http.DefaultTransport; DELETE always returns 204, without listeners.
import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type d2cAPITransport func(*http.Request) (*http.Response, error)

func (f d2cAPITransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// 〔守卫〕C13_ForceAPIShape：API 强撤 active 真 id 行（live 攻击）。
// 判据：200 且响应体恰为 {ok:true, message:"force removed <rule> (attack #<id>)"}（无 warning）；manual_override success 日志 1 条；
// 覆盖**去重后** 1 行（读 MockStore 表行；MockStore.Create 按四元组幂等，⛔ 限制 Create 调用次数）；行 withdrawn；DELETE 恰 1（claim_ref = a600.x41）。HEAD 绿。
// 实施后守：引擎锁内写 + API 再写（幂等）不得产生第二条覆盖 / 第二条 manual_override 日志 / warning。
func TestD2C_C13_ForceAPIShape(t *testing.T) {
	const (
		attackID  = 600
		actionID  = 41
		connID    = 7
		rule      = "rule-d2c-force"
		claimRef  = "a600.x41"
		xdropBase = "http://192.0.2.20/api/v1"
	)
	ctx := context.Background()
	ms := NewMockStore()
	ms.attacks.attacks = append(ms.attacks.attacks, store.Attack{ID: attackID, DstIP: "192.0.2.60", StartedAt: time.Now().Add(-5 * time.Minute)})
	ms.responses.actions = append(ms.responses.actions, store.ResponseAction{ID: actionID, ResponseID: 1, ActionType: "xdrop"})
	ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{ID: connID, Name: "d2c", APIURL: xdropBase, APIKey: legacyV3Key, Enabled: true, TimeoutMs: 1000})
	if _, err := ms.xdropActiveRules.Upsert(ctx, &store.XDropActiveRule{AttackID: attackID, ActionID: actionID, ConnectorID: connID, ExternalRuleID: rule, Status: "active"}); err != nil {
		t.Fatalf("device: seed active xdrop row: %v", err)
	}
	deletes, other := 0, 0
	old := http.DefaultTransport
	http.DefaultTransport = d2cAPITransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/rules/"+rule && r.URL.Query().Get("claim_ref") == claimRef && r.Header.Get("Authorization") == "Bearer "+legacyV3Key {
			deletes++
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
		}
		other++
		return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":"unexpected","message":"d2c fake"}`)), Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })

	e := action.NewEngine(ms, "auto")
	w := dao4Request(t, ms, e, "POST", "/api/active-actions/force-remove", `{"attack_id":600,"action_id":41,"connector_id":7,"external_rule_id":"`+rule+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("force-remove HTTP %d want 200; body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v body=%s", err, w.Body.String())
	}
	wantMsg := "force removed " + rule + " (attack #600)"
	if len(body) != 2 || body["ok"] != true || body["message"] != wantMsg {
		t.Errorf("response=%v; want exactly {ok:true, message:%q} (no warning)", body, wantMsg)
	}
	if deletes != 1 || other != 0 {
		t.Errorf("xDrop DELETE=%d other requests=%d; want 1/0", deletes, other)
	}
	manual := 0
	for _, l := range ms.actionExecLog.snapshotLogs() {
		if l.ActionType == "manual_override" && l.TriggerPhase == "manual_override" && l.Status == "success" && l.AttackID == attackID && l.ActionID == actionID && l.ConnectorID != nil && *l.ConnectorID == connID && l.ExternalRuleID == rule {
			manual++
		}
	}
	if manual != 1 {
		t.Errorf("manual_override success logs=%d want 1; logs=%+v", manual, ms.actionExecLog.snapshotLogs())
	}
	overrides, _ := ms.ManualOverrides().ListByAttack(ctx, attackID)
	if len(overrides) != 1 || overrides[0].ActionID != actionID || overrides[0].ConnectorID != connID || overrides[0].ExternalRuleID != rule {
		t.Errorf("overrides=%+v; want exactly one row for the four-tuple", overrides)
	}
	rows, _ := ms.XDropActiveRules().ListByAttack(ctx, attackID)
	if len(rows) != 1 || rows[0].Status != "withdrawn" {
		t.Errorf("rows=%+v; want one withdrawn row", rows)
	}
}
