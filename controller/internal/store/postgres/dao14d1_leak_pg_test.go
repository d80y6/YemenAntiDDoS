package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/configpub"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/baseline"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/threshold"
	"github.com/d80y6/YemenDDoS/controller/internal/ingestion"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

type dao14d1Route struct {
	method, route, path, body string
	status                    int
}

// Frozen request inventory: future route additions and removals must update it.
// A zero status denotes the plan's pending L0 determination; leak and JSON
// checks still apply to that request.
var dao14d1Routes = []dao14d1Route{
	{"POST", "/api/login", "/api/login", "{\"username\":\"admin\",\"password\":\"x\"}", 401},
	{"GET", "/api/users", "/api/users", "", 500},
	{"POST", "/api/users", "/api/users", "{\"username\":\"dao14u\",\"password\":\"dao14-pass-1\"}", 500},
	{"PUT", "/api/users/:id", "/api/users/1", "{\"role\":\"viewer\"}", 404},
	{"DELETE", "/api/users/:id", "/api/users/1", "", 500},
	{"GET", "/api/nodes", "/api/nodes", "", 500},
	{"POST", "/api/nodes", "/api/nodes", "{\"id\":\"dao14-n1\",\"api_key\":\"k1\"}", 500},
	{"GET", "/api/nodes/:id", "/api/nodes/dao14-n1", "", 404},
	{"PUT", "/api/nodes/:id", "/api/nodes/dao14-n1", "{\"description\":\"d\"}", 404},
	{"DELETE", "/api/nodes/:id", "/api/nodes/dao14-n1", "", 500},
	{"GET", "/api/nodes/:id/status", "/api/nodes/dao14-n1/status", "", 404},
	{"GET", "/api/prefixes", "/api/prefixes", "", 500},
	{"POST", "/api/prefixes", "/api/prefixes", "{\"prefix\":\"198.51.100.0/24\"}", 500},
	{"GET", "/api/prefixes/:id", "/api/prefixes/1", "", 404},
	{"PUT", "/api/prefixes/:id", "/api/prefixes/1", "{\"name\":\"n\"}", 404},
	{"DELETE", "/api/prefixes/:id", "/api/prefixes/1", "", 500},
	{"GET", "/api/threshold-templates", "/api/threshold-templates", "", 500},
	{"POST", "/api/threshold-templates", "/api/threshold-templates", "{\"name\":\"dao14-t\"}", 500},
	{"GET", "/api/threshold-templates/:id", "/api/threshold-templates/1", "", 404},
	{"PUT", "/api/threshold-templates/:id", "/api/threshold-templates/1", "{\"name\":\"t2\"}", 404},
	{"DELETE", "/api/threshold-templates/:id", "/api/threshold-templates/1", "", 500},
	{"POST", "/api/threshold-templates/:id/duplicate", "/api/threshold-templates/1/duplicate", "", 404},
	{"GET", "/api/threshold-templates/:id/rules", "/api/threshold-templates/1/rules", "", 500},
	{"POST", "/api/threshold-templates/:id/rules", "/api/threshold-templates/1/rules", "{\"decoder\":\"ip\",\"unit\":\"pps\",\"value\":1000,\"domain\":\"subnet\"}", 500},
	{"GET", "/api/thresholds", "/api/thresholds?prefix_id=1", "", 500},
	{"POST", "/api/thresholds", "/api/thresholds", "{\"prefix_id\":1,\"domain\":\"subnet\",\"direction\":\"receives\",\"decoder\":\"ip\",\"unit\":\"pps\",\"comparison\":\"over\",\"value\":1000}", 500},
	{"GET", "/api/thresholds/:id", "/api/thresholds/1", "", 404},
	{"PUT", "/api/thresholds/:id", "/api/thresholds/1", "{\"value\":2000}", 404},
	{"DELETE", "/api/thresholds/:id", "/api/thresholds/1", "", 500},
	{"PUT", "/api/threshold-rules/:id", "/api/threshold-rules/1", "{\"value\":2000}", 404},
	{"DELETE", "/api/threshold-rules/:id", "/api/threshold-rules/1", "", 500},
	{"GET", "/api/responses", "/api/responses", "", 500},
	{"POST", "/api/responses", "/api/responses", "{\"name\":\"dao14-r\"}", 500},
	{"GET", "/api/responses/:id", "/api/responses/1", "", 404},
	{"PUT", "/api/responses/:id", "/api/responses/1", "{\"name\":\"r2\"}", 404},
	{"DELETE", "/api/responses/:id", "/api/responses/1", "", 500},
	{"GET", "/api/responses/:id/actions", "/api/responses/1/actions", "", 500},
	{"POST", "/api/responses/:id/actions", "/api/responses/1/actions", "{\"action_type\":\"webhook\",\"trigger_phase\":\"on_detected\",\"run_mode\":\"once\",\"execution\":\"automatic\",\"enabled\":true,\"priority\":1,\"connector_id\":1}", 500},
	{"PUT", "/api/actions/:id", "/api/actions/1", "{\"priority\":2}", 404},
	{"DELETE", "/api/actions/:id", "/api/actions/1", "", 404},
	{"GET", "/api/actions/:id/xdrop-targets", "/api/actions/1/xdrop-targets", "", 500},
	{"PUT", "/api/actions/:id/xdrop-targets", "/api/actions/1/xdrop-targets", "{\"connector_ids\":[1]}", 500},
	{"GET", "/api/actions/:id/preconditions", "/api/actions/1/preconditions", "", 500},
	{"PUT", "/api/actions/:id/preconditions", "/api/actions/1/preconditions", "{\"preconditions\":[{\"attribute\":\"pps\",\"operator\":\"gt\",\"value\":\"1\"}]}", 500},
	{"GET", "/api/webhooks", "/api/webhooks", "", 500},
	{"POST", "/api/webhooks", "/api/webhooks", "{}", 410},
	{"PUT", "/api/webhooks/:id", "/api/webhooks/1", "{}", 410},
	{"DELETE", "/api/webhooks/:id", "/api/webhooks/1", "", 410},
	{"GET", "/api/stats/summary", "/api/stats/summary", "", 500},
	{"GET", "/api/baseline", "/api/baseline", "", 500},
	{"GET", "/api/stats/timeseries", "/api/stats/timeseries?prefix=198.51.100.0/24", "", 500},
	{"GET", "/api/stats/overview", "/api/stats/overview", "", 200},
	{"GET", "/api/stats/total-timeseries", "/api/stats/total-timeseries", "", 500},
	{"GET", "/api/attacks", "/api/attacks", "", 500},
	{"GET", "/api/attacks/mitigation-brief", "/api/attacks/mitigation-brief?ids=1", "", 500},
	{"GET", "/api/attacks/active", "/api/attacks/active", "", 500},
	{"GET", "/api/attacks/:id", "/api/attacks/1", "", 404},
	{"GET", "/api/attacks/:id/action-log", "/api/attacks/1/action-log", "", 500},
	{"GET", "/api/attacks/:id/sensor-logs", "/api/attacks/1/sensor-logs", "", 0},
	{"GET", "/api/attacks/:id/mitigation-summary", "/api/attacks/1/mitigation-summary", "", 0},
	{"POST", "/api/attacks/:id/expire", "/api/attacks/1/expire", "{}", 404},
	{"GET", "/api/active-actions/bgp", "/api/active-actions/bgp", "", 500},
	{"GET", "/api/active-actions/xdrop", "/api/active-actions/xdrop", "", 500},
	{"GET", "/api/active-actions/xdrop/delivery", "/api/active-actions/xdrop/delivery?connector_id=1&rule_id=r", "", 404},
	{"GET", "/api/active-actions/timeline", "/api/active-actions/timeline?attack_id=1&external_rule_id=r", "", 500},
	{"POST", "/api/active-actions/force-remove", "/api/active-actions/force-remove", "{\"attack_id\":1,\"action_id\":1,\"connector_id\":1,\"external_rule_id\":\"rule-1\"}", 500},
	{"POST", "/api/active-actions/bgp/orphan-force-withdraw", "/api/active-actions/bgp/orphan-force-withdraw", "{\"announcement_id\":1}", 0},
	{"POST", "/api/active-actions/bgp/orphan-dismiss", "/api/active-actions/bgp/orphan-dismiss", "{\"announcement_id\":1}", 0},
	{"GET", "/api/active-actions/bgp/dismissed-orphans", "/api/active-actions/bgp/dismissed-orphans", "", 500},
	{"POST", "/api/active-actions/bgp/orphan-undismiss", "/api/active-actions/bgp/orphan-undismiss", "{\"announcement_id\":1}", 0},
	{"GET", "/api/audit-log", "/api/audit-log", "", 500},
	{"GET", "/api/dynamic-detection/config", "/api/dynamic-detection/config", "", 500},
	{"PUT", "/api/dynamic-detection/config", "/api/dynamic-detection/config", "{\"enabled\":true,\"deviation_min\":10,\"deviation_max\":50,\"stable_weeks\":2,\"min_pps\":0,\"min_bps\":0,\"ewma_alpha\":0.3}", 500},
	{"GET", "/api/dynamic-detection/status", "/api/dynamic-detection/status", "", 200},
	{"GET", "/api/settings/webhook-connectors", "/api/settings/webhook-connectors", "", 500},
	{"POST", "/api/settings/webhook-connectors", "/api/settings/webhook-connectors", "{\"name\":\"w\",\"url\":\"https://198.51.100.10/hook\"}", 500},
	{"GET", "/api/settings/webhook-connectors/:id", "/api/settings/webhook-connectors/1", "", 404},
	{"PUT", "/api/settings/webhook-connectors/:id", "/api/settings/webhook-connectors/1", "{\"name\":\"webhook2\"}", 404},
	{"DELETE", "/api/settings/webhook-connectors/:id", "/api/settings/webhook-connectors/1", "", 500},
	{"POST", "/api/settings/webhook-connectors/:id/test", "/api/settings/webhook-connectors/1/test", "{}", 404},
	{"GET", "/api/settings/xdrop-connectors", "/api/settings/xdrop-connectors", "", 500},
	{"POST", "/api/settings/xdrop-connectors", "/api/settings/xdrop-connectors", "{\"name\":\"x\",\"api_url\":\"https://198.51.100.11\",\"api_key\":\"k\"}", 500},
	{"GET", "/api/settings/xdrop-connectors/:id", "/api/settings/xdrop-connectors/1", "", 404},
	{"PUT", "/api/settings/xdrop-connectors/:id", "/api/settings/xdrop-connectors/1", "{\"name\":\"xdrop2\"}", 404},
	{"DELETE", "/api/settings/xdrop-connectors/:id", "/api/settings/xdrop-connectors/1", "", 500},
	{"POST", "/api/settings/xdrop-connectors/:id/test", "/api/settings/xdrop-connectors/1/test", "{}", 404},
	{"GET", "/api/settings/shell-connectors", "/api/settings/shell-connectors", "", 500},
	{"POST", "/api/settings/shell-connectors", "/api/settings/shell-connectors", "{\"name\":\"s\",\"command\":\"/bin/true\"}", 500},
	{"GET", "/api/settings/shell-connectors/:id", "/api/settings/shell-connectors/1", "", 404},
	{"PUT", "/api/settings/shell-connectors/:id", "/api/settings/shell-connectors/1", "{\"name\":\"shell2\"}", 404},
	{"DELETE", "/api/settings/shell-connectors/:id", "/api/settings/shell-connectors/1", "", 500},
	{"GET", "/api/settings/bgp-connectors", "/api/settings/bgp-connectors", "", 500},
	{"POST", "/api/settings/bgp-connectors", "/api/settings/bgp-connectors", "{\"name\":\"b\",\"bgp_asn\":64500}", 500},
	{"GET", "/api/settings/bgp-connectors/:id", "/api/settings/bgp-connectors/1", "", 404},
	{"PUT", "/api/settings/bgp-connectors/:id", "/api/settings/bgp-connectors/1", "{\"name\":\"bgp2\"}", 404},
	{"DELETE", "/api/settings/bgp-connectors/:id", "/api/settings/bgp-connectors/1", "", 500},
	{"POST", "/api/settings/bgp-connectors/:id/test", "/api/settings/bgp-connectors/1/test", "{}", 404},
	{"GET", "/api/settings/bgp-connectors/:id/routes", "/api/settings/bgp-connectors/1/routes", "", 404},
	{"GET", "/api/flow-listeners", "/api/flow-listeners?node_id=dao14-n1", "", 500},
	{"POST", "/api/flow-listeners", "/api/flow-listeners", "{\"node_id\":\"dao14-n1\",\"listen_address\":\":6343\",\"protocol_mode\":\"auto\"}", 400},
	{"GET", "/api/flow-listeners/:id", "/api/flow-listeners/1", "", 404},
	{"PUT", "/api/flow-listeners/:id", "/api/flow-listeners/1", "{\"node_id\":\"dao14-n1\",\"listen_address\":\":6343\",\"protocol_mode\":\"auto\"}", 404},
	{"DELETE", "/api/flow-listeners/:id", "/api/flow-listeners/1", "", 500},
	{"GET", "/api/flow-sources", "/api/flow-sources?listener_id=1", "", 500},
	{"POST", "/api/flow-sources", "/api/flow-sources", "{\"listener_id\":1,\"name\":\"s\",\"device_ip\":\"192.0.2.1\",\"sample_mode\":\"auto\"}", 400},
	{"GET", "/api/flow-sources/:id", "/api/flow-sources/1", "", 404},
	{"PUT", "/api/flow-sources/:id", "/api/flow-sources/1", "{\"name\":\"s\",\"device_ip\":\"192.0.2.1\",\"sample_mode\":\"auto\"}", 404},
	{"DELETE", "/api/flow-sources/:id", "/api/flow-sources/1", "", 500},
	{"GET", "/api/thresholds", "/api/thresholds", "", 500},
}

func dao14d1PGDeps(s store.Store) api.Dependencies {
	return api.Dependencies{
		Store: s, APIKey: "dao14d1-key", JWTSecret: "dao14d1",
		ActionEngine: action.NewEngine(s, "auto"), Tracker: tracker.New(tracker.Config{}, s, nil, nil, nil),
		NodeState: ingestion.NewNodeState(), ThreshTree: threshold.NewTree(),
		ProfileEngine: baseline.NewProfileEngine(ring.New(ring.DefaultLimits()), s.DynDetect(), s.Stats()),
		BaselineCalc:  baseline.NewCalculator(s.Stats(), baseline.DefaultConfig()),
	}
}
func dao14d1PGRequest(r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "dao14d1-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func dao14d1PGError(t *testing.T, w *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid error JSON: %s (%v)", w.Body, err)
	}
	if w.Code != status || !reflect.DeepEqual(got, map[string]any{"error": message}) {
		t.Errorf("status=%d body=%s want=%d %q", w.Code, w.Body, status, message)
	}
	for _, word := range []string{"SQLSTATE", "ERROR:", "relation", "violates", "user=", "database="} {
		if strings.Contains(w.Body.String(), word) {
			t.Errorf("leaked %q: %s", word, w.Body)
		}
	}
}

func TestDao14d1_G4a(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	ctx := context.Background()
	var database string
	if err := db.Pool().QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile("^xsight_ct_[0-9a-f]{16}$").MatchString(database) {
		t.Fatalf("unsafe fixture database %q", database)
	}
	if _, err := db.Pool().Exec(ctx, "CREATE SCHEMA dao14d1_empty"); err != nil {
		t.Fatal(err)
	}
	dsn := db.Pool().Config().ConnString()
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		parsed, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		query := parsed.Query()
		query.Set("search_path", "dao14d1_empty")
		parsed.RawQuery = query.Encode()
		dsn = parsed.String()
	} else {
		dsn += " search_path=dao14d1_empty"
	}
	leaky, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leaky.Close)
	var searchPath string
	if err := leaky.Pool().QueryRow(ctx, "SELECT current_setting('search_path')").Scan(&searchPath); err != nil {
		t.Fatal(err)
	}
	if searchPath != "dao14d1_empty" {
		t.Fatalf("search_path=%q", searchPath)
	}
	var count int
	err = leaky.Pool().QueryRow(ctx, "SELECT count(*) FROM users").Scan(&count)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42P01" {
		t.Fatalf("broken empty-schema fixture: %T %v", err, err)
	}
	router := api.NewRouter(dao14d1PGDeps(leaky))
	actual := map[string]bool{}
	for _, route := range router.Routes() {
		if route.Path != "/metrics" {
			actual[route.Method+" "+route.Path] = true
		}
	}
	inventory := map[string]bool{}
	for _, tc := range dao14d1Routes {
		inventory[tc.method+" "+tc.route] = true
	}
	if !reflect.DeepEqual(actual, inventory) {
		t.Fatalf("route inventory mismatch: router=%v table=%v", actual, inventory)
	}
	var leaks []string
	for _, tc := range dao14d1Routes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := dao14d1PGRequest(router, tc.method, tc.path, tc.body)
			var value any
			if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
				t.Fatalf("empty or invalid response: status=%d body=%s error=%v", w.Code, w.Body, err)
			}
			if w.Code < 200 || w.Code >= 300 {
				object, ok := value.(map[string]any)
				if !ok || len(object) != 1 {
					t.Errorf("non-2xx body is not an error object: %s", w.Body)
				} else if _, ok := object["error"].(string); !ok {
					t.Errorf("error is not a string: %s", w.Body)
				}
			}
			leaked := false
			for _, word := range []string{"SQLSTATE", "ERROR:", "relation", "does not exist", "dao14d1_empty"} {
				leaked = leaked || strings.Contains(w.Body.String(), word)
			}
			if leaked {
				leaks = append(leaks, tc.method+" "+tc.path)
				t.Errorf("database text leaked: %s", w.Body)
			}
			if tc.status != 0 && w.Code != tc.status {
				t.Errorf("status=%d want=%d body=%s", w.Code, tc.status, w.Body)
			}
			t.Logf("ROUTE %s %s status=%d", tc.method, tc.path, w.Code)
		})
	}
	t.Logf("DAO14D1_LEAKS n=%d routes=%v", len(leaks), leaks)
}

func TestDao14d1_G4b(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	deps := dao14d1PGDeps(db)
	deps.ConfigPub = configpub.New(db, nil, func() []string { return nil })
	router := api.NewRouter(deps)
	create := func(method, path string, body any) int {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		w := dao14d1PGRequest(router, method, path, string(raw))
		if w.Code < 200 || w.Code >= 300 {
			t.Fatalf("seed %s %s: status=%d body=%s", method, path, w.Code, w.Body)
		}
		var result struct{ ID int }
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.ID
	}
	prefix := create("POST", "/api/prefixes", map[string]any{"prefix": "198.51.100.0/24"})
	templateA := create("POST", "/api/threshold-templates", map[string]any{"name": "dao14-t"})
	templateB := create("POST", "/api/threshold-templates", map[string]any{"name": "dao14-t-b"})
	response := create("POST", "/api/responses", map[string]any{"name": "dao14-r"})
	connector := create("POST", "/api/settings/xdrop-connectors", map[string]any{"name": "dao14-x", "api_url": "https://198.51.100.11", "api_key": "fixture"})
	ruleBody := map[string]any{"decoder": "ip", "unit": "pps", "value": 1000, "domain": "subnet"}
	templateRule := create("POST", fmt.Sprintf("/api/threshold-templates/%d/rules", templateA), ruleBody)
	prefixBody := map[string]any{"prefix_id": prefix, "domain": "subnet", "direction": "receives", "decoder": "ip", "unit": "pps", "comparison": "over", "value": 1000}
	prefixRule := create("POST", "/api/thresholds", prefixBody)
	actionBody := map[string]any{"action_type": "xdrop", "trigger_phase": "on_detected", "run_mode": "once", "execution": "automatic", "enabled": true, "priority": 1, "xdrop_action": "filter_l4", "xdrop_custom_payload": map[string]any{"dst_ip": "192.0.2.1"}, "target_node_ids": []int{connector}}
	actionID := create("POST", fmt.Sprintf("/api/responses/%d/actions", response), actionBody)
	create("POST", "/api/users", map[string]any{"username": "dao14u", "password": "dao14-pass-1"})
	if w := dao14d1PGRequest(router, "POST", "/api/nodes", `{"id":"dao14-n1","api_key":"k1"}`); w.Code != 201 {
		t.Fatalf("node seed: status=%d body=%s", w.Code, w.Body)
	}
	create("POST", fmt.Sprintf("/api/threshold-templates/%d/duplicate", templateA), nil)
	var missingTemplate int
	if err := db.Pool().QueryRow(context.Background(), "SELECT coalesce(max(id),0)+1000 FROM threshold_templates").Scan(&missingTemplate); err != nil {
		t.Fatal(err)
	}
	var missingAction, missingConnector int
	if err := db.Pool().QueryRow(context.Background(), "SELECT coalesce(max(id),0)+1000 FROM response_actions").Scan(&missingAction); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool().QueryRow(context.Background(), "SELECT coalesce(max(id),0)+1000 FROM xdrop_connectors").Scan(&missingConnector); err != nil {
		t.Fatal(err)
	}
	badAction := map[string]any{}
	for k, v := range actionBody {
		badAction[k] = v
	}
	badAction["target_node_ids"] = []int{missingConnector}
	noOwner := map[string]any{}
	for k, v := range prefixBody {
		if k != "prefix_id" {
			noOwner[k] = v
		}
	}
	for _, tc := range []struct {
		name, method, path string
		body               any
		status             int
		message            string
	}{
		{"U2", "POST", "/api/users", map[string]any{"username": "dao14u", "password": "dao14-pass-1"}, 409, "already exists"},
		{"N2", "POST", "/api/nodes", map[string]any{"id": "dao14-n1", "api_key": "k1"}, 409, "already exists"},
		{"P2_Syntax", "POST", "/api/prefixes", map[string]any{"prefix": "abc"}, 400, "invalid input"},
		{"P2_HostBits", "POST", "/api/prefixes", map[string]any{"prefix": "192.0.2.1/24"}, 400, "invalid input"},
		{"P2_TemplateFK", "POST", "/api/prefixes", map[string]any{"prefix": "203.0.113.0/24", "threshold_template_id": missingTemplate}, 400, "referenced object not found"},
		{"P4", "PUT", fmt.Sprintf("/api/prefixes/%d", prefix), map[string]any{"parent_id": 99999}, 400, "parent_id not found"},
		{"T2", "POST", "/api/threshold-templates", map[string]any{"name": "dao14-t2", "response_id": 99999}, 400, "referenced object not found"},
		{"T6", "POST", fmt.Sprintf("/api/threshold-templates/%d/duplicate", templateA), nil, 409, "already exists"},
		{"T8_FK", "POST", fmt.Sprintf("/api/threshold-templates/%d/rules", missingTemplate), ruleBody, 400, "referenced object not found"},
		{"T8_Dup", "POST", fmt.Sprintf("/api/threshold-templates/%d/rules", templateA), ruleBody, 409, "already exists"},
		{"H2_XOR", "POST", "/api/thresholds", noOwner, 400, "invalid value"},
		{"H2_Dup", "POST", "/api/thresholds", prefixBody, 409, "already exists"},
		{"AC2", "POST", fmt.Sprintf("/api/responses/%d/actions", response), badAction, 400, "set xdrop targets: referenced object not found"},
		{"AC3", "PUT", fmt.Sprintf("/api/actions/%d", actionID), map[string]any{"target_node_ids": []int{missingConnector}}, 500, "set xdrop targets: database error"},
		{"AC6_Conn", "PUT", fmt.Sprintf("/api/actions/%d/xdrop-targets", actionID), map[string]any{"connector_ids": []int{missingConnector}}, 400, "referenced object not found"},
		{"AC6_Action", "PUT", fmt.Sprintf("/api/actions/%d/xdrop-targets", missingAction), map[string]any{"connector_ids": []int{connector}}, 400, "referenced object not found"},
		{"AC8", "PUT", fmt.Sprintf("/api/actions/%d/preconditions", missingAction), map[string]any{"preconditions": []map[string]any{{"attribute": "pps", "operator": "gt", "value": "1"}}}, 400, "referenced object not found"},
		{"K1", "GET", "/api/attacks?offset=-1", nil, 400, "invalid input"},
		{"K1_Audit", "GET", "/api/audit-log?offset=-1", nil, 400, "invalid input"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var before *store.ResponseAction
			if tc.name == "AC3" {
				var err error
				before, err = db.Responses().GetAction(context.Background(), actionID)
				if err != nil {
					t.Fatal(err)
				}
			}
			body := ""
			if tc.body != nil {
				raw, err := json.Marshal(tc.body)
				if err != nil {
					t.Fatal(err)
				}
				body = string(raw)
			}
			w := dao14d1PGRequest(router, tc.method, tc.path, body)
			dao14d1PGError(t, w, tc.status, tc.message)
			if tc.name == "AC3" {
				after, err := db.Responses().GetAction(context.Background(), actionID)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, after) {
					t.Error("AC3 parent row was not restored")
				}
			}
		})
	}
	for _, tc := range []struct {
		name, path string
		id         int
		body       map[string]any
	}{
		{"H4", fmt.Sprintf("/api/thresholds/%d", prefixRule), prefixRule, map[string]any{"template_id": templateB, "prefix_id": nil}},
		{"H6", fmt.Sprintf("/api/threshold-rules/%d", templateRule), templateRule, map[string]any{"template_id": nil, "prefix_id": prefix}},
		{"N1", fmt.Sprintf("/api/threshold-rules/%d", templateRule), templateRule, map[string]any{"template_id": templateB, "prefix_id": prefix}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, err := db.Thresholds().Get(context.Background(), tc.id)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			w := dao14d1PGRequest(router, "PUT", tc.path, string(raw))
			if w.Code != 200 {
				t.Errorf("status=%d body=%s", w.Code, w.Body)
			}
			after, err := db.Thresholds().Get(context.Background(), tc.id)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before.TemplateID, after.TemplateID) || !reflect.DeepEqual(before.PrefixID, after.PrefixID) {
				t.Errorf("ownership changed: before=%+v after=%+v", before, after)
			}
			if tc.name == "N1" {
				var oldOwner int
				err := db.Pool().QueryRow(context.Background(), "SELECT (diff->'old'->>'template_id')::int FROM config_audit_log WHERE entity_type='threshold' AND entity_id=$1 ORDER BY id DESC LIMIT 1", fmt.Sprint(tc.id)).Scan(&oldOwner)
				if err != nil {
					t.Fatal(err)
				}
				if oldOwner != templateA {
					t.Errorf("audit old.template_id=%d want=%d", oldOwner, templateA)
				}
			}
		})
	}
}
