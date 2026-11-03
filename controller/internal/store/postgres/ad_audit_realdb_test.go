package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/configpub"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/gin-gonic/gin"
)

// The contract backend skips before any connection when XSIGHT_TEST_ADMIN_DSN
// is absent. Requests use the HTTP router, never newly added production symbols.
func adPGRequest(t *testing.T, r *gin.Engine, method, path string, body any, status int) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "dao14d1-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != status {
		t.Fatalf("HTTP %s %s status=%d want=%d body=%s", method, path, w.Code, status, w.Body)
	}
	return w
}
func adPGCreate(t *testing.T, r *gin.Engine, path string, body any) int {
	t.Helper()
	w := adPGRequest(t, r, "POST", path, body, 201)
	var row struct{ ID int }
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil || row.ID == 0 {
		t.Fatalf("seed id: %s err=%v", w.Body, err)
	}
	return row.ID
}
func adPGJSON(t *testing.T, label string, raw json.RawMessage, want any) {
	t.Helper()
	if len(raw) == 0 {
		t.Errorf("%s missing; want=%v", label, want)
		return
	}
	var got any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var normalized any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, normalized) {
		t.Errorf("%s=%s want=%s", label, raw, encoded)
	}
}
func adPGField(t *testing.T, d map[string]json.RawMessage, side, key string, want any) {
	t.Helper()
	var row map[string]json.RawMessage
	if err := json.Unmarshal(d[side], &row); err != nil || row == nil {
		t.Fatalf("%s must be object: %s err=%v", side, d[side], err)
	}
	adPGJSON(t, side+"."+key, row[key], want)
}
func adPGUpdateDiff(t *testing.T, db *PGStore, r *gin.Engine, path string, body any) map[string]json.RawMessage {
	t.Helper()
	ctx := context.Background()
	var before int64
	if err := db.Pool().QueryRow(ctx, "SELECT coalesce(max(id),0) FROM config_audit_log").Scan(&before); err != nil {
		t.Fatal(err)
	}
	adPGRequest(t, r, "PUT", path, body, 200)
	var count int
	if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM config_audit_log WHERE id > $1", before).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit count=%d want=1", count)
	}
	var raw []byte
	if err := db.Pool().QueryRow(ctx, "SELECT diff FROM config_audit_log WHERE id > $1", before).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("audit diff must be nonempty")
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("audit diff must decode: %v: %s", err, raw)
	}
	for _, side := range []string{"old", "new"} {
		if _, ok := d[side]; !ok {
			t.Fatalf("diff missing %s: %s", side, raw)
		}
	}
	return d
}

func TestAD_G1_AuditDiff(t *testing.T) {
	db := newPostgresContractBackend(t).Store().(*PGStore)
	gin.SetMode(gin.TestMode)
	deps := dao14d1PGDeps(db)
	seed := api.NewRouter(deps)
	// Setup writes go through the same public routes, without publishing audits.
	for i := 1; i <= 5; i++ {
		id := adPGCreate(t, seed, "/api/responses", map[string]any{"name": fmt.Sprintf("ad-r%d", i)})
		if id != i {
			t.Fatalf("response fixture id=%d want=%d", id, i)
		}
	}
	for i := 1; i <= 2; i++ {
		id := adPGCreate(t, seed, "/api/settings/bgp-connectors", map[string]any{"name": fmt.Sprintf("ad-b%d", i), "bgp_asn": 64512})
		if id != i {
			t.Fatalf("bgp fixture id=%d want=%d", id, i)
		}
	}
	for i := 1; i <= 4; i++ {
		id := adPGCreate(t, seed, "/api/settings/xdrop-connectors", map[string]any{"name": fmt.Sprintf("ad-x%d", i), "api_url": "https://192.0.2.1", "api_key": "ad-fixture"})
		if id != i {
			t.Fatalf("xdrop fixture id=%d want=%d", id, i)
		}
	}
	deps.ConfigPub = configpub.New(db, nil, func() []string { return nil })
	router := api.NewRouter(deps)
	createAction := func(t *testing.T, kind string) int {
		t.Helper()
		body := map[string]any{"action_type": kind, "trigger_phase": "on_detected", "run_mode": "once", "execution": "automatic"}
		if kind == "bgp" {
			body["connector_id"] = 1
			body["bgp_route_map"] = "BLACKHOLE"
		} else {
			body["xdrop_action"] = "filter_l4"
			body["xdrop_custom_payload"] = map[string]string{"dst_ip": "192.0.2.1"}
			body["target_node_ids"] = []int{3}
		}
		return adPGCreate(t, seed, "/api/responses/1/actions", body)
	}
	t.Run("A4_BGPConnector_FixRed", func(t *testing.T) {
		id := createAction(t, "bgp")
		d := adPGUpdateDiff(t, db, router, fmt.Sprintf("/api/actions/%d", id), map[string]any{"connector_id": 2})
		adPGField(t, d, "old", "bgp_connector_id", 1)
		adPGField(t, d, "new", "bgp_connector_id", 2)
	})
	t.Run("A4_Payload_FixRed", func(t *testing.T) {
		id := createAction(t, "xdrop")
		d := adPGUpdateDiff(t, db, router, fmt.Sprintf("/api/actions/%d", id), map[string]any{"xdrop_custom_payload": map[string]string{"dst_ip": "192.0.2.2"}})
		adPGField(t, d, "old", "xdrop_custom_payload", map[string]string{"dst_ip": "192.0.2.1"})
		adPGField(t, d, "new", "xdrop_custom_payload", map[string]string{"dst_ip": "192.0.2.2"})
	})
	t.Run("A4_Targets_FixRed", func(t *testing.T) {
		id := createAction(t, "xdrop")
		d := adPGUpdateDiff(t, db, router, fmt.Sprintf("/api/actions/%d", id), map[string]any{"target_node_ids": []int{4}})
		adPGField(t, d, "old", "target_node_ids", []int{3})
		adPGField(t, d, "new", "target_node_ids", []int{4})
	})
	for _, existing := range []bool{true, false} {
		name := "A5_ExistingTwo_FixRed"
		if !existing {
			name = "A5_EmptyArray_FixRed"
		}
		t.Run(name, func(t *testing.T) {
			id := createAction(t, "xdrop")
			path := fmt.Sprintf("/api/actions/%d/preconditions", id)
			old := []store.ActionPrecondition{}
			if existing {
				adPGRequest(t, seed, "PUT", path, map[string]any{"preconditions": []store.ActionPrecondition{{Attribute: "pps", Operator: "gt", Value: "100"}, {Attribute: "decoder", Operator: "eq", Value: "udp"}}}, 200)
				var err error
				old, err = db.Preconditions().List(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
				if len(old) != 2 {
					t.Fatalf("old fixture count=%d want=2", len(old))
				}
			}
			next := []store.ActionPrecondition{{Attribute: "bps", Operator: "gte", Value: "200"}}
			d := adPGUpdateDiff(t, db, router, path, map[string]any{"preconditions": next})
			adPGJSON(t, "old preconditions", d["old"], old)
			adPGJSON(t, "new preconditions", d["new"], next)
		})
	}
	for _, kind := range []string{"Template", "Threshold"} {
		t.Run("A6_"+kind+"ToFive_FixRed", func(t *testing.T) {
			template := adPGCreate(t, seed, "/api/threshold-templates", map[string]any{"name": "ad-" + kind, "response_id": 1})
			id := template
			path := fmt.Sprintf("/api/threshold-templates/%d", id)
			if kind == "Threshold" {
				id = adPGCreate(t, seed, fmt.Sprintf("/api/threshold-templates/%d/rules", template), map[string]any{"domain": "subnet", "direction": "receives", "decoder": "ip", "unit": "pps", "comparison": "over", "value": 1000, "response_id": 1})
				path = fmt.Sprintf("/api/thresholds/%d", id)
			}
			d := adPGUpdateDiff(t, db, router, path, map[string]any{"response_id": 5})
			adPGField(t, d, "old", "response_id", 1)
			adPGField(t, d, "new", "response_id", 5)
			var stored *int
			if kind == "Template" {
				row, err := db.ThresholdTemplates().Get(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
				stored = row.ResponseID
			} else {
				row, err := db.Thresholds().Get(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
				stored = row.ResponseID
			}
			if stored == nil || *stored != 5 {
				t.Errorf("stored response_id=%v want=5", stored)
			}
		})
	}
}
