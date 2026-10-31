package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/configpub"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// These wrappers are local to AD; existing mocks retain their behavior.
type adStore struct {
	*MockStore
	audits                                []store.AuditLog
	templates                             map[int]store.ThresholdTemplate
	thresholds                            map[int]store.Threshold
	preconditionLists, preconditionWrites int
	preconditionErr                       error
	targetsUnknown                        bool
}

func adFixture() *adStore {
	s := &adStore{MockStore: NewMockStore(), templates: map[int]store.ThresholdTemplate{}, thresholds: map[int]store.Threshold{}}
	s.responses.responses = []store.Response{{ID: 1, Name: "old", Enabled: false}, {ID: 5, Name: "five", Enabled: true}}
	return s
}

type adAuditRepo struct {
	store.AuditLogRepo
	s *adStore
}

func (s *adStore) AuditLog() store.AuditLogRepo { return adAuditRepo{s.MockStore.AuditLog(), s} }
func (r adAuditRepo) Create(_ context.Context, row *store.AuditLog) error {
	cp := *row
	cp.Diff = append(json.RawMessage(nil), row.Diff...)
	r.s.audits = append(r.s.audits, cp)
	return nil
}

type adTemplateRepo struct {
	store.ThresholdTemplateRepo
	s *adStore
}

func (s *adStore) ThresholdTemplates() store.ThresholdTemplateRepo {
	return adTemplateRepo{s.MockStore.ThresholdTemplates(), s}
}
func adTemplateCopy(row store.ThresholdTemplate) store.ThresholdTemplate {
	row.ResponseID = snapshotPointer(row.ResponseID)
	return row
}
func (r adTemplateRepo) Get(_ context.Context, id int) (*store.ThresholdTemplate, error) {
	row, ok := r.s.templates[id]
	if !ok {
		return nil, errors.New("missing template")
	}
	row = adTemplateCopy(row)
	return &row, nil
}
func (r adTemplateRepo) Create(_ context.Context, row *store.ThresholdTemplate) (int, error) {
	cp := adTemplateCopy(*row)
	cp.ID = 40
	r.s.templates[40] = cp
	return 40, nil
}
func (r adTemplateRepo) Update(_ context.Context, row *store.ThresholdTemplate) error {
	r.s.templates[row.ID] = adTemplateCopy(*row)
	return nil
}
func (r adTemplateRepo) Duplicate(_ context.Context, id int, name string) (int, error) {
	cp := adTemplateCopy(r.s.templates[id])
	cp.ID = 41
	cp.Name = name
	r.s.templates[41] = cp
	return 41, nil
}

type adThresholdRepo struct {
	store.ThresholdRepo
	s *adStore
}

func (s *adStore) Thresholds() store.ThresholdRepo {
	return adThresholdRepo{s.MockStore.Thresholds(), s}
}
func (r adThresholdRepo) Get(_ context.Context, id int) (*store.Threshold, error) {
	row, ok := r.s.thresholds[id]
	if !ok {
		return nil, errors.New("missing threshold")
	}
	row = snapshotThreshold(row)
	return &row, nil
}
func (r adThresholdRepo) Update(_ context.Context, row *store.Threshold) error {
	r.s.thresholds[row.ID] = snapshotThreshold(*row)
	return nil
}

type adPreconditionRepo struct {
	store.PreconditionRepo
	s *adStore
}

func (s *adStore) Preconditions() store.PreconditionRepo {
	return adPreconditionRepo{s.MockStore.Preconditions(), s}
}
func (r adPreconditionRepo) List(ctx context.Context, id int) ([]store.ActionPrecondition, error) {
	r.s.preconditionLists++
	if r.s.preconditionErr != nil {
		return nil, r.s.preconditionErr
	}
	return r.PreconditionRepo.List(ctx, id)
}
func (r adPreconditionRepo) ReplaceAll(ctx context.Context, id int, rows []store.ActionPrecondition) error {
	r.s.preconditionWrites++
	return r.PreconditionRepo.ReplaceAll(ctx, id, rows)
}

type adTargetsRepo struct {
	store.XDropTargetRepo
	s *adStore
}

func (s *adStore) XDropTargets() store.XDropTargetRepo {
	return adTargetsRepo{s.MockStore.XDropTargets(), s}
}
func (r adTargetsRepo) List(ctx context.Context, id int) ([]store.XDropConnector, error) {
	if r.s.targetsUnknown {
		return nil, errors.New("fixture targets unavailable")
	}
	return r.XDropTargetRepo.List(ctx, id)
}

type adNodesRepo struct{ store.NodeRepo }

func (s *adStore) Nodes() store.NodeRepo { return adNodesRepo{s.MockStore.Nodes()} }
func (r adNodesRepo) Get(_ context.Context, id string) (*store.Node, error) {
	return &store.Node{ID: id, Mode: "flow"}, nil
}

type adListenersRepo struct{ store.FlowListenerRepo }

func (s *adStore) FlowListeners() store.FlowListenerRepo {
	return adListenersRepo{s.MockStore.FlowListeners()}
}
func (r adListenersRepo) Create(context.Context, *store.FlowListener) (int, error) { return 40, nil }
func (r adListenersRepo) Get(_ context.Context, id int) (*store.FlowListener, error) {
	return &store.FlowListener{ID: id, NodeID: "n1"}, nil
}

type adSourcesRepo struct{ store.FlowSourceRepo }

func (s *adStore) FlowSources() store.FlowSourceRepo                           { return adSourcesRepo{s.MockStore.FlowSources()} }
func (r adSourcesRepo) Create(context.Context, *store.FlowSource) (int, error) { return 41, nil }

func adRequest(t *testing.T, s *adStore, method, path, body string, status int) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := api.NewRouter(api.Dependencies{Store: s, JWTSecret: testJWTSecret, ConfigPub: configpub.New(s, nil, func() []string { return nil })})
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != status {
		t.Errorf("HTTP %s %s status=%d want=%d body=%s", method, path, w.Code, status, w.Body)
	}
	return w
}
func adID(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	var row struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &row); err != nil || row.ID == 0 {
		t.Fatalf("nonzero response id: body=%s err=%v", w.Body, err)
	}
	return row.ID
}
func adDiff(t *testing.T, s *adStore) map[string]json.RawMessage {
	t.Helper()
	if len(s.audits) != 1 {
		t.Fatalf("audit count=%d want=1", len(s.audits))
	}
	raw := s.audits[0].Diff
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
func adObject(t *testing.T, d map[string]json.RawMessage, side string) map[string]json.RawMessage {
	t.Helper()
	var row map[string]json.RawMessage
	if err := json.Unmarshal(d[side], &row); err != nil || row == nil {
		t.Fatalf("%s must be object: %s err=%v", side, d[side], err)
	}
	return row
}
func adJSON(t *testing.T, label string, raw json.RawMessage, want any) {
	t.Helper()
	var got any
	if len(raw) == 0 {
		t.Errorf("%s missing; want=%v", label, want)
		return
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%s invalid JSON: %v", label, err)
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
func adField(t *testing.T, d map[string]json.RawMessage, side, key string, want any) {
	t.Helper()
	adJSON(t, side+"."+key, adObject(t, d, side)[key], want)
}
func adAbsent(t *testing.T, d map[string]json.RawMessage, side, key string) {
	t.Helper()
	if raw, ok := adObject(t, d, side)[key]; ok {
		t.Errorf("%s.%s must be absent; got=%s", side, key, raw)
	}
}
func adSeedAction(t *testing.T, s *adStore, kind string, paired bool) int {
	t.Helper()
	a := store.ResponseAction{ResponseID: 1, ActionType: kind, Enabled: true, TriggerPhase: "on_detected", RunMode: "once", Execution: "automatic", Config: json.RawMessage(`{}`)}
	switch kind {
	case "bgp":
		a.BGPConnectorID = intPtr(1)
		a.BGPRouteMap = "BLACKHOLE"
	case "webhook":
		a.WebhookConnectorID = intPtr(1)
	case "shell":
		a.ShellConnectorID = intPtr(1)
	case "xdrop":
		a.XDropAction = "filter_l4"
		a.XDropCustomPayload = json.RawMessage(`{"dst_ip":"192.0.2.1"}`)
	}
	if paired {
		child := a
		child.TriggerPhase = "on_expired"
		child.AutoGenerated = true
		child.XDropAction = "unblock"
		id, err := s.responses.CreateAction(context.Background(), &child)
		if err != nil {
			t.Fatal(err)
		}
		a.PairedWith = &id
	}
	id, err := s.responses.CreateAction(context.Background(), &a)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func adSeedTargets(t *testing.T, s *adStore, id int) {
	t.Helper()
	for i := 1; i <= 4; i++ {
		got, err := s.XDropConnectors().Create(context.Background(), &store.XDropConnector{Name: fmt.Sprint(i), Enabled: true})
		if err != nil || got != i {
			t.Fatalf("target fixture id=%d want=%d err=%v", got, i, err)
		}
	}
	if err := s.MockStore.XDropTargets().Set(context.Background(), id, []int{3}); err != nil {
		t.Fatal(err)
	}
}

func TestAD_A1_Response(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		enabled                  bool
	}{
		{"CreateDefault_FixRed", "POST", "/api/responses", `{"name":"new"}`, true},
		{"CreateFalse_Guard", "POST", "/api/responses", `{"name":"new","enabled":false}`, false},
		{"UpdateFalseToTrue_FixRed", "PUT", "/api/responses/1", `{"enabled":true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := adFixture()
			status := 200
			if tc.method == "POST" {
				status = 201
			}
			w := adRequest(t, s, tc.method, tc.path, tc.body, status)
			d := adDiff(t, s)
			id := 1
			if tc.method == "POST" {
				id = adID(t, w)
				adJSON(t, "old", d["old"], nil)
			} else {
				adField(t, d, "old", "enabled", false)
			}
			row, err := s.Responses().Get(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if row.Enabled != tc.enabled {
				t.Errorf("stored enabled=%v want=%v", row.Enabled, tc.enabled)
			}
			adField(t, d, "new", "enabled", row.Enabled)
		})
	}
}
func TestAD_A2_Template(t *testing.T) {
	t.Run("CreateResponseID_FixRed", func(t *testing.T) {
		s := adFixture()
		id := adID(t, adRequest(t, s, "POST", "/api/threshold-templates", `{"name":"new","response_id":1}`, 201))
		d := adDiff(t, s)
		adJSON(t, "old", d["old"], nil)
		adField(t, d, "new", "response_id", 1)
		if row := s.templates[id]; row.ResponseID == nil || *row.ResponseID != 1 {
			t.Errorf("stored response_id=%v want=1", row.ResponseID)
		}
	})
	t.Run("DuplicateDetails_FixRed", func(t *testing.T) {
		s := adFixture()
		s.templates[7] = store.ThresholdTemplate{ID: 7, Name: "source", Description: "source description", ResponseID: intPtr(1)}
		id := adID(t, adRequest(t, s, "POST", "/api/threshold-templates/7/duplicate", `{"name":"copy"}`, 201))
		d := adDiff(t, s)
		adJSON(t, "old", d["old"], nil)
		adField(t, d, "new", "id", id)
		adField(t, d, "new", "name", "copy")
		adField(t, d, "new", "description", "source description")
		adField(t, d, "new", "response_id", 1)
		adField(t, d, "new", "duplicated_from", 7)
		row := s.templates[id]
		if row.Description != "source description" || row.ResponseID == nil || *row.ResponseID != 1 {
			t.Errorf("stored duplicate=%+v", row)
		}
	})
}
func TestAD_A3_CreateAction(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		targets    []int
		webhook    bool
	}{
		{"XDropTargetsAndPair_FixRed", `{"action_type":"xdrop","trigger_phase":"on_detected","run_mode":"once","execution":"automatic","xdrop_action":"filter_l4","xdrop_custom_payload":{"dst_ip":"192.0.2.1"},"target_node_ids":[3]}`, []int{3}, false},
		{"XDropEmptyTargets_FixRed", `{"action_type":"xdrop","trigger_phase":"on_detected","run_mode":"once","execution":"automatic","xdrop_action":"filter_l4","xdrop_custom_payload":{"dst_ip":"192.0.2.1"}}`, []int{}, false},
		{"WebhookShape_Guard", `{"action_type":"webhook","trigger_phase":"on_detected","run_mode":"once","execution":"automatic","connector_id":1}`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := adFixture()
			id := adID(t, adRequest(t, s, "POST", "/api/responses/1/actions", tc.body, 201))
			d := adDiff(t, s)
			adJSON(t, "old", d["old"], nil)
			adField(t, d, "new", "id", id)
			if s.audits[0].EntityType != "response_action" {
				t.Errorf("entity_type=%s", s.audits[0].EntityType)
			}
			if tc.webhook {
				adAbsent(t, d, "new", "target_node_ids")
				adAbsent(t, d, "new", "paired_with")
			} else {
				adField(t, d, "new", "target_node_ids", tc.targets)
				row, err := s.Responses().GetAction(context.Background(), id)
				if err != nil || row.PairedWith == nil || *row.PairedWith == 0 {
					t.Fatalf("stored pairing=%+v err=%v", row, err)
				}
				child, err := s.Responses().GetAction(context.Background(), *row.PairedWith)
				if err != nil || !child.AutoGenerated || child.TriggerPhase != "on_expired" {
					t.Fatalf("paired child=%+v err=%v", child, err)
				}
				adField(t, d, "new", "paired_with", child.ID)
			}
		})
	}
}
func TestAD_A4_UpdateAction(t *testing.T) {
	for _, kind := range []string{"bgp", "webhook", "shell"} {
		t.Run(kind+"Connector_FixRed", func(t *testing.T) {
			s := adFixture()
			id := adSeedAction(t, s, kind, false)
			adRequest(t, s, "PUT", fmt.Sprintf("/api/actions/%d", id), `{"connector_id":2}`, 200)
			d := adDiff(t, s)
			adField(t, d, "old", kind+"_connector_id", 1)
			adField(t, d, "new", kind+"_connector_id", 2)
		})
	}
	t.Run("Payload_FixRed", func(t *testing.T) {
		s := adFixture()
		id := adSeedAction(t, s, "xdrop", false)
		adRequest(t, s, "PUT", fmt.Sprintf("/api/actions/%d", id), `{"xdrop_custom_payload":{"dst_ip":"192.0.2.2"}}`, 200)
		d := adDiff(t, s)
		adField(t, d, "old", "xdrop_custom_payload", map[string]string{"dst_ip": "192.0.2.1"})
		adField(t, d, "new", "xdrop_custom_payload", map[string]string{"dst_ip": "192.0.2.2"})
	})
	for _, unknown := range []bool{false, true} {
		name := "Targets_FixRed"
		if unknown {
			name = "UnknownTargets_FixRed"
		}
		t.Run(name, func(t *testing.T) {
			s := adFixture()
			id := adSeedAction(t, s, "xdrop", false)
			adSeedTargets(t, s, id)
			s.targetsUnknown = unknown
			adRequest(t, s, "PUT", fmt.Sprintf("/api/actions/%d", id), `{"target_node_ids":[4]}`, 200)
			d := adDiff(t, s)
			if unknown {
				adAbsent(t, d, "old", "target_node_ids")
			} else {
				adField(t, d, "old", "target_node_ids", []int{3})
			}
			adField(t, d, "new", "target_node_ids", []int{4})
		})
	}
	t.Run("PairedOneAudit_Guard", func(t *testing.T) {
		s := adFixture()
		id := adSeedAction(t, s, "xdrop", true)
		before, err := s.Responses().GetAction(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		pair := *before.PairedWith
		adRequest(t, s, "PUT", fmt.Sprintf("/api/actions/%d", id), `{"priority":7}`, 200)
		d := adDiff(t, s)
		adField(t, d, "old", "paired_with", pair)
		adField(t, d, "new", "paired_with", pair)
	})
}
func TestAD_A5_Preconditions(t *testing.T) {
	for _, existing := range []bool{true, false} {
		name := "ExistingTwo_FixRed"
		if !existing {
			name = "EmptyArray_FixRed"
		}
		t.Run(name, func(t *testing.T) {
			s := adFixture()
			id := adSeedAction(t, s, "webhook", false)
			old := []store.ActionPrecondition{}
			if existing {
				rows := []store.ActionPrecondition{{Attribute: "pps", Operator: "gt", Value: "100"}, {Attribute: "decoder", Operator: "eq", Value: "udp"}}
				if err := s.MockStore.Preconditions().ReplaceAll(context.Background(), id, rows); err != nil {
					t.Fatal(err)
				}
				var err error
				old, err = s.MockStore.Preconditions().List(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
			}
			adRequest(t, s, "PUT", fmt.Sprintf("/api/actions/%d/preconditions", id), `{"preconditions":[{"attribute":"bps","operator":"gte","value":"200"}]}`, 200)
			d := adDiff(t, s)
			adJSON(t, "old preconditions", d["old"], old)
			adJSON(t, "new preconditions", d["new"], []store.ActionPrecondition{{Attribute: "bps", Operator: "gte", Value: "200"}})
			if s.preconditionLists != 1 || s.preconditionWrites != 1 {
				t.Errorf("preconditions List=%d ReplaceAll=%d want=1,1", s.preconditionLists, s.preconditionWrites)
			}
		})
	}
	t.Run("ListFailure_FixRed", func(t *testing.T) {
		s := adFixture()
		s.preconditionErr = errors.New("fixture list failed")
		adRequest(t, s, "PUT", "/api/actions/1/preconditions", `{"preconditions":[{"attribute":"pps","operator":"gt","value":"1"}]}`, 500)
		if s.preconditionLists != 1 || s.preconditionWrites != 0 || len(s.audits) != 0 {
			t.Errorf("List failure: List=%d ReplaceAll=%d audits=%d want=1,0,0", s.preconditionLists, s.preconditionWrites, len(s.audits))
		}
	})
	t.Run("ValidationBeforeList_Guard", func(t *testing.T) {
		s := adFixture()
		adRequest(t, s, "PUT", "/api/actions/1/preconditions", `{"preconditions":[{"attribute":"invalid","operator":"gt","value":"1"}]}`, 400)
		if s.preconditionLists != 0 || s.preconditionWrites != 0 || len(s.audits) != 0 {
			t.Errorf("invalid request: List=%d ReplaceAll=%d audits=%d want=0,0,0", s.preconditionLists, s.preconditionWrites, len(s.audits))
		}
	})
}
func TestAD_A6_ResponseID(t *testing.T) {
	for _, kind := range []string{"Template", "Threshold"} {
		for _, clear := range []bool{false, true} {
			name := kind + "ToFive_FixRed"
			body := `{"response_id":5}`
			var want any = 5
			if clear {
				name = kind + "ToNull_Guard"
				body = `{"response_id":null}`
				want = nil
			}
			t.Run(name, func(t *testing.T) {
				s := adFixture()
				path := "/api/threshold-templates/7"
				s.templates[7] = store.ThresholdTemplate{ID: 7, Name: "old", ResponseID: intPtr(1)}
				if kind == "Threshold" {
					path = "/api/thresholds/7"
					s.thresholds[7] = store.Threshold{ID: 7, TemplateID: intPtr(9), ResponseID: intPtr(1), Domain: "subnet", Direction: "receives", Unit: "pps", Comparison: "over", Value: 100, Enabled: true}
				}
				adRequest(t, s, "PUT", path, body, 200)
				d := adDiff(t, s)
				adField(t, d, "old", "response_id", 1)
				adField(t, d, "new", "response_id", want)
				stored := s.templates[7].ResponseID
				if kind == "Threshold" {
					stored = s.thresholds[7].ResponseID
				}
				if clear {
					if stored != nil {
						t.Errorf("stored response_id=%v want=nil", *stored)
					}
				} else if stored == nil || *stored != 5 {
					t.Errorf("stored response_id=%v want=5", stored)
				}
			})
		}
	}
}
func TestAD_A7_FlowID(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"Listener_FixRed", "/api/flow-listeners", `{"node_id":"n1","listen_address":":6343","protocol_mode":"sflow"}`},
		{"Source_FixRed", "/api/flow-sources", `{"listener_id":40,"name":"source","device_ip":"192.0.2.1","sample_mode":"none"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := adFixture()
			id := adID(t, adRequest(t, s, "POST", tc.path, tc.body, 201))
			d := adDiff(t, s)
			adJSON(t, "old", d["old"], nil)
			adField(t, d, "new", "id", id)
		})
	}
}
func TestAD_A8_Masking(t *testing.T) {
	t.Run("WebhookHeaders_Guard", func(t *testing.T) {
		s := adFixture()
		id := adSeedAction(t, s, "webhook", false)
		a, err := s.Responses().GetAction(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		const secret = "ad-fixture-bearer-secret"
		a.Config = json.RawMessage(`{"headers":{"Authorization":"Bearer ` + secret + `"}}`)
		if err := s.Responses().UpdateAction(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		adRequest(t, s, "PUT", fmt.Sprintf("/api/actions/%d", id), `{"priority":9}`, 200)
		d := adDiff(t, s)
		adField(t, d, "old", "config", map[string]any{"headers": map[string]string{"Authorization": "******"}})
		adField(t, d, "new", "config", map[string]any{})
		raw := string(s.audits[0].Diff)
		if strings.Contains(raw, secret) || !strings.Contains(raw, "******") {
			t.Errorf("masked diff=%s", raw)
		}
		if s.audits[0].EntityType != "response_action" {
			t.Errorf("entity_type=%s", s.audits[0].EntityType)
		}
	})
}
