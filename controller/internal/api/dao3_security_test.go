package api

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/d80y6/YemenDDoS/controller/internal/configpub"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// Each repository operation locks, and reads return independent snapshots.
type dao3Store struct {
	store.Store
	mu         sync.Mutex
	actions    []store.ResponseAction
	webhooks   []store.Webhook
	connectors []store.WebhookConnector
	xdrops     []store.XDropConnector
	prefixes   []store.WatchPrefix
	audits     []store.AuditLog
	logs       []store.ActionExecutionLog
}

func dao3Copy[T any](v T) T {
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(v); err != nil {
		panic(err)
	}
	var c T
	if err := gob.NewDecoder(&b).Decode(&c); err != nil {
		panic(err)
	}
	return c
}

type dao3Responses struct {
	store.ResponseRepo
	s *dao3Store
}

func (s *dao3Store) Responses() store.ResponseRepo { return dao3Responses{s: s} }
func (r dao3Responses) Get(context.Context, int) (*store.Response, error) {
	return &store.Response{ID: 1, Name: "test"}, nil
}
func (r dao3Responses) ListActions(context.Context, int) ([]store.ResponseAction, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return dao3Copy(r.s.actions), nil
}
func (r dao3Responses) GetAction(_ context.Context, id int) (*store.ResponseAction, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, a := range r.s.actions {
		if a.ID == id {
			c := dao3Copy(a)
			return &c, nil
		}
	}
	return nil, fmt.Errorf("missing")
}
func (r dao3Responses) CreateAction(_ context.Context, a *store.ResponseAction) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c := dao3Copy(*a)
	c.ID = len(r.s.actions) + 1
	r.s.actions = append(r.s.actions, c)
	return c.ID, nil
}
func (r dao3Responses) UpdateAction(_ context.Context, a *store.ResponseAction) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.actions {
		if r.s.actions[i].ID == a.ID {
			r.s.actions[i] = dao3Copy(*a)
			return nil
		}
	}
	return fmt.Errorf("missing")
}
func (r dao3Responses) DeleteAction(_ context.Context, id int) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.actions {
		if r.s.actions[i].ID == id {
			r.s.actions = append(r.s.actions[:i], r.s.actions[i+1:]...)
			break
		}
	}
	return nil
}
func (r dao3Responses) SetPairedWith(_ context.Context, id int, p *int) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.actions {
		if r.s.actions[i].ID == id {
			r.s.actions[i].PairedWith = dao3Copy(p)
		}
	}
	return nil
}
func (r dao3Responses) CountActionsByWebhookConnector(context.Context, int) (int, error) {
	return 0, nil
}

type dao3Targets struct{ store.XDropTargetRepo }

func (s *dao3Store) XDropTargets() store.XDropTargetRepo  { return dao3Targets{} }
func (dao3Targets) Set(context.Context, int, []int) error { return nil }

type dao3Nodes struct{ store.NodeRepo }

func (s *dao3Store) Nodes() store.NodeRepo                   { return dao3Nodes{} }
func (dao3Nodes) List(context.Context) ([]store.Node, error) { return nil, nil }

type dao3Thresholds struct{ store.ThresholdRepo }

func (s *dao3Store) Thresholds() store.ThresholdRepo                   { return dao3Thresholds{} }
func (dao3Thresholds) List(context.Context) ([]store.Threshold, error) { return nil, nil }

type dao3Audit struct {
	store.AuditLogRepo
	s *dao3Store
}

func (s *dao3Store) AuditLog() store.AuditLogRepo { return dao3Audit{s: s} }
func (r dao3Audit) Create(_ context.Context, a *store.AuditLog) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.audits = append(r.s.audits, dao3Copy(*a))
	return nil
}
func (r dao3Audit) List(context.Context, store.AuditFilter) ([]store.AuditLog, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return dao3Copy(r.s.audits), nil
}

type dao3Attacks struct{ store.AttackRepo }

func (s *dao3Store) Attacks() store.AttackRepo { return dao3Attacks{} }
func (dao3Attacks) Get(context.Context, int) (*store.Attack, error) {
	now := time.Now()
	return &store.Attack{ID: 1, EndedAt: &now}, nil
}

type dao3Logs struct {
	store.ActionExecLogRepo
	s *dao3Store
}

func (s *dao3Store) ActionExecLog() store.ActionExecLogRepo { return dao3Logs{s: s} }
func (r dao3Logs) ListByAttack(context.Context, int) ([]store.ActionExecutionLog, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return dao3Copy(r.s.logs), nil
}

type dao3Announcements struct{ store.BGPAnnouncementRepo }

func (s *dao3Store) BGPAnnouncements() store.BGPAnnouncementRepo { return dao3Announcements{} }
func (dao3Announcements) ListAttachmentsForAttack(context.Context, int) ([]store.BGPAnnouncementAttack, error) {
	return nil, nil
}

type dao3Rules struct{ store.XDropActiveRuleRepo }

func (s *dao3Store) XDropActiveRules() store.XDropActiveRuleRepo                     { return dao3Rules{} }
func (dao3Rules) ListByAttack(context.Context, int) ([]store.XDropActiveRule, error) { return nil, nil }

func dao3Call(t *testing.T, s *dao3Store, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-API-Key", "test")
	w := httptest.NewRecorder()
	deps := Dependencies{Store: s, APIKey: "test", ConfigPub: configpub.New(s, nil, func() []string { return nil })}
	NewRouter(deps).ServeHTTP(w, r)
	return w
}
func dao3Status(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
}
func dao3Secret(t *testing.T, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	for _, secret := range []string{"t0ken", "s3cret", `t0\"ken`} {
		if strings.Contains(string(b), secret) {
			t.Errorf("secret %q escaped: %s", secret, b)
		}
	}
}
func dao3BGPBody(rm string) map[string]any {
	return map[string]any{"action_type": "bgp", "trigger_phase": "on_detected", "run_mode": "once", "connector_id": 7, "bgp_route_map": rm}
}
func dao3CreateRouteMap(t *testing.T, rm string, want int) {
	t.Helper()
	s := &dao3Store{}
	w := dao3Call(t, s, "POST", "/api/responses/1/actions", dao3BGPBody(rm))
	dao3Status(t, w, want)
	rows, _ := s.Responses().ListActions(context.Background(), 1)
	if want == 400 && len(rows) != 0 {
		t.Fatalf("rejected request wrote %d rows", len(rows))
	}
	if want == 201 && len(rows) != 2 {
		t.Fatalf("parent/pair rows=%d", len(rows))
	}
}
func TestDao3_T1a_CreateInjection(t *testing.T) {
	dao3CreateRouteMap(t, "RTBH\nno router bgp 64496", 400)
}
func TestDao3_T1b_CreateInvalidNames(t *testing.T) {
	for _, tc := range []struct{ name, value string }{{"semicolon", "RTBH;x"}, {"space", "RT BH"}, {"tab", "RTBH\t"}, {"empty", ""}} {
		t.Run(tc.name, func(t *testing.T) { dao3CreateRouteMap(t, tc.value, 400) })
	}
}
func TestDao3_T1c_CreateValidName(t *testing.T) { dao3CreateRouteMap(t, "RTBH-v4.blackhole_1", 201) }
func TestDao3_T1d_UpdateInjection(t *testing.T) {
	cid := 7
	a := store.ResponseAction{ID: 1, ResponseID: 1, ActionType: "bgp", TriggerPhase: "on_detected", RunMode: "once", BGPConnectorID: &cid, BGPRouteMap: "RTBH"}
	s := &dao3Store{actions: []store.ResponseAction{a}}
	w := dao3Call(t, s, "PUT", "/api/actions/1", map[string]any{"bgp_route_map": "RTBH\nno router bgp 64496"})
	dao3Status(t, w, 400)
	got, _ := s.Responses().GetAction(context.Background(), 1)
	if !reflect.DeepEqual(*got, a) {
		t.Fatal("stored action changed")
	}
}

func dao3XDrop(t *testing.T, url, key string, want int) {
	t.Helper()
	old := store.XDropConnector{ID: 1, APIURL: "https://old.example/api", APIKey: "old-key"}
	s := &dao3Store{xdrops: []store.XDropConnector{old}}
	w := dao3Call(t, s, "PUT", "/api/settings/xdrop-connectors/1", map[string]any{"api_url": url, "api_key": key})
	dao3Status(t, w, want)
	got, _ := s.XDropConnectors().Get(context.Background(), 1)
	if want == 400 {
		if !reflect.DeepEqual(*got, old) {
			t.Fatal("rejected request changed URL/key")
		}
	} else {
		if key == "" {
			key = old.APIKey
		}
		if got.APIURL != strings.TrimRight(url, "/") || got.APIKey != key {
			t.Fatalf("stored=%+v", got)
		}
	}
}
func TestDao3_T2a_URLRequiresKey(t *testing.T) { dao3XDrop(t, "https://new.example/api", "", 400) }
func TestDao3_T2b_URLWithNewKey(t *testing.T) {
	dao3XDrop(t, "https://new.example/api", "new-key", 200)
}
func TestDao3_T2c_SameURLKeepsKey(t *testing.T) { dao3XDrop(t, "https://old.example/api/", "", 200) }

const dao3Headers = `{"Authorization":"Bearer t0ken"}`

func dao3WebhookStore() *dao3Store {
	return &dao3Store{connectors: []store.WebhookConnector{{ID: 1, Name: "test", URL: "https://hooks.example/hook", Method: "POST", Headers: json.RawMessage(dao3Headers), Enabled: true}}, webhooks: []store.Webhook{{ID: 1, URL: "https://hooks.example/hook", Headers: json.RawMessage(dao3Headers)}}}
}
func TestDao3_T4a_ReadConnector(t *testing.T) {
	for _, suffix := range []string{"", "/1"} {
		t.Run(map[bool]string{true: "list", false: "get"}[suffix == ""], func(t *testing.T) {
			s := dao3WebhookStore()
			w := dao3Call(t, s, "GET", "/api/settings/webhook-connectors"+suffix, nil)
			dao3Status(t, w, 200)
			dao3Secret(t, w.Body.String())
			if !strings.Contains(w.Body.String(), "******") {
				t.Error("mask absent")
			}
			got, _ := s.WebhookConnectors().Get(context.Background(), 1)
			if string(got.Headers) != dao3Headers {
				t.Error("read modified storage")
			}
		})
	}
}
func dao3AuditCRUD(t *testing.T, legacy bool) {
	t.Helper()
	base := "/api/settings/webhook-connectors"
	if legacy {
		base = "/api/webhooks"
	}
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			s := dao3WebhookStore()
			var before []store.Webhook
			if legacy {
				before, _ = s.Webhooks().List(context.Background())
			}
			path := base
			if method != "POST" {
				path += "/1"
			}
			body := map[string]any{"name": "test", "url": "https://hooks.example/hook", "headers": map[string]string{"Authorization": "Bearer t0ken"}}
			w := dao3Call(t, s, method, path, body)
			if legacy {
				dao3Status(t, w, 410)
				rows, _ := s.AuditLog().List(context.Background(), store.AuditFilter{})
				after, _ := s.Webhooks().List(context.Background())
				if len(rows) != 0 || !reflect.DeepEqual(before, after) {
					t.Fatalf("retired write changed storage or audit: rows=%+v", rows)
				}
				return
			}
			want := 200
			if method == "POST" {
				want = 201
			}
			dao3Status(t, w, want)
			rows, _ := s.AuditLog().List(context.Background(), store.AuditFilter{})
			if len(rows) != 1 {
				t.Fatalf("actual AuditLog.Create calls=%d", len(rows))
			}
			dao3Secret(t, rows)
			if !strings.Contains(string(rows[0].Diff), "******") {
				t.Error("audit mask absent")
			}
		})
	}
}
func TestDao3_T4b_ConnectorAuditWrites(t *testing.T) { dao3AuditCRUD(t, false) }
func dao3MaskedPut(t *testing.T, url, key string, want int) {
	t.Helper()
	s := dao3WebhookStore()
	old, _ := s.WebhookConnectors().Get(context.Background(), 1)
	w := dao3Call(t, s, "PUT", "/api/settings/webhook-connectors/1", map[string]any{"name": "test", "url": url, "headers": map[string]string{key: "******"}})
	dao3Status(t, w, want)
	got, _ := s.WebhookConnectors().Get(context.Background(), 1)
	if want == 400 {
		if !reflect.DeepEqual(old, got) {
			t.Error("rejected request changed storage")
		}
	} else {
		var h map[string]string
		_ = json.Unmarshal(got.Headers, &h)
		if h["Authorization"] != "Bearer t0ken" {
			t.Fatalf("stored headers=%s", got.Headers)
		}
	}
}
func TestDao3_T4c_MaskKeepsOriginal(t *testing.T) {
	dao3MaskedPut(t, "https://hooks.example/hook", "Authorization", 200)
}
func TestDao3_T4d_MaskRejectsURLChange(t *testing.T) {
	dao3MaskedPut(t, "https://other.example/hook", "Authorization", 400)
}
func TestDao3_T4e_MaskRequiresOriginal(t *testing.T) {
	dao3MaskedPut(t, "https://hooks.example/hook", "Missing", 400)
}
func TestDao3_T4f_LegacyWebhook(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		w := dao3Call(t, dao3WebhookStore(), "GET", "/api/webhooks", nil)
		dao3Status(t, w, 200)
		dao3Secret(t, w.Body.String())
		if !strings.Contains(w.Body.String(), "******") {
			t.Error("mask absent")
		}
	})
	t.Run("audit", func(t *testing.T) { dao3AuditCRUD(t, true) })
}
func TestDao3_T4g_DirtyHeaders(t *testing.T) {
	s := dao3WebhookStore()
	s.connectors[0].Headers = json.RawMessage(`"Bearer t0ken"`)
	w := dao3Call(t, s, "GET", "/api/settings/webhook-connectors/1", nil)
	dao3Status(t, w, 200)
	dao3Secret(t, w.Body.String())
	if !strings.Contains(w.Body.String(), `"headers":null`) {
		t.Error("dirty headers must be null")
	}
}
func TestDao3_T4i_HistoricalAudit(t *testing.T) {
	for _, headerKey := range []string{"headers", "Headers", "HEADERS"} {
		for _, entity := range []string{"webhook_connector", "webhook", "response_action"} {
			name := entity
			if headerKey != "headers" {
				name = headerKey + "/" + name
			}
			t.Run(name, func(t *testing.T) {
				obj := map[string]any{headerKey: map[string]string{"Authorization": "Bearer t0ken"}}
				if entity == "response_action" {
					obj = map[string]any{"config": obj}
				}
				raw := makeDiff(obj, obj)
				s := &dao3Store{audits: []store.AuditLog{{EntityType: entity, Diff: raw}}}
				w := dao3Call(t, s, "GET", "/api/audit-log", nil)
				dao3Status(t, w, 200)
				dao3Secret(t, w.Body.String())
				if !strings.Contains(w.Body.String(), "******") {
					t.Error("mask absent")
				}
				rows, _ := s.AuditLog().List(context.Background(), store.AuditFilter{})
				if string(rows[0].Diff) != string(raw) {
					t.Error("historical storage modified")
				}
			})
		}
	}
}
func TestDao3_T4j_LegacyActionHeaders(t *testing.T) {
	for _, headerKey := range []string{"headers", "Headers", "HEADERS"} {
		for _, mode := range []string{"list", "get", "delete"} {
			name := mode
			if headerKey != "headers" {
				name = headerKey + "/" + name
			}
			t.Run(name, func(t *testing.T) {
				a := store.ResponseAction{ID: 1, ResponseID: 1, ActionType: "webhook", Config: json.RawMessage(fmt.Sprintf(`{"%s":{"Authorization":"Bearer t0ken"}}`, headerKey))}
				s := &dao3Store{actions: []store.ResponseAction{a}}
				path, method := "/api/responses/1/actions", "GET"
				if mode == "get" {
					path = "/api/responses/1"
				}
				if mode == "delete" {
					path = "/api/actions/1"
					method = "DELETE"
				}
				w := dao3Call(t, s, method, path, nil)
				dao3Status(t, w, 200)
				dao3Secret(t, w.Body.String())
				if mode == "delete" {
					rows, _ := s.AuditLog().List(context.Background(), store.AuditFilter{})
					if len(rows) != 1 {
						t.Fatalf("audit writes=%d", len(rows))
					}
					dao3Secret(t, rows)
				} else {
					if !strings.Contains(w.Body.String(), "******") {
						t.Error("mask absent")
					}
					got, _ := s.Responses().GetAction(context.Background(), 1)
					if string(got.Config) != string(a.Config) {
						t.Error("read modified action")
					}
				}
			})
		}
	}
}
func TestDao3_T4k_ExactURL(t *testing.T) {
	for _, url := range []string{"https://hooks.example/hook?tenant=a", "https://hooks.example/hook"} {
		t.Run(url, func(t *testing.T) {
			s := dao3WebhookStore()
			s.connectors[0].URL = url
			w := dao3Call(t, s, "PUT", "/api/settings/webhook-connectors/1", map[string]any{"url": url + "/", "headers": map[string]string{"Authorization": "******"}})
			dao3Status(t, w, 400)
			got, _ := s.WebhookConnectors().Get(context.Background(), 1)
			if got.URL != url || string(got.Headers) != dao3Headers {
				t.Error("rejected request wrote storage")
			}
		})
	}
}
func TestDao3_T4m_HistoricalExecutionErrors(t *testing.T) {
	for _, endpoint := range []string{"action-log", "mitigation-summary", "detail"} {
		t.Run(endpoint, func(t *testing.T) {
			logs := []store.ActionExecutionLog{{ID: 1, ActionType: "webhook", Status: "failed", ErrorMessage: "HTTP 400: Bearer t0ken"}, {ID: 2, ActionType: "webhook", Status: "failed", ErrorMessage: `Post "https://hooks.example/?token=s3cret": dial tcp refused`}, {ID: 3, ActionType: "webhook", Status: "success"}}
			s := &dao3Store{logs: dao3Copy(logs)}
			path := "/api/attacks/1"
			if endpoint != "detail" {
				path += "/" + endpoint
			}
			w := dao3Call(t, s, "GET", path, nil)
			dao3Status(t, w, 200)
			dao3Secret(t, w.Body.String())
			var root any
			_ = json.Unmarshal(w.Body.Bytes(), &root)
			var errors []string
			var walk func(any)
			walk = func(v any) {
				switch x := v.(type) {
				case map[string]any:
					if x["action_type"] == "webhook" {
						msg, _ := x["error_message"].(string)
						errors = append(errors, msg)
					}
					for _, child := range x {
						walk(child)
					}
				case []any:
					for _, child := range x {
						walk(child)
					}
				}
			}
			walk(root)
			if !reflect.DeepEqual(errors, []string{"HTTP 400", "webhook error (details redacted)", ""}) {
				t.Fatalf("error messages=%q", errors)
			}
			got, _ := s.ActionExecLog().ListByAttack(context.Background(), 1)
			if !reflect.DeepEqual(got, logs) {
				t.Error("historical rows changed")
			}
		})
	}
}

func TestDao3_T5a_IPv6DefaultCreate(t *testing.T) {
	for _, prefix := range []string{"0::/0", "::/0", "0:0::/0", "::0/0"} {
		t.Run(prefix, func(t *testing.T) {
			s := &dao3Store{}
			w := dao3Call(t, s, "POST", "/api/prefixes", map[string]any{"prefix": prefix})
			dao3Status(t, w, 400)
			rows, _ := s.Prefixes().List(context.Background())
			if len(rows) != 0 {
				t.Error("rejected prefix persisted")
			}
		})
	}
}
func TestDao3_T5b_AllowedPrefixes(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/0", "2001:db8::/32"} {
		t.Run(prefix, func(t *testing.T) {
			s := &dao3Store{}
			w := dao3Call(t, s, "POST", "/api/prefixes", map[string]any{"prefix": prefix})
			dao3Status(t, w, 201)
			rows, _ := s.Prefixes().List(context.Background())
			if len(rows) != 1 || rows[0].Prefix != prefix {
				t.Fatalf("prefixes=%+v", rows)
			}
		})
	}
}
func TestDao3_T5c_IPv6DefaultUpdate(t *testing.T) {
	old := store.WatchPrefix{ID: 1, Prefix: "2001:db8::/32"}
	s := &dao3Store{prefixes: []store.WatchPrefix{old}}
	w := dao3Call(t, s, "PUT", "/api/prefixes/1", map[string]any{"prefix": "0::/0"})
	dao3Status(t, w, 400)
	got, _ := s.Prefixes().Get(context.Background(), 1)
	if !reflect.DeepEqual(*got, old) {
		t.Error("rejected update persisted")
	}
}

type dao3Webhooks struct {
	store.WebhookRepo
	s *dao3Store
}

func (s *dao3Store) Webhooks() store.WebhookRepo { return dao3Webhooks{s: s} }
func (r dao3Webhooks) List(context.Context) ([]store.Webhook, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return dao3Copy(r.s.webhooks), nil
}
func (r dao3Webhooks) Get(_ context.Context, id int) (*store.Webhook, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, row := range r.s.webhooks {
		if row.ID == id {
			c := dao3Copy(row)
			return &c, nil
		}
	}
	return nil, fmt.Errorf("missing")
}
func (r dao3Webhooks) Create(_ context.Context, row *store.Webhook) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c := dao3Copy(*row)
	c.ID = len(r.s.webhooks) + 1
	r.s.webhooks = append(r.s.webhooks, c)
	return c.ID, nil
}
func (r dao3Webhooks) Update(_ context.Context, row *store.Webhook) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.webhooks {
		if r.s.webhooks[i].ID == row.ID {
			r.s.webhooks[i] = dao3Copy(*row)
			return nil
		}
	}
	return fmt.Errorf("missing")
}
func (r dao3Webhooks) Delete(_ context.Context, id int) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.webhooks {
		if r.s.webhooks[i].ID == id {
			r.s.webhooks = append(r.s.webhooks[:i], r.s.webhooks[i+1:]...)
			break
		}
	}
	return nil
}

type dao3WebhookConnectors struct {
	store.WebhookConnectorRepo
	s *dao3Store
}

func (s *dao3Store) WebhookConnectors() store.WebhookConnectorRepo {
	return dao3WebhookConnectors{s: s}
}
func (r dao3WebhookConnectors) List(context.Context) ([]store.WebhookConnector, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return dao3Copy(r.s.connectors), nil
}
func (r dao3WebhookConnectors) Get(_ context.Context, id int) (*store.WebhookConnector, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, row := range r.s.connectors {
		if row.ID == id {
			c := dao3Copy(row)
			return &c, nil
		}
	}
	return nil, fmt.Errorf("missing")
}
func (r dao3WebhookConnectors) Create(_ context.Context, row *store.WebhookConnector) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c := dao3Copy(*row)
	c.ID = len(r.s.connectors) + 1
	r.s.connectors = append(r.s.connectors, c)
	return c.ID, nil
}
func (r dao3WebhookConnectors) Update(_ context.Context, row *store.WebhookConnector) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.connectors {
		if r.s.connectors[i].ID == row.ID {
			r.s.connectors[i] = dao3Copy(*row)
			return nil
		}
	}
	return fmt.Errorf("missing")
}
func (r dao3WebhookConnectors) Delete(_ context.Context, id int) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.connectors {
		if r.s.connectors[i].ID == id {
			r.s.connectors = append(r.s.connectors[:i], r.s.connectors[i+1:]...)
			break
		}
	}
	return nil
}

type dao3XDropConnectors struct {
	store.XDropConnectorRepo
	s *dao3Store
}

func (s *dao3Store) XDropConnectors() store.XDropConnectorRepo { return dao3XDropConnectors{s: s} }
func (r dao3XDropConnectors) List(context.Context) ([]store.XDropConnector, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return append([]store.XDropConnector(nil), r.s.xdrops...), nil
}
func (r dao3XDropConnectors) Get(_ context.Context, id int) (*store.XDropConnector, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, row := range r.s.xdrops {
		if row.ID == id {
			c := row
			return &c, nil
		}
	}
	return nil, fmt.Errorf("missing")
}
func (r dao3XDropConnectors) Create(_ context.Context, row *store.XDropConnector) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c := *row
	c.ID = len(r.s.xdrops) + 1
	r.s.xdrops = append(r.s.xdrops, c)
	return c.ID, nil
}
func (r dao3XDropConnectors) Update(_ context.Context, row *store.XDropConnector) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.xdrops {
		if r.s.xdrops[i].ID == row.ID {
			r.s.xdrops[i] = *row
			return nil
		}
	}
	return fmt.Errorf("missing")
}
func (r dao3XDropConnectors) Delete(_ context.Context, id int) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.xdrops {
		if r.s.xdrops[i].ID == id {
			r.s.xdrops = append(r.s.xdrops[:i], r.s.xdrops[i+1:]...)
			break
		}
	}
	return nil
}

type dao3Prefixes struct {
	store.PrefixRepo
	s *dao3Store
}

func (s *dao3Store) Prefixes() store.PrefixRepo { return dao3Prefixes{s: s} }
func (r dao3Prefixes) List(context.Context) ([]store.WatchPrefix, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return dao3Copy(r.s.prefixes), nil
}
func (r dao3Prefixes) Get(_ context.Context, id int) (*store.WatchPrefix, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, row := range r.s.prefixes {
		if row.ID == id {
			c := dao3Copy(row)
			return &c, nil
		}
	}
	return nil, fmt.Errorf("missing")
}
func (r dao3Prefixes) Create(_ context.Context, row *store.WatchPrefix) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	c := dao3Copy(*row)
	c.ID = len(r.s.prefixes) + 1
	r.s.prefixes = append(r.s.prefixes, c)
	return c.ID, nil
}
func (r dao3Prefixes) Update(_ context.Context, row *store.WatchPrefix) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.prefixes {
		if r.s.prefixes[i].ID == row.ID {
			r.s.prefixes[i] = dao3Copy(*row)
			return nil
		}
	}
	return fmt.Errorf("missing")
}
func (r dao3Prefixes) Delete(_ context.Context, id int) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for i := range r.s.prefixes {
		if r.s.prefixes[i].ID == id {
			r.s.prefixes = append(r.s.prefixes[:i], r.s.prefixes[i+1:]...)
			break
		}
	}
	return nil
}
