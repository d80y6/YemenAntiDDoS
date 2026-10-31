package api

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/configpub"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Reads and snapshots are independent copies. Every implemented write counts
// calls even when the written row is identical, including audit and target writes.
type dao11cStore struct {
	store.Store
	mu         sync.Mutex
	writes     map[string]int
	actions    *dao11cRows[store.ResponseAction]
	thresholds *dao11cRows[store.Threshold]
	shells     *dao11cRows[store.ShellConnector]
	xdrops     *dao11cRows[store.XDropConnector]
	hooks      *dao11cRows[store.WebhookConnector]
	bgps       *dao11cRows[store.BGPConnector]
	prefixes   *dao11cRows[store.WatchPrefix]
	audits     []store.AuditLog
}

func dao11cCopy[T any](v T) T {
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(v); err != nil {
		panic(err)
	}
	var out T
	if err := gob.NewDecoder(&b).Decode(&out); err != nil {
		panic(err)
	}
	return out
}

type dao11cRows[T any] struct {
	s    *dao11cStore
	name string
	rows []T
}

func (r *dao11cRows[T]) List(context.Context) ([]T, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return dao11cCopy(r.rows), nil
}
func (r *dao11cRows[T]) Get(_ context.Context, id int) (*T, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for _, row := range r.rows {
		if int(reflect.ValueOf(row).FieldByName("ID").Int()) == id {
			v := dao11cCopy(row)
			return &v, nil
		}
	}
	return nil, fmt.Errorf("missing %s %d", r.name, id)
}
func (r *dao11cRows[T]) Create(_ context.Context, row *T) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.writes[r.name+".Create"]++
	v := dao11cCopy(*row)
	id := len(r.rows) + 1
	reflect.ValueOf(&v).Elem().FieldByName("ID").SetInt(int64(id))
	r.rows = append(r.rows, v)
	return id, nil
}
func (r *dao11cRows[T]) Update(_ context.Context, row *T) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.writes[r.name+".Update"]++
	id := reflect.ValueOf(*row).FieldByName("ID").Int()
	for i, v := range r.rows {
		if reflect.ValueOf(v).FieldByName("ID").Int() == id {
			r.rows[i] = dao11cCopy(*row)
			return nil
		}
	}
	return fmt.Errorf("missing %s %d", r.name, id)
}
func (r *dao11cRows[T]) Delete(_ context.Context, id int) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.writes[r.name+".Delete"]++
	for i, v := range r.rows {
		if int(reflect.ValueOf(v).FieldByName("ID").Int()) == id {
			r.rows = append(r.rows[:i], r.rows[i+1:]...)
			break
		}
	}
	return nil
}
func (r *dao11cRows[T]) Count(c context.Context) (int, error)               { v, e := r.List(c); return len(v), e }
func (r *dao11cRows[T]) ListByPrefix(c context.Context, _ int) ([]T, error) { return r.List(c) }
func (r *dao11cRows[T]) ListTree(c context.Context) ([]T, error)            { return r.List(c) }
func (r *dao11cRows[T]) ListEnabled(c context.Context) ([]T, error)         { return r.List(c) }
func (r *dao11cRows[T]) ListGlobal(c context.Context) ([]T, error)          { return r.List(c) }

func (s *dao11cStore) ShellConnectors() store.ShellConnectorRepo     { return s.shells }
func (s *dao11cStore) XDropConnectors() store.XDropConnectorRepo     { return s.xdrops }
func (s *dao11cStore) WebhookConnectors() store.WebhookConnectorRepo { return s.hooks }
func (s *dao11cStore) BGPConnectors() store.BGPConnectorRepo         { return s.bgps }
func (s *dao11cStore) Thresholds() store.ThresholdRepo               { return s.thresholds }
func (s *dao11cStore) Prefixes() store.PrefixRepo                    { return s.prefixes }
func (s *dao11cStore) count(name string)                             { s.mu.Lock(); defer s.mu.Unlock(); s.writes[name]++ }

type dao11cResponses struct {
	store.ResponseRepo
	s *dao11cStore
}

func (s *dao11cStore) Responses() store.ResponseRepo { return dao11cResponses{s: s} }
func (r dao11cResponses) Create(context.Context, *store.Response) (int, error) {
	r.s.count("Responses.Create")
	return 1, nil
}
func (r dao11cResponses) Update(context.Context, *store.Response) error {
	r.s.count("Responses.Update")
	return nil
}
func (r dao11cResponses) Delete(context.Context, int) error {
	r.s.count("Responses.Delete")
	return nil
}
func (r dao11cResponses) CreateAction(c context.Context, a *store.ResponseAction) (int, error) {
	return r.s.actions.Create(c, a)
}
func (r dao11cResponses) UpdateAction(c context.Context, a *store.ResponseAction) error {
	return r.s.actions.Update(c, a)
}
func (r dao11cResponses) DeleteAction(c context.Context, id int) error {
	return r.s.actions.Delete(c, id)
}
func (r dao11cResponses) GetAction(c context.Context, id int) (*store.ResponseAction, error) {
	return r.s.actions.Get(c, id)
}
func (r dao11cResponses) ListActions(c context.Context, _ int) ([]store.ResponseAction, error) {
	return r.s.actions.List(c)
}
func (r dao11cResponses) SetPairedWith(context.Context, int, *int) error {
	r.s.count("Responses.SetPairedWith")
	return nil
}

type dao11cTargets struct {
	store.XDropTargetRepo
	s *dao11cStore
}

func (s *dao11cStore) XDropTargets() store.XDropTargetRepo                        { return dao11cTargets{s: s} }
func (r dao11cTargets) Set(context.Context, int, []int) error                     { r.s.count("Targets.Set"); return nil }
func (r dao11cTargets) List(context.Context, int) ([]store.XDropConnector, error) { return nil, nil }

type dao11cNodes struct {
	store.NodeRepo
	s *dao11cStore
}

func (s *dao11cStore) Nodes() store.NodeRepo                     { return dao11cNodes{s: s} }
func (r dao11cNodes) List(context.Context) ([]store.Node, error) { return nil, nil }
func (r dao11cNodes) Create(context.Context, *store.Node) error {
	r.s.count("Nodes.Create")
	return nil
}
func (r dao11cNodes) Update(context.Context, *store.Node) error {
	r.s.count("Nodes.Update")
	return nil
}
func (r dao11cNodes) Delete(context.Context, string) error { r.s.count("Nodes.Delete"); return nil }
func (r dao11cNodes) UpdateDeliveryVersionCurrent(context.Context, string, int64) error {
	r.s.count("Nodes.UpdateDeliveryVersionCurrent")
	return nil
}

type dao11cAudit struct{ s *dao11cStore }

func (s *dao11cStore) AuditLog() store.AuditLogRepo { return dao11cAudit{s: s} }
func (r dao11cAudit) Create(_ context.Context, a *store.AuditLog) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.writes["Audit.Create"]++
	r.s.audits = append(r.s.audits, dao11cCopy(*a))
	return nil
}
func (r dao11cAudit) List(context.Context, store.AuditFilter) ([]store.AuditLog, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return dao11cCopy(r.s.audits), nil
}

func dao11cFixture() *dao11cStore {
	s := &dao11cStore{writes: map[string]int{}}
	id := 1
	s.actions = &dao11cRows[store.ResponseAction]{s: s, name: "Actions", rows: []store.ResponseAction{{ID: 1, ResponseID: 1, ActionType: "webhook", TriggerPhase: "on_detected", RunMode: "once", WebhookConnectorID: &id, Enabled: true}}}
	s.thresholds = &dao11cRows[store.Threshold]{s: s, name: "Thresholds", rows: []store.Threshold{{ID: 1, PrefixID: &id, Unit: "pps", Comparison: "over", Domain: "internal_ip", Decoder: "udp", Direction: "receives", Value: 100, Enabled: true}}}
	s.shells = &dao11cRows[store.ShellConnector]{s: s, name: "Shells", rows: []store.ShellConnector{{ID: 1, Name: "n1", Command: "/opt/a.sh", DefaultArgs: "-v", TimeoutMs: 45000, PassStdin: true, Enabled: true}}}
	s.xdrops = &dao11cRows[store.XDropConnector]{s: s, name: "XDrops", rows: []store.XDropConnector{{ID: 1, Name: "n1", APIURL: "https://old.example/api", APIKey: "K", TimeoutMs: 7000, Enabled: true}}}
	s.hooks = &dao11cRows[store.WebhookConnector]{s: s, name: "Hooks", rows: []store.WebhookConnector{{ID: 1, Name: "n1", URL: "https://old.example/hook", Method: "PUT", Headers: json.RawMessage(`{"A":"b"}`), TimeoutMs: 3000, Global: true, Enabled: true}}}
	s.bgps = &dao11cRows[store.BGPConnector]{s: s, name: "BGPs", rows: []store.BGPConnector{{ID: 1, Name: "n1", BGPASN: 65000, Enabled: true}}}
	s.prefixes = &dao11cRows[store.WatchPrefix]{s: s, name: "Prefixes", rows: []store.WatchPrefix{{ID: 1, Prefix: "192.0.2.0/24", Enabled: true}}}
	return s
}

type dao11cSnapshot struct {
	Actions    []store.ResponseAction
	Thresholds []store.Threshold
	Shells     []store.ShellConnector
	XDrops     []store.XDropConnector
	Hooks      []store.WebhookConnector
	BGPs       []store.BGPConnector
	Prefixes   []store.WatchPrefix
	Audits     []store.AuditLog
}

func (s *dao11cStore) snapshot() (dao11cSnapshot, map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return dao11cCopy(dao11cSnapshot{s.actions.rows, s.thresholds.rows, s.shells.rows, s.xdrops.rows, s.hooks.rows, s.bgps.rows, s.prefixes.rows, s.audits}), dao11cCopy(s.writes)
}
func dao11cCalls(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
func dao11cRequest(t *testing.T, s *dao11cStore, method, path string, body any, want int, field string) *httptest.ResponseRecorder {
	t.Helper()
	before, writesBefore := s.snapshot()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "dao11c")
	gin.SetMode(gin.TestMode)
	deps := Dependencies{Store: s, APIKey: "dao11c", ConfigPub: configpub.New(s, nil, func() []string { return nil })}
	rec := httptest.NewRecorder()
	NewRouter(deps).ServeHTTP(rec, req)
	if rec.Code != want {
		t.Errorf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
	}
	after, writesAfter := s.snapshot()
	delta := dao11cCalls(writesAfter) - dao11cCalls(writesBefore)
	if want == 400 {
		if !strings.Contains(rec.Body.String(), field) {
			t.Errorf("error body=%s must contain %q", rec.Body.String(), field)
		}
		if delta != 0 {
			t.Errorf("rejected request write delta=%d want=0 calls=%v", delta, writesAfter)
		}
		if !reflect.DeepEqual(before, after) {
			t.Error("rejected request changed stored rows")
		}
	} else {
		expected := 2
		if strings.HasSuffix(path, "/test") {
			expected = 0
		}
		if delta != expected {
			t.Errorf("accepted request write delta=%d want=%d calls=%v", delta, expected, writesAfter)
		}
		if expected > 0 && writesAfter["Audit.Create"]-writesBefore["Audit.Create"] != 1 {
			t.Errorf("audit positive control delta=%d want=1", writesAfter["Audit.Create"]-writesBefore["Audit.Create"])
		}
	}
	return rec
}
func dao11cEqual[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stored row=%+v want=%+v", got, want)
	}
}
func dao11cActionBody() map[string]any {
	return map[string]any{"action_type": "webhook", "connector_id": 1, "trigger_phase": "on_detected", "run_mode": "once"}
}
func dao11cThresholdBody() map[string]any {
	return map[string]any{"prefix_id": 1, "unit": "pps", "comparison": "over", "domain": "internal_ip", "decoder": "udp", "direction": "receives", "value": 100}
}
func dao11cConnectorBody(kind string) map[string]any {
	switch kind {
	case "shell":
		return map[string]any{"name": "n1", "command": "/opt/a.sh"}
	case "webhook":
		return map[string]any{"name": "n1", "url": "https://old.example/hook"}
	case "xdrop":
		return map[string]any{"name": "n1", "api_url": "https://old.example/api"}
	default:
		return map[string]any{"name": "n1", "bgp_asn": 65000}
	}
}
func dao11cConnectorPath(kind, method string) string {
	p := "/api/settings/" + kind + "-connectors"
	if method == "PUT" {
		p += "/1"
	}
	return p
}

func TestDao11c_V2a_ActionType(t *testing.T) {
	for _, v := range []string{"", "xdrop_api", "foo"} {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			s := dao11cFixture()
			s.actions.rows = nil
			b := dao11cActionBody()
			b["action_type"] = v
			dao11cRequest(t, s, "POST", "/api/responses/1/actions", b, 400, "action_type")
		})
	}
}
func TestDao11c_V2b_RunMode(t *testing.T) {
	s := dao11cFixture()
	s.actions.rows = nil
	b := dao11cActionBody()
	b["run_mode"] = "periodc"
	dao11cRequest(t, s, "POST", "/api/responses/1/actions", b, 400, "run_mode")
}
func TestDao11c_V2c_MergedAction(t *testing.T) {
	for _, v := range []string{"old_type", "old_mode", "empty_type"} {
		t.Run(v, func(t *testing.T) {
			s := dao11cFixture()
			b := map[string]any{"priority": 9}
			field := "action_type"
			switch v {
			case "old_type":
				s.actions.rows[0].ActionType = "xdrop_api"
			case "old_mode":
				s.actions.rows[0].RunMode = "bogus"
				field = "run_mode"
			case "empty_type":
				b["action_type"] = ""
			}
			dao11cRequest(t, s, "PUT", "/api/actions/1", b, 400, field)
		})
	}
}
func TestDao11c_V3a_RequiredThresholdFields(t *testing.T) {
	for _, f := range []string{"unit", "comparison", "domain"} {
		t.Run(f, func(t *testing.T) {
			s := dao11cFixture()
			b := dao11cThresholdBody()
			delete(b, f)
			dao11cRequest(t, s, "POST", "/api/thresholds", b, 400, f)
		})
	}
}
func dao11cThresholdEntries(t *testing.T, field string, value any) {
	t.Helper()
	for _, entry := range []struct{ name, method, path string }{{"threshold", "POST", "/api/thresholds"}, {"template", "POST", "/api/threshold-templates/1/rules"}, {"rule", "PUT", "/api/threshold-rules/1"}} {
		t.Run(entry.name, func(t *testing.T) {
			s := dao11cFixture()
			b := dao11cThresholdBody()
			b[field] = value
			dao11cRequest(t, s, entry.method, entry.path, b, 400, field)
		})
	}
}
func TestDao11c_V3b_ThresholdEnums(t *testing.T) {
	for f, v := range map[string]string{"unit": "bsp", "comparison": "abov", "domain": "host"} {
		t.Run(f, func(t *testing.T) { dao11cThresholdEntries(t, f, v) })
	}
}
func TestDao11c_V3c_NegativeValue(t *testing.T) {
	for _, unit := range []string{"pps", "bps"} {
		t.Run(unit, func(t *testing.T) {
			for _, entry := range []struct{ name, method, path string }{{"threshold", "POST", "/api/thresholds"}, {"template", "POST", "/api/threshold-templates/1/rules"}, {"rule", "PUT", "/api/threshold-rules/1"}} {
				t.Run(entry.name, func(t *testing.T) {
					s := dao11cFixture()
					b := dao11cThresholdBody()
					b["unit"] = unit
					b["value"] = -1
					dao11cRequest(t, s, entry.method, entry.path, b, 400, "value")
				})
			}
		})
	}
}
func TestDao11c_V3d_MergedThreshold(t *testing.T) {
	s := dao11cFixture()
	s.thresholds.rows[0].Comparison = ""
	dao11cRequest(t, s, "PUT", "/api/threshold-rules/1", map[string]any{"response_id": 1}, 400, "comparison")
}
func TestDao11c_V4a_DefaultArgs(t *testing.T) {
	for _, m := range []string{"POST", "PUT"} {
		t.Run(m, func(t *testing.T) {
			s := dao11cFixture()
			b := dao11cConnectorBody("shell")
			b["default_args"] = "--ip {dts_ip}"
			dao11cRequest(t, s, m, dao11cConnectorPath("shell", m), b, 400, "default_args")
		})
	}
}
func TestDao11c_V5a_XDropMerge(t *testing.T) {
	s := dao11cFixture()
	want := s.xdrops.rows[0]
	want.Name = "n2"
	dao11cRequest(t, s, "PUT", dao11cConnectorPath("xdrop", "PUT"), map[string]any{"name": "n2"}, 200, "")
	dao11cEqual(t, s.xdrops.rows[0], want)
}
func TestDao11c_V5b_XDropEmpty(t *testing.T) {
	for _, f := range []string{"name", "api_url"} {
		t.Run(f, func(t *testing.T) {
			s := dao11cFixture()
			b := dao11cConnectorBody("xdrop")
			b[f] = ""
			b["api_key"] = "new-key"
			dao11cRequest(t, s, "PUT", dao11cConnectorPath("xdrop", "PUT"), b, 400, f+" is required")
		})
	}
}
func TestDao11c_V5c_ShellMerge(t *testing.T) {
	s := dao11cFixture()
	want := s.shells.rows[0]
	want.Name = "x"
	dao11cRequest(t, s, "PUT", dao11cConnectorPath("shell", "PUT"), map[string]any{"name": "x"}, 200, "")
	dao11cEqual(t, s.shells.rows[0], want)
}
func TestDao11c_V5d_WebhookMerge(t *testing.T) {
	s := dao11cFixture()
	want := dao11cCopy(s.hooks.rows[0])
	want.Name = "x"
	dao11cRequest(t, s, "PUT", dao11cConnectorPath("webhook", "PUT"), map[string]any{"name": "x"}, 200, "")
	dao11cEqual(t, s.hooks.rows[0], want)
}
func TestDao11c_V5e_WebhookURLCredentials(t *testing.T) {
	for name, h := range map[string]string{"valid": `{"Authorization":"Bearer K"}`, "malformed": `{"Authorization":"Bearer K","N":1}`} {
		t.Run(name, func(t *testing.T) {
			s := dao11cFixture()
			s.hooks.rows[0].Headers = json.RawMessage(h)
			dao11cRequest(t, s, "PUT", dao11cConnectorPath("webhook", "PUT"), map[string]any{"name": "n1", "url": "https://new.example/hook"}, 400, "re-entered")
		})
	}
}
func TestDao11c_V5f_RequiredMergedFields(t *testing.T) {
	for _, kind := range []string{"shell", "webhook"} {
		for _, f := range []string{"name", map[string]string{"shell": "command", "webhook": "url"}[kind]} {
			t.Run(kind+"/"+f, func(t *testing.T) {
				s := dao11cFixture()
				b := dao11cConnectorBody(kind)
				b[f] = ""
				dao11cRequest(t, s, "PUT", dao11cConnectorPath(kind, "PUT"), b, 400, f+" is required")
			})
		}
	}
}
func TestDao11c_V6a_ASNRange(t *testing.T) {
	for _, m := range []string{"POST", "PUT"} {
		values := []int64{-1, 4294967296}
		if m == "PUT" {
			values = append(values, 0)
		}
		for _, v := range values {
			t.Run(fmt.Sprintf("%s/%d", m, v), func(t *testing.T) {
				s := dao11cFixture()
				b := dao11cConnectorBody("bgp")
				b["bgp_asn"] = v
				dao11cRequest(t, s, m, dao11cConnectorPath("bgp", m), b, 400, "bgp_asn")
			})
		}
	}
	t.Run("stored_negative", func(t *testing.T) {
		s := dao11cFixture()
		s.bgps.rows[0].BGPASN = -5
		dao11cRequest(t, s, "PUT", dao11cConnectorPath("bgp", "PUT"), map[string]any{"name": "n2"}, 400, "bgp_asn")
	})
}
func TestDao11c_V7a_Method(t *testing.T) {
	for _, m := range []string{"POST", "PUT"} {
		for _, v := range []string{"get", "DELETE", "PO ST", "post", " put "} {
			t.Run(m+"/"+v, func(t *testing.T) {
				s := dao11cFixture()
				b := dao11cConnectorBody("webhook")
				b["method"] = v
				want := 400
				if v == "post" || v == " put " {
					want = 200
					if m == "POST" {
						want = 201
					}
				}
				dao11cRequest(t, s, m, dao11cConnectorPath("webhook", m), b, want, "method")
				if want != 400 {
					dao11cEqual(t, s.hooks.rows[len(s.hooks.rows)-1].Method, strings.ToUpper(strings.TrimSpace(v)))
				}
			})
		}
	}
}
func TestDao11c_V7b_HeaderShape(t *testing.T) {
	for _, m := range []string{"POST", "PUT"} {
		for name, h := range map[string]string{"array": `[]`, "string": `"x"`, "number": `{"a":1}`, "null_value": `{"A":null}`} {
			t.Run(m+"/"+name, func(t *testing.T) {
				s := dao11cFixture()
				b := dao11cConnectorBody("webhook")
				b["headers"] = json.RawMessage(h)
				rec := dao11cRequest(t, s, m, dao11cConnectorPath("webhook", m), b, 400, "headers")
				var body struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Error != "headers must be a JSON object with string values" {
					t.Errorf("shape error must contain no values: %q", body.Error)
				}
			})
		}
	}
}
func TestDao11c_V7c_NegativeTimeout(t *testing.T) {
	for _, m := range []string{"POST", "PUT"} {
		t.Run(m, func(t *testing.T) {
			s := dao11cFixture()
			b := dao11cConnectorBody("webhook")
			b["timeout_ms"] = -1
			dao11cRequest(t, s, m, dao11cConnectorPath("webhook", m), b, 400, "timeout_ms")
		})
	}
}

type dao11cTransport func(*http.Request) (*http.Response, error)

func (f dao11cTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDao11c_V7d_TestButtonMethod(t *testing.T) {
	for _, v := range []string{"", "post"} {
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			s := dao11cFixture()
			s.hooks.rows[0].Method = v
			previous := action.WebhookTransport
			t.Cleanup(func() { action.WebhookTransport = previous })
			var methods []string
			action.WebhookTransport = dao11cTransport(func(r *http.Request) (*http.Response, error) {
				methods = append(methods, r.Method)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: r}, nil
			})
			dao11cRequest(t, s, "POST", "/api/settings/webhook-connectors/1/test", map[string]any{}, 200, "")
			dao11cEqual(t, methods, []string{"POST"})
		})
	}
}
func TestDao11c_V7e_PreserveMethod(t *testing.T) {
	s := dao11cFixture()
	dao11cRequest(t, s, "PUT", dao11cConnectorPath("webhook", "PUT"), dao11cConnectorBody("webhook"), 200, "")
	dao11cEqual(t, s.hooks.rows[0].Method, "PUT")
}

func TestDao11c_W2_EmptyRunMode(t *testing.T) {
	s := dao11cFixture()
	s.actions.rows = nil
	b := dao11cActionBody()
	b["run_mode"] = ""
	dao11cRequest(t, s, "POST", "/api/responses/1/actions", b, 201, "")
	dao11cEqual(t, s.actions.rows[0].RunMode, "")
}
func TestDao11c_W3a_ZeroValue(t *testing.T) {
	for _, path := range []string{"/api/thresholds", "/api/threshold-templates/1/rules"} {
		t.Run(path, func(t *testing.T) {
			s := dao11cFixture()
			b := dao11cThresholdBody()
			b["value"] = 0
			dao11cRequest(t, s, "POST", path, b, 201, "")
			dao11cEqual(t, s.thresholds.rows[1].Value, int64(0))
		})
	}
}
func TestDao11c_W3b_TemplateDefaults(t *testing.T) {
	s := dao11cFixture()
	dao11cRequest(t, s, "POST", "/api/threshold-templates/1/rules", map[string]any{"decoder": "udp", "value": 1}, 201, "")
	v := s.thresholds.rows[1]
	dao11cEqual(t, []string{v.Unit, v.Comparison, v.Domain}, []string{"pps", "over", "internal_ip"})
}
func TestDao11c_W4_TemplateVars(t *testing.T) {
	s := dao11cFixture()
	b := dao11cConnectorBody("shell")
	b["default_args"] = "{ip} ${HOME}"
	dao11cRequest(t, s, "POST", dao11cConnectorPath("shell", "POST"), b, 201, "")
	dao11cEqual(t, s.shells.rows[1].DefaultArgs, "{ip} ${HOME}")
}
func TestDao11c_W5a_XDropZeroFalse(t *testing.T) {
	s := dao11cFixture()
	b := dao11cConnectorBody("xdrop")
	b["timeout_ms"] = 0
	b["enabled"] = false
	dao11cRequest(t, s, "PUT", dao11cConnectorPath("xdrop", "PUT"), b, 200, "")
	dao11cEqual(t, s.xdrops.rows[0].TimeoutMs, 0)
	dao11cEqual(t, s.xdrops.rows[0].Enabled, false)
}
func TestDao11c_W5b_ShellZeroFalse(t *testing.T) {
	s := dao11cFixture()
	b := dao11cConnectorBody("shell")
	b["timeout_ms"] = 0
	b["enabled"] = false
	b["pass_stdin"] = false
	dao11cRequest(t, s, "PUT", dao11cConnectorPath("shell", "PUT"), b, 200, "")
	v := s.shells.rows[0]
	dao11cEqual(t, v.TimeoutMs, 0)
	dao11cEqual(t, []bool{v.Enabled, v.PassStdin}, []bool{false, false})
}
func TestDao11c_W5c_WebhookNullHeaders(t *testing.T) {
	t.Run("clear", func(t *testing.T) {
		s := dao11cFixture()
		b := dao11cConnectorBody("webhook")
		b["headers"] = nil
		dao11cRequest(t, s, "PUT", dao11cConnectorPath("webhook", "PUT"), b, 200, "")
		dao11cEqual(t, string(s.hooks.rows[0].Headers), "null")
	})
	t.Run("change_url", func(t *testing.T) {
		s := dao11cFixture()
		s.hooks.rows[0].Headers = json.RawMessage("null")
		b := dao11cConnectorBody("webhook")
		b["url"] = "https://new.example/hook"
		dao11cRequest(t, s, "PUT", dao11cConnectorPath("webhook", "PUT"), b, 200, "")
		dao11cEqual(t, s.hooks.rows[0].URL, "https://new.example/hook")
	})
}
func TestDao11c_W5d_XDropTrailingSlash(t *testing.T) {
	s := dao11cFixture()
	b := dao11cConnectorBody("xdrop")
	b["api_url"] = "https://old.example/api/"
	dao11cRequest(t, s, "PUT", dao11cConnectorPath("xdrop", "PUT"), b, 200, "")
	dao11cEqual(t, s.xdrops.rows[0].APIURL, "https://old.example/api")
	dao11cEqual(t, s.xdrops.rows[0].APIKey, "K")
}
func TestDao11c_W5e_NullScalar(t *testing.T) {
	for kind, f := range map[string]string{"xdrop": "timeout_ms", "shell": "pass_stdin", "webhook": "enabled"} {
		t.Run(kind, func(t *testing.T) {
			s := dao11cFixture()
			b := dao11cConnectorBody(kind)
			b[f] = nil
			dao11cRequest(t, s, "PUT", dao11cConnectorPath(kind, "PUT"), b, 200, "")
			switch kind {
			case "xdrop":
				dao11cEqual(t, s.xdrops.rows[0].TimeoutMs, 7000)
			case "shell":
				dao11cEqual(t, s.shells.rows[0].PassStdin, true)
			case "webhook":
				dao11cEqual(t, s.hooks.rows[0].Enabled, true)
			}
		})
	}
}
func TestDao11c_W6_ASNFullRangeAndOmitted(t *testing.T) {
	t.Run("create_max", func(t *testing.T) {
		s := dao11cFixture()
		b := dao11cConnectorBody("bgp")
		b["bgp_asn"] = int64(4294967295)
		dao11cRequest(t, s, "POST", dao11cConnectorPath("bgp", "POST"), b, 201, "")
		dao11cEqual(t, s.bgps.rows[1].BGPASN, int(4294967295))
	})
	t.Run("update_omitted", func(t *testing.T) {
		s := dao11cFixture()
		dao11cRequest(t, s, "PUT", dao11cConnectorPath("bgp", "PUT"), map[string]any{"name": "n2"}, 200, "")
		dao11cEqual(t, s.bgps.rows[0].BGPASN, 65000)
	})
}
func TestDao11c_W7b_NoTimeoutUpperBound(t *testing.T) {
	s := dao11cFixture()
	b := dao11cConnectorBody("webhook")
	b["timeout_ms"] = 20000
	dao11cRequest(t, s, "POST", dao11cConnectorPath("webhook", "POST"), b, 201, "")
	dao11cEqual(t, s.hooks.rows[1].TimeoutMs, 20000)
}
