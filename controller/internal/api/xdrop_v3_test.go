package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

const apiV3Key = "xdk_0000000000000000_test"

type apiV3Store struct {
	store.Store
	conn store.XDropConnector
}
type apiV3Connectors struct {
	store.XDropConnectorRepo
	s *apiV3Store
}

func (s *apiV3Store) XDropConnectors() store.XDropConnectorRepo { return apiV3Connectors{s: s} }
func (r apiV3Connectors) Get(_ context.Context, id int) (*store.XDropConnector, error) {
	if id != r.s.conn.ID {
		return nil, fmt.Errorf("connector not found")
	}
	c := r.s.conn
	return &c, nil
}
func apiV3Call(t *testing.T, s *apiV3Store, method, path string, auth bool) (int, map[string]any) {
	t.Helper()
	router := NewRouter(Dependencies{Store: s, APIKey: "xsight_test_auth"})
	r := httptest.NewRequest(method, path, nil)
	if auth {
		r.Header.Set("X-API-Key", "xsight_test_auth")
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return w.Code, out
}
func apiV3Data(out map[string]any) map[string]any {
	if data, ok := out["data"].(map[string]any); ok {
		return data
	}
	return out
}
func TestC11_ConnectorAuth(t *testing.T) {
	for _, tc := range []struct {
		name, key, body, wantError string
		status                     int
		success                    bool
	}{
		{"machine", apiV3Key, `{"kind":"machine","name":"xsight-test"}`, "", 200, true},
		{"wrong_key", "xdk_wrong_test", "", "HTTP 401 unauthenticated: invalid credential", 401, false},
		{"no_key", "", "", "HTTP 401 unauthenticated: invalid credential", 401, false},
		{"user", apiV3Key, `{"kind":"user","name":"user-test"}`, "invalid xdrop machine auth response", 200, false},
		{"malformed", apiV3Key, `broken`, "invalid xdrop machine auth response", 200, false},
		{"no_code", apiV3Key, `broken`, "HTTP 503: broken", 503, false},
		{"field", apiV3Key, `{"code":"invalid_field","field":"key","message":"invalid credential"}`, "HTTP 400 invalid_field field=key: invalid credential", 400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/auth/me" {
					t.Errorf("%s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-API-Key") != "" {
					t.Error("old auth header")
				}
				if r.Header.Get("Authorization") != "Bearer "+apiV3Key {
					w.WriteHeader(401)
					_, _ = w.Write([]byte(`{"code":"unauthenticated","message":"invalid credential"}`))
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			s := &apiV3Store{conn: store.XDropConnector{ID: 7, APIURL: srv.URL, APIKey: tc.key, Enabled: true}}
			status, out := apiV3Call(t, s, "POST", "/api/settings/xdrop-connectors/7/test", true)
			data := apiV3Data(out)
			if status != 200 || data["success"] != tc.success || data["status_code"] != float64(tc.status) || calls != 1 {
				t.Fatalf("status=%d data=%v calls=%d", status, data, calls)
			}
			if tc.success {
				if data["kind"] != "machine" || data["name"] != "xsight-test" {
					t.Fatal(data)
				}
			} else if data["error"] != tc.wantError {
				t.Fatalf("error=%v want=%s", data["error"], tc.wantError)
			}
		})
	}
}
func TestC12_DeliveryAPI(t *testing.T) {
	for _, mode := range []string{"normal", "retry", "retry_limit", "missing", "disabled", "absent_connector", "unauthenticated", "missing_epoch", "malformed", "upstream_401", "bad_parameter"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var paths []string
			deliveries := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				paths = append(paths, r.URL.Path)
				if r.Header.Get("Authorization") != "Bearer "+apiV3Key {
					t.Error("missing bearer")
					w.WriteHeader(401)
					return
				}
				if r.Method != "GET" {
					t.Error("not GET")
				}
				if mode == "upstream_401" {
					w.WriteHeader(401)
					_, _ = w.Write([]byte(`{"code":"unauthenticated","message":"test rejection"}`))
					return
				}
				if r.URL.Path == "/nodes" {
					body := `{"epoch":"epoch-test"}`
					if mode == "missing_epoch" {
						body = `{}`
					}
					if mode == "malformed" {
						body = `broken`
					}
					_, _ = w.Write([]byte(body))
					return
				}
				deliveries++
				if r.URL.Query().Get("gen") != "0" || r.URL.Query().Get("epoch") != "epoch-test" {
					t.Error("wrong generation query")
				}
				if mode == "retry_limit" && deliveries <= 2 || mode == "retry" && deliveries == 1 {
					w.WriteHeader(409)
					_, _ = w.Write([]byte(`{"code":"gen_epoch_mismatch","message":"stale epoch"}`))
					return
				}
				if mode == "missing" {
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"code":"not_found","message":"missing"}`))
					return
				}
				_, _ = w.Write([]byte(`{"rule_id":"rule_test","target_gen":7,"epoch":"epoch-test","nodes":[{"name":"node-a","state":"rejected","code":"invalid_rule","error":"test rejection"}]}`))
			}))
			defer srv.Close()
			s := &apiV3Store{conn: store.XDropConnector{ID: 7, APIURL: srv.URL, APIKey: apiV3Key, Enabled: mode != "disabled"}}
			connector := "7"
			if mode == "absent_connector" {
				connector = "8"
			}
			if mode == "bad_parameter" {
				connector = "no"
			}
			status, out := apiV3Call(t, s, "GET", "/api/active-actions/xdrop/delivery?connector_id="+connector+"&rule_id=rule_test", mode != "unauthenticated")
			data := apiV3Data(out)
			wantStatus, wantCalls := 200, 2
			switch mode {
			case "retry":
				wantCalls = 4
			case "retry_limit":
				wantStatus, wantCalls = 502, 4
			case "disabled", "absent_connector":
				wantStatus, wantCalls = 404, 0
			case "unauthenticated":
				wantStatus, wantCalls = 401, 0
			case "missing_epoch", "malformed", "upstream_401":
				wantStatus, wantCalls = 502, 1
			case "bad_parameter":
				wantStatus, wantCalls = 400, 0
			}
			mu.Lock()
			gotPaths := append([]string(nil), paths...)
			mu.Unlock()
			if status != wantStatus || len(gotPaths) != wantCalls {
				t.Fatalf("status=%d out=%v paths=%v", status, out, gotPaths)
			}
			if mode == "retry" || mode == "retry_limit" {
				if !reflect.DeepEqual(gotPaths, []string{"/nodes", "/rules/rule_test/delivery", "/nodes", "/rules/rule_test/delivery"}) {
					t.Fatal(gotPaths)
				}
			}
			if mode == "normal" || mode == "retry" {
				raw, _ := json.Marshal(data)
				if string(raw) != `{"epoch":"epoch-test","nodes":[{"code":"invalid_rule","error":"test rejection","name":"node-a","state":"rejected"}],"rule_id":"rule_test","target_gen":7}` {
					t.Fatal(string(raw))
				}
			}
			if mode == "missing" && data["found"] != false {
				t.Fatal(data)
			}
			text := fmt.Sprint(out)
			for test, part := range map[string]string{"retry_limit": "gen_epoch_mismatch", "missing_epoch": "v3 nodes epoch missing", "upstream_401": "unauthenticated"} {
				if mode == test && !strings.Contains(text, part) {
					t.Fatalf("missing %s in %v", part, out)
				}
			}
		})
	}
}
