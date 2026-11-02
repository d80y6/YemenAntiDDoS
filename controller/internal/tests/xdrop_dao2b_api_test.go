package tests

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

type d2bAPITransport func(*http.Request) (*http.Response, error)

func (f d2bAPITransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Behavior C18: create transport errors or 503 bodies containing a URL and fake key are dispatched through the real engine and recorded in execution logs.
// Responses from GET /api/attacks/:id/action-log and GET /api/attacks/:id (attack details) must omit the fake key, userinfo, and HTTP URLs.
// Seeds M18 and M28 detect exposing raw error_message / response_body when only webhook logs are sanitized.
func TestD2B_C18_CreateErrorRedactedAPI(t *testing.T) {
	const secret = "d2b-obviously-fake-credential-0123456789"
	for _, kind := range []string{"transport_error", "http_503"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				ms := NewMockStore()
				ms.responses.responses = []store.Response{{ID: 1, Name: "d2b", Enabled: true}}
				ms.responses.actions = []store.ResponseAction{{ID: 10, ResponseID: 1, ActionType: "xdrop", TriggerPhase: "on_detected", RunMode: "once", Enabled: true, Execution: "automatic", XDropAction: "drop"}}
				ms.xdropConnectors.connectors = []store.XDropConnector{{ID: 7, Name: "d2b", APIURL: "http://192.0.2.20/api/v1", APIKey: secret, TimeoutMs: 1000, Enabled: true}}
				ended := time.Now()
				attack := store.Attack{ResponseID: intPtr(1), DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", AttackType: "udp_flood", PeakPPS: 100, StartedAt: time.Now(), EndedAt: &ended}
				id, err := ms.Attacks().Create(ctx, &attack)
				if err != nil {
					t.Fatal(err)
				}
				stored := attack
				stored.ID, stored.EndedAt = id, &ended // Create 清 EndedAt；详情接口对未结束攻击要读 Tracker（本装置无）
				if err := ms.Attacks().Update(ctx, &stored); err != nil {
					t.Fatal(err)
				}
				posts := 0
				old := http.DefaultTransport
				http.DefaultTransport = d2bAPITransport(func(r *http.Request) (*http.Response, error) {
					posts++
					reflected := "request " + r.URL.String() + " credential " + secret + " peer https://user:" + secret + "@192.0.2.21/path"
					if kind == "transport_error" {
						return nil, errors.New(reflected)
					}
					body, _ := json.Marshal(map[string]string{"code": "upstream_error", "field": "rule", "message": reflected})
					return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
				})
				t.Cleanup(func() { http.DefaultTransport = old })
				live := attack
				live.ID, live.EndedAt = id, nil
				e := action.NewEngine(ms, "auto")
				e.HandleEvent(tracker.AttackEvent{Type: "confirmed", DBID: id, Attack: &live})
				synctest.Wait()
				failed := 0
				for _, l := range ms.actionExecLog.snapshotLogs() {
					if l.ActionType == "xdrop" && l.Status == "failed" {
						failed++
					}
				}
				if posts != 1 || failed != 1 {
					t.Fatalf("device: create POST=%d failed xdrop logs=%d; want 1/1; logs=%+v", posts, failed, ms.actionExecLog.snapshotLogs())
				}
				for _, path := range []string{"/api/attacks/" + strconv.Itoa(id) + "/action-log", "/api/attacks/" + strconv.Itoa(id)} {
					w := dao4Request(t, ms, e, "GET", path, "")
					body := w.Body.String()
					if w.Code != 200 || !strings.Contains(body, "upstream_error") && kind == "http_503" {
						t.Errorf("%s HTTP %d (device: want 200 with the failed xdrop row); body=%s", path, w.Code, body)
					}
					for _, forbidden := range []string{secret, "user:", "http://", "https://"} {
						if strings.Contains(body, forbidden) {
							t.Errorf("%s exposes %q", path, forbidden)
						}
					}
				}
			})
		})
	}
}
