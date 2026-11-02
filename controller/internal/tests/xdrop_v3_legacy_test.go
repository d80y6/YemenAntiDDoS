package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

const legacyV3Key = "xdk_0000000000000000_test"

func assertLegacyV3Delete(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Method != http.MethodDelete {
		t.Errorf("expected DELETE, got %s", r.Method)
		return
	}
	refs := map[string]string{"rule-overdue": "a100.x40", "rule-future": "a101.x41", "rule-audit": "a103.x43", "rule-failaudit": "a104.x44", "rule-cancel": "a102.x42", "stuck-rule": "a200.x50", "gone-rule": "a201.x51", "bad-rule": "a202.x52", "rule-to-force": "a500.x40", "r-multi": "a1000.x41", "executing-ghost": "a300.x60"}
	want := refs[strings.TrimPrefix(r.URL.Path, "/rules/")]
	if want == "" || r.URL.Query().Get("claim_ref") != want {
		t.Errorf("claim_ref=%q want=%q path=%s", r.URL.Query().Get("claim_ref"), want, r.URL.Path)
	}
	if r.Header.Get("Authorization") != "Bearer "+legacyV3Key {
		t.Errorf("missing v3 bearer")
	}
}
func assertLegacyAnomalyV3(t *testing.T, decoder string, actionID int) {
	t.Helper()
	requests := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/rules" || r.Header.Get("Authorization") != "Bearer "+legacyV3Key {
			t.Errorf("wrong v3 request")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"rule_00000000000000000000000000000001"}`))
		requests <- body
	}))
	defer srv.Close()
	act := store.ResponseAction{ID: actionID, ActionType: "xdrop", XDropAction: "rate_limit", TriggerPhase: "on_detected", RunMode: "once", Enabled: true, XDropCustomPayload: json.RawMessage(`{"dst_ip":"{dst_ip}","action":"rate_limit","rate_limit":5000}`)}
	ms, eng, attack := setupDispatchMock(t, "auto", []store.ResponseAction{act})
	attack.DecoderFamily = decoder
	ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{ID: 7, Name: "v3-test", APIURL: srv.URL, APIKey: legacyV3Key, Enabled: true})
	dispatch(eng, attack)
	select {
	case body := <-requests:
		want := float64(1)
		if decoder == "invalid" {
			want = 2
		}
		if body["match_anomaly"] != want || body["rate_limit"] != float64(5000) {
			t.Fatal(body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("anomaly rate_limit POST did not happen")
	}
}
