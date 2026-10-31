package action

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func dao14c2Assert(t *testing.T, name string, ok bool, detail any) {
	t.Helper()
	if ok {
		t.Logf("ASSERT %s PASS: %v", name, detail)
	} else {
		t.Errorf("ASSERT %s FAIL: %v", name, detail)
	}
}

func dao14c2Payload(t *testing.T, event, entry string, ended bool, reason string) map[string]any {
	t.Helper()
	var payload map[string]any
	dao9bTransport(t, func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		return dao9bOK(r)
	})
	ev := dao9bEvent()
	ev.Type = event
	if ended {
		end := ev.Attack.StartedAt.Add(time.Minute)
		ev.Attack.EndedAt = &end
	}
	if reason != "" {
		ev.Attack.ReasonCodes = []string{reason}
	}
	conn := dao9bConnector("POST", 1000)
	var err error
	switch entry {
	case "Connector":
		_, err = postConnectorWebhook(context.Background(), conn, ev.Attack, event, nil)
	case "Legacy":
		_, err = executeWebhook(context.Background(), []byte(`{"url":"http://dao14c2.invalid"}`), ev.Attack, event)
	case "Global":
		NewEngine(&dao9bStore{connectors: []store.WebhookConnector{conn}}, "auto").fireGlobalWebhooks(context.Background(), ev)
	}
	if err != nil || payload == nil {
		t.Fatalf("DEVICE webhook body=%v err=%v", payload, err)
	}
	return payload
}

func dao14c2EndFields(t *testing.T, body map[string]any, event string, ended bool) {
	t.Helper()
	dao14c2Assert(t, "Event", body["event"] == event, body["event"])
	_, hasEnd := body["ended_at"]
	duration, hasDuration := body["duration_seconds"]
	dao14c2Assert(t, "EndedAt", hasEnd == ended, body)
	dao14c2Assert(t, "Duration", hasDuration == ended && (!ended || duration == float64(60)), body)
}

func TestDao14c2_W1(t *testing.T) {
	for _, entry := range []string{"Connector", "Legacy"} {
		for _, event := range []string{"expired", "evicted"} {
			for _, ended := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s.%s.EndedAt=%v", entry, event, ended), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						code, want := "", "expired"
						if event == "evicted" {
							code, want = "evicted_by_cap", "evicted_by_cap"
						}
						body := dao14c2Payload(t, event, entry, ended, code)
						dao14c2Assert(t, "EndReason", body["end_reason"] == want, body)
						dao14c2EndFields(t, body, event, ended)
					})
				})
			}
		}
	}
	// The reason-code scan remains shared with global webhooks, even for a
	// manually constructed evicted event without the tracker-added reason code.
	t.Run("Connector.evicted.ReasonFallback", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			body := dao14c2Payload(t, "evicted", "Connector", false, "")
			dao14c2Assert(t, "EndReason", body["end_reason"] == "expired", body)
		})
	})
}
func TestDao14c2_W2(t *testing.T) {
	for _, event := range []string{"confirmed", "updated", "type_upgrade"} {
		t.Run("NonEnd."+event, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				body := dao14c2Payload(t, event, "Connector", false, "evicted_by_cap")
				_, found := body["end_reason"]
				dao14c2Assert(t, "NoEndReason", !found, body)
				dao14c2EndFields(t, body, event, false)
			})
		})
	}
	for _, event := range []string{"expired", "evicted"} {
		for _, ended := range []bool{true, false} {
			t.Run(fmt.Sprintf("Global.%s.EndedAt=%v", event, ended), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					code, want := "", "expired"
					if event == "evicted" {
						code, want = "evicted_by_cap", "evicted_by_cap"
					}
					body := dao14c2Payload(t, event, "Global", ended, code)
					dao14c2Assert(t, "EndReason", body["end_reason"] == want, body)
					dao14c2EndFields(t, body, "attack_end", ended)
				})
			})
		}
	}
}
