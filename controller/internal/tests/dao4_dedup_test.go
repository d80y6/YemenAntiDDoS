package tests

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

// All HTTP stays in memory. Tests are deliberately not parallel because the
// clients share http.DefaultTransport (xDrop) or action.WebhookTransport. synctest.Wait drains dispatch
// goroutines without a sleep or a timing-dependent negative assertion.
type dao4Transport struct {
	mu       sync.Mutex
	requests []*http.Request
	status   int
	handler  func(*http.Request) int
}

func (d *dao4Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.requests = append(d.requests, r.Clone(r.Context()))
	status := d.status
	d.mu.Unlock()
	if d.handler != nil {
		status = d.handler(r)
	}
	if status == 0 {
		status = http.StatusOK
		if r.Method == "DELETE" {
			status = http.StatusNoContent
		}
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"rule-1"}`)), Request: r}, nil
}
func (d *dao4Transport) count() int      { d.mu.Lock(); defer d.mu.Unlock(); return len(d.requests) }
func (d *dao4Transport) setStatus(n int) { d.mu.Lock(); defer d.mu.Unlock(); d.status = n }
func dao4HTTP(t *testing.T) *dao4Transport {
	t.Helper()
	d := &dao4Transport{}
	oldDefault, oldWebhook := http.DefaultTransport, action.WebhookTransport
	http.DefaultTransport, action.WebhookTransport = d, d
	t.Cleanup(func() {
		http.DefaultTransport, action.WebhookTransport = oldDefault, oldWebhook
	})
	return d
}
func dao4Fixture(kind, mode, phase string) (*MockStore, *action.Engine, tracker.AttackEvent) {
	ms := NewMockStore()
	ms.responses.responses = []store.Response{{ID: 1, Name: "dao4", Enabled: true}}
	ms.responses.actions = []store.ResponseAction{{ID: 10, ResponseID: 1, ActionType: kind, TriggerPhase: phase, RunMode: mode, Enabled: true, Execution: "automatic", Config: []byte(`{"url":"http://dao4.invalid/webhook"}`), XDropAction: "drop"}}
	return ms, action.NewEngine(ms, "auto"), tracker.AttackEvent{Type: "confirmed", DBID: 20, Attack: &store.Attack{ID: 20, ResponseID: intPtr(1), DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", AttackType: "udp_flood", PeakPPS: 100, StartedAt: time.Now()}}
}
func dao4Emit(t *testing.T, ms *MockStore, e *action.Engine, event tracker.AttackEvent, kind string) {
	t.Helper()
	event.Type = kind
	e.HandleEvent(event)
	synctest.Wait()
	b := &mockContractBackend{ms: ms}
	for _, row := range ms.actionExecLog.snapshotLogs() {
		if err := b.SetTime("action_execution_log", "id", row.ID, "executed_at", time.Now().Add(-time.Hour+time.Duration(row.ID)*time.Nanosecond)); err != nil {
			t.Fatal(err)
		}
	}
}
func dao4Log(t *testing.T, ms *MockStore, status string, connector *int) {
	t.Helper()
	act, err := ms.Responses().GetAction(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ms.ActionExecLog().Create(context.Background(), &store.ActionExecutionLog{AttackID: 20, ActionID: 10, ActionType: act.ActionType, TriggerPhase: "on_detected", Status: status, ConnectorID: connector, ExecutedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
}
func dao4WantCount(t *testing.T, d *dao4Transport, want int) {
	t.Helper()
	if got := d.count(); got != want {
		t.Fatalf("HTTP requests = %d; want %d", got, want)
	}
}

func TestDao4_B1_RetrySuccessSkipSkip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, e, ev := dao4Fixture("webhook", "retry_until_success", "on_detected")
		dao4Emit(t, ms, e, ev, "confirmed")
		dao4Emit(t, ms, e, ev, "updated")
		dao4Emit(t, ms, e, ev, "updated")
		dao4WantCount(t, d, 1)
	})
}
func TestDao4_B1b_RetryTypeUpgrade(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, e, ev := dao4Fixture("webhook", "retry_until_success", "on_detected")
		dao4Emit(t, ms, e, ev, "confirmed")
		dao4Emit(t, ms, e, ev, "type_upgrade")
		dao4WantCount(t, d, 1)
	})
}
func TestDao4_B1c_RetryFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		d.setStatus(500)
		ms, e, ev := dao4Fixture("webhook", "retry_until_success", "on_detected")
		dao4Emit(t, ms, e, ev, "confirmed")
		d.setStatus(200)
		dao4Emit(t, ms, e, ev, "updated")
		dao4WantCount(t, d, 2)
	})
}
func TestDao4_B1d_RetryOnlySkipped(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, e, ev := dao4Fixture("webhook", "retry_until_success", "on_detected")
		dao4Log(t, ms, "skipped", nil)
		dao4Emit(t, ms, e, ev, "updated")
		dao4WantCount(t, d, 1)
	})
}
func TestDao4_B2_OncePreconditionSkipCoversSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, e, ev := dao4Fixture("webhook", "once", "on_detected")
		_, err := ms.Preconditions().Create(context.Background(), &store.ActionPrecondition{ActionID: 10, Attribute: "pps", Operator: "gt", Value: "50"})
		if err != nil {
			t.Fatal(err)
		}
		dao4Emit(t, ms, e, ev, "confirmed")
		dao4WantCount(t, d, 1)
		ev.Attack.PeakPPS = 1
		dao4Emit(t, ms, e, ev, "type_upgrade")
		logs := ms.actionExecLog.snapshotLogs()
		if logs[len(logs)-1].SkipReason != action.SkipReasonPreconditionNotMatched {
			t.Fatal("seed did not write precondition skip")
		}
		ev.Attack.PeakPPS = 100
		dao4Emit(t, ms, e, ev, "type_upgrade")
		dao4WantCount(t, d, 1)
	})
}
func TestDao4_B2b_OnceOnlyFailed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, e, ev := dao4Fixture("webhook", "once", "on_detected")
		dao4Log(t, ms, "failed", nil)
		dao4Emit(t, ms, e, ev, "type_upgrade")
		dao4WantCount(t, d, 1)
	})
}
