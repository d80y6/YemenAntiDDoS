package action

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

const dao9bURL = "https://hooks.example/dao9b?token=private-url"
const dao9bSecret = "private-header"

type dao9bStore struct {
	store.Store
	connectors []store.WebhookConnector
	rows       []store.ActionExecutionLog
	createErrs []error
}
type dao9bConnectors struct {
	store.WebhookConnectorRepo
	s *dao9bStore
}
type dao9bResponses struct{ store.ResponseRepo }
type dao9bExecLogs struct {
	store.ActionExecLogRepo
	s *dao9bStore
}

func (s *dao9bStore) WebhookConnectors() store.WebhookConnectorRepo { return dao9bConnectors{s: s} }
func (s *dao9bStore) Responses() store.ResponseRepo                 { return dao9bResponses{} }
func (s *dao9bStore) ActionExecLog() store.ActionExecLogRepo        { return dao9bExecLogs{s: s} }
func (r dao9bConnectors) Get(_ context.Context, id int) (*store.WebhookConnector, error) {
	for _, c := range r.s.connectors {
		if c.ID == id {
			return &c, nil
		}
	}
	return nil, errors.New("missing connector")
}
func (r dao9bConnectors) ListGlobal(context.Context) ([]store.WebhookConnector, error) {
	return r.s.connectors, nil
}
func (dao9bResponses) Get(context.Context, int) (*store.Response, error) {
	return &store.Response{Name: "dao9b"}, nil
}
func (r dao9bExecLogs) Create(ctx context.Context, row *store.ActionExecutionLog) (int, error) {
	r.s.rows = append(r.s.rows, *row)
	r.s.createErrs = append(r.s.createErrs, ctx.Err())
	return len(r.s.rows), nil
}

func dao9bConnector(method string, ms int) store.WebhookConnector {
	return store.WebhookConnector{ID: 91, Name: "dao9b", URL: dao9bURL, Method: method, TimeoutMs: ms,
		Headers: json.RawMessage(`{"Authorization":"private-header"}`), Enabled: true, Global: true}
}
func dao9bEvent() tracker.AttackEvent {
	return tracker.AttackEvent{Type: "confirmed", DBID: 92, Attack: &store.Attack{ID: 92, DstIP: "192.0.2.9", DecoderFamily: "udp", AttackType: "udp_flood", Severity: "high", StartedAt: time.Now().Add(-time.Minute)}}
}
func dao9bAction(ctx context.Context, s *dao9bStore, fa *FlowAnalysis) {
	cid := s.connectors[0].ID
	NewEngine(s, "auto").executeAction(ctx, dao9bEvent(), store.ResponseAction{ID: 93, ResponseID: 94, ActionType: "webhook", WebhookConnectorID: &cid, TriggerPhase: "on_detected"}, fa)
}
func dao9bTransport(t *testing.T, fn dao3RoundTrip) {
	t.Helper()
	old, fallback := WebhookTransport, http.DefaultTransport
	WebhookTransport = fn
	// M5 must fail locally, even if the production client omits its transport.
	http.DefaultTransport = dao3RoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("dao9b default transport blocked") })
	t.Cleanup(func() { WebhookTransport = old; http.DefaultTransport = fallback })
}
func dao9bOK(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
}
func dao9bRow(t *testing.T, s *dao9bStore, status string) store.ActionExecutionLog {
	t.Helper()
	if len(s.rows) != 1 || len(s.createErrs) != 1 {
		t.Fatalf("execution Create calls=%d context observations=%d want=1", len(s.rows), len(s.createErrs))
	}
	row := s.rows[0]
	if row.Status != status {
		t.Errorf("execution status=%q want=%q", row.Status, status)
	}
	if strings.Contains(row.ErrorMessage, dao9bURL) || strings.Contains(row.ErrorMessage, "private-url") || strings.Contains(row.ErrorMessage, dao9bSecret) {
		t.Errorf("unsafe error=%q", row.ErrorMessage)
	}
	return row
}

func TestDao9b_W1_ActionPUTBody(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var bodies [][]byte
		var methods []string
		dao9bTransport(t, func(r *http.Request) (*http.Response, error) {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			bodies = append(bodies, b)
			methods = append(methods, r.Method)
			if r.Header.Get("Authorization") != dao9bSecret {
				t.Error("stored header missing")
			}
			return dao9bOK(r)
		})
		fa := &FlowAnalysis{TopSrcIPs: []string{"198.51.100.1"}, UniqueSrcIPs: 1}
		for _, method := range []string{"POST", "PUT"} {
			s := &dao9bStore{connectors: []store.WebhookConnector{dao9bConnector(method, 200)}}
			before := len(methods)
			dao9bAction(context.Background(), s, fa)
			if len(methods)-before != 1 {
				t.Fatalf("requests per action=%d want=1", len(methods)-before)
			}
			if methods[before] != method {
				t.Errorf("method=%q want=%q", methods[before], method)
			}
			dao9bRow(t, s, "success")
		}
		if !bytes.Equal(bodies[0], bodies[1]) {
			t.Errorf("PUT body differs from POST: %s / %s", bodies[1], bodies[0])
		}
		var payload map[string]any
		if err := json.Unmarshal(bodies[1], &payload); err != nil {
			t.Fatal(err)
		}
		if payload["attack_id"] != float64(92) || payload["event"] != "confirmed" || payload["dst_ip"] != "192.0.2.9" || payload["decoder"] != "udp" || payload["unique_src_ips"] != float64(1) {
			t.Errorf("payload lost attack/event/flow fields: %s", bodies[1])
		}
	})
}

func dao9bActionTimeout(t *testing.T, ms int, want time.Duration) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		logs := dao3Capture(t)
		calls := 0
		dao9bTransport(t, func(r *http.Request) (*http.Response, error) {
			calls++
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		s := &dao9bStore{connectors: []store.WebhookConnector{dao9bConnector("POST", ms)}}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		start := time.Now()
		dao9bAction(ctx, s, nil)
		elapsed := time.Since(start)
		if elapsed != want {
			t.Errorf("elapsed=%s want=%s", elapsed, want)
		}
		if calls != 1 {
			t.Errorf("transport calls=%d want=1", calls)
		}
		row := dao9bRow(t, s, "failed")
		if row.ErrorMessage != "timeout" {
			t.Errorf("error=%q want=timeout", row.ErrorMessage)
		}
		if row.DurationMs != int(want.Milliseconds()) {
			t.Errorf("duration_ms=%d want=%d", row.DurationMs, want.Milliseconds())
		}
		if s.createErrs[0] != nil {
			t.Errorf("Create ctx.Err()=%v want=nil", s.createErrs[0])
		}
		if strings.Contains(logs.String(), dao9bURL) || strings.Contains(logs.String(), dao9bSecret) {
			t.Errorf("unsafe application log=%s", logs.String())
		}
		t.Logf("elapsed=%s requests=%d status=%s error=%q Create calls=%d ctx.Err()=%v", elapsed, calls, row.Status, row.ErrorMessage, len(s.rows), s.createErrs[0])
	})
}
func TestDao9b_W2_ActionShortTimeout(t *testing.T)    { dao9bActionTimeout(t, 200, 200*time.Millisecond) }
func TestDao9b_W3_ActionZeroTimeout(t *testing.T)     { dao9bActionTimeout(t, 0, 10*time.Second) }
func TestDao9b_W4_ActionNegativeTimeout(t *testing.T) { dao9bActionTimeout(t, -5, 10*time.Second) }
func TestDao9b_W10_ActionTimeoutCapPreservesLogContext(t *testing.T) {
	dao9bActionTimeout(t, 60000, 10*time.Second)
}

func dao9bGlobal(t *testing.T, method string, ms int, want time.Duration) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		logs := dao3Capture(t)
		a, b := dao9bConnector(method, ms), dao9bConnector("", 0)
		b.ID = 95
		b.URL = dao9bURL + "-B"
		s := &dao9bStore{connectors: []store.WebhookConnector{a, b}}
		var methods []string
		var aElapsed time.Duration
		bSucceeded := false
		dao9bTransport(t, func(r *http.Request) (*http.Response, error) {
			methods = append(methods, r.Method)
			if len(methods) == 1 {
				start := time.Now()
				<-r.Context().Done()
				aElapsed = time.Since(start)
				return nil, r.Context().Err()
			}
			if err := r.Context().Err(); err != nil {
				return nil, err
			}
			bSucceeded = true
			return dao9bOK(r)
		})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		start := time.Now()
		NewEngine(s, "auto").fireGlobalWebhooks(ctx, dao9bEvent())
		if len(methods) != 2 {
			t.Fatalf("global requests=%d want=2", len(methods))
		}
		if methods[0] != method || methods[1] != "POST" {
			t.Errorf("methods=%v want=[%s POST]", methods, method)
		}
		if aElapsed != want || time.Since(start) != want {
			t.Errorf("A elapsed=%s total=%s want=%s", aElapsed, time.Since(start), want)
		}
		if !bSucceeded {
			t.Error("B did not succeed after A timeout")
		}
		text := logs.String()
		if strings.Count(text, "global webhook connector 91 failed: timeout") != 1 || strings.Count(text, "global webhook connector 95 sent: HTTP 200") != 1 || len(strings.Split(strings.TrimSpace(text), "\n")) != 2 {
			t.Errorf("want exactly A failed + B success application logs: %s", text)
		}
		if strings.Contains(text, dao9bURL) || strings.Contains(text, dao9bSecret) {
			t.Errorf("unsafe logs=%s", text)
		}
		if len(s.rows) != 0 {
			t.Errorf("global path wrote %d execution logs", len(s.rows))
		}
		t.Logf("methods=%v A elapsed=%s B success=%v application logs=\n%s", methods, aElapsed, bSucceeded, text)
	})
}
func TestDao9b_W5_GlobalPATCHThenDefaultPOST(t *testing.T) {
	dao9bGlobal(t, "PATCH", 300, 300*time.Millisecond)
}
func TestDao9b_W11_GlobalTimeoutCapAllowsNext(t *testing.T) {
	dao9bGlobal(t, "POST", 30000, 10*time.Second)
}

func TestDao9b_W6_ActionEmptyMethodDefaultsPOST(t *testing.T) {
	calls := 0
	dao9bTransport(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" {
			t.Errorf("method=%q want=POST", r.Method)
		}
		return dao9bOK(r)
	})
	s := &dao9bStore{connectors: []store.WebhookConnector{dao9bConnector("", 0)}}
	dao9bAction(context.Background(), s, nil)
	if calls != 1 {
		t.Errorf("requests=%d want=1", calls)
	}
	dao9bRow(t, s, "success")
}

func TestDao9b_W7_LegacyPUTTenSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		dao9bTransport(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "PUT" {
				t.Errorf("legacy method=%q want=PUT", r.Method)
			}
			<-r.Context().Done()
			return nil, r.Context().Err()
		})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		start := time.Now()
		_, err := executeWebhook(ctx, []byte(`{"url":"https://hooks.example/dao9b","method":"PUT"}`), dao9bEvent().Attack, "confirmed")
		if elapsed := time.Since(start); elapsed != 10*time.Second {
			t.Errorf("legacy elapsed=%s want=10s", elapsed)
		}
		if err == nil || err.Error() != "timeout" || calls != 1 {
			t.Errorf("legacy err=%v requests=%d", err, calls)
		}
		t.Logf("legacy elapsed=%s requests=%d error=%v", time.Since(start), calls, err)
	})
}

func TestDao9b_W9_SharedTransport(t *testing.T) {
	calls := 0
	dao9bTransport(t, func(r *http.Request) (*http.Response, error) { calls++; return dao9bOK(r) })
	s := &dao9bStore{connectors: []store.WebhookConnector{dao9bConnector("PUT", 200)}}
	dao9bAction(context.Background(), s, nil)
	if calls != 1 {
		t.Errorf("WebhookTransport calls=%d want=1", calls)
	}
	dao9bRow(t, s, "success")
}

func TestDao9b_W12_MethodNormalizationAndSafeWARN(t *testing.T) {
	totalWarns := 0
	for i, tc := range []struct {
		name, method, want string
		warn               bool
	}{
		{"post", "post", "POST", false}, {"spaced_put", " put ", "PUT", false}, {"GET", "GET", "POST", true}, {"invalid_token", "PO ST", "POST", true}, {"DELETE", "DELETE", "POST", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := dao3Capture(t)
			calls := 0
			dao9bTransport(t, func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != tc.want {
					t.Errorf("method=%q want=%q", r.Method, tc.want)
				}
				return dao9bOK(r)
			})
			wc := dao9bConnector(tc.method, 0)
			wc.ID += i
			if wc.URL == "" || len(wc.Headers) == 0 {
				t.Fatal("URL/header positive controls must be nonempty")
			}
			s := &dao9bStore{connectors: []store.WebhookConnector{wc}}
			dao9bAction(context.Background(), s, nil)
			if calls != 1 {
				t.Errorf("requests=%d want=1", calls)
			}
			dao9bRow(t, s, "success")
			text := logs.String()
			warns := 0
			for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
				if strings.Contains(line, "WARN") {
					warns++
					if !strings.Contains(line, fmt.Sprintf("connector %d", wc.ID)) {
						t.Errorf("WARN missing connector ID: %s", line)
					}
				}
			}
			wantWarns := 0
			if tc.warn {
				wantWarns = 1
			}
			if warns != wantWarns {
				t.Errorf("WARN lines=%d want=%d log=%q", warns, wantWarns, text)
			}
			totalWarns += warns
			if strings.Contains(text, wc.URL) || strings.Contains(text, "private-url") || strings.Contains(text, dao9bSecret) {
				t.Errorf("WARN leaked URL/headers: %s", text)
			}
		})
	}
	if totalWarns != 3 {
		t.Errorf("total WARN lines=%d want=3", totalWarns)
	}
}
