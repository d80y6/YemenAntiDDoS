package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

type dao3LogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *dao3LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *dao3LogBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func dao3Capture(t *testing.T) *dao3LogBuffer {
	t.Helper()
	b := &dao3LogBuffer{}
	old := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(old) })
	return b
}

type dao3BGPStore struct {
	*v3Store
	conn store.BGPConnector
	ann  *dao3BGPRepo
}
type dao3BGPConn struct {
	store.BGPConnectorRepo
	s *dao3BGPStore
}

func (s *dao3BGPStore) BGPConnectors() store.BGPConnectorRepo { return dao3BGPConn{s: s} }
func (r dao3BGPConn) Get(context.Context, int) (*store.BGPConnector, error) {
	c := r.s.conn
	return &c, nil
}
func (s *dao3BGPStore) BGPAnnouncements() store.BGPAnnouncementRepo     { return s.ann }
func (s *dao3BGPStore) ManualOverrides() store.ActionManualOverrideRepo { return dao4BGPOverrides{} }

type dao3BGPRepo struct {
	store.BGPAnnouncementRepo
	mu       sync.Mutex
	rows     []store.BGPAnnouncement
	failures []string
}

func (r *dao3BGPRepo) Attach(context.Context, store.BGPAttachParams) (store.BGPAttachResult, error) {
	return store.BGPAttachResult{AnnouncementID: 1, NeedAnnounce: true}, nil
}
func (r *dao3BGPRepo) Detach(context.Context, int, string, string, int) (store.BGPDetachResult, error) {
	return store.BGPDetachResult{AnnouncementID: 1, NeedWithdraw: true}, nil
}
func (r *dao3BGPRepo) MarkAnnounced(context.Context, int, int) error                { return nil }
func (r *dao3BGPRepo) MarkWithdrawn(context.Context, int, int) error                { return nil }
func (r *dao3BGPRepo) AppendEvent(context.Context, int, string, *int, string) error { return nil }
func (r *dao3BGPRepo) fail(msg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = append(r.failures, msg)
	return nil
}
func (r *dao3BGPRepo) MarkFailedAnnounce(_ context.Context, _ int, gen int, msg string) error {
	return r.fail(msg)
}
func (r *dao3BGPRepo) MarkFailedWithdraw(_ context.Context, _ int, gen int, msg string) error {
	return r.fail(msg)
}
func (r *dao3BGPRepo) ListActive(context.Context) ([]store.BGPAnnouncement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]store.BGPAnnouncement(nil), r.rows...), nil
}
func (r *dao3BGPRepo) FindByBusinessKey(context.Context, string, string, int) (*store.BGPAnnouncement, error) {
	return nil, nil
}
func (r *dao3BGPRepo) failureText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.failures, "\n")
}
func dao3BGPFixture(t *testing.T) (*dao3BGPStore, store.ResponseAction, string) {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "calls")
	script := filepath.Join(dir, "vtysh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 'called\\n' >> '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cid := 7
	act := store.ResponseAction{ID: 10, ActionType: "bgp", BGPConnectorID: &cid, BGPRouteMap: "RTBH", TriggerPhase: "on_detected"}
	s := &dao3BGPStore{v3Store: newV3Store("http://unused.invalid"), conn: store.BGPConnector{ID: 7, Enabled: true, BGPASN: 64512, VtyshPath: script}, ann: &dao3BGPRepo{}}
	s.actions = []store.ResponseAction{act}
	return s, act, marker
}
func dao3Marker(t *testing.T, path string, want int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "called\n"); got != want {
		t.Errorf("vtysh invocations=%d want=%d", got, want)
	}
}
func TestDao3_T1e_ExecutionGuards(t *testing.T) {
	for _, path := range []string{"announce", "withdraw", "orphan", "recover_active", "recover_delayed", "retry", "force_remove"} {
		for _, field := range []string{"route_map", "prefix"} {
			t.Run(path+"/"+field, func(t *testing.T) {
				s, act, marker := dao3BGPFixture(t)
				logs := dao3Capture(t)
				prefix, routeMap := "192.0.2.1/32", "RTBH"
				bad := "BAD\nINJECT"
				if field == "prefix" {
					prefix = bad
				} else {
					routeMap = bad
				}
				act.BGPRouteMap = routeMap
				ann := store.BGPAnnouncement{ID: 1, ConnectorID: 7, Prefix: prefix, RouteMap: routeMap, Status: "active"}
				ctx := context.Background()
				var entry *store.ActionExecutionLog
				var err error
				wantCalls := 0
				switch path {
				case "announce":
					entry, err = bgpAnnounce(ctx, s, nil, &s.conn, act, prefix, 20, "test", "on_detected")
				case "withdraw":
					entry, err = bgpWithdraw(ctx, s, nil, &s.conn, act, prefix, 20, "test", "on_expired")
				case "orphan":
					entry, err = PerformBGPWithdrawForOrphan(ctx, s, &s.conn, act, prefix, routeMap, 1, 0)
				case "recover_active", "recover_delayed":
					ann.Status = strings.TrimPrefix(path, "recover_")
					s.ann.rows = []store.BGPAnnouncement{ann, {ID: 2, ConnectorID: 7, Prefix: "192.0.2.2/32", RouteMap: "RTBH", Status: ann.Status}}
					RecoverBGPRoutes(ctx, s)
					wantCalls = 1
				case "retry":
					NewEngine(s, "auto").retryBGPAnnounce(ann)
				case "force_remove":
					err = NewEngine(s, "auto").ForceRemove(ctx, 20, 10, 7, prefix+"|"+routeMap)
				}
				dao3Marker(t, marker, wantCalls)
				failure := s.ann.failureText() + logs.String()
				if err != nil {
					failure += err.Error()
				}
				if entry != nil {
					if entry.Status != "failed" {
						t.Errorf("status=%s want failed", entry.Status)
					}
					failure += entry.ErrorMessage
				}
				if !strings.Contains(failure, "unsafe vtysh token") || strings.Contains(failure, bad) {
					t.Errorf("missing safe failure or raw token exposed: %q", failure)
				}
				if (path == "announce" || path == "withdraw" || path == "orphan" || path == "force_remove") && err == nil {
					t.Error("expected error")
				}
			})
		}
	}
	t.Run("tab", func(t *testing.T) {
		s, a, marker := dao3BGPFixture(t)
		a.BGPRouteMap = "RT\tBH"
		entry, err := bgpAnnounce(context.Background(), s, nil, &s.conn, a, "192.0.2.1/32", 20, "test", "on_detected")
		dao3Marker(t, marker, 0)
		if err == nil || entry == nil || entry.Status != "failed" || !strings.Contains(entry.ErrorMessage, "unsafe vtysh token") || strings.Contains(entry.ErrorMessage, a.BGPRouteMap) {
			t.Fatalf("entry=%+v err=%v", entry, err)
		}
	})
}
func TestDao3_T1f_VisibleFRRNameAllowed(t *testing.T) {
	s, a, marker := dao3BGPFixture(t)
	a.BGPRouteMap = "RTBH:v4"
	entry, err := bgpAnnounce(context.Background(), s, nil, &s.conn, a, "192.0.2.1/32", 20, "test", "on_detected")
	if err != nil || entry == nil || entry.Status != "success" {
		t.Fatalf("entry=%+v err=%v", entry, err)
	}
	dao3Marker(t, marker, 1)
}

type dao3WebhookStore struct {
	*v3Store
	wc store.WebhookConnector
}
type dao3WebhookRepo struct {
	store.WebhookConnectorRepo
	s *dao3WebhookStore
}

func (s *dao3WebhookStore) WebhookConnectors() store.WebhookConnectorRepo {
	return dao3WebhookRepo{s: s}
}
func (r dao3WebhookRepo) Get(context.Context, int) (*store.WebhookConnector, error) {
	c := r.s.wc
	return &c, nil
}
func (r dao3WebhookRepo) ListGlobal(context.Context) ([]store.WebhookConnector, error) {
	return []store.WebhookConnector{r.s.wc}, nil
}

type dao3RoundTrip func(*http.Request) (*http.Response, error)

func (f dao3RoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDao3_T4h_WebhookErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
	}{{"1_bad_headers", "", 200}, {"2_connection", "", 0}, {"3_success", "", 200}, {"4_bearer", "Bearer t0ken", 400}, {"5_escaped", `{"token":"t0\"ken"}`, 400}, {"6_url", "https://hooks.example/hook?token=s3cret", 400}, {"7_redirect", "", 302}, {"8_bare", "t0ken", 400}} {
		t.Run(tc.name, func(t *testing.T) {
			logs := dao3Capture(t)
			old := WebhookTransport
			t.Cleanup(func() { WebhookTransport = old })
			calls := 0
			headers := json.RawMessage(`{"Authorization":"Bearer t0ken"}`)
			if tc.name == "1_bad_headers" {
				headers = json.RawMessage(`"t0ken"`)
			}
			if tc.name == "5_escaped" {
				headers = json.RawMessage(`{"Authorization":"t0\"ken"}`)
			}
			WebhookTransport = dao3RoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if tc.code == 0 {
					return nil, fmt.Errorf("dial: %s Bearer t0ken", r.URL)
				}
				h := make(http.Header)
				if tc.code == 302 {
					h.Set("Location", "https://hooks.example/%zz?token=s3cret&echo=Bearer%20t0ken")
				}
				return &http.Response{StatusCode: tc.code, Header: h, Body: io.NopCloser(strings.NewReader(tc.body)), Request: r}, nil
			})
			s := &dao3WebhookStore{v3Store: newV3Store("http://unused.invalid"), wc: store.WebhookConnector{ID: 7, URL: "https://hooks.example/hook?token=s3cret", Headers: headers, Enabled: true}}
			e := NewEngine(s, "auto")
			ev := tracker.AttackEvent{Type: "confirmed", DBID: 20, Attack: &store.Attack{ID: 20, DstIP: "192.0.2.1"}}
			cid := 7
			e.fireGlobalWebhooks(context.Background(), ev)
			e.executeAction(context.Background(), ev, store.ResponseAction{ID: 10, ActionType: "webhook", WebhookConnectorID: &cid, TriggerPhase: "on_detected"}, nil)
			if calls != 2 {
				t.Fatalf("send attempts=%d want global+action", calls)
			}
			rows := s.logSnapshot()
			if len(rows) != 1 {
				t.Fatalf("execution records=%d", len(rows))
			}
			b, _ := json.Marshal(rows)
			for _, secret := range []string{"s3cret", "t0ken", `t0\"ken`} {
				if strings.Contains(logs.String(), secret) || strings.Contains(string(b), secret) {
					t.Errorf("secret %q in logs=%s executions=%s", secret, logs.String(), b)
				}
			}
			if tc.code == 400 && rows[0].ErrorMessage != "HTTP 400" {
				t.Errorf("error=%q want HTTP 400", rows[0].ErrorMessage)
			}
			if tc.code == 302 && rows[0].ErrorMessage != "redirect error" && rows[0].ErrorMessage != "transport error" {
				t.Errorf("unsafe redirect error=%q", rows[0].ErrorMessage)
			}
			if tc.code == 200 && rows[0].Status != "success" {
				t.Errorf("200 status=%s", rows[0].Status)
			}
		})
	}
}
