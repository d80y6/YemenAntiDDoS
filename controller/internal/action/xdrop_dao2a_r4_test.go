package action

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type d2R4Log struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *d2R4Log) Write(p []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.b.Write(p) }
func (b *d2R4Log) text() string                { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func d2R4Capture(t *testing.T) *d2R4Log {
	t.Helper()
	b := &d2R4Log{}
	old := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(old) })
	return b
}

type d2R4ScanStore struct {
	*d2Store
	before, resume chan struct{}
}
type d2R4ScanRules struct {
	d2Rules
	f *d2R4ScanStore
}

func (s *d2R4ScanStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2R4ScanRules{d2Rules{v3Active{s: s.v3Store}, s.d2Store}, s}
}
func (r d2R4ScanRules) ListWithdrawing(c context.Context) ([]store.XDropActiveRule, error) {
	close(r.f.before)
	<-r.f.resume
	return r.d2Rules.ListWithdrawing(c)
}
func TestD2A_B24_SnapshotInterleaveKeepsBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		captured := d2R4Capture(t)
		s, _, sa := d2Fixture(t, "withdrawing")
		f := &d2R4ScanStore{d2Store: s, before: make(chan struct{}), resume: make(chan struct{})}
		e := NewEngine(f, "auto")
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		d2HTTP(t, func(*http.Request) (*http.Response, error) {
			if calls.Add(1) == 1 {
				close(entered)
				<-release
			}
			return d2Reply(503, `{"code":"unavailable"}`), nil
		})
		go func() { e.executeRecoveredXDropUnblock(context.Background(), sa); close(done) }()
		<-entered
		scanDone := make(chan struct{})
		go func() { e.reconcileXDropRound(context.Background()); close(scanDone) }()
		<-f.before
		close(release)
		<-done
		if !e.xdropBackoff(xdropKeyFromSchedule(sa)) {
			t.Fatal("device: first attempt did not establish backoff")
		}
		close(f.resume)
		<-scanDone
		e.executeRecoveredXDropUnblock(context.Background(), sa)
		time.Sleep(xdropReconcileInterval - time.Second)
		e.executeRecoveredXDropUnblock(context.Background(), sa)
		if calls.Load() != 1 {
			t.Errorf("before retry eligibility DELETE=%d want=1", calls.Load())
		}
		if got := strings.Count(captured.text(), "attempt=1 "); got != 1 {
			t.Errorf("attempt reset before eligibility: count=%d", got)
		}
		time.Sleep(time.Second)
		e.executeRecoveredXDropUnblock(context.Background(), sa)
		if calls.Load() != 2 || !strings.Contains(captured.text(), "attempt=2 ") {
			t.Errorf("eligible attempt must preserve history: DELETE=%d logs=%s", calls.Load(), captured.text())
		}
	})
}

type d2R4DetailStore struct{ *d2Store }
type d2R4DetailRules struct{ d2Rules }

func (s *d2R4DetailStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2R4DetailRules{d2Rules{v3Active{s: s.v3Store}, s.d2Store}}
}
func (r d2R4DetailRules) MarkFailed(c context.Context, a, b, d int, id, msg string) error {
	if err := r.d2Rules.MarkFailed(c, a, b, d, id, msg); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := v3RuleKey(a, b, d, id)
	row := r.s.rules[key]
	row.ErrorMessage = msg
	r.s.rules[key] = row
	return nil
}
func TestD2A_B25_DeleteErrorRedaction(t *testing.T) {
	for _, kind := range []string{"json_503", "plain_404", "malformed_location_301", "transport_error"} {
		t.Run(kind, func(t *testing.T) {
			captured := d2R4Capture(t)
			s, _, sa := d2Fixture(t, "active")
			s.conn.APIKey = "r4-obviously-fake-credential-0123456789"
			secret := s.conn.APIKey
			e := NewEngine(&d2R4DetailStore{s}, "auto")
			requestURL := s.conn.APIURL + "/rules/rule-draft?claim_ref=a101.x11"
			var calls atomic.Int32
			d2HTTP(t, func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				reflected := "request " + r.URL.String() + " credential " + secret + " peer https://user:" + secret + "@192.0.2.21/path"
				switch kind {
				case "json_503":
					body, _ := json.Marshal(map[string]string{"code": "upstream_error", "field": "rule_id", "message": reflected})
					return d2Reply(503, string(body)), nil
				case "plain_404":
					return d2Reply(404, reflected), nil
				case "transport_error":
					return nil, &url.Error{Op: "parse", URL: requestURL, Err: errors.New(reflected)}
				default:
					resp := d2Reply(301, "")
					resp.Header.Set("Location", "http://user:"+secret+"@192.0.2.21/%zz")
					return resp, nil
				}
			})
			forceErr := e.ForceRemove(context.Background(), 101, 11, 7, "rule-draft")
			if forceErr == nil {
				t.Fatal("missing ForceRemove failure")
			}
			e.executeRecoveredXDropUnblock(context.Background(), sa)
			if calls.Load() != 2 {
				t.Fatalf("DELETE=%d want ForceRemove+automatic=2 and no redirect hop", calls.Load())
			}
			d2Status(t, s, "failed")
			rows, err := s.XDropActiveRules().ListByAttack(context.Background(), 101)
			if err != nil || len(rows) != 1 {
				t.Fatal("missing row")
			}
			logs := s.logSnapshot()
			if len(logs) != 1 || logs[0].Status != "failed" {
				t.Fatalf("execution logs=%+v", logs)
			}
			detail := forceErr.Error()
			destinations := map[string]string{"force": detail, "rule": rows[0].ErrorMessage, "execution": logs[0].ErrorMessage, "server": captured.text()}
			for name, text := range destinations {
				for _, forbidden := range []string{secret, "user:", requestURL, "http://", "https://"} {
					if strings.Contains(text, forbidden) {
						t.Errorf("%s exposes %q: %s", name, forbidden, text)
					}
				}
				if !strings.Contains(text, detail) {
					t.Errorf("%s did not receive same sanitized detail: %s", name, text)
				}
			}
			if kind == "json_503" {
				for _, want := range []string{"HTTP 503", "upstream_error", "field=rule_id", "request <url>", "[redacted]"} {
					if !strings.Contains(detail, want) {
						t.Errorf("lost safe diagnostic %q: %s", want, detail)
					}
				}
			}
			if kind == "plain_404" && !strings.Contains(detail, "DELETE route not found; check connector API URL (expected versioned API base)") {
				t.Error("404 diagnostic changed")
			}
			if (kind == "transport_error" || kind == "malformed_location_301") && !strings.Contains(detail, "result unknown; will retry") {
				t.Error("unknown result diagnostic missing")
			}
		})
	}
}

type d2R4NoEffectStore struct {
	*d2Store
	writes atomic.Int32
}
type d2R4NoEffectRules struct {
	d2Rules
	f *d2R4NoEffectStore
}

func (s *d2R4NoEffectStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2R4NoEffectRules{d2Rules{v3Active{s: s.v3Store}, s.d2Store}, s}
}
func (r d2R4NoEffectRules) MarkWithdrawn(context.Context, int, int, int, string) error {
	r.f.writes.Add(1)
	return nil
}
func (r d2R4NoEffectRules) MarkFailed(context.Context, int, int, int, string, string) error {
	r.f.writes.Add(1)
	return nil
}
func TestD2A_B06_NoEffectTerminalWrite(t *testing.T) {
	for _, code := range []int{204, 503} {
		name, op := "mark_withdrawn", "xdrop_mark_withdrawn"
		if code == 503 {
			name, op = "mark_failed", "xdrop_mark_failed"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, _, sa := d2Fixture(t, "active")
				f := &d2R4NoEffectStore{d2Store: s}
				e := NewEngine(f, "auto")
				before := d2Metric(op)
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(code, ""), nil })
				e.executeRecoveredXDropUnblock(context.Background(), sa)
				if f.writes.Load() != 3 {
					t.Errorf("nil/no-effect writes=%d want=3", f.writes.Load())
				}
				d2Status(t, s, "withdrawing")
				if d2LogCount(s, "success") != 0 || d2LogCount(s, "failed") != 1 {
					t.Error("unconfirmed write logged success")
				}
				if d2Metric(op)-before != 1 {
					t.Error("missing exhausted state-write metric")
				}
				if calls.Load() != 1 {
					t.Error("write retry repeated HTTP")
				}
			})
		})
	}
}
func TestD2A_B26_ScheduleQueryDiagnostic(t *testing.T) {
	for _, outer := range []bool{false, true} {
		name := "helper"
		if outer {
			name = "child"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				captured := d2R4Capture(t)
				s, e, sa := d2FaultFixture(t, "active")
				s.scheduleErr.Store(true)
				s.actions[0].UnblockDelayMinutes = 1
				before := testutil.ToFloat64(metrics.XDropReconcile.WithLabelValues("list_error"))
				d2HTTP(t, func(*http.Request) (*http.Response, error) {
					t.Error("query failure sent DELETE")
					return d2Reply(204, ""), nil
				})
				if outer {
					row, err := executeXDrop(context.Background(), s, s.actions[1], v3Attack(101, "udp", "198.51.100.7"), "expired", "198.51.100.7", "r4", "on_expired", 101, nil, e)
					if err == nil || row != nil || err.Error() != "xdrop action failed: "+xdropScheduleFailure {
						t.Errorf("child diagnostic: row=%+v err=%v", row, err)
					}
					childFailures := 0
					for _, entry := range s.logSnapshot() {
						if entry.ActionID == s.actions[1].ID && entry.Status == "failed" && entry.ErrorMessage == xdropScheduleFailure {
							childFailures++
						}
					}
					if childFailures != 1 {
						t.Errorf("child failed logs=%d want=1", childFailures)
					}
					if !strings.Contains(captured.text(), "delayed=0") {
						t.Error("outer summary counted unscheduled candidate")
					}
				} else {
					sa.ScheduledFor = time.Now().Add(time.Minute)
					persisted, err := e.scheduleXDrop(context.Background(), sa, "on_expired", "r4")
					if persisted || err == nil || err.Error() != xdropScheduleFailure {
						t.Error("query failure reported scheduled")
					}
				}
				if testutil.ToFloat64(metrics.XDropReconcile.WithLabelValues("list_error"))-before != 1 {
					t.Error("list_error increment must be one")
				}
				if !strings.Contains(captured.text(), "WARN") || !strings.Contains(captured.text(), xdropScheduleFailure) {
					t.Error("missing WARN diagnostic")
				}
				if len(s.schedules) != 0 {
					t.Error("schedule query failure created schedule")
				}
				d2Status(t, s.d2Store, "active")
				if d2LogCount(s.d2Store, "success") != 0 {
					t.Error("query failure recorded success")
				}
				d2LogContains(t, s.d2Store, xdropScheduleFailure)
			})
		})
	}
}

type d2R4PersistStore struct {
	*d2FaultStore
	entered, release chan struct{}
	once             sync.Once
	failed           atomic.Int32
}
type d2R4PersistSchedules struct {
	d2FaultSchedules
	f *d2R4PersistStore
}
type d2R4PersistRules struct {
	d2FaultRules
	f *d2R4PersistStore
}

func (s *d2R4PersistStore) ScheduledActions() store.ScheduledActionRepo {
	return d2R4PersistSchedules{d2FaultSchedules{d2Schedules{v3Schedules{s: s.v3Store}}, s.d2FaultStore}, s}
}
func (s *d2R4PersistStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2R4PersistRules{d2FaultRules{d2Rules{v3Active{s: s.v3Store}, s.d2Store}, s.d2FaultStore}, s}
}
func (r d2R4PersistSchedules) Schedule(context.Context, *store.ScheduledAction) (int, error) {
	r.f.once.Do(func() { close(r.f.entered) })
	<-r.f.release
	return 0, errors.New("injected schedule failure")
}
func (r d2R4PersistRules) MarkFailed(context.Context, int, int, int, string, string) error {
	r.f.failed.Add(1)
	return errors.New("injected pre-withdrawal MarkFailed failure")
}
func TestD2A_B27_UnpersistedDelaySweep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base, _, _ := d2FaultFixture(t, "active")
		base.actions[0].UnblockDelayMinutes = 1
		s := &d2R4PersistStore{d2FaultStore: base, entered: make(chan struct{}), release: make(chan struct{})}
		e := NewEngine(s, "auto")
		var calls atomic.Int32
		d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
		a := v3Attack(101, "udp", "198.51.100.7")
		id := 1
		a.ResponseID = &id
		event := tracker.AttackEvent{Type: "expired", DBID: 101, Attack: a}
		e.HandleEvent(event)
		<-s.entered
		synctest.Wait()
		e.HandleEvent(event)
		close(s.release)
		synctest.Wait()
		if s.failed.Load() == 0 || len(s.schedules) != 0 {
			t.Fatal("device: schedule and pre-withdrawal state write must fail")
		}
		if calls.Load() != 1 {
			t.Errorf("unpersisted delay must permit immediate ended sweep: DELETE=%d", calls.Load())
		}
		d2Status(t, s.d2Store, "withdrawn")
		if e.endingInFlight(101) {
			t.Error("child still holds endInflight")
		}
	})
}

type d2R5ConnectorStore struct {
	*d2Store
	getErr error
	gets   int
}
type d2R5Connectors struct {
	d2Conns
	f *d2R5ConnectorStore
}

func (s *d2R5ConnectorStore) XDropConnectors() store.XDropConnectorRepo {
	return d2R5Connectors{d2Conns{v3Connectors{s: s.v3Store}}, s}
}
func (r d2R5Connectors) Get(context.Context, int) (*store.XDropConnector, error) {
	r.f.gets++
	return nil, r.f.getErr
}

func TestD2A_B17_DeletedConnector(t *testing.T) {
	for _, origin := range []string{"ended-sweep", "recovered", "schedule"} {
		for _, kind := range []string{"nil_connector", "wrapped_no_rows", "query_error"} {
			t.Run(origin+"/"+kind, func(t *testing.T) {
				s, _, sa := d2Fixture(t, "active")
				f := &d2R5ConnectorStore{d2Store: s}
				if kind == "wrapped_no_rows" {
					f.getErr = fmt.Errorf("connector 7: %w", sql.ErrNoRows)
				} else if kind == "query_error" {
					f.getErr = errors.New("injected connector query failure")
				}
				e := NewEngine(f, "auto")
				before, err := s.XDropActiveRules().ListByAttack(context.Background(), sa.AttackID)
				if err != nil || len(before) != 1 {
					t.Fatal("device: missing active row")
				}
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
				counters := map[string]struct {
					read func() float64
					want float64
				}{
					"list_error": {read: func() float64 { return testutil.ToFloat64(metrics.XDropReconcile.WithLabelValues("list_error")) }},
					"skipped_connector": {read: func() float64 {
						return testutil.ToFloat64(metrics.XDropReconcile.WithLabelValues("skipped_connector"))
					}},
					"sweep_failed": {read: func() float64 { return testutil.ToFloat64(metrics.EndedSweep.WithLabelValues("xdrop", "failed")) }},
					"sweep_skipped": {read: func() float64 {
						return testutil.ToFloat64(metrics.EndedSweep.WithLabelValues("xdrop", "skipped_connector"))
					}},
				}
				for name, counter := range counters {
					want := float64(0)
					if kind == "query_error" && (name == "list_error" || name == "sweep_failed" && origin == "ended-sweep") ||
						kind != "query_error" && (name == "skipped_connector" && origin != "schedule" || name == "sweep_skipped" && origin == "ended-sweep") {
						want = 1
					}
					counter.want = counter.read() + want
					counters[name] = counter
				}
				switch origin {
				case "ended-sweep":
					e.sweepEndedXDrop(context.Background(), sa.AttackID)
				case "recovered":
					want := "skipped_connector"
					if kind == "query_error" {
						want = "list_error"
					}
					if got := e.withdrawXDropRule(context.Background(), sa, origin, "on_expired"); got != want {
						t.Errorf("outcome=%s want=%s", got, want)
					}
				case "schedule":
					durable, err := e.scheduleXDrop(context.Background(), sa, "on_expired", "")
					if durable || (err != nil) != (kind == "query_error") {
						t.Errorf("durable=%v err=%v", durable, err)
					}
				}
				for name, counter := range counters {
					if got := counter.read(); got != counter.want {
						t.Errorf("%s=%v want=%v", name, got, counter.want)
					}
				}
				after, err := s.XDropActiveRules().ListByAttack(context.Background(), sa.AttackID)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Errorf("rule changed: before=%+v after=%+v err=%v", before, after, err)
				}
				if f.gets != 1 || calls.Load() != 0 || len(s.schedules) != 0 {
					t.Errorf("Get=%d DELETE=%d schedules=%d", f.gets, calls.Load(), len(s.schedules))
				}
				logs := s.logSnapshot()
				if origin == "schedule" && kind == "query_error" {
					if len(logs) != 1 || logs[0].Status != "failed" || logs[0].ErrorMessage != xdropScheduleFailure {
						t.Errorf("query failure diagnostic=%+v", logs)
					}
				} else if len(logs) != 0 {
					t.Errorf("unexpected execution logs=%+v", logs)
				}
			})
		}
	}
}

type d2R6ScanStore struct {
	*d2Store
	before, resume chan struct{}
	intercept      atomic.Bool
}
type d2R6ScanRules struct {
	d2Rules
	f *d2R6ScanStore
}

func (s *d2R6ScanStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2R6ScanRules{d2Rules{v3Active{s: s.v3Store}, s.d2Store}, s}
}
func (r d2R6ScanRules) ListWithdrawing(c context.Context) ([]store.XDropActiveRule, error) {
	if r.f.intercept.Swap(false) {
		close(r.f.before)
		<-r.f.resume
	}
	return r.d2Rules.ListWithdrawing(c)
}

func TestD2A_B28_SnapshotKeepsDisabledObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, sa := d2Fixture(t, "withdrawing")
		f := &d2R6ScanStore{d2Store: s, before: make(chan struct{}), resume: make(chan struct{})}
		f.intercept.Store(true)
		e := NewEngine(f, "auto")
		e.xdropInterval = time.Second
		entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var calls atomic.Int32
		d2HTTP(t, func(*http.Request) (*http.Response, error) {
			n := calls.Add(1)
			if n < 4 {
				return d2Reply(503, "unavailable"), nil
			}
			if n == 4 {
				close(entered)
				<-release
				return d2Reply(503, "unavailable"), nil
			}
			return d2Reply(204, ""), nil
		})
		e.executeRecoveredXDropUnblock(context.Background(), sa)
		time.Sleep(time.Second)
		e.executeRecoveredXDropUnblock(context.Background(), sa)
		time.Sleep(2 * time.Second)
		e.executeRecoveredXDropUnblock(context.Background(), sa)
		time.Sleep(4 * time.Second)
		go func() { e.executeRecoveredXDropUnblock(context.Background(), sa); close(done) }()
		<-entered
		scanDone := make(chan struct{})
		go func() { e.reconcileXDropRound(context.Background()); close(scanDone) }()
		<-f.before // ListActive omitted withdrawing; second list has not run.
		close(release)
		<-done // Fourth failure establishes 8I backoff.
		s.setEnabled(false)
		if got := e.withdrawXDropRule(context.Background(), sa, "recovered", "on_expired"); got != "skipped_connector" {
			t.Fatal(got)
		}
		e.xdropMu.Lock()
		observed, seen := e.xdropEnabled[7]
		e.xdropMu.Unlock()
		if !seen || observed {
			t.Fatal("device: disabled state was not observed")
		}
		close(f.resume)
		<-scanDone
		e.xdropMu.Lock()
		_, seen = e.xdropEnabled[7]
		e.xdropMu.Unlock()
		if !seen || !e.xdropBackoff(xdropKeyFromSchedule(sa)) {
			t.Error("snapshot miss discarded disabled observation or unexpired backoff")
		}
		s.setEnabled(true)
		time.Sleep(time.Second)
		e.reconcileXDropRound(context.Background())
		synctest.Wait()
		t.Logf("next enabled round: DELETE=%d state=%s", calls.Load(), s.state(101, 11, "rule-draft"))
		if calls.Load() != 5 || s.state(101, 11, "rule-draft") != "withdrawn" {
			t.Error("observed false->true must regain eligibility on next round")
		}
		e.reconcileXDropRound(context.Background())
		synctest.Wait()
		e.xdropMu.Lock()
		_, retained := e.xdropEnabled[7]
		retries := len(e.xdropRetries)
		e.xdropMu.Unlock()
		if retained || retries != 0 || calls.Load() != 5 {
			t.Errorf("completed key was not reclaimed: observation=%v retries=%d DELETE=%d", retained, retries, calls.Load())
		}
	})
}
