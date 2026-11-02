package action

// 草稿门：只装测试，不装生产修复。HTTP 全部走内存 RoundTripper，禁止监听。
import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type d2Transport func(*http.Request) (*http.Response, error)

func (f d2Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func d2HTTP(t *testing.T, f d2Transport) {
	t.Helper()
	old := http.DefaultTransport
	http.DefaultTransport = f
	t.Cleanup(func() { http.DefaultTransport = old })
}
func d2Reply(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

type d2Store struct {
	*v3Store
	claimErr, terminalErr bool
	writes                atomic.Int32
	live                  bool
}
type d2Rules struct {
	v3Active
	d *d2Store
}
type d2Conns struct{ v3Connectors }
type d2Targets struct {
	store.XDropTargetRepo
	d *d2Store
}
type d2Attacks struct {
	store.AttackRepo
	d *d2Store
}
type d2Schedules struct{ v3Schedules }

func (s *d2Store) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2Rules{v3Active{s: s.v3Store}, s}
}
func (s *d2Store) XDropConnectors() store.XDropConnectorRepo {
	return d2Conns{v3Connectors{s: s.v3Store}}
}
func (s *d2Store) setEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.Enabled = enabled
}
func (r d2Conns) Get(c context.Context, id int) (*store.XDropConnector, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.v3Connectors.Get(c, id)
}
func (r d2Conns) ListEnabled(c context.Context) ([]store.XDropConnector, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return r.v3Connectors.ListEnabled(c)
}
func (s *d2Store) XDropTargets() store.XDropTargetRepo { return d2Targets{d: s} }
func (s *d2Store) Attacks() store.AttackRepo           { return d2Attacks{d: s} }
func (s *d2Store) ScheduledActions() store.ScheduledActionRepo {
	return d2Schedules{v3Schedules{s: s.v3Store}}
}
func (r d2Targets) List(context.Context, int) ([]store.XDropConnector, error) {
	r.d.mu.Lock()
	defer r.d.mu.Unlock()
	return []store.XDropConnector{r.d.conn}, nil
}
func (r d2Attacks) LiveIDs(_ context.Context, ids []int) (map[int]bool, error) {
	m := map[int]bool{}
	for _, id := range ids {
		m[id] = r.d.live
	}
	return m, nil
}
func (r d2Rules) ListActive(context.Context) ([]store.XDropActiveRule, error) {
	return r.list(false), nil
}
func (r d2Rules) ListWithdrawing(context.Context) ([]store.XDropActiveRule, error) {
	return r.list(true), nil
}
func (r d2Rules) list(w bool) []store.XDropActiveRule {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.XDropActiveRule
	for _, x := range r.s.rules {
		if (w && x.Status == "withdrawing") || (!w && (x.Status == "active" || x.Status == "delayed" || x.Status == "failed")) {
			out = append(out, x)
		}
	}
	return out
}
func (r d2Rules) MarkWithdrawing(c context.Context, a, b, d int, id string) (bool, error) {
	if r.d.claimErr {
		return false, errors.New("injected claim failure")
	}
	if err := c.Err(); err != nil {
		return false, err
	}
	return r.v3Active.MarkWithdrawing(c, a, b, d, id)
}
func (r d2Rules) MarkWithdrawn(c context.Context, a, b, d int, id string) error {
	r.d.writes.Add(1)
	if r.d.terminalErr {
		return errors.New("injected terminal failure")
	}
	if err := c.Err(); err != nil {
		return err
	}
	return r.v3Active.MarkWithdrawn(c, a, b, d, id)
}
func (r d2Rules) MarkFailed(c context.Context, a, b, d int, id, msg string) error {
	if err := c.Err(); err != nil {
		return err
	}
	return r.v3Active.MarkFailed(c, a, b, d, id, msg)
}
func (r d2Schedules) ListPending(context.Context) ([]store.ScheduledAction, error) {
	return r.list("pending"), nil
}
func (r d2Schedules) ListExecuting(context.Context) ([]store.ScheduledAction, error) {
	return r.list("executing"), nil
}
func (r d2Schedules) list(status string) []store.ScheduledAction {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.ScheduledAction
	for _, x := range r.s.schedules {
		if x.Status == status {
			out = append(out, x)
		}
	}
	return out
}

func d2Fixture(t *testing.T, status string) (*d2Store, *Engine, store.ScheduledAction) {
	t.Helper()
	s := &d2Store{v3Store: newV3Store("http://192.0.2.20/api/v1")}
	s.conn.APIKey = ""
	s.actions = []store.ResponseAction{{ID: 11, ResponseID: 1, ActionType: "xdrop", Enabled: true}, {ID: 12, ResponseID: 1, ActionType: "xdrop", XDropAction: "unblock", TriggerPhase: "on_expired", RunMode: "once", Enabled: true}}
	_, err := s.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: "rule-draft", Status: status})
	if err != nil {
		t.Fatal(err)
	}
	return s, NewEngine(s, "auto"), store.ScheduledAction{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: "rule-draft", ActionType: "xdrop_unblock"}
}
func d2Immediate(s *d2Store, e *Engine, c context.Context) {
	_, _ = executeXDrop(c, s, s.actions[1], v3Attack(101, "udp", "198.51.100.7"), "expired", "198.51.100.7", "draft", "on_expired", 101, nil, e)
}
func d2Status(t *testing.T, s *d2Store, want string) {
	t.Helper()
	if got := s.state(101, 11, "rule-draft"); got != want {
		t.Fatalf("status=%s want=%s", got, want)
	}
}
func d2LogContains(t *testing.T, s *d2Store, want string) {
	t.Helper()
	for _, l := range s.logSnapshot() {
		if strings.Contains(l.ErrorMessage, want) {
			return
		}
	}
	t.Fatalf("missing diagnostic %q in logs=%+v", want, s.logSnapshot())
}

func TestD2A_B01_Delete404(t *testing.T) {
	for _, path := range []string{"immediate", "recovered", "delayed"} {
		t.Run(path, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, sa := d2Fixture(t, "active")
				const key = "xdk_0000000000000000_dao2a_fake_auth"
				s.conn.APIKey = key
				var calls atomic.Int32
				d2HTTP(t, func(r *http.Request) (*http.Response, error) {
					calls.Add(1)
					if r.Method != "DELETE" || r.URL.Query().Get("claim_ref") != "a101.x11" {
						t.Error("wrong release identity")
					}
					if r.Header.Get("Authorization") != "Bearer "+key {
						t.Error("missing xDrop DELETE bearer")
					}
					return d2Reply(404, `{"code":"route_not_found","message":"route not found"}`), nil
				})
				switch path {
				case "immediate":
					d2Immediate(s, e, context.Background())
				case "recovered":
					e.executeRecoveredXDropUnblock(context.Background(), sa)
				case "delayed":
					s.actions[0].UnblockDelayMinutes = 1
					d2Immediate(s, e, context.Background())
					time.Sleep(time.Minute)
					synctest.Wait()
				}
				if calls.Load() != 1 {
					t.Fatalf("calls=%d want=1", calls.Load())
				}
				d2Status(t, s, "failed")
				d2LogContains(t, s, "route_not_found")
			})
		})
	}
}
func TestD2A_B02_ForceErrorMapping(t *testing.T) {
	s, e, _ := d2Fixture(t, "active")
	d2HTTP(t, func(*http.Request) (*http.Response, error) {
		return d2Reply(404, `{"code":"route_not_found","message":"route not found"}`), nil
	})
	err := e.ForceRemove(context.Background(), 101, 11, 7, "rule-draft")
	if err == nil || !strings.Contains(err.Error(), "route_not_found") {
		t.Fatalf("err=%v; want mapped route_not_found", err)
	}
	_ = s
}
func TestD2A_B03_TimeoutUniform(t *testing.T) {
	for _, path := range []string{"recovered_default", "delayed_configured", "force_configured"} {
		t.Run(path, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, sa := d2Fixture(t, "active")
				want := 750 * time.Millisecond
				s.conn.TimeoutMs = 750
				if path == "recovered_default" {
					s.conn.TimeoutMs = 0
					want = 10 * time.Second
				}
				var got time.Duration
				d2HTTP(t, func(r *http.Request) (*http.Response, error) {
					dl, ok := r.Context().Deadline()
					if !ok {
						t.Error("no HTTP deadline")
					}
					got = time.Until(dl)
					return d2Reply(204, ""), nil
				})
				switch path {
				case "recovered_default":
					e.executeRecoveredXDropUnblock(context.Background(), sa)
				case "force_configured":
					_ = e.ForceRemove(context.Background(), 101, 11, 7, "rule-draft")
				default:
					s.actions[0].UnblockDelayMinutes = 1
					d2Immediate(s, e, context.Background())
					time.Sleep(time.Minute)
					synctest.Wait()
				}
				if got != want {
					t.Fatalf("deadline=%s want=%s", got, want)
				}
			})
		})
	}
}
func TestD2A_B04_IndependentStateContext(t *testing.T) {
	s, e, sa := d2Fixture(t, "active")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d2HTTP(t, func(*http.Request) (*http.Response, error) { cancel(); return d2Reply(204, ""), nil })
	e.executeRecoveredXDropUnblock(ctx, sa)
	d2Status(t, s, "withdrawn")
}
func TestD2A_B05_ClaimFailureStopsHTTP(t *testing.T) {
	for _, path := range []string{"immediate", "recovered"} {
		t.Run(path, func(t *testing.T) {
			s, e, sa := d2Fixture(t, "active")
			s.claimErr = true
			var calls atomic.Int32
			d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
			if path == "immediate" {
				d2Immediate(s, e, context.Background())
			} else {
				e.executeRecoveredXDropUnblock(context.Background(), sa)
			}
			if calls.Load() != 0 {
				t.Fatalf("DELETE after failed claim: %d", calls.Load())
			}
		})
	}
}
func TestD2A_B06_TerminalWriteBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, sa := d2Fixture(t, "active")
		s.terminalErr = true
		before := testutil.ToFloat64(metrics.StateWriteFailures.WithLabelValues("xdrop_mark_withdrawn"))
		d2HTTP(t, func(*http.Request) (*http.Response, error) { return d2Reply(204, ""), nil })
		e.executeRecoveredXDropUnblock(context.Background(), sa)
		if n := s.writes.Load(); n != 3 {
			t.Errorf("terminal attempts=%d want=3", n)
		}
		for _, l := range s.logSnapshot() {
			if l.Status == "success" {
				t.Error("terminal persistence failed but logged success")
			}
		}
		d2Status(t, s, "withdrawing")
		if testutil.ToFloat64(metrics.StateWriteFailures.WithLabelValues("xdrop_mark_withdrawn"))-before != 1 {
			t.Error("missing terminal-write exhaustion metric")
		}
	})
}

// Only a 3xx response with Location triggers http.Client redirects; a 204 from the second hop must not count as a successful release.
const d2SecondHopHost = "192.0.2.21"

func TestD2A_B16_Only204Succeeds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		code     int
		location bool
	}{
		{"200", 200, false},
		{"301_no_location", 301, false},
		{"301_location", 301, true},
		{"307_location", 307, true},
		{"308_location", 308, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e, sa := d2Fixture(t, "active")
			var first, second int
			d2HTTP(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == d2SecondHopHost {
					second++
					return d2Reply(204, ""), nil
				}
				first++
				resp := d2Reply(tc.code, "unexpected response")
				if tc.location {
					resp.Header.Set("Location", "http://"+d2SecondHopHost+"/api/v1/rules/rule-draft?claim_ref=a101.x11")
				}
				return resp, nil
			})
			e.executeRecoveredXDropUnblock(context.Background(), sa)
			if first != 1 || second != 0 {
				t.Errorf("first hop=%d second hop=%d; want 1/0 (DELETE must not follow redirects)", first, second)
			}
			d2Status(t, s, "failed")
		})
	}
}

func TestD2A_B17_RuntimeSafety(t *testing.T) {
	for _, kind := range []string{"live", "future_schedule", "synthetic"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, sa := d2Fixture(t, "active")
				switch kind {
				case "live":
					s.live = true
				case "future_schedule":
					sa.ScheduledFor = time.Now().Add(time.Minute)
					_, _ = s.ScheduledActions().Schedule(context.Background(), &sa)
				case "synthetic":
					s.mu.Lock()
					s.rules = map[string]store.XDropActiveRule{}
					s.mu.Unlock()
					_, _ = s.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: "failed-create-101-11", Status: "failed"})
				}
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
				stop := d2Start(t, e)
				defer stop()
				time.Sleep(3 * time.Second)
				synctest.Wait()
				if calls.Load() != 0 {
					t.Fatalf("protected %s DELETE=%d", kind, calls.Load())
				}
				if kind == "synthetic" {
					rows, err := s.XDropActiveRules().ListByAttack(context.Background(), 101)
					if err != nil || len(rows) != 1 || rows[0].Status != "withdrawn" {
						t.Fatalf("no-log synthetic should close locally: rows=%+v err=%v", rows, err)
					}
				}
			})
		})
	}
}
func TestD2A_B07_Disabled(t *testing.T) {
	for _, path := range []string{"immediate", "recovered", "delayed"} {
		t.Run(path, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, sa := d2Fixture(t, "active")
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
				if path == "delayed" {
					s.actions[0].UnblockDelayMinutes = 1
					d2Immediate(s, e, context.Background())
					s.setEnabled(false)
					time.Sleep(time.Minute)
					synctest.Wait()
				} else {
					s.setEnabled(false)
					if path == "immediate" {
						d2Immediate(s, e, context.Background())
					} else {
						e.executeRecoveredXDropUnblock(context.Background(), sa)
					}
				}
				if calls.Load() != 0 {
					t.Fatalf("disabled connector DELETE=%d", calls.Load())
				}
				if s.state(101, 11, "rule-draft") == "withdrawn" {
					t.Fatal("disabled rule locally withdrawn")
				}
			})
		})
	}
}
func TestD2A_B08_ChildDoesNotSuppressSweep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _ := d2Fixture(t, "active")
		s.conn.ID = 8 // 子动作的目标漂移；规则仍属于连接器 7。
		// 覆写 Get 由专用连接器仓储提供原连接器；显式 targets 保持 8。
		ds := &d2DriftStore{d2Store: s}
		e = NewEngine(ds, "auto")
		var calls atomic.Int32
		d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
		a := v3Attack(101, "udp", "198.51.100.7")
		rid := 1
		a.ResponseID = &rid
		e.HandleEvent(tracker.AttackEvent{Type: "expired", DBID: 101, Attack: a})
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("old connector rule DELETE=%d want=1", calls.Load())
		}
	})
}

type d2DriftStore struct{ *d2Store }
type d2DriftConns struct {
	store.XDropConnectorRepo
	s *d2Store
}

func (s *d2DriftStore) XDropConnectors() store.XDropConnectorRepo { return d2DriftConns{s: s.d2Store} }
func (r d2DriftConns) Get(context.Context, int) (*store.XDropConnector, error) {
	c := r.s.conn
	c.ID = 7
	return &c, nil
}
func (r d2DriftConns) ListEnabled(context.Context) ([]store.XDropConnector, error) {
	return []store.XDropConnector{r.s.conn}, nil
}
func TestD2A_B09_ConcurrentRecovery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, sa := d2Fixture(t, "withdrawing")
		var entered, maxActive, active, calls atomic.Int32
		gate := make(chan struct{})
		d2HTTP(t, func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			v := active.Add(1)
			if v > maxActive.Load() {
				maxActive.Store(v)
			}
			entered.Add(1)
			<-gate
			active.Add(-1)
			return d2Reply(204, ""), nil
		})
		go e.executeRecoveredXDropUnblock(context.Background(), sa)
		synctest.Wait()
		if entered.Load() != 1 {
			t.Fatal("barrier not reached")
		}
		go e.executeRecoveredXDropUnblock(context.Background(), sa)
		synctest.Wait()
		close(gate)
		synctest.Wait()
		if maxActive.Load() != 1 || calls.Load() != 1 {
			t.Fatalf("max concurrent=%d total=%d want 1/1", maxActive.Load(), calls.Load())
		}
		d2Status(t, s, "withdrawn")
	})
}

// 接口断言让同一测试在 HEAD 编译；缺生产入口属于明确红，不是编译错误。
type d2Runner interface {
	RunXDropReconcile(context.Context, time.Duration)
}

func d2Start(t *testing.T, e *Engine) context.CancelFunc {
	t.Helper()
	r, ok := any(e).(d2Runner)
	if !ok {
		t.Fatal("HEAD lacks RunXDropReconcile: runtime behavior unavailable")
	}
	c, cancel := context.WithCancel(context.Background())
	go r.RunXDropReconcile(c, time.Second)
	synctest.Wait()
	return cancel
}
func TestD2A_B10_RuntimeStates(t *testing.T) {
	for _, status := range []string{"active", "failed", "withdrawing", "delayed"} {
		t.Run(status, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, _ := d2Fixture(t, status)
				var calls atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
				stop := d2Start(t, e)
				defer stop()
				time.Sleep(time.Second)
				synctest.Wait()
				d2Status(t, s, "withdrawn")
				if calls.Load() != 1 {
					t.Fatalf("calls=%d", calls.Load())
				}
			})
		})
	}
}
func TestD2A_B11_ReenableNextRound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _ := d2Fixture(t, "active")
		s.setEnabled(false)
		var calls atomic.Int32
		d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
		stop := d2Start(t, e)
		defer stop()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if calls.Load() != 0 {
			t.Fatal("disabled request")
		}
		s.setEnabled(true)
		time.Sleep(time.Second)
		synctest.Wait()
		d2Status(t, s, "withdrawn")
		if calls.Load() != 1 {
			t.Fatalf("reenable calls=%d", calls.Load())
		}
	})
}
func TestD2A_B12_Backoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _ := d2Fixture(t, "failed")
		var stamps []time.Time
		d2HTTP(t, func(*http.Request) (*http.Response, error) {
			stamps = append(stamps, time.Now())
			return d2Reply(503, `{"code":"unavailable","message":"retry"}`), nil
		})
		stop := d2Start(t, e)
		defer stop()
		time.Sleep(17 * time.Second)
		synctest.Wait()
		if len(stamps) < 3 || len(stamps) > 6 {
			t.Fatalf("calls=%d want 3..6", len(stamps))
		}
		for i := 2; i < len(stamps); i++ {
			gap := stamps[i].Sub(stamps[i-1])
			previous := stamps[i-1].Sub(stamps[i-2])
			if gap < previous {
				t.Fatalf("backoff regressed %s < %s", gap, previous)
			}
		}
		d2Status(t, s, "failed")
	})
}
func TestD2A_B13_OverduePending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, sa := d2Fixture(t, "delayed")
		sa.ScheduledFor = time.Now().Add(-time.Minute)
		_, _ = s.ScheduledActions().Schedule(context.Background(), &sa)
		d2HTTP(t, func(*http.Request) (*http.Response, error) { return d2Reply(204, ""), nil })
		stop := d2Start(t, e)
		defer stop()
		time.Sleep(time.Second)
		synctest.Wait()
		d2Status(t, s, "withdrawn")
		if p, _ := s.ScheduledActions().ListPending(context.Background()); len(p) != 0 {
			t.Fatal("pending schedule not finalized")
		}
	})
}

func TestD2A_B18_ReconcileAndEndOnlyOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, sa := d2Fixture(t, "active")
		gate := make(chan struct{})
		var calls, active, peak atomic.Int32
		d2HTTP(t, func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			n := active.Add(1)
			if n > peak.Load() {
				peak.Store(n)
			}
			<-gate
			active.Add(-1)
			return d2Reply(204, ""), nil
		})
		// 在 HEAD，能力缺失在开 HTTP 之前判红；交付列必须真走入屏障。
		stop := d2Start(t, e)
		defer stop()
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			close(gate)
			t.Fatal("runtime did not enter request barrier")
		}
		a := v3Attack(101, "udp", "198.51.100.7")
		rid := 1
		a.ResponseID = &rid
		e.HandleEvent(tracker.AttackEvent{Type: "expired", DBID: 101, Attack: a})
		go e.executeRecoveredXDropUnblock(context.Background(), sa)
		synctest.Wait()
		close(gate)
		synctest.Wait()
		if calls.Load() != 1 || peak.Load() != 1 {
			t.Fatalf("DELETE=%d concurrent=%d", calls.Load(), peak.Load())
		}
		d2Status(t, s, "withdrawn")
	})
}
func TestD2A_G01_204Release(t *testing.T) {
	s, e, sa := d2Fixture(t, "active")
	var calls atomic.Int32
	d2HTTP(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.URL.Query().Get("claim_ref") != "a101.x11" {
			t.Error("claim identity changed")
		}
		return d2Reply(204, ""), nil
	})
	e.executeRecoveredXDropUnblock(context.Background(), sa)
	d2Status(t, s, "withdrawn")
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
}
func TestD2A_G02_ForceDisabled(t *testing.T) {
	s, e, _ := d2Fixture(t, "active")
	s.setEnabled(false)
	d2HTTP(t, func(*http.Request) (*http.Response, error) { t.Error("disabled HTTP"); return d2Reply(204, ""), nil })
	if e.ForceRemove(context.Background(), 101, 11, 7, "rule-draft") == nil {
		t.Error("want failure")
	}
}
func TestD2A_G03_FutureDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _ := d2Fixture(t, "active")
		s.actions[0].UnblockDelayMinutes = 1
		var calls atomic.Int32
		d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
		d2Immediate(s, e, context.Background())
		time.Sleep(59 * time.Second)
		synctest.Wait()
		if calls.Load() != 0 {
			t.Fatal("early DELETE")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("delayed DELETE missing")
		}
	})
}
func TestD2A_G04_SyntheticExcluded(t *testing.T) {
	for _, kind := range []string{"no_logs", "not_sent"} {
		t.Run(kind, func(t *testing.T) {
			s, e, _ := d2Fixture(t, "failed")
			s.mu.Lock()
			s.rules = map[string]store.XDropActiveRule{}
			s.mu.Unlock()
			_, _ = s.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: "failed-create-101-11", Status: "failed"})
			if kind == "not_sent" {
				connID := 7
				_, _ = s.ActionExecLog().Create(context.Background(), &store.ActionExecutionLog{AttackID: 101, ActionID: 11, ConnectorID: &connID, ActionType: "xdrop", TriggerPhase: "on_detected", ExternalRuleID: "failed-create-101-11", Status: "failed", ErrorMessage: "create request: invalid request"})
			}
			d2HTTP(t, func(*http.Request) (*http.Response, error) { t.Error("synthetic DELETE"); return d2Reply(204, ""), nil })
			d2Immediate(s, e, context.Background())
			rows, err := s.XDropActiveRules().ListByAttack(context.Background(), 101)
			if err != nil || len(rows) != 1 || rows[0].Status != "withdrawn" {
				t.Fatalf("synthetic should close locally: rows=%+v err=%v", rows, err)
			}
		})
	}
}

// ---- additional cases ----

// Before the loop starts, backoff uses the default I=2min; keep this constant in sync with that default.
const d2DefaultI = 2 * time.Minute

// 〔行为〕N5：同键首次失败后，资格时间前恢复 / 普通撤销 / 结束事件都不得多发 DELETE；
// 到资格后三入口齐发也只允许一次尝试。HEAD 红因：各入口无共享退避，恢复入口立即重打。
func TestD2A_B19_SharedBackoffAcrossEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, sa := d2Fixture(t, "active")
		var calls atomic.Int32
		var healthy atomic.Bool
		d2HTTP(t, func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			if healthy.Load() {
				return d2Reply(204, ""), nil
			}
			return d2Reply(503, `{"code":"unavailable","message":"retry"}`), nil
		})
		a := v3Attack(101, "udp", "198.51.100.7")
		rid := 1
		a.ResponseID = &rid
		entries := []struct {
			name string
			run  func()
		}{
			{"recovered", func() { e.executeRecoveredXDropUnblock(context.Background(), sa) }},
			{"normal", func() { d2Immediate(s, e, context.Background()) }},
			{"ended_event", func() { e.HandleEvent(tracker.AttackEvent{Type: "expired", DBID: 101, Attack: a}) }},
		}
		e.executeRecoveredXDropUnblock(context.Background(), sa)
		synctest.Wait()
		if calls.Load() != 1 || s.state(101, 11, "rule-draft") == "withdrawn" {
			t.Fatalf("device: first failure not recorded calls=%d status=%s", calls.Load(), s.state(101, 11, "rule-draft"))
		}
		for _, wait := range []time.Duration{0, d2DefaultI - time.Second} {
			time.Sleep(wait)
			for _, en := range entries {
				before := calls.Load()
				en.run()
				synctest.Wait()
				if d := calls.Load() - before; d != 0 {
					t.Errorf("%s before nextAttempt (after extra wait %s) bypassed backoff: +%d DELETE", en.name, wait, d)
				}
			}
		}
		healthy.Store(true)
		time.Sleep(2 * time.Second) // 失败后 I+1s：已到资格
		synctest.Wait()
		before := calls.Load()
		for _, en := range entries {
			en.run()
			synctest.Wait()
		}
		if d := calls.Load() - before; d != 1 {
			t.Errorf("after eligibility attempts=%d want exactly 1", d)
		}
		d2Status(t, s, "withdrawn")
	})
}

// 〔行为〕R1：首轮空跑完成后才出现的候选，下一 tick 必须尝试（不能“先观察一轮再撤”）。
// HEAD 红因：缺 RunXDropReconcile 入口。
func TestD2A_B20_CandidateAfterEmptyRound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, _ := d2Fixture(t, "active")
		s.mu.Lock()
		s.rules = map[string]store.XDropActiveRule{}
		s.mu.Unlock()
		var stamps []time.Time
		d2HTTP(t, func(*http.Request) (*http.Response, error) {
			stamps = append(stamps, time.Now())
			return d2Reply(204, ""), nil
		})
		stop := d2Start(t, e) // 首轮在空表上完成
		defer stop()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		appeared := time.Now()
		if _, err := s.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: "rule-draft", Status: "active"}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second) // 越过下一 tick（I=1s）
		synctest.Wait()
		if len(stamps) != 1 {
			t.Fatalf("calls by next tick=%d want 1", len(stamps))
		}
		if lag := stamps[0].Sub(appeared); lag > time.Second {
			t.Fatalf("candidate attempted %s after appearing; want <= I", lag)
		}
		d2Status(t, s, "withdrawn")
	})
}

// 〔行为〕R3：关停时循环 / 等行锁者随 ctx 退出、所测 goroutine 收尾；
// synctest.Test 在 f 返回后等待气泡内 goroutine，泄漏即失败（循环不退出则表现为 -timeout）。
// Scope: d2Fixture sets TimeoutMs=1000 through newV3Store, so this case does not verify the default 10s
// HTTP budget; B03/recovered_default covers that deadline. This test requires RunXDropReconcile.
func TestD2A_B21_ShutdownNoLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, sa := d2Fixture(t, "active")
		var calls atomic.Int32
		d2HTTP(t, func(r *http.Request) (*http.Response, error) {
			calls.Add(1)
			<-r.Context().Done() // 远端挂住，直到连接器 HTTP 预算到期
			return nil, r.Context().Err()
		})
		r, ok := any(e).(d2Runner)
		if !ok {
			t.Fatal("HEAD lacks RunXDropReconcile: runtime behavior unavailable")
		}
		loopCtx, stopLoop := context.WithCancel(context.Background())
		loopDone := make(chan struct{})
		go func() { r.RunXDropReconcile(loopCtx, time.Second); close(loopDone) }()
		synctest.Wait()
		if calls.Load() != 1 {
			stopLoop()
			t.Fatalf("device: runtime worker not in HTTP, calls=%d", calls.Load())
		}
		waitCtx, stopWait := context.WithCancel(context.Background())
		waitDone := make(chan struct{})
		go func() { e.executeRecoveredXDropUnblock(waitCtx, sa); close(waitDone) }()
		synctest.Wait()
		if calls.Load() != 1 {
			t.Errorf("lock waiter bypassed row lock: calls=%d", calls.Load())
		}
		stopWait()
		stopLoop()
		synctest.Wait()
		select {
		case <-waitDone:
		default:
			t.Error("row-lock waiter did not exit on ctx cancel")
		}
		select {
		case <-loopDone:
		default:
			t.Error("reconcile loop did not exit on ctx cancel")
		}
		time.Sleep(11 * time.Second) // 越过本装置 1s 连接器预算（及 10s 缺省上限），在途 worker 记账后释放锁
		synctest.Wait()
		if calls.Load() != 1 {
			t.Errorf("DELETE after shutdown: calls=%d", calls.Load())
		}
		if st := s.state(101, 11, "rule-draft"); st == "withdrawn" {
			t.Errorf("unknown HTTP outcome recorded as withdrawn")
		}
	})
}

// 〔守卫〕N1：有真实调度、无规则行 ⇒ 调度驱动入口仍按调度行 rule id + 原 action claim_ref 发 DELETE，
// 只写调度终态与执行日志，不造规则行。HEAD 绿 = 现有恢复能力；删该分支 ⇒ DELETE=0 红。
func TestD2A_G06_NoRowScheduleRecovery(t *testing.T) {
	for _, kind := range []string{"overdue_pending", "future_pending", "executing", "overdue_pending_500"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				s, e, sa := d2Fixture(t, "active")
				s.mu.Lock()
				s.rules = map[string]store.XDropActiveRule{}
				s.mu.Unlock()
				code := 204
				if kind == "overdue_pending_500" {
					code = 500
				}
				var calls atomic.Int32
				d2HTTP(t, func(r *http.Request) (*http.Response, error) {
					calls.Add(1)
					if r.Method != "DELETE" || !strings.HasSuffix(r.URL.Path, "/rules/rule-draft") || r.URL.Query().Get("claim_ref") != "a101.x11" {
						t.Errorf("wrong release identity: %s %s", r.Method, r.URL)
					}
					if code == 204 {
						return d2Reply(204, ""), nil
					}
					return d2Reply(code, `{"code":"internal","message":"retry"}`), nil
				})
				sa.ScheduledFor = time.Now().Add(-time.Minute)
				if kind == "future_pending" {
					sa.ScheduledFor = time.Now().Add(time.Minute)
				}
				id, err := s.ScheduledActions().Schedule(ctx, &sa)
				if err != nil {
					t.Fatal(err)
				}
				sa.ID = id
				if kind == "executing" {
					if err := s.ScheduledActions().MarkExecuting(ctx, id); err != nil {
						t.Fatal(err)
					}
					e.executeRecoveredXDropUnblock(ctx, sa)
				} else {
					if err := e.RecoverScheduledActions(ctx); err != nil {
						t.Fatal(err)
					}
					if kind == "future_pending" {
						time.Sleep(59 * time.Second)
						synctest.Wait()
						if calls.Load() != 0 {
							t.Fatalf("future schedule fired early: calls=%d", calls.Load())
						}
						time.Sleep(time.Second)
					}
					synctest.Wait()
				}
				if calls.Load() != 1 {
					t.Fatalf("no-row schedule DELETE=%d want 1", calls.Load())
				}
				wantSched, wantLog := "completed", "success"
				if code != 204 {
					wantSched, wantLog = "executing", "failed"
				}
				s.mu.Lock()
				gotSched := s.schedules[id-1].Status
				s.mu.Unlock()
				if gotSched != wantSched {
					t.Errorf("schedule status=%s want %s", gotSched, wantSched)
				}
				found := false
				for _, l := range s.logSnapshot() {
					found = found || l.ActionID == 11 && l.ExternalRuleID == "rule-draft" && l.Status == wantLog
				}
				if !found {
					t.Errorf("missing %s execution log; logs=%+v", wantLog, s.logSnapshot())
				}
				if rows, _ := s.XDropActiveRules().ListByAttack(ctx, 101); len(rows) != 0 {
					t.Errorf("no-row schedule recovery fabricated rule rows: %+v", rows)
				}
			})
		})
	}
}

// ---- additional cases ----

// d2NoRowSchedule：清空规则表，只种一条 xdrop_unblock 调度（status=pending；executing=true 时再标 executing）。
func d2NoRowSchedule(t *testing.T, s *d2Store, sa store.ScheduledAction, at time.Time, executing bool) store.ScheduledAction {
	t.Helper()
	ctx := context.Background()
	s.mu.Lock()
	s.rules = map[string]store.XDropActiveRule{}
	s.mu.Unlock()
	sa.ScheduledFor = at
	id, err := s.ScheduledActions().Schedule(ctx, &sa)
	if err != nil {
		t.Fatal(err)
	}
	sa.ID = id
	if executing {
		if err := s.ScheduledActions().MarkExecuting(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	return sa
}
func d2SchedStatus(s *d2Store, id int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.schedules[id-1].Status
}
func d2LogCount(s *d2Store, status string) int {
	n := 0
	for _, l := range s.logSnapshot() {
		if l.ActionID == 11 && l.ExternalRuleID == "rule-draft" && l.Status == status {
			n++
		}
	}
	return n
}

// Behavior case: no rule row and overdue schedule S; late worker A has won MarkExecuting (past
// MarkExecutingDelay in runRecoveredAction) but has not acquired the row lock. Worker B enters recovery
// on the same Engine, acquires the lock, gets 204, and completes S. Then A resumes and rereads S by schedule ID
// and business key under the lock: completed means exit, with one DELETE total, S still completed, and no failure log.
// In after_complete, A enters after B finishes; in waiting_on_lock, A arrives during B's HTTP request and waits.
// A second request receives 503 from the fake, exposing a Complete-to-Fail regression if locking or rereading is missing.
func TestD2A_B22_NoRowLateWorker(t *testing.T) {
	for _, kind := range []string{"after_complete", "waiting_on_lock"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				s, e, sa := d2Fixture(t, "active")
				sa = d2NoRowSchedule(t, s, sa, time.Now().Add(-time.Minute), true)
				gate := make(chan struct{})
				var calls, active, peak atomic.Int32
				d2HTTP(t, func(*http.Request) (*http.Response, error) {
					n := calls.Add(1)
					if v := active.Add(1); v > peak.Load() {
						peak.Store(v)
					}
					defer active.Add(-1)
					if n == 1 {
						if kind == "waiting_on_lock" {
							<-gate
						}
						return d2Reply(204, ""), nil
					}
					return d2Reply(503, `{"code":"unavailable","message":"late worker"}`), nil
				})
				if kind == "after_complete" {
					close(gate)
					e.executeRecoveredXDropUnblock(ctx, sa) // 先到者 B
					synctest.Wait()
					if calls.Load() != 1 || d2SchedStatus(s, sa.ID) != "completed" {
						t.Fatalf("device: first worker calls=%d schedule=%s; want 1/completed", calls.Load(), d2SchedStatus(s, sa.ID))
					}
					e.executeRecoveredXDropUnblock(ctx, sa) // 迟到者 A（同一调度快照）
					synctest.Wait()
				} else {
					bDone, aDone := make(chan struct{}), make(chan struct{})
					go func() { e.executeRecoveredXDropUnblock(ctx, sa); close(bDone) }()
					synctest.Wait()
					if calls.Load() != 1 {
						close(gate)
						t.Fatalf("device: first worker not in HTTP barrier, calls=%d", calls.Load())
					}
					go func() { e.executeRecoveredXDropUnblock(ctx, sa); close(aDone) }()
					synctest.Wait()
					close(gate)
					synctest.Wait()
					for name, ch := range map[string]chan struct{}{"first": bDone, "late": aDone} {
						select {
						case <-ch:
						default:
							t.Errorf("%s worker did not return", name)
						}
					}
				}
				if calls.Load() != 1 || peak.Load() != 1 {
					t.Errorf("DELETE total=%d max concurrent=%d; want 1/1", calls.Load(), peak.Load())
				}
				if st := d2SchedStatus(s, sa.ID); st != "completed" {
					t.Errorf("schedule status=%s want completed (late worker must not regress Complete→Fail)", st)
				}
				if n := d2LogCount(s, "failed"); n != 0 {
					t.Errorf("failed execution logs=%d want 0", n)
				}
				if n := d2LogCount(s, "success"); n != 1 {
					t.Errorf("success execution logs=%d want 1", n)
				}
				if rows, _ := s.XDropActiveRules().ListByAttack(ctx, 101); len(rows) != 0 {
					t.Errorf("no-row branch fabricated rule rows: %+v", rows)
				}
			})
		})
	}
}

// Behavior case: start RunXDropReconcile with I=1s, no rule rows, only schedules, and no workers.
// overdue_pending and lost_executing: within I, the runtime sends exactly one DELETE, completes the schedule, logs success, and creates no rule row.
// live (ended_at IS NULL, LiveIDs=true) with overdue pending: no requests over three intervals; the schedule stays pending.
// future_pending (ScheduledFor=+60s): no requests before its due time (+59s); the schedule stays pending.
// These cases require the RunXDropReconcile entry point.
func TestD2A_B23_RuntimeNoRow(t *testing.T) {
	for _, kind := range []string{"overdue_pending", "lost_executing", "live", "future_pending"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, sa := d2Fixture(t, "active")
				at := time.Now().Add(-time.Minute)
				if kind == "future_pending" {
					at = time.Now().Add(time.Minute)
				}
				sa = d2NoRowSchedule(t, s, sa, at, kind == "lost_executing")
				s.live = kind == "live"
				var calls atomic.Int32
				d2HTTP(t, func(r *http.Request) (*http.Response, error) {
					calls.Add(1)
					if r.Method != "DELETE" || !strings.HasSuffix(r.URL.Path, "/rules/rule-draft") || r.URL.Query().Get("claim_ref") != "a101.x11" {
						t.Errorf("wrong release identity: %s %s", r.Method, r.URL)
					}
					return d2Reply(204, ""), nil
				})
				stop := d2Start(t, e)
				defer stop()
				switch kind {
				case "overdue_pending", "lost_executing":
					time.Sleep(time.Second)
					synctest.Wait()
					if calls.Load() != 1 {
						t.Fatalf("runtime no-row takeover DELETE=%d want 1", calls.Load())
					}
					if st := d2SchedStatus(s, sa.ID); st != "completed" {
						t.Errorf("schedule status=%s want completed", st)
					}
					if n := d2LogCount(s, "success"); n != 1 {
						t.Errorf("success execution logs=%d want 1", n)
					}
				case "live":
					time.Sleep(3 * time.Second)
					synctest.Wait()
				case "future_pending":
					time.Sleep(59 * time.Second)
					synctest.Wait()
				}
				if kind == "live" || kind == "future_pending" {
					if calls.Load() != 0 {
						t.Fatalf("protected no-row %s DELETE=%d want 0", kind, calls.Load())
					}
					if st := d2SchedStatus(s, sa.ID); st != "pending" {
						t.Errorf("protected schedule status=%s want pending", st)
					}
				}
				if rows, _ := s.XDropActiveRules().ListByAttack(context.Background(), 101); len(rows) != 0 {
					t.Errorf("runtime no-row branch fabricated rule rows: %+v", rows)
				}
			})
		})
	}
}
