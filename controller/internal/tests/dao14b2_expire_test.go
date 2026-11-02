package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/ingestion"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

type dao14b2Fixture struct {
	t      *testing.T
	s      store.Store
	d      *dedup.Dedup
	tk     *tracker.Tracker
	h      http.Handler
	events []tracker.AttackEvent
}

func dao14b2Config(cap int) tracker.Config {
	return tracker.Config{HardConfirmSeconds: 3, ExpiryIntervalSeconds: 300, MaxActiveAttacks: cap}
}

func dao14b2New(t *testing.T, cfg tracker.Config, s store.Store) *dao14b2Fixture {
	t.Helper()
	if s == nil {
		s = NewMockStore()
	}
	f := &dao14b2Fixture{t: t, s: s, d: dedup.New()}
	f.tk = tracker.New(cfg, s, nil, f.d, func(e tracker.AttackEvent) { f.events = append(f.events, e) })
	f.h = api.NewRouter(api.Dependencies{Store: s, JWTSecret: testJWTSecret, APIKey: "test-api-key", Tracker: f.tk, NodeState: ingestion.NewNodeState()})
	return f
}

func dao14b2Events(ip, decoder string, pps int64) []engine.ThresholdExceeded {
	rows := dao4Threshold(false)
	for i := range rows {
		rows[i].DstIP = net.ParseIP(ip)
		rows[i].Decoder = decoder
		if rows[i].Unit == "pps" {
			rows[i].Actual = pps
		}
	}
	return rows
}

func (f *dao14b2Fixture) step(filter bool, batches ...[]engine.ThresholdExceeded) {
	time.Sleep(time.Second)
	var rows []engine.ThresholdExceeded
	for _, batch := range batches {
		for _, e := range batch {
			if !filter || !f.d.ShouldSuppress(e) {
				rows = append(rows, e)
			}
		}
	}
	f.tk.Feed(rows)
}

func (f *dao14b2Fixture) count(kind string, id int) int {
	n := 0
	for _, e := range f.events {
		if e.Type == kind && (id == 0 || e.DBID == id) {
			n++
		}
	}
	return n
}

func (f *dao14b2Fixture) row(id int) *store.Attack {
	f.t.Helper()
	a, err := f.s.Attacks().Get(context.Background(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

func (f *dao14b2Fixture) post(path string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, nil)
	r.Header.Set("Authorization", "Bearer "+makeTestToken(f.t))
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, r)
	return w
}

func (f *dao14b2Fixture) expire(query, method string) *httptest.ResponseRecorder {
	f.t.Helper()
	w := f.post("/api/attacks/1/expire" + query)
	if w.Code != http.StatusOK || w.Body.String() != fmt.Sprintf(`{"method":%q,"ok":true}`, method) {
		f.t.Fatalf("expire status=%d body=%s; want 200/%s", w.Code, w.Body, method)
	}
	return w
}

func (f *dao14b2Fixture) confirm(rows []engine.ThresholdExceeded) time.Time {
	f.t.Helper()
	f.step(false, rows)
	start := time.Now()
	f.step(false, rows)
	f.step(false, rows)
	if f.count("confirmed", 0) != 1 || f.count("confirmed", 1) != 1 || f.row(1).EndedAt != nil {
		f.t.Fatalf("setup must confirm exactly id 1: %+v", f.events)
	}
	return start
}

func dao14b2Capture(fn func()) string {
	var b bytes.Buffer
	w, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&b)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() { log.SetOutput(w); log.SetFlags(flags); log.SetPrefix(prefix) }()
	fn()
	return b.String()
}

// Compare the complete event payload except the storage-owned CreatedAt field.
func dao14b2AssertZeroPath(t *testing.T, f *dao14b2Fixture, w *httptest.ResponseRecorder, logs string, start, end time.Time) {
	t.Helper()
	if w != nil && (w.Code != 200 || w.Body.String() != `{"method":"tracker","ok":true}`) {
		t.Errorf("zero path response=%d/%s", w.Code, w.Body)
	}
	wantLogs := "tracker: force-expire attack 192.0.2.10/udp (id=1) by user\ntracker: ATTACK EXPIRED 192.0.2.10 decoder=udp duration=2s peak_pps=25001\n"
	if logs != wantLogs {
		t.Errorf("zero path logs=%q; want %q", logs, wantLogs)
	}
	if f.count("expired", 0) != 1 || f.count("expired", 1) != 1 {
		t.Fatalf("expired events=%+v", f.events)
	}
	var got store.Attack
	for _, e := range f.events {
		if e.Type == "expired" {
			got = *e.Attack
		}
	}
	got.CreatedAt = time.Time{}
	want := store.Attack{ID: 1, DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", PrefixID: intPtr(7), ThresholdRuleID: intPtr(8), AttackType: "udp_flood", Severity: "medium", Confidence: 0.9, PeakPPS: 25001, PeakBPS: 800000, ReasonCodes: []string{"udp_exceeded"}, NodeSources: []string{"n1"}, StartedAt: start, EndedAt: &end}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("zero path payload=%+v; want %+v", got, want)
	}
}

func dao14b2AssertReconfirm(t *testing.T, f *dao14b2Fixture, wantTick int, gap bool) {
	t.Helper()
	first := -1
	for k := 0; k < 30; k++ {
		if gap && k == 0 {
			f.step(false)
		} else {
			f.step(false, dao4Threshold(false))
		}
		if first < 0 && f.count("confirmed", 2) > 0 {
			first = k
		}
	}
	if first != wantTick {
		t.Errorf("new id first tick=%d; want %d", first, wantTick)
	}
	var sequence []string
	for _, e := range f.events {
		sequence = append(sequence, fmt.Sprintf("%s(%d)", e.Type, e.DBID))
	}
	if got := strings.Join(sequence, " "); got != "confirmed(1) expired(1) confirmed(2)" {
		t.Errorf("sequence=%s", got)
	}
}

func TestDao14b2_D4(t *testing.T) {
	t.Run("API", func(t *testing.T) {
		for _, name := range []string{"HoldWhileExceeding", "HoldCap", "NoParamGlobalZero", "ReleaseOnDrop", "HeldNotCounted", "EvictionSkipsHeld", "HeldInvisible", "SecondForceExpireNoEvent", "FallbackIgnoresHold", "RestartClears"} {
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					cap := 100
					if name == "HeldNotCounted" || name == "EvictionSkipsHeld" {
						cap = 1
					}
					f := dao14b2New(t, dao14b2Config(cap), nil)
					a := dao4Threshold(false)
					if name == "EvictionSkipsHeld" {
						a = dao14b2Events("192.0.2.10", "udp", 15000)
					}
					start := f.confirm(a)
					query := "?hold_seconds=60"
					if name == "HoldCap" {
						query = "?hold_seconds=10"
					}
					if name == "HeldInvisible" {
						query = "?hold_seconds=600"
					}
					if name == "RestartClears" {
						query = "?hold_seconds=300"
					}
					if name == "NoParamGlobalZero" {
						query = ""
					}
					end := time.Now()
					var w *httptest.ResponseRecorder
					logs := dao14b2Capture(func() { w = f.expire(query, "tracker") })
					switch name {
					case "NoParamGlobalZero":
						dao14b2AssertZeroPath(t, f, w, logs, start, end)
						dao14b2AssertReconfirm(t, f, 2, false)
					case "ReleaseOnDrop":
						dao14b2AssertReconfirm(t, f, 3, true)
					case "HoldWhileExceeding", "HoldCap":
						for k := 0; k < 30; k++ {
							f.step(false, a)
							if (name == "HoldWhileExceeding" || k <= 9) && f.count("confirmed", 0) != 1 {
								t.Errorf("tick %d re-confirmed: %+v", k, f.events)
								break
							}
						}
						want := 1
						if name == "HoldCap" {
							want = 2
						}
						rows, err := f.s.Attacks().List(context.Background(), store.AttackFilter{Limit: 100})
						if err != nil {
							t.Fatal(err)
						}
						if f.count("confirmed", 0) != want || f.count("expired", 1) != 1 || len(rows) != want {
							t.Errorf("confirmed=%d expired=%d rows=%d; want %d/1/%d", f.count("confirmed", 0), f.count("expired", 1), len(rows), want, want)
						}
						if want == 2 && f.count("confirmed", 2) != 1 {
							t.Error("missing new id 2")
						}
					case "HeldNotCounted", "EvictionSkipsHeld":
						suppressed, evicted := f.tk.SuppressedTotal.Load(), f.tk.EvictedTotal.Load()
						pps := int64(25001)
						if name == "EvictionSkipsHeld" {
							pps = 50000
						}
						b := dao14b2Events("192.0.2.11", "udp", pps)
						for k := 0; k < 3; k++ {
							f.step(false, a, b)
						}
						if name == "HeldNotCounted" {
							if f.count("confirmed", 0) != 2 || f.tk.SuppressedTotal.Load() != suppressed || f.tk.EvictedTotal.Load() != evicted || f.count("evicted", 0) != 0 || f.row(2).DstIP != "192.0.2.11" {
								t.Errorf("held counted: confirmed=%d suppressed delta=%d evicted delta=%d", f.count("confirmed", 0), f.tk.SuppressedTotal.Load()-suppressed, f.tk.EvictedTotal.Load()-evicted)
							}
						} else {
							suppressed = f.tk.SuppressedTotal.Load()
							c := dao14b2Events("192.0.2.12", "udp", 200000)
							for k := 0; k < 5; k++ {
								f.step(false, a, b, c)
							}
							if f.count("confirmed", 0) != 3 || f.count("evicted", 0) != 1 || f.count("evicted", 2) != 1 || f.tk.SuppressedTotal.Load() != suppressed {
								t.Errorf("eviction: confirmed=%d evicted=%d B evicted=%d suppressed delta=%d", f.count("confirmed", 0), f.count("evicted", 0), f.count("evicted", 2), f.tk.SuppressedTotal.Load()-suppressed)
							}
							for _, e := range f.events {
								if e.Type == "confirmed" && e.DBID != 1 && e.Attack.DstIP == "192.0.2.10" {
									t.Error("held A received a new id")
								}
							}
						}
					case "HeldInvisible":
						if _, ok := f.tk.ActiveTimers()[1]; ok || f.tk.ActiveCount() != 0 || len(f.tk.ActiveDstIPs()) != 0 {
							t.Error("held attack immediately visible")
						}
						before := f.row(1).AttackType
						f.tk.UpgradeType(net.ParseIP("192.0.2.10"), "dns_amp", 0.7, []string{"dns"})
						if f.count("type_upgrade", 0) != 0 || f.row(1).AttackType != before {
							t.Error("held attack upgraded")
						}
						dao4Tick(f.tk, a)
						if _, ok := f.tk.ActiveTimers()[1]; ok || f.tk.ActiveCount() != 0 || f.count("updated", 0) != 0 {
							t.Error("held attack visible after periodic tick")
						}
					case "SecondForceExpireNoEvent":
						if f.tk.ForceExpire(1) || f.count("expired", 1) != 1 {
							t.Error("second ForceExpire found ended id or emitted an event")
						}
					case "FallbackIgnoresHold":
						f.s.(*MockStore).attacks.appendAttacks(store.Attack{ID: 50, DstIP: "192.0.2.50", Direction: "receives", DecoderFamily: "udp", StartedAt: time.Now()})
						w = f.post("/api/attacks/50/expire?hold_seconds=60")
						if w.Code != 200 || w.Body.String() != `{"method":"db","ok":true}` || f.count("expired", 50) != 1 {
							t.Errorf("fallback=%d/%s events=%+v", w.Code, w.Body, f.events)
						}
					case "RestartClears":
						wide := dao14b2Events("192.0.2.10", "ip", 25001)
						f.step(true, a, wide)
						g := dao14b2New(t, dao14b2Config(100), f.s)
						if err := g.tk.RecoverFromDB(context.Background()); err != nil {
							t.Fatal(err)
						}
						if g.tk.ActiveCount() != 0 {
							t.Fatal("restart recovered ended attack")
						}
						first := map[string]int{}
						for k := 0; k < 10; k++ {
							g.step(true, a, wide)
							for _, e := range g.events {
								if e.Type == "confirmed" {
									if _, ok := first[e.Attack.DecoderFamily]; !ok {
										first[e.Attack.DecoderFamily] = k
									}
								}
							}
						}
						if !reflect.DeepEqual(first, map[string]int{"udp": 2, "ip": 2}) {
							t.Errorf("restart first confirmations=%v", first)
						}
					}
				})
			})
		}
		t.Run("Invalid", func(t *testing.T) {
			for _, seed := range []struct{ name, raw, id string }{{"-1", "-1", "1"}, {"abc", "abc", "1"}, {"86401", "86401", "1"}, {"1.5", "1.5", "1"}, {"empty", "", "1"}, {"MissingID", "-1", "999"}} {
				t.Run(seed.name, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						ms := NewMockStore()
						probe := &dao14b2ReadStore{Store: ms, repo: ms.Attacks()}
						f := dao14b2New(t, dao14b2Config(100), probe)
						f.confirm(dao4Threshold(false))
						probe.reads, probe.writes = 0, 0
						w := f.post("/api/attacks/" + seed.id + "/expire?hold_seconds=" + seed.raw)
						if probe.reads != 0 || probe.writes != 0 {
							t.Errorf("invalid input read=%d write=%d; want zero", probe.reads, probe.writes)
						}
						var body struct {
							Error string `json:"error"`
						}
						if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
							t.Fatal(err)
						}
						if w.Code != 400 || body.Error != "hold_seconds must be an integer between 0 and 86400" || f.count("expired", 0) != 0 || f.tk.ActiveTimers()[1].State != "active" || f.row(1).EndedAt != nil {
							t.Errorf("invalid status=%d body=%s expired=%d", w.Code, w.Body, f.count("expired", 0))
						}
					})
				})
			}
		})
	})
}

type dao14b2ReadStore struct {
	store.Store
	repo          store.AttackRepo
	reads, writes int
}
type dao14b2ReadRepo struct {
	store.AttackRepo
	s *dao14b2ReadStore
}

func (s *dao14b2ReadStore) Attacks() store.AttackRepo { return dao14b2ReadRepo{s.repo, s} }
func (r dao14b2ReadRepo) Get(ctx context.Context, id int) (*store.Attack, error) {
	r.s.reads++
	return r.AttackRepo.Get(ctx, id)
}
func (r dao14b2ReadRepo) Update(ctx context.Context, a *store.Attack) error {
	r.s.writes++
	return r.AttackRepo.Update(ctx, a)
}

func TestDao14b2_D4D(t *testing.T) {
	for _, name := range []string{"WideRuleHeld", "WideAfterRelease/Drop", "WideAfterRelease/Deadline", "WideHoldZero"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14b2New(t, dao14b2Config(100), nil)
				udp, ip := dao4Threshold(false), dao14b2Events("192.0.2.10", "ip", 25001)
				f.confirm(udp)
				f.step(true, udp, ip)
				f.step(true, udp, ip)
				if f.count("confirmed", 0) != 1 || !f.d.ShouldSuppress(ip[0]) {
					t.Fatal("setup did not suppress wide event")
				}
				query := "?hold_seconds=60"
				if name == "WideAfterRelease/Deadline" {
					query = "?hold_seconds=10"
				}
				if name == "WideHoldZero" {
					query = ""
				}
				f.expire(query, "tracker")
				first, counts := map[string]int{}, map[string]int{}
				for k := 0; k < 30; k++ {
					if name == "WideAfterRelease/Drop" {
						f.step(true, ip)
					} else {
						f.step(true, udp, ip)
					}
					for _, e := range f.events {
						if e.Type == "confirmed" && e.DBID != 1 {
							if _, ok := first[e.Attack.DecoderFamily]; !ok {
								first[e.Attack.DecoderFamily] = k
							}
						}
					}
				}
				for _, e := range f.events {
					if e.Type == "confirmed" && e.DBID != 1 {
						counts[e.Attack.DecoderFamily]++
					}
				}
				t.Logf("new confirmation ticks=%v counts=%v", first, counts)
				if name == "WideRuleHeld" {
					if len(counts) != 0 {
						t.Errorf("held keys re-confirmed: %v", counts)
					}
				} else {
					if counts["ip"] != 1 {
						t.Errorf("wide confirmations=%d; want 1", counts["ip"])
					}
					if name != "WideAfterRelease/Drop" && counts["udp"] != 1 {
						t.Errorf("udp confirmations=%d; want 1", counts["udp"])
					}
					if name == "WideHoldZero" && !reflect.DeepEqual(first, map[string]int{"udp": 2, "ip": 2}) {
						t.Errorf("zero path ticks=%v", first)
					}
				}
			})
		})
	}
	for _, seed := range []struct{ name, db, live string }{{"v4", "192.0.2.10/32", "192.0.2.10"}, {"v6", "2001:db8::10/128", "2001:db8::10"}} {
		for _, check := range []string{"HeldFirstFive", "ReleasedThenDetected"} {
			t.Run("RecoveredCanonicalRelease/"+seed.name+"/"+check, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ms := NewMockStore()
					ms.attacks.appendAttacks(store.Attack{ID: 1, DstIP: seed.db, Direction: "receives", DecoderFamily: "udp", Severity: "medium", StartedAt: time.Now()})
					f := dao14b2New(t, dao14b2Config(100), ms)
					if err := f.tk.RecoverFromDB(context.Background()); err != nil {
						t.Fatal(err)
					}
					udp, ip := dao14b2Events(seed.live, "udp", 25001), dao14b2Events(seed.live, "ip", 25001)
					f.step(true, udp, ip)
					if f.tk.ActiveCount() != 1 || !f.d.ShouldSuppress(ip[0]) || f.count("confirmed", 0) != 0 {
						t.Fatal("canonical recovery setup failed")
					}
					f.expire("?hold_seconds=60", "tracker")
					during, first := 0, -1
					for k := 0; k < 30; k++ {
						if k < 5 {
							f.step(true, udp, ip)
						} else {
							f.step(true, ip)
						}
						if k == 4 {
							during = f.count("confirmed", 0)
						}
						for _, e := range f.events {
							if e.Type == "confirmed" && e.Attack.DecoderFamily == "ip" && first < 0 {
								first = k
							}
						}
					}
					t.Logf("first-five confirmed=%d new wide tick=%d", during, first)
					if check == "HeldFirstFive" && during != 0 {
						t.Errorf("held key re-confirmed %d times", during)
					}
					if check == "ReleasedThenDetected" && first < 0 {
						t.Error("canonical dedup registration never released")
					}
				})
			})
		}
	}
}

func dao14b2FailStore() *dao5AttackStore {
	ms := NewMockStore()
	return &dao5AttackStore{MockStore: ms, r: &dao5Attacks{AttackRepo: ms.Attacks()}}
}

func TestDao14b2_D47(t *testing.T) {
	t.Run("HoldWithFailedWrite", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s := dao14b2FailStore()
			f := dao14b2New(t, dao14b2Config(100), s)
			f.confirm(dao4Threshold(false))
			s.r.failUpdates(2, 0)
			ended := time.Now()
			f.expire("?hold_seconds=60", "tracker")
			for k := 0; k < 10; k++ {
				f.step(false, dao4Threshold(false))
				if k >= 4 {
					if got := f.row(1).EndedAt; got == nil || !got.Equal(ended) {
						t.Errorf("tick %d ended_at=%v; want %v", k, got, ended)
					}
				}
			}
			if f.count("confirmed", 0) != 1 || f.count("expired", 1) != 1 {
				t.Errorf("hold/write events=%+v", f.events)
			}
			w := f.post("/api/attacks/1/expire")
			if w.Code != 409 || f.count("expired", 1) != 1 {
				t.Errorf("repeat expire=%d events=%+v", w.Code, f.events)
			}
		})
	})
}

func TestDao14b2_D7(t *testing.T) {
	for _, name := range []string{"PendingSnapshot", "FailedRetryQuiet", "SecondWriteSuccess"} {
		for _, path := range []struct {
			kind   string
			op     string
			events int
		}{
			{kind: "expired", op: "attack_update_expired", events: 2},
			{kind: "evicted", op: "attack_update_evicted", events: 3},
		} {
			t.Run(name+"/"+path.kind, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					s := dao14b2FailStore()
					f := dao14b2New(t, tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 300, MaxActiveAttacks: 1}, s)
					f.tk.Feed(dao4Threshold(false))
					if f.count("confirmed", 1) != 1 || len(f.events) != 1 || f.row(1).EndedAt != nil {
						t.Fatal("setup must confirm only active id 1")
					}
					// Fix the expected end time independently of the observed event or write.
					wantEnd := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
					if !time.Now().Equal(wantEnd) {
						t.Fatalf("fixture time=%v; want %v", time.Now(), wantEnd)
					}
					failures := 0
					f.tk.StateWriteFailure = func(op string) {
						if op != path.op {
							t.Errorf("failure operation=%q; want %q", op, path.op)
						}
						failures++
					}
					switch name {
					case "PendingSnapshot":
						s.r.failUpdates(2, 0)
					case "FailedRetryQuiet":
						s.r.failUpdates(3, 0)
					case "SecondWriteSuccess":
						s.r.failUpdates(1, 0)
					}
					if path.kind == "expired" {
						if !f.tk.ForceExpire(1) {
							t.Fatal("expire missed id 1")
						}
					} else {
						dao4Evict(f.tk)
					}
					if _, updates := s.r.counts(); updates != 2 {
						t.Fatalf("immediate update calls=%d; want 2", updates)
					}
					if f.count(path.kind, 1) != 1 || len(f.events) != path.events {
						t.Fatalf("end events=%+v; want one %s for id 1 and %d total", f.events, path.kind, path.events)
					}
					var ended *time.Time
					for _, e := range f.events {
						if e.DBID == 1 && e.Type == path.kind {
							ended = e.Attack.EndedAt
						}
					}
					if ended == nil || !ended.Equal(wantEnd) {
						t.Fatalf("end event time=%v; want %v", ended, wantEnd)
					}
					if name == "SecondWriteSuccess" {
						if got := f.row(1).EndedAt; failures != 0 || got == nil || !got.Equal(wantEnd) {
							t.Fatalf("second write failures=%d ended_at=%v; want 0/%v", failures, got, wantEnd)
						}
						for k := 0; k < 6; k++ {
							f.step(false)
						}
						if _, updates := s.r.counts(); updates != 2 {
							t.Errorf("successful second write was retried: update calls=%d; want 2", updates)
						}
						if f.tk.ForceExpire(1) {
							t.Error("successfully persisted id 1 remains tracked or pending; want false")
						}
						return
					}
					if failures != 1 || f.row(1).EndedAt != nil {
						t.Fatalf("failed end writes: failures=%d ended_at=%v; want 1/nil", failures, f.row(1).EndedAt)
					}
					switch name {
					case "PendingSnapshot":
						// Mutate the pointer already handed to the consumer, not a copied value.
						*ended = time.Date(2000, time.January, 1, 1, 0, 0, 0, time.UTC)
						for k := 0; k < 5; k++ {
							f.step(false)
						}
						if _, updates := s.r.counts(); updates != 3 {
							t.Errorf("snapshot retry update calls=%d; want 3", updates)
						}
						if got := f.row(1).EndedAt; got == nil || !got.Equal(wantEnd) {
							t.Errorf("pending snapshot changed through event: ended_at=%v; want %v", got, wantEnd)
						}
					case "FailedRetryQuiet":
						// Let the eviction replacement enter expiring before capturing the retry.
						for k := 0; k < 4; k++ {
							f.step(false)
						}
						if _, updates := s.r.counts(); updates != 2 {
							t.Fatalf("before retry update calls=%d; want 2", updates)
						}
						logs := dao14b2Capture(func() { f.step(false) })
						_, updates := s.r.counts()
						if updates != 3 || failures != 1 || logs != "" || len(f.events) != path.events {
							t.Errorf("failed retry: update calls=%d failures=%d logs=%q events=%d; want 3/1/empty/%d", updates, failures, logs, len(f.events), path.events)
						}
						if f.row(1).EndedAt != nil || f.count(path.kind, 1) != 1 {
							t.Error("failed retry persisted the row or emitted another end event")
						}
					}
				})
			})
		}
	}
	for _, kind := range []string{"expired", "evicted"} {
		t.Run("RetryPersists/"+kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, tk, _, events, _ := dao5Tracker(t, 1, false)
				tk.Feed(dao4Threshold(false))
				if len(*events) != 1 || (*events)[0].DBID != 1 {
					t.Fatal("setup must confirm id 1")
				}
				s.r.failUpdates(2, 0)
				end := time.Now()
				if kind == "expired" {
					if !tk.ForceExpire(1) {
						t.Fatal("expire missed id 1")
					}
				} else {
					dao4Evict(tk)
				}
				for k := 1; k <= 8; k++ {
					time.Sleep(time.Second)
					tk.Feed(nil)
				}
				_, updates := s.r.counts()
				row, err := s.Attacks().Get(context.Background(), 1)
				if err != nil {
					t.Fatal(err)
				}
				if updates != 3 || row.EndedAt == nil || !row.EndedAt.Equal(end) {
					t.Errorf("updates=%d ended_at=%v; want 3/%v", updates, row.EndedAt, end)
				}
				restarted := tracker.New(tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 10, MaxActiveAttacks: 1}, s, nil, dedup.New(), func(e tracker.AttackEvent) { *events = append(*events, e) })
				if err := restarted.RecoverFromDB(context.Background()); err != nil {
					t.Fatal(err)
				}
				for k := 0; k < 15; k++ {
					time.Sleep(time.Second)
					restarted.Feed(nil)
				}
				n := 0
				for _, e := range *events {
					if e.DBID == 1 && (e.Type == "expired" || e.Type == "evicted") {
						n++
					}
				}
				if n != 1 {
					t.Errorf("id 1 end events across restart=%d; want 1", n)
				}
			})
		})
	}
	for _, name := range []string{"EndedAtOnReadBack", "ReadBackKeepsExistingEndedAt", "EvictedEventHasEndedAt", "PendingInvisible", "SecondAPIExpireNoDuplicate", "RetryThrottle/Single", "RetryThrottle/TwoPending"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				if name == "EndedAtOnReadBack" || name == "ReadBackKeepsExistingEndedAt" {
					s := dao14b2TimedStore(2)
					cfg := dao14b2Config(10)
					cfg.HardConfirmSeconds = 1
					f := dao14b2New(t, cfg, s)
					f.tk.Feed(dao4Threshold(false))
					end := time.Now()
					want := end
					if name == "ReadBackKeepsExistingEndedAt" {
						want = end.Add(-time.Second)
						s.r.getEnded = &want
					} else {
						s.r.hostSuffix = "/32"
					}
					if !f.tk.ForceExpire(1) {
						t.Fatal("expire missed id 1")
					}
					if f.count("expired", 1) != 1 {
						t.Fatal("missing end event")
					}
					got := f.events[len(f.events)-1].Attack
					if got.EndedAt == nil || !got.EndedAt.Equal(want) {
						t.Errorf("event ended_at=%v; want %v", got.EndedAt, want)
					}
					if name == "EndedAtOnReadBack" && got.DstIP != "192.0.2.10/32" {
						t.Errorf("readback address=%s; want database /32 text", got.DstIP)
					}
					return
				}
				s := dao14b2FailStore()
				cfg := tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 10, MaxActiveAttacks: 1}
				if name == "SecondAPIExpireNoDuplicate" {
					cfg = dao14b2Config(100)
				}
				if name == "RetryThrottle/TwoPending" {
					cfg.MaxActiveAttacks = 10
				}
				f := dao14b2New(t, cfg, s)
				if name == "SecondAPIExpireNoDuplicate" {
					f.confirm(dao4Threshold(false))
				} else {
					f.tk.Feed(dao4Threshold(false))
				}
				if f.count("confirmed", 1) != 1 {
					t.Fatal("setup must confirm id 1")
				}
				failures := 2
				if name == "RetryThrottle/Single" {
					failures = 3
				}
				if name == "RetryThrottle/TwoPending" {
					f.tk.Feed(append(dao4Threshold(false), dao14b2Events("192.0.2.11", "udp", 25001)...))
					if f.count("confirmed", 2) != 1 {
						t.Fatal("setup must confirm id 2")
					}
					failures = 4
				}
				s.r.failUpdates(failures, 0)
				end := time.Now()
				switch name {
				case "SecondAPIExpireNoDuplicate":
					f.expire("", "tracker")
					f.expire("", "tracker")
					if f.count("expired", 1) != 1 {
						t.Errorf("duplicate expired events=%d", f.count("expired", 1))
					}
				case "EvictedEventHasEndedAt":
					dao4Evict(f.tk)
					if f.count("evicted", 1) != 1 {
						t.Fatal("missing eviction event")
					}
					for _, e := range f.events {
						if e.Type == "evicted" && e.DBID == 1 {
							if e.Attack.EndedAt == nil || !e.Attack.EndedAt.Equal(end) || !strings.Contains(strings.Join(e.Attack.ReasonCodes, ","), "evicted_by_cap") {
								t.Errorf("evicted payload=%+v", e.Attack)
							}
						}
					}
				default:
					if !f.tk.ForceExpire(1) {
						t.Fatal("expire missed id 1")
					}
					if name == "PendingInvisible" {
						if _, ok := f.tk.ActiveTimers()[1]; ok || f.tk.ActiveCount() != 0 || len(f.tk.ActiveDstIPs()) != 0 {
							t.Errorf("pending visible: count=%d timers=%v ips=%v", f.tk.ActiveCount(), f.tk.ActiveTimers(), f.tk.ActiveDstIPs())
						}
						return
					}
					base := 2
					if name == "RetryThrottle/TwoPending" {
						if !f.tk.ForceExpire(2) {
							t.Fatal("expire missed id 2")
						}
						base = 4
					}
					for k := 1; k <= 15; k++ {
						f.step(false)
						want := base
						if k >= 5 {
							want++
						}
						if k >= 10 {
							want++
						}
						_, got := s.r.counts()
						if got != want {
							t.Errorf("tick %d update calls=%d; want %d", k, got, want)
						}
						if name == "RetryThrottle/TwoPending" && k >= 5 && f.row(1).EndedAt == nil {
							t.Errorf("tick %d oldest id not persisted", k)
						}
						if k >= 10 {
							id := 1
							if name == "RetryThrottle/TwoPending" {
								id = 2
							}
							if got := f.row(id).EndedAt; got == nil || !got.Equal(end) {
								t.Errorf("tick %d id %d ended_at=%v", k, id, got)
							}
						}
					}
				}
			})
		})
	}
}

type dao14b2Call struct {
	id, n      int
	start, end time.Time
	success    bool
}
type dao14b2TimedRepo struct {
	store.AttackRepo
	failFirst  int
	perID      map[int]int
	failCall   map[int]map[int]time.Duration
	calls      []dao14b2Call
	hostSuffix string
	getEnded   *time.Time
}
type dao14b2TimedBackend struct {
	store.Store
	r *dao14b2TimedRepo
}

func (s *dao14b2TimedBackend) Attacks() store.AttackRepo { return s.r }
func dao14b2TimedStore(failFirst int) *dao14b2TimedBackend {
	ms := NewMockStore()
	return &dao14b2TimedBackend{Store: ms, r: &dao14b2TimedRepo{AttackRepo: ms.Attacks(), failFirst: failFirst, perID: map[int]int{}, failCall: map[int]map[int]time.Duration{}}}
}
func (r *dao14b2TimedRepo) Get(ctx context.Context, id int) (*store.Attack, error) {
	a, err := r.AttackRepo.Get(ctx, id)
	if err == nil {
		copy := *a
		a = &copy
		a.DstIP += r.hostSuffix
		if r.getEnded != nil {
			v := *r.getEnded
			a.EndedAt = &v
		}
	}
	return a, err
}
func (r *dao14b2TimedRepo) Update(ctx context.Context, a *store.Attack) error {
	r.perID[a.ID]++
	n, start := r.perID[a.ID], time.Now()
	delay, injected := r.failCall[a.ID][n]
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
		}
	}
	var err error
	if n <= r.failFirst || injected {
		err = dao5Fault
	} else {
		err = r.AttackRepo.Update(ctx, a)
	}
	r.calls = append(r.calls, dao14b2Call{a.ID, n, start, time.Now(), err == nil})
	return err
}

func TestDao14b2_D7T(t *testing.T) {
	for _, name := range []string{"SlowTickNoSameTickRetry", "NoStarvation", "SpacingFromCompletion", "FailedHeadYields"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := dao14b2TimedStore(2)
				cfg := tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 300, MaxActiveAttacks: 10}
				if name == "SlowTickNoSameTickRetry" {
					cfg.ExpiryIntervalSeconds = 290
				}
				f := dao14b2New(t, cfg, s)
				origin := time.Now()
				if name == "SlowTickNoSameTickRetry" {
					s.r.failCall[2] = map[int]time.Duration{1: 6 * time.Second}
					a, b := dao4Threshold(false), dao14b2Events("192.0.2.11", "udp", 25001)
					f.step(false, a)
					f.step(false, a, b)
					f.step(false, b)
					if f.row(1).DstIP != "192.0.2.10" || f.row(2).DstIP != "192.0.2.11" {
						t.Fatal("setup requires fixed IDs")
					}
					time.Sleep(298 * time.Second)
					f.tk.Feed(b)
					if s.r.perID[1] != 2 || time.Since(origin) != 306*time.Second {
						t.Errorf("slow tick id1 calls=%d elapsed=%v; want 2/306s", s.r.perID[1], time.Since(origin))
					}
					return
				}
				count := 1
				if name == "NoStarvation" {
					count = 8
				}
				if name == "FailedHeadYields" {
					count = 2
				}
				var rows []engine.ThresholdExceeded
				for i := 0; i < count; i++ {
					rows = append(rows, dao14b2Events(fmt.Sprintf("192.0.2.%d", 10+i), "udp", 25001)...)
				}
				f.tk.Feed(rows)
				if f.count("confirmed", 0) != count {
					t.Fatal("setup confirmation count mismatch")
				}
				origin = time.Now()
				if name == "NoStarvation" {
					for k := 0; k < 45; k++ {
						if k%2 == 0 && k/2 < 8 {
							if !f.tk.ForceExpire(k/2 + 1) {
								t.Fatalf("missing id %d", k/2+1)
							}
						}
						f.step(false)
					}
					var seq []string
					for _, c := range s.r.calls {
						if c.success {
							seq = append(seq, fmt.Sprintf("%d@+%v", c.id, c.start.Sub(origin)))
						}
					}
					t.Logf("successful retries: %s", strings.Join(seq, " "))
					want := []string{"1@+5s", "2@+10s", "3@+15s", "4@+20s", "5@+25s", "6@+30s", "7@+35s", "8@+40s"}
					if !reflect.DeepEqual(seq, want) {
						t.Errorf("retry sequence=%v; want %v", seq, want)
					}
					return
				}
				if name == "SpacingFromCompletion" {
					s.r.failCall[1] = map[int]time.Duration{3: 2 * time.Second}
				} else {
					s.r.failCall[1] = map[int]time.Duration{3: 0}
				}
				if !f.tk.ForceExpire(1) {
					t.Fatal("missing id 1")
				}
				if name == "FailedHeadYields" {
					f.step(false)
					if !f.tk.ForceExpire(2) {
						t.Fatal("missing id 2")
					}
				}
				for k := 0; k < 20; k++ {
					f.step(false)
				}
				var retries []dao14b2Call
				for _, c := range s.r.calls {
					if c.n >= 3 {
						retries = append(retries, c)
					}
				}
				if name == "SpacingFromCompletion" {
					if len(retries) != 2 {
						t.Fatalf("retries=%+v; want two", retries)
					}
					if retries[0].start.Sub(origin) != 5*time.Second || retries[0].end.Sub(origin) != 7*time.Second || retries[0].success || retries[1].start.Sub(origin) != 12*time.Second || !retries[1].success {
						t.Errorf("retry timing=%+v origin=%v", retries, origin)
					}
				} else {
					var seq []string
					for _, c := range retries {
						seq = append(seq, fmt.Sprintf("%v:%d:%t", c.start.Sub(origin).Truncate(time.Second), c.id, c.success))
					}
					want := []string{"5s:1:false", "10s:2:true", "15s:1:true"}
					if !reflect.DeepEqual(seq, want) {
						t.Errorf("retry order=%v; want %v", seq, want)
					}
				}
			})
		})
	}
}
