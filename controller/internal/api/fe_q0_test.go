package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/baseline"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/ingestion"
	"github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/jackc/pgx/v5/pgconn"
)

// Only explicitly implemented repository methods may be called by these GETs.
type q0Store struct {
	store.Store
	attacks, recovered        []store.Attack
	prefix                    *store.WatchPrefix
	prefixGets                int
	nodes                     []store.Node
	listFilters, countFilters []store.AttackFilter
	countErr                  error
	countTotal                int // >0 overrides Count (default: len(attacks))
	xdrop                     map[int][]store.XDropActiveRule
	attachments               map[int][]store.BGPAnnouncementAttack
	anns                      map[int]*store.BGPAnnouncement
	faultAt                   string
	calls                     []string
}
type q0Attacks struct {
	store.AttackRepo
	s *q0Store
}
type q0Prefixes struct {
	store.PrefixRepo
	s *q0Store
}
type q0Nodes struct {
	store.NodeRepo
	s *q0Store
}
type q0Thresholds struct{ store.ThresholdRepo }
type q0Logs struct{ store.ActionExecLogRepo }
type q0XDrop struct {
	store.XDropActiveRuleRepo
	s *q0Store
}
type q0BGP struct {
	store.BGPAnnouncementRepo
	s *q0Store
}

func (s *q0Store) Attacks() store.AttackRepo                   { return q0Attacks{s: s} }
func (s *q0Store) Prefixes() store.PrefixRepo                  { return q0Prefixes{s: s} }
func (s *q0Store) Nodes() store.NodeRepo                       { return q0Nodes{s: s} }
func (s *q0Store) Thresholds() store.ThresholdRepo             { return q0Thresholds{} }
func (s *q0Store) ActionExecLog() store.ActionExecLogRepo      { return q0Logs{} }
func (s *q0Store) XDropActiveRules() store.XDropActiveRuleRepo { return q0XDrop{s: s} }
func (s *q0Store) BGPAnnouncements() store.BGPAnnouncementRepo { return q0BGP{s: s} }
func (r q0Attacks) List(_ context.Context, f store.AttackFilter) ([]store.Attack, error) {
	r.s.listFilters = append(r.s.listFilters, f)
	return r.s.attacks, nil
}
func (r q0Attacks) Count(_ context.Context, f store.AttackFilter) (int, error) {
	r.s.countFilters = append(r.s.countFilters, f)
	if r.s.countErr != nil {
		return 0, r.s.countErr
	}
	if r.s.countTotal > 0 {
		return r.s.countTotal, nil
	}
	return len(r.s.attacks), nil
}
func (r q0Attacks) ListActive(context.Context, int) ([]store.Attack, error) { return r.s.attacks, nil }
func (r q0Attacks) ListAllActive(context.Context) ([]store.Attack, error)   { return r.s.recovered, nil }
func (r q0Attacks) CountActive(context.Context) (int, error)                { return len(r.s.attacks), nil }
func (r q0Attacks) Get(_ context.Context, id int) (*store.Attack, error) {
	for _, a := range r.s.attacks {
		if a.ID == id {
			return &a, nil
		}
	}
	return nil, errors.New("missing")
}
func (r q0Prefixes) Get(context.Context, int) (*store.WatchPrefix, error) {
	r.s.prefixGets++
	return r.s.prefix, nil
}
func (r q0Prefixes) Count(context.Context) (int, error)                { return 1, nil }
func (r q0Prefixes) List(context.Context) ([]store.WatchPrefix, error) { return nil, nil }
func (r q0Nodes) List(context.Context) ([]store.Node, error)           { return r.s.nodes, nil }
func (r q0Nodes) Get(_ context.Context, id string) (*store.Node, error) {
	for _, n := range r.s.nodes {
		if n.ID == id {
			return &n, nil
		}
	}
	return nil, errors.New("missing")
}
func (r q0Nodes) UpdateMode(context.Context, string, string) error                   { return nil }
func (q0Thresholds) Count(context.Context) (int, error)                              { return 2, nil }
func (q0Thresholds) List(context.Context) ([]store.Threshold, error)                 { return nil, nil }
func (q0Logs) ListByAttack(context.Context, int) ([]store.ActionExecutionLog, error) { return nil, nil }
func (s *q0Store) fault(method string) error {
	s.calls = append(s.calls, method)
	if s.faultAt == method {
		return &pgconn.PgError{Code: "22P02", Message: "fixture private detail"}
	}
	return nil
}
func (r q0XDrop) ListByAttack(_ context.Context, id int) ([]store.XDropActiveRule, error) {
	return r.s.xdrop[id], r.s.fault("xdrop")
}
func (r q0BGP) ListAttachmentsForAttack(_ context.Context, id int) ([]store.BGPAnnouncementAttack, error) {
	return r.s.attachments[id], r.s.fault("attachments")
}
func (r q0BGP) Get(_ context.Context, id int) (*store.BGPAnnouncement, error) {
	return r.s.anns[id], r.s.fault("announcement")
}

func q0Deps(s *q0Store, rings *ring.RingStore) Dependencies {
	return Dependencies{Store: s, APIKey: "q0", Tracker: tracker.New(tracker.Config{}, s, rings, dedup.New(), nil), NodeState: ingestion.NewNodeState(), ProfileEngine: baseline.NewProfileEngine(rings, nil, nil)}
}
func q0Get(t *testing.T, d Dependencies, path string, status int) []byte {
	t.Helper()
	r := NewRouter(d)
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("X-API-Key", d.APIKey)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != status {
		t.Fatalf("GET %s status=%d want=%d body=%s", path, w.Code, status, w.Body)
	}
	return w.Body.Bytes()
}
func q0JSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func q0Equal(t *testing.T, label string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s got=%#v want=%#v", label, got, want)
	}
}
func q0Time(v string) time.Time {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		panic(err)
	}
	return t
}

func TestFEQ0_G2_B1(t *testing.T) {
	for _, endpoint := range []string{"timeseries", "total-timeseries"} {
		t.Run(endpoint, func(t *testing.T) {
			base := url.Values{"from": {"2026-10-27T00:00:00Z"}, "to": {"2026-10-27T01:00:00Z"}, "resolution": {"5s"}, "direction": {"sends"}, "node_id": {"n1"}, "include_extras": {"true"}}
			for _, tc := range []struct{ name, ip string }{{"IPv4", "192.0.2.10"}, {"Host32", "192.0.2.10/32"}, {"Host128", "2001:db8::10/128"}} {
				t.Run(tc.name, func(t *testing.T) {
					q := base.Encode() + "&dst_ip=" + url.QueryEscape(tc.ip)
					s := &dao14e1Store{}
					w := dao14e1Get(s, "/api/stats/"+endpoint+"?"+q)
					q0Equal(t, "status", w.Code, 200)
					filters := append(s.plain, s.total...)
					q0Equal(t, "calls", len(filters), 1)
					wantIP := "192.0.2.10"
					if tc.name == "Host128" {
						wantIP = "2001:db8::10"
					}
					q0Equal(t, "filter", filters[0], store.TimeseriesFilter{DstIP: wantIP, NodeID: "n1", From: q0Time("2026-10-27T00:00:00Z"), To: q0Time("2026-10-27T01:00:00Z"), Resolution: "5s", Direction: "sends", Limit: 7200, IncludeExtras: true})
				})
			}
			for _, tc := range []struct{ name, key, value, message string }{
				{"Invalid", "dst_ip", "bad", "invalid dst_ip"}, {"NonHostCIDR", "dst_ip", "192.0.2.0/24", "invalid dst_ip"}, {"Empty", "dst_ip", "", "invalid dst_ip"},
				{"Resolution1h", "resolution", "1h", "dst_ip resolution must be '5s' or '5min'"},
				{"SevenHours", "to", "2026-10-27T07:00:00Z", "dst_ip queries are limited to 6h"},
				{"Both", "direction", "both", "dst_ip direction must be 'receives' or 'sends'"},
				{"PrefixConflict", "prefix", "192.0.2.0/24", "dst_ip and prefix are mutually exclusive"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					q, _ := url.ParseQuery(base.Encode())
					q.Set("dst_ip", "192.0.2.10")
					q.Set(tc.key, tc.value)
					s := &dao14e1Store{}
					w := dao14e1Get(s, "/api/stats/"+endpoint+"?"+q.Encode())
					q0Equal(t, "status", w.Code, 400)
					q0Equal(t, "error", q0JSON(t, w.Body.Bytes())["error"], tc.message)
					q0Equal(t, "store calls", len(s.plain)+len(s.total), 0)
				})
			}
			t.Run("WithoutDstIPUnchanged", func(t *testing.T) {
				s := &dao14e1Store{}
				w := dao14e1Get(s, "/api/stats/"+endpoint+"?"+base.Encode()+"&prefix=192.0.2.0/24")
				q0Equal(t, "status", w.Code, 200)
				filters := append(s.plain, s.total...)
				q0Equal(t, "filter", filters, []store.TimeseriesFilter{{Prefix: "192.0.2.0/24", NodeID: "n1", From: q0Time("2026-10-27T00:00:00Z"), To: q0Time("2026-10-27T01:00:00Z"), Resolution: "5s", Direction: "sends", Limit: 7200, IncludeExtras: true}})
			})
			t.Run("SixHours5min", func(t *testing.T) {
				s := &dao14e1Store{}
				w := dao14e1Get(s, "/api/stats/"+endpoint+"?dst_ip=192.0.2.10&resolution=5min&from=2026-10-27T00:00:00Z&to=2026-10-27T06:00:00Z")
				q0Equal(t, "status", w.Code, 200)
			})
			t.Run("DefaultToNow", func(t *testing.T) {
				s := &dao14e1Store{}
				before := time.Now()
				w := dao14e1Get(s, "/api/stats/"+endpoint+"?dst_ip=192.0.2.10")
				after := time.Now()
				q0Equal(t, "status", w.Code, 200)
				f := append(s.plain, s.total...)[0]
				if f.To.Before(before) || f.To.After(after) {
					t.Fatalf("default to=%v outside request interval", f.To)
				}
			})
		})
	}
}

func TestFEQ0_G2_B2(t *testing.T) {
	for _, name := range []string{"Host32TwoNodes", "Host128", "StalePoint", "NoPoints", "CIDRWithoutOwnership", "GlobalCIDR", "OutboundIP", "OutboundCIDR", "RecoveredPrefix", "MissingPrefixID", "MissingPrefixRow", "Ended", "Untracked"} {
		t.Run(name, func(t *testing.T) {
			r := ring.New(ring.DefaultLimits())
			pid := 7
			a := store.Attack{ID: 1, DstIP: "192.0.2.10/32", PrefixID: &pid, Direction: "receives", DecoderFamily: "udp", StartedAt: time.Now().Add(-time.Hour)}
			prefix, ip := "192.0.2.0/24", "192.0.2.10"
			want, known := attackCurrent{PPS: 30, BPS: 300}, true
			if name == "Host128" {
				prefix, ip = "2001:db8::/64", "2001:db8::10"
				a.DstIP = ip + "/128"
			}
			isCIDR := name == "CIDRWithoutOwnership" || name == "GlobalCIDR" || name == "OutboundCIDR"
			if name == "GlobalCIDR" {
				prefix = "0.0.0.0/0"
			}
			if isCIDR {
				a.DstIP = prefix
				a.PrefixID = nil
			}
			if strings.HasPrefix(name, "Outbound") {
				a.Direction = "sends"
			}
			if name == "MissingPrefixID" {
				a.PrefixID = nil
				known = false
			}
			if name == "NoPoints" || name == "MissingPrefixRow" || name == "Ended" || name == "Untracked" {
				known = false
			}
			if name == "Ended" {
				stamp := time.Now()
				a.EndedAt = &stamp
			}
			for i, node := range []string{"n1", "n2"} {
				dp := ring.DataPoint{Time: time.Now(), PPS: 10, BPS: 100}
				if i == 1 {
					dp.PPS = 20
					dp.BPS = 200
				}
				if name == "StalePoint" && i == 1 {
					dp.Time = time.Now().Add(-11 * time.Second)
					want = attackCurrent{PPS: 10, BPS: 100}
				}
				if name == "NoPoints" {
					continue
				}
				if isCIDR {
					if a.Direction == "sends" {
						r.PushSrcPrefix(node, prefix, dp)
					} else {
						r.PushPrefix(node, prefix, dp)
					}
				} else {
					if a.Direction == "sends" {
						r.PushSrcIP(node, prefix, net.ParseIP(ip), dp)
					} else {
						r.PushIP(node, prefix, net.ParseIP(ip), dp)
					}
				}
			}
			// Distinct inbound values catch accidentally using inbound rings for sends.
			if a.Direction == "sends" {
				r.PushPrefix("wrong", prefix, ring.DataPoint{Time: time.Now(), PPS: 900, BPS: 9000})
				r.PushIP("wrong", prefix, net.ParseIP(ip), ring.DataPoint{Time: time.Now(), PPS: 900, BPS: 9000})
			}
			s := &q0Store{attacks: []store.Attack{a}, recovered: []store.Attack{a}, prefix: &store.WatchPrefix{ID: 7, Prefix: prefix}}
			if name == "RecoveredPrefix" {
				s.prefix.Prefix = "192.0.2.123/24"
			}
			if name == "MissingPrefixRow" {
				s.prefix = nil
			}
			if name == "Untracked" {
				s.recovered = nil
			}
			d := q0Deps(s, r)
			if err := d.Tracker.RecoverFromDB(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/api/attacks/active", "/api/attacks/1"} {
				body := q0JSON(t, q0Get(t, d, path, 200))
				value, exists := body["current"]
				if !known {
					if exists {
						t.Fatalf("%s current must be absent, got=%v", path, value)
					}
					continue
				}
				if !exists {
					t.Fatalf("%s current missing", path)
				}
				if path == "/api/attacks/active" {
					value = value.(map[string]any)["1"]
				}
				q0Equal(t, "current pps/bps", value, map[string]any{"pps": float64(want.PPS), "bps": float64(want.BPS)})
			}
			if name == "RecoveredPrefix" {
				q0Equal(t, "fallback prefix lookups", s.prefixGets, 2)
			}
			if isCIDR || name == "MissingPrefixID" {
				q0Equal(t, "no ownership lookup", s.prefixGets, 0)
			}
		})
	}
	t.Run("TimerPrefixAvoidsLookup", func(t *testing.T) {
		r := ring.New(ring.DefaultLimits())
		r.PushIP("n1", "192.0.2.0/24", net.ParseIP("192.0.2.10"), ring.DataPoint{Time: time.Now(), PPS: 17, BPS: 170})
		s := &q0Store{}
		value, found := currentAttackTraffic(context.Background(), r, s.Prefixes(), store.Attack{DstIP: "192.0.2.10/32"}, tracker.AttackTimer{Prefix: "192.0.2.0/24"})
		q0Equal(t, "found", found, true)
		q0Equal(t, "current", value, attackCurrent{PPS: 17, BPS: 170})
		q0Equal(t, "lookups", s.prefixGets, 0)
	})
}

func TestFEQ0_G2_B3(t *testing.T) {
	fixture := func() *q0Store {
		stamp := q0Time("2026-10-27T12:00:00Z")
		detached := q0Time("2026-10-27T12:02:00Z")
		return &q0Store{xdrop: map[int][]store.XDropActiveRule{1: {{ExternalRuleID: "r1", Status: "delayed", DelayStartedAt: &stamp, DelayMinutes: 5}, {ExternalRuleID: "r2", Status: "active"}}}, attachments: map[int][]store.BGPAnnouncementAttack{2: {{AnnouncementID: 9, AttachedAt: stamp, DetachedAt: &detached, DelayMinutes: 7}}}, anns: map[int]*store.BGPAnnouncement{9: {Prefix: "192.0.2.0/24", RouteMap: "RTBH", Status: "active"}}}
	}
	t.Run("ThreeIDs", func(t *testing.T) {
		s := fixture()
		body := q0JSON(t, q0Get(t, q0Deps(s, nil), "/api/attacks/mitigation-brief?ids=1,2,3", 200))
		want := q0JSON(t, []byte(`{"1":{"xdrop_rules":[{"external_rule_id":"r1","status":"delayed","scheduled_for":"2026-10-27T12:05:00Z"},{"external_rule_id":"r2","status":"active"}],"bgp":[]},"2":{"xdrop_rules":[],"bgp":[{"prefix":"192.0.2.0/24","route_map":"RTBH","status":"active","attached_at":"2026-10-27T12:00:00Z","detached_at":"2026-10-27T12:02:00Z","delay_minutes":7}]},"3":{"xdrop_rules":[],"bgp":[]}}`))
		q0Equal(t, "brief", body, want)
		q0Equal(t, "2N+A calls", s.calls, []string{"xdrop", "attachments", "xdrop", "attachments", "announcement", "xdrop", "attachments"})
	})
	ids := make([]string, 51)
	for i := range ids {
		ids[i] = fmt.Sprint(i + 1)
	}
	for _, tc := range []struct {
		name, ids string
		status    int
	}{{"Fifty", strings.Join(ids[:50], ","), 200}, {"Empty", "", 400}, {"Zero", "1,0", 400}, {"Negative", "-1", 400}, {"NonInteger", "1,x", 400}, {"FiftyOne", strings.Join(ids, ","), 400}, {"Duplicate", "1,2,1", 400}, {"OverInt32", "2147483648", 400}} {
		t.Run(tc.name, func(t *testing.T) {
			s := &q0Store{}
			body := q0Get(t, q0Deps(s, nil), "/api/attacks/mitigation-brief?ids="+tc.ids, tc.status)
			if tc.status == 200 {
				q0Equal(t, "entries", len(q0JSON(t, body)), 50)
				q0Equal(t, "store calls", len(s.calls), 100)
			} else {
				q0Equal(t, "no partial queries", len(s.calls), 0)
			}
		})
	}
	t.Run("Int32Max", func(t *testing.T) {
		s := &q0Store{}
		body := q0JSON(t, q0Get(t, q0Deps(s, nil), "/api/attacks/mitigation-brief?ids=2147483647", 200))
		q0Equal(t, "entries", len(body), 1)
		q0Equal(t, "int32 max entry", body["2147483647"], map[string]any{"xdrop_rules": []any{}, "bgp": []any{}})
		q0Equal(t, "store calls", len(s.calls), 2)
	})
	for _, stage := range []string{"xdrop", "attachments", "announcement"} {
		t.Run("Error_"+stage, func(t *testing.T) {
			s := fixture()
			s.faultAt = stage
			body := q0JSON(t, q0Get(t, q0Deps(s, nil), "/api/attacks/mitigation-brief?ids=1,2,3", 500))
			prefix := map[string]string{"xdrop": "load xdrop rules: ", "attachments": "load bgp attachments: ", "announcement": "load bgp announcement: "}[stage]
			q0Equal(t, "safe error", body, map[string]any{"error": prefix + "database error"})
		})
	}
}

func TestFEQ0_G2_B4B11(t *testing.T) {
	for _, ip := range []string{"198.51.100.7", "198.51.100.0/24", "2001:db8::/32"} {
		t.Run(ip, func(t *testing.T) {
			s := &q0Store{}
			q0Get(t, q0Deps(s, nil), "/api/attacks?dst_ip="+url.QueryEscape(ip)+"&ended_after=2026-10-27T00:00:00Z&to=2026-10-27T01:00:00Z", 200)
			after, to := q0Time("2026-10-27T00:00:00Z"), q0Time("2026-10-27T01:00:00Z")
			want := []store.AttackFilter{{DstIP: ip, EndedAfter: &after, TimeTo: &to, Limit: 50}}
			q0Equal(t, "list filter", s.listFilters, want)
			q0Equal(t, "count filter", s.countFilters, want)
		})
	}
	for _, tc := range []struct{ query, message string }{{"dst_ip=wrong", "invalid dst_ip"}, {"dst_ip=", "invalid dst_ip"}, {"ended_after=wrong", "invalid ended_after"}, {"ended_after=", "invalid ended_after"}} {
		t.Run(tc.query, func(t *testing.T) {
			s := &q0Store{}
			b := q0JSON(t, q0Get(t, q0Deps(s, nil), "/api/attacks?"+tc.query, 400))
			q0Equal(t, "error", b["error"], tc.message)
			q0Equal(t, "store calls", len(s.listFilters), 0)
		})
	}
}

func TestFEQ0_G2_B6(t *testing.T) {
	for _, mode := range []string{"auto", "observe", "nil"} {
		t.Run(mode, func(t *testing.T) {
			s := &q0Store{}
			d := q0Deps(s, nil)
			if mode != "nil" {
				d.ActionEngine = action.NewEngine(s, mode)
			}
			body := q0JSON(t, q0Get(t, d, "/api/stats/summary", 200))
			if mode == "nil" {
				if _, exists := body["action_mode"]; exists {
					t.Fatal("action_mode must be absent")
				}
			} else {
				q0Equal(t, "action_mode", body["action_mode"], mode)
			}
		})
	}
}

func TestFEQ0_G2_B8(t *testing.T) {
	for _, direction := range []string{"receives", "sends", "both"} {
		t.Run(direction, func(t *testing.T) {
			r := ring.New(ring.DefaultLimits())
			now := time.Now()
			for _, p := range []struct {
				node, prefix string
				pps, bps     int64
			}{{"b", "192.0.2.0/24", 10, 100}, {"a", "198.51.100.0/24", 20, 200}, {"a", "203.0.113.0/24", 30, 300}, {"a", "0.0.0.0/0", 900, 9000}} {
				dp := ring.DataPoint{Time: now, PPS: p.pps, BPS: p.bps}
				r.PushPrefix(p.node, p.prefix, dp)
				r.PushSrcPrefix(p.node, p.prefix, dp)
			}
			r.PushPrefix("stale", "10.0.0.0/8", ring.DataPoint{Time: now.Add(-11 * time.Second), PPS: 700, BPS: 7000})
			d := q0Deps(&q0Store{}, r)
			for _, filtered := range []bool{false, true} {
				name := "All"
				query := "?direction=" + direction
				if filtered {
					name = "Filtered"
					query += "&node_id=b"
				}
				t.Run(name, func(t *testing.T) {
					b := q0JSON(t, q0Get(t, d, "/api/stats/overview"+query, 200))
					want := []any{map[string]any{"id": "a", "pps": float64(50), "bps": float64(500)}, map[string]any{"id": "b", "pps": float64(10), "bps": float64(100)}}
					total := float64(60)
					if direction == "both" {
						want = []any{map[string]any{"id": "a", "pps": float64(100), "bps": float64(1000)}, map[string]any{"id": "b", "pps": float64(20), "bps": float64(200)}}
						total = 120
					}
					if filtered {
						want = want[1:]
						total = 10
						if direction == "both" {
							total = 20
						}
					}
					q0Equal(t, "nodes", b["nodes"], want)
					q0Equal(t, "total_pps", b["total_pps"], total)
					sum := float64(0)
					for _, n := range b["nodes"].([]any) {
						sum += n.(map[string]any)["pps"].(float64)
					}
					q0Equal(t, "sum nodes = total_pps", sum, b["total_pps"])
				})
			}
		})
	}
	t.Run("Unready", func(t *testing.T) {
		b := q0JSON(t, q0Get(t, q0Deps(&q0Store{}, nil), "/api/stats/overview", 200))
		q0Equal(t, "nodes", b["nodes"], []any{})
	})
}

func TestFEQ0_G2_B7B9(t *testing.T) {
	s := &q0Store{nodes: []store.Node{{ID: "n1", APIKey: "fixture", Enabled: true, DeliveryVersionCurrent: 1}, {ID: "never"}}}
	d := q0Deps(s, nil)
	h := ingestion.NewGRPCHandler(ingestion.GRPCHandlerConfig{Store: s, NodeState: d.NodeState})
	handshake := func(names []string) {
		t.Helper()
		res, err := h.Handshake(context.Background(), &pb.NodeHandshake{NodeId: "n1", ApiKey: "fixture", Interfaces: names})
		if err != nil || !res.Accepted {
			t.Fatalf("handshake=%v error=%v", res, err)
		}
	}
	handshake([]string{"eth1", "eth0"})
	d.NodeState.TouchStats("n1")
	stamp := d.NodeState.LastStatsAt("n1")
	d.NodeState.NoteCapture("n1", "eth1", 100)
	d.NodeState.NoteCapture("n1", "eth0", 10)
	d.NodeState.NoteCapture("n1", "eth0", 20)
	d.NodeState.NoteCapture("n1", "", 999)
	t.Run("ListHeartbeat", func(t *testing.T) {
		var rows []map[string]any
		if err := json.Unmarshal(q0Get(t, d, "/api/nodes", 200), &rows); err != nil {
			t.Fatal(err)
		}
		q0Equal(t, "last_stats_at", rows[0]["last_stats_at"], stamp.Format(time.RFC3339Nano))
		if _, exists := rows[1]["last_stats_at"]; exists {
			t.Fatal("unknown heartbeat must be omitted")
		}
	})
	t.Run("StatusCapture", func(t *testing.T) {
		b := q0JSON(t, q0Get(t, d, "/api/nodes/n1/status", 200))
		q0Equal(t, "interfaces", b["interfaces"], []any{"eth1", "eth0"})
		q0Equal(t, "capture", b["capture"], []any{map[string]any{"interface": "eth0", "upstream_sample_rate": float64(20)}, map[string]any{"interface": "eth1", "upstream_sample_rate": float64(100)}})
	})
	t.Run("RejectedHandshakeRetainsCapture", func(t *testing.T) {
		res, err := h.Handshake(context.Background(), &pb.NodeHandshake{NodeId: "n1", ApiKey: "wrong", Interfaces: []string{"bad"}})
		if err != nil || res.Accepted {
			t.Fatalf("rejected handshake=%v err=%v", res, err)
		}
		q0Equal(t, "retained capture", d.NodeState.GetCapture("n1"), map[string]uint32{"eth0": 20, "eth1": 100})
	})
	t.Run("ReconnectClearsCapture", func(t *testing.T) {
		handshake([]string{"eth2"})
		b := q0JSON(t, q0Get(t, d, "/api/nodes/n1/status", 200))
		q0Equal(t, "replaced interfaces", b["interfaces"], []any{"eth2"})
		if _, exists := b["capture"]; exists {
			t.Fatalf("capture must be absent after accepted reconnect: %v", b["capture"])
		}
	})
	t.Run("UnknownOmitted", func(t *testing.T) {
		b := q0JSON(t, q0Get(t, d, "/api/nodes/never/status", 200))
		for _, key := range []string{"interfaces", "capture", "last_stats_at"} {
			if _, exists := b[key]; exists {
				t.Fatalf("%s must be absent", key)
			}
		}
	})
}

func TestFEQ0_G2_B10(t *testing.T) {
	for _, tc := range []struct {
		name, body     string
		src, dst, rate int
		ip             string
	}{
		{"Numbers", `{"src_port":53,"dst_port":443,"rate_limit":5000,"dst_ip":"192.0.2.10"}`, 53, 443, 5000, "192.0.2.10"},
		{"DigitStrings", `{"src_port":"53","dst_port":"443","rate_limit":"5000"}`, 53, 443, 5000, ""},
		{"InvalidShapes", `{"src_port":[],"dst_port":true,"rate_limit":{}}`, 0, 0, 0, ""},
		{"NonDigitStrings", `{"src_port":" 53","dst_port":"1e3","rate_limit":"5.5"}`, 0, 0, 0, ""},
		{"FractionOverflow", `{"src_port":1.5,"dst_port":1e100,"rate_limit":"999999999999999999999999"}`, 0, 0, 0, ""},
		{"CIDRFallback", `{"dst_cidr":"192.0.2.0/24"}`, 0, 0, 0, "192.0.2.0/24"},
		{"IPPriority", `{"dst_ip":"192.0.2.10","dst_cidr":"192.0.2.0/24"}`, 0, 0, 0, "192.0.2.10"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ActiveResponseAction
			parseXDropRequestBody(tc.body, &item)
			q0Equal(t, "ports/rate", []int{item.SrcPort, item.DstPort, item.RateLimit}, []int{tc.src, tc.dst, tc.rate})
			q0Equal(t, "dst_ip", item.DstIP, tc.ip)
			if tc.src == 0 && tc.dst == 0 && tc.rate == 0 {
				b, _ := json.Marshal(item)
				m := q0JSON(t, b)
				for _, key := range []string{"src_port", "dst_port", "rate_limit"} {
					if _, exists := m[key]; exists {
						t.Fatalf("%s must be omitted", key)
					}
				}
			}
		})
	}
}

func TestFEQ0_G4_Docs(t *testing.T) {
	var additions [][]string
	pattern := regexp.MustCompile(`<!-- fe-q0:([^ ]+) -->`)
	for _, path := range []string{"../../API.md", "../../API.zh.md"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		t.Run(path, func(t *testing.T) {
			if !strings.Contains(s, "| GET | `/api/attacks/mitigation-brief` |") {
				t.Fatal("new route missing from route table")
			}
			for _, field := range []string{"dst_ip", "ended_after", "action_mode", "last_stats_at", "upstream_sample_rate", "threshold_value", "threshold_unit", "src_port", "dst_port", "rate_limit", "scheduled_for"} {
				if !strings.Contains(s, "`"+field+"`") {
					t.Fatalf("missing field %s", field)
				}
			}
		})
		var ids []string
		for _, m := range pattern.FindAllStringSubmatch(s, -1) {
			ids = append(ids, m[1])
		}
		additions = append(additions, ids)
	}
	q0Equal(t, "EN/ZH added entries", additions[0], additions[1])
	q0Equal(t, "added entries per language", len(additions[0]), 10)
	r := NewRouter(Dependencies{})
	found := false
	for _, route := range r.Routes() {
		if route.Method == "GET" && route.Path == "/api/attacks/mitigation-brief" {
			found = true
		}
	}
	q0Equal(t, "documented route registered", found, true)
}
