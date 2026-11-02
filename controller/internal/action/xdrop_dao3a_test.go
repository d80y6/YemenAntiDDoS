package action

// Tests for concentration-based narrowing and protocol-level fallback rate limiting.
// Coverage includes single-body fallback behavior and top-k dispatch.
// Exercise executeXDrop / analyzeFlows / v3Mock.serve / v3Store / config.Load.
// v3Mock replaces http.DefaultTransport and calls serve in process, without httptest.Server or listeners.
// The store uses v3Store and d3aStore, which adds a counted Thresholds() fake; no database is required.
// Fixture failures use t.Fatalf("device: ...").
// Seeds whose leading share is below T1 but whose top k reach T2 assert multiple rules through
// d3bExecute / d3bCheckTopK in xdrop_dao3b_test.go, checking every POST. The original fallback and threshold assertions remain
// in corresponding _below_t2 subcases using d3aSpread seeds: 13 rows, a 10% leader, and the top 8 reaching only 75%, below T2.

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/config"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

const d3aHost = "xdrop-d3a.invalid"

type d3aRT func(*http.Request) (*http.Response, error)

func (f d3aRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// d3aMock returns the existing v3 contract mock served in-process (no listener).
func d3aMock(t *testing.T) *v3Mock {
	t.Helper()
	m := &v3Mock{rules: map[string]*v3Rule{}, epoch: "epoch-test"}
	old := http.DefaultTransport
	http.DefaultTransport = d3aRT(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != d3aHost {
			return nil, fmt.Errorf("d3a-device: refused non-mock host %q", r.URL.Host)
		}
		if r.Body == nil {
			r = r.Clone(r.Context())
			r.Body = http.NoBody
		}
		rec := httptest.NewRecorder()
		m.serve(rec, r)
		res := rec.Result()
		res.Request = r
		return res, nil
	})
	t.Cleanup(func() { http.DefaultTransport = old })
	return m
}

// d3aStore adds a counting Thresholds() to v3Store (whose embedded nil
// store.Store would panic on Thresholds()).
type d3aStore struct {
	*v3Store
	tmu        sync.Mutex
	thresholds map[int]*store.Threshold
	thErr      error
	accessor   int
	gets       []int
}
type d3aThresholds struct {
	store.ThresholdRepo
	s *d3aStore
}

func (s *d3aStore) Thresholds() store.ThresholdRepo {
	s.tmu.Lock()
	s.accessor++
	s.tmu.Unlock()
	return d3aThresholds{s: s}
}
func (r d3aThresholds) Get(_ context.Context, id int) (*store.Threshold, error) {
	r.s.tmu.Lock()
	defer r.s.tmu.Unlock()
	r.s.gets = append(r.s.gets, id)
	if r.s.thErr != nil {
		return nil, r.s.thErr
	}
	th := r.s.thresholds[id]
	if th == nil {
		return nil, nil
	}
	cp := *th
	return &cp, nil
}
func (s *d3aStore) lookups() (int, []int) {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	return s.accessor + len(s.gets), append([]int(nil), s.gets...)
}

const d3aThID = 42

func d3aNewStore(unit string, value int64) *d3aStore {
	s := &d3aStore{v3Store: newV3Store("http://" + d3aHost), thresholds: map[int]*store.Threshold{}}
	if unit != "" {
		s.thresholds[d3aThID] = &store.Threshold{ID: d3aThID, Unit: unit, Value: value, Enabled: true, Decoder: "udp", Direction: "receives", Comparison: "over"}
	}
	return s
}

func d3aAttack(dec, dst string, withThreshold bool) *store.Attack {
	a := v3Attack(301, dec, dst)
	if withThreshold {
		id := d3aThID
		a.ThresholdRuleID = &id
	}
	return a
}

type d3aRun struct {
	log   store.ActionExecutionLog
	body  map[string]any
	posts int
	calls int
	ids   []int
}

func d3aExecute(t *testing.T, m *v3Mock, s *d3aStore, a *store.Attack, act store.ResponseAction, fa *FlowAnalysis) d3aRun {
	t.Helper()
	before := len(s.logSnapshot())
	l, _ := executeXDrop(context.Background(), s, act, a, "confirmed", a.DstIP, "d3a", act.TriggerPhase, a.ID, fa, nil)
	if l != nil {
		_, _ = s.ActionExecLog().Create(context.Background(), l)
	}
	logs := s.logSnapshot()
	if len(logs) <= before {
		t.Fatalf("device: no execution log")
	}
	out := d3aRun{log: logs[len(logs)-1]}
	if strings.Contains(out.log.ErrorMessage, "d3a-device:") {
		t.Fatalf("device: request escaped the in-process mock: %s", out.log.ErrorMessage)
	}
	for _, req := range m.snapshot() {
		if req.Method == "POST" && req.Path == "/rules" {
			out.posts++
			out.body = nil
			if err := json.Unmarshal(req.Body, &out.body); err != nil {
				t.Fatalf("device: POST body not JSON: %v", err)
			}
		}
	}
	out.calls, out.ids = s.lookups()
	return out
}

// d3aFlows builds n flow rows of the given protocol/flags; row(i) returns src, sport, dport, packets.
func d3aFlows(proto, flags, n int, row func(i int) (string, int, int, int64)) []store.FlowLog {
	var out []store.FlowLog
	for i := 0; i < n; i++ {
		src, sport, dport, pkts := row(i)
		out = append(out, store.FlowLog{SrcIP: src, DstIP: "198.51.100.7", SrcPort: sport, DstPort: dport, Protocol: proto, TCPFlags: flags, Packets: pkts})
	}
	return out
}
func d3aSrc(i int) string { return fmt.Sprintf("192.0.2.%d", 10+i) }

// Scenario flow sets (10 rows x 100 packets = 1000 samples unless stated).
var (
	d3aConcentratedDst = func(i int) (string, int, int, int64) { // dst 53 = 90%, src port 10%, src ip 10%
		dport := 53
		if i == 9 {
			dport = 80
		}
		return d3aSrc(i), 10000 + i, dport, 100
	}
	d3aRandom = func(i int) (string, int, int, int64) { // every dimension 10%
		return d3aSrc(i), 10000 + i, 1000 + i, 100
	}
	d3aReflection = func(i int) (string, int, int, int64) { // src port 53 = 100%, dst 10%
		return d3aSrc(i), 53, 1000 + i, 100
	}
	d3aBothPorts = func(i int) (string, int, int, int64) { // src 53 = 90%, dst 53 = 90%
		if i == 9 {
			return d3aSrc(i), 54, 80, 100
		}
		return d3aSrc(i), 53, 53, 100
	}
	d3aSingleSource = func(i int) (string, int, int, int64) { // src ip = 100%, ports 10%
		return "192.0.2.10", 10000 + i, 1000 + i, 100
	}
	d3aPortZero = func(i int) (string, int, int, int64) { // dst port 0 = 90%
		dport := 0
		if i == 9 {
			dport = 80
		}
		return d3aSrc(i), 10000 + i, dport, 100
	}
	d3aLowSample = func(i int) (string, int, int, int64) { // concentrated but 100 samples
		src, sport, dport, _ := d3aConcentratedDst(i)
		return src, sport, dport, 10
	}
	// Below-T2 seeds: 13 rows (7 x 100 + 6 x 50 = 1000 samples); every dimension's top
	// share is 10% and its top 8 reach 75% < T2, so the single-body fallback and threshold paths stay covered.
	d3aSpread = func(i int) (string, int, int, int64) {
		pkts := int64(100)
		if i >= 7 {
			pkts = 50
		}
		return d3aSrc(i), 10000 + i, 1000 + i, pkts
	}
	d3aPortZeroSpread = func(i int) (string, int, int, int64) { // dst port 0 = 90%, src ports spread
		src, sport, _, pkts := d3aSpread(i)
		if i == 0 {
			return src, sport, 80, pkts
		}
		return src, sport, 0, pkts
	}
	d3aSingleSourceSpread = func(i int) (string, int, int, int64) { // src ip = 100%, ports spread
		_, sport, dport, pkts := d3aSpread(i)
		return "192.0.2.10", sport, dport, pkts
	}
)

// d3aSrc8 = the top-8 source ports of d3aRandom / d3aPortZero / d3aSingleSource (10 x 10%: k = 8, src wins the tie).
var d3aSrc8 = []int{10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007}

// d3aTopK runs the call with every POST / log kept and checks the top-k multi-row result.
func d3aTopK(t *testing.T, m *v3Mock, s *d3aStore, a *store.Attack, act store.ResponseAction, fa *FlowAnalysis, w d3bWant) d3bRun {
	t.Helper()
	r := d3bExecute(t, m, s, a, act, fa)
	d3bCheckTopK(t, r, a, act.ID, w)
	return r
}

// d3aFA runs the production analyzeFlows over the given flows.
func d3aFA(t *testing.T, s *d3aStore, a *store.Attack, flows []store.FlowLog) *FlowAnalysis {
	t.Helper()
	s.flows = flows
	fa := analyzeFlows(context.Background(), s, a)
	if fa == nil {
		t.Fatalf("device: analyzeFlows returned nil for %d rows", len(flows))
	}
	return fa
}

func d3aHas(m map[string]any, key string) bool { _, ok := m[key]; return ok }

// d3aCheckLookups: fallback => exactly one Get(42); otherwise no Thresholds() access at all.
func d3aCheckLookups(t *testing.T, r d3aRun, fallback bool) {
	t.Helper()
	if fallback {
		if len(r.ids) != 1 || r.ids[0] != d3aThID {
			t.Errorf("fallback threshold Get ids=%v want [%d]", r.ids, d3aThID)
		}
		return
	}
	if r.calls != 0 {
		t.Errorf("threshold accessed without fallback: accessor+get=%d ids=%v", r.calls, r.ids)
	}
}

func d3aWebAction() store.ResponseAction { return v3Action(31, v3WebPayload) }

// ---------------------------------------------------------------- S01 / S06

func TestD3A_S01_ShapeMatrixE2E(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		row                    func(int) (string, int, int, int64)
		n                      int
		dst                    string
		wantDst, wantSrc       any
		wantSrcIP              string // "" = absent
		wantAction             string
		wantRate               float64
		wantHints, absentHints []string
		topk                   []int // Top-k: expected source-port rules.
	}{
		{"dst_only", d3aConcentratedDst, 10, "198.51.100.7", float64(53), nil, "", "drop", 0,
			[]string{"shape: kept dst_port=90%", "shape: dropped src_port=10%", "shape: dropped src_ip=10%"}, []string{"shape: fallback"}, nil},
		{"src_only", d3aReflection, 10, "198.51.100.7", nil, float64(53), "", "drop", 0,
			[]string{"shape: kept src_port=100%", "shape: dropped dst_port=10%"}, []string{"shape: fallback"}, nil},
		{"both_keep_src", d3aBothPorts, 10, "198.51.100.7", nil, float64(53), "", "drop", 0,
			[]string{"shape: kept src_port=90%", "shape: dropped dst_port=90%"}, []string{"shape: kept dst_port"}, nil},
		{"neither_fallback", d3aRandom, 10, "198.51.100.7", nil, nil, "", "drop", 0,
			[]string{"shape: dropped dst_port=10%", "shape: topk src_port=8 80%", "shape: dropped src_ip=10%"}, []string{"shape: fallback", "fallback rate unavailable"}, d3aSrc8},
		{"port_zero_fallback", d3aPortZero, 10, "198.51.100.7", nil, nil, "", "drop", 0,
			[]string{"shape: topk src_port=8 80%"}, []string{"shape: fallback", "shape: kept"}, d3aSrc8},
		{"single_source", d3aSingleSource, 10, "198.51.100.0/24", nil, nil, "192.0.2.10/32", "drop", 0,
			[]string{"shape: kept src_ip=100%", "shape: topk src_port=8 80%"}, []string{"shape: fallback"}, d3aSrc8},
		{"neither_fallback_below_t2", d3aSpread, 13, "198.51.100.7", nil, nil, "", "rate_limit", 50000,
			[]string{"shape: dropped dst_port=10%", "shape: dropped src_port=10%", "shape: dropped src_ip=10%", "shape: fallback rate_limit=50000"}, nil, nil},
		{"port_zero_fallback_below_t2", d3aPortZeroSpread, 13, "198.51.100.7", nil, nil, "", "rate_limit", 50000,
			[]string{"shape: fallback rate_limit=50000"}, []string{"shape: kept"}, nil},
		{"single_source_below_t2", d3aSingleSourceSpread, 13, "198.51.100.0/24", nil, nil, "192.0.2.10/32", "drop", 0,
			[]string{"shape: kept src_ip=100%"}, []string{"shape: fallback"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 50000)
			a := d3aAttack("udp", tc.dst, true)
			fa := d3aFA(t, s, a, d3aFlows(17, 0, tc.n, tc.row))
			if tc.topk != nil {
				same := map[string]any{"action": tc.wantAction}
				absent := []string{"dst_port", "rate_limit", "src_ip", "src_cidr"}
				if tc.wantSrcIP != "" {
					same["src_cidr"] = tc.wantSrcIP
					absent = []string{"dst_port", "rate_limit", "src_ip"}
				}
				rb := d3aTopK(t, m, s, a, d3aWebAction(), fa, d3bWant{dim: "src_port", ports: tc.topk, pct: 80, absent: absent, same: same})
				for _, l := range rb.logs {
					for _, h := range tc.wantHints {
						if !strings.Contains(l.ErrorMessage, h) {
							t.Errorf("missing hint %q in %q", h, l.ErrorMessage)
						}
					}
					for _, h := range tc.absentHints {
						if strings.Contains(l.ErrorMessage, h) {
							t.Errorf("unexpected hint %q in %q", h, l.ErrorMessage)
						}
					}
				}
				d3aCheckLookups(t, d3aRun{calls: rb.calls, ids: rb.ids}, false)
				return
			}
			r := d3aExecute(t, m, s, a, d3aWebAction(), fa)
			v3Success(t, r.log)
			if r.posts != 1 {
				t.Fatalf("POST count=%d", r.posts)
			}
			for _, key := range []string{"dst_port", "src_port"} {
				want := tc.wantDst
				if key == "src_port" {
					want = tc.wantSrc
				}
				if want == nil && d3aHas(r.body, key) || want != nil && r.body[key] != want {
					t.Errorf("%s=%v want %v (body %v)", key, r.body[key], want, r.body)
				}
			}
			srcKey := "src_ip"
			if strings.Contains(tc.dst, "/") {
				srcKey = "src_cidr"
			}
			if tc.wantSrcIP == "" && (d3aHas(r.body, "src_ip") || d3aHas(r.body, "src_cidr")) || tc.wantSrcIP != "" && r.body[srcKey] != tc.wantSrcIP {
				t.Errorf("source=%v/%v want %q", r.body["src_ip"], r.body["src_cidr"], tc.wantSrcIP)
			}
			if r.body["action"] != tc.wantAction {
				t.Errorf("action=%v want %s", r.body["action"], tc.wantAction)
			}
			if tc.wantRate == 0 && d3aHas(r.body, "rate_limit") || tc.wantRate != 0 && r.body["rate_limit"] != tc.wantRate {
				t.Errorf("rate_limit=%v want %v", r.body["rate_limit"], tc.wantRate)
			}
			for _, h := range tc.wantHints {
				if !strings.Contains(r.log.ErrorMessage, h) {
					t.Errorf("missing hint %q in %q", h, r.log.ErrorMessage)
				}
			}
			for _, h := range tc.absentHints {
				if strings.Contains(r.log.ErrorMessage, h) {
					t.Errorf("unexpected hint %q in %q", h, r.log.ErrorMessage)
				}
			}
			d3aCheckLookups(t, r, tc.wantAction == "rate_limit")
		})
	}
}

func TestD3A_S01_BoundaryE2E(t *testing.T) {
	// dst share exactly 80% => kept (>= T1); 79% => dropped => fallback.
	for _, tc := range []struct {
		name string
		rows []store.FlowLog
		keep bool
		topk []int // Top-k: 79% plus the next 1% reach T2, yielding two destination-port rules.
	}{
		{"pct80_kept", d3aFlows(17, 0, 28, func(i int) (string, int, int, int64) {
			if i < 8 {
				return d3aSrc(i), 10000 + i, 53, 100
			}
			return d3aSrc(i), 10000 + i, 2000 + i, 10
		}), true, nil},
		{"pct79_dropped", d3aFlows(17, 0, 29, func(i int) (string, int, int, int64) {
			switch {
			case i < 7:
				return d3aSrc(i), 10000 + i, 53, 100
			case i == 7:
				return d3aSrc(i), 10000 + i, 53, 90
			}
			return d3aSrc(i), 10000 + i, 2000 + i, 10
		}), false, []int{53, 2008}},
		// 79% + 210 one-packet rows: the top 8 reach 79.7% < T2, selecting the single-body fallback.
		{"pct79_dropped_below_t2", d3aFlows(17, 0, 218, func(i int) (string, int, int, int64) {
			switch {
			case i < 7:
				return d3aSrc(i), 10000 + i, 53, 100
			case i == 7:
				return d3aSrc(i), 10000 + i, 53, 90
			}
			return d3aSrc(i), 10000 + i, 2000 + i, 1
		}), false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 50000)
			a := d3aAttack("udp", "198.51.100.7", true)
			fa := d3aFA(t, s, a, tc.rows)
			if fa.DominantDstPort != 53 || (tc.keep && fa.DominantDstPortPct != 80) || (!tc.keep && fa.DominantDstPortPct != 79) {
				t.Fatalf("device: fixture share %+v", fa)
			}
			if tc.topk != nil {
				d3aTopK(t, m, s, a, d3aWebAction(), fa, d3bWant{dim: "dst_port", ports: tc.topk, pct: 80, absent: []string{"src_port", "src_ip", "rate_limit"}, same: map[string]any{"action": "drop"}})
				return
			}
			r := d3aExecute(t, m, s, a, d3aWebAction(), fa)
			v3Success(t, r.log)
			if tc.keep && (r.body["dst_port"] != float64(53) || r.body["action"] != "drop") {
				t.Fatalf("80%% must keep dst_port: %v", r.body)
			}
			if !tc.keep && (d3aHas(r.body, "dst_port") || r.body["action"] != "rate_limit") {
				t.Fatalf("79%% must drop dst_port and fall back: %v", r.body)
			}
		})
	}
}

// ---------------------------------------------------------------- S02

func TestD3A_S02_LowSampleE2E(t *testing.T) {
	t.Run("below_N", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		fa := d3aFA(t, s, a, d3aFlows(17, 0, 10, d3aLowSample))
		if fa.DominantDstPortPct != 90 {
			t.Fatalf("device: fixture %+v", fa)
		}
		r := d3aExecute(t, m, s, a, d3aWebAction(), fa)
		v3Success(t, r.log)
		v3NoKeys(t, r.body, "dst_port", "src_port", "src_ip", "src_cidr")
		if r.body["action"] != "rate_limit" || r.body["rate_limit"] != float64(50000) {
			t.Fatalf("low sample must fall back: %v", r.body)
		}
		if !strings.Contains(r.log.ErrorMessage, "shape: samples 100 < 1000") || strings.Contains(r.log.ErrorMessage, "shape: kept") {
			t.Fatalf("hints=%q", r.log.ErrorMessage)
		}
	})
	t.Run("fa_nil", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		r := d3aExecute(t, m, s, a, d3aWebAction(), nil)
		v3Success(t, r.log)
		v3NoKeys(t, r.body, "dst_port", "src_port", "src_ip", "src_cidr")
		if r.body["action"] != "rate_limit" || r.body["rate_limit"] != float64(50000) {
			t.Fatalf("fa=nil must fall back: %v", r.body)
		}
		if !strings.Contains(r.log.ErrorMessage, "shape: samples 0 < 1000") {
			t.Fatalf("hints=%q", r.log.ErrorMessage)
		}
	})
}

// ---------------------------------------------------------------- S03

// S03 seeds: every exclusion cell carries a valid pps
// threshold (1000), a permitted src_ip and too few samples, so the only reason
// not to fall back is the exclusion under test.
const d3aSrcIPTpl = `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","protocol":"{decoder}","action":"drop"}`

func d3aLowSampleV6(i int) (string, int, int, int64) {
	_, sport, dport, pkts := d3aLowSample(i)
	return fmt.Sprintf("2001:db8:1::%d", i+1), sport, dport, pkts
}

func TestD3A_S03_FallbackScopeE2E(t *testing.T) {
	type tc struct {
		name, dec, dst, payload, xdropAction string
		row                                  func(int) (string, int, int, int64)
		proto                                int
		wantAction                           string
		wantRate                             float64
		wantKeys                             map[string]any
	}
	webRate := `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","dst_port":"{dominant_dst_port}","src_port":"{dominant_src_port}","protocol":"{decoder}","action":"rate_limit","rate_limit":5000}`
	for _, c := range []tc{
		// guards: operator action unchanged, no threshold access at all
		{"guard_unpermitted", "udp", "198.51.100.7", `{"dst_ip":"{dst_ip}","protocol":"{decoder}","action":"drop"}`, "filter_l4", d3aLowSample, 17, "drop", 0, nil},
		{"guard_literal_port", "udp", "198.51.100.7", `{"dst_ip":"{dst_ip}","dst_port":53,"protocol":"{decoder}","action":"drop"}`, "filter_l4", d3aLowSample, 17, "drop", 0, map[string]any{"dst_port": float64(53)}},
		{"guard_default_payload", "udp", "198.51.100.7", "", "filter_l4", d3aLowSample, 17, "drop", 0, nil},
		{"guard_operator_rate_enum", "udp", "198.51.100.7", webRate, "rate_limit", d3aLowSample, 17, "rate_limit", 5000, nil},
		{"guard_operator_rate_body", "udp", "198.51.100.7", webRate, "filter_l4", d3aLowSample, 17, "rate_limit", 5000, nil},
		{"guard_fragment_v4", "fragment", "198.51.100.7", d3aSrcIPTpl, "filter_l4", d3aLowSample, 17, "drop", 0, map[string]any{"fragment": "frag", "protocol": "all"}},
		{"guard_fragment_v6", "fragment", "2001:db8::7", d3aSrcIPTpl, "filter_l4", d3aLowSampleV6, 17, "drop", 0, map[string]any{"protocol": "all"}},
		{"guard_anomaly_invalid", "invalid", "198.51.100.7", d3aSrcIPTpl, "filter_l4", d3aLowSample, 17, "drop", 0, map[string]any{"match_anomaly": float64(2)}},
		{"guard_anomaly_bad_fragment", "bad_fragment", "198.51.100.7", d3aSrcIPTpl, "filter_l4", d3aLowSample, 17, "drop", 0, map[string]any{"match_anomaly": float64(1)}},
		{"guard_portless_ports_only", "icmp", "198.51.100.7", `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","src_port":"{dominant_src_port}","protocol":"{decoder}","action":"drop"}`, "filter_l4", d3aLowSample, 1, "drop", 0, nil},
		// behaviour: same seeds, fallback conditions all hold
		{"udp_src_ip_fallback", "udp", "198.51.100.7", d3aSrcIPTpl, "filter_l4", d3aLowSample, 17, "rate_limit", 1000, nil},
		{"portless_src_ip_fallback", "icmp", "198.51.100.7", d3aSrcIPTpl, "filter_l4", d3aLowSample, 1, "rate_limit", 1000, map[string]any{"protocol": "icmp"}},
		{"absent_action_is_drop", "udp", "198.51.100.7", `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","protocol":"{decoder}"}`, "filter_l4", d3aLowSample, 17, "rate_limit", 1000, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 1000)
			a := d3aAttack(c.dec, c.dst, true)
			rows := d3aFlows(c.proto, 0, 10, c.row)
			var total int64
			for _, f := range rows {
				total += f.Packets
			}
			if total >= 1000 {
				t.Fatalf("device: S03 seed must be below N=1000, has %d", total)
			}
			fa := d3aFA(t, s, a, rows)
			act := v3Action(41, c.payload)
			act.XDropAction = c.xdropAction
			r := d3aExecute(t, m, s, a, act, fa)
			v3Success(t, r.log)
			if r.body["action"] != c.wantAction {
				t.Errorf("action=%v want %s (body %v)", r.body["action"], c.wantAction, r.body)
			}
			if c.wantRate == 0 && d3aHas(r.body, "rate_limit") || c.wantRate != 0 && r.body["rate_limit"] != c.wantRate {
				t.Errorf("rate_limit=%v want %v (operator rate must survive; threshold is 1000)", r.body["rate_limit"], c.wantRate)
			}
			for k, v := range c.wantKeys {
				if r.body[k] != v {
					t.Errorf("%s=%v want %v", k, r.body[k], v)
				}
			}
			guard := strings.HasPrefix(c.name, "guard_")
			if guard && strings.Contains(r.log.ErrorMessage, "fallback") {
				t.Errorf("guard case logged a fallback hint: %q", r.log.ErrorMessage)
			}
			d3aCheckLookups(t, r, !guard)
		})
	}
}

// v0.3 §三-4: a literal narrowing condition in the template excludes fallback.
// Seed: literal src_port 123 + permitted {dominant_dst_port} not reaching T1
// (dst 10%, samples 1000) + operator drop + valid pps threshold.
func TestD3A_S03_LiteralConditionExcludesFallbackE2E(t *testing.T) {
	m := d3aMock(t)
	s := d3aNewStore("pps", 1000)
	a := d3aAttack("udp", "198.51.100.7", true)
	fa := d3aFA(t, s, a, d3aFlows(17, 0, 10, d3aRandom))
	if fa.DominantDstPortPct != 10 {
		t.Fatalf("device: dst share %d want 10", fa.DominantDstPortPct)
	}
	act := v3Action(42, `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","src_port":123,"protocol":"{decoder}","action":"drop"}`)
	rb := d3aTopK(t, m, s, a, act, fa, d3bWant{dim: "dst_port", ports: []int{1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007}, pct: 80,
		absent: []string{"rate_limit"}, same: map[string]any{"src_port": float64(123), "action": "drop"}})
	r := d3aRun{log: rb.last, body: rb.posts[len(rb.posts)-1], posts: len(rb.posts), calls: rb.calls, ids: rb.ids}
	v3Success(t, r.log)
	if r.body["src_port"] != float64(123) {
		t.Fatalf("device: literal src_port not carried: %v", r.body)
	}
	if r.body["action"] != "drop" || d3aHas(r.body, "rate_limit") {
		t.Errorf("literal condition must keep operator drop: %v", r.body)
	}
	if strings.Contains(r.log.ErrorMessage, "shape: fallback") || strings.Contains(r.log.ErrorMessage, "fallback rate unavailable") {
		t.Errorf("fallback hint logged: %q", r.log.ErrorMessage)
	}
	d3aCheckLookups(t, r, false)
}

// Below-T2 twin of TestD3A_S03_LiteralConditionExcludesFallbackE2E: the original single-body assertions.
func TestD3A_S03_LiteralConditionExcludesFallbackBelowT2E2E(t *testing.T) {
	m := d3aMock(t)
	s := d3aNewStore("pps", 1000)
	a := d3aAttack("udp", "198.51.100.7", true)
	fa := d3aFA(t, s, a, d3aFlows(17, 0, 13, d3aSpread))
	if fa.DominantDstPortPct != 10 {
		t.Fatalf("device: dst share %d want 10", fa.DominantDstPortPct)
	}
	r := d3aExecute(t, m, s, a, v3Action(42, `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","src_port":123,"protocol":"{decoder}","action":"drop"}`), fa)
	v3Success(t, r.log)
	if r.posts != 1 {
		t.Fatalf("POST count=%d want 1", r.posts)
	}
	if r.body["src_port"] != float64(123) {
		t.Fatalf("device: literal src_port not carried: %v", r.body)
	}
	if r.body["action"] != "drop" || d3aHas(r.body, "rate_limit") {
		t.Errorf("literal condition must keep operator drop: %v", r.body)
	}
	if strings.Contains(r.log.ErrorMessage, "shape: fallback") || strings.Contains(r.log.ErrorMessage, "fallback rate unavailable") {
		t.Errorf("fallback hint logged: %q", r.log.ErrorMessage)
	}
	d3aCheckLookups(t, r, false)
}

// v0.4 §三-4 (r2 N1): a literal that cleaning/sanitize/finalize removes is not
// an effective condition and must not block fallback. Each seed carries one
// permitted dimension below T1 and a valid pps threshold (1000).
func TestD3A_S03_IneffectiveLiteralFallsBackE2E(t *testing.T) {
	type ineffective struct {
		name, dec, payload string
		proto              int
		n                  int
		row                func(int) (string, int, int, int64)
		topk               bool // Top-k: d3aRandom's 10 destination ports reach T2, yielding eight destination-port rules and no fallback.
	}
	var cases []ineffective
	for _, c := range []ineffective{
		{"zero_literal_src_ip", "udp", `{"dst_ip":"{dst_ip}","src_ip":"0.0.0.0","dst_port":"{dominant_dst_port}","protocol":"{decoder}","action":"drop"}`, 17, 10, d3aRandom, true},
		{"zero_literal_src_port_string", "udp", `{"dst_ip":"{dst_ip}","src_port":"0","dst_port":"{dominant_dst_port}","protocol":"{decoder}","action":"drop"}`, 17, 10, d3aRandom, true},
		{"zero_literal_src_port_number", "udp", `{"dst_ip":"{dst_ip}","src_port":0,"dst_port":"{dominant_dst_port}","protocol":"{decoder}","action":"drop"}`, 17, 10, d3aRandom, true},
		{"portless_literal_port", "icmp", `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","dst_port":53,"protocol":"{decoder}","action":"drop"}`, 1, 10, d3aRandom, false},
	} {
		cases = append(cases, c)
		if c.topk {
			cases = append(cases, ineffective{c.name + "_below_t2", c.dec, c.payload, c.proto, 13, d3aSpread, false})
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 1000)
			a := d3aAttack(c.dec, "198.51.100.7", true)
			fa := d3aFA(t, s, a, d3aFlows(c.proto, 0, c.n, c.row))
			if fa.DominantDstPortPct != 10 {
				t.Fatalf("device: permitted dimension share %d want 10", fa.DominantDstPortPct)
			}
			if c.topk {
				rb := d3aTopK(t, m, s, a, v3Action(43, c.payload), fa, d3bWant{dim: "dst_port", ports: []int{1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007}, pct: 80,
					absent: []string{"src_ip", "src_cidr", "rate_limit"}, same: map[string]any{"action": "drop"}})
				for i, b := range rb.posts {
					if p, ok := b["src_port"]; ok && p != float64(0) {
						t.Errorf("item %d unexpected src_port=%v", i+1, p)
					}
				}
				for _, l := range rb.logs {
					if strings.Contains(l.ErrorMessage, "shape: fallback") || strings.Contains(l.ErrorMessage, "fallback rate unavailable") {
						t.Errorf("top-k items logged a fallback hint: %q", l.ErrorMessage)
					}
				}
				d3aCheckLookups(t, d3aRun{calls: rb.calls, ids: rb.ids}, false)
				return
			}
			r := d3aExecute(t, m, s, a, v3Action(43, c.payload), fa)
			v3Success(t, r.log)
			if r.body["action"] != "rate_limit" || r.body["rate_limit"] != float64(1000) {
				t.Errorf("ineffective literal must not block fallback: %v", r.body)
			}
			v3NoKeys(t, r.body, "src_ip", "src_cidr", "dst_port")
			if p, ok := r.body["src_port"]; ok && p != float64(0) {
				t.Errorf("unexpected src_port=%v", p)
			}
			if !strings.Contains(r.log.ErrorMessage, "shape: fallback rate_limit=1000") {
				t.Errorf("missing fallback hint: %q", r.log.ErrorMessage)
			}
			d3aCheckLookups(t, r, true)
		})
	}
}

// ---------------------------------------------------------------- S04

func TestD3A_S04_ThresholdE2E(t *testing.T) {
	type threshold struct {
		name        string
		unit        string
		value       int64
		withID      bool
		readErr     error
		wantAction  string
		wantRate    float64
		wantGets    int
		unavailable bool
	}
	for _, c := range []threshold{
		{"pps", "pps", 50000, true, nil, "rate_limit", 50000, 1, false},
		{"pps_one", "pps", 1, true, nil, "rate_limit", 1, 1, false},
		{"pps_clamped", "pps", 5_000_000_000, true, nil, "rate_limit", 4294967295, 1, false},
		{"pps_uint32_max", "pps", 4294967295, true, nil, "rate_limit", 4294967295, 1, false},
		{"bps", "bps", 50000, true, nil, "drop", 0, 1, true},
		{"pct", "pct", 50, true, nil, "drop", 0, 1, true},
		{"pps_zero", "pps", 0, true, nil, "drop", 0, 1, true},
		{"nil_rule_id", "pps", 50000, false, nil, "drop", 0, 0, true},
		{"row_deleted", "", 0, true, nil, "drop", 0, 1, true},
		{"read_error", "pps", 50000, true, fmt.Errorf("db down"), "drop", 0, 1, true},
	} {
		// d3aRandom reaches T2 on both port dimensions, yielding eight source-port rules with no threshold access.
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore(c.unit, c.value)
			s.thErr = c.readErr
			a := d3aAttack("udp", "198.51.100.7", c.withID)
			fa := d3aFA(t, s, a, d3aFlows(17, 0, 10, d3aRandom))
			rb := d3aTopK(t, m, s, a, d3aWebAction(), fa, d3bWant{dim: "src_port", ports: d3aSrc8, pct: 80, absent: []string{"dst_port", "src_ip", "rate_limit"}, same: map[string]any{"action": "drop"}})
			if rb.calls != 0 || len(rb.ids) != 0 {
				t.Errorf("top-k branch accessed thresholds: accessor+get=%d ids=%v", rb.calls, rb.ids)
			}
			for _, l := range rb.logs {
				if strings.Contains(l.ErrorMessage, "fallback rate unavailable: ") || strings.Contains(l.ErrorMessage, "shape: fallback") {
					t.Errorf("top-k items logged a fallback hint: %q", l.ErrorMessage)
				}
			}
		})
		// The original threshold-branch assertions on the below-T2 seed.
		t.Run(c.name+"_below_t2", func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore(c.unit, c.value)
			s.thErr = c.readErr
			a := d3aAttack("udp", "198.51.100.7", c.withID)
			fa := d3aFA(t, s, a, d3aFlows(17, 0, 13, d3aSpread))
			r := d3aExecute(t, m, s, a, d3aWebAction(), fa)
			v3Success(t, r.log)
			if r.posts != 1 {
				t.Fatalf("POST count=%d", r.posts)
			}
			v3NoKeys(t, r.body, "dst_port", "src_port", "src_ip")
			if r.body["action"] != c.wantAction {
				t.Errorf("action=%v want %s", r.body["action"], c.wantAction)
			}
			if c.wantRate == 0 && d3aHas(r.body, "rate_limit") || c.wantRate != 0 && r.body["rate_limit"] != c.wantRate {
				t.Errorf("rate_limit=%v want %v", r.body["rate_limit"], c.wantRate)
			}
			if _, ids := s.lookups(); len(ids) != c.wantGets || c.wantGets > 0 && ids[0] != d3aThID {
				t.Errorf("Get ids=%v want %d call(s) with id %d", ids, c.wantGets, d3aThID)
			}
			has := strings.Contains(r.log.ErrorMessage, "fallback rate unavailable: ")
			if has != c.unavailable {
				t.Errorf("unavailable hint=%v want %v: %q", has, c.unavailable, r.log.ErrorMessage)
			}
			if !c.unavailable && !strings.Contains(r.log.ErrorMessage, fmt.Sprintf("shape: fallback rate_limit=%d", int64(c.wantRate))) {
				t.Errorf("missing fallback hint: %q", r.log.ErrorMessage)
			}
		})
	}
	t.Run("no_fallback_no_lookup", func(t *testing.T) {
		for name, row := range map[string]func(int) (string, int, int, int64){"dst": d3aConcentratedDst, "src_port": d3aReflection, "src_ip": d3aSingleSource} {
			t.Run(name, func(t *testing.T) {
				m := d3aMock(t)
				s := d3aNewStore("pps", 50000)
				a := d3aAttack("udp", "198.51.100.7", true)
				fa := d3aFA(t, s, a, d3aFlows(17, 0, 10, row))
				var r d3aRun
				if name == "src_ip" {
					// A single source plus d3aSingleSource's 10 source ports yields eight source-port rules, each retaining the source.
					rb := d3aTopK(t, m, s, a, d3aWebAction(), fa, d3bWant{dim: "src_port", ports: d3aSrc8, pct: 80, absent: []string{"dst_port", "rate_limit"},
						same: map[string]any{"src_ip": "192.0.2.10", "action": "drop"}})
					r = d3aRun{log: rb.last, body: rb.posts[len(rb.posts)-1], posts: len(rb.posts), calls: rb.calls, ids: rb.ids}
				} else {
					r = d3aExecute(t, m, s, a, d3aWebAction(), fa)
				}
				v3Success(t, r.log)
				if r.calls != 0 {
					t.Fatalf("threshold looked up without fallback: %d (%v)", r.calls, r.ids)
				}
				if r.body["action"] != "drop" {
					t.Fatalf("action=%v", r.body["action"])
				}
			})
		}
	})
}

// ---------------------------------------------------------------- S05

var d3aHintFormats = []*regexp.Regexp{
	regexp.MustCompile(`^shape: (kept|dropped) (dst_port|src_port|src_ip)=\d+%$`),
	regexp.MustCompile(`^shape: samples \d+ < \d+$`),
	regexp.MustCompile(`^shape: fallback rate_limit=\d+$`),
	regexp.MustCompile(`^fallback rate unavailable: \S.*$`),
	// Top-k hints: exact formats only.
	regexp.MustCompile(`^shape: topk (dst_port|src_port)=\d+ \d+%$`),
	regexp.MustCompile(`^shape: item \d+/\d+ (dst_port|src_port)=\d+$`),
}

func d3aCheckHintFormats(t *testing.T, msg string) {
	t.Helper()
	for _, part := range strings.Split(msg, "; ") {
		if !strings.HasPrefix(part, "shape:") && !strings.Contains(part, "fallback") {
			continue
		}
		ok := false
		for _, re := range d3aHintFormats {
			ok = ok || re.MatchString(part)
		}
		if !ok {
			t.Errorf("hint %q does not follow §三-9", part)
		}
		if strings.Contains(part, "protocol pinned:") {
			t.Errorf("shape hint contains protocol pinned: %q", part)
		}
	}
}

func TestD3A_S05_HintsE2E(t *testing.T) {
	// On d3aRandom, every item log carries the exact top-k hints and no fallback hint.
	topkHints := []string{"shape: topk src_port=8 80%", "shape: dropped dst_port=10%", "shape: dropped src_ip=10%"}
	for _, c := range []struct {
		name   string
		row    func(int) (string, int, int, int64)
		n      int
		unit   string
		withID bool
		want   []string
		topk   bool
	}{
		{"kept", d3aConcentratedDst, 10, "pps", true, []string{"shape: kept dst_port=90%", "shape: dropped src_port=10%", "shape: dropped src_ip=10%"}, false},
		{"fallback", d3aRandom, 10, "pps", true, topkHints, true},
		{"samples", d3aLowSample, 10, "pps", true, []string{"shape: samples 100 < 1000", "shape: fallback rate_limit=50000"}, false},
		{"unavailable", d3aRandom, 10, "bps", true, topkHints, true},
		{"unavailable_nil_id", d3aRandom, 10, "pps", false, topkHints, true},
		{"fallback_below_t2", d3aSpread, 13, "pps", true, []string{"shape: dropped dst_port=10%", "shape: dropped src_port=10%", "shape: dropped src_ip=10%", "shape: fallback rate_limit=50000"}, false},
		{"unavailable_below_t2", d3aSpread, 13, "bps", true, []string{"fallback rate unavailable: "}, false},
		{"unavailable_nil_id_below_t2", d3aSpread, 13, "pps", false, []string{"fallback rate unavailable: "}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore(c.unit, 50000)
			a := d3aAttack("udp", "198.51.100.7", c.withID)
			fa := d3aFA(t, s, a, d3aFlows(17, 0, c.n, c.row))
			if c.topk {
				rb := d3aTopK(t, m, s, a, d3aWebAction(), fa, d3bWant{dim: "src_port", ports: d3aSrc8, pct: 80})
				for i, l := range rb.logs {
					for _, h := range append(append([]string(nil), c.want...), fmt.Sprintf("shape: item %d/8 src_port=%d", i+1, d3aSrc8[i]), "dropped: source") {
						if !strings.Contains(l.ErrorMessage, h) {
							t.Errorf("log %d missing %q in %q", i+1, h, l.ErrorMessage)
						}
					}
					for _, h := range []string{"shape: fallback", "fallback rate unavailable", "protocol pinned:", "shape: kept"} {
						if strings.Contains(l.ErrorMessage, h) {
							t.Errorf("log %d unexpected %q in %q", i+1, h, l.ErrorMessage)
						}
					}
					d3aCheckHintFormats(t, l.ErrorMessage)
				}
				return
			}
			r := d3aExecute(t, m, s, a, d3aWebAction(), fa)
			v3Success(t, r.log)
			for _, h := range c.want {
				if !strings.Contains(r.log.ErrorMessage, h) {
					t.Errorf("missing %q in %q", h, r.log.ErrorMessage)
				}
			}
			// {decoder} normalizes to udp => finalize logs no pin; any pin text came from shaping.
			if strings.Contains(r.log.ErrorMessage, "protocol pinned:") {
				t.Errorf("protocol pinned: present: %q", r.log.ErrorMessage)
			}
			if !strings.Contains(r.log.ErrorMessage, "dropped: source") {
				t.Fatalf("device: finalize hints missing from log: %q", r.log.ErrorMessage)
			}
			d3aCheckHintFormats(t, r.log.ErrorMessage)
		})
	}
	// Item 1 gets the 409; its deferred failure log is the call's last log and carries its item hint.
	t.Run("failure_log_carries_hints", func(t *testing.T) {
		m := d3aMock(t)
		m.postStatus, m.postBody = 409, []byte(`{"code":"rule_conflict","message":"conflict"}`)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		fa := d3aFA(t, s, a, d3aFlows(17, 0, 10, d3aRandom))
		rb := d3bExecute(t, m, s, a, d3aWebAction(), fa)
		if len(rb.posts) != 8 || len(rb.logs) != 8 {
			t.Fatalf("POSTs=%d logs=%d want 8 / 8", len(rb.posts), len(rb.logs))
		}
		if rb.last.Status != "failed" || !strings.Contains(rb.last.ErrorMessage, "rule_conflict") {
			t.Fatalf("last log=%+v want the deferred 409 failure", rb.last)
		}
		for _, h := range []string{"shape: topk src_port=8 80%", "shape: item 1/8 src_port=10000"} {
			if !strings.Contains(rb.last.ErrorMessage, h) {
				t.Errorf("failure log lost %q: %q", h, rb.last.ErrorMessage)
			}
		}
		for _, l := range rb.logs[:7] {
			v3Success(t, l)
		}
	})
	t.Run("failure_log_carries_hints_below_t2", func(t *testing.T) {
		m := d3aMock(t)
		m.postStatus, m.postBody = 409, []byte(`{"code":"rule_conflict","message":"conflict"}`)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		fa := d3aFA(t, s, a, d3aFlows(17, 0, 13, d3aSpread))
		r := d3aExecute(t, m, s, a, d3aWebAction(), fa)
		if r.log.Status != "failed" || !strings.Contains(r.log.ErrorMessage, "rule_conflict") {
			t.Fatalf("device: expected 409 failure log: %+v", r.log)
		}
		if !strings.Contains(r.log.ErrorMessage, "shape: fallback rate_limit=50000") {
			t.Fatalf("failure log lost shape hints: %q", r.log.ErrorMessage)
		}
	})
}

// v0.4 §三-9 (r2 R3): the local rate guard's early-return failure log also
// carries the shape hints.
func TestD3A_S05_RateGuardFailureCarriesHints(t *testing.T) {
	for _, c := range []struct{ name, payload string }{
		{"rate_zero", `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","protocol":"{decoder}","action":"rate_limit","rate_limit":0}`},
		{"rate_missing", `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","protocol":"{decoder}","action":"rate_limit"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 1000)
			a := d3aAttack("udp", "198.51.100.7", true)
			fa := d3aFA(t, s, a, d3aFlows(17, 0, 10, d3aLowSample))
			r := d3aExecute(t, m, s, a, v3Action(44, c.payload), fa)
			if r.posts != 0 {
				t.Fatalf("invalid explicit rate reached XDrop: %d POST(s)", r.posts)
			}
			if r.log.Status != "failed" {
				t.Fatalf("guard must write a failed log: %+v", r.log)
			}
			for _, want := range []string{"shape: samples 100 < 1000", "no valid rate_limit"} {
				if !strings.Contains(r.log.ErrorMessage, want) {
					t.Errorf("failure log missing %q: %q", want, r.log.ErrorMessage)
				}
			}
			d3aCheckLookups(t, r, false)
		})
	}
}

// ---------------------------------------------------------------- S06

func TestD3A_S06_EndToEndBody(t *testing.T) {
	t.Run("udp_concentrated", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		r := d3aExecute(t, m, s, a, d3aWebAction(), d3aFA(t, s, a, d3aFlows(17, 0, 10, d3aConcentratedDst)))
		v3Success(t, r.log)
		if r.body["dst_port"] != float64(53) || r.body["action"] != "drop" || r.body["protocol"] != "udp" {
			t.Fatalf("body=%v", r.body)
		}
		v3NoKeys(t, r.body, "src_port", "src_ip", "src_cidr", "rate_limit", "source")
	})
	// d3aRandom yields eight source-port rules, with every body finalized for protocol, address, and SYN flags.
	for _, c := range []struct {
		name, dec, dst string
		proto, flags   int
		same           map[string]any
		absent         []string
	}{
		{"udp_random", "udp", "198.51.100.7", 17, 0, map[string]any{"action": "drop", "protocol": "udp", "dst_ip": "198.51.100.7"}, []string{"dst_port", "src_ip", "src_cidr", "rate_limit", "source"}},
		{"udp_random_subnet", "udp", "198.51.100.0/24", 17, 0, map[string]any{"action": "drop", "protocol": "udp", "dst_cidr": "198.51.100.0/24"}, []string{"dst_ip", "dst_port", "src_ip", "src_cidr", "rate_limit", "source"}},
		{"syn_fallback_keeps_flags", "tcp_syn", "198.51.100.7", 6, 2, map[string]any{"action": "drop", "protocol": "tcp", "tcp_flags": "SYN,!ACK"}, []string{"dst_port", "src_ip", "src_cidr", "rate_limit", "source"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 50000)
			a := d3aAttack(c.dec, c.dst, true)
			d3aTopK(t, m, s, a, d3aWebAction(), d3aFA(t, s, a, d3aFlows(c.proto, c.flags, 10, d3aRandom)), d3bWant{dim: "src_port", ports: d3aSrc8, pct: 80, absent: c.absent, same: c.same})
		})
	}
	t.Run("udp_random_below_t2", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		r := d3aExecute(t, m, s, a, d3aWebAction(), d3aFA(t, s, a, d3aFlows(17, 0, 13, d3aSpread)))
		v3Success(t, r.log)
		if r.body["action"] != "rate_limit" || r.body["rate_limit"] != float64(50000) || r.body["protocol"] != "udp" || r.body["dst_ip"] != "198.51.100.7" {
			t.Fatalf("body=%v", r.body)
		}
		v3NoKeys(t, r.body, "dst_port", "src_port", "src_ip", "src_cidr")
	})
	t.Run("udp_random_subnet_below_t2", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.0/24", true)
		r := d3aExecute(t, m, s, a, d3aWebAction(), d3aFA(t, s, a, d3aFlows(17, 0, 13, d3aSpread)))
		v3Success(t, r.log)
		if r.body["action"] != "rate_limit" || r.body["rate_limit"] != float64(50000) || r.body["dst_cidr"] != "198.51.100.0/24" {
			t.Fatalf("body=%v", r.body)
		}
		v3NoKeys(t, r.body, "dst_port", "src_port", "src_ip", "src_cidr")
	})
	t.Run("syn_fallback_keeps_flags_below_t2", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("tcp_syn", "198.51.100.7", true)
		r := d3aExecute(t, m, s, a, d3aWebAction(), d3aFA(t, s, a, d3aFlows(6, 2, 13, d3aSpread)))
		v3Success(t, r.log)
		if r.body["action"] != "rate_limit" || r.body["rate_limit"] != float64(50000) || r.body["tcp_flags"] != "SYN,!ACK" || r.body["protocol"] != "tcp" {
			t.Fatalf("body=%v", r.body)
		}
		v3NoKeys(t, r.body, "dst_port", "src_port", "src_ip", "src_cidr")
	})
	// An all-zero top source is not a retained condition.
	for _, z := range []struct{ name, dst, src string }{{"zero_source_v4", "198.51.100.7", "0.0.0.0"}, {"zero_source_v6", "2001:db8::7", "::"}} {
		t.Run(z.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 50000)
			a := d3aAttack("udp", z.dst, true)
			fa := d3aFA(t, s, a, d3aFlows(17, 0, 10, func(i int) (string, int, int, int64) { return z.src, 10000 + i, 1000 + i, 100 }))
			if len(fa.TopSrcIPs) != 1 || fa.TopSrcIPs[0] != z.src {
				t.Fatalf("device: top source %v", fa.TopSrcIPs)
			}
			r := d3aExecute(t, m, s, a, v3Action(32, d3aSrcIPTpl), fa)
			v3Success(t, r.log)
			if r.body["action"] != "rate_limit" || r.body["rate_limit"] != float64(50000) {
				t.Fatalf("all-zero source must not count as kept: %v", r.body)
			}
			v3NoKeys(t, r.body, "src_ip", "src_cidr", "dst_port", "src_port")
			d3aCheckLookups(t, r, true)
		})
	}
	t.Run("syn_concentrated", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("tcp_syn", "198.51.100.7", true)
		r := d3aExecute(t, m, s, a, d3aWebAction(), d3aFA(t, s, a, d3aFlows(6, 2, 10, d3aConcentratedDst)))
		v3Success(t, r.log)
		if r.body["action"] != "drop" || r.body["dst_port"] != float64(53) || r.body["tcp_flags"] != "SYN,!ACK" {
			t.Fatalf("body=%v", r.body)
		}
		v3NoKeys(t, r.body, "src_port", "rate_limit")
	})
}

// ---------------------------------------------------------------- S07

func TestD3A_S07_RateGuard(t *testing.T) {
	for _, c := range []struct {
		name, xdropAction, payload string
		wantPost                   bool
	}{
		{"filter_l4_rate_missing", "filter_l4", `{"dst_ip":"{dst_ip}","protocol":"{decoder}","action":"rate_limit"}`, false},
		{"filter_l4_rate_zero", "filter_l4", `{"dst_ip":"{dst_ip}","protocol":"{decoder}","action":"rate_limit","rate_limit":0}`, false},
		{"filter_l4_rate_over", "filter_l4", `{"dst_ip":"{dst_ip}","protocol":"{decoder}","action":"rate_limit","rate_limit":4294967296}`, false},
		{"rate_limit_rate_over", "rate_limit", `{"dst_ip":"{dst_ip}","protocol":"{decoder}","action":"rate_limit","rate_limit":4294967296}`, false},
		{"positive_uint32_max", "filter_l4", `{"dst_ip":"{dst_ip}","protocol":"{decoder}","action":"rate_limit","rate_limit":4294967295}`, true},
		{"positive_drop_no_rate", "filter_l4", `{"dst_ip":"{dst_ip}","protocol":"{decoder}","action":"drop"}`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 50000)
			a := d3aAttack("udp", "198.51.100.7", true)
			act := v3Action(51, c.payload)
			act.XDropAction = c.xdropAction
			r := d3aExecute(t, m, s, a, act, nil)
			if c.wantPost {
				v3Success(t, r.log)
				if r.posts != 1 {
					t.Fatalf("POST count=%d", r.posts)
				}
				return
			}
			if r.posts != 0 {
				t.Fatalf("out-of-range rate reached XDrop: %d POST(s), log %+v", r.posts, r.log)
			}
			if r.log.Status != "failed" {
				t.Fatalf("guard must write a failed log: %+v", r.log)
			}
		})
	}
}

// ---------------------------------------------------------------- S08

const d3aBaseYAML = `
database:
  driver: postgres
  dsn: "postgres://localhost/xsight_test"
auth:
  api_key: "test-key-123"
`

func d3aLoad(t *testing.T, extra string) (*config.Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(d3aBaseYAML+extra), 0o600); err != nil {
		t.Fatalf("device: write config: %v", err)
	}
	return config.Load(p)
}

// d3aActionField reads the ActionConfig field tagged yaml:"<tag>" (name not locked).
func d3aActionField(cfg *config.Config, tag string) (int64, bool) {
	v := reflect.ValueOf(cfg.Action)
	for i := 0; i < v.NumField(); i++ {
		if strings.Split(v.Type().Field(i).Tag.Get("yaml"), ",")[0] != tag {
			continue
		}
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return f.Int(), true
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return int64(f.Uint()), true
		}
	}
	return 0, false
}

func TestD3A_S08_Config(t *testing.T) {
	t.Run("device_positive_control", func(t *testing.T) {
		cfg, err := d3aLoad(t, "")
		if err != nil {
			t.Fatalf("device: base config rejected: %v", err)
		}
		if cfg.Action.Mode != "observe" {
			t.Fatalf("device: base defaults not applied: %+v", cfg.Action)
		}
		if _, err := d3aLoad(t, "action_engine:\n  mode: bogus\n"); err == nil {
			t.Fatalf("device: Load accepts an invalid action_engine.mode")
		}
	})
	t.Run("defaults", func(t *testing.T) {
		cfg, err := d3aLoad(t, "")
		if err != nil {
			t.Fatal(err)
		}
		for tag, want := range map[string]int64{"xdrop_narrow_pct": 80, "xdrop_min_sample_packets": 1000} {
			got, ok := d3aActionField(cfg, tag)
			if !ok || got != want {
				t.Errorf("action_engine.%s default=%d present=%v want %d", tag, got, ok, want)
			}
		}
	})
	for _, c := range []struct {
		name, yaml string
		tag        string
		want       int64
		bad        bool
	}{
		{"narrow_1", "xdrop_narrow_pct: 1", "xdrop_narrow_pct", 1, false},
		{"narrow_100", "xdrop_narrow_pct: 100", "xdrop_narrow_pct", 100, false},
		{"narrow_0", "xdrop_narrow_pct: 0", "xdrop_narrow_pct", 0, true},
		{"narrow_101", "xdrop_narrow_pct: 101", "xdrop_narrow_pct", 0, true},
		{"narrow_negative", "xdrop_narrow_pct: -5", "xdrop_narrow_pct", 0, true},
		{"samples_0", "xdrop_min_sample_packets: 0", "xdrop_min_sample_packets", 0, false},
		{"samples_5000", "xdrop_min_sample_packets: 5000", "xdrop_min_sample_packets", 5000, false},
		{"samples_negative", "xdrop_min_sample_packets: -1", "xdrop_min_sample_packets", 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := d3aLoad(t, "action_engine:\n  "+c.yaml+"\n")
			if c.bad {
				if err == nil {
					t.Fatalf("out-of-range %s accepted", c.yaml)
				}
				if c.tag == "xdrop_narrow_pct" && !strings.Contains(err.Error(), "xdrop_narrow_pct") {
					t.Fatalf("error does not name the key: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := d3aActionField(cfg, c.tag); !ok || got != c.want {
				t.Fatalf("%s=%d present=%v want %d", c.tag, got, ok, c.want)
			}
		})
	}
	t.Run("main_injects_before_engine_start", func(t *testing.T) {
		src, err := os.ReadFile(filepath.Join("..", "..", "main.go"))
		if err != nil {
			t.Fatalf("device: read main.go: %v", err)
		}
		text := string(src)
		if !strings.Contains(text, "actionEngine.Start()") {
			t.Fatalf("device: main.go anchor actionEngine.Start() missing")
		}
		if n := strings.Count(text, "action.SetXDropShapeConfig("); n != 1 {
			t.Fatalf("action.SetXDropShapeConfig( calls in main.go=%d want 1", n)
		}
		if strings.Index(text, "action.SetXDropShapeConfig(") > strings.Index(text, "actionEngine.Start()") {
			t.Fatalf("shape config injected after the engine starts")
		}
	})
}

// v0.4 §4-4 (r2 N2): the two injected arguments must be selector expressions
// whose final field is the config.ActionConfig field tagged
// xdrop_narrow_pct / xdrop_min_sample_packets (a type conversion wrapper is allowed).
func TestD3A_S08_MainInjectionArgsFromConfig(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "..", "main.go"), nil, 0)
	if err != nil {
		t.Fatalf("device: parse main.go: %v", err)
	}
	tags := map[string]string{}
	at := reflect.TypeOf(config.ActionConfig{})
	for i := 0; i < at.NumField(); i++ {
		tags[at.Field(i).Name] = strings.Split(at.Field(i).Tag.Get("yaml"), ",")[0]
	}
	if tags["Mode"] != "mode" {
		t.Fatalf("device: ActionConfig tag map broken: %v", tags)
	}
	var calls []*ast.CallExpr
	startPos := token.NoPos
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "action" && sel.Sel.Name == "SetXDropShapeConfig" {
				calls = append(calls, call)
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "actionEngine" && sel.Sel.Name == "Start" && startPos == token.NoPos {
				startPos = call.Pos()
			}
		}
		return true
	})
	if startPos == token.NoPos {
		t.Fatalf("device: actionEngine.Start() not found in main.go")
	}
	if len(calls) != 1 {
		t.Fatalf("action.SetXDropShapeConfig calls=%d want 1", len(calls))
	}
	call := calls[0]
	if call.Pos() > startPos {
		t.Fatalf("SetXDropShapeConfig called after actionEngine.Start()")
	}
	if len(call.Args) != 2 {
		t.Fatalf("SetXDropShapeConfig args=%d want 2", len(call.Args))
	}
	for i, want := range []string{"xdrop_narrow_pct", "xdrop_min_sample_packets"} {
		arg := call.Args[i]
		if conv, ok := arg.(*ast.CallExpr); ok && len(conv.Args) == 1 {
			if id, ok := conv.Fun.(*ast.Ident); ok && strings.Contains(" int int32 int64 uint uint32 uint64 ", " "+id.Name+" ") {
				arg = conv.Args[0]
			}
		}
		sel, ok := arg.(*ast.SelectorExpr)
		if !ok {
			t.Errorf("arg %d is %T, want a selector into the loaded config", i, arg)
			continue
		}
		if got := tags[sel.Sel.Name]; got != want {
			t.Errorf("arg %d field %s has yaml tag %q, want %q", i, sel.Sel.Name, got, want)
		}
	}
}
