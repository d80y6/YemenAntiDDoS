package action

// Tests for dispatching multiple rules for the top K ports in one call.
// Cases S01 / S01b / S02 / S03 / S03b / S04 / S05 / S06 / S07 / S08.
// Exercise executeXDrop / analyzeFlows / HandleEvent / ForceRemove / reconcileXDropRound /
// xdropSyntheticBodies / lockXDrop / v3Mock.serve / d2bRemote / v3Store / d3aStore / config.Load.
// d3aMock / d3bRemote replace http.DefaultTransport and call v3Mock.serve in process, accepting only .invalid hosts; no listeners.
// Stores use v3Store / d2bStore / d3aStore and d3bStore, which records executed_at on insertion and respects ctx.Err(); no database is required.
// Subcases prefixed guard_ preserve existing behavior; other subcases assert the expected top-k behavior.
// Fixture failures use t.Fatalf("device: ...").

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/config"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

// ---------------------------------------------------------------- 种子

// d3bCell is one (src port, dst port, packets) bucket. A port of -1 means
// "spread": every 50-packet row gets its own port, so that dimension never
// concentrates (each row = 5% of 1000 samples, top 8 = 40%).
type d3bCell struct {
	sport, dport int
	pkts         int64
}

// d3bRows splits every bucket into rows of at most 50 packets with distinct
// source addresses (TopSrcIPPct stays at 5% for 1000 samples).
func d3bRows(proto, flags int, cells ...d3bCell) []store.FlowLog {
	var out []store.FlowLog
	n := 0
	for _, c := range cells {
		for left := c.pkts; left > 0; left -= 50 {
			p := left
			if p > 50 {
				p = 50
			}
			sport, dport := c.sport, c.dport
			if sport < 0 {
				sport = 40000 + n
			}
			if dport < 0 {
				dport = 50000 + n
			}
			out = append(out, store.FlowLog{SrcIP: fmt.Sprintf("192.0.2.%d", 20+n%200), DstIP: "198.51.100.7", SrcPort: sport, DstPort: dport, Protocol: proto, TCPFlags: flags, Packets: p})
			n++
		}
	}
	return out
}

// d3bDst: (dst port, packets) pairs, source ports spread.
func d3bDst(pairs ...int64) []d3bCell {
	var out []d3bCell
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, d3bCell{-1, int(pairs[i]), pairs[i+1]})
	}
	return out
}

// d3bSrc: (src port, packets) pairs, destination ports spread.
func d3bSrc(pairs ...int64) []d3bCell {
	var out []d3bCell
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, d3bCell{int(pairs[i]), -1, pairs[i+1]})
	}
	return out
}

const (
	d3bDstTpl = `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","protocol":"{decoder}","action":"drop"}`
	d3bSrcTpl = `{"dst_ip":"{dst_ip}","src_port":"{dominant_src_port}","protocol":"{decoder}","action":"drop"}`
)

// d3bSeed4040 = dst 40% / 40% / 20% on 7701 / 7702 / 7703 (k = 2), sources spread.
func d3bSeed4040() []store.FlowLog {
	return d3bRows(17, 0, d3bDst(7701, 400, 7702, 400, 7703, 200)...)
}

// d3bSeedK3 = dst 40% / 30% / 10% + four 5% ports (k = 3 on 8001 / 8002 / 8003).
func d3bSeedK3(proto, flags int) []store.FlowLog {
	return d3bRows(proto, flags, d3bDst(8001, 400, 8002, 300, 8003, 100, 8101, 50, 8102, 50, 8103, 50, 8104, 50)...)
}

// ---------------------------------------------------------------- d3a 栈上的多份执行

type d3bRun struct {
	posts []map[string]any           // every POST /rules body of this call, in order
	logs  []store.ActionExecutionLog // every execution log written by this call, in order
	last  store.ActionExecutionLog
	calls int
	ids   []int
}

// d3bExecute = d3aExecute, but keeps every POST and every new log (⛔ only the last one).
func d3bExecute(t *testing.T, m *v3Mock, s *d3aStore, a *store.Attack, act store.ResponseAction, fa *FlowAnalysis) d3bRun {
	t.Helper()
	logsBefore, reqsBefore := len(s.logSnapshot()), len(m.snapshot())
	l, _ := executeXDrop(context.Background(), s, act, a, "confirmed", a.DstIP, "d3b", act.TriggerPhase, a.ID, fa, nil)
	if l != nil {
		_, _ = s.ActionExecLog().Create(context.Background(), l)
	}
	logs := s.logSnapshot()
	if len(logs) <= logsBefore {
		t.Fatalf("device: no execution log")
	}
	out := d3bRun{logs: append([]store.ActionExecutionLog(nil), logs[logsBefore:]...), last: logs[len(logs)-1]}
	for _, entry := range out.logs {
		if strings.Contains(entry.ErrorMessage, "d3a-device:") {
			t.Fatalf("device: request escaped the in-process mock: %s", entry.ErrorMessage)
		}
	}
	for _, req := range m.snapshot()[reqsBefore:] {
		if req.Method == "POST" && req.Path == "/rules" {
			var body map[string]any
			if err := json.Unmarshal(req.Body, &body); err != nil {
				t.Fatalf("device: POST body not JSON: %v", err)
			}
			out.posts = append(out.posts, body)
		}
	}
	out.calls, out.ids = s.lookups()
	return out
}

func d3bPorts(posts []map[string]any, key string) []any {
	var out []any
	for _, b := range posts {
		out = append(out, b[key])
	}
	return out
}

type d3bWant struct {
	dim    string         // dst_port | src_port
	ports  []int          // expected port of item 1..k, in rank order
	pct    int            // cumulative share printed in the topk hint
	absent []string       // keys that must be absent from every body
	same   map[string]any // keys every body must carry with this value
}

// d3bCheckTopK: exactly k POSTs (all checked), one ranked port each, same claim_ref,
// k success logs each carrying its own single body and `shape: item i/k`.
func d3bCheckTopK(t *testing.T, r d3bRun, a *store.Attack, actionID int, w d3bWant) {
	t.Helper()
	k := len(w.ports)
	if len(r.posts) != k {
		t.Fatalf("POST count=%d want %d (one rule per top-%d %s); %s=%v bodies=%v", len(r.posts), k, k, w.dim, w.dim, d3bPorts(r.posts, w.dim), r.posts)
	}
	ref := xdropClaimRef(a.ID, actionID)
	for i, b := range r.posts {
		if b[w.dim] != float64(w.ports[i]) {
			t.Errorf("item %d %s=%v want %d (body %v)", i+1, w.dim, b[w.dim], w.ports[i], b)
		}
		if b["claim_ref"] != ref {
			t.Errorf("item %d claim_ref=%v want %s", i+1, b["claim_ref"], ref)
		}
		for _, key := range w.absent {
			if d3aHas(b, key) {
				t.Errorf("item %d unexpected %s=%v (body %v)", i+1, key, b[key], b)
			}
		}
		for key, v := range w.same {
			if b[key] != v {
				t.Errorf("item %d %s=%v want %v (body %v)", i+1, key, b[key], v, b)
			}
		}
	}
	if len(r.logs) != k {
		t.Fatalf("execution logs=%d want %d (one per item)", len(r.logs), k)
	}
	topk := fmt.Sprintf("shape: topk %s=%d %d%%", w.dim, k, w.pct)
	for i, l := range r.logs {
		v3Success(t, l)
		var logged map[string]any
		if err := json.Unmarshal([]byte(l.RequestBody), &logged); err != nil || !reflect.DeepEqual(logged, r.posts[i]) {
			t.Errorf("log %d RequestBody=%s is not the single body POSTed as item %d (%v)", i+1, l.RequestBody, i+1, r.posts[i])
		}
		item := fmt.Sprintf("shape: item %d/%d %s=%d", i+1, k, w.dim, w.ports[i])
		for _, h := range []string{topk, item} {
			if !strings.Contains(l.ErrorMessage, h) {
				t.Errorf("log %d missing hint %q in %q", i+1, h, l.ErrorMessage)
			}
		}
	}
}

// d3bCheckSingle checks the single-body path: one POST and no top-k hint.
func d3bCheckSingle(t *testing.T, r d3bRun, action string, rate float64, absent ...string) {
	t.Helper()
	if len(r.posts) != 1 {
		t.Fatalf("POST count=%d want 1 (single-body path); bodies=%v", len(r.posts), r.posts)
	}
	b := r.posts[0]
	if b["action"] != action {
		t.Errorf("action=%v want %s (body %v)", b["action"], action, b)
	}
	if rate == 0 && d3aHas(b, "rate_limit") || rate != 0 && b["rate_limit"] != rate {
		t.Errorf("rate_limit=%v want %v", b["rate_limit"], rate)
	}
	for _, key := range absent {
		if d3aHas(b, key) {
			t.Errorf("unexpected %s=%v (body %v)", key, b[key], b)
		}
	}
	for _, l := range r.logs {
		if strings.Contains(l.ErrorMessage, "shape: topk") || strings.Contains(l.ErrorMessage, "shape: item") {
			t.Errorf("single-body path logged a top-k hint: %q", l.ErrorMessage)
		}
	}
}

// ---------------------------------------------------------------- S01 选择矩阵

func TestD3B_S01_SelectionMatrixE2E(t *testing.T) {
	web := v3WebPayload
	for _, c := range []struct {
		name, dec, tpl string
		rows           []store.FlowLog
		bypass         bool
		samples        uint64 // device: SamplePackets of the filtered rows
		want           *d3bWant
		single         func(t *testing.T, r d3bRun)
	}{
		// R1: src port 0 holds 90% (old T1 fails: the expanded port is 0); dst 40/40/20 ⇒ two dst rules.
		{name: "t1_port_zero_does_not_preempt", dec: "udp", tpl: web, samples: 1000,
			rows: d3bRows(17, 0, d3bCell{0, 7001, 400}, d3bCell{0, 7002, 400}, d3bCell{0, 7003, 100}, d3bCell{30001, 7003, 50}, d3bCell{30002, 7003, 50}),
			want: &d3bWant{dim: "dst_port", ports: []int{7001, 7002}, pct: 80, absent: []string{"src_port", "src_ip", "src_cidr", "rate_limit"}, same: map[string]any{"action": "drop"}}},
		{name: "min_k_40_40_10_10", dec: "udp", tpl: d3bDstTpl, samples: 1000,
			rows: d3bRows(17, 0, d3bDst(7011, 400, 7012, 400, 7013, 100, 7014, 100)...),
			want: &d3bWant{dim: "dst_port", ports: []int{7011, 7012}, pct: 80, absent: []string{"src_port", "rate_limit"}, same: map[string]any{"action": "drop"}}},
		// both dimensions need k = 2 ⇒ source port wins the tie.
		{name: "tie_prefers_src", dec: "udp", tpl: web, samples: 1000,
			rows: d3bRows(17, 0, d3bCell{5001, 6001, 500}, d3bCell{5002, 6002, 300}, d3bCell{5003, 6003, 200}),
			want: &d3bWant{dim: "src_port", ports: []int{5001, 5002}, pct: 80, absent: []string{"dst_port", "src_ip", "rate_limit"}, same: map[string]any{"action": "drop"}}},
		// src needs k = 3 (30/30/30/10), dst needs k = 2 (45/45/10) ⇒ dst wins on the smaller k.
		{name: "smaller_k_wins", dec: "udp", tpl: web, samples: 1000,
			rows: d3bRows(17, 0, d3bCell{5101, 6101, 300}, d3bCell{5102, 6101, 150}, d3bCell{5102, 6102, 150}, d3bCell{5103, 6102, 300}, d3bCell{5104, 6103, 100}),
			want: &d3bWant{dim: "dst_port", ports: []int{6101, 6102}, pct: 90, absent: []string{"src_port", "src_ip", "rate_limit"}, same: map[string]any{"action": "drop"}}},
		// ranking and denominator come from the analyzeFlows-filtered rows (a 100000-packet TCP row is filtered out).
		{name: "filtered_denominator", dec: "udp", tpl: d3bDstTpl, bypass: true, samples: 1000,
			rows: append(d3bRows(17, 0, d3bDst(7021, 400, 7022, 400, 7023, 200)...), store.FlowLog{SrcIP: "203.0.113.9", DstPort: 7029, Protocol: 6, Packets: 100000}),
			want: &d3bWant{dim: "dst_port", ports: []int{7021, 7022}, pct: 80, absent: []string{"rate_limit"}, same: map[string]any{"action": "drop"}}},
		// port 0 = 20% stays in the denominator: 40+30 = 70% < 80 ⇒ k = 3 (a denominator without 0 would give k = 2).
		{name: "port_zero_in_denominator", dec: "udp", tpl: d3bDstTpl, samples: 1000,
			rows: d3bRows(17, 0, d3bDst(0, 200, 7031, 400, 7032, 300, 7033, 100)...),
			want: &d3bWant{dim: "dst_port", ports: []int{7031, 7032, 7033}, pct: 80, absent: []string{"rate_limit"}, same: map[string]any{"action": "drop"}}},
		// equal counts rank by port ascending: 7043 (40%) then 7041 / 7042 out of 7041 / 7042 / 7044 (20% each).
		{name: "tie_order_port_ascending", dec: "udp", tpl: d3bDstTpl, samples: 1000,
			rows: d3bRows(17, 0, d3bDst(7044, 200, 7043, 400, 7042, 200, 7041, 200)...),
			want: &d3bWant{dim: "dst_port", ports: []int{7043, 7041, 7042}, pct: 80, absent: []string{"rate_limit"}, same: map[string]any{"action": "drop"}}},
		{name: "src_dimension", dec: "udp", tpl: d3bSrcTpl, samples: 1000,
			rows: d3bRows(17, 0, d3bSrc(53, 400, 123, 400, 389, 200)...),
			want: &d3bWant{dim: "src_port", ports: []int{53, 123}, pct: 80, absent: []string{"dst_port", "rate_limit"}, same: map[string]any{"action": "drop"}}},

		// ---- guards: the single-body path ----
		{name: "guard_low_sample", dec: "udp", tpl: d3bDstTpl, samples: 999,
			rows: d3bRows(17, 0, d3bDst(7051, 400, 7052, 400, 7053, 199)...),
			single: func(t *testing.T, r d3bRun) {
				d3bCheckSingle(t, r, "rate_limit", 50000, "dst_port")
				if !strings.Contains(r.last.ErrorMessage, "shape: samples 999 < 1000") {
					t.Errorf("hints=%q", r.last.ErrorMessage)
				}
			}},
		{name: "guard_unpermitted_dimension", dec: "udp", tpl: d3aSrcIPTpl, samples: 1000,
			rows: d3bSeed4040(),
			single: func(t *testing.T, r d3bRun) {
				d3bCheckSingle(t, r, "rate_limit", 50000, "dst_port", "src_port", "src_ip")
			}},
		{name: "guard_non_ported_decoder", dec: "icmp", tpl: web, samples: 1000,
			rows: d3bRows(1, 0, d3bDst(7061, 400, 7062, 400, 7063, 200)...),
			single: func(t *testing.T, r d3bRun) {
				d3bCheckSingle(t, r, "rate_limit", 50000, "dst_port", "src_port", "src_ip")
				if r.posts[0]["protocol"] != "icmp" {
					t.Errorf("protocol=%v", r.posts[0]["protocol"])
				}
			}},
		{name: "guard_t1_single", dec: "udp", tpl: web, samples: 1000,
			rows: d3bRows(17, 0, d3bDst(53, 900, 80, 100)...),
			single: func(t *testing.T, r d3bRun) {
				d3bCheckSingle(t, r, "drop", 0, "src_port", "src_ip")
				if r.posts[0]["dst_port"] != float64(53) {
					t.Errorf("T1 dst_port=%v want 53", r.posts[0]["dst_port"])
				}
				if r.calls != 0 {
					t.Errorf("threshold accessed: %d", r.calls)
				}
			}},
		// port 0 = 40%, non-zero 30/30 = 60% < 80 ⇒ no top-k rule (port 0 is never a candidate).
		{name: "guard_port_zero_not_candidate", dec: "udp", tpl: d3bDstTpl, samples: 1000,
			rows: d3bRows(17, 0, d3bDst(0, 400, 7071, 300, 7072, 300)...),
			single: func(t *testing.T, r d3bRun) {
				d3bCheckSingle(t, r, "rate_limit", 50000, "dst_port")
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 50000)
			s.bypassFilter = c.bypass
			a := d3aAttack(c.dec, "198.51.100.7", true)
			fa := d3aFA(t, s, a, c.rows)
			if fa.SamplePackets != c.samples {
				t.Fatalf("device: SamplePackets=%d want %d", fa.SamplePackets, c.samples)
			}
			act := v3Action(61, c.tpl)
			runs := 1
			if c.name == "tie_order_port_ascending" {
				runs = 12 // map order differs per run; the order must not
			}
			for i := 0; i < runs; i++ {
				r := d3bExecute(t, m, s, a, act, fa)
				if c.want != nil {
					d3bCheckTopK(t, r, a, act.ID, *c.want)
					if r.calls != 0 {
						t.Errorf("top-k branch accessed thresholds: %d (%v)", r.calls, r.ids)
					}
				} else {
					c.single(t, r)
				}
				if t.Failed() {
					return
				}
				fa = d3aFA(t, s, a, c.rows)
			}
		})
	}
}

// ---------------------------------------------------------------- S01b 字面另一维 / 端口 0 边界

func TestD3B_S01b_LiteralAndZeroBoundaryE2E(t *testing.T) {
	t.Run("literal_src_port_kept_per_item", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 1000)
		a := d3aAttack("udp", "198.51.100.7", true)
		fa := d3aFA(t, s, a, d3bSeed4040())
		act := v3Action(62, `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","src_port":123,"protocol":"{decoder}","action":"drop"}`)
		r := d3bExecute(t, m, s, a, act, fa)
		d3bCheckTopK(t, r, a, act.ID, d3bWant{dim: "dst_port", ports: []int{7701, 7702}, pct: 80, absent: []string{"rate_limit"},
			same: map[string]any{"src_port": float64(123), "action": "drop"}})
		d3aCheckLookups(t, d3aRun{calls: r.calls, ids: r.ids}, false)
	})
	// N1: port 0 = 20% and eight non-zero ports at 10% each ⇒ all eight are candidates ⇒ 8 rules.
	t.Run("zero20_eight_nonzero10", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 1000)
		a := d3aAttack("udp", "198.51.100.7", true)
		fa := d3aFA(t, s, a, d3bRows(17, 0, d3bDst(0, 200, 7401, 100, 7402, 100, 7403, 100, 7404, 100, 7405, 100, 7406, 100, 7407, 100, 7408, 100)...))
		if fa.DominantDstPort != 0 || fa.DominantDstPortPct != 20 {
			t.Fatalf("device: fixture dominant %d/%d%%", fa.DominantDstPort, fa.DominantDstPortPct)
		}
		act := v3Action(63, d3bDstTpl)
		r := d3bExecute(t, m, s, a, act, fa)
		d3bCheckTopK(t, r, a, act.ID, d3bWant{dim: "dst_port", ports: []int{7401, 7402, 7403, 7404, 7405, 7406, 7407, 7408}, pct: 80, absent: []string{"rate_limit"}, same: map[string]any{"action": "drop"}})
	})
}

// ---------------------------------------------------------------- S02 多行端到端

func TestD3B_S02_MultiRowE2E(t *testing.T) {
	// tcp_syn + subnet target + the Web template's "source" field: every body must be
	// finalized on its own (claim_ref, dst_cidr, tcp_flags, protocol, dropped source).
	m := d3aMock(t)
	s := d3aNewStore("pps", 50000)
	a := d3aAttack("tcp_syn", "198.51.100.0/24", true)
	fa := d3aFA(t, s, a, d3bSeedK3(6, 2))
	act := v3Action(64, v3WebPayload)
	r := d3bExecute(t, m, s, a, act, fa)
	d3bCheckTopK(t, r, a, act.ID, d3bWant{dim: "dst_port", ports: []int{8001, 8002, 8003}, pct: 80})
	for i, b := range r.posts {
		want := map[string]any{"action": "drop", "claim_ref": "a301.x64", "dst_cidr": "198.51.100.0/24", "dst_port": float64([]int{8001, 8002, 8003}[i]), "protocol": "tcp", "tcp_flags": "SYN,!ACK"}
		if !reflect.DeepEqual(b, want) {
			t.Errorf("item %d body=%v want %v", i+1, b, want)
		}
	}
	for i, l := range r.logs {
		for _, h := range []string{"shape: dropped src_port=5%", "shape: dropped src_ip=5%", "dropped: source"} {
			if !strings.Contains(l.ErrorMessage, h) {
				t.Errorf("log %d missing %q in %q", i+1, h, l.ErrorMessage)
			}
		}
	}
	active := map[string]bool{}
	s.mu.Lock()
	for _, row := range s.rules {
		if row.Status == "active" && row.ActionID == act.ID {
			active[row.ExternalRuleID] = true
		}
	}
	s.mu.Unlock()
	if len(active) != 3 {
		t.Errorf("active rows=%d want 3 (%v)", len(active), s.rules)
	}
	for _, l := range r.logs {
		if !active[l.ExternalRuleID] {
			t.Errorf("log rule %q has no active row", l.ExternalRuleID)
		}
	}
	if m.count() != 3 {
		t.Errorf("remote rules=%d want 3", m.count())
	}
}

// ---------------------------------------------------------------- S03 不兜底 / S03b 运维显式限速

func TestD3B_S03_TopKNoFallbackE2E(t *testing.T) {
	m := d3aMock(t)
	s := d3aNewStore("pps", 1000)
	a := d3aAttack("udp", "198.51.100.7", true)
	fa := d3aFA(t, s, a, d3bSeed4040())
	act := v3Action(65, d3bDstTpl)
	r := d3bExecute(t, m, s, a, act, fa)
	d3bCheckTopK(t, r, a, act.ID, d3bWant{dim: "dst_port", ports: []int{7701, 7702}, pct: 80, absent: []string{"rate_limit"}, same: map[string]any{"action": "drop"}})
	for _, l := range r.logs {
		if strings.Contains(l.ErrorMessage, "shape: fallback") || strings.Contains(l.ErrorMessage, "fallback rate unavailable") {
			t.Errorf("top-k branch logged a fallback hint: %q", l.ErrorMessage)
		}
	}
	d3aCheckLookups(t, d3aRun{calls: r.calls, ids: r.ids}, false)
}

func TestD3B_S03b_OperatorRateTopKE2E(t *testing.T) {
	for _, c := range []struct {
		name, xdropAction, payload string
		wantAction                 any // nil = absent
	}{
		{"enum_rate_limit", "rate_limit", `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","protocol":"{decoder}","rate_limit":5000}`, nil},
		{"body_rate_limit", "filter_l4", `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","protocol":"{decoder}","action":"rate_limit","rate_limit":5000}`, "rate_limit"},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 1000)
			a := d3aAttack("udp", "198.51.100.7", true)
			fa := d3aFA(t, s, a, d3bSeed4040())
			act := v3Action(66, c.payload)
			act.XDropAction = c.xdropAction
			r := d3bExecute(t, m, s, a, act, fa)
			d3bCheckTopK(t, r, a, act.ID, d3bWant{dim: "dst_port", ports: []int{7701, 7702}, pct: 80, same: map[string]any{"rate_limit": float64(5000)}})
			for i, b := range r.posts {
				if got, has := b["action"]; c.wantAction == nil && has || c.wantAction != nil && got != c.wantAction {
					t.Errorf("item %d action=%v (present %v) want %v: operator action must survive", i+1, got, has, c.wantAction)
				}
			}
			d3aCheckLookups(t, d3aRun{calls: r.calls, ids: r.ids}, false)
		})
	}
	// Each body is rate-guarded on its own: both items are rejected, no POST, one failed log per item.
	t.Run("explicit_rate_missing_rejected_per_item", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 1000)
		a := d3aAttack("udp", "198.51.100.7", true)
		fa := d3aFA(t, s, a, d3bSeed4040())
		r := d3bExecute(t, m, s, a, v3Action(67, `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","protocol":"{decoder}","action":"rate_limit"}`), fa)
		if len(r.posts) != 0 {
			t.Fatalf("invalid explicit rate reached XDrop: %d POST(s)", len(r.posts))
		}
		if len(r.logs) != 2 {
			t.Fatalf("failed logs=%d want 2 (one per rejected item): %+v", len(r.logs), r.logs)
		}
		for i, l := range r.logs {
			want := []string{"no valid rate_limit", "shape: topk dst_port=2 80%", fmt.Sprintf("shape: item %d/2 dst_port=%d", i+1, 7701+i)}
			if l.Status != "failed" {
				t.Errorf("log %d status=%s want failed", i+1, l.Status)
			}
			for _, h := range want {
				if !strings.Contains(l.ErrorMessage, h) {
					t.Errorf("log %d missing %q in %q", i+1, h, l.ErrorMessage)
				}
			}
		}
		d3aCheckLookups(t, d3aRun{calls: r.calls, ids: r.ids}, false)
	})
}

// ---------------------------------------------------------------- S06 单次 K（缺省 K = 8）

func TestD3B_S06_SingleDispatchKE2E(t *testing.T) {
	t.Run("exactly_K_when_top_K_needed", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		fa := d3aFA(t, s, a, d3bRows(17, 0, d3bDst(7501, 100, 7502, 100, 7503, 100, 7504, 100, 7505, 100, 7506, 100, 7507, 100, 7508, 100,
			7601, 40, 7602, 40, 7603, 40, 7604, 40, 7605, 40)...))
		act := v3Action(68, d3bDstTpl)
		r := d3bExecute(t, m, s, a, act, fa)
		d3bCheckTopK(t, r, a, act.ID, d3bWant{dim: "dst_port", ports: []int{7501, 7502, 7503, 7504, 7505, 7506, 7507, 7508}, pct: 80, absent: []string{"rate_limit"}})
	})
	// Eleven ports at 91 packets: the top 8 reach only 72%, so use the single-body fallback with one POST.
	t.Run("guard_top_K_short_of_T2", func(t *testing.T) {
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		var pairs []int64
		for p := int64(7801); p <= 7811; p++ {
			pairs = append(pairs, p, 91)
		}
		fa := d3aFA(t, s, a, d3bRows(17, 0, d3bDst(pairs...)...))
		r := d3bExecute(t, m, s, a, v3Action(69, d3bDstTpl), fa)
		d3bCheckSingle(t, r, "rate_limit", 50000, "dst_port")
		if !strings.Contains(r.last.ErrorMessage, "shape: fallback rate_limit=50000") {
			t.Errorf("hints=%q", r.last.ErrorMessage)
		}
	})
}

// ---------------------------------------------------------------- S04 / S05 / S07 装置

const d3bHost = "xdrop-d3b.invalid"

// d3bRemote wraps d2bRemote (v3Mock.serve + batch validate) behind a host check and
// per-create-POST control: modes[i] is the d2bRemote create mode of the i-th
// POST /rules ("" forward, "409", "503", "lost", …) or "cancel" (cancel the
// dispatch ctx and fail with its error); reached[i] closes when the i-th POST
// arrives; gates[i] holds it; after[i] runs once its response is ready.
type d3bRemote struct {
	x       *d2bRemote
	mu      sync.Mutex
	creates int
	modes   map[int]string
	gates   map[int]chan struct{}
	reached map[int]chan struct{}
	after   map[int]func()
	cancel  context.CancelFunc
}

func (r *d3bRemote) set(f func()) { r.mu.Lock(); defer r.mu.Unlock(); f() }
func (r *d3bRemote) createCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.creates
}
func (r *d3bRemote) roundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != d3bHost {
		return nil, fmt.Errorf("d3b-device: refused non-mock host %q", req.URL.Host)
	}
	if req.Method != http.MethodPost || req.URL.Path != "/rules" {
		return r.x.roundTrip(req)
	}
	r.mu.Lock()
	r.creates++
	i := r.creates
	mode, gate, reached, after, cancel := r.modes[i], r.gates[i], r.reached[i], r.after[i], r.cancel
	r.mu.Unlock()
	if reached != nil {
		close(reached)
	}
	if gate != nil {
		<-gate
	}
	if mode == "cancel" {
		body, _ := io.ReadAll(req.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		ref, _ := m["claim_ref"].(string)
		r.x.mu.Lock()
		r.x.reqs = append(r.x.reqs, d2bReq{req.Method, req.URL.Host, req.URL.Path, req.URL.RawQuery, ref, body})
		r.x.mu.Unlock()
		cancel()
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	r.x.setPost(mode)
	resp, err := r.x.roundTrip(req)
	r.x.setPost("")
	if after != nil {
		after()
	}
	return resp, err
}

// d3bStore: d2bStore whose execution-log Create records executed_at at insert time
// (PostgreSQL default) and, like the state Upsert, refuses an expired ctx.
type d3bStore struct {
	*d2bStore
	thCalls atomic.Int32
}
type d3bLogs struct{ d2bLogs }
type d3bRules struct{ store.XDropActiveRuleRepo }
type d3bThresholds struct{ store.ThresholdRepo }

func (s *d3bStore) ActionExecLog() store.ActionExecLogRepo {
	return d3bLogs{d2bLogs{v3Logs{s: s.v3Store}, s.d2bStore}}
}
func (s *d3bStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d3bRules{s.d2bStore.XDropActiveRules()}
}
func (s *d3bStore) Thresholds() store.ThresholdRepo { s.thCalls.Add(1); return d3bThresholds{} }
func (d3bThresholds) Get(context.Context, int) (*store.Threshold, error) {
	return nil, nil
}
func (r d3bLogs) Create(ctx context.Context, l *store.ActionExecutionLog) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("d3b log store: %w", err)
	}
	cp := *l
	cp.ExecutedAt = time.Now()
	return r.d2bLogs.Create(ctx, &cp)
}
func (r d3bRules) Upsert(ctx context.Context, row *store.XDropActiveRule) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("d3b rule store: %w", err)
	}
	return r.XDropActiveRuleRepo.Upsert(ctx, row)
}

const (
	d3bAttackID = 101
	d3bActionID = 11
)

func d3bFixture(t *testing.T, tpl string, rows []store.FlowLog) (*d3bStore, *Engine, *d3bRemote) {
	t.Helper()
	d, _, _ := d2Fixture(t, "active")
	d.mu.Lock()
	d.rules = map[string]store.XDropActiveRule{}
	d.history = map[string][]string{}
	d.conn.APIKey = v3TestKey
	d.conn.APIURL = "http://" + d3bHost
	d.flows = rows
	d.mu.Unlock()
	d.actions[0].XDropAction = "filter_l4"
	d.actions[0].TriggerPhase = "on_detected"
	d.actions[0].RunMode = "once"
	d.actions[0].XDropCustomPayload = json.RawMessage(tpl)
	s := &d3bStore{d2bStore: &d2bStore{d2Store: d}}
	x := &d2bRemote{m: &v3Mock{rules: map[string]*v3Rule{}, epoch: "epoch-test"}, expiry: map[string]string{}}
	r := &d3bRemote{x: x, modes: map[int]string{}, gates: map[int]chan struct{}{}, reached: map[int]chan struct{}{}, after: map[int]func(){}}
	d2HTTP(t, r.roundTrip)
	return s, NewEngine(s, "auto"), r
}

func d3bAttack() *store.Attack {
	a := v3Attack(d3bAttackID, "udp", "198.51.100.7")
	rid := 1
	a.ResponseID = &rid
	return a
}

// d3bCreate runs the real create path once (real analyzeFlows over the store's rows).
func d3bCreate(t *testing.T, ctx context.Context, s *d3bStore, e *Engine, phase string) {
	t.Helper()
	a := d3bAttack()
	fa := analyzeFlows(context.Background(), s, a)
	if fa == nil {
		t.Fatalf("device: analyzeFlows nil")
	}
	l, _ := executeXDrop(ctx, s, s.actions[0], a, "confirmed", a.DstIP, "d3b", phase, d3bAttackID, fa, e)
	if l != nil {
		_, _ = s.ActionExecLog().Create(context.Background(), l)
	}
}

// d3bUnblock = the paired on_expired unblock action (normal end-of-attack entry).
func d3bUnblock(s *d3bStore, e *Engine) {
	a := d3bAttack()
	l, _ := executeXDrop(context.Background(), s, s.actions[1], a, "expired", a.DstIP, "d3b", "on_expired", d3bAttackID, nil, e)
	if l != nil {
		_, _ = s.ActionExecLog().Create(context.Background(), l)
	}
}

func d3bPostBodies(t *testing.T, r *d3bRemote, from int) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, req := range r.x.since(from) {
		if d2bKind(req) == "create" {
			var b map[string]any
			if err := json.Unmarshal(req.Body, &b); err != nil {
				t.Fatalf("device: create body not JSON: %v", err)
			}
			out = append(out, b)
		}
	}
	return out
}

func d3bCreateLogs(s *d3bStore) []store.ActionExecutionLog {
	var out []store.ActionExecutionLog
	for _, l := range s.logSnapshot() {
		if l.AttackID == d3bAttackID && l.ActionID == d3bActionID && l.Status != "skipped" && xdropCreatePhase(l.TriggerPhase) {
			out = append(out, l)
		}
	}
	return out
}

func d3bRowsByStatus(s *d3bStore) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for _, row := range s.rules {
		if row.AttackID == d3bAttackID && row.ActionID == d3bActionID {
			out[row.ExternalRuleID] = row.Status
		}
	}
	return out
}

func d3bDone(t *testing.T, s *d3bStore) bool {
	t.Helper()
	done, err := s.ActionExecLog().AllTargetsDone(context.Background(), d3bAttackID, d3bActionID, "on_detected")
	if err != nil {
		t.Fatalf("device: AllTargetsDone: %v", err)
	}
	return done
}

// d3bLatest = the latest non-skipped create log by (executed_at, id), as AllTargetsDone orders it.
func d3bLatest(s *d3bStore) (store.ActionExecutionLog, bool) {
	var best store.ActionExecutionLog
	found := false
	for _, l := range d3bCreateLogs(s) {
		if !found || l.ExecutedAt.After(best.ExecutedAt) || l.ExecutedAt.Equal(best.ExecutedAt) && l.ID > best.ID {
			best, found = l, true
		}
	}
	return best, found
}

var d3bSynthKey = xdropRuleKey{d3bAttackID, d3bActionID, 7, d2bSynthetic}

// ---------------------------------------------------------------- S04 部分失败

// k = 4 (dst 25/25/20/10 + four 5% ports): item 1 ok, 2 = 409, 3 = lost (remote created, reply lost), 4 = 503.
func d3bSeedK4() []store.FlowLog {
	return d3bRows(17, 0, d3bDst(9001, 250, 9002, 250, 9003, 200, 9004, 100, 9101, 50, 9102, 50, 9103, 50, 9104, 50)...)
}

func TestD3B_S04_PartialFailureE2E(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK4())
		r.set(func() { r.modes[2], r.modes[3], r.modes[4] = "409", "lost", "503" })
		d3bCreate(t, context.Background(), s, e, "on_detected")
		synctest.Wait()
		posts := d3bPostBodies(t, r, 0)
		if len(posts) != 4 {
			t.Fatalf("POST count=%d want 4 (top-4 dst ports); dst_port=%v", len(posts), d3bPorts(posts, "dst_port"))
		}
		rows := d3bRowsByStatus(s)
		active := 0
		for id, st := range rows {
			if st == "active" {
				active++
			} else if id != d2bSynthetic {
				t.Errorf("unexpected row %s=%s", id, st)
			}
		}
		if active != 1 || rows[d2bSynthetic] != "failed" || len(rows) != 2 {
			t.Errorf("rows=%v want 1 active real row + %s failed", rows, d2bSynthetic)
		}
		var failed []store.ActionExecutionLog
		for _, l := range d3bCreateLogs(s) {
			if l.Status == "failed" {
				failed = append(failed, l)
				if l.ExternalRuleID != d2bSynthetic {
					t.Errorf("failed item rule id=%q want exactly %q (one synthetic id per action)", l.ExternalRuleID, d2bSynthetic)
				}
			}
		}
		if len(failed) != 3 {
			t.Fatalf("failed create logs=%d want 3", len(failed))
		}
		bodies, count, err := e.xdropSyntheticBodies(context.Background(), d3bSynthKey)
		if err != nil {
			t.Fatalf("device: synthetic bodies: %v", err)
		}
		var wantBodies []string
		for _, l := range failed {
			var b map[string]any
			_ = json.Unmarshal([]byte(l.RequestBody), &b)
			if b["dst_port"] == float64(9003) || b["dst_port"] == float64(9004) {
				wantBodies = append(wantBodies, l.RequestBody)
			}
		}
		if count != 3 || len(wantBodies) != 2 || !reflect.DeepEqual(bodies, wantBodies) {
			t.Errorf("synthetic recovery bodies=%v count=%d want the 2 uncertain bodies %v (409 excluded) / 3", bodies, count, wantBodies)
		}
		if n := r.x.ourClaims(); n != 2 {
			t.Errorf("remote claims=%d want 2 (item 1 + lost item 3)", n)
		}
		d3bUnblock(s, e)
		synctest.Wait()
		if n := r.x.ourClaims(); n != 0 {
			t.Errorf("after attack end remote claims=%d want 0", n)
		}
		for id, st := range d3bRowsByStatus(s) {
			if st != "withdrawn" {
				t.Errorf("after attack end row %s=%s want withdrawn", id, st)
			}
		}
	})
}

// ---------------------------------------------------------------- S05 完成语义

func TestD3B_S05_CompletionE2E(t *testing.T) {
	// k = 3, item 2 fails (503, not forwarded), item 3 succeeds: the connector's latest log is the failure.
	t.Run("latest_log_is_failure", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK3(17, 0))
			r.set(func() { r.modes[2] = "503" })
			d3bCreate(t, context.Background(), s, e, "on_detected")
			synctest.Wait()
			posts := d3bPostBodies(t, r, 0)
			if len(posts) != 3 {
				t.Fatalf("POST count=%d want 3; dst_port=%v", len(posts), d3bPorts(posts, "dst_port"))
			}
			latest, ok := d3bLatest(s)
			if !ok || latest.Status != "failed" || !strings.Contains(latest.RequestBody, `"dst_port":8002`) {
				t.Errorf("latest create log=%+v want the failed item 2 (dst_port 8002)", latest)
			}
			if d3bDone(t, s) {
				t.Errorf("AllTargetsDone=true with a failed item; logs=%s", d2bLogTexts(s.d2bStore))
			}
		})
	})
	t.Run("retry_until_success_reruns", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK3(17, 0))
			s.actions[0].RunMode = store.RunModeRetryUntilSuccess
			r.set(func() { r.modes[2] = "503" })
			a := d3bAttack()
			e.HandleEvent(tracker.AttackEvent{Type: "confirmed", DBID: d3bAttackID, Attack: a})
			synctest.Wait()
			first := d3bPostBodies(t, r, 0)
			if len(first) != 3 || d3bDone(t, s) {
				t.Fatalf("first dispatch POSTs=%d done=%v want 3 / false", len(first), d3bDone(t, s))
			}
			mark, logsBefore := r.x.mark(), len(d3bCreateLogs(s))
			e.HandleEvent(tracker.AttackEvent{Type: "updated", DBID: d3bAttackID, Attack: a})
			synctest.Wait()
			second := d3bPostBodies(t, r, mark)
			if len(second) != 3 {
				t.Fatalf("retry dispatch POSTs=%d want 3 (failed item retried)", len(second))
			}
			if !reflect.DeepEqual(first, second) {
				t.Errorf("retry recomputed a different set: %v vs %v", d3bPorts(first, "dst_port"), d3bPorts(second, "dst_port"))
			}
			logs := d3bCreateLogs(s)[logsBefore:]
			if len(logs) != 3 {
				t.Fatalf("retry logs=%d want 3", len(logs))
			}
			for i, want := range []int{200, 201, 200} {
				l := logs[i]
				if l.Status != "success" || l.StatusCode == nil || *l.StatusCode != want {
					t.Errorf("retry item %d status=%s code=%v want success/%d (existing for items already created)", i+1, l.Status, l.StatusCode, want)
				}
			}
			if !d3bDone(t, s) {
				t.Errorf("AllTargetsDone=false after every item succeeded")
			}
			mark = r.x.mark()
			e.HandleEvent(tracker.AttackEvent{Type: "updated", DBID: d3bAttackID, Attack: a})
			synctest.Wait()
			if n := len(d3bPostBodies(t, r, mark)); n != 0 {
				t.Errorf("completed retry_until_success dispatched again: %d POST(s)", n)
			}
		})
	})
	t.Run("once_reruns_on_type_upgrade", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK3(17, 0))
			r.set(func() { r.modes[2] = "503" })
			a := d3bAttack()
			e.HandleEvent(tracker.AttackEvent{Type: "confirmed", DBID: d3bAttackID, Attack: a})
			synctest.Wait()
			if n := len(d3bPostBodies(t, r, 0)); n != 3 || d3bDone(t, s) {
				t.Fatalf("first dispatch POSTs=%d done=%v want 3 / false", n, d3bDone(t, s))
			}
			mark := r.x.mark()
			e.HandleEvent(tracker.AttackEvent{Type: "updated", DBID: d3bAttackID, Attack: a})
			synctest.Wait()
			if n := len(d3bPostBodies(t, r, mark)); n != 0 {
				t.Errorf("once ran on updated: %d POST(s)", n)
			}
			mark = r.x.mark()
			e.HandleEvent(tracker.AttackEvent{Type: "type_upgrade", DBID: d3bAttackID, Attack: a})
			synctest.Wait()
			if n := len(d3bPostBodies(t, r, mark)); n != 3 {
				t.Errorf("once on type_upgrade after a partial failure POSTs=%d want 3", n)
			}
			if !d3bDone(t, s) {
				t.Errorf("AllTargetsDone=false after the type_upgrade rerun succeeded")
			}
			mark = r.x.mark()
			e.HandleEvent(tracker.AttackEvent{Type: "type_upgrade", DBID: d3bAttackID, Attack: a})
			synctest.Wait()
			if n := len(d3bPostBodies(t, r, mark)); n != 0 {
				t.Errorf("completed once dispatched again: %d POST(s)", n)
			}
		})
	})
	// N6: item 1 = lost (uncertain), item 2 ok, item 3 runs the dispatch ctx out.
	// The deferred failure logs and the synthetic row must still land (independent DB budget).
	t.Run("deferred_failure_survives_expired_actctx", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK3(17, 0))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.set(func() { r.modes[1], r.modes[3], r.cancel = "lost", "cancel", cancel })
			d3bCreate(t, ctx, s, e, "on_detected")
			synctest.Wait()
			posts := d3bPostBodies(t, r, 0)
			if len(posts) != 3 {
				t.Fatalf("POST count=%d want 3; dst_port=%v", len(posts), d3bPorts(posts, "dst_port"))
			}
			if ctx.Err() == nil {
				t.Fatalf("device: dispatch ctx was not cancelled by item 3")
			}
			byPort := map[float64]store.ActionExecutionLog{}
			for _, l := range d3bCreateLogs(s) {
				var b map[string]any
				_ = json.Unmarshal([]byte(l.RequestBody), &b)
				if p, ok := b["dst_port"].(float64); ok {
					byPort[p] = l
				}
			}
			for _, p := range []float64{8001, 8003} {
				if l, ok := byPort[p]; !ok || l.Status != "failed" || l.ExternalRuleID != d2bSynthetic {
					t.Errorf("deferred failure log for dst_port %v=%+v present=%v; want a failed %s log", p, l, ok, d2bSynthetic)
				}
			}
			if st := d3bRowsByStatus(s)[d2bSynthetic]; st != "failed" {
				t.Errorf("synthetic row=%q want failed (state write needs its own budget too)", st)
			}
			if d3bDone(t, s) {
				t.Errorf("AllTargetsDone=true although items 1 and 3 failed")
			}
			bodies, _, err := e.xdropSyntheticBodies(context.Background(), d3bSynthKey)
			if err != nil {
				t.Fatalf("device: synthetic bodies: %v", err)
			}
			if len(bodies) != 2 || !strings.Contains(strings.Join(bodies, " "), `"dst_port":8001`) {
				t.Errorf("recovery evidence=%v want the uncertain bodies of items 1 and 3", bodies)
			}
		})
	})
}

// ---------------------------------------------------------------- S07 在途竞态

// d3bInflight starts the create dispatch in the background and waits until POST #i is held at its gate.
// A dispatch that finishes first lacks item i: that is a business failure, not a device timeout.
func d3bInflight(t *testing.T, s *d3bStore, e *Engine, r *d3bRemote, i int) (release func(), done chan struct{}) {
	t.Helper()
	gate, reached := make(chan struct{}), make(chan struct{})
	r.set(func() { r.gates[i], r.reached[i] = gate, reached })
	a := d3bAttack()
	fa := analyzeFlows(context.Background(), s, a)
	if fa == nil {
		t.Fatalf("device: analyzeFlows nil")
	}
	done = make(chan struct{})
	go func() {
		defer close(done)
		_, _ = executeXDrop(context.Background(), s, s.actions[0], a, "confirmed", a.DstIP, "d3b", "on_detected", d3bAttackID, fa, e)
	}()
	select {
	case <-reached:
	case <-done:
		t.Fatalf("dispatch finished after %d POST(s); want item %d of the top-k set in flight", r.createCount(), i)
	case <-time.After(20 * time.Second):
		t.Fatalf("device: neither POST #%d nor dispatch end within 20s", i)
	}
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	return release, done
}

func d3bActiveIDs(s *d3bStore) []string {
	var out []string
	for _, l := range d3bCreateLogs(s) {
		if l.Status == "success" {
			out = append(out, l.ExternalRuleID)
		}
	}
	return out
}

func TestD3B_S07_InFlightRaceE2E(t *testing.T) {
	// item 3 in flight, item 1 force-removed: readback releases item 3, item 2 (already active) stays (Q-3).
	t.Run("force_sibling_while_inflight", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK3(17, 0))
			release, done := d3bInflight(t, s, e, r, 3)
			ids := d3bActiveIDs(s)
			if len(ids) != 2 {
				t.Fatalf("device: active items before force=%v want 2", ids)
			}
			if err := e.ForceRemove(context.Background(), d3bAttackID, d3bActionID, 7, ids[0]); err != nil {
				t.Fatalf("device: ForceRemove: %v", err)
			}
			release()
			<-done
			synctest.Wait()
			all := d3bActiveIDs(s)
			if len(all) != 3 {
				t.Fatalf("success logs=%v want 3", all)
			}
			rows := d3bRowsByStatus(s)
			if rows[ids[0]] != "withdrawn" || rows[ids[1]] != "active" || rows[all[2]] != "withdrawn" {
				t.Errorf("rows forced=%s sibling=%s inflight=%s want withdrawn / active / withdrawn", rows[ids[0]], rows[ids[1]], rows[all[2]])
			}
			if n := r.x.m.claimCount(all[2]); n != 0 {
				t.Errorf("in-flight item still claimed after readback: %d", n)
			}
			if n := r.x.ourClaims(); n != 1 {
				t.Errorf("remote claims=%d want 1 (the active sibling)", n)
			}
		})
	})
	// Between items no S lock is held: while item 2 is in flight the synthetic key is free.
	t.Run("synthetic_lock_free_between_items", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK3(17, 0))
			release, done := d3bInflight(t, s, e, r, 2)
			unlock, ok := e.lockXDrop(context.Background(), d3bSynthKey, true)
			if !ok {
				t.Errorf("synthetic key S held across items while item 2 is in flight")
			} else {
				unlock()
			}
			release()
			<-done
			synctest.Wait()
			if n := len(d3bActiveIDs(s)); n != 3 {
				t.Errorf("success items=%d want 3", n)
			}
		})
	})
	// Each readback owns a fresh 2T: the test holds S for 1.5T after items 1 and 2 (3T in total).
	t.Run("readback_budget_per_item", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK3(17, 0))
			hold := 3 * xdropTimeout(s.conn) / 2
			var holds atomic.Int32
			for _, i := range []int{1, 2} {
				r.set(func() {
					r.after[i] = func() {
						unlock, ok := e.lockXDrop(context.Background(), d3bSynthKey, true)
						if !ok {
							return
						}
						holds.Add(1)
						go func() { time.Sleep(hold); unlock() }()
					}
				})
			}
			d3bCreate(t, context.Background(), s, e, "on_detected")
			synctest.Wait()
			posts := d3bPostBodies(t, r, 0)
			if len(posts) != 3 {
				t.Fatalf("POST count=%d want 3", len(posts))
			}
			if holds.Load() != 2 {
				t.Fatalf("device: S held %d time(s) want 2", holds.Load())
			}
			rows := d3bRowsByStatus(s)
			for _, id := range d3bActiveIDs(s) {
				if rows[id] != "active" {
					t.Errorf("row %s=%s want active", id, rows[id])
				}
			}
			if d2bAnyLog(s.d2bStore, "late create leaked") {
				t.Errorf("a readback ran out of budget: %s", d2bLogTexts(s.d2bStore))
			}
			if n := r.x.ourClaims(); n != 3 {
				t.Errorf("remote claims=%d want 3", n)
			}
		})
	})
	// The end-of-attack scan runs while item 3 is in flight: its row lands later and readback keeps it;
	// the next reconcile round (attack no longer live) closes it.
	t.Run("end_scan_before_row_then_reconcile", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			s, e, r := d3bFixture(t, d3bDstTpl, d3bSeedK3(17, 0))
			release, done := d3bInflight(t, s, e, r, 3)
			before := d3bActiveIDs(s)
			d3bUnblock(s, e)
			synctest.Wait()
			rows := d3bRowsByStatus(s)
			for _, id := range before {
				if rows[id] != "withdrawn" {
					t.Errorf("end scan left %s=%s", id, rows[id])
				}
			}
			release()
			<-done
			synctest.Wait()
			all := d3bActiveIDs(s)
			if len(all) != 3 {
				t.Fatalf("success items=%v want 3", all)
			}
			late := all[2]
			if st := d3bRowsByStatus(s)[late]; st != "active" || r.x.m.claimCount(late) != 1 {
				t.Errorf("readback after the end scan: row=%s claims=%d want active / 1 (closed by reconcile, not readback)", st, r.x.m.claimCount(late))
			}
			e.reconcileXDropRound(context.Background())
			synctest.Wait()
			if st := d3bRowsByStatus(s)[late]; st != "withdrawn" {
				t.Errorf("reconcile left late row %s=%s want withdrawn", late, st)
			}
			if n := r.x.ourClaims(); n != 0 {
				t.Errorf("remote claims after reconcile=%d want 0", n)
			}
		})
	})
}

// ---------------------------------------------------------------- S08 配置

func TestD3B_S08_Config(t *testing.T) {
	t.Run("device_positive_control", func(t *testing.T) {
		cfg, err := d3aLoad(t, "")
		if err != nil || cfg.Action.Mode != "observe" {
			t.Fatalf("device: base config: %v %+v", err, cfg)
		}
		if got, ok := d3aActionField(cfg, "xdrop_narrow_pct"); !ok || got != 80 {
			t.Fatalf("device: reflection reader broken: xdrop_narrow_pct=%d present=%v", got, ok)
		}
	})
	t.Run("defaults", func(t *testing.T) {
		cfg, err := d3aLoad(t, "")
		if err != nil {
			t.Fatal(err)
		}
		for tag, want := range map[string]int64{"xdrop_topk_pct": 80, "xdrop_topk_max": 8} {
			if got, ok := d3aActionField(cfg, tag); !ok || got != want {
				t.Errorf("action_engine.%s default=%d present=%v want %d", tag, got, ok, want)
			}
		}
	})
	for _, c := range []struct {
		name, tag string
		value     int64
		bad       bool
	}{
		{"pct_1", "xdrop_topk_pct", 1, false},
		{"pct_100", "xdrop_topk_pct", 100, false},
		{"pct_0", "xdrop_topk_pct", 0, true},
		{"pct_101", "xdrop_topk_pct", 101, true},
		{"pct_negative", "xdrop_topk_pct", -5, true},
		{"max_1", "xdrop_topk_max", 1, false},
		{"max_8", "xdrop_topk_max", 8, false},
		{"max_0", "xdrop_topk_max", 0, true},
		{"max_9", "xdrop_topk_max", 9, true},
		{"max_negative", "xdrop_topk_max", -1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := d3aLoad(t, fmt.Sprintf("action_engine:\n  %s: %d\n", c.tag, c.value))
			if c.bad {
				if err == nil {
					t.Fatalf("out-of-range %s=%d accepted", c.tag, c.value)
				}
				if !strings.Contains(err.Error(), c.tag) {
					t.Fatalf("error does not name the key %s: %v", c.tag, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := d3aActionField(cfg, c.tag); !ok || got != c.value {
				t.Fatalf("%s=%d present=%v want %d", c.tag, got, ok, c.value)
			}
		})
	}
}

// main.go injects T2 / K exactly once, before actionEngine.Start(), from the loaded config
// (selector arguments whose final field carries yaml tag xdrop_topk_pct / xdrop_topk_max).
func TestD3B_S08_MainInjectionFromConfig(t *testing.T) {
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
	var calls, shape []*ast.CallExpr
	startPos := token.NoPos
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "action" && sel.Sel.Name == "SetXDropTopKConfig" {
				calls = append(calls, call)
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "action" && sel.Sel.Name == "SetXDropShapeConfig" {
				shape = append(shape, call)
			}
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "actionEngine" && sel.Sel.Name == "Start" && startPos == token.NoPos {
				startPos = call.Pos()
			}
		}
		return true
	})
	if startPos == token.NoPos || len(shape) != 1 {
		t.Fatalf("device: anchors actionEngine.Start()=%v SetXDropShapeConfig calls=%d", startPos != token.NoPos, len(shape))
	}
	if len(calls) != 1 {
		t.Fatalf("action.SetXDropTopKConfig calls=%d want 1", len(calls))
	}
	call := calls[0]
	if call.Pos() > startPos {
		t.Fatalf("SetXDropTopKConfig called after actionEngine.Start()")
	}
	if len(call.Args) != 2 {
		t.Fatalf("SetXDropTopKConfig args=%d want 2", len(call.Args))
	}
	for i, want := range []string{"xdrop_topk_pct", "xdrop_topk_max"} {
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
