package action

// Direct tests of shapeXDropBody / SetXDropShapeConfig /
// FlowAnalysis.SamplePackets / FlowAnalysis.TopSrcIPPct.
// Cases S01-S05, S08 (injection), and S09; fixture failures use t.Fatalf("device: ...").

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

const d3aWebTpl = `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","dst_port":"{dominant_dst_port}","src_port":"{dominant_src_port}","protocol":"{decoder}","action":"drop"}`

type d3aShapeOut struct {
	body  map[string]any
	hints []string
	ids   []int
}

func d3aRestoreShapeConfig(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { SetXDropShapeConfig(80, 1000) })
}

// d3aShape runs shapeXDropBody on a copy of body (operator action enum != rate_limit).
func d3aShape(t *testing.T, tplJSON string, body map[string]any, fa *FlowAnalysis, a *store.Attack, th *store.Threshold, thErr error) d3aShapeOut {
	t.Helper()
	return d3aShapeOp(t, tplJSON, body, fa, a, false, th, thErr)
}

// d3aShapeOp is d3aShape with an explicit operatorRateLimit argument. th/thErr is what lookup returns.
func d3aShapeOp(t *testing.T, tplJSON string, body map[string]any, fa *FlowAnalysis, a *store.Attack, opRate bool, th *store.Threshold, thErr error) d3aShapeOut {
	t.Helper()
	var tpl map[string]any
	if err := json.Unmarshal([]byte(tplJSON), &tpl); err != nil {
		t.Fatalf("device: template not JSON: %v", err)
	}
	out := d3aShapeOut{body: map[string]any{}}
	for k, v := range body {
		out.body[k] = v
	}
	lookup := func(id int) (*store.Threshold, error) {
		out.ids = append(out.ids, id)
		if thErr != nil {
			return nil, thErr
		}
		if th == nil {
			return nil, nil
		}
		cp := *th
		return &cp, nil
	}
	out.hints = shapeXDropBody(tpl, out.body, fa, a, a.DecoderFamily, opRate, lookup)
	return out
}

// d3aNum normalizes a JSON-ish number (any integer kind or float64).
func d3aNum(v any) (float64, bool) {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	}
	return 0, false
}

func d3aSorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func d3aPPS(v int64) *store.Threshold {
	return &store.Threshold{ID: d3aThID, Unit: "pps", Value: v, Enabled: true}
}

// d3aBody is the post-sanitize body for the Web template given fa.
func d3aBody(fa *FlowAnalysis, dec string) map[string]any {
	b := map[string]any{"dst_ip": "198.51.100.7", "protocol": "udp", "action": "drop"}
	if fa != nil {
		if fa.DominantDstPort != 0 {
			b["dst_port"] = float64(fa.DominantDstPort)
		}
		if fa.DominantSrcPort != 0 {
			b["src_port"] = float64(fa.DominantSrcPort)
		}
		if len(fa.TopSrcIPs) > 0 {
			b["src_ip"] = fa.TopSrcIPs[0]
		}
	}
	switch dec {
	case "tcp_syn":
		b["protocol"], b["tcp_flags"] = "tcp", "SYN,!ACK"
	case "icmp":
		b["protocol"] = "icmp"
		delete(b, "dst_port")
		delete(b, "src_port")
	case "fragment":
		b["protocol"] = "all"
		delete(b, "dst_port")
		delete(b, "src_port")
	case "bad_fragment", "invalid":
		delete(b, "protocol")
		delete(b, "dst_port")
		delete(b, "src_port")
		b["match_anomaly"] = float64(xdropAnomalyBit(dec))
	}
	return b
}

func d3aFAOf(dst, dstPct, src, srcPct, ipPct int, samples uint64) *FlowAnalysis {
	return &FlowAnalysis{DominantDstPort: dst, DominantDstPortPct: dstPct, DominantSrcPort: src, DominantSrcPortPct: srcPct,
		TopSrcIPs: []string{"192.0.2.10"}, TopSrcIPPct: ipPct, UniqueSrcIPs: 10, SamplePackets: samples}
}

func d3aWantRate(t *testing.T, body map[string]any, action string, rate float64) {
	t.Helper()
	if body["action"] != action {
		t.Errorf("action=%v want %s", body["action"], action)
	}
	got, has := body["rate_limit"]
	if rate == 0 {
		if has {
			t.Errorf("unexpected rate_limit=%v", got)
		}
		return
	}
	if n, ok := d3aNum(got); !ok || n != rate {
		t.Errorf("rate_limit=%v (%T) want %v", got, got, rate)
	}
}

// ---------------------------------------------------------------- S01

func TestD3A_S01_ShapeMatrix(t *testing.T) {
	d3aRestoreShapeConfig(t)
	SetXDropShapeConfig(80, 1000)
	for _, c := range []struct {
		name     string
		fa       *FlowAnalysis
		keep     []string // permitted keys that must survive
		hints    []string // exact set
		fallback bool
	}{
		{"dst85_src10", d3aFAOf(53, 85, 1234, 10, 10, 2000), []string{"dst_port"},
			[]string{"shape: kept dst_port=85%", "shape: dropped src_port=10%", "shape: dropped src_ip=10%"}, false},
		{"dst10_src85", d3aFAOf(53, 10, 1234, 85, 10, 2000), []string{"src_port"},
			[]string{"shape: dropped dst_port=10%", "shape: kept src_port=85%", "shape: dropped src_ip=10%"}, false},
		{"both_ge_t1_keep_src_only", d3aFAOf(53, 85, 1234, 90, 10, 2000), []string{"src_port"},
			[]string{"shape: dropped dst_port=85%", "shape: kept src_port=90%", "shape: dropped src_ip=10%"}, false},
		{"both_lt_t1_fallback", d3aFAOf(53, 70, 1234, 60, 10, 2000), nil,
			[]string{"shape: dropped dst_port=70%", "shape: dropped src_port=60%", "shape: dropped src_ip=10%", "shape: fallback rate_limit=50000"}, true},
		{"port_zero_not_narrowable", d3aFAOf(0, 90, 1234, 10, 10, 2000), nil,
			[]string{"shape: dropped dst_port=90%", "shape: dropped src_port=10%", "shape: dropped src_ip=10%", "shape: fallback rate_limit=50000"}, true},
		{"src_ip85_kept", d3aFAOf(53, 10, 1234, 10, 85, 2000), []string{"src_ip"},
			[]string{"shape: dropped dst_port=10%", "shape: dropped src_port=10%", "shape: kept src_ip=85%"}, false},
		{"src_ip79_dropped", d3aFAOf(53, 10, 1234, 10, 79, 2000), nil,
			[]string{"shape: dropped dst_port=10%", "shape: dropped src_port=10%", "shape: dropped src_ip=79%", "shape: fallback rate_limit=50000"}, true},
		{"boundary80_kept", d3aFAOf(53, 80, 1234, 10, 80, 2000), []string{"dst_port", "src_ip"},
			[]string{"shape: kept dst_port=80%", "shape: dropped src_port=10%", "shape: kept src_ip=80%"}, false},
		{"boundary79_dst_dropped", d3aFAOf(53, 79, 1234, 10, 10, 2000), nil,
			[]string{"shape: dropped dst_port=79%", "shape: dropped src_port=10%", "shape: dropped src_ip=10%", "shape: fallback rate_limit=50000"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := d3aAttack("udp", "198.51.100.7", true)
			in := d3aBody(c.fa, "udp")
			out := d3aShape(t, d3aWebTpl, in, c.fa, a, d3aPPS(50000), nil)
			keep := map[string]bool{}
			for _, k := range c.keep {
				keep[k] = true
			}
			for _, k := range []string{"dst_port", "src_port", "src_ip"} {
				_, has := out.body[k]
				if has != keep[k] {
					t.Errorf("%s present=%v want %v (body %v)", k, has, keep[k], out.body)
				}
				if has && !reflect.DeepEqual(out.body[k], in[k]) {
					t.Errorf("%s value changed %v -> %v", k, in[k], out.body[k])
				}
			}
			if out.body["dst_ip"] != "198.51.100.7" || out.body["protocol"] != "udp" {
				t.Errorf("non-shape keys touched: %v", out.body)
			}
			if !reflect.DeepEqual(d3aSorted(out.hints), d3aSorted(c.hints)) {
				t.Errorf("hints=%q want %q", out.hints, c.hints)
			}
			if c.fallback {
				d3aWantRate(t, out.body, "rate_limit", 50000)
				if !reflect.DeepEqual(out.ids, []int{d3aThID}) {
					t.Errorf("lookup ids=%v", out.ids)
				}
			} else {
				d3aWantRate(t, out.body, "drop", 0)
				if len(out.ids) != 0 {
					t.Errorf("lookup called without fallback: %v", out.ids)
				}
			}
		})
	}
}

// Source validity and tied candidates.
func TestD3A_S01_SourceValidityAndTieCandidates(t *testing.T) {
	d3aRestoreShapeConfig(t)
	SetXDropShapeConfig(80, 1000)
	for _, c := range []struct{ name, dst, src string }{
		{"v4_zero", "198.51.100.7", "0.0.0.0"},
		{"v6_zero", "2001:db8::7", "::"},
		{"v4_zero_host_prefix", "198.51.100.7", "0.0.0.0/32"},
		{"v6_zero_host_prefix", "2001:db8::7", "::/128"},
		{"v6_zero_expanded", "2001:db8::7", "0:0:0:0:0:0:0:0"},
		{"v4_mapped_zero", "198.51.100.7", "::ffff:0.0.0.0"},
	} {
		t.Run("zero_source/"+c.name, func(t *testing.T) {
			fa := &FlowAnalysis{TopSrcIPs: []string{c.src}, TopSrcIPPct: 100, UniqueSrcIPs: 1, SamplePackets: 1000}
			body := map[string]any{"dst_ip": c.dst, "src_ip": c.src, "protocol": "udp", "action": "drop"}
			out := d3aShape(t, d3aSrcIPTpl, body, fa, d3aAttack("udp", c.dst, true), d3aPPS(1000), nil)
			v3NoKeys(t, out.body, "src_ip")
			d3aWantRate(t, out.body, "rate_limit", 1000)
			if !reflect.DeepEqual(out.ids, []int{d3aThID}) {
				t.Errorf("lookup ids=%v", out.ids)
			}
			for _, h := range out.hints {
				if strings.HasPrefix(h, "shape: kept") {
					t.Errorf("all-zero source logged as kept: %q", h)
				}
			}
		})
	}
	// v0.3 §三-2: only all-zero sources are excluded; multicast is not a separate class.
	t.Run("multicast_source_kept", func(t *testing.T) {
		for _, src := range []string{"224.0.0.1", "ff02::1"} {
			dst := "198.51.100.7"
			if strings.Contains(src, ":") {
				dst = "2001:db8::7"
			}
			fa := &FlowAnalysis{TopSrcIPs: []string{src}, TopSrcIPPct: 100, UniqueSrcIPs: 1, SamplePackets: 1000}
			body := map[string]any{"dst_ip": dst, "src_ip": src, "protocol": "udp", "action": "drop"}
			out := d3aShape(t, d3aSrcIPTpl, body, fa, d3aAttack("udp", dst, true), d3aPPS(1000), nil)
			if out.body["src_ip"] != src || len(out.ids) != 0 {
				t.Errorf("%s at 100%% must be kept without fallback: %v ids=%v", src, out.body, out.ids)
			}
			d3aWantRate(t, out.body, "drop", 0)
		}
	})
	t.Run("zero_source/positive_control", func(t *testing.T) {
		fa := &FlowAnalysis{TopSrcIPs: []string{"192.0.2.10"}, TopSrcIPPct: 100, UniqueSrcIPs: 1, SamplePackets: 1000}
		body := map[string]any{"dst_ip": "198.51.100.7", "src_ip": "192.0.2.10", "protocol": "udp", "action": "drop"}
		out := d3aShape(t, d3aSrcIPTpl, body, fa, d3aAttack("udp", "198.51.100.7", true), d3aPPS(1000), nil)
		if out.body["src_ip"] != "192.0.2.10" {
			t.Fatalf("device: valid unicast source not kept: %v", out.body)
		}
		if len(out.ids) != 0 {
			t.Errorf("lookup called without fallback: %v", out.ids)
		}
		d3aWantRate(t, out.body, "drop", 0)
	})
	dstOnlyTpl := `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","protocol":"{decoder}","action":"drop"}`
	t.Run("tie/unpermitted_src_port_not_a_candidate", func(t *testing.T) {
		fa := d3aFAOf(53, 90, 1234, 95, 10, 2000)
		body := map[string]any{"dst_ip": "198.51.100.7", "dst_port": float64(53), "src_port": float64(1234), "protocol": "udp", "action": "drop"}
		out := d3aShape(t, dstOnlyTpl, body, fa, d3aAttack("udp", "198.51.100.7", true), d3aPPS(1000), nil)
		if out.body["dst_port"] != float64(53) || out.body["src_port"] != float64(1234) {
			t.Fatalf("unpermitted src_port must neither win the tie nor be touched: %v", out.body)
		}
		d3aWantRate(t, out.body, "drop", 0)
	})
	t.Run("tie/zero_src_port_not_a_candidate", func(t *testing.T) {
		fa := d3aFAOf(53, 90, 0, 95, 10, 2000)
		out := d3aShape(t, d3aWebTpl, d3aBody(fa, "udp"), fa, d3aAttack("udp", "198.51.100.7", true), d3aPPS(1000), nil)
		if out.body["dst_port"] != float64(53) {
			t.Fatalf("port-0 src_port must not win the tie: %v %q", out.body, out.hints)
		}
		v3NoKeys(t, out.body, "src_port")
		d3aWantRate(t, out.body, "drop", 0)
	})
}

// ---------------------------------------------------------------- S02

func TestD3A_S02_SampleThreshold(t *testing.T) {
	d3aRestoreShapeConfig(t)
	t.Run("below_N", func(t *testing.T) {
		SetXDropShapeConfig(80, 1000)
		fa := d3aFAOf(53, 95, 1234, 95, 95, 999)
		out := d3aShape(t, d3aWebTpl, d3aBody(fa, "udp"), fa, d3aAttack("udp", "198.51.100.7", true), d3aPPS(50000), nil)
		v3NoKeys(t, out.body, "dst_port", "src_port", "src_ip")
		d3aWantRate(t, out.body, "rate_limit", 50000)
		if !reflect.DeepEqual(d3aSorted(out.hints), d3aSorted([]string{"shape: samples 999 < 1000", "shape: fallback rate_limit=50000"})) {
			t.Errorf("hints=%q", out.hints)
		}
	})
	t.Run("equal_N_narrows", func(t *testing.T) {
		SetXDropShapeConfig(80, 1000)
		fa := d3aFAOf(53, 95, 1234, 10, 10, 1000)
		out := d3aShape(t, d3aWebTpl, d3aBody(fa, "udp"), fa, d3aAttack("udp", "198.51.100.7", true), d3aPPS(50000), nil)
		if out.body["dst_port"] != float64(53) {
			t.Errorf("SamplePackets == N must narrow: %v", out.body)
		}
		d3aWantRate(t, out.body, "drop", 0)
	})
	t.Run("fa_nil", func(t *testing.T) {
		SetXDropShapeConfig(80, 1000)
		out := d3aShape(t, d3aWebTpl, d3aBody(nil, "udp"), nil, d3aAttack("udp", "198.51.100.7", true), d3aPPS(50000), nil)
		d3aWantRate(t, out.body, "rate_limit", 50000)
		if !reflect.DeepEqual(d3aSorted(out.hints), d3aSorted([]string{"shape: samples 0 < 1000", "shape: fallback rate_limit=50000"})) {
			t.Errorf("hints=%q", out.hints)
		}
	})
	t.Run("N0_no_check", func(t *testing.T) {
		SetXDropShapeConfig(80, 0)
		fa := d3aFAOf(53, 95, 1234, 10, 10, 5)
		out := d3aShape(t, d3aWebTpl, d3aBody(fa, "udp"), fa, d3aAttack("udp", "198.51.100.7", true), d3aPPS(50000), nil)
		if out.body["dst_port"] != float64(53) {
			t.Errorf("N=0 must not check samples: %v", out.body)
		}
		d3aWantRate(t, out.body, "drop", 0)
		for _, h := range out.hints {
			if strings.Contains(h, "samples") {
				t.Errorf("N=0 logged %q", h)
			}
		}
	})
	t.Run("N0_fa_nil_falls_back", func(t *testing.T) {
		SetXDropShapeConfig(80, 0)
		out := d3aShape(t, d3aWebTpl, d3aBody(nil, "udp"), nil, d3aAttack("udp", "198.51.100.7", true), d3aPPS(50000), nil)
		d3aWantRate(t, out.body, "rate_limit", 50000)
	})
}

// ---------------------------------------------------------------- S03

// Every exclusion cell: valid pps threshold 1000, permitted src_ip (except the
// unpermitted cells), samples below N — only the exclusion keeps the action.
func TestD3A_S03_FallbackScope(t *testing.T) {
	d3aRestoreShapeConfig(t)
	SetXDropShapeConfig(80, 1000)
	low := d3aFAOf(53, 95, 1234, 95, 95, 100)
	lowV6 := &FlowAnalysis{TopSrcIPs: []string{"2001:db8:1::1"}, TopSrcIPPct: 95, UniqueSrcIPs: 2, SamplePackets: 100}
	rateTpl := `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","dst_port":"{dominant_dst_port}","src_port":"{dominant_src_port}","action":"rate_limit","rate_limit":5000}`
	rateBody := func() map[string]any {
		return map[string]any{"dst_ip": "198.51.100.7", "src_ip": "192.0.2.10", "dst_port": float64(53), "src_port": float64(1234), "protocol": "udp", "action": "rate_limit", "rate_limit": float64(5000)}
	}
	for _, c := range []struct {
		name, tpl, dec, dst string
		fa                  *FlowAnalysis
		body                map[string]any
		opRate              bool
		wantAction          string
		wantRate            float64
		fallback            bool
	}{
		{"guard_unpermitted", `{"dst_ip":"{dst_ip}","protocol":"{decoder}","action":"drop"}`, "udp", "198.51.100.7", low,
			map[string]any{"dst_ip": "198.51.100.7", "protocol": "udp", "action": "drop"}, false, "drop", 0, false},
		{"guard_literal_values", `{"dst_ip":"{dst_ip}","dst_port":53,"src_port":"123","src_ip":"192.0.2.9","action":"drop"}`, "udp", "198.51.100.7", low,
			map[string]any{"dst_ip": "198.51.100.7", "dst_port": float64(53), "src_port": float64(123), "src_ip": "192.0.2.9", "action": "drop"}, false, "drop", 0, false},
		{"guard_operator_rate_enum", rateTpl, "udp", "198.51.100.7", low, rateBody(), true, "rate_limit", 5000, false},
		{"guard_operator_rate_body", rateTpl, "udp", "198.51.100.7", low, rateBody(), false, "rate_limit", 5000, false},
		{"guard_operator_rate_enum_absent_action", d3aSrcIPTpl, "udp", "198.51.100.7", low,
			map[string]any{"dst_ip": "198.51.100.7", "src_ip": "192.0.2.10", "protocol": "udp"}, true, "", 0, false},
		{"guard_fragment_v4", d3aSrcIPTpl, "fragment", "198.51.100.7", low, d3aBody(low, "fragment"), false, "drop", 0, false},
		{"guard_fragment_v6", d3aSrcIPTpl, "fragment", "2001:db8::7", lowV6,
			map[string]any{"dst_ip": "2001:db8::7", "src_ip": "2001:db8:1::1", "protocol": "all", "action": "drop"}, false, "drop", 0, false},
		{"guard_anomaly_bad_fragment", d3aSrcIPTpl, "bad_fragment", "198.51.100.7", low, d3aBody(low, "bad_fragment"), false, "drop", 0, false},
		{"guard_anomaly_invalid", d3aSrcIPTpl, "invalid", "198.51.100.7", low, d3aBody(low, "invalid"), false, "drop", 0, false},
		{"guard_portless_ports_only", `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","src_port":"{dominant_src_port}","protocol":"{decoder}","action":"drop"}`, "icmp", "198.51.100.7", low,
			map[string]any{"dst_ip": "198.51.100.7", "protocol": "icmp", "action": "drop"}, false, "drop", 0, false},
		{"guard_literal_src_port_mixed", `{"dst_ip":"{dst_ip}","dst_port":"{dominant_dst_port}","src_port":123,"protocol":"{decoder}","action":"drop"}`, "udp", "198.51.100.7", d3aFAOf(53, 10, 1234, 10, 10, 1000),
			map[string]any{"dst_ip": "198.51.100.7", "dst_port": float64(53), "src_port": float64(123), "protocol": "udp", "action": "drop"}, false, "drop", 0, false},
		{"guard_literal_src_ip_mixed", `{"dst_ip":"{dst_ip}","src_ip":"192.0.2.9","dst_port":"{dominant_dst_port}","protocol":"{decoder}","action":"drop"}`, "udp", "198.51.100.7", d3aFAOf(53, 10, 1234, 10, 10, 1000),
			map[string]any{"dst_ip": "198.51.100.7", "src_ip": "192.0.2.9", "dst_port": float64(53), "protocol": "udp", "action": "drop"}, false, "drop", 0, false},
		{"udp_fallback", d3aWebTpl, "udp", "198.51.100.7", low, d3aBody(low, "udp"), false, "rate_limit", 1000, true},
		// v0.4 r2 N1: literals removed by cleaning do not block fallback.
		{"ineffective_literal_zero_src_ip", `{"dst_ip":"{dst_ip}","src_ip":"0.0.0.0","dst_port":"{dominant_dst_port}","action":"drop"}`, "udp", "198.51.100.7", d3aFAOf(53, 10, 1234, 10, 10, 1000),
			map[string]any{"dst_ip": "198.51.100.7", "src_ip": "0.0.0.0", "dst_port": float64(53), "protocol": "udp", "action": "drop"}, false, "rate_limit", 1000, true},
		{"ineffective_literal_port_zero_removed", `{"dst_ip":"{dst_ip}","src_port":"0","dst_port":"{dominant_dst_port}","action":"drop"}`, "udp", "198.51.100.7", d3aFAOf(53, 10, 1234, 10, 10, 1000),
			map[string]any{"dst_ip": "198.51.100.7", "dst_port": float64(53), "protocol": "udp", "action": "drop"}, false, "rate_limit", 1000, true},
		{"ineffective_literal_port_zero_number", `{"dst_ip":"{dst_ip}","src_port":0,"dst_port":"{dominant_dst_port}","action":"drop"}`, "udp", "198.51.100.7", d3aFAOf(53, 10, 1234, 10, 10, 1000),
			map[string]any{"dst_ip": "198.51.100.7", "src_port": float64(0), "dst_port": float64(53), "protocol": "udp", "action": "drop"}, false, "rate_limit", 1000, true},
		{"ineffective_literal_portless_port", `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","dst_port":53,"action":"drop"}`, "icmp", "198.51.100.7", d3aFAOf(53, 10, 1234, 10, 10, 1000),
			map[string]any{"dst_ip": "198.51.100.7", "src_ip": "192.0.2.10", "protocol": "icmp", "action": "drop"}, false, "rate_limit", 1000, true},
		{"absent_action_is_drop", d3aSrcIPTpl, "udp", "198.51.100.7", low,
			map[string]any{"dst_ip": "198.51.100.7", "src_ip": "192.0.2.10", "protocol": "udp"}, false, "rate_limit", 1000, true},
		{"portless_src_ip_fallback", d3aWebTpl, "icmp", "198.51.100.7", low, d3aBody(low, "icmp"), false, "rate_limit", 1000, true},
		{"syn_fallback", d3aWebTpl, "tcp_syn", "198.51.100.7", low, d3aBody(low, "tcp_syn"), false, "rate_limit", 1000, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := d3aAttack(c.dec, c.dst, true)
			out := d3aShapeOp(t, c.tpl, c.body, c.fa, a, c.opRate, d3aPPS(1000), nil)
			if c.wantAction == "" {
				if d3aHas(out.body, "action") || d3aHas(out.body, "rate_limit") {
					t.Errorf("operator enum rate_limit: action/rate must stay absent: %v", out.body)
				}
			} else {
				d3aWantRate(t, out.body, c.wantAction, c.wantRate)
			}
			if c.fallback && !reflect.DeepEqual(out.ids, []int{d3aThID}) || !c.fallback && len(out.ids) != 0 {
				t.Errorf("lookup ids=%v fallback=%v", out.ids, c.fallback)
			}
			for _, h := range out.hints {
				if !c.fallback && strings.Contains(h, "fallback") {
					t.Errorf("non-fallback case logged %q", h)
				}
				if c.dec == "icmp" && strings.Contains(h, "_port") {
					t.Errorf("portless family logged a port dimension: %q", h)
				}
			}
			switch c.name {
			case "guard_unpermitted", "guard_literal_values", "guard_portless_ports_only":
				if !reflect.DeepEqual(out.body, c.body) || len(out.hints) != 0 {
					t.Errorf("unpermitted template must be untouched: body %v hints %q", out.body, out.hints)
				}
			case "guard_literal_src_port_mixed", "guard_literal_src_ip_mixed":
				v3NoKeys(t, out.body, "dst_port") // permitted dim below T1 is still dropped
				for k, v := range c.body {
					if k != "dst_port" && !reflect.DeepEqual(out.body[k], v) {
						t.Errorf("literal %s changed: %v -> %v", k, v, out.body[k])
					}
				}
			case "syn_fallback":
				if out.body["tcp_flags"] != "SYN,!ACK" || out.body["protocol"] != "tcp" {
					t.Errorf("SYN fallback lost flags: %v", out.body)
				}
			}
		})
	}
}

// ---------------------------------------------------------------- S04

func TestD3A_S04_ThresholdLookup(t *testing.T) {
	d3aRestoreShapeConfig(t)
	SetXDropShapeConfig(80, 1000)
	random := d3aFAOf(1000, 10, 10000, 10, 10, 1000)
	for _, c := range []struct {
		name     string
		th       *store.Threshold
		err      error
		withID   bool
		action   string
		rate     float64
		wantIDs  []int
		fallback string // exact fallback-related hint, or prefix for unavailable
	}{
		{"pps", d3aPPS(50000), nil, true, "rate_limit", 50000, []int{d3aThID}, "shape: fallback rate_limit=50000"},
		{"pps_1", d3aPPS(1), nil, true, "rate_limit", 1, []int{d3aThID}, "shape: fallback rate_limit=1"},
		{"pps_max", d3aPPS(4294967295), nil, true, "rate_limit", 4294967295, []int{d3aThID}, "shape: fallback rate_limit=4294967295"},
		{"pps_clamped", d3aPPS(4294967296), nil, true, "rate_limit", 4294967295, []int{d3aThID}, "shape: fallback rate_limit=4294967295"},
		{"pps_huge_clamped", d3aPPS(1 << 62), nil, true, "rate_limit", 4294967295, []int{d3aThID}, "shape: fallback rate_limit=4294967295"},
		{"bps", &store.Threshold{ID: d3aThID, Unit: "bps", Value: 50000}, nil, true, "drop", 0, []int{d3aThID}, "fallback rate unavailable: "},
		{"pct", &store.Threshold{ID: d3aThID, Unit: "pct", Value: 50}, nil, true, "drop", 0, []int{d3aThID}, "fallback rate unavailable: "},
		{"pps_zero", d3aPPS(0), nil, true, "drop", 0, []int{d3aThID}, "fallback rate unavailable: "},
		{"pps_negative", d3aPPS(-7), nil, true, "drop", 0, []int{d3aThID}, "fallback rate unavailable: "},
		{"nil_id", d3aPPS(50000), nil, false, "drop", 0, nil, "fallback rate unavailable: "},
		{"deleted", nil, nil, true, "drop", 0, []int{d3aThID}, "fallback rate unavailable: "},
		{"read_error", nil, fmt.Errorf("db down"), true, "drop", 0, []int{d3aThID}, "fallback rate unavailable: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := d3aAttack("udp", "198.51.100.7", c.withID)
			out := d3aShape(t, d3aWebTpl, d3aBody(random, "udp"), random, a, c.th, c.err)
			d3aWantRate(t, out.body, c.action, c.rate)
			if !reflect.DeepEqual(out.ids, c.wantIDs) {
				t.Errorf("lookup ids=%v want %v", out.ids, c.wantIDs)
			}
			n := 0
			for _, h := range out.hints {
				if strings.Contains(h, "fallback") {
					n++
					if c.action == "rate_limit" && h != c.fallback || c.action == "drop" && !strings.HasPrefix(h, c.fallback) {
						t.Errorf("fallback hint %q want %q", h, c.fallback)
					}
				}
			}
			if n != 1 {
				t.Errorf("fallback hints=%d want 1: %q", n, out.hints)
			}
		})
	}
	t.Run("no_fallback_zero_lookups", func(t *testing.T) {
		for name, fa := range map[string]*FlowAnalysis{
			"dst": d3aFAOf(53, 90, 1234, 10, 10, 2000), "src_port": d3aFAOf(53, 10, 53, 90, 10, 2000), "src_ip": d3aFAOf(53, 10, 1234, 10, 90, 2000),
		} {
			out := d3aShape(t, d3aWebTpl, d3aBody(fa, "udp"), fa, d3aAttack("udp", "198.51.100.7", true), d3aPPS(50000), nil)
			if len(out.ids) != 0 {
				t.Errorf("%s: lookup called without fallback: %v", name, out.ids)
			}
		}
	})
}

// ---------------------------------------------------------------- S05

func TestD3A_S05_HintFormat(t *testing.T) {
	d3aRestoreShapeConfig(t)
	SetXDropShapeConfig(80, 1000)
	type sc struct {
		fa  *FlowAnalysis
		dec string
		th  *store.Threshold
		err error
		id  bool
	}
	random := d3aFAOf(1000, 10, 10000, 10, 10, 1000)
	all := map[string]sc{
		"kept":            {d3aFAOf(53, 90, 1234, 10, 10, 2000), "udp", d3aPPS(1), nil, true},
		"tie":             {d3aFAOf(53, 90, 53, 90, 90, 2000), "udp", d3aPPS(1), nil, true},
		"fallback":        {random, "udp", d3aPPS(50000), nil, true},
		"samples":         {d3aFAOf(53, 90, 1234, 10, 10, 10), "udp", d3aPPS(50000), nil, true},
		"fa_nil":          {nil, "udp", d3aPPS(50000), nil, true},
		"bps":             {random, "udp", &store.Threshold{Unit: "bps", Value: 1}, nil, true},
		"nil_id":          {random, "udp", nil, nil, false},
		"read_error":      {random, "udp", nil, fmt.Errorf("x"), true},
		"syn":             {random, "tcp_syn", d3aPPS(50000), nil, true},
		"icmp":            {random, "icmp", d3aPPS(50000), nil, true},
		"fragment_guard":  {random, "fragment", d3aPPS(50000), nil, true},
		"anomaly_guard":   {random, "invalid", d3aPPS(50000), nil, true},
		"wrong_proto_tpl": {random, "udp", d3aPPS(50000), nil, true},
	}
	for name, c := range all {
		t.Run(name, func(t *testing.T) {
			body := d3aBody(c.fa, c.dec)
			if name == "wrong_proto_tpl" {
				body["protocol"] = "tcp"
			}
			out := d3aShape(t, d3aWebTpl, body, c.fa, d3aAttack(c.dec, "198.51.100.7", c.id), c.th, c.err)
			if len(out.hints) == 0 {
				t.Fatalf("permitted template produced no decision hint")
			}
			for _, h := range out.hints {
				ok := false
				for _, re := range d3aHintFormats {
					ok = ok || re.MatchString(h)
				}
				if !ok {
					t.Errorf("hint %q does not follow §三-9", h)
				}
				if strings.Contains(h, "protocol pinned:") {
					t.Errorf("hint contains protocol pinned: %q", h)
				}
			}
		})
	}
}

// ---------------------------------------------------------------- S08 (injection)

func TestD3A_S08_Injection(t *testing.T) {
	d3aRestoreShapeConfig(t)
	a := d3aAttack("udp", "198.51.100.7", true)
	t.Run("package_default_80_1000", func(t *testing.T) {
		for _, c := range []struct {
			name string
			fa   *FlowAnalysis
			keep bool
		}{
			{"pct80_n1000", d3aFAOf(53, 80, 1234, 10, 10, 1000), true},
			{"pct79", d3aFAOf(53, 79, 1234, 10, 10, 1000), false},
			{"n999", d3aFAOf(53, 95, 1234, 10, 10, 999), false},
		} {
			out := d3aShape(t, d3aWebTpl, d3aBody(c.fa, "udp"), c.fa, a, d3aPPS(50000), nil)
			if _, has := out.body["dst_port"]; has != c.keep {
				t.Errorf("%s: dst_port kept=%v want %v (default config not 80/1000?)", c.name, has, c.keep)
			}
		}
	})
	t.Run("injected_50_10", func(t *testing.T) {
		SetXDropShapeConfig(50, 10)
		fa := d3aFAOf(53, 60, 1234, 10, 10, 20)
		out := d3aShape(t, d3aWebTpl, d3aBody(fa, "udp"), fa, a, d3aPPS(50000), nil)
		if out.body["dst_port"] != float64(53) {
			t.Errorf("injected T1=50 N=10 not applied: %v %q", out.body, out.hints)
		}
		fa = d3aFAOf(53, 49, 1234, 10, 10, 20)
		out = d3aShape(t, d3aWebTpl, d3aBody(fa, "udp"), fa, a, d3aPPS(50000), nil)
		if _, has := out.body["dst_port"]; has {
			t.Errorf("injected T1=50 kept 49%%: %v", out.body)
		}
		fa = d3aFAOf(53, 95, 1234, 10, 10, 9)
		out = d3aShape(t, d3aWebTpl, d3aBody(fa, "udp"), fa, a, d3aPPS(50000), nil)
		if !reflect.DeepEqual(d3aSorted(out.hints), d3aSorted([]string{"shape: samples 9 < 10", "shape: fallback rate_limit=50000"})) {
			t.Errorf("injected N=10 hints=%q", out.hints)
		}
	})
}

// ---------------------------------------------------------------- S09

// d3aFlowStore records which flow query branch analyzeFlows used.
type d3aFlowStore struct {
	*v3Store
	method string
	filter store.FlowLogFilter
}
type d3aFlowRepo struct {
	store.FlowLogRepo
	s *d3aFlowStore
}

func (s *d3aFlowStore) FlowLogs() store.FlowLogRepo { return d3aFlowRepo{s: s} }
func (r d3aFlowRepo) QueryByDstIP(ctx context.Context, f store.FlowLogFilter) ([]store.FlowLog, error) {
	r.s.method, r.s.filter = "dst", f
	return v3Flows{s: r.s.v3Store}.QueryByDstIP(ctx, f)
}
func (r d3aFlowRepo) QueryBySrcIP(ctx context.Context, f store.FlowLogFilter) ([]store.FlowLog, error) {
	r.s.method, r.s.filter = "src", f
	return v3Flows{s: r.s.v3Store}.QueryByDstIP(ctx, f)
}

func TestD3A_S09_FlowAnalysisFields(t *testing.T) {
	udp := func(src string, dport int, pkts int64) store.FlowLog {
		return store.FlowLog{SrcIP: src, DstPort: dport, Protocol: 17, Packets: pkts}
	}
	syn := func(src string, flags int, pkts int64) store.FlowLog {
		return store.FlowLog{SrcIP: src, DstPort: 80, Protocol: 6, TCPFlags: flags, Packets: pkts}
	}
	for _, c := range []struct {
		name, dec, dst, dir string
		flows               []store.FlowLog
		bypass              bool
		wantMethod          string
		samples             uint64
		topPct              int
	}{
		{"single_source_1000", "udp", "198.51.100.7", "receives", []store.FlowLog{udp("192.0.2.1", 53, 250), udp("192.0.2.1", 54, 250), udp("192.0.2.1", 55, 250), udp("192.0.2.1", 56, 250)}, false, "dst", 1000, 100},
		{"two_sources_500_each", "udp", "198.51.100.7", "receives", []store.FlowLog{udp("192.0.2.1", 53, 500), udp("192.0.2.2", 53, 500)}, false, "dst", 1000, 50},
		{"sixty_forty", "udp", "198.51.100.7", "receives", []store.FlowLog{udp("192.0.2.1", 53, 600), udp("192.0.2.2", 53, 400)}, false, "dst", 1000, 60},
		{"dirty_other_protocol", "udp", "198.51.100.7", "receives", []store.FlowLog{udp("192.0.2.1", 53, 500), udp("192.0.2.2", 53, 500), {SrcIP: "192.0.2.9", DstPort: 443, Protocol: 6, Packets: 100000}}, true, "dst", 1000, 50},
		{"dirty_tcp_flags", "tcp_syn", "198.51.100.7", "receives", []store.FlowLog{syn("192.0.2.1", 2, 500), syn("192.0.2.2", 2, 500), syn("192.0.2.9", 18, 100000), syn("192.0.2.9", 16, 100000)}, true, "dst", 1000, 50},
		{"sends_direction", "udp", "198.51.100.7", "sends", []store.FlowLog{udp("198.51.100.7", 53, 1000)}, false, "src", 1000, 100},
		{"subnet_target", "udp", "198.51.100.0/24", "receives", []store.FlowLog{udp("192.0.2.1", 53, 500), udp("192.0.2.2", 53, 500)}, false, "dst", 1000, 50},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := &d3aFlowStore{v3Store: newV3Store("")}
			s.bypassFilter = c.bypass
			s.flows = c.flows
			a := v3Attack(101, c.dec, c.dst)
			a.Direction = c.dir
			fa := analyzeFlows(context.Background(), s, a)
			if fa == nil {
				t.Fatalf("device: analyzeFlows nil")
			}
			if s.method != c.wantMethod || s.filter.DstIP != c.dst {
				t.Fatalf("device: query branch=%s DstIP=%q want %s/%q", s.method, s.filter.DstIP, c.wantMethod, c.dst)
			}
			if fa.SamplePackets != c.samples || fa.TopSrcIPPct != c.topPct {
				t.Fatalf("SamplePackets=%d TopSrcIPPct=%d want %d/%d", fa.SamplePackets, fa.TopSrcIPPct, c.samples, c.topPct)
			}
		})
	}
	t.Run("zero_rows", func(t *testing.T) {
		s := newV3Store("")
		if fa := analyzeFlows(context.Background(), s, v3Attack(101, "udp", "198.51.100.7")); fa != nil {
			t.Fatalf("0 rows must stay nil (S02 treats nil as 0 samples): %+v", fa)
		}
		s.bypassFilter = true
		s.flows = []store.FlowLog{{Protocol: 6, DstPort: 443, Packets: 10}}
		if fa := analyzeFlows(context.Background(), s, v3Attack(101, "udp", "198.51.100.7")); fa != nil {
			t.Fatalf("all-filtered must stay nil: %+v", fa)
		}
	})
}
