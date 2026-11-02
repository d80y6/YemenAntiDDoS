package action

// Direct tests of shapeXDropBodies / SetXDropTopKConfig /
// FlowAnalysis.SrcPortRank / DstPortRank / PortCount.
// Uses helpers from xdrop_dao3b_test.go and the single-body shaping tests; fixture failures use t.Fatalf("device: ...").

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func d3bRestoreTopK(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { SetXDropTopKConfig(80, 8); SetXDropShapeConfig(80, 1000) })
}

// ---------------------------------------------------------------- N01 排名（全量过滤后、非 0、包数降序端口升序、前 8）

func TestD3B_N01_PortRank(t *testing.T) {
	t.Run("nonzero_sorted_top8", func(t *testing.T) {
		s := newV3Store("")
		// dst: 0=300 (counts in the 1000 samples, never ranked), 10 non-zero ports; ties at 50 resolved by port ascending; 9th port dropped.
		s.flows = d3bRows(17, 0, d3bCell{1, 0, 300}, d3bCell{1, 905, 100}, d3bCell{1, 903, 100}, d3bCell{1, 901, 200},
			d3bCell{2, 909, 50}, d3bCell{2, 907, 50}, d3bCell{2, 908, 50}, d3bCell{2, 902, 50}, d3bCell{2, 904, 50}, d3bCell{2, 906, 50})
		fa := analyzeFlows(context.Background(), s, v3Attack(101, "udp", "198.51.100.7"))
		if fa == nil || fa.SamplePackets != 1000 {
			t.Fatalf("device: fa=%+v", fa)
		}
		want := []PortCount{{901, 200}, {903, 100}, {905, 100}, {902, 50}, {904, 50}, {906, 50}, {907, 50}, {908, 50}}
		if !reflect.DeepEqual(fa.DstPortRank, want) {
			t.Errorf("DstPortRank=%v want %v", fa.DstPortRank, want)
		}
		if want := []PortCount{{1, 700}, {2, 300}}; !reflect.DeepEqual(fa.SrcPortRank, want) {
			t.Errorf("SrcPortRank=%v want %v", fa.SrcPortRank, want)
		}
	})
	t.Run("filtered_rows_only", func(t *testing.T) {
		s := newV3Store("")
		s.bypassFilter = true
		s.flows = append(d3bRows(17, 0, d3bCell{10, 53, 600}, d3bCell{11, 54, 400}), store.FlowLog{SrcPort: 99, DstPort: 443, Protocol: 6, Packets: 100000})
		fa := analyzeFlows(context.Background(), s, v3Attack(101, "udp", "198.51.100.7"))
		if fa == nil || fa.SamplePackets != 1000 {
			t.Fatalf("device: fa=%+v", fa)
		}
		if want := []PortCount{{53, 600}, {54, 400}}; !reflect.DeepEqual(fa.DstPortRank, want) {
			t.Errorf("DstPortRank=%v want %v (other protocol must be filtered out)", fa.DstPortRank, want)
		}
		if want := []PortCount{{10, 600}, {11, 400}}; !reflect.DeepEqual(fa.SrcPortRank, want) {
			t.Errorf("SrcPortRank=%v want %v", fa.SrcPortRank, want)
		}
	})
	t.Run("existing_fields_unchanged", func(t *testing.T) {
		s := newV3Store("")
		s.flows = d3bRows(17, 0, d3bCell{10, 53, 600}, d3bCell{11, 54, 400})
		fa := analyzeFlows(context.Background(), s, v3Attack(101, "udp", "198.51.100.7"))
		if fa == nil || fa.DominantDstPort != 53 || fa.DominantDstPortPct != 60 || !reflect.DeepEqual(fa.TopDstPorts, []int{53, 54}) || !reflect.DeepEqual(fa.TopSrcPorts, []int{10, 11}) {
			t.Errorf("legacy fields changed: %+v", fa)
		}
	})
}

// ---------------------------------------------------------------- N02 多份入口（shape 层）

func d3bShapeBodies(t *testing.T, tplJSON string, body map[string]any, fa *FlowAnalysis, a *store.Attack, opRate bool, th *store.Threshold) ([]map[string]any, []string, []string, []int) {
	t.Helper()
	var tpl map[string]any
	if err := json.Unmarshal([]byte(tplJSON), &tpl); err != nil {
		t.Fatalf("device: template not JSON: %v", err)
	}
	in := map[string]any{}
	for k, v := range body {
		in[k] = v
	}
	var ids []int
	lookup := func(id int) (*store.Threshold, error) {
		ids = append(ids, id)
		if th == nil {
			return nil, nil
		}
		cp := *th
		return &cp, nil
	}
	bodies, hints, items := shapeXDropBodies(tpl, in, fa, a, a.DecoderFamily, opRate, lookup)
	return bodies, hints, items, ids
}

func d3bFA(dstRank, srcRank []PortCount, dstPct, srcPct, ipPct int, samples uint64) *FlowAnalysis {
	fa := &FlowAnalysis{TopSrcIPs: []string{"192.0.2.10"}, TopSrcIPPct: ipPct, UniqueSrcIPs: 10, SamplePackets: samples,
		DominantDstPortPct: dstPct, DominantSrcPortPct: srcPct, DstPortRank: dstRank, SrcPortRank: srcRank}
	if len(dstRank) > 0 {
		fa.DominantDstPort = dstRank[0].Port
	}
	if len(srcRank) > 0 {
		fa.DominantSrcPort = srcRank[0].Port
	}
	return fa
}

func TestD3B_N02_ShapeBodies(t *testing.T) {
	d3bRestoreTopK(t)
	a := d3aAttack("udp", "198.51.100.7", true)
	dst404020 := []PortCount{{53, 400}, {123, 400}, {389, 200}}
	spread := []PortCount{{40001, 50}, {40002, 50}, {40003, 50}}
	t.Run("topk_bodies_and_exact_hints", func(t *testing.T) {
		fa := d3bFA(dst404020, spread, 40, 5, 5, 1000)
		bodies, hints, items, ids := d3bShapeBodies(t, d3aWebTpl, d3aBody(fa, "udp"), fa, a, false, d3aPPS(50000))
		want := []map[string]any{
			{"dst_ip": "198.51.100.7", "protocol": "udp", "action": "drop", "dst_port": 53},
			{"dst_ip": "198.51.100.7", "protocol": "udp", "action": "drop", "dst_port": 123},
		}
		if len(bodies) != 2 {
			t.Fatalf("bodies=%v want 2", bodies)
		}
		for i := range want {
			got := map[string]any{}
			for k, v := range bodies[i] {
				if n, ok := d3aNum(v); ok && k == "dst_port" {
					v = int(n)
				}
				got[k] = v
			}
			if !reflect.DeepEqual(got, want[i]) {
				t.Errorf("body %d=%v want %v", i+1, bodies[i], want[i])
			}
		}
		if w := []string{"shape: dropped src_ip=5%", "shape: dropped src_port=5%", "shape: topk dst_port=2 80%"}; !reflect.DeepEqual(d3aSorted(hints), w) {
			t.Errorf("hints=%q want %q", hints, w)
		}
		if w := []string{"shape: item 1/2 dst_port=53", "shape: item 2/2 dst_port=123"}; !reflect.DeepEqual(items, w) {
			t.Errorf("item hints=%q want %q", items, w)
		}
		if len(ids) != 0 {
			t.Errorf("top-k branch looked up thresholds: %v", ids)
		}
		for _, h := range append(hints, items...) {
			if strings.Contains(h, "protocol pinned:") {
				t.Errorf("hint carries protocol pinned: %q", h)
			}
		}
	})
	t.Run("topk_keeps_concentrated_source", func(t *testing.T) {
		fa := d3bFA(dst404020, spread, 40, 5, 90, 1000)
		bodies, hints, _, _ := d3bShapeBodies(t, d3aWebTpl, d3aBody(fa, "udp"), fa, a, false, d3aPPS(50000))
		if len(bodies) != 2 {
			t.Fatalf("bodies=%v", bodies)
		}
		for i, b := range bodies {
			if b["src_ip"] != "192.0.2.10" {
				t.Errorf("body %d src_ip=%v want kept 192.0.2.10", i+1, b["src_ip"])
			}
		}
		if !reflect.DeepEqual(d3aSorted(hints), []string{"shape: dropped src_port=5%", "shape: kept src_ip=90%", "shape: topk dst_port=2 80%"}) {
			t.Errorf("hints=%q", hints)
		}
	})
	t.Run("operator_rate_kept_no_lookup", func(t *testing.T) {
		fa := d3bFA(dst404020, spread, 40, 5, 5, 1000)
		body := d3aBody(fa, "udp")
		body["action"], body["rate_limit"] = "rate_limit", float64(5000)
		for _, op := range []bool{false, true} {
			bodies, _, _, ids := d3bShapeBodies(t, d3aWebTpl, body, fa, a, op, d3aPPS(1000))
			if len(bodies) != 2 || len(ids) != 0 {
				t.Fatalf("op=%v bodies=%d lookups=%v", op, len(bodies), ids)
			}
			for i, b := range bodies {
				d3aWantRate(t, b, "rate_limit", 5000)
				if t.Failed() {
					t.Fatalf("op=%v body %d=%v", op, i+1, b)
				}
			}
		}
	})
	// k = 1 and "no top-k" inputs return exactly what shapeXDropBody returns, as one body.
	t.Run("single_body_equivalence", func(t *testing.T) {
		for _, c := range []struct {
			name string
			fa   *FlowAnalysis
		}{
			{"t1", d3bFA([]PortCount{{53, 900}, {80, 100}}, spread, 90, 5, 5, 1000)},
			{"low_sample", d3bFA(dst404020, spread, 40, 5, 5, 999)},
			{"short_of_t2", d3bFA([]PortCount{{1, 91}, {2, 91}, {3, 91}, {4, 91}, {5, 91}, {6, 91}, {7, 91}, {8, 91}}, spread, 9, 5, 5, 1001)},
			{"no_rank", d3bFA(nil, nil, 40, 5, 5, 1000)},
			{"fa_nil", nil},
		} {
			t.Run(c.name, func(t *testing.T) {
				body := d3aBody(c.fa, "udp")
				if c.fa != nil && c.fa.DominantDstPort == 0 {
					body["dst_port"] = float64(53)
				}
				old := d3aShape(t, d3aWebTpl, body, c.fa, a, d3aPPS(50000), nil)
				bodies, hints, items, ids := d3bShapeBodies(t, d3aWebTpl, body, c.fa, a, false, d3aPPS(50000))
				if len(bodies) != 1 || items != nil {
					t.Fatalf("bodies=%d items=%q want 1 / nil", len(bodies), items)
				}
				if !reflect.DeepEqual(bodies[0], old.body) || !reflect.DeepEqual(hints, old.hints) || !reflect.DeepEqual(ids, old.ids) {
					t.Errorf("single path diverged:\n new %v %q %v\n old %v %q %v", bodies[0], hints, ids, old.body, old.hints, old.ids)
				}
			})
		}
	})
	// SamplePackets = 0 with N = 0: the old path, no division by zero.
	t.Run("zero_samples_no_divide", func(t *testing.T) {
		SetXDropShapeConfig(80, 0)
		defer SetXDropShapeConfig(80, 1000)
		fa := d3bFA(dst404020, spread, 0, 0, 0, 0)
		bodies, hints, items, _ := d3bShapeBodies(t, d3aWebTpl, d3aBody(fa, "udp"), fa, a, false, d3aPPS(50000))
		if len(bodies) != 1 || items != nil {
			t.Fatalf("zero samples took the top-k branch: %v %q %q", bodies, hints, items)
		}
	})
	t.Run("non_ported_and_unpermitted", func(t *testing.T) {
		fa := d3bFA(dst404020, dst404020, 40, 40, 5, 1000)
		icmp := d3aAttack("icmp", "198.51.100.7", true)
		if bodies, _, items, _ := d3bShapeBodies(t, d3aWebTpl, d3aBody(fa, "icmp"), fa, icmp, false, d3aPPS(50000)); len(bodies) != 1 || items != nil {
			t.Errorf("non-ported decoder produced %d bodies", len(bodies))
		}
		if bodies, _, items, _ := d3bShapeBodies(t, d3aSrcIPTpl, d3aBody(fa, "udp"), fa, a, false, d3aPPS(50000)); len(bodies) != 1 || items != nil {
			t.Errorf("unpermitted ports produced %d bodies", len(bodies))
		}
	})
}

// ---------------------------------------------------------------- N03 注入（T2 / K）端到端

func TestD3B_N03_TopKConfigE2E(t *testing.T) {
	d3bRestoreTopK(t)
	run := func(t *testing.T, rows []store.FlowLog) (d3bRun, *store.Attack) {
		t.Helper()
		m := d3aMock(t)
		s := d3aNewStore("pps", 50000)
		a := d3aAttack("udp", "198.51.100.7", true)
		fa := d3aFA(t, s, a, rows)
		return d3bExecute(t, m, s, a, v3Action(81, d3bDstTpl), fa), a
	}
	k3 := func() []store.FlowLog {
		return d3bRows(17, 0, d3bDst(7901, 400, 7902, 200, 7903, 100, 7904, 100, 7905, 100, 7906, 100)...)
	}
	t.Run("K1_disables_topk_keeps_fallback", func(t *testing.T) {
		SetXDropTopKConfig(80, 1)
		r, _ := run(t, d3bSeed4040())
		d3bCheckSingle(t, r, "rate_limit", 50000, "dst_port")
	})
	t.Run("K1_keeps_t1", func(t *testing.T) {
		SetXDropTopKConfig(80, 1)
		r, _ := run(t, d3bRows(17, 0, d3bDst(53, 900, 80, 100)...))
		d3bCheckSingle(t, r, "drop", 0)
		if r.posts[0]["dst_port"] != float64(53) {
			t.Errorf("K=1 lost the T1 port: %v", r.posts[0])
		}
	})
	t.Run("K3_three_rules", func(t *testing.T) {
		SetXDropTopKConfig(80, 3)
		r, a := run(t, d3bRows(17, 0, d3bDst(7901, 400, 7902, 300, 7903, 100, 7904, 100, 7905, 100)...))
		d3bCheckTopK(t, r, a, 81, d3bWant{dim: "dst_port", ports: []int{7901, 7902, 7903}, pct: 80, absent: []string{"rate_limit"}})
	})
	// 40/20/10/10/10/10: top 4 = 80% but K = 3, so no top-k rule; use the single-body fallback path.
	t.Run("K3_cap_short_of_T2", func(t *testing.T) {
		SetXDropTopKConfig(80, 3)
		r, _ := run(t, k3())
		d3bCheckSingle(t, r, "rate_limit", 50000, "dst_port")
	})
	t.Run("K8_same_seed_four_rules", func(t *testing.T) {
		SetXDropTopKConfig(80, 8)
		r, a := run(t, k3())
		d3bCheckTopK(t, r, a, 81, d3bWant{dim: "dst_port", ports: []int{7901, 7902, 7903, 7904}, pct: 80, absent: []string{"rate_limit"}})
	})
	t.Run("T2_60", func(t *testing.T) {
		SetXDropTopKConfig(60, 8)
		r, a := run(t, k3())
		d3bCheckTopK(t, r, a, 81, d3bWant{dim: "dst_port", ports: []int{7901, 7902}, pct: 60, absent: []string{"rate_limit"}})
	})
}
