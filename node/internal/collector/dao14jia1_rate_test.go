package collector

import (
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/node/internal/bpf"
)

// Expected traces come from the independent rate_cells.out oracle.
func dao14Trace(t *testing.T, smooth float64, applied uint32, pps uint64, active, quiet int, drops bool) ([]uint32, []int) {
	t.Helper()
	var trace []uint32
	writes := []int{}
	var last time.Time
	for i := 1; i <= active+quiet; i++ {
		now := time.Unix(1000+int64(i), 0)
		input, drop := pps, 0
		if drops {
			drop = i
		}
		if i > active {
			input, drop = 0, 0
		}
		s, candidate, write := nextSampleRate(smooth, applied, last, input, drop, DefaultTargetSPS, now)
		smooth = s
		if write {
			applied, last = candidate, now
			writes = append(writes, i)
		}
		if applied < 1 || applied > 1000 {
			t.Fatalf("tick %d: rate %d outside [1,1000]", i, applied)
		}
		trace = append(trace, applied)
	}
	return trace, writes
}

func TestDao14jia1_G2(t *testing.T) {
	tests := []struct {
		name                            string
		pps                             uint64
		n, quiet                        int
		smooth                          float64
		applied, activeEnd, final, peak uint32
		drops                           bool
		prefix                          []uint32
		writes                          []int
	}{
		{name: "B12Ramp", pps: 383000, n: 60, smooth: 1, applied: 1, activeEnd: 4, final: 4, prefix: []uint32{2, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4}},
		{name: "Rate1_5M", pps: 1500000, n: 60, smooth: 1, applied: 1, activeEnd: 14, final: 14},
		{name: "B6RampAndBack", pps: 1067000, n: 60, quiet: 15, smooth: 1, applied: 1, activeEnd: 10, final: 1},
		{name: "BelowTwoStaysOne", pps: 150000, n: 60, smooth: 1, applied: 1, activeEnd: 1, final: 1, writes: []int{}},
		{name: "Raw2_5", pps: 250000, n: 60, quiet: 15, smooth: 1, applied: 1, activeEnd: 2, final: 1},
		{name: "BackpressureExact", pps: 40000, n: 10, smooth: 1, applied: 1, activeEnd: 5, final: 5, drops: true, prefix: []uint32{1, 1, 1, 2, 2, 2, 3, 3, 3, 5}, writes: []int{4, 7, 10}},
		{name: "BackpressureLong", pps: 40000, n: 20, quiet: 30, smooth: 1, applied: 1, final: 1, drops: true},
		{name: "HoldSpacing", pps: 383000, n: 7, smooth: 1, applied: 1, final: 4, writes: []int{1, 4, 7}},
		{name: "BandHolds", pps: 10500000, n: 60, smooth: 100, applied: 100, activeEnd: 100, final: 100, peak: 100, writes: []int{}},
		{name: "BandMoves", pps: 11500000, n: 60, smooth: 100, applied: 100, activeEnd: 111, final: 111, writes: []int{4}},
		{name: "UpperClampBackpressure", pps: 40000, n: 1000, quiet: 200, smooth: 1, applied: 1, peak: 913, final: 1, drops: true},
		{name: "UpperClampMaxInput", pps: math.MaxUint64, n: 1000, quiet: 200, smooth: 1, applied: 1, peak: 918, final: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace, writes := dao14Trace(t, tt.smooth, tt.applied, tt.pps, tt.n, tt.quiet, tt.drops)
			if trace[len(trace)-1] != tt.final {
				t.Errorf("final=%d want=%d trace=%v", trace[len(trace)-1], tt.final, trace)
			}
			if tt.activeEnd != 0 && trace[tt.n-1] != tt.activeEnd {
				t.Errorf("active end=%d want=%d", trace[tt.n-1], tt.activeEnd)
			}
			if tt.prefix != nil && !reflect.DeepEqual(trace[:len(tt.prefix)], tt.prefix) {
				t.Errorf("trace=%v want prefix=%v", trace, tt.prefix)
			}
			if tt.writes != nil && !reflect.DeepEqual(writes, tt.writes) {
				t.Errorf("writes=%v want=%v", writes, tt.writes)
			}
			for i := 1; i < len(writes); i++ {
				if writes[i]-writes[i-1] < 3 {
					t.Errorf("hold violated: writes=%v", writes)
				}
			}
			var peak uint32
			for _, rate := range trace {
				peak = max(peak, rate)
			}
			if tt.peak != 0 && peak != tt.peak {
				t.Errorf("peak=%d want=%d", peak, tt.peak)
			}
		})
	}
	for _, tt := range []struct {
		name       string
		pps        [2]uint64
		smoothed   [2]float64
		candidates [2]uint32
		writes     [2]bool
	}{
		{"AppliedBandRising", [2]uint64{13000000, 11300000}, [2]float64{109, 110.2}, [2]uint32{109, 110}, [2]bool{false, true}},
		{"AppliedBandFalling", [2]uint64{7000000, 8900000}, [2]float64{91, 90.4}, [2]uint32{91, 90}, [2]bool{false, false}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Absolute tolerance 1e-9 covers floating-point rounding only.
			const tolerance = 1e-9
			start := time.Unix(2000, 0)
			lastChange := start.Add(-10 * time.Second)
			smoothed := 100.0
			for tick, pps := range tt.pps {
				// The first tick must not write, so applied stays at 100.
				s, candidate, write := nextSampleRate(smoothed, 100, lastChange, pps, 0, 100000, start.Add(time.Duration(tick)*time.Second))
				if math.Abs(s-tt.smoothed[tick]) > tolerance || candidate != tt.candidates[tick] || write != tt.writes[tick] {
					t.Fatalf("tick %d: smoothed=%.12g candidate=%d write=%t; want %.12g,%d,%t (absolute tolerance=1e-9)", tick+1, s, candidate, write, tt.smoothed[tick], tt.candidates[tick], tt.writes[tick])
				}
				smoothed = s
			}
		})
	}
}

func TestDao14jia1_G3a(t *testing.T) {
	t.Run("DecayFrom7", func(t *testing.T) {
		got, _ := dao14Trace(t, 6.55, 7, 0, 15, 0, false)
		want := []uint32{5, 5, 5, 2, 2, 2, 1}
		if !reflect.DeepEqual(got[:7], want) || got[14] != 1 {
			t.Fatalf("trace=%v want prefix=%v and final=1", got, want)
		}
	})
}

func dao14Leaves(v reflect.Value, visit func(reflect.Value)) {
	switch v.Kind() {
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			name := v.Type().Field(i).Name
			if name != "Pad" && name != "_" {
				dao14Leaves(v.Field(i), visit)
			}
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			dao14Leaves(v.Index(i), visit)
		}
	case reflect.Uint32, reflect.Uint64:
		visit(v)
	default:
		panic("unexpected counter leaf type")
	}
}

func TestDao14jia1_G4a(t *testing.T) {
	t.Run("TickSpan", func(t *testing.T) {
		base := time.Unix(1000, 0)
		for _, tt := range []struct {
			name string
			prev time.Time
			span time.Duration
			want uint64
		}{
			{"Zero", time.Time{}, 0, 1}, {"Span0_3", base, 300 * time.Millisecond, 1}, {"Span1_3", base, 1300 * time.Millisecond, 1},
			{"Span1_49", base, 1490 * time.Millisecond, 1}, {"Span1_5", base, 1500 * time.Millisecond, 2}, {"Span2", base, 2 * time.Second, 2},
			{"Span2_6", base, 2600 * time.Millisecond, 3}, {"Span60_2", base, 60200 * time.Millisecond, 60},
		} {
			t.Run(tt.name, func(t *testing.T) {
				if got := tickSpan(tt.prev, base.Add(tt.span)); got != tt.want {
					t.Fatalf("span=%d want=%d", got, tt.want)
				}
			})
		}
	})
	for _, k := range []uint64{3, 1} {
		name := "ScaleEveryField"
		if k == 1 {
			name = "K1Unchanged"
		}
		t.Run(name, func(t *testing.T) {
			var g GlobalDelta
			ips := []IPDelta{{Key: bpf.LPMKey{Prefixlen: 32, Addr: [16]byte{192, 0, 2, 1}}}}
			ps := []PrefixDelta{{Key: bpf.PrefixKeyGo{Prefixlen: 24, Addr: [16]byte{192, 0, 2}}, ActiveIPs: 91, Stats: bpf.PrefixStats{Pad: 97}}}
			if reflect.TypeOf(g).NumField() != 11 {
				t.Fatal("GlobalDelta must have eleven top-level fields")
			}
			values := []reflect.Value{reflect.ValueOf(&g).Elem(), reflect.ValueOf(&ips[0].Stats).Elem(), reflect.ValueOf(&ps[0].Stats).Elem()}
			n := uint64(101)
			for i, v := range values {
				count := 0
				dao14Leaves(v, func(x reflect.Value) { x.SetUint(n); n++; count++ })
				if count != []int{71, 37, 35}[i] {
					t.Fatalf("counter leaves=%d", count)
				}
			}
			wantG, wantI, wantP := g, ips[0], ps[0]
			for _, v := range []reflect.Value{reflect.ValueOf(&wantG).Elem(), reflect.ValueOf(&wantI.Stats).Elem(), reflect.ValueOf(&wantP.Stats).Elem()} {
				dao14Leaves(v, func(x reflect.Value) { x.SetUint(x.Uint() / k) })
			}
			scaleGlobalDelta(&g, k)
			scaleIPDeltas(ips, k)
			scalePrefixDeltas(ps, k)
			if g != wantG {
				t.Errorf("global=%+v want=%+v", g, wantG)
			}
			if ips[0] != wantI {
				t.Errorf("IP=%+v want=%+v", ips[0], wantI)
			}
			if ps[0] != wantP {
				t.Errorf("prefix=%+v want=%+v", ps[0], wantP)
			}
		})
	}
}
