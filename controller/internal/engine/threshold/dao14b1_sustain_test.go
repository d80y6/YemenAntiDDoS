package threshold

import (
	"net"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
)

func TestDao14b1V04_T1(t *testing.T) {
	base := time.Unix(1000, 0)
	pt := func(off int, pps int64) ring.DataPoint {
		return ring.DataPoint{Time: base.Add(time.Duration(off) * time.Second), PPS: pps}
	}
	over := func(p ring.DataPoint) bool { return p.PPS > 300 }
	for _, tc := range []struct {
		name string
		pts  []ring.DataPoint
		want int
	}{
		{"empty", nil, 0},
		{"single", []ring.DataPoint{pt(0, 600)}, 1},
		{"three", []ring.DataPoint{pt(0, 600), pt(-1, 600), pt(-2, 600)}, 3},
		{"oneGap", []ring.DataPoint{pt(0, 600), pt(-2, 600), pt(-3, 600)}, 3},
		{"twoGap", []ring.DataPoint{pt(0, 600), pt(-3, 600)}, 1},
		{"dup", []ring.DataPoint{pt(0, 600), pt(0, 600), pt(-1, 600)}, 2},
		{"backwards", []ring.DataPoint{pt(0, 600), pt(1, 600)}, 1},
		{"firstLow", []ring.DataPoint{pt(0, 100), pt(-1, 600)}, 0},
		{"midLow", []ring.DataPoint{pt(0, 600), pt(-1, 100), pt(-2, 600)}, 1},
		{"duplicateLow", []ring.DataPoint{pt(0, 900), pt(0, 100), pt(-1, 900)}, 1},
	} {
		t.Run("SustainedRun/"+tc.name, func(t *testing.T) {
			if got := SustainedRun(tc.pts, over); got != tc.want {
				t.Errorf("got %d want %d", got, tc.want)
			}
		})
	}
	t.Run("RollbackAllHigh", func(t *testing.T) {
		for _, branch := range []string{"IPRecv", "IPSend", "PrefixRecv", "PrefixSend"} {
			t.Run(branch, func(t *testing.T) {
				rs := ring.New(ring.Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 100, MaxGlobalKeys: 100})
				const prefix = "192.0.2.0/24"
				ip := net.ParseIP("192.0.2.1")
				var push func(ring.DataPoint)
				var read func() []ring.DataPoint
				switch branch {
				case "IPRecv":
					push = func(p ring.DataPoint) { rs.PushIP("n1", prefix, ip, p) }
					read = func() []ring.DataPoint { return rs.LatestNIPByKey("n1", prefix, ip.String(), 10) }
				case "IPSend":
					push = func(p ring.DataPoint) { rs.PushSrcIP("n1", prefix, ip, p) }
					read = func() []ring.DataPoint { return rs.LatestNSrcIPByKey("n1", prefix, ip.String(), 10) }
				case "PrefixRecv":
					push = func(p ring.DataPoint) { rs.PushPrefix("n1", prefix, p) }
					read = func() []ring.DataPoint { return rs.LatestNPrefix("n1", prefix, 10) }
				case "PrefixSend":
					push = func(p ring.DataPoint) { rs.PushSrcPrefix("n1", prefix, p) }
					read = func() []ring.DataPoint { return rs.LatestNSrcPrefix("n1", prefix, 10) }
				}
				push(pt(0, 900))
				push(pt(1, 900))
				push(pt(0, 900))
				pts := read()
				if got := SustainedRun(pts, over); len(pts) != 3 || got != 1 {
					t.Errorf("all-high arrival t,t+1,t: slots=%d sustained=%d want 3/1", len(pts), got)
				}
			})
		}
	})
	t.Run("ClampAtLeastOne", func(t *testing.T) {
		r := engine.ResolvedThreshold{Decoder: "ip", Unit: "pps", Comparison: "over", Value: 300}
		if sustained(r, []ring.DataPoint{pt(0, 100), pt(-1, 600)}) != 1 || sustained(r, nil) != 1 {
			t.Error("ClampAtLeastOne")
		}
	})
	t.Run("StaleAfterEqualsFreshness", func(t *testing.T) {
		if ring.StaleAfter != ringFreshnessWindow {
			t.Error("StaleAfterEqualsFreshness")
		}
	})
	t.Run("Window", func(t *testing.T) {
		d := &Detector{}
		d.SetSustainWindow(0)
		if d.window() != 10 {
			t.Error("Window default")
		}
		d.SetSustainWindow(24)
		if d.window() != 24 {
			t.Error("Window setter")
		}
	})
	t.Run("SustainWindow", func(t *testing.T) {
		for _, tc := range []struct{ h, dy, c, want int }{{3, 5, 120, 10}, {12, 5, 10, 10}, {0, 0, 120, 2}, {-5, -5, 120, 2}, {600, 1, 600, 600}, {1 << 62, 1, 120, 120}} {
			if got := SustainWindow(tc.h, tc.dy, tc.c); got != tc.want {
				t.Errorf("SustainWindow(%d,%d,%d)=%d want %d", tc.h, tc.dy, tc.c, got, tc.want)
			}
		}
	})
}
