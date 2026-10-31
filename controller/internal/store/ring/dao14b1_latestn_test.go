package ring

import (
	"net"
	"testing"
	"time"
)

func TestDao14b1V04_R3(t *testing.T) {
	for _, name := range []string{"LatestNPrefix", "LatestNSrcPrefix", "LatestNIPByKey", "LatestNSrcIPByKey"} {
		t.Run("LatestN/"+name, func(t *testing.T) {
			rs := New(Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 100, MaxGlobalKeys: 1000})
			ip := net.ParseIP("192.0.2.10")
			prefix := "192.0.2.0/24"
			base := time.Unix(1000, 0)
			push := func(dp DataPoint) {
				switch name {
				case "LatestNPrefix":
					rs.PushPrefix("n1", prefix, dp)
				case "LatestNSrcPrefix":
					rs.PushSrcPrefix("n1", prefix, dp)
				case "LatestNIPByKey":
					rs.PushIP("n1", prefix, ip, dp)
				case "LatestNSrcIPByKey":
					rs.PushSrcIP("n1", prefix, ip, dp)
				}
			}
			read := func(node string, n int) []DataPoint {
				switch name {
				case "LatestNPrefix":
					return rs.LatestNPrefix(node, prefix, n)
				case "LatestNSrcPrefix":
					return rs.LatestNSrcPrefix(node, prefix, n)
				case "LatestNIPByKey":
					return rs.LatestNIPByKey(node, prefix, ip.String(), n)
				default:
					return rs.LatestNSrcIPByKey(node, prefix, ip.String(), n)
				}
			}
			if got := read("n1", 3); got != nil {
				t.Fatalf("absent ring returned %v", got)
			}
			for i := 0; i < 5; i++ {
				push(DataPoint{Time: base.Add(time.Duration(i) * time.Second), PPS: int64(i)})
			}
			for _, n := range []int{3, 9, 0, -1} {
				points := read("n1", n)
				if n < 1 {
					if points != nil {
						t.Errorf("n=%d returned %v, want nil", n, points)
					}
					continue
				}
				want := min(n, 5)
				if len(points) != want {
					t.Fatalf("n=%d returned %d points, want %d", n, len(points), want)
				}
				for i, point := range points {
					if point.PPS != int64(4-i) || !point.Time.Equal(base.Add(time.Duration(4-i)*time.Second)) {
						t.Errorf("n=%d point %d=%v, want newest-first arrival order", n, i, point)
					}
				}
				points[0].PPS = -99
				if got := read("n1", 1); len(got) != 1 || got[0].PPS != 4 {
					t.Errorf("mutating returned history changed the ring: %v", got)
				}
			}
			if got := read("missing", 3); got != nil {
				t.Errorf("missing key returned %v", got)
			}
		})
	}
}
