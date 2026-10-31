package ring

import (
	"net"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type g4K struct {
	pfx, ip string
	age     time.Duration
	pps     int64
	prot    bool
}

func g4Present(t *testing.T, lim Limits, keys []g4K, nc g4K) string {
	var out []string
	synctest.Test(t, func(t *testing.T) {
		rs := New(lim)
		now := time.Now()
		for _, k := range keys {
			rs.PushIP("n1", k.pfx, net.ParseIP(k.ip), DataPoint{Time: now.Add(-k.age), PPS: k.pps})
			if k.prot {
				rs.MarkActive("n1", k.pfx, net.ParseIP(k.ip))
			}
		}
		rs.PushIP("n1", nc.pfx, net.ParseIP(nc.ip), DataPoint{Time: now, PPS: nc.pps})
		for _, k := range append(keys, nc) {
			if rs.GetIPRing("n1", k.pfx, net.ParseIP(k.ip)) != nil {
				out = append(out, k.ip[strings.LastIndex(k.ip, ".")+1:])
			}
		}
		if _, count, _ := rs.Stats(); count != len(out) {
			t.Errorf("Stats IP count=%d want %d", count, len(out))
		}
	})
	return strings.Join(out, " ")
}

func TestDao14b1V04_R2(t *testing.T) {
	t.Run("LatestPPS", func(t *testing.T) {
		for _, direction := range []string{"Receives", "Sends"} {
			t.Run(direction, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					rs := New(Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 100, MaxGlobalKeys: 2})
					push, get := rs.PushIP, rs.GetIPRingByKey
					if direction == "Sends" {
						push, get = rs.PushSrcIP, rs.GetSrcIPRingByKey
					}
					now := time.Now()
					const prefix = "192.0.2.0/24"
					push("n1", prefix, net.ParseIP("192.0.2.10"), DataPoint{Time: now.Add(-3 * time.Second), PPS: 10})
					push("n1", prefix, net.ParseIP("192.0.2.10"), DataPoint{Time: now.Add(-2 * time.Second), PPS: 1000})
					push("n1", prefix, net.ParseIP("192.0.2.11"), DataPoint{Time: now.Add(-time.Second), PPS: 500})
					push("n1", prefix, net.ParseIP("192.0.2.12"), DataPoint{Time: now, PPS: 600})
					a, b, c := get("n1", prefix, "192.0.2.10") != nil, get("n1", prefix, "192.0.2.11") != nil, get("n1", prefix, "192.0.2.12") != nil
					if !a || b || !c {
						t.Errorf("A 10->1000, B 500, C 600: present A/B/C=%t/%t/%t want true/false/true (evict B)", a, b, c)
					}
					if _, keys, protected := rs.Stats(); keys != 2 || protected != 0 {
						t.Errorf("keys/protected=%d/%d want 2/0", keys, protected)
					}
				})
			})
		}
	})
	P, Q := "192.0.2.0/24", "198.51.100.0/24"
	g4 := Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 100, MaxGlobalKeys: 4}
	four := func(pps ...int64) []g4K {
		return []g4K{{P, "192.0.2.10", 4 * time.Second, pps[0], false}, {P, "192.0.2.11", 3 * time.Second, pps[1], false}, {P, "192.0.2.12", 2 * time.Second, pps[2], false}, {P, "192.0.2.13", time.Second, pps[3], false}}
	}
	for _, tc := range []struct {
		name string
		lim  Limits
		keys []g4K
		nc   g4K
		want string
	}{
		{"RefuseLighter", g4, four(100, 100, 100, 100), g4K{P, "192.0.2.99", 0, 50, false}, "10 11 12 13"},
		{"TieRefused", g4, four(100, 100, 100, 100), g4K{P, "192.0.2.99", 0, 100, false}, "10 11 12 13"},
		{"HeavierDisplacesLightest", g4, four(500, 10, 300, 301), g4K{P, "192.0.2.99", 0, 200, false}, "10 12 13 99"},
		{"StaleBoundary", g4, []g4K{{P, "192.0.2.10", 5 * time.Second, 1000, false}, {P, "192.0.2.11", 3 * time.Second, 1000, false}, {P, "192.0.2.12", 2 * time.Second, 1000, false}, {P, "192.0.2.13", time.Second, 1000, false}}, g4K{P, "192.0.2.99", 0, 10, false}, "10 11 12 13"},
		{"PrefixScopeRefuse", Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 3, MaxGlobalKeys: 100}, []g4K{{P, "192.0.2.10", 3 * time.Second, 1000, false}, {P, "192.0.2.11", 2 * time.Second, 1000, false}, {P, "192.0.2.12", time.Second, 1000, false}}, g4K{P, "192.0.2.99", 0, 10, false}, "10 11 12"},
		{"PrefixFirstNoWaste", Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 2, MaxGlobalKeys: 4}, []g4K{{Q, "198.51.100.20", 4 * time.Second, 1, false}, {Q, "198.51.100.21", 3 * time.Second, 1, false}, {P, "192.0.2.10", 2 * time.Second, 1000, false}, {P, "192.0.2.11", time.Second, 1000, false}}, g4K{P, "192.0.2.99", 0, 50, false}, "20 21 10 11"},
		{"StaleFirst", g4, []g4K{{P, "192.0.2.10", 7 * time.Second, 1000, false}, {P, "192.0.2.11", 6 * time.Second, 1000, false}, {P, "192.0.2.12", 2 * time.Second, 10, false}, {P, "192.0.2.13", time.Second, 1000, false}}, g4K{P, "192.0.2.99", 0, 50, false}, "11 12 13 99"},
		{"AllProtectedGlobalFallback", g4, []g4K{{P, "192.0.2.10", 4 * time.Second, 1, true}, {P, "192.0.2.11", 3 * time.Second, 1, true}, {P, "192.0.2.12", 2 * time.Second, 1, true}, {P, "192.0.2.13", time.Second, 1, true}}, g4K{P, "192.0.2.99", 0, 50, false}, "11 12 13 99"},
		{"AllProtectedPrefixSoftOverflow", Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 2, MaxGlobalKeys: 100}, []g4K{{P, "192.0.2.10", 2 * time.Second, 1, true}, {P, "192.0.2.11", time.Second, 1, true}}, g4K{P, "192.0.2.99", 0, 50, false}, "10 11 99"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := g4Present(t, tc.lim, tc.keys, tc.nc); got != tc.want {
				t.Errorf("present=[%s] want [%s]", got, tc.want)
			}
		})
	}
}

func TestDao14b1V04_R4(t *testing.T) {
	t.Run("LatestSlotOnly", func(t *testing.T) {
		for _, branch := range []string{"IPRecv", "IPSend", "PrefixRecv", "PrefixSend"} {
			t.Run(branch, func(t *testing.T) {
				rs := New(Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 100, MaxGlobalKeys: 100})
				const prefix = "192.0.2.0/24"
				ip := net.ParseIP("192.0.2.1")
				var push func(DataPoint)
				var read func() (int, []DataPoint)
				switch branch {
				case "IPRecv":
					push = func(p DataPoint) { rs.PushIP("n1", prefix, ip, p) }
					read = func() (int, []DataPoint) { r := rs.GetIPRing("n1", prefix, ip); return r.Count(), r.Latest(10) }
				case "IPSend":
					push = func(p DataPoint) { rs.PushSrcIP("n1", prefix, ip, p) }
					read = func() (int, []DataPoint) {
						r := rs.GetSrcIPRingByKey("n1", prefix, ip.String())
						return r.Count(), r.Latest(10)
					}
				case "PrefixRecv":
					push = func(p DataPoint) { rs.PushPrefix("n1", prefix, p) }
					read = func() (int, []DataPoint) { r := rs.GetPrefixRing("n1", prefix); return r.Count(), r.Latest(10) }
				case "PrefixSend":
					push = func(p DataPoint) { rs.PushSrcPrefix("n1", prefix, p) }
					read = func() (int, []DataPoint) { r := rs.GetSrcPrefixRing("n1", prefix); return r.Count(), r.Latest(10) }
				}
				ts := time.Unix(1000, 0)
				push(DataPoint{Time: ts, PPS: 10})
				push(DataPoint{Time: ts.Add(time.Second), PPS: 20})
				push(DataPoint{Time: ts, PPS: 30})
				count, pts := read()
				var got []int64
				for _, p := range pts {
					got = append(got, p.PPS)
				}
				if count != 3 || !slices.Equal(got, []int64{30, 20, 10}) {
					t.Errorf("arrival t:10,t+1:20,t:30: slots=%d newest-first=%v want 3/[30 20 10]", count, got)
				}
			})
		}
	})
	t.Run("SameTimestampOverwrite", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rs := New(Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 100, MaxGlobalKeys: 100})
			ts := time.Unix(time.Now().Unix(), 0)
			ip := net.ParseIP("192.0.2.1")
			rs.PushIP("n1", "192.0.2.0/24", ip, DataPoint{Time: ts, PPS: 100})
			rs.PushIP("n1", "192.0.2.0/24", ip, DataPoint{Time: ts, PPS: 200})
			rs.PushPrefix("n1", "192.0.2.0/24", DataPoint{Time: ts, PPS: 1})
			rs.PushPrefix("n1", "192.0.2.0/24", DataPoint{Time: ts, PPS: 2})
			ir, pr := rs.GetIPRing("n1", "192.0.2.0/24", ip), rs.GetPrefixRing("n1", "192.0.2.0/24")
			dp, _ := ir.LatestOne(0)
			pp, _ := pr.LatestOne(0)
			if ir.Count() != 1 || dp.PPS != 200 || pr.Count() != 1 || pp.PPS != 2 {
				t.Errorf("SameTimestampOverwrite ip count=%d latest=%d prefix count=%d latest=%d; want 1/200 1/2", ir.Count(), dp.PPS, pr.Count(), pp.PPS)
			}
		})
	})
}
