package tracker

// Dao14b1 v0.4 loop gates use baseline APIs and assert the planned behavior.

import (
	"context"
	"fmt"
	"net"
	"sort"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/threshold"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

type g4Tree struct {
	store.Store
	p []store.WatchPrefix
	r []store.Threshold
}
type g4P struct {
	store.PrefixRepo
	rows []store.WatchPrefix
}
type g4R struct {
	store.ThresholdRepo
	rows []store.Threshold
}

func (s g4Tree) Prefixes() store.PrefixRepo                     { return g4P{rows: s.p} }
func (s g4Tree) Thresholds() store.ThresholdRepo                { return g4R{rows: s.r} }
func (r g4P) List(context.Context) ([]store.WatchPrefix, error) { return r.rows, nil }
func (r g4R) List(context.Context) ([]store.Threshold, error)   { return r.rows, nil }
func g4Int(n int) *int                                          { return &n }

func g4Rule(domain, dir, unit, cmp string, v int64) store.Threshold {
	return store.Threshold{ID: 0, PrefixID: g4Int(1), Domain: domain, Direction: dir, Decoder: "udp", Unit: unit, Comparison: cmp, Value: v, Inheritable: true, Enabled: true}
}

var g4Over300 = []store.Threshold{g4Rule("internal_ip", "receives", "pps", "over", 300)}

type g4Rig struct {
	rings     *ring.RingStore
	det       *threshold.Detector
	d         *dedup.Dedup
	tk        *Tracker
	events    []AttackEvent
	base      time.Time
	n         int
	order     func([]engine.ThresholdExceeded)
	confirmAt int
	rebreach  int
}

func g4New(t *testing.T, rules []store.Threshold, lim ring.Limits, cfg Config) *g4Rig {
	tree := threshold.NewTree()
	if err := tree.Rebuild(context.Background(), g4Tree{p: []store.WatchPrefix{{ID: 1, Prefix: "192.0.2.0/24", Enabled: true}}, r: rules}); err != nil {
		t.Fatal(err)
	}
	r := &g4Rig{rings: ring.New(lim), d: dedup.New(), confirmAt: -1}
	r.det = threshold.NewDetector(tree, r.rings)
	r.tk = New(cfg, &dao6Store{}, r.rings, r.d, func(e AttackEvent) { r.events = append(r.events, e) })
	r.tk.SetRebreachCallback(func(int) { r.rebreach++ })
	return r
}

var g4Lim = ring.Limits{MaxPointsPerIP: 120, MaxIPsPerPrefix: 10000, MaxGlobalKeys: 100000}
var g4Cfg = Config{HardConfirmSeconds: 3, DynamicConfirmSeconds: 5, ExpiryIntervalSeconds: 20, MaxActiveAttacks: 100}

func g4DP(pps, bps int64, skew time.Duration) ring.DataPoint {
	dp := ring.DataPoint{Time: time.Unix(time.Now().Add(skew).Unix(), 0), PPS: pps, BPS: bps}
	dp.DecoderPPS[decoder.UDP] = int32(pps)
	dp.DecoderBPS[decoder.UDP] = bps
	return dp
}
func (r *g4Rig) ip(node, ip string, pps int64, skew time.Duration) {
	r.rings.PushIP(node, "192.0.2.0/24", net.ParseIP(ip), g4DP(pps, 0, skew))
}

func (r *g4Rig) count(kind string) int {
	n := 0
	for _, e := range r.events {
		if e.Type == kind {
			n++
		}
	}
	return n
}

// one simulated second: pushes at +0.8 s, detection tick at +1.05 s
func (r *g4Rig) step(pushes func()) {
	if r.base.IsZero() {
		r.base = time.Now()
	}
	k := time.Duration(r.n) * time.Second
	time.Sleep(time.Until(r.base.Add(k + 800*time.Millisecond)))
	if pushes != nil {
		pushes()
	}
	time.Sleep(time.Until(r.base.Add(k + 1050*time.Millisecond)))
	evs := r.det.Tick([]string{"n1", "fake"})
	if r.order != nil {
		r.order(evs)
	}
	var f []engine.ThresholdExceeded
	for _, e := range evs {
		if !r.d.ShouldSuppress(e) {
			f = append(f, e)
		}
	}
	before := r.count("confirmed")
	r.tk.Feed(f)
	if r.confirmAt < 0 && r.count("confirmed") > before {
		r.confirmAt = r.n
	}
	r.n++
}

func (r *g4Rig) state(ip string) string {
	for _, a := range r.tk.attacks {
		if a.Key.DstIP == ip {
			return a.State
		}
	}
	return ""
}

// seq: each element = pushes for that second on n1/192.0.2.90 (0 = no push)
func g4Seq(t *testing.T, rules []store.Threshold, seq [][]int64) *g4Rig {
	r := g4New(t, rules, g4Lim, g4Cfg)
	for _, sec := range seq {
		sec := sec
		r.step(func() {
			for _, p := range sec {
				if p > 0 {
					r.ip("n1", "192.0.2.90", p, 0)
				}
			}
		})
	}
	return r
}

func g4S(vs ...int64) [][]int64 {
	var out [][]int64
	for _, v := range vs {
		out = append(out, []int64{v})
	}
	return out
}
func g4Rep(s [][]int64, n int) [][]int64 {
	var out [][]int64
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return out
}

func g4Want(t *testing.T, r *g4Rig, confirmed, at int) {
	t.Helper()
	if got := r.count("confirmed"); got != confirmed {
		t.Errorf("confirmed=%d want %d", got, confirmed)
	}
	if confirmed > 0 && r.confirmAt != at {
		t.Errorf("confirm tick=%d want %d", r.confirmAt, at)
	}
}

func TestDao14b1V04_D1(t *testing.T) {
	under := []store.Threshold{g4Rule("internal_ip", "receives", "pps", "under", 300)}
	for _, tc := range []struct {
		name      string
		rules     []store.Threshold
		seq       [][]int64
		confirmed int
		at        int
	}{
		{"Spike1Point", g4Over300, g4S(1000, 0, 0, 0, 0, 0, 0, 0), 0, 0},
		{"Spike2Points", g4Over300, g4S(1000, 1000, 0, 0, 0, 0, 0, 0), 0, 0},
		{"CycleLeadLow", g4Over300, g4Rep(g4S(61, 599, 540, 0), 3), 0, 0},
		{"CycleAligned", g4Over300, g4Rep(g4S(600, 600, 0, 0), 3), 0, 0},
		{"DupTimestamp", g4Over300, append([][]int64{{1000, 1000}, {1000}}, g4S(0, 0, 0, 0, 0, 0)...), 0, 0},
		{"OneGapTolerated", g4Over300, g4S(600, 600, 0, 600, 600, 0, 0, 0, 0, 0, 0), 1, 3},
		{"SameSecondHighThenLow", g4Over300, append([][]int64{{1000}, {1000, 100}, {1000}}, g4S(0, 0, 0, 0, 0)...), 0, 0},
		{"UnderSpike", under, g4S(100, 100, 0, 0, 0, 0, 0, 0), 0, 0},
		{"AltGap", g4Over300, g4S(600, 0, 600, 0, 600, 0, 0, 0, 0, 0), 1, 4},
		{"TrailingLow", g4Over300, g4S(1000, 1000, 100, 0, 0, 0, 0, 0), 0, 0},
		{"Cycle600_100", g4Over300, g4Rep(g4S(600, 600, 100), 3), 0, 0},
		{"Sustained3", g4Over300, g4S(600, 600, 600, 0, 0, 0, 0, 0), 1, 2},
		{"DupFlood", g4Over300, g4Rep([][]int64{{1000, 1000, 1000, 1000, 1000, 1000}}, 6), 1, 2},
		{"SameSecondLowThenHigh", g4Over300, append([][]int64{{1000}, {100, 1000}, {1000}}, g4S(0, 0, 0, 0, 0)...), 1, 2},
		{"UnderSustained", under, g4S(100, 100, 100, 100), 1, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { g4Want(t, g4Seq(t, tc.rules, tc.seq), tc.confirmed, tc.at) })
		})
	}
	t.Run("MultiNodeNoSum", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Lim, g4Cfg)
			for s := 0; s < 8; s++ {
				s := s
				r.step(func() {
					if s < 2 {
						r.ip("n1", "192.0.2.90", 1000, 0)
						r.ip("fake", "192.0.2.90", 1000, 0)
					}
				})
			}
			g4Want(t, r, 0, 0)
		})
	})
	t.Run("MultiNodeMax", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Lim, g4Cfg)
			for s := 0; s < 6; s++ {
				s := s
				r.step(func() {
					r.ip("n1", "192.0.2.90", 600, 0)
					if s == 2 {
						r.ip("fake", "192.0.2.90", 600, 0)
					}
				})
			}
			g4Want(t, r, 1, 2)
		})
	})
	t.Run("IngestLag", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Lim, g4Cfg)
			for s := 0; s < 12; s++ {
				s := s
				r.step(func() {
					if s%3 == 2 {
						for back := 2; back >= 0; back-- {
							r.ip("n1", "192.0.2.90", 600, -time.Duration(back)*time.Second)
						}
					}
				})
			}
			if got := r.count("confirmed"); got != 1 {
				t.Errorf("confirmed=%d want 1", got)
			}
		})
	})
	t.Run("ZeroIsUnknown", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tk := New(g4Cfg, &dao6Store{}, nil, dedup.New(), nil)
			at := -1
			for i := 0; i < 3; i++ {
				time.Sleep(time.Second)
				tk.Feed([]engine.ThresholdExceeded{{DstIP: net.ParseIP("192.0.2.90"), Prefix: "192.0.2.0/24", Direction: "receives", Decoder: "udp", Unit: "pps", Actual: 600, NodeID: "n1"}})
				if at < 0 && tk.CreatedTotal.Load() == 1 {
					at = i
				}
			}
			if at != 2 {
				t.Errorf("confirm tick=%d want 2", at)
			}
		})
	})
	// N3(MB15) loop killer: the low point enters the ring between two ticks, followed by a high point.
	t.Run("LateLowBetweenTicks", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Lim, g4Cfg)
			for s := 0; s < 8; s++ {
				s := s
				r.step(func() {
					switch {
					case s == 2:
					case s == 3:
						r.ip("n1", "192.0.2.90", 100, -time.Second)
						r.ip("n1", "192.0.2.90", 600, 0)
					default:
						r.ip("n1", "192.0.2.90", 600, 0)
					}
				})
			}
			g4Want(t, r, 1, 5)
		})
	})
	// R4: control the order of the two rules' events fed into Feed; the short-run event is last.
	two := []store.Threshold{g4Rule("internal_ip", "receives", "pps", "over", 300), g4Rule("internal_ip", "receives", "bps", "over", 8000)}
	for _, tc := range []struct {
		name  string
		first string
		pts   [][2]int64 // (pps, bps) per second
	}{
		{"MultiRuleMax/ppsFirst", "pps", [][2]int64{{600, 0}, {600, 0}, {600, 9000}, {600, 0}, {600, 0}}},
		{"MultiRuleMax/bpsFirst", "bps", [][2]int64{{100, 9000}, {100, 9000}, {600, 9000}, {100, 9000}, {100, 9000}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := g4New(t, two, g4Lim, g4Cfg)
				r.order = func(evs []engine.ThresholdExceeded) {
					sort.SliceStable(evs, func(i, j int) bool { return evs[i].Unit == tc.first && evs[j].Unit != tc.first })
				}
				for _, p := range tc.pts {
					p := p
					r.step(func() { r.rings.PushIP("n1", "192.0.2.0/24", net.ParseIP("192.0.2.90"), g4DP(p[0], p[1], 0)) })
				}
				g4Want(t, r, 1, 2)
			})
		})
	}
	t.Run("RuleAlternation", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, two, g4Lim, g4Cfg)
			for i, p := range [][2]int64{{600, 0}, {100, 9000}, {600, 0}, {100, 9000}, {600, 0}, {100, 9000}, {600, 0}} {
				p := p
				_ = i
				r.step(func() { r.rings.PushIP("n1", "192.0.2.0/24", net.ParseIP("192.0.2.90"), g4DP(p[0], p[1], 0)) })
			}
			g4Want(t, r, 0, 0)
		})
	})
	for _, br := range []struct {
		name string
		rule store.Threshold
		push func(r *g4Rig, pps int64)
	}{
		{"SubnetRecv", g4Rule("subnet", "receives", "pps", "over", 300), func(r *g4Rig, p int64) { r.rings.PushPrefix("n1", "192.0.2.0/24", g4DP(p, 0, 0)) }},
		{"SubnetSend", g4Rule("subnet", "sends", "pps", "over", 300), func(r *g4Rig, p int64) { r.rings.PushSrcPrefix("n1", "192.0.2.0/24", g4DP(p, 0, 0)) }},
		{"IPSend", g4Rule("internal_ip", "sends", "pps", "over", 300), func(r *g4Rig, p int64) {
			r.rings.PushSrcIP("n1", "192.0.2.0/24", net.ParseIP("192.0.2.90"), g4DP(p, 0, 0))
		}},
	} {
		for _, shape := range []struct {
			name string
			pts  []int64
			want int
			at   int
		}{{"Control600x3", []int64{600, 600, 600, 0, 0}, 1, 2}, {"Spike2Points", []int64{1000, 1000, 0, 0, 0, 0, 0, 0}, 0, 0}} {
			t.Run("Branch/"+br.name+"/"+shape.name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r := g4New(t, []store.Threshold{br.rule}, g4Lim, g4Cfg)
					for _, p := range shape.pts {
						p := p
						r.step(func() {
							if p > 0 {
								br.push(r, p)
							}
						})
					}
					g4Want(t, r, shape.want, shape.at)
				})
			})
		}
	}
}

func TestDao14b1V04_E1(t *testing.T) {
	for _, tc := range []struct {
		name          string
		pts           []int64
		expAt, backAt int
	}{
		{"RealPathTrailingLow", []int64{600, 600, 600, 600, 600, 120, 0, 0, 0, 0, 0, 0}, 5, -1},
		{"FakeProbeStop", []int64{600, 600, 600, 600, 600, 0, 0, 0, 0, 0, 0, 0}, 8, -1},
		{"ExpiringRebreachSinglePoint", []int64{600, 600, 600, 600, 600, 0, 0, 0, 0, 0, 0, 600, 0, 0}, 8, 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := g4New(t, g4Over300, g4Lim, g4Cfg)
				expAt, backAt, prev := -1, -1, ""
				confirmedID := 0
				for i, p := range tc.pts {
					p := p
					r.step(func() {
						if p > 0 {
							r.ip("n1", "192.0.2.90", p, 0)
						}
					})
					st := r.state("192.0.2.90")
					for _, a := range r.tk.attacks {
						if a.DBID > 0 {
							if confirmedID != 0 && a.DBID != confirmedID {
								t.Errorf("DBID changed from %d to %d", confirmedID, a.DBID)
							}
							confirmedID = a.DBID
						}
					}
					if st == StateExpiring && expAt < 0 {
						expAt = i
					}
					if prev == StateExpiring && st == StateActive && backAt < 0 {
						backAt = i
					}
					prev = st
				}
				if expAt != tc.expAt || backAt != tc.backAt {
					t.Errorf("expiring@%d back@%d want %d/%d", expAt, backAt, tc.expAt, tc.backAt)
				}
				if tc.backAt >= 0 && (r.rebreach != 1 || confirmedID == 0 || r.count("confirmed") != 1) {
					t.Errorf("onRebreach=%d want 1", r.rebreach)
				}
			})
		})
	}
}

func g4Spray(r *g4Rig, seq *int, pps int64) {
	// Six tablefuls per tick force turnover even in the smaller race-test fixture.
	for i := 0; i < 96; i++ {
		*seq++
		r.rings.PushIP("fake", "2001:db8::/48", net.ParseIP(fmt.Sprintf("2001:db8::%x:%x", *seq>>16, *seq&0xffff)), g4DP(pps, 0, 0))
	}
}

var g4Press = ring.Limits{MaxPointsPerIP: 120, MaxIPsPerPrefix: 50000, MaxGlobalKeys: 16}

func TestDao14b1V04_D2(t *testing.T) {
	// Twelve ticks cover confirmation and repeated stale-key turnover. Targets
	// stay one second behind pressure keys so HEAD target eviction avoids ties.
	for _, tc := range []struct {
		name        string
		targetFirst bool
		pressure    bool
	}{{"SprayTargetFirst", true, true}, {"SprayTargetLast", false, true}, {"NoPressure", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := g4New(t, g4Over300, g4Press, g4Cfg)
				seq := 0
				for s := 0; s < 12; s++ {
					r.step(func() {
						if tc.pressure && !tc.targetFirst {
							g4Spray(r, &seq, 1)
						}
						r.ip("n1", "192.0.2.148", 600, -time.Second)
						if tc.pressure && tc.targetFirst {
							g4Spray(r, &seq, 1)
						}
					})
				}
				if got := r.count("confirmed"); got != 1 {
					t.Errorf("confirmed=%d want 1", got)
				}
			})
		})
	}
	t.Run("LightTargetProtected", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, []store.Threshold{g4Rule("internal_ip", "receives", "pps", "over", 3)}, g4Press, g4Cfg)
			seq := 0
			for s := 0; s < 12; s++ {
				s := s
				r.step(func() {
					r.ip("n1", "192.0.2.150", 5, -time.Second)
					if s >= 1 {
						g4Spray(r, &seq, 10)
					}
				})
			}
			if got := r.count("confirmed"); got != 1 {
				t.Errorf("confirmed=%d want 1", got)
			}
		})
	})
	t.Run("RecoveredHeavyNoFlap", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Press, g4Cfg)
			r.tk.store = &dao13aRecoveryStore{dao6Store: &dao6Store{next: 10}, rows: []store.Attack{
				{ID: 7, DstIP: "192.0.2.147/32", Direction: "receives", DecoderFamily: "udp", Severity: "medium", NodeSources: []string{"n1"}, StartedAt: time.Now().Add(-time.Hour)}}}
			if err := r.tk.RecoverFromDB(context.Background()); err != nil {
				t.Fatal(err)
			}
			seq, expTicks := 0, 0
			for s := 0; s < 12; s++ {
				r.step(func() {
					r.ip("n1", "192.0.2.147", 3000, -time.Second)
					g4Spray(r, &seq, 1)
				})
				for _, a := range r.tk.attacks {
					if a.DBID == 7 && a.State == StateExpiring {
						expTicks++
					}
				}
			}
			if expTicks != 0 {
				t.Errorf("expiring ticks=%d want 0", expTicks)
			}
		})
	})
	activeAfter := func(t *testing.T, r *g4Rig) int { _, _, a := r.rings.Stats(); return a }
	t.Run("ConfirmingMarked", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Lim, g4Cfg)
			r.step(func() { r.ip("n1", "192.0.2.90", 600, 0) })
			if a := activeAfter(t, r); a != 1 || r.state("192.0.2.90") != StateConfirming {
				t.Errorf("protected=%d state=%s want 1/confirming", a, r.state("192.0.2.90"))
			}
		})
	})
	t.Run("ConfirmingSecondNode", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Lim, g4Cfg)
			var got []int
			for s := 0; s < 2; s++ {
				s := s
				r.step(func() {
					r.ip("n1", "192.0.2.90", 600, 0)
					if s == 1 {
						r.ip("fake", "192.0.2.90", 600, 0)
					}
				})
				got = append(got, activeAfter(t, r))
			}
			if fmt.Sprint(got) != "[1 2]" {
				t.Errorf("protected per tick=%v want [1 2]", got)
			}
		})
	})
	t.Run("DiscardReleases", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Lim, g4Cfg)
			var got []int
			for _, p := range []int64{600, 100, 0, 0} {
				p := p
				r.step(func() {
					if p > 0 {
						r.ip("n1", "192.0.2.90", p, 0)
					}
				})
				got = append(got, activeAfter(t, r))
			}
			if got[1] != 0 || got[2] != 0 || got[3] != 0 {
				t.Errorf("protected per tick=%v want 0 from tick 1", got)
			}
		})
	})
	for _, tc := range []struct {
		name                    string
		sibNode, sibPfx, sibDir string
		sibConfirming           bool
		want                    int
	}{
		{"SameSlot", "n1", "192.0.2.0/24", "receives", false, 1},
		{"OtherNode", "n2", "192.0.2.0/24", "receives", false, 1},
		{"OtherPrefix", "n1", "192.0.2.0/25", "receives", false, 1},
		{"OtherDir", "n1", "192.0.2.0/24", "sends", false, 1},
		{"BothConfirming", "n1", "192.0.2.0/24", "receives", true, 1},
	} {
		t.Run("Isolation/"+tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rs := ring.New(ring.Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 100, MaxGlobalKeys: 100})
				confirm := 3
				if tc.sibConfirming {
					confirm = 9
				}
				tk := New(Config{HardConfirmSeconds: confirm, ExpiryIntervalSeconds: 60, MaxActiveAttacks: 10}, &dao6Store{}, rs, dedup.New(), nil)
				sib := engine.ThresholdExceeded{DstIP: net.ParseIP("192.0.2.7"), Prefix: tc.sibPfx, Direction: tc.sibDir, Decoder: "udp", Unit: "pps", Actual: 5000, NodeID: tc.sibNode}
				x := engine.ThresholdExceeded{DstIP: net.ParseIP("192.0.2.7"), Prefix: "192.0.2.0/24", Direction: "receives", Decoder: "ip", Unit: "pps", Actual: 5000, NodeID: "n1"}
				n := 3
				if tc.sibConfirming {
					n = 1
				}
				for i := 0; i < n; i++ {
					time.Sleep(time.Second)
					tk.Feed([]engine.ThresholdExceeded{sib})
				}
				time.Sleep(time.Second)
				tk.Feed([]engine.ThresholdExceeded{sib, x})
				time.Sleep(time.Second)
				tk.Feed([]engine.ThresholdExceeded{sib})
				if _, _, a := rs.Stats(); a != tc.want {
					t.Errorf("protected after discard=%d want %d", a, tc.want)
				}
			})
		})
	}
}
