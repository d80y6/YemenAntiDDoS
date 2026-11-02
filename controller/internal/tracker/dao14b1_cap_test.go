package tracker

import (
	"fmt"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
)

type g4Cap struct {
	tk      *Tracker
	evicted []AttackEvent
}

func g4CapNew(cap int) *g4Cap {
	c := &g4Cap{}
	c.tk = New(Config{HardConfirmSeconds: 3, ExpiryIntervalSeconds: 120, MaxActiveAttacks: cap}, &dao6Store{next: 10}, nil, dedup.New(), func(e AttackEvent) {
		if e.Type == "evicted" {
			c.evicted = append(c.evicted, e)
		}
	})
	return c
}
func g4Ev(ip string, pps int64) engine.ThresholdExceeded {
	return engine.ThresholdExceeded{DstIP: net.ParseIP(ip), Prefix: "203.0.113.0/24", Direction: "receives", Decoder: "ip", Unit: "pps", Actual: pps, NodeID: "n1"}
}
func (c *g4Cap) sec(rows ...engine.ThresholdExceeded) { time.Sleep(time.Second); c.tk.Feed(rows) }
func (c *g4Cap) evictedIPs() string {
	s := ""
	for _, e := range c.evicted {
		s += e.Attack.DstIP + " "
	}
	return s
}
func (c *g4Cap) st(ip string) string {
	for _, a := range c.tk.attacks {
		if a.Key.DstIP == ip {
			return a.State
		}
	}
	return ""
}

func TestDao14b1V04_D3(t *testing.T) {
	t.Run("CapFullOfExpiring", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := g4CapNew(2)
			for i := 0; i < 3; i++ {
				c.sec(g4Ev("203.0.113.25", 20000), g4Ev("203.0.113.26", 15000))
			}
			c.sec()
			c.sec()
			e0, s0 := c.tk.EvictedTotal.Load(), c.tk.SuppressedTotal.Load()
			at := -1
			for i := 0; i < 3; i++ {
				before := c.tk.CreatedTotal.Load()
				c.sec(g4Ev("203.0.113.27", 200000))
				if at < 0 && c.tk.CreatedTotal.Load() > before {
					at = i
				}
			}
			n := 0
			for _, a := range c.tk.attacks {
				if a.State == StateActive || a.State == StateExpiring {
					n++
				}
			}
			if at != 2 || c.tk.EvictedTotal.Load()-e0 != 1 || c.evictedIPs() != "203.0.113.26 " || c.tk.SuppressedTotal.Load()-s0 != 0 || n != 2 || c.st("203.0.113.25") != StateExpiring {
				t.Errorf("at=%d evictedΔ=%d evicted=%q supΔ=%d counted=%d .25=%s", at, c.tk.EvictedTotal.Load()-e0, c.evictedIPs(), c.tk.SuppressedTotal.Load()-s0, n, c.st("203.0.113.25"))
			}
			if len(c.evicted) == 1 {
				ev := c.evicted[0].Attack
				hasReason := false
				for _, r := range ev.ReasonCodes {
					hasReason = hasReason || r == "evicted_by_cap"
				}
				if ev.EndedAt == nil || !hasReason {
					t.Errorf("evicted event EndedAt=%v reasons=%v", ev.EndedAt, ev.ReasonCodes)
				}
			}
		})
	})
	for _, tc := range []struct {
		name, want string
		plan       func(c *g4Cap)
	}{
		{"SameSeverityExpiringFirst", "203.0.113.26 ", func(c *g4Cap) {
			for i := 0; i < 3; i++ {
				c.sec(g4Ev("203.0.113.25", 12000), g4Ev("203.0.113.26", 50000))
			}
			c.sec(g4Ev("203.0.113.25", 12000))
			c.sec(g4Ev("203.0.113.25", 12000))
			for i := 0; i < 4; i++ {
				c.sec(g4Ev("203.0.113.25", 12000), g4Ev("203.0.113.27", 15000))
			}
		}},
		{"HigherSeverityExpiringKept", "203.0.113.26 ", func(c *g4Cap) {
			for i := 0; i < 3; i++ {
				c.sec(g4Ev("203.0.113.25", 200000), g4Ev("203.0.113.26", 5000))
			}
			c.sec(g4Ev("203.0.113.26", 5000))
			c.sec(g4Ev("203.0.113.26", 5000))
			for i := 0; i < 4; i++ {
				c.sec(g4Ev("203.0.113.26", 5000), g4Ev("203.0.113.27", 20000))
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := g4CapNew(2)
				tc.plan(c)
				if tc.name == "SameSeverityExpiringFirst" && c.st("203.0.113.25") != StateActive {
					t.Errorf("A state=%s want active", c.st("203.0.113.25"))
				}
				if c.evictedIPs() != tc.want {
					t.Errorf("evicted=%q want %q", c.evictedIPs(), tc.want)
				}
			})
		})
	}
	t.Run("AllHigherSuppressed", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c := g4CapNew(2)
			for i := 0; i < 3; i++ {
				c.sec(g4Ev("203.0.113.25", 2000000), g4Ev("203.0.113.26", 1500000))
			}
			c.sec()
			c.sec()
			s0 := c.tk.SuppressedTotal.Load()
			for i := 0; i < 4; i++ {
				c.sec(g4Ev("203.0.113.27", 200000))
			}
			if c.evictedIPs() != "" || c.st("203.0.113.27") != StateConfirming || c.tk.SuppressedTotal.Load()-s0 != 2 {
				t.Errorf("evicted=%q C=%s supΔ=%d", c.evictedIPs(), c.st("203.0.113.27"), c.tk.SuppressedTotal.Load()-s0)
			}
			c.sec()
			if c.st("203.0.113.27") != "" {
				t.Errorf("C not discarded after a missed tick: %s", c.st("203.0.113.27"))
			}
		})
	})
	for _, bBeforeC := range []bool{false, true} {
		name := "RebreachSameTickDirect/CBeforeB"
		if bBeforeC {
			name = "RebreachSameTickDirect/BBeforeC"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c := g4CapNew(2)
				mk := func(ip, st string, pps int64, id int) *trackedAttack {
					k := attackKey{ip, "receives", "ip"}
					a := &trackedAttack{Key: k, State: st, DBID: id, PeakPPS: pps, Severity: classifySeverity(pps, 0), SeenThisTick: true, Decoder: "ip"}
					c.tk.attacks[k] = a
					return a
				}
				mk("203.0.113.25", StateActive, 12000, 1)
				b := mk("203.0.113.26", StateExpiring, 50000, 2)
				if bBeforeC {
					b.State = StateActive
				}
				x := mk("203.0.113.27", StateConfirming, 15000, 0)
				c.tk.mu.Lock()
				c.tk.transitionToActive(x, time.Now())
				c.tk.mu.Unlock()
				if c.evictedIPs() != "203.0.113.25 " {
					t.Errorf("evicted=%q want .25", c.evictedIPs())
				}
			})
		})
	}
	t.Run("RebreachSameTickFeed", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			synctest.Test(t, func(t *testing.T) {
				c := g4CapNew(2)
				re := 0
				c.tk.SetRebreachCallback(func(int) { re++ })
				for i := 0; i < 3; i++ {
					c.sec(g4Ev("203.0.113.25", 12000), g4Ev("203.0.113.26", 50000))
				}
				c.sec(g4Ev("203.0.113.25", 12000))
				c.sec(g4Ev("203.0.113.25", 12000), g4Ev("203.0.113.27", 15000))
				c.sec(g4Ev("203.0.113.25", 12000), g4Ev("203.0.113.27", 15000))
				c.sec(g4Ev("203.0.113.25", 12000), g4Ev("203.0.113.26", 50000), g4Ev("203.0.113.27", 15000))
				if c.evictedIPs() != "203.0.113.25 " || c.st("203.0.113.26") != StateActive || re != 1 {
					t.Errorf("run %d evicted=%q B=%s rebreach=%d", i, c.evictedIPs(), c.st("203.0.113.26"), re)
				}
			})
		}
	})
	t.Run("SuppressedRetryNeedsBothGates", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := g4New(t, g4Over300, g4Lim, Config{HardConfirmSeconds: 3, DynamicConfirmSeconds: 5, ExpiryIntervalSeconds: 20, MaxActiveAttacks: 1})
			for i := 0; i < 3; i++ {
				r.step(func() { r.ip("n1", "192.0.2.200", 2000000, 0) })
			}
			s0 := r.tk.SuppressedTotal.Load()
			on := map[int]bool{0: true, 1: true, 2: true, 5: true, 6: true, 7: true}
			var got []int64
			for s := 0; s < 9; s++ {
				s := s
				r.step(func() {
					r.ip("n1", "192.0.2.200", 2000000, 0)
					if on[s] {
						r.ip("n1", "192.0.2.91", 600, 0)
					}
				})
				got = append(got, r.tk.SuppressedTotal.Load()-s0)
			}
			if fmt.Sprint(got) != "[0 0 1 2 3 3 3 4 5]" {
				t.Errorf("suppressed cumulative=%v want [0 0 1 2 3 3 3 4 5]", got)
			}
		})
	})
}
