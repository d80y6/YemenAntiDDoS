package tracker

// New-symbol cells, including explicit Sustained events that cannot compile on HEAD.

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/threshold"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
)

func TestDao14b1V04_D2Sends(t *testing.T) {
	for _, tc := range []struct {
		name     string
		pressure bool
	}{{"ConfirmingMarked", false}, {"LightTargetProtected", true}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				rs := ring.New(ring.Limits{MaxPointsPerIP: 10, MaxIPsPerPrefix: 100, MaxGlobalKeys: 2})
				tk := New(g4Cfg, &dao6Store{}, rs, dedup.New(), nil)
				const prefix = "192.0.2.0/24"
				target := net.ParseIP("192.0.2.150")
				rs.PushSrcIP("n1", prefix, target, ring.DataPoint{Time: time.Now(), PPS: 5})
				tk.Feed([]engine.ThresholdExceeded{{DstIP: target, Prefix: prefix, Direction: "sends", Decoder: "udp", Unit: "pps", Actual: 5, NodeID: "n1", Sustained: 1}})
				key := attackKey{DstIP: "192.0.2.150", Direction: "sends", DecoderFamily: "udp"}
				a := tk.attacks[key]
				if a == nil {
					t.Fatal("first sends event did not create a confirming attack")
				}
				if _, _, protected := rs.Stats(); protected != 1 {
					t.Errorf("first sends tick protected=%d want 1", protected)
				}
				if a.State != StateConfirming || a.ConsecutiveExceeded != 1 || a.DBID != 0 {
					t.Errorf("first sends tick state/count/DBID=%s/%d/%d want confirming/1/0", a.State, a.ConsecutiveExceeded, a.DBID)
				}
				if tc.pressure {
					rs.PushSrcIP("n1", prefix, net.ParseIP("192.0.2.151"), ring.DataPoint{Time: time.Now(), PPS: 10})
					rs.PushSrcIP("n1", prefix, net.ParseIP("192.0.2.152"), ring.DataPoint{Time: time.Now(), PPS: 20})
					if rs.GetSrcIPRingByKey("n1", prefix, "192.0.2.150") == nil {
						t.Error("5 PPS sends target was evicted before activation by 10/20 PPS newcomers")
					}
					if _, keys, protected := rs.Stats(); keys != 2 || protected != 1 {
						t.Errorf("after pressure keys/protected=%d/%d want 2/1", keys, protected)
					}
					if a := tk.attacks[key]; a == nil || a.State != StateConfirming || a.DBID != 0 {
						t.Errorf("after pressure attack=%+v want confirming with DBID 0", a)
					}
				}
				tk.Feed(nil)
				if _, exists := tk.attacks[key]; exists {
					t.Error("unseen sends attack was not discarded")
				}
				if _, _, protected := rs.Stats(); protected != 0 {
					t.Errorf("discarded sends attack protected=%d want 0", protected)
				}
			})
		})
	}
}

func TestDao14b1V04_Window(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cap, n, total int
		at            int
	}{{"LongConfirm", 120, 12, 14, 11}, {"SmallRingBigN", 10, 10, 12, 9}} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := g4Cfg
				cfg.HardConfirmSeconds = tc.n
				r := g4New(t, g4Over300, ring.Limits{MaxPointsPerIP: tc.cap, MaxIPsPerPrefix: 10000, MaxGlobalKeys: 100000}, cfg)
				r.det.SetSustainWindow(threshold.SustainWindow(tc.n, 5, tc.cap))
				for i := 0; i < tc.total; i++ {
					r.step(func() { r.ip("n1", "192.0.2.90", 600, 0) })
				}
				g4Want(t, r, 1, tc.at)
			})
		})
	}
}
