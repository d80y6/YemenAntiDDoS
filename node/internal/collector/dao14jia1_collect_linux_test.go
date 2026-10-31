//go:build linux

package collector

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/littlewolf9527/xsight/node/internal/bpf"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

func dao14Manager(t *testing.T) *bpf.Manager {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("Dao14jia1 kernel gates require root; skips are forbidden")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	m, err := bpf.Load("", 64)
	if err != nil {
		t.Fatalf("load unpinned BPF: %+v", err)
	}
	t.Cleanup(m.Close)
	if m.PinPath != "" || len(m.Attachments) != 0 {
		t.Fatal("fixture must not pin or attach")
	}
	p, err := bpf.ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.HotSwap([]bpf.PrefixEntry{p}); err != nil {
		t.Fatal(err)
	}
	return m
}
func dao14Collector(t *testing.T) *Collector { t.Helper(); return New(dao14Manager(t), 0) }
func dao14Slot(t *testing.T, m *ebpf.Map) uint64 {
	t.Helper()
	key := uint32(0)
	var value uint64
	if err := m.Lookup(&key, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDao14jia1_G2r(t *testing.T) {
	t.Run("RampTrace", func(t *testing.T) {
		c := dao14Collector(t)
		t0 := time.Now()
		var returns, slots []uint32
		for i := 1; i <= 12; i++ {
			returns = append(returns, c.adjustSampleRate(383000, t0.Add(time.Duration(i)*time.Second)))
			slots = append(slots, uint32(dao14Slot(t, c.mgr.Objs.XsightConfig)))
		}
		want := []uint32{2, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 4}
		if !reflect.DeepEqual(returns, want) || !reflect.DeepEqual(slots, want) {
			t.Fatalf("returns=%v slots=%v want=%v", returns, slots, want)
		}
	})
}
func TestDao14jia1_G3b(t *testing.T) {
	t.Run("NewResetsSlot", func(t *testing.T) {
		m := dao14Manager(t)
		if err := m.SetConfig(0, 7); err != nil {
			t.Fatal(err)
		}
		c := New(m, 0)
		if slot := dao14Slot(t, m.Objs.XsightConfig); slot != 1 {
			t.Errorf("New slot=%d want=1", slot)
		}
		for i := 0; i < 2; i++ {
			r := dao13fCollect(t, c)
			if r.SampleRate != 1 || uint64(r.SampleRate) != dao14Slot(t, m.Objs.XsightConfig) {
				t.Errorf("tick %d report=%d slot=%d", i, r.SampleRate, dao14Slot(t, m.Objs.XsightConfig))
			}
		}
	})
}
func TestDao14jia1_G3c(t *testing.T) {
	t.Run("WriteFailKeepsApplied", func(t *testing.T) {
		c := dao14Collector(t)
		m := c.mgr
		clone, err := m.Objs.XsightConfig.Clone()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Objs.XsightConfig = clone })
		if err := m.Objs.XsightConfig.Close(); err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		r := c.adjustSampleRate(1500000, t0.Add(time.Second))
		slot := dao14Slot(t, clone)
		if r != 1 || uint64(r) != slot {
			t.Errorf("failed write returned=%d slot=%d want=1", r, slot)
		}
		m.Objs.XsightConfig = clone
		r = c.adjustSampleRate(1500000, t0.Add(2*time.Second))
		slot = dao14Slot(t, clone)
		if r != 8 || uint64(r) != slot {
			t.Errorf("recovery returned=%d slot=%d want=8", r, slot)
		}
	})
}
func TestDao14jia1_G3d(t *testing.T) {
	t.Run("SkipTickReportsApplied", func(t *testing.T) {
		c := dao14Collector(t)
		t0 := time.Now()
		for i := 1; i <= 3; i++ {
			c.adjustSampleRate(383000, t0.Add(time.Duration(i)*time.Second))
		}
		c.NotifyHotSwap()
		r := dao13fCollect(t, c)
		slot := dao14Slot(t, c.mgr.Objs.XsightConfig)
		if r.SampleRate != 2 || uint64(r.SampleRate) != slot {
			t.Fatalf("skip report=%d slot=%d want=2", r.SampleRate, slot)
		}
	})
}
func TestDao14jia1_G4b(t *testing.T) {
	for _, tt := range []struct {
		name string
		wait time.Duration
		out  int
		want uint64
	}{
		{"Span2s", 2 * time.Second, 200, 100}, {"Span2_6s", 2600 * time.Millisecond, 0, 66},
		{"Span1_3sExact", 1300 * time.Millisecond, 0, 200}, {"Span0_3sExact", 300 * time.Millisecond, 0, 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := dao14Collector(t)
			baseline := dao13fCollect(t, c)
			dao13fPackets(t, c.mgr, 200, tt.out)
			time.Sleep(tt.wait)
			r := dao13fCollect(t, c)
			t.Logf("actual collection interval=%s; single trial, no retries", r.Timestamp.Sub(baseline.Timestamp))
			check := func(label string, ips []IPDelta, ps []PrefixDelta, global uint64) {
				t.Helper()
				if len(ips) != 1 || len(ps) != 1 {
					t.Fatalf("%s IPs=%v prefixes=%v", label, ips, ps)
				}
				if ips[0].Stats.PktCount != tt.want || uint64(ips[0].Stats.DecoderCounts[decoder.UDP]) != tt.want || ps[0].Stats.PktCount != tt.want || uint64(ps[0].Stats.DecoderCounts[decoder.UDP]) != tt.want || global != tt.want {
					t.Errorf("%s IP=%+v prefix=%+v global=%d want=%d", label, ips[0], ps[0], global, tt.want)
				}
			}
			check("inbound", r.IPDeltas, r.PrefixDeltas, r.Global.MatchedPkts)
			if tt.out > 0 {
				check("outbound", r.SrcIPDeltas, r.SrcPrefixDeltas, r.Global.SrcMatchedPkts)
			}
		})
	}
}
func TestDao14jia1_G4c(t *testing.T) {
	t.Run("GlobalFailSpansTwo", func(t *testing.T) {
		c := dao14Collector(t)
		dao13fCollect(t, c)
		dao13fPackets(t, c.mgr, 4, 0)
		time.Sleep(time.Second)
		restore := dao13fBreak(t, c, "GlobalRead")
		if r, err := c.collect(); err == nil || r != nil {
			t.Fatalf("global read failure not reached: report=%v err=%v", r, err)
		}
		restore()
		time.Sleep(time.Second)
		r := dao13fCollect(t, c)
		if r.Global.MatchedPkts != 2 {
			t.Fatalf("recovery matched=%d want=2", r.Global.MatchedPkts)
		}
	})
}
func TestDao14jia1_G4d(t *testing.T) {
	t.Run("ChecksReadUnscaled", func(t *testing.T) {
		c := dao14Collector(t)
		dao13fCollect(t, c)
		key := uint32(0)
		var gs bpf.GlobalStats
		if err := c.mgr.Objs.GlobalStats.Lookup(&key, &gs); err != nil {
			t.Fatal(err)
		}
		gs.TotalPkts++
		gs.SampleDrops++
		if err := c.mgr.Objs.GlobalStats.Update(&key, &gs, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Second)
		r := dao13fCollect(t, c)
		if c.dropTicks != 1 || c.zeroTicks != 0 || r.Global.SampleDrops != 0 || r.Global.TotalPkts != 0 {
			t.Fatalf("dropTicks=%d zeroTicks=%d global=%+v", c.dropTicks, c.zeroTicks, r.Global)
		}
	})
}
