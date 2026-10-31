//go:build linux

package collector

import (
	"maps"
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/littlewolf9527/xsight/node/internal/bpf"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

// No attachment, pinning, socket, or dependency on a physical interface.
func dao13fManager(t *testing.T) *bpf.Manager {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("Dao13f real-map gates require root; skipping is not permitted")
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

func dao13fNew(t *testing.T, m *bpf.Manager) *Collector {
	t.Helper()
	c := New(m, 0)
	if err := m.SetConfig(0, 1<<32); err != nil {
		t.Fatal(err)
	}
	key := uint32(0)
	var got uint64
	if err := m.Objs.XsightConfig.Lookup(&key, &got); err != nil {
		t.Fatal(err)
	}
	if got != 1<<32 {
		t.Fatalf("sample rate readback=%d, want %d", got, uint64(1<<32))
	}
	return c
}

func dao13fGlobal(t *testing.T, m *bpf.Manager) bpf.GlobalStats {
	t.Helper()
	gs, err := m.GlobalStats()
	if err != nil {
		t.Fatal(err)
	}
	return *gs
}

func dao13fSeed(t *testing.T, m *bpf.Manager) {
	t.Helper()
	var seed bpf.GlobalStats
	// All scalar and array values are distinct and nonzero, including drops.
	n := uint64(101)
	var fill func(reflect.Value)
	fill = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.Struct, reflect.Array:
			count := v.Len
			at := v.Index
			if v.Kind() == reflect.Struct {
				count, at = v.NumField, v.Field
			}
			for i := 0; i < count(); i++ {
				fill(at(i))
			}
		case reflect.Uint32, reflect.Uint64:
			v.SetUint(n)
			n++
		default:
			t.Fatalf("unexpected global counter kind: %s", v.Kind())
		}
	}
	fill(reflect.ValueOf(&seed).Elem())
	key := uint32(0)
	if err := m.Objs.GlobalStats.Update(&key, &seed, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if got := dao13fGlobal(t, m); got != seed {
		t.Fatalf("seed readback=%+v, want %+v", got, seed)
	}
}

func dao13fPackets(t *testing.T, m *bpf.Manager, inbound, outbound int) {
	t.Helper()
	// Reuse only the existing frame/BPF_PROG_RUN helper, not its skipping loader.
	c := &Collector{mgr: m}
	for i := 0; i < inbound; i++ {
		dao7jiaPacket(t, c, 1, false)
	}
	for i := 0; i < outbound; i++ {
		dao7jiaPacket(t, c, 2, true)
	}
}

func dao13fCollect(t *testing.T, c *Collector) *Report {
	t.Helper()
	r, err := c.collect()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func dao13fGlobalDifference(after, before bpf.GlobalStats) GlobalDelta {
	d := GlobalDelta{
		TotalPkts: after.TotalPkts - before.TotalPkts, TotalBytes: after.TotalBytes - before.TotalBytes,
		MatchedPkts: after.MatchedPkts - before.MatchedPkts, MatchedBytes: after.MatchedBytes - before.MatchedBytes,
		SampleDrops:    after.SampleDrops - before.SampleDrops,
		SrcMatchedPkts: after.SrcMatchedPkts - before.SrcMatchedPkts, SrcMatchedBytes: after.SrcMatchedBytes - before.SrcMatchedBytes,
	}
	for i := 0; i < decoder.MaxDecoders; i++ {
		d.DecoderCounts[i] = after.DecoderCounts[i] - before.DecoderCounts[i]
		d.DecoderByteCounts[i] = after.DecoderByteCounts[i] - before.DecoderByteCounts[i]
		d.SrcDecoderCounts[i] = after.SrcDecoderCounts[i] - before.SrcDecoderCounts[i]
		d.SrcDecoderByteCounts[i] = after.SrcDecoderByteCounts[i] - before.SrcDecoderByteCounts[i]
	}
	return d
}

func dao13fEmpty(t *testing.T, r *Report) {
	t.Helper()
	if len(r.IPDeltas)+len(r.PrefixDeltas)+len(r.SrcIPDeltas)+len(r.SrcPrefixDeltas) != 0 {
		t.Fatalf("recovery must omit all four delta families: %+v", r)
	}
}

func dao13fOneEach(t *testing.T, r *Report) {
	t.Helper()
	for _, ds := range [][]IPDelta{r.IPDeltas, r.SrcIPDeltas} {
		if len(ds) != 1 || ds[0].Stats.PktCount != 1 {
			t.Fatalf("per-IP deltas=%+v, want exactly one packet", ds)
		}
	}
	for _, ds := range [][]PrefixDelta{r.PrefixDeltas, r.SrcPrefixDeltas} {
		if len(ds) != 1 || ds[0].Stats.PktCount != 1 {
			t.Fatalf("prefix deltas=%+v, want exactly one packet", ds)
		}
	}
}

func TestDao13f_R3(t *testing.T) {
	for _, name := range []string{"UnsetIsZero", "SkipTickStamped", "NormalTickStamped"} {
		t.Run(name, func(t *testing.T) {
			c := dao13fNew(t, dao13fManager(t))
			want := uint32(0)
			if name != "UnsetIsZero" {
				want = 10
				c.SetUpstreamRate(want)
			}
			if name == "NormalTickStamped" {
				dao13fCollect(t, c)
				c.SetUpstreamRate(17)
				want = 17
			}
			if r := dao13fCollect(t, c); r.UpstreamRate != want {
				t.Fatalf("tick upstream rate=%d, want %d", r.UpstreamRate, want)
			}
		})
	}
}

func TestDao13f_B1(t *testing.T) {
	t.Run("FirstTickNotCumulative", func(t *testing.T) {
		m := dao13fManager(t)
		dao13fSeed(t, m)
		dao13fPackets(t, m, 2, 1)
		c := dao13fNew(t, m)
		if r := dao13fCollect(t, c); r.Global != (GlobalDelta{}) {
			t.Fatalf("first global delta=%+v, want every field zero", r.Global)
		}
	})
	t.Run("NewTrafficAfterNew", func(t *testing.T) {
		m := dao13fManager(t)
		dao13fSeed(t, m)
		c := dao13fNew(t, m)
		g0 := dao13fGlobal(t, m)
		dao13fPackets(t, m, 3, 1)
		g1 := dao13fGlobal(t, m)
		if g1.MatchedPkts-g0.MatchedPkts != 3 {
			t.Fatal("precondition: inbound traffic must advance matched by three")
		}
		if r, want := dao13fCollect(t, c), dao13fGlobalDifference(g1, g0); r.Global != want {
			t.Fatalf("first global delta=%+v, want traffic since New=%+v", r.Global, want)
		}
	})
	t.Run("SecondTickExact", func(t *testing.T) {
		m := dao13fManager(t)
		dao13fSeed(t, m)
		c := dao13fNew(t, m)
		dao13fPackets(t, m, 3, 1)
		dao13fCollect(t, c)
		dao13fPackets(t, m, 3, 0)
		g := dao13fCollect(t, c).Global
		const bytes = 3 * (14 + 20 + 8)
		if g.MatchedPkts != 3 || g.MatchedBytes != bytes || g.DecoderCounts[decoder.UDP] != 3 || g.DecoderByteCounts[decoder.UDP] != bytes {
			t.Fatalf("second tick global=%+v", g)
		}
	})
}

func TestDao13f_B2(t *testing.T) {
	t.Run("HotSwapSkipTickGlobalExact", func(t *testing.T) {
		m := dao13fManager(t)
		c := dao13fNew(t, m)
		dao13fCollect(t, c)
		p, err := bpf.ParsePrefix("192.0.2.0/24")
		if err != nil {
			t.Fatal(err)
		}
		if err := m.HotSwap([]bpf.PrefixEntry{p}); err != nil {
			t.Fatal(err)
		}
		c.NotifyHotSwap()
		before := dao13fGlobal(t, m)
		dao13fPackets(t, m, 3, 1)
		after := dao13fGlobal(t, m)
		r := dao13fCollect(t, c)
		dao13fEmpty(t, r)
		if want := dao13fGlobalDifference(after, before); r.Global != want {
			t.Fatalf("HotSwap skip global=%+v, want %+v", r.Global, want)
		}
	})
}

// Clone keeps the kernel map alive while Close invalidates the production
// userspace handle. Restoring the clone preserves the intervening BPF writes.
func dao13fBreak(t *testing.T, c *Collector, name string) func() {
	t.Helper()
	slot, err := c.mgr.ReadActiveSlot()
	if err != nil {
		t.Fatal(err)
	}
	var at **ebpf.Map
	switch name {
	case "GlobalRead":
		at = &c.mgr.Objs.GlobalStats
	case "PrefixIter":
		at = &c.mgr.Objs.PrefixStatsMap
	case "ActiveSlot":
		at = &c.mgr.Objs.ActiveSlot
	case "IPBatch":
		at = &c.mgr.Objs.IpStatsA
		if slot != 0 {
			at = &c.mgr.Objs.IpStatsB
		}
	case "SrcPrefixIter":
		at = &c.mgr.Objs.SrcPrefixStatsMap
	case "SrcIPBatch":
		at = &c.mgr.Objs.SrcStatsA
		if slot != 0 {
			at = &c.mgr.Objs.SrcStatsB
		}
	default:
		t.Fatalf("unknown failure phase %q", name)
	}
	clone, err := (*at).Clone()
	if err != nil {
		t.Fatal(err)
	}
	if err := (*at).Close(); err != nil {
		clone.Close()
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			*at, restored = clone, true
		}
	}
	t.Cleanup(restore)
	return restore
}

func dao13fFailure(t *testing.T, c *Collector, phase string) {
	t.Helper()
	dao13fPackets(t, c.mgr, 1, 1)
	last, idle := maps.Clone(c.lastIP), maps.Clone(c.idleIP)
	restore := dao13fBreak(t, c, phase)
	r, err := c.collect()
	restore()
	if err == nil || r != nil {
		t.Fatalf("closed map must fail %s: report=%v error=%v", phase, r, err)
	}
	if !reflect.DeepEqual(c.lastIP, last) || !reflect.DeepEqual(c.idleIP, idle) {
		t.Fatal("failed collection advanced lastIP or idleIP")
	}
}

func dao13fReady(t *testing.T) *Collector {
	t.Helper()
	c := dao13fNew(t, dao13fManager(t))
	dao13fPackets(t, c.mgr, 1, 1)
	dao13fCollect(t, c)
	dao13fPackets(t, c.mgr, 1, 1)
	dao13fOneEach(t, dao13fCollect(t, c))
	return c
}

func TestDao13f_K1(t *testing.T) {
	for _, phase := range []string{"GlobalRead", "PrefixIter", "ActiveSlot", "IPBatch", "SrcPrefixIter", "SrcIPBatch"} {
		t.Run(phase, func(t *testing.T) {
			clauses := []string{"FailurePreservesBaseline", "RecoverySkipsDeltas", "RecoveryGlobalExact", "NextTickExact"}
			if phase == "GlobalRead" {
				clauses[2] = "RecoveryGlobalTwoTicks"
			}
			for _, clause := range clauses {
				t.Run(clause, func(t *testing.T) {
					c := dao13fReady(t)
					dao13fFailure(t, c, phase)
					dao13fPackets(t, c.mgr, 1, 1)
					r := dao13fCollect(t, c)
					switch clause {
					case "RecoverySkipsDeltas":
						dao13fEmpty(t, r)
					case "RecoveryGlobalExact", "RecoveryGlobalTwoTicks":
						want := uint64(1)
						if phase == "GlobalRead" {
							want = 2
						}
						if r.Global.MatchedPkts != want || r.Global.SrcMatchedPkts != want {
							t.Fatalf("recovery global=%+v, want matched=%d in both directions", r.Global, want)
						}
					case "NextTickExact":
						dao13fPackets(t, c.mgr, 1, 1)
						dao13fOneEach(t, dao13fCollect(t, c))
					}
				})
			}
		})
	}
}

func dao13fNotifyInterleave(t *testing.T, kind string, notify bool) *Report {
	t.Helper()
	c := dao13fReady(t)
	switch kind {
	case "Recovery":
		dao13fFailure(t, c, "PrefixIter")
	case "HotSwap":
		p, err := bpf.ParsePrefix("192.0.2.0/24")
		if err != nil {
			t.Fatal(err)
		}
		if err := c.mgr.HotSwap([]bpf.PrefixEntry{p}); err != nil {
			t.Fatal(err)
		}
		c.NotifyHotSwap()
	}
	testHookAfterSkipDecision = nil
	t.Cleanup(func() { testHookAfterSkipDecision = nil })
	called := 0
	if notify {
		testHookAfterSkipDecision = func() {
			called++
			c.NotifyHotSwap()
		}
	}
	dao13fPackets(t, c.mgr, 1, 1)
	dao13fCollect(t, c)
	testHookAfterSkipDecision = nil
	if notify && called != 1 {
		t.Fatalf("decision hook calls=%d, want one", called)
	}
	dao13fPackets(t, c.mgr, 1, 1)
	return dao13fCollect(t, c)
}

func TestDao13f_K2(t *testing.T) {
	for _, tc := range []struct{ name, kind string }{
		{"NotifyDuringRecoveryTickKept", "Recovery"},
		{"NotifyDuringHotSwapSkipTickKept", "HotSwap"},
		{"NotifyDuringNormalTickKept", "Normal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dao13fOneEach(t, dao13fNotifyInterleave(t, tc.kind, false))
			dao13fEmpty(t, dao13fNotifyInterleave(t, tc.kind, true))
		})
	}
	t.Run("SerialEquivalence", func(t *testing.T) {
		dao13fOneEach(t, dao13fNotifyInterleave(t, "HotSwap", false))
	})
}

func TestDao13f_R0FixedB(t *testing.T) {
	t.Run("FirstTickNotCumulative", func(t *testing.T) {
		m := dao13fManager(t)
		dao13fPackets(t, m, 5, 2)
		if g := dao13fGlobal(t, m); g.MatchedPkts != 5 || g.SrcMatchedPkts != 2 {
			t.Fatalf("precondition: global=%+v", g)
		}
		if r := dao13fCollect(t, dao13fNew(t, m)); r.Global != (GlobalDelta{}) {
			t.Fatalf("first global delta=%+v, want zero", r.Global)
		}
	})
}

func TestDao13f_R0FixedK(t *testing.T) {
	t.Run("RecoveryWindowAligned", func(t *testing.T) {
		c := dao13fReady(t)
		dao13fFailure(t, c, "PrefixIter")
		dao13fPackets(t, c.mgr, 1, 1)
		r := dao13fCollect(t, c)
		dao13fEmpty(t, r)
		if r.Global.MatchedPkts != 1 || r.Global.SrcMatchedPkts != 1 {
			t.Fatalf("recovery global=%+v, want one packet per direction", r.Global)
		}
	})
}
