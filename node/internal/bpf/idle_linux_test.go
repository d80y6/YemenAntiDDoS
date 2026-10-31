//go:build linux

package bpf

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Independent unpinned loader; dao8Load and its map sizing stay untouched.
func dao7jiaLoad(t *testing.T) (*Manager, []PrefixEntry) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("Dao7jia real-map BPF_PROG_RUN requires root; no kernel test executed")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadXsight()
	if err != nil {
		t.Fatal(err)
	}
	for name, ms := range spec.Maps {
		if ms.Pinning != ebpf.PinNone {
			t.Fatalf("map %s unexpectedly requests pinning", name)
		}
		switch name {
		case "ip_stats_a", "ip_stats_b", "src_stats_a", "src_stats_b":
			ms.MaxEntries = 64
		}
	}
	objs := &xsightObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("load unpinned BPF: %+v", err)
	}
	m := &Manager{Objs: objs}
	t.Cleanup(m.Close)
	if err := m.SetConfig(0, 1<<32); err != nil {
		t.Fatal(err)
	}
	p, err := ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	prefixes := []PrefixEntry{p}
	if err := m.HotSwap(prefixes); err != nil {
		t.Fatal(err)
	}
	return m, prefixes
}

func dao7jiaSeen(t *testing.T, m *Manager, src bool) (uint32, map[LPMKey]DstIPStats, LPMKey) {
	t.Helper()
	slot, err := m.ReadActiveSlot()
	if err != nil {
		t.Fatal(err)
	}
	seen, err := m.BatchReadIPStats()
	if src {
		seen, err = m.BatchReadSrcIPStats()
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 {
		t.Fatalf("positive control: want exactly one per-IP entry, got %d", len(seen))
	}
	for k, v := range seen {
		if v.PktCount != 1 {
			t.Fatalf("positive control: packets=%d, want 1", v.PktCount)
		}
		return slot, seen, k
	}
	t.Fatal("unreachable empty snapshot")
	return 0, nil, LPMKey{}
}

func dao7jiaBoth(t *testing.T, test func(*testing.T, bool)) {
	t.Helper()
	for _, direction := range []string{"inbound", "outbound"} {
		t.Run(direction, func(t *testing.T) { test(t, direction == "outbound") })
	}
}

func TestDao7jia_A3_ReadThenPacket(t *testing.T) {
	dao7jiaBoth(t, func(t *testing.T, src bool) {
		m, prefixes := dao7jiaLoad(t)
		dao8Positive(t, m, prefixes[0], "192.0.2.1", false, src)
		slot, seen, key := dao7jiaSeen(t, m, src)
		// The caller supplies an idle candidate and its old read; no wall clock needed.
		dao8Run(t, m, "192.0.2.1", false, src)
		deleted, skipped, err := m.DeleteIdleStats(src, slot, []LPMKey{key}, seen)
		if err != nil || skipped || len(deleted) != 0 {
			t.Fatalf("deleted=%v skipped=%t err=%v", deleted, skipped, err)
		}
		var cur DstIPStats
		if err := dao8IPMap(t, m, src).Lookup(&key, &cur); err != nil || cur.PktCount != 2 {
			t.Fatalf("fresh traffic lost: packets=%d err=%v", cur.PktCount, err)
		}
	})
}

func TestDao7jia_A3_EveryCounterRechecked(t *testing.T) {
	changes := map[string]func(*DstIPStats){
		"packets":         func(v *DstIPStats) { v.PktCount++ },
		"bytes":           func(v *DstIPStats) { v.ByteCount++ },
		"small":           func(v *DstIPStats) { v.SmallPkt++ },
		"medium":          func(v *DstIPStats) { v.MediumPkt++ },
		"large":           func(v *DstIPStats) { v.LargePkt++ },
		"decoder_packets": func(v *DstIPStats) { v.DecoderCounts[len(v.DecoderCounts)-1]++ },
		"decoder_bytes":   func(v *DstIPStats) { v.DecoderByteCounts[len(v.DecoderByteCounts)-1]++ },
	}
	dao7jiaBoth(t, func(t *testing.T, src bool) {
		m, prefixes := dao7jiaLoad(t)
		dao8Positive(t, m, prefixes[0], "192.0.2.1", false, src)
		slot, seen, key := dao7jiaSeen(t, m, src)
		mp := dao8IPMap(t, m, src)
		for name, change := range changes {
			t.Run(name, func(t *testing.T) {
				cur := seen[key]
				change(&cur)
				if err := mp.Update(&key, &cur, ebpf.UpdateExist); err != nil {
					t.Fatal(err)
				}
				deleted, skipped, err := m.DeleteIdleStats(src, slot, []LPMKey{key}, seen)
				if err != nil || skipped || len(deleted) != 0 {
					t.Fatalf("changed %s: deleted=%v skipped=%t err=%v", name, deleted, skipped, err)
				}
				var got DstIPStats
				if err := mp.Lookup(&key, &got); err != nil || got != cur {
					t.Fatalf("counter-only update lost: %+v err=%v", got, err)
				}
			})
		}
	})
}

func TestDao7jia_A4_HotSwapMutex(t *testing.T) {
	dao7jiaBoth(t, func(t *testing.T, src bool) {
		m, prefixes := dao7jiaLoad(t)
		dao8Positive(t, m, prefixes[0], "192.0.2.1", false, src)
		slot, seen, key := dao7jiaSeen(t, m, src)
		m.swapMu.Lock()
		deleted, skipped, err := m.DeleteIdleStats(src, slot, []LPMKey{key}, seen)
		m.swapMu.Unlock()
		if err != nil || !skipped || len(deleted) != 0 {
			t.Fatalf("locked: deleted=%v skipped=%t err=%v", deleted, skipped, err)
		}
		_, after, _ := dao7jiaSeen(t, m, src)
		if len(after) != len(seen) || after[key] != seen[key] {
			t.Fatal("locked deletion changed entries")
		}
		deleted, skipped, err = m.DeleteIdleStats(src, slot, []LPMKey{key}, seen)
		if err != nil || skipped || len(deleted) != 1 || deleted[0] != key {
			t.Fatalf("unlocked: deleted=%v skipped=%t err=%v", deleted, skipped, err)
		}
		var cur DstIPStats
		if err := dao8IPMap(t, m, src).Lookup(&key, &cur); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("successful deletion lookup=%v", err)
		}
	})
}

func TestDao7jia_A5_StaleSlot(t *testing.T) {
	dao7jiaBoth(t, func(t *testing.T, src bool) {
		m, prefixes := dao7jiaLoad(t)
		dao8Positive(t, m, prefixes[0], "192.0.2.1", false, src)
		slot, seen, key := dao7jiaSeen(t, m, src)
		if err := m.HotSwap(prefixes); err != nil {
			t.Fatal(err)
		}
		current, migrated, _ := dao7jiaSeen(t, m, src)
		if current == slot || migrated[key] != seen[key] {
			t.Fatal("fixture did not switch slots and preserve counters")
		}
		// Restore an old-slot sentinel: without the slot check deletion is observable
		// even though HotSwap normally clears that slot. It is never pinned/attached.
		oldMap := m.Objs.IpStatsA
		if src {
			oldMap = m.Objs.SrcStatsA
		}
		if slot == 1 {
			oldMap = m.Objs.IpStatsB
			if src {
				oldMap = m.Objs.SrcStatsB
			}
		}
		v := seen[key]
		if err := oldMap.Update(&key, &v, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		deleted, skipped, err := m.DeleteIdleStats(src, slot, []LPMKey{key}, seen)
		if err != nil || !skipped || len(deleted) != 0 {
			t.Fatalf("stale slot: deleted=%v skipped=%t err=%v", deleted, skipped, err)
		}
		for _, mp := range []*ebpf.Map{oldMap, dao8IPMap(t, m, src)} {
			var cur DstIPStats
			if err := mp.Lookup(&key, &cur); err != nil || cur != v {
				t.Fatalf("stale-slot call changed map: %+v err=%v", cur, err)
			}
		}
	})
}

func TestDao7jia_A3_DeletedSetAndMissingKeys(t *testing.T) {
	dao7jiaBoth(t, func(t *testing.T, src bool) {
		m, prefixes := dao7jiaLoad(t)
		dao8Positive(t, m, prefixes[0], "192.0.2.1", false, src)
		slot, seen, key := dao7jiaSeen(t, m, src)
		missing := key
		missing.Addr[3] = 99
		deleted, skipped, err := m.DeleteIdleStats(src, slot, []LPMKey{missing, key, key}, seen)
		if err != nil || skipped || len(deleted) != 1 || deleted[0] != key {
			t.Fatalf("successful key set=%v skipped=%t err=%v", deleted, skipped, err)
		}
	})
}

func TestDao7jia_A7_Dao8Regression(t *testing.T) {
	t.Run("P1", TestDao8_P1_IPv4CannotMatchIPv6)
	t.Run("P2", TestDao8_P2_IPv6CannotMatchIPv4)
	t.Run("P3", TestDao8_P3_MixedFamilies)
	t.Run("P4", TestDao8_P4_MappedIPv6Blocked)
	t.Run("P5", TestDao8_P5_Sources)
	t.Run("P6", TestDao8_P6_PerIPKeysUnchanged)
	t.Run("P7", TestDao8_P7_BroadIPv6DoesNotCountIPv4)
	t.Run("P7b", TestDao8_P7b_BroadIPv6SourceDoesNotCountIPv4)
	t.Run("P8", TestDao8_P8_EncodedValueMasksPrefix)
	t.Run("N8", TestDao8_N8_TrieValueEncoded)
}
