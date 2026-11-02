//go:build linux

package collector

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/d80y6/YemenDDoS/node/internal/bpf"
)

// This loader uses the explicit unpinned branch of Load, never an interface.
// Only inbound size is overridden by Load; src sizing stays as shipped.
func dao7jiaCollector(t *testing.T) *Collector {
	t.Helper()
	return dao7jiaCollectorSized(t, 64)
}

func dao7jiaCollectorSized(t *testing.T, maxEntries uint32) *Collector {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("Dao7jia real-map BPF_PROG_RUN requires root; no kernel test executed")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	m, err := bpf.Load("", maxEntries)
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
	old := ipIdleTicks
	ipIdleTicks = 3
	t.Cleanup(func() { ipIdleTicks = old })
	c := New(m, 0)
	if err := m.SetConfig(0, 1<<32); err != nil {
		t.Fatal(err)
	}
	return c
}

func dao7jiaKey(last byte) bpf.LPMKey {
	k := bpf.LPMKey{Prefixlen: 32}
	copy(k.Addr[:4], net.IP{192, 0, 2, last})
	return k
}

func dao7jiaPacket(t *testing.T, c *Collector, last byte, src bool) {
	t.Helper()
	frame := make([]byte, 14+20+8)
	copy(frame[:12], []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ip[2:4], 28)
	s, d := net.IP{198, 51, 100, 254}, net.IP{192, 0, 2, last}
	if src {
		s, d = d, s
	}
	copy(ip[12:16], s)
	copy(ip[16:20], d)
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 54321)
	binary.BigEndian.PutUint16(udp[4:6], 8) // zero UDP checksum is valid in IPv4
	if _, err := c.mgr.Objs.XsightMain.Run(&ebpf.RunOptions{Data: frame, Repeat: 1}); err != nil {
		t.Fatalf("BPF_PROG_RUN: %v", err)
	}
}

func dao7jiaMap(t *testing.T, c *Collector, src bool) *ebpf.Map {
	t.Helper()
	slot, err := c.mgr.ReadActiveSlot()
	if err != nil {
		t.Fatal(err)
	}
	maps := [2]*ebpf.Map{c.mgr.Objs.IpStatsA, c.mgr.Objs.IpStatsB}
	if src {
		maps = [2]*ebpf.Map{c.mgr.Objs.SrcStatsA, c.mgr.Objs.SrcStatsB}
	}
	return maps[slot]
}

func dao7jiaPositive(t *testing.T, c *Collector, last byte, src bool) {
	t.Helper()
	before, err := c.mgr.GlobalStats()
	if err != nil {
		t.Fatal(err)
	}
	dao7jiaPacket(t, c, last, src)
	after, err := c.mgr.GlobalStats()
	if err != nil {
		t.Fatal(err)
	}
	old, got := before.MatchedPkts, after.MatchedPkts
	if src {
		old, got = before.SrcMatchedPkts, after.SrcMatchedPkts
	}
	if got != old+1 {
		t.Fatalf("positive control: matched packets=%d, want %d", got, old+1)
	}
	k := dao7jiaKey(last)
	var v bpf.DstIPStats
	if err := dao7jiaMap(t, c, src).Lookup(&k, &v); err != nil || v.PktCount != 1 {
		t.Fatalf("positive control: per-IP packets=%d, err=%v", v.PktCount, err)
	}
}

func dao7jiaCollect(t *testing.T, c *Collector) *Report {
	t.Helper()
	r, err := c.collect()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func dao7jiaExists(t *testing.T, c *Collector, last byte, src, want bool) {
	t.Helper()
	k := dao7jiaKey(last)
	var v bpf.DstIPStats
	err := dao7jiaMap(t, c, src).Lookup(&k, &v)
	if want && err != nil {
		t.Fatalf("key %d must exist: %v", last, err)
	}
	if !want && !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("key %d lookup=%v, want ErrKeyNotExist", last, err)
	}
}

func dao7jiaDelta(t *testing.T, r *Report, last byte, src bool, want uint64) {
	t.Helper()
	deltas := r.IPDeltas
	if src {
		deltas = r.SrcIPDeltas
	}
	k := dao7jiaKey(last)
	var matches int
	for _, d := range deltas {
		if d.Key == k {
			matches++
			if d.Stats.PktCount != want {
				t.Errorf("key %d delta=%d, want %d", last, d.Stats.PktCount, want)
			}
		}
	}
	if matches != 1 {
		t.Errorf("key %d delta entries=%d, want exactly one", last, matches)
	}
}

func dao7jiaIdleRetention(t *testing.T, src bool) {
	c := dao7jiaCollector(t)
	dao7jiaPositive(t, c, 1, src)
	dao7jiaPacket(t, c, 2, src)
	dao7jiaCollect(t, c)
	for i := 0; i < 4; i++ {
		dao7jiaPacket(t, c, 2, src)
		dao7jiaDelta(t, dao7jiaCollect(t, c), 2, src, 1)
	}
	dao7jiaExists(t, c, 1, src, false)
	dao7jiaExists(t, c, 2, src, true)
	last, idle := c.lastIP, c.idleIP
	if src {
		last, idle = c.lastSrcIP, c.idleSrc
	}
	if _, ok := last[dao7jiaKey(1)]; ok {
		t.Error("deleted key remains in last snapshot")
	}
	if _, ok := idle[dao7jiaKey(1)]; ok {
		t.Error("deleted key remains in idle state")
	}
	// M1: one quiet tick between two packets must not delete K2.
	dao7jiaCollect(t, c)
	dao7jiaExists(t, c, 2, src, true)
	if idle[dao7jiaKey(2)] != 1 {
		t.Errorf("K2 idle ticks=%d, want 1", idle[dao7jiaKey(2)])
	}
	dao7jiaPacket(t, c, 2, src)
	dao7jiaDelta(t, dao7jiaCollect(t, c), 2, src, 1)
}

func TestDao7jia_A1_InboundIdleRetention(t *testing.T)  { dao7jiaIdleRetention(t, false) }
func TestDao7jia_A1_OutboundIdleRetention(t *testing.T) { dao7jiaIdleRetention(t, true) }

func TestDao7jia_A2_FullMapMakesRoom(t *testing.T) {
	c := dao7jiaCollector(t)
	info, err := dao7jiaMap(t, c, false).Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxEntries != 64 {
		t.Fatalf("fixture MaxEntries=%d, want 64", info.MaxEntries)
	}
	dao7jiaPositive(t, c, 1, false)
	for i := 2; i <= 64; i++ {
		dao7jiaPacket(t, c, byte(i), false)
	}
	seen, err := c.mgr.BatchReadIPStats()
	if err != nil || len(seen) != 64 {
		t.Fatalf("full-map entries=%d err=%v", len(seen), err)
	}
	dao7jiaPacket(t, c, 65, false)
	dao7jiaExists(t, c, 65, false, false)
	dao7jiaCollect(t, c)
	for i := uint16(0); i < ipIdleTicks+1; i++ {
		dao7jiaCollect(t, c)
	}
	dao7jiaPacket(t, c, 65, false)
	dao7jiaExists(t, c, 65, false, true)
	dao7jiaDelta(t, dao7jiaCollect(t, c), 65, false, 1)
}

func TestDao7jia_A2_RecreatedKeyDelta(t *testing.T) {
	for _, src := range []bool{false, true} {
		name := "inbound"
		if src {
			name = "outbound"
		}
		t.Run(name, func(t *testing.T) {
			c := dao7jiaCollector(t)
			dao7jiaPositive(t, c, 1, src)
			dao7jiaCollect(t, c)
			for i := uint16(0); i < ipIdleTicks; i++ {
				dao7jiaCollect(t, c)
			}
			dao7jiaExists(t, c, 1, src, false)
			dao7jiaPacket(t, c, 1, src)
			dao7jiaDelta(t, dao7jiaCollect(t, c), 1, src, 1)
		})
	}
}

func TestDao7jia_A1_HotSwapResetsIdle(t *testing.T) {
	c := dao7jiaCollector(t)
	dao7jiaPositive(t, c, 1, false)
	dao7jiaPositive(t, c, 2, true)
	dao7jiaCollect(t, c)
	dao7jiaCollect(t, c)
	dao7jiaCollect(t, c)
	p, err := bpf.ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.mgr.HotSwap([]bpf.PrefixEntry{p}); err != nil {
		t.Fatal(err)
	}
	c.NotifyHotSwap()
	r := dao7jiaCollect(t, c)
	if len(c.idleIP) != 0 || len(c.idleSrc) != 0 || len(r.IPDeltas) != 0 || len(r.SrcIPDeltas) != 0 {
		t.Fatal("HotSwap baseline tick must reset idle state and skip deltas")
	}
	for i := uint16(1); i <= ipIdleTicks; i++ {
		dao7jiaCollect(t, c)
		dao7jiaExists(t, c, 1, false, i < ipIdleTicks)
		dao7jiaExists(t, c, 2, true, i < ipIdleTicks)
	}
}

func TestDao7jia_A1_MissingKeysForgetIdle(t *testing.T) {
	c := dao7jiaCollector(t)
	dao7jiaPositive(t, c, 1, false)
	dao7jiaPositive(t, c, 2, true)
	dao7jiaCollect(t, c)
	dao7jiaCollect(t, c)
	for i, src := range []bool{false, true} {
		k := dao7jiaKey(byte(i + 1))
		if err := dao7jiaMap(t, c, src).Delete(&k); err != nil {
			t.Fatal(err)
		}
	}
	dao7jiaCollect(t, c)
	if len(c.idleIP) != 0 || len(c.idleSrc) != 0 || len(c.lastIP) != 0 || len(c.lastSrcIP) != 0 {
		t.Fatal("absent map keys must not retain snapshots or idle counts")
	}
}

func TestDao7jia_A1_ReadErrorDoesNotDelete(t *testing.T) {
	c := dao7jiaCollector(t)
	dao7jiaPositive(t, c, 1, false)
	dao7jiaCollect(t, c)
	dao7jiaCollect(t, c)
	dao7jiaCollect(t, c)
	key := dao7jiaKey(1)
	before, idle := c.lastIP[key], c.idleIP[key]
	if err := c.mgr.Objs.SrcPrefixStatsMap.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.collect(); err == nil {
		t.Fatal("closed outbound prefix map must fail collection")
	}
	dao7jiaExists(t, c, 1, false, true)
	if c.lastIP[key] != before || c.idleIP[key] != idle {
		t.Fatal("failed collection advanced inbound baseline/idle state")
	}
}

func TestDao7jia_A1_DeleteBudgetAndSaturation(t *testing.T) {
	if maxIdleDeletesPerTick != 10_000 {
		t.Fatalf("deletion budget=%d, want 10000 per direction", maxIdleDeletesPerTick)
	}
	const entries = maxIdleDeletesPerTick + 2
	c := dao7jiaCollectorSized(t, entries)
	dao7jiaPositive(t, c, 1, false)
	dao7jiaPositive(t, c, 1, true)
	for _, src := range []bool{false, true} {
		mp := dao7jiaMap(t, c, src)
		for i := 1; i < entries; i++ {
			key := bpf.LPMKey{Prefixlen: 32}
			copy(key.Addr[:4], net.IP{10, byte(i >> 16), byte(i >> 8), byte(i)})
			v := bpf.DstIPStats{PktCount: 1}
			if err := mp.Update(&key, &v, ebpf.UpdateNoExist); err != nil {
				t.Fatal(err)
			}
		}
	}
	dao7jiaCollect(t, c)
	c.idleIP, c.idleSrc = make(map[bpf.LPMKey]uint16), make(map[bpf.LPMKey]uint16)
	for key := range c.lastIP {
		c.idleIP[key] = math.MaxUint16
	}
	for key := range c.lastSrcIP {
		c.idleSrc[key] = math.MaxUint16
	}
	dao7jiaCollect(t, c)
	for _, src := range []bool{false, true} {
		seen, err := c.mgr.BatchReadIPStats()
		last, idle := c.lastIP, c.idleIP
		if src {
			seen, err = c.mgr.BatchReadSrcIPStats()
			last, idle = c.lastSrcIP, c.idleSrc
		}
		if err != nil || len(seen) != 2 || len(last) != 2 || len(idle) != 2 {
			t.Fatalf("direction %t: map=%d baseline=%d idle=%d err=%v; want 2 each", src, len(seen), len(last), len(idle), err)
		}
		for key := range seen {
			if idle[key] != math.MaxUint16 {
				t.Errorf("idle counter wrapped: %d", idle[key])
			}
		}
	}
	dao7jiaCollect(t, c)
	if len(c.lastIP) != 0 || len(c.lastSrcIP) != 0 || len(c.idleIP) != 0 || len(c.idleSrc) != 0 {
		t.Fatal("remaining two keys in each direction must be deleted next tick")
	}
}
