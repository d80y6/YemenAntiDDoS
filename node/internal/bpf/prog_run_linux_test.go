//go:build linux

package bpf

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Run only on Linux after make generate. Missing bindings/ELF are build errors.
// Root failures (including verifier failures) are fatal, never skips.
// No interface attachment, pinning, map-size override, or network sockets.
func dao8Load(t *testing.T, cidrs ...string) (*Manager, []PrefixEntry) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("Dao8 BPF_PROG_RUN requires root; no kernel test executed")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadXsight()
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			t.Fatalf("map %s unexpectedly requests pinning", name)
		}
	}
	objs := &xsightObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("load unpinned BPF: %+v", err)
	}
	m := &Manager{Objs: objs}
	t.Cleanup(m.Close)
	// Avoid ring-buffer sampling; counters are never sampled.
	if err := m.SetConfig(0, 1<<32); err != nil {
		t.Fatal(err)
	}
	var prefixes []PrefixEntry
	for _, cidr := range cidrs {
		p, err := ParsePrefix(cidr)
		if err != nil {
			t.Fatal(err)
		}
		prefixes = append(prefixes, p)
	}
	return m, prefixes
}
func dao8HotSwap(t *testing.T, cidrs ...string) (*Manager, []PrefixEntry) {
	t.Helper()
	m, prefixes := dao8Load(t, cidrs...)
	if err := m.HotSwap(prefixes); err != nil {
		t.Fatal(err)
	}
	return m, prefixes
}

// Explicit family controls serialization, including mapped addresses in IPv6.
func dao8Frame(t *testing.T, address string, ipv6, outbound bool) []byte {
	t.Helper()
	target := net.ParseIP(address)
	if target == nil {
		t.Fatalf("invalid fixture IP %q", address)
	}
	frame := make([]byte, 14+20+8)
	if ipv6 {
		frame = make([]byte, 14+40+8)
	}
	copy(frame[:6], []byte{2, 0, 0, 0, 0, 1})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 2})
	var src, dst net.IP
	if ipv6 {
		src, dst = net.ParseIP("2001:db9::ff").To16(), target.To16()
		if outbound {
			src, dst = dst, src
		}
		binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
		ip := frame[14:54]
		ip[0], ip[6], ip[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(ip[4:6], 8)
		copy(ip[8:24], src)
		copy(ip[24:40], dst)
	} else {
		src, dst = net.IP{198, 51, 100, 254}, target.To4()
		if dst == nil {
			t.Fatalf("fixture %q is not IPv4", address)
		}
		if outbound {
			src, dst = dst, src
		}
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
		ip := frame[14:34]
		ip[0], ip[8], ip[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(ip[2:4], 28)
		copy(ip[12:16], src)
		copy(ip[16:20], dst)
		var sum uint32
		for i := 0; i < len(ip); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
		}
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	}
	udp := frame[len(frame)-8:]
	binary.BigEndian.PutUint16(udp[:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 54321)
	binary.BigEndian.PutUint16(udp[4:6], 8)
	// Supply a valid UDP checksum in either address family.
	var sum uint32
	for _, ip := range []net.IP{src, dst} {
		for i := 0; i < len(ip); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
		}
	}
	sum += 17 + 8
	for i := 0; i < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return frame
}
func dao8Run(t *testing.T, m *Manager, address string, ipv6, outbound bool) {
	t.Helper()
	ret, err := m.Objs.XsightMain.Run(&ebpf.RunOptions{Data: dao8Frame(t, address, ipv6, outbound), Repeat: 1})
	if err != nil {
		t.Fatalf("BPF_PROG_RUN: %v", err)
	}
	if ret != 1 {
		t.Fatalf("XDP return = %d, want XDP_DROP (1)", ret)
	}
}
func dao8PrefixPackets(t *testing.T, m *Manager, p PrefixEntry, outbound bool) uint64 {
	t.Helper()
	mp := m.Objs.PrefixStatsMap
	if outbound {
		mp = m.Objs.SrcPrefixStatsMap
	}
	key := p.PrefixKey()
	var value PrefixStats
	if err := mp.Lookup(&key, &value); err != nil {
		t.Fatal(err)
	}
	return value.PktCount
}
func dao8Matched(t *testing.T, m *Manager, outbound bool) uint64 {
	t.Helper()
	key := uint32(0)
	var value GlobalStats
	if err := m.Objs.GlobalStats.Lookup(&key, &value); err != nil {
		t.Fatal(err)
	}
	if outbound {
		return value.SrcMatchedPkts
	}
	return value.MatchedPkts
}
func dao8IPMap(t *testing.T, m *Manager, outbound bool) *ebpf.Map {
	t.Helper()
	slot, err := m.ReadActiveSlot()
	if err != nil {
		t.Fatal(err)
	}
	if outbound {
		if slot == 0 {
			return m.Objs.SrcStatsA
		}
		return m.Objs.SrcStatsB
	}
	if slot == 0 {
		return m.Objs.IpStatsA
	}
	return m.Objs.IpStatsB
}
func dao8IPPackets(t *testing.T, m *Manager, outbound bool) uint64 {
	t.Helper()
	iter := dao8IPMap(t, m, outbound).Iterate()
	var key LPMKey
	var value DstIPStats
	var total uint64
	for iter.Next(&key, &value) {
		total += value.PktCount
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	return total
}
func dao8Positive(t *testing.T, m *Manager, p PrefixEntry, address string, ipv6, outbound bool) {
	t.Helper()
	before := dao8PrefixPackets(t, m, p, outbound)
	global := dao8Matched(t, m, outbound)
	dao8Run(t, m, address, ipv6, outbound)
	if got := dao8PrefixPackets(t, m, p, outbound); got != before+1 {
		t.Fatalf("positive control: prefix %s packets = %d, want %d", p.String(), got, before+1)
	}
	if got := dao8Matched(t, m, outbound); got != global+1 {
		t.Fatalf("positive control: global matched = %d, want %d", got, global+1)
	}
}

type dao8MissCase struct {
	cidr, control, probe string
	controlV6, probeV6   bool
}

var dao8MissCases = map[string]dao8MissCase{
	"P1": {"2001:db8::/32", "2001:db8::1", "32.1.13.184", true, false},
	"P2": {"32.0.0.0/8", "32.1.2.3", "2001:db8::1", false, true},
	"P4": {"192.0.2.0/24", "192.0.2.1", "::ffff:192.0.2.1", false, true},
	"P7": {"::/80", "::1", "192.0.2.1", true, false},
}

func dao8Miss(t *testing.T, tc dao8MissCase, outbound bool) {
	t.Helper()
	m, prefixes := dao8HotSwap(t, tc.cidr)
	p := prefixes[0]
	dao8Positive(t, m, p, tc.control, tc.controlV6, outbound)
	before, global, ips := dao8PrefixPackets(t, m, p, outbound), dao8Matched(t, m, outbound), dao8IPPackets(t, m, outbound)
	dao8Run(t, m, tc.probe, tc.probeV6, outbound)
	if got := dao8PrefixPackets(t, m, p, outbound); got != before {
		t.Errorf("cross-family probe %s changed prefix packets: %d -> %d", tc.probe, before, got)
	}
	if got := dao8Matched(t, m, outbound); got != global {
		t.Errorf("unmatched probe changed global matched: %d -> %d", global, got)
	}
	if got := dao8IPPackets(t, m, outbound); got != ips {
		t.Errorf("unmatched probe changed per-IP packets: %d -> %d", ips, got)
	}
}
func TestDao8_P1_IPv4CannotMatchIPv6(t *testing.T)       { dao8Miss(t, dao8MissCases["P1"], false) }
func TestDao8_P2_IPv6CannotMatchIPv4(t *testing.T)       { dao8Miss(t, dao8MissCases["P2"], false) }
func TestDao8_P4_MappedIPv6Blocked(t *testing.T)         { dao8Miss(t, dao8MissCases["P4"], false) }
func TestDao8_P7_BroadIPv6DoesNotCountIPv4(t *testing.T) { dao8Miss(t, dao8MissCases["P7"], false) }
func TestDao8_P7b_BroadIPv6SourceDoesNotCountIPv4(t *testing.T) {
	dao8Miss(t, dao8MissCases["P7"], true)
}

func dao8Mixed(t *testing.T, outbound bool) {
	t.Helper()
	for i, name := range []string{"v4", "v6"} {
		t.Run(name, func(t *testing.T) {
			m, prefixes := dao8HotSwap(t, "192.0.2.0/24", "2001:db8::/32")
			addresses := []string{"192.0.2.1", "2001:db8::1"}
			dao8Positive(t, m, prefixes[i], addresses[i], i == 1, outbound)
			other := dao8PrefixPackets(t, m, prefixes[1-i], outbound)
			dao8Positive(t, m, prefixes[i], addresses[i], i == 1, outbound)
			if got := dao8PrefixPackets(t, m, prefixes[1-i], outbound); got != other {
				t.Errorf("other family prefix changed: %d -> %d", other, got)
			}
		})
	}
}
func TestDao8_P3_MixedFamilies(t *testing.T) { dao8Mixed(t, false) }
func TestDao8_P5_Sources(t *testing.T) {
	for _, name := range []string{"P1", "P2", "P4"} {
		t.Run(name, func(t *testing.T) { dao8Miss(t, dao8MissCases[name], true) })
	}
	t.Run("P3", func(t *testing.T) { dao8Mixed(t, true) })
}
func TestDao8_P8_EncodedValueMasksPrefix(t *testing.T) {
	m, prefixes := dao8HotSwap(t, "192.0.2.0/24")
	dao8Positive(t, m, prefixes[0], "192.0.2.1", false, false)
	dao8Positive(t, m, prefixes[0], "192.0.2.1", false, false)
}
func TestDao8_P6_PerIPKeysUnchanged(t *testing.T) {
	for _, direction := range []string{"inbound", "outbound"} {
		t.Run(direction, func(t *testing.T) {
			outbound := direction == "outbound"
			m, prefixes := dao8HotSwap(t, "192.0.2.0/24", "2001:db8::/32")
			dao8Positive(t, m, prefixes[0], "192.0.2.1", false, outbound)
			dao8Run(t, m, "2001:db8::1", true, outbound)
			want := map[LPMKey]bool{}
			v4, v6 := LPMKey{Prefixlen: 32}, LPMKey{Prefixlen: 128}
			copy(v4.Addr[:4], net.IP{192, 0, 2, 1})
			copy(v6.Addr[:], net.ParseIP("2001:db8::1").To16())
			want[v4], want[v6] = true, true
			iter := dao8IPMap(t, m, outbound).Iterate()
			var key LPMKey
			var value DstIPStats
			for iter.Next(&key, &value) {
				if !want[key] || value.PktCount != 1 {
					t.Errorf("unexpected per-IP entry: %+v packets=%d", key, value.PktCount)
				}
				delete(want, key)
			}
			if err := iter.Err(); err != nil {
				t.Fatal(err)
			}
			if len(want) != 0 {
				t.Errorf("missing per-IP keys: %+v", want)
			}
		})
	}
}
func TestDao8_N8_TrieValueEncoded(t *testing.T) {
	for _, method := range []string{"HotSwap", "PopulateTrie"} {
		t.Run(method, func(t *testing.T) {
			m, prefixes := dao8Load(t, "192.0.2.0/24")
			var err error
			if method == "HotSwap" {
				err = m.HotSwap(prefixes)
			} else {
				err = m.PopulateTrie(prefixes)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := dao8PrefixPackets(t, m, prefixes[0], false)
			global := dao8Matched(t, m, false)
			dao8Run(t, m, "192.0.2.1", false, false)
			// Count failures must not prevent the independent trie-value diagnostic.
			if got := dao8PrefixPackets(t, m, prefixes[0], false); got != before+1 {
				t.Errorf("positive control: prefix %s packets = %d, want %d", prefixes[0].String(), got, before+1)
			}
			if got := dao8Matched(t, m, false); got != global+1 {
				t.Errorf("positive control: global matched = %d, want %d", got, global+1)
			}
			slot, err := m.ReadActiveSlot()
			if err != nil {
				t.Fatal(err)
			}
			trie := m.Objs.WatchTrieA
			if slot != 0 {
				trie = m.Objs.WatchTrieB
			}
			key := prefixes[0].LPMKey()
			var value uint32
			if err := trie.Lookup(&key, &value); err != nil {
				t.Fatal(err)
			}
			if value != 120 {
				t.Errorf("%s trie value = %d, want 120", method, value)
			} else {
				t.Logf("%s trie value = %d, want 120", method, value)
			}
		})
	}
}
