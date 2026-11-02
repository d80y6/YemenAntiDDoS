package bpf_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
	"github.com/d80y6/YemenDDoS/node/internal/collector"
)

func dao8Prefix(t *testing.T, cidr string) bpf.PrefixEntry {
	t.Helper()
	p, err := bpf.ParsePrefix(cidr)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func dao8CheckKeys(t *testing.T, cidr, address string, bits uint32) {
	t.Helper()
	p := dao8Prefix(t, cidr)
	want := net.ParseIP(address).To16()
	lpm, prefix := p.LPMKey(), p.PrefixKey()
	if lpm.Prefixlen != bits || !bytes.Equal(lpm.Addr[:], want) {
		t.Errorf("LPMKey(%s) = %+v, want addr %x prefixlen %d", cidr, lpm, want, bits)
	}
	if prefix.Prefixlen != bits || !bytes.Equal(prefix.Addr[:], want) {
		t.Errorf("PrefixKey(%s) = %+v, want addr %x prefixlen %d", cidr, prefix, want, bits)
	}
}
func TestDao8_N1_IPv4Keys(t *testing.T) { dao8CheckKeys(t, "192.0.2.0/24", "::ffff:192.0.2.0", 120) }
func TestDao8_N2_IPv6Keys(t *testing.T) { dao8CheckKeys(t, "2001:db8::/32", "2001:db8::", 32) }

func dao8CheckDecoded(t *testing.T, key bpf.PrefixKeyGo, wantIP net.IP, ones int) {
	t.Helper()
	// Use the existing collector entry point so these tests also compile on HEAD.
	n := collector.PrefixKeyToIPNet(key)
	gotOnes, bits := n.Mask.Size()
	if len(n.IP) != len(wantIP) || !bytes.Equal(n.IP, wantIP) || gotOnes != ones || bits != len(wantIP)*8 {
		t.Errorf("decode %+v = IP(%d bytes) %x mask %d/%d, want IP(%d bytes) %x mask %d/%d",
			key, len(n.IP), []byte(n.IP), gotOnes, bits, len(wantIP), []byte(wantIP), ones, len(wantIP)*8)
	}
}
func TestDao8_N3_DecodeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		cidr, encoded, ip string
		encodedBits       uint32
		ones              int
		v4                bool
	}{
		{"192.0.2.0/24", "::ffff:192.0.2.0", "192.0.2.0", 120, 24, true},
		{"2001:db8::/32", "2001:db8::", "2001:db8::", 32, 32, false},
		{"0.0.0.0/0", "::ffff:0.0.0.0", "0.0.0.0", 96, 0, true},
		{"192.0.2.1/32", "::ffff:192.0.2.1", "192.0.2.1", 128, 32, true},
		{"2001:db8::1/128", "2001:db8::1", "2001:db8::1", 128, 128, false},
		{"::/0", "::", "::", 0, 0, false},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			want := net.ParseIP(tc.ip).To16()
			if tc.v4 {
				want = want.To4()
			}
			key := bpf.PrefixKeyGo{Prefixlen: tc.encodedBits}
			copy(key.Addr[:], net.ParseIP(tc.encoded).To16())
			dao8CheckDecoded(t, key, want, tc.ones)
			dao8CheckDecoded(t, dao8Prefix(t, tc.cidr).PrefixKey(), want, tc.ones)
		})
	}
}
func TestDao8_N4_D1_IPv6Slash32(t *testing.T) {
	dao8CheckDecoded(t, dao8Prefix(t, "2001:db8::/32").PrefixKey(), net.ParseIP("2001:db8::").To16(), 32)
}
func TestDao8_N5_D13_DistinctFamilies(t *testing.T) {
	v4 := dao8Prefix(t, "32.1.13.184/32").PrefixKey()
	v6 := dao8Prefix(t, "2001:db8::/32").PrefixKey()
	if v4 == v6 {
		t.Fatalf("cross-family PrefixKey collision: %+v", v4)
	}
}
func TestDao8_N6_RejectMapped(t *testing.T) {
	for _, cidr := range []string{"::ffff:192.0.2.0/120", "::ffff:192.0.2.0/80", "::ffff:c000:200/120",
		"::ffff:192.0.2.0/0120", "::ffff:192.0.2.0/080"} {
		t.Run(cidr, func(t *testing.T) {
			if p, err := bpf.ParsePrefix(cidr); err == nil {
				t.Errorf("ParsePrefix(%q) accepted %+v", cidr, p)
			}
		})
	}
}
func TestDao8_N6b_AcceptNative(t *testing.T) {
	for _, cidr := range []string{"192.0.2.0/24", "2001:db8::/32", "::/80", "64:ff9b::/96"} {
		t.Run(cidr, func(t *testing.T) { dao8Prefix(t, cidr) })
	}
}
