//go:build linux

package bpf_test

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
)

// keyBytes returns the marshaled memory image of a filter_rule_key exactly as
// it goes to bpf_map_update_elem (cilium/ebpf marshals structs via their
// native memory layout).
func keyBytes(k *bpf.FilterRuleKey) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(k)), unsafe.Sizeof(*k))
}

// valBytes is the memory image of a filter_rule value.
func valBytes(v *bpf.FilterRule) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(v)), unsafe.Sizeof(*v))
}

func TestEncodeInlineRuleKernelKeyBytes(t *testing.T) {
	key, val, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{
		ID:           42,
		DstIP:        "198.51.100.7",
		DstPrefixLen: 32,
		SrcIP:        "203.0.113.9",
		SrcPrefixLen: 32,
		Protocol:     6,
		DstPort:      443,
		SrcPort:      40000,
		Action:       "drop",
		Priority:     20,
		ExpiresNS:    1700000000000000000,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Prefix lens must be zero: filter_exact_lookup() zeroes them before every
	// hash lookup; a non-zero value makes the marshaled key a different
	// hash-map entry than the kernel constructs, and the rule would never match.
	if key.DstPrefixLen != 0 || key.SrcPrefixLen != 0 {
		t.Errorf("prefix lens = (%d,%d), want (0,0) for exact hash rules",
			key.DstPrefixLen, key.SrcPrefixLen)
	}

	// Expected memory image (little-endian struct layout):
	//   u32 dst_prefix_len = 0, u32 src_prefix_len = 0,
	//   u8 dst_addr[16], u8 src_addr[16], u8 proto, u8 pad[3],
	//   u16 dst_port, u16 src_port (wire/network byte order).
	var want bpf.FilterRuleKey // zero value == the kernel's `struct filter_rule_key k = {}`
	copy(want.DstAddr[:4], []byte{198, 51, 100, 7})
	copy(want.SrcAddr[:4], []byte{203, 0, 113, 9})
	want.Proto = 6
	// The kernel memcpy's wire bytes into the __u16 fields: 443 -> 0x01BB,
	// 40000 -> 0x9C40, each stored big-endian in memory.
	want.DstPort = nativeOfWire(443)
	want.SrcPort = nativeOfWire(40000)

	got := keyBytes(&key)
	wantRaw := keyBytes(&want)
	if len(got) != len(wantRaw) {
		t.Fatalf("key size = %d, kernel constructs %d", len(got), len(wantRaw))
	}
	for i := range wantRaw {
		if got[i] != wantRaw[i] {
			t.Fatalf("key byte[%d] = %#02x, want %#02x\n got=% x\nwant=% x",
				i, got[i], wantRaw[i], got, wantRaw)
		}
	}

	// Value layout: action, encap, pad, egress_ifindex, rate_limit_pps,
	// priority, rule_id, expires_ns — mirrors struct filter_rule.
	vb := valBytes(&val)
	if vb[0] != bpf.FilterActionDrop {
		t.Errorf("action byte = %d, want DROP(%d)", vb[0], bpf.FilterActionDrop)
	}
	if vb[1] != bpf.EncapNone {
		t.Errorf("encap byte = %d, want NONE", vb[1])
	}
	if binary.LittleEndian.Uint32(vb[8:12]) != 0 {
		t.Errorf("rate_limit_pps = %d, want 0 for a plain drop",
			binary.LittleEndian.Uint32(vb[8:12]))
	}
	if binary.LittleEndian.Uint32(vb[12:16]) != 20 {
		t.Errorf("priority = %d, want 20", binary.LittleEndian.Uint32(vb[12:16]))
	}
	if binary.LittleEndian.Uint64(vb[16:24]) != 42 {
		t.Errorf("rule id = %d, want 42", binary.LittleEndian.Uint64(vb[16:24]))
	}
	if binary.LittleEndian.Uint64(vb[24:32]) != 1700000000000000000 {
		t.Errorf("expiry = %d, want 1700000000000000000", binary.LittleEndian.Uint64(vb[24:32]))
	}
	// Encap_daddr is appended after src_port (offset 40) to preserve every
	// existing field offset; it is stored as network-byte-order IPv4 bytes.
	if binary.LittleEndian.Uint32(vb[40:44]) != 0 {
		t.Errorf("encap_daddr = %#x, want 0 for a plain drop",
			binary.LittleEndian.Uint32(vb[40:44]))
	}
}

// nativeOfWire reinterprets network byte order bytes as a native __u16 — the
// byte image the kernel memcpy's from the packet.
func nativeOfWire(port uint16) uint16 {
	var wire [2]byte
	wire[0] = byte(port >> 8)
	wire[1] = byte(port)
	return *(*uint16)(unsafe.Pointer(&wire[0]))
}

func TestEncodeInlineRulePortByteOrder(t *testing.T) {
	key, _, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{
		DstIP: "198.51.100.7", DstPrefixLen: 32, Protocol: 6, DstPort: 443, Action: "drop",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := keyBytes(&key)
	// Layout offsets: u32+u32 prefix, 16 dst, 16 src, u8 proto, 3 pad → 42.
	off := 4 + 4 + 16 + 16 + 1 + 3
	if raw[off] != 0x01 || raw[off+1] != 0xBB {
		t.Fatalf("dst_port bytes = [%02x %02x], want [01 bb] (network order)",
			raw[off], raw[off+1])
	}
}

func TestEncodeInlineRuleWildcardOmitsPorts(t *testing.T) {
	key, _, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{
		DstIP: "198.51.100.7", DstPrefixLen: 32, Action: "rate_limit", RateLimitPPS: 20000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.DstPort != 0 || key.SrcPort != 0 || key.Proto != 0 {
		t.Errorf("broad rule must leave ports/proto zero, got proto=%d dport=%#x sport=%#x",
			key.Proto, key.DstPort, key.SrcPort)
	}
}

func TestEncodeInlineRuleActions(t *testing.T) {
	for name, want := range map[string]uint8{
		"":           bpf.FilterActionPass,
		"pass":       bpf.FilterActionPass,
		"drop":       bpf.FilterActionDrop,
		"tx":         bpf.FilterActionTX,
		"redirect":   bpf.FilterActionRedirect,
		"rate_limit": bpf.FilterActionRateLimit,
		"syn_cookie": bpf.FilterActionSynCookie,
		"challenge":  bpf.FilterActionChallenge,
	} {
		got, err := bpf.ParseAction(name)
		if err != nil {
			t.Errorf("ParseAction(%q): %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("ParseAction(%q) = %d, want %d", name, got, want)
		}
	}
	if _, err := bpf.ParseAction("reject"); err == nil {
		t.Error("unknown action accepted")
	}
	for name, want := range map[string]uint8{
		"":       bpf.EncapNone,
		"none":   bpf.EncapNone,
		"gre":    bpf.EncapGRE,
		"geneve": bpf.EncapGeneve,
	} {
		got, err := bpf.ParseEncap(name)
		if err != nil || got != want {
			t.Errorf("ParseEncap(%q) = (%d,%v), want %d", name, got, err, want)
		}
	}
	if _, err := bpf.ParseEncap("vxlan"); err == nil {
		t.Error("unknown encap accepted")
	}
}

func TestEncodeInlineRuleEncapAndDaddr(t *testing.T) {
	_, val, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{
		ID: 71, DstIP: "192.0.2.1", Action: "redirect",
		Encap: "gre", EncapDaddr: "203.0.113.9", EgressIfindex: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if val.Encap != bpf.EncapGRE {
		t.Errorf("encap = %d, want GRE(%d)", val.Encap, bpf.EncapGRE)
	}
	// The field's byte image must be the network-order address (203.0.113.9).
	if want := binary.NativeEndian.Uint32([]byte{203, 0, 113, 9}); val.EncapDaddr != want {
		t.Errorf("encap_daddr = %#x, want %#x", val.EncapDaddr, want)
	}
	// Egress 0 is preserved: the data plane substitutes CFG_EGRESS_IFINDEX.
	if val.EgressIfindex != 0 {
		t.Errorf("egress_ifindex = %d, want 0", val.EgressIfindex)
	}

	// GENEVE is declared on the wire but not implemented; reject at install.
	if _, _, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{
		DstIP: "192.0.2.1", Action: "redirect", Encap: "geneve",
	}); err == nil {
		t.Error("geneve encap accepted; want install-time error")
	}

	// Subnet rules carry the same encap fields.
	_, sval, err := bpf.EncodeInlineSubnet(bpf.InlineRuleSpec{
		DstIP: "192.0.2.0", DstPrefixLen: 24, Action: "redirect",
		Encap: "gre", EncapDaddr: "198.51.100.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sval.EncapDaddr != binary.NativeEndian.Uint32([]byte{198, 51, 100, 7}) {
		t.Errorf("subnet encap_daddr = %#x, want network-order 198.51.100.7", sval.EncapDaddr)
	}

	// A non-IPv4 tunnel destination cannot be encoded in the IPv4 field.
	if _, _, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{
		Action: "redirect", Encap: "gre", EncapDaddr: "2001:db8::1",
	}); err == nil {
		t.Error("IPv6 encap_daddr accepted, want error")
	}
}

func TestEncodeInlineRuleIPv6AndErrors(t *testing.T) {
	key, _, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{
		DstIP: "2001:db8::7", Protocol: 17, DstPort: 53,
		Action: "redirect", Encap: "gre", EgressIfindex: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}
	if key.DstAddr != want {
		t.Errorf("v6 addr = % x, want % x", key.DstAddr, want)
	}
	if _, _, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{DstIP: "not-an-ip", Action: "drop"}); err == nil {
		t.Error("bad IP accepted")
	}
	// A rule with no destination is legal: it keys on source only (egress ACL).
	if _, _, err := bpf.EncodeInlineRule(bpf.InlineRuleSpec{Action: "drop"}); err != nil {
		t.Errorf("wildcard rule: %v", err)
	}
}

func TestEncodeInlineSubnetKeepsRealPrefixLen(t *testing.T) {
	// /24 → LPM trie with a REAL prefix length (unlike exact hash rules,
	// whose lens are zeroed because the kernel does the same).
	key, val, err := bpf.EncodeInlineSubnet(bpf.InlineRuleSpec{
		ID: 7, DstIP: "203.0.113.240", DstPrefixLen: 24,
		Action: "rate_limit", RateLimitPPS: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.Prefixlen != 24 {
		t.Errorf("prefixlen = %d, want 24", key.Prefixlen)
	}
	if key.Addr[0] != 203 || key.Addr[1] != 0 || key.Addr[2] != 113 || key.Addr[3] != 240 {
		t.Errorf("subnet addr bytes = % x, want cb 00 71 f0", key.Addr[:4])
	}
	if val.Action != bpf.FilterActionRateLimit {
		t.Errorf("action = %d, want RATE_LIMIT", val.Action)
	}
	if binary.LittleEndian.Uint32(valBytes(&val)[8:12]) != 1000 {
		t.Errorf("rate_limit_pps = %d, want 1000", binary.LittleEndian.Uint32(valBytes(&val)[8:12]))
	}

	// Source-only subnet (egress ACL): destination wildcarded.
	key2, _, err := bpf.EncodeInlineSubnet(bpf.InlineRuleSpec{
		SrcIP: "192.0.2.128", SrcPrefixLen: 25, Action: "drop",
	})
	if err != nil {
		t.Fatal(err)
	}
	if key2.Prefixlen != 25 {
		t.Errorf("src subnet prefixlen = %d, want 25", key2.Prefixlen)
	}
	if key2.Addr[0] != 192 || key2.Addr[3] != 128 {
		t.Errorf("src subnet addr = % x, want c0 00 02 80", key2.Addr[:4])
	}

	// A subnet rule with no address at all is a configuration error.
	if _, _, err := bpf.EncodeInlineSubnet(bpf.InlineRuleSpec{Action: "drop"}); err == nil {
		t.Error("subnet rule without address accepted")
	}
}

func TestClassifyInlineRuleRoutesMixedPrefixes(t *testing.T) {
	cases := []struct {
		name string
		spec bpf.InlineRuleSpec
		want bpf.InlineRuleTarget
	}{
		{
			name: "exact",
			spec: bpf.InlineRuleSpec{DstIP: "198.51.100.7"},
			want: bpf.InlineRuleTargetExact,
		},
		{
			name: "dst-subnet",
			spec: bpf.InlineRuleSpec{DstIP: "198.51.100.0", DstPrefixLen: 24},
			want: bpf.InlineRuleTargetSubnetDst,
		},
		{
			// A /32 host prefix is not a subnet: it must use the exact hash
			// table so per-port rules for the same host do not overwrite each
			// other in the address-keyed LPM trie.
			name: "dst-host-v4",
			spec: bpf.InlineRuleSpec{DstIP: "198.51.100.7", DstPrefixLen: 32},
			want: bpf.InlineRuleTargetExact,
		},
		{
			name: "dst-host-v6",
			spec: bpf.InlineRuleSpec{DstIP: "2001:db8::7", DstPrefixLen: 128},
			want: bpf.InlineRuleTargetExact,
		},
		{
			name: "dst-host-v4-src-exact",
			spec: bpf.InlineRuleSpec{
				DstIP: "198.51.100.7", DstPrefixLen: 32, SrcIP: "203.0.113.9",
			},
			want: bpf.InlineRuleTargetExact,
		},
		{
			// Mixed host-dst + source prefix: the source prefix still wins
			// (source LPM); the destination host constraint is not representable
			// in the address-keyed tries.
			name: "mixed-host-dst-src-prefix",
			spec: bpf.InlineRuleSpec{
				DstIP: "203.0.113.7", DstPrefixLen: 32,
				SrcIP: "198.51.100.0", SrcPrefixLen: 24,
			},
			want: bpf.InlineRuleTargetSubnetSrc,
		},
		{
			name: "src-subnet",
			spec: bpf.InlineRuleSpec{SrcIP: "198.51.100.0", SrcPrefixLen: 24},
			want: bpf.InlineRuleTargetSubnetSrc,
		},
		{
			name: "mixed-exact-dst-src-prefix",
			spec: bpf.InlineRuleSpec{
				DstIP: "203.0.113.7", SrcIP: "198.51.100.0", SrcPrefixLen: 24,
			},
			want: bpf.InlineRuleTargetSubnetSrc,
		},
		{
			name: "mixed-dst-prefix-src-exact",
			spec: bpf.InlineRuleSpec{
				DstIP: "203.0.113.0", DstPrefixLen: 24, SrcIP: "198.51.100.9",
			},
			want: bpf.InlineRuleTargetSubnetDst,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bpf.ClassifyInlineRule(tc.spec); got != tc.want {
				t.Fatalf("ClassifyInlineRule = %d, want %d", got, tc.want)
			}
		})
	}

	// Mixed exact-dst + src-prefix must encode the source side of the LPM key.
	key, _, err := bpf.EncodeInlineSubnet(bpf.InlineRuleSpec{
		DstIP: "203.0.113.7", SrcIP: "198.51.100.0", SrcPrefixLen: 24, Action: "drop",
	})
	if err != nil {
		t.Fatal(err)
	}
	if key.Prefixlen != 24 || key.Addr[0] != 198 || key.Addr[3] != 0 {
		t.Errorf("mixed rule key = %+v, want source 198.51.100.0/24", key)
	}
}

func TestRuleExpiryNS(t *testing.T) {
	const base = uint64(1_000_000)
	if got := bpf.RuleExpiryNS(0, 100, base); got != 0 {
		t.Errorf("zero expiry = %d, want 0 (never)", got)
	}
	if got := bpf.RuleExpiryNS(150, 100, base); got != base+50_000_000_000 {
		t.Errorf("50s TTL = %d, want %d", got, base+50_000_000_000)
	}
	// An expiry at or before "now" is already elapsed: clamp to a tiny positive
	// deadline instead of installing an immortal rule.
	for _, exp := range []int64{100, 99, -1} {
		if got := bpf.RuleExpiryNS(exp, 100, base); got != base+1 {
			t.Errorf("expiry %d relative to now = %d, want %d", exp, got, base+1)
		}
	}
}

func TestBurstAlertHelpers(t *testing.T) {
	a := bpf.BurstAlert{IsV4: 1}
	copy(a.DstAddr[:4], []byte{198, 51, 100, 7})
	ip := a.DstIP()
	if len(ip) != 4 || ip[0] != 198 || ip[3] != 7 {
		t.Errorf("DstIP = %v, want 198.51.100.7", ip)
	}
	a6 := bpf.BurstAlert{}
	copy(a6.DstAddr[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7})
	if got := a6.DstIP().String(); got != "2001:db8::7" {
		t.Errorf("DstIP v6 = %s, want 2001:db8::7", got)
	}
}
