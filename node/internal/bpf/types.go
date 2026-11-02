package bpf

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/d80y6/YemenDDoS/shared/decoder"
)

// SampleHdr mirrors struct sample_hdr in xsight.h.
// Prefixed to each ring buffer record to carry effective length.
type SampleHdr struct {
	CapLen uint32 // actual captured bytes
	PktLen uint32 // original packet length on wire
}

// SampleHdrSize is the byte size of SampleHdr (used by sampler).
const SampleHdrSize = 8

// GlobalStats mirrors struct global_stats in xsight.h.
// v2.11: added MatchedBytes + per-decoder breakdown for global threshold detection.
// v2.11 Phase 2: added outbound (src_ip matched) counters.
type GlobalStats struct {
	TotalPkts         uint64
	TotalBytes        uint64
	MatchedPkts       uint64
	MatchedBytes      uint64                      // bytes within watch scope (for global ip+bps)
	SampleDrops       uint64                      // ring buffer reserve failures (backpressure signal)
	DecoderCounts     [decoder.MaxDecoders]uint32 // per-decoder PPS (inbound matched only)
	DecoderByteCounts [decoder.MaxDecoders]uint64 // per-decoder BPS (inbound matched only)
	// Outbound (src_ip matched) global counters
	SrcMatchedPkts       uint64
	SrcMatchedBytes      uint64
	SrcDecoderCounts     [decoder.MaxDecoders]uint32
	SrcDecoderByteCounts [decoder.MaxDecoders]uint64
}

// DstIPStats mirrors struct dst_ip_stats in xsight.h.
// DecoderCounts is indexed by shared/decoder constants.
type DstIPStats struct {
	PktCount          uint64
	ByteCount         uint64
	DecoderCounts     [decoder.MaxDecoders]uint32 // indexed by decoder.TCP, decoder.UDP, etc.
	DecoderByteCounts [decoder.MaxDecoders]uint64 // per-decoder byte counts for BPS thresholds
	SmallPkt          uint32
	MediumPkt         uint32
	LargePkt          uint32
	_                 [4]byte // padding to match BPF struct alignment (bpf2go generated)
}

// PrefixStats mirrors struct prefix_stats in xsight.h.
// DecoderCounts is indexed by shared/decoder constants.
type PrefixStats struct {
	PktCount          uint64
	ByteCount         uint64
	OverflowCount     uint32
	Pad               uint32                      // alignment padding, matches BPF struct
	DecoderCounts     [decoder.MaxDecoders]uint32 // indexed by decoder.TCP, decoder.UDP, etc.
	DecoderByteCounts [decoder.MaxDecoders]uint64 // per-decoder byte counts for BPS thresholds
}

// LPMKey mirrors struct lpm_key in xsight.h.
type LPMKey struct {
	Prefixlen uint32
	Addr      [16]byte
}

// PrefixKey mirrors struct prefix_key in xsight.h.
type PrefixKeyGo struct {
	Addr      [16]byte
	Prefixlen uint32
}

// PrefixEntry is a convenience type for specifying watch prefixes.
type PrefixEntry struct {
	Net       net.IPNet
	Prefixlen uint32
}

// isIPv4MappedPrefix checks the original address independently of mask syntax.
func isIPv4MappedPrefix(cidr string) bool {
	address, _, _ := strings.Cut(cidr, "/")
	if ip, err := netip.ParseAddr(address); err == nil && ip.Is4In6() {
		return true
	}
	ip := net.ParseIP(address)
	return strings.Contains(address, ":") && ip != nil && ip.To4() != nil
}

// ParsePrefix parses a CIDR string into a PrefixEntry.
func ParsePrefix(cidr string) (PrefixEntry, error) {
	if isIPv4MappedPrefix(cidr) {
		return PrefixEntry{}, fmt.Errorf("use IPv4 notation for IPv4-mapped prefix %q", cidr)
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return PrefixEntry{}, fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	ones, _ := ipnet.Mask.Size()
	return PrefixEntry{Net: *ipnet, Prefixlen: uint32(ones)}, nil
}

// LPMKey returns the BPF LPM trie key for this prefix.
func (p PrefixEntry) LPMKey() LPMKey {
	key := LPMKey{Prefixlen: p.Prefixlen}
	ip := p.Net.IP
	if ip4 := ip.To4(); ip4 != nil {
		key.Addr[10], key.Addr[11] = 0xff, 0xff
		copy(key.Addr[12:], ip4)
		key.Prefixlen += 96
	} else {
		copy(key.Addr[:], ip.To16())
	}
	return key
}

// PrefixKey returns the BPF prefix_stats map key for this prefix.
func (p PrefixEntry) PrefixKey() PrefixKeyGo {
	pkey := PrefixKeyGo{Prefixlen: p.Prefixlen}
	ip := p.Net.IP
	if ip4 := ip.To4(); ip4 != nil {
		pkey.Addr[10], pkey.Addr[11] = 0xff, 0xff
		copy(pkey.Addr[12:], ip4)
		pkey.Prefixlen += 96
	} else {
		copy(pkey.Addr[:], ip.To16())
	}
	return pkey
}

// PrefixKeyToIPNet decodes prefix keys; per-IP HASH keys use a separate format.
func PrefixKeyToIPNet(k PrefixKeyGo) net.IPNet {
	ones := int(k.Prefixlen)
	isV4 := ones >= 96 && k.Addr[10] == 0xff && k.Addr[11] == 0xff
	for i := 0; i < 10; i++ {
		isV4 = isV4 && k.Addr[i] == 0
	}
	if isV4 {
		return net.IPNet{IP: net.IP(k.Addr[12:]), Mask: net.CIDRMask(ones-96, 32)}
	}
	return net.IPNet{IP: net.IP(k.Addr[:]), Mask: net.CIDRMask(ones, 128)}
}

// String returns the CIDR notation.
func (p PrefixEntry) String() string {
	return p.Net.String()
}
