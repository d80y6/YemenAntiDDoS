//go:build linux

// Inline scrubbing support: active filter rules, SYN-cookie engine controls,
// burst alert consumption, and clean-pipe egress configuration.
//
// The BPF-side contracts live in node/bpf/xsight.h (v4.0 block). This file
// owns the userspace half: rule table maintenance, config-map plumbing and
// the CriticalEventStream feeder that drains the kernel alert ringbuf.

package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// Inline config-map indices (CFG_* in xsight.h).
const (
	CfgInlineEnable    uint32 = 4
	CfgSynCookieEnable uint32 = 5
	CfgCookieSecretLo  uint32 = 6
	CfgCookieSecretHi  uint32 = 7
	CfgEgressIfindex   uint32 = 8
	CfgBurstPPS        uint32 = 9
	CfgAlertsEnable    uint32 = 10
	CfgDNSProtect      uint32 = 11
	CfgInlineSample    uint32 = 12
	CfgEgressSaddr     uint32 = 13
)

// Filter actions (FILTER_ACTION_* in xsight.h).
const (
	FilterActionPass      uint8 = 0
	FilterActionDrop      uint8 = 1
	FilterActionTX        uint8 = 2
	FilterActionRedirect  uint8 = 3
	FilterActionRateLimit uint8 = 4
	FilterActionSynCookie uint8 = 5
	FilterActionChallenge uint8 = 6
)

// Encap kinds (ENCAP_* in xsight.h).
const (
	EncapNone   uint8 = 0
	EncapGRE    uint8 = 1
	EncapGeneve uint8 = 2
)

// FilterRuleKey mirrors struct filter_rule_key (xsight.h).
// IPv4 addresses occupy the first four bytes; prefix lens are host-length.
type FilterRuleKey struct {
	DstPrefixLen uint32
	SrcPrefixLen uint32
	DstAddr      [16]byte
	SrcAddr      [16]byte
	Proto        uint8
	_            [3]byte
	DstPort      uint16 // network byte order
	SrcPort      uint16 // network byte order
}

// FilterRule mirrors struct filter_rule (xsight.h).
type FilterRule struct {
	Action        uint8
	Encap         uint8
	_             uint16
	EgressIfindex uint32
	RateLimitPPS  uint32
	Priority      uint32
	RuleID        uint64
	ExpiresNS     uint64 // monotonic ktime deadline, 0 = never
	Proto         uint8
	_             [3]byte
	DstPort       uint16
	SrcPort       uint16
	EncapDaddr    uint32 // GRE outer IPv4 destination, network byte order
	_             [4]byte
}

// BurstAlert mirrors struct burst_alert (xsight.h) — the ringbuf record.
type BurstAlert struct {
	TimestampNS uint64
	DstAddr     [16]byte
	IsV4        uint32
	WindowPPS   uint32
	Proto       uint32
	TCPFlags    uint32
}

// DstIP returns the alerted destination as a Go IP.
func (a BurstAlert) DstIP() net.IP {
	if a.IsV4 == 1 {
		return net.IP(a.DstAddr[:4])
	}
	return net.IP(a.DstAddr[:])
}

// InlineRuleSpec is a controller-supplied filter rule before BPF encoding.
// It mirrors proto InlineRule so the bpf package stays protobuf-free.
type InlineRuleSpec struct {
	ID            uint64
	DstIP         string // "" = any destination (src-only ACLs)
	DstPrefixLen  int
	SrcIP         string // "" = any source
	SrcPrefixLen  int
	Protocol      uint32 // 0 = any
	DstPort       uint32 // 0 = any
	SrcPort       uint32 // 0 = any
	Action        string // "pass"|"drop"|"tx"|"redirect"|"rate_limit"|"syn_cookie"|"challenge"
	RateLimitPPS  uint64
	Priority      uint32
	ExpiresUnix   int64  // controller wall-clock expiry, 0 = until withdrawn
	ExpiresNS     uint64 // monotonic kernel deadline; install layer converts ExpiresUnix
	EgressIfindex uint32
	Encap         string // ""|"gre"|"geneve"
	EncapDaddr    string // GRE outer IPv4 destination ("" = 0)
}

// ParseAction converts an InlineRule.action string to its BPF constant.
func ParseAction(s string) (uint8, error) {
	switch s {
	case "", "pass":
		return FilterActionPass, nil
	case "drop":
		return FilterActionDrop, nil
	case "tx":
		return FilterActionTX, nil
	case "redirect":
		return FilterActionRedirect, nil
	case "rate_limit":
		return FilterActionRateLimit, nil
	case "syn_cookie":
		return FilterActionSynCookie, nil
	case "challenge":
		return FilterActionChallenge, nil
	default:
		return 0, fmt.Errorf("unknown inline action %q", s)
	}
}

// ParseEncap converts an InlineRule.encap string to its BPF constant.
func ParseEncap(s string) (uint8, error) {
	switch s {
	case "", "none":
		return EncapNone, nil
	case "gre":
		return EncapGRE, nil
	case "geneve":
		return EncapGeneve, nil
	default:
		return 0, fmt.Errorf("unknown encap %q", s)
	}
}

// MonotonicNowNS returns CLOCK_MONOTONIC in nanoseconds. This is the same
// clock domain as bpf_ktime_get_ns(), so deadlines computed from it can be
// compared directly in the kernel.
func MonotonicNowNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		// CLOCK_MONOTONIC is always available on Linux. Returning 0 makes any
		// deadline computed from it already elapsed rather than silently
		// falling back to wall time.
		return 0
	}
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// RuleExpiryNS converts a controller wall-clock expiry (Unix seconds) into a
// monotonic kernel deadline. expiresUnix == 0 means "until withdrawn". An
// expiry at or before now is already elapsed, so it is clamped to a deadline
// one nanosecond in the future instead of becoming an immortal rule.
func RuleExpiryNS(expiresUnix, nowUnix int64, nowNS uint64) uint64 {
	if expiresUnix == 0 {
		return 0
	}
	ttl := expiresUnix - nowUnix
	if ttl <= 0 {
		return nowNS + 1
	}
	return nowNS + uint64(ttl)*1_000_000_000
}

// parseEncapForInstall validates an encapsulation kind for the data plane.
// GENEVE is declared in the wire protocol but intentionally not implemented;
// rejecting it here prevents a silent plain redirect.
func parseEncapForInstall(s string) (uint8, error) {
	encap, err := ParseEncap(s)
	if err != nil {
		return 0, err
	}
	if encap == EncapGeneve {
		return 0, errors.New("geneve encapsulation not supported; use gre")
	}
	return encap, nil
}

// ipv4NetworkOrder encodes an IPv4 literal as a u32 whose in-memory bytes are
// the network-byte-order address, matching iphdr.daddr. The kernel copies the
// field straight into the header, so the byte image (not the host-order
// number) is what matters. An empty string maps to zero.
func ipv4NetworkOrder(ipStr string) (uint32, error) {
	if ipStr == "" {
		return 0, nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("bad encap_daddr %q", ipStr)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0, fmt.Errorf("encap_daddr %q must be IPv4", ipStr)
	}
	return binary.NativeEndian.Uint32(ip4), nil
}

// InlineRuleTarget identifies the kernel filter table a spec belongs to.
type InlineRuleTarget int

const (
	InlineRuleTargetExact InlineRuleTarget = iota
	InlineRuleTargetSubnetDst
	InlineRuleTargetSubnetSrc
)

// inlineHostPrefix reports whether prefixLen addresses a single host for the
// given IP literal: /32 for IPv4 and /128 for IPv6. Prefix lengths are matched
// to the parsed address family rather than assuming IPv4.
func inlineHostPrefix(ipStr string, prefixLen int) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.To4() != nil {
		return prefixLen == 32
	}
	return prefixLen == 128
}

// ClassifyInlineRule routes a rule to the exact hash table or one of the two
// subnet tries. A host destination prefix (/32 IPv4, /128 IPv6) with no source
// prefix is an exact-match rule: the LPM tries key on address+prefix only, so
// per-port rules for the same host would otherwise overwrite one another.
// A source prefix wins over the destination, so a mixed host-dst + source-prefix
// rule is written to the source trie. NOTE: for that mixed case the destination
// constraint is not representable in the address-keyed tries and is therefore
// not enforced in the kernel table.
func ClassifyInlineRule(spec InlineRuleSpec) InlineRuleTarget {
	if spec.SrcPrefixLen > 0 {
		return InlineRuleTargetSubnetSrc
	}
	if spec.DstPrefixLen > 0 && !inlineHostPrefix(spec.DstIP, spec.DstPrefixLen) {
		return InlineRuleTargetSubnetDst
	}
	return InlineRuleTargetExact
}

// addr16ForRule encodes an IP into the raw 16-byte rule layout.
// IPv4 keeps host length in the prefix len (no v4-mapped trie offset — the
// inline tables are separate from the watch tries).
func addr16ForRule(ipStr string, prefixLen int) ([16]byte, uint32, error) {
	var out [16]byte
	if ipStr == "" {
		return out, 0, nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return out, 0, fmt.Errorf("bad rule IP %q", ipStr)
	}
	if ip4 := ip.To4(); ip4 != nil {
		copy(out[:4], ip4)
		if prefixLen <= 0 || prefixLen > 32 {
			prefixLen = 32
		}
		return out, uint32(prefixLen), nil
	}
	copy(out[:], ip.To16())
	if prefixLen <= 0 || prefixLen > 128 {
		prefixLen = 128
	}
	return out, uint32(prefixLen), nil
}

// wirePortKey returns the uint16 whose native in-memory byte order equals the
// network byte order of the port: the kernel builds filter_rule_key.dst_port by
// memcpy'ing the two wire bytes, so the marshaled bytes must be [hi, lo] on every
// architecture.
func wirePortKey(port uint32) uint16 {
	var wire [2]byte
	binary.BigEndian.PutUint16(wire[:], uint16(port)) // memory bytes we need
	return binary.NativeEndian.Uint16(wire[:])        // reinterpret as the field type
}

// EncodeInlineRule converts a spec into the BPF hash key/value pair.
func EncodeInlineRule(spec InlineRuleSpec) (FilterRuleKey, FilterRule, error) {
	var key FilterRuleKey
	var val FilterRule

	action, err := ParseAction(spec.Action)
	if err != nil {
		return key, val, err
	}
	encap, err := parseEncapForInstall(spec.Encap)
	if err != nil {
		return key, val, err
	}
	encapDaddr, err := ipv4NetworkOrder(spec.EncapDaddr)
	if err != nil {
		return key, val, err
	}
	dstAddr, _, err := addr16ForRule(spec.DstIP, spec.DstPrefixLen)
	if err != nil {
		return key, val, err
	}
	srcAddr, _, err := addr16ForRule(spec.SrcIP, spec.SrcPrefixLen)
	if err != nil {
		return key, val, err
	}

	// filter_exact_lookup (xsight.c) zeroes dst_prefix_len/src_prefix_len before
	// every bpf_map_lookup_elem call: the hash table never keys on them, and a
	// non-zero value here would make the marshaled key differ byte-for-byte from
	// the kernel's constructed key, so the rule would silently never match.
	// Subnet-scope rules go to the LPM trie (EncodeInlineSubnet) instead, where
	// the prefix length is part of the real key.
	key.DstPrefixLen = 0
	key.SrcPrefixLen = 0
	key.DstAddr = dstAddr
	key.SrcAddr = srcAddr
	key.Proto = uint8(spec.Protocol)
	// The kernel copies the ports straight off the wire, so the key's memory
	// layout must hold the network byte order (big-endian) bytes — NOT the
	// host-order value (reversed on little-endian).
	key.DstPort = wirePortKey(spec.DstPort)
	key.SrcPort = wirePortKey(spec.SrcPort)

	val.Proto = key.Proto
	val.DstPort = key.DstPort
	val.SrcPort = key.SrcPort
	val.Action = action
	val.Encap = encap
	val.EgressIfindex = spec.EgressIfindex
	val.RateLimitPPS = uint32(spec.RateLimitPPS)
	val.Priority = spec.Priority
	val.RuleID = spec.ID
	val.ExpiresNS = spec.ExpiresNS
	val.EncapDaddr = encapDaddr
	return key, val, nil
}

// EncodeInlineSubnet builds the LPM key for subnet-scope rules.
func EncodeInlineSubnet(spec InlineRuleSpec) (LPMKey, FilterRule, error) {
	var key LPMKey
	var val FilterRule

	action, err := ParseAction(spec.Action)
	if err != nil {
		return key, val, err
	}
	encap, err := parseEncapForInstall(spec.Encap)
	if err != nil {
		return key, val, err
	}
	encapDaddr, err := ipv4NetworkOrder(spec.EncapDaddr)
	if err != nil {
		return key, val, err
	}

	// Source-prefixed rules (including mixed exact-dst + src-prefix) use the
	// source trie; all other subnet rules use the destination trie.
	addrStr, prefixLen := spec.DstIP, spec.DstPrefixLen
	if ClassifyInlineRule(spec) == InlineRuleTargetSubnetSrc {
		addrStr, prefixLen = spec.SrcIP, spec.SrcPrefixLen
	}
	if addrStr == "" {
		return key, val, fmt.Errorf("subnet rule %d has no address", spec.ID)
	}
	ip := net.ParseIP(addrStr)
	if ip == nil {
		return key, val, fmt.Errorf("bad subnet IP %q", addrStr)
	}
	if ip4 := ip.To4(); ip4 != nil {
		if prefixLen <= 0 || prefixLen > 32 {
			prefixLen = 32
		}
		copy(key.Addr[:4], ip4)
		key.Prefixlen = uint32(prefixLen)
	} else {
		if prefixLen <= 0 || prefixLen > 128 {
			prefixLen = 128
		}
		copy(key.Addr[:], ip.To16())
		key.Prefixlen = uint32(prefixLen)
	}

	val.Proto = uint8(spec.Protocol)
	val.DstPort = wirePortKey(spec.DstPort)
	val.SrcPort = wirePortKey(spec.SrcPort)
	val.Action = action
	val.Encap = encap
	val.EgressIfindex = spec.EgressIfindex
	val.RateLimitPPS = uint32(spec.RateLimitPPS)
	val.Priority = spec.Priority
	val.RuleID = spec.ID
	val.ExpiresNS = spec.ExpiresNS
	val.EncapDaddr = encapDaddr
	return key, val, nil
}

// InlineStats is a snapshot of the kernel inline counters.
type InlineStats struct {
	CookieReplies     uint64
	CookieValidated   uint64
	CookieDropped     uint64
	EmergencyDrops    uint64
	FilterDrops       uint64
	DNSDrops          uint64
	RedirectOK        uint64
	RedirectErr       uint64
	XSKSteered        uint64
	FilterPass        uint64
	ValidatedClients  uint64
	ActiveFilterRules uint64
}

// ApplyInlineRules atomically replaces the kernel filter tables.
// Exact 5-tuple specs go to the hash map; subnet-scope specs go to the LPM
// trie. When defaultAction is "drop" a lowest-priority catch-all rule is
// installed first (all-zero key = global wildcard) so unmatched traffic is
// dropped; it is cleared again on the next snapshot that is not drop-default
// (including an empty withdraw push). Rules are applied to a shadow copy only
// when the swap fails entirely (map updates are per-entry; a partial failure
// keeps previously applied entries which the controller reconciles on the next
// push).
func (m *Manager) ApplyInlineRules(specs []InlineRuleSpec, defaultAction string) error {
	if m.Objs == nil {
		return fmt.Errorf("bpf: not loaded")
	}

	// Clear both tables, then repopulate. Tables are small (controller-curated),
	// so clear+fill beats diffing for determinism.
	if err := clearExactMap(m.Objs.ActiveFilterRules); err != nil {
		return fmt.Errorf("clear active_filter_rules: %w", err)
	}
	if err := clearMap(m.Objs.ActiveFilterSubnetsDst); err != nil {
		return fmt.Errorf("clear active_filter_subnets_dst: %w", err)
	}
	if err := clearMap(m.Objs.ActiveFilterSubnetsSrc); err != nil {
		return fmt.Errorf("clear active_filter_subnets_src: %w", err)
	}

	// Install the catch-all before the snapshot rules: a controller-supplied
	// global rule shares the same all-zero key and must win over the default.
	if defaultAction == "drop" {
		var key FilterRuleKey
		val := FilterRule{Action: FilterActionDrop, Priority: ^uint32(0)}
		if err := m.Objs.ActiveFilterRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("install default-drop rule: %w", err)
		}
	} else if defaultAction != "" && defaultAction != "pass" {
		log.Printf("inline: ignoring unknown default_action %q (treating as pass)", defaultAction)
	}

	applied := 0
	for _, spec := range specs {
		switch ClassifyInlineRule(spec) {
		case InlineRuleTargetSubnetDst, InlineRuleTargetSubnetSrc:
			key, val, err := EncodeInlineSubnet(spec)
			if err != nil {
				log.Printf("inline: skip subnet rule %d: %v", spec.ID, err)
				continue
			}
			subnets := m.Objs.ActiveFilterSubnetsDst
			if ClassifyInlineRule(spec) == InlineRuleTargetSubnetSrc {
				subnets = m.Objs.ActiveFilterSubnetsSrc
			}
			if err := subnets.Update(&key, &val, ebpf.UpdateAny); err != nil {
				log.Printf("inline: subnet rule %d update: %v", spec.ID, err)
				continue
			}
			applied++
		default:
			key, val, err := EncodeInlineRule(spec)
			if err != nil {
				log.Printf("inline: skip rule %d: %v", spec.ID, err)
				continue
			}
			if err := m.Objs.ActiveFilterRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
				log.Printf("inline: rule %d update: %v", spec.ID, err)
				continue
			}
			applied++
		}
	}
	log.Printf("inline: applied %d/%d filter rules", applied, len(specs))
	return nil
}

// clearExactMap clears a hash map keyed by FilterRuleKey.
func clearExactMap(m *ebpf.Map) error {
	var keys []FilterRuleKey
	var k FilterRuleKey
	var v FilterRule
	iter := m.Iterate()
	for iter.Next(&k, &v) {
		keys = append(keys, k)
	}
	for i := range keys {
		_ = m.Delete(&keys[i])
	}
	return iter.Err()
}

// ClearValidatedClients evicts every SYN-cookie-validated client (used when
// the controller rotates the cookie secret).
func (m *Manager) ClearValidatedClients() error {
	var keys [][16]byte
	var k [16]byte
	var v uint64
	iter := m.Objs.ValidatedClients.Iterate()
	for iter.Next(&k, &v) {
		keys = append(keys, k)
	}
	for i := range keys {
		_ = m.Objs.ValidatedClients.Delete(&keys[i])
	}
	return iter.Err()
}

// SetInlineEnabled toggles the inline engine (CFG_INLINE_ENABLE).
func (m *Manager) SetInlineEnabled(on bool) error {
	var v uint64
	if on {
		v = 1
	}
	return m.SetConfig(CfgInlineEnable, v)
}

// SetSynCookieEnabled toggles the SYN-cookie engine.
func (m *Manager) SetSynCookieEnabled(on bool) error {
	var v uint64
	if on {
		v = 1
	}
	return m.SetConfig(CfgSynCookieEnable, v)
}

// SetCookieSecret installs the siphash secret (rotated hourly by the agent).
func (m *Manager) SetCookieSecret(lo, hi uint64) error {
	if err := m.SetConfig(CfgCookieSecretLo, lo); err != nil {
		return err
	}
	return m.SetConfig(CfgCookieSecretHi, hi)
}

// SetBurstThreshold configures the per-destination burst PPS trigger.
func (m *Manager) SetBurstThreshold(pps uint64) error {
	return m.SetConfig(CfgBurstPPS, pps)
}

// SetEgressIfindex configures the clean-pipe egress interface.
func (m *Manager) SetEgressIfindex(idx uint32) error {
	return m.SetConfig(CfgEgressIfindex, uint64(idx))
}

// SetEgressSaddr configures the GRE outer source address. The low 32 bits
// carry the IPv4 address in network byte order.
func (m *Manager) SetEgressSaddr(saddr uint32) error {
	return m.SetConfig(CfgEgressSaddr, uint64(saddr))
}

// SetDNSProtect toggles UDP/DNS reflection defense.
func (m *Manager) SetDNSProtect(on bool) error {
	var v uint64
	if on {
		v = 1
	}
	return m.SetConfig(CfgDNSProtect, v)
}

// SetInlineSampleRate sets the 1-in-N L7 sampling rate for inline mode.
func (m *Manager) SetInlineSampleRate(rate uint32) error {
	return m.SetConfig(CfgInlineSample, uint64(rate))
}

// InlineCounters snapshots the kernel inline_stats array.
func (m *Manager) InlineCounters() InlineStats {
	var out InlineStats
	if m.Objs == nil {
		return out
	}
	read := func(idx uint32) uint64 {
		var v uint64
		_ = m.Objs.InlineStats.Lookup(&idx, &v)
		return v
	}
	out.CookieReplies = read(0)
	out.CookieValidated = read(1)
	out.CookieDropped = read(2)
	out.EmergencyDrops = read(3)
	out.FilterDrops = read(4)
	out.DNSDrops = read(5)
	out.RedirectOK = read(6)
	out.RedirectErr = read(7)
	out.XSKSteered = read(8)
	out.FilterPass = read(9)
	out.ValidatedClients = mapCount(m.Objs.ValidatedClients)
	out.ActiveFilterRules = mapCount(m.Objs.ActiveFilterRules)
	return out
}

func mapCount(m *ebpf.Map) uint64 {
	if m == nil {
		return 0
	}
	n := uint64(0)
	var k, v interface{}
	iter := m.Iterate()
	for iter.Next(&k, &v) {
		n++
	}
	return n
}

// DrainAlerts reads burst alerts from the kernel ringbuf and hands each one
// to `handle`. Blocks until ctx is done; the reader is resilient to ringbuf
// recreation on BPF reload.
func (m *Manager) DrainAlerts(handle func(BurstAlert)) error {
	if m.Objs == nil || m.Objs.Alerts == nil {
		return fmt.Errorf("bpf: alerts ringbuf unavailable")
	}
	reader, err := ringbuf.NewReader(m.Objs.Alerts)
	if err != nil {
		return fmt.Errorf("open alerts ringbuf: %w", err)
	}
	defer reader.Close()
	for {
		rec, err := reader.Read()
		if err != nil {
			if isRingbufClosed(err) {
				return nil
			}
			log.Printf("inline: alerts read: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		a, err := readBurstAlert(rec.RawSample)
		if err != nil {
			continue
		}
		handle(a)
	}
}

func isRingbufClosed(err error) bool {
	return errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, io.EOF)
}

// readBurstAlert decodes one ringbuf record into a BurstAlert.
func readBurstAlert(raw []byte) (BurstAlert, error) {
	var a BurstAlert
	if len(raw) < 40 {
		return a, fmt.Errorf("short alert record %d", len(raw))
	}
	a.TimestampNS = binary.LittleEndian.Uint64(raw[0:8])
	copy(a.DstAddr[:], raw[8:24])
	a.IsV4 = binary.LittleEndian.Uint32(raw[24:28])
	a.WindowPPS = binary.LittleEndian.Uint32(raw[28:32])
	a.Proto = binary.LittleEndian.Uint32(raw[32:36])
	a.TCPFlags = binary.LittleEndian.Uint32(raw[36:40])
	return a, nil
}

// AttachXDPMode attaches an XDP program to an interface in the requested
// execution mode: "driver" (native), "generic", or "offload".
// Offload failures fall back to driver mode (SmartNICs reject ringbuf/prandom
// helpers); driver failures fall back to generic. The effective mode is
// returned for posture reporting.
func (m *Manager) AttachXDPMode(ifaceName, mode string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	linkPinPath := ""
	if m.PinPath != "" {
		linkPinPath = filepathJoinPin(m.PinPath)
	}
	if linkPinPath != "" {
		if old, err := linkLoadPinned(linkPinPath); err == nil {
			_ = old.Unpin()
			_ = old.Close()
		}
	}

	prog := m.Objs.XsightMain
	if m.inlineProgram {
		prog = m.Objs.XdpInline
	}

	type attachMode struct {
		name string
		flag link.XDPAttachFlags
	}
	tryModes := []attachMode{
		{"offload", link.XDPOffloadMode},
		{"driver", link.XDPDriverMode},
		{"generic", link.XDPGenericMode},
	}

	// Build the ordered attempt list from the requested mode.
	var attempts []attachMode
	switch mode {
	case "offload":
		attempts = tryModes
	case "generic":
		attempts = tryModes[2:]
	default: // driver (default)
		attempts = tryModes[1:]
	}

	var lastErr error
	for _, at := range attempts {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: iface.Index,
			Flags:     at.flag,
		})
		if err != nil {
			lastErr = err
			continue
		}
		if linkPinPath != "" {
			if err := l.Pin(linkPinPath); err != nil {
				log.Printf("warning: pin XDP link failed: %v (XDP will detach on exit)", err)
			}
		}
		m.Attachments = append(m.Attachments, XDPAttachment{
			Iface: ifaceName, Link: l, PinPath: linkPinPath,
		})
		log.Printf("XDP attached to %s (%s mode, program=%s)",
			ifaceName, at.name, map[bool]string{true: "xdp_inline", false: "xsight_main"}[m.inlineProgram])
		m.effectiveMode = at.name
		return at.name, nil
	}
	return "", fmt.Errorf("attach XDP to %s in %s mode: %w", ifaceName, mode, lastErr)
}

// inlineProgram/effectiveMode are set by SetInlineProgram/AttachXDPMode.
func (m *Manager) SetInlineProgram(on bool) { m.inlineProgram = on }

// SetAttachMode records the preferred XDP execution mode used by AttachXDP.
func (m *Manager) SetAttachMode(mode string) { m.preferredMode = mode }

// EffectiveXDPMode reports the execution mode of the last attach.
func (m *Manager) EffectiveXDPMode() string {
	if m.effectiveMode == "" {
		return "unknown"
	}
	return m.effectiveMode
}

// filepathJoinPin joins the pin path with the link file name.
func filepathJoinPin(pinPath string) string {
	return filepath.Join(pinPath, "link")
}

// linkLoadPinned loads a previously pinned XDP link.
func linkLoadPinned(pinPath string) (link.Link, error) {
	return link.LoadPinnedLink(pinPath, nil)
}
