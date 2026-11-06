//go:build linux

package bpf

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	xdpAborted  = 0
	xdpDrop     = 1
	xdpPass     = 2
	xdpTx       = 3
	xdpRedirect = 4
)

// inlineProgramLoad loads the xdp_inline program fail-closed: missing root is a
// fatal error, never a skip. No interface attachment, pinning, or sockets.
func inlineProgramLoad(t *testing.T) *Manager {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("BPF prog-run gates require root; run under sudo")
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
	return m
}

// inlineRun executes one frame through the xdp_inline program and returns the
// XDP verdict.
func inlineRun(t *testing.T, m *Manager, frame []byte) uint32 {
	t.Helper()
	ret, err := m.Objs.XdpInline.Run(&ebpf.RunOptions{Data: frame, Repeat: 1})
	if err != nil {
		t.Fatalf("BPF_PROG_RUN xdp_inline: %v", err)
	}
	return ret
}

// inlineRunOut also returns the post-run frame (including bpf_xdp_adjust_head
// rewrites) for header-construction assertions.
func inlineRunOut(t *testing.T, m *Manager, frame []byte) (uint32, []byte) {
	t.Helper()
	out := make([]byte, len(frame)+64)
	ret, err := m.Objs.XdpInline.Run(&ebpf.RunOptions{Data: frame, DataOut: out, Repeat: 1})
	if err != nil {
		t.Fatalf("BPF_PROG_RUN xdp_inline: %v", err)
	}
	return ret, out
}

// inlineARPFrame builds a minimal broadcast ARP request (14 + 28 bytes).
func inlineARPFrame() []byte {
	frame := make([]byte, 14+28)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 0x0001) // htype ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // ptype IPv4
	arp[4], arp[5] = 6, 4                        // hlen, plen
	binary.BigEndian.PutUint16(arp[6:8], 0x0001) // op request
	copy(arp[8:14], []byte{2, 0, 0, 0, 0, 1})
	copy(arp[14:18], net.IP{192, 0, 2, 1}.To4())
	copy(arp[18:24], []byte{0, 0, 0, 0, 0, 0})
	copy(arp[24:28], net.IP{192, 0, 2, 2}.To4())
	return frame
}

// inlineTCPSYN builds a minimal Ethernet+IPv4 TCP/SYN frame (14 + 20 + 20).
func inlineTCPSYN(t *testing.T) []byte {
	t.Helper()
	frame := make([]byte, 14+20+20)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:4], 40)
	copy(ip[12:16], net.IP{198, 51, 100, 254}.To4())
	copy(ip[16:20], net.IP{192, 0, 2, 1}.To4())
	binary.BigEndian.PutUint16(ip[10:12], dao14Checksum(ip, 0))
	tcp := frame[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = 0x50 // data offset 5 words
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	var pseudo uint32
	pseudo += uint32(binary.BigEndian.Uint16(ip[12:14])) + uint32(binary.BigEndian.Uint16(ip[14:16]))
	pseudo += uint32(binary.BigEndian.Uint16(ip[16:18])) + uint32(binary.BigEndian.Uint16(ip[18:20]))
	pseudo += 6 + uint32(len(tcp))
	cs := dao14Checksum(tcp, pseudo)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(tcp[16:18], cs)
	return frame
}

// inlineTCPFrame builds an Ethernet+IPv4 TCP frame with a 4-byte payload so
// the SYN-cookie path (which rewrites a 24-byte TCP header) can run.
func inlineTCPFrame(t *testing.T, src, dst string, sport, dport uint16, flags uint8) []byte {
	t.Helper()
	sip, dip := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	if sip == nil || dip == nil {
		t.Fatalf("inlineTCPFrame: src=%q dst=%q must be IPv4", src, dst)
	}
	frame := make([]byte, 14+20+24)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	binary.BigEndian.PutUint16(ip[2:4], 44)
	copy(ip[12:16], sip)
	copy(ip[16:20], dip)
	binary.BigEndian.PutUint16(ip[10:12], dao14Checksum(ip, 0))
	tcp := frame[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 0x50 // data offset 5 words
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	return frame
}

// burstWindowValue mirrors struct burst_window for direct map fixtures.
type burstWindowValue struct {
	Count            uint32
	Sustained        uint32
	WindowStartNS    uint64
	EmergencyUntilNS uint64
}

// inlineAddrKey packs an IPv4 literal into the 16-byte map key layout.
func inlineAddrKey(ip string) [16]byte {
	var k [16]byte
	copy(k[:4], net.ParseIP(ip).To4())
	return k
}

// inlineTCPFrameSeq is inlineTCPFrame with explicit sequence/ack fields.
func inlineTCPFrameSeq(t *testing.T, src, dst string, sport, dport uint16, flags uint8, seq, ack uint32) []byte {
	t.Helper()
	frame := inlineTCPFrame(t, src, dst, sport, dport, flags)
	tcp := frame[34:]
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	return frame
}

func TestInlineProgram_CookieAckValidation(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.SetConfig(CfgSynCookieEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.SetCookieSecret(0x0123456789abcdef, 0xfedcba9876543210); err != nil {
		t.Fatal(err)
	}
	p, err := ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PopulateTrie([]PrefixEntry{p}); err != nil {
		t.Fatal(err)
	}
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 90, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80, Action: "syn_cookie",
	})

	src, dst := "198.51.100.254", "192.0.2.1"
	syn := inlineTCPFrameSeq(t, src, dst, 12345, 80, 0x02, 0x11111111, 0)
	ret, out := inlineRunOut(t, m, syn)
	if ret != xdpTx {
		t.Fatalf("SYN: xdp_inline = %d, want XDP_TX (%d)", ret, xdpTx)
	}
	isn := binary.BigEndian.Uint32(out[38:42])

	// Drive the destination into emergency so the final-ACK validation branch
	// runs without waiting for a real two-window burst.
	now := MonotonicNowNS()
	key := inlineAddrKey(dst)
	w := burstWindowValue{WindowStartNS: now, EmergencyUntilNS: now + uint64(time.Second)}
	if err := m.Objs.BurstWindows.Update(&key, &w, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	// Real clients send an arbitrary seq; only ack_seq == cookie+1 validates.
	good := inlineTCPFrameSeq(t, src, dst, 12345, 80, 0x10, 0xa5a5a5a5, isn+1)
	if got := inlineRun(t, m, good); got != xdpPass {
		t.Fatalf("valid ACK: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
	srcKey := inlineAddrKey(src)
	var expiry uint64
	if err := m.Objs.ValidatedClients.Lookup(&srcKey, &expiry); err != nil {
		t.Fatalf("valid ACK was not admitted into validated_clients: %v", err)
	}
	if expiry <= MonotonicNowNS() {
		t.Fatalf("validated client expiry %d is not in the future", expiry)
	}

	// A different client with a wrong ack_seq must be rejected and not admitted.
	other := "203.0.113.9"
	syn2 := inlineTCPFrameSeq(t, other, dst, 12345, 80, 0x02, 0x22222222, 0)
	ret, out = inlineRunOut(t, m, syn2)
	if ret != xdpTx {
		t.Fatalf("second SYN: xdp_inline = %d, want XDP_TX (%d)", ret, xdpTx)
	}
	otherISN := binary.BigEndian.Uint32(out[38:42])
	bad := inlineTCPFrameSeq(t, other, dst, 12345, 80, 0x10, 0x33333333, otherISN)
	if got := inlineRun(t, m, bad); got != xdpDrop {
		t.Fatalf("wrong ACK: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}
	otherKey := inlineAddrKey(other)
	if err := m.Objs.ValidatedClients.Lookup(&otherKey, &expiry); err == nil {
		t.Fatal("wrong ACK admitted the client into validated_clients")
	}
}

// inlineTCPSYNCustom builds a SYN with an optional 802.1Q tag and an explicit
// IPv4 header length (IHL >= 5). The frame is exactly eth + ipHdr + 24 bytes so
// the cookie reply can be checked without a tail resize.
func inlineTCPSYNCustom(t *testing.T, src, dst string, sport, dport uint16, vlan bool, ihl int) []byte {
	t.Helper()
	if ihl < 5 || ihl > 15 {
		t.Fatalf("inlineTCPSYNCustom: ihl=%d out of range", ihl)
	}
	sip, dip := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	if sip == nil || dip == nil {
		t.Fatalf("inlineTCPSYNCustom: src=%q dst=%q must be IPv4", src, dst)
	}
	ethLen := 14
	if vlan {
		ethLen = 18
	}
	ipHdrLen := ihl * 4
	frame := make([]byte, ethLen+ipHdrLen+24)
	copy(frame[0:6], []byte{2, 0, 0, 0, 0, 1})
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 2})
	if vlan {
		binary.BigEndian.PutUint16(frame[12:14], 0x8100)
		binary.BigEndian.PutUint16(frame[14:16], 0)      // TCI
		binary.BigEndian.PutUint16(frame[16:18], 0x0800) // inner EtherType
	} else {
		binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	}
	ip := frame[ethLen : ethLen+ipHdrLen]
	ip[0] = 0x40 | byte(ihl)
	ip[8], ip[9] = 64, 6
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipHdrLen+24))
	copy(ip[12:16], sip)
	copy(ip[16:20], dip)
	for i := 20; i < ipHdrLen; i++ {
		ip[i] = 1 // NOP options
	}
	binary.BigEndian.PutUint16(ip[10:12], dao14Checksum(ip, 0))
	tcp := frame[ethLen+ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 0x50 // data offset 5 words
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	return frame
}

// ipv4HeaderChecksumValid reports whether the IPv4 header checksum verifies.
func ipv4HeaderChecksumValid(frame []byte, l3Off, hdrLen int) bool {
	return dao14Checksum(frame[l3Off:l3Off+hdrLen], 0) == 0
}

// tcpChecksumValid recomputes the TCP checksum over the emitted segment and
// its pseudo-header; a valid checksum makes the ones-complement sum zero.
func tcpChecksumValid(frame []byte, l3Off, hdrLen int) bool {
	ip := frame[l3Off : l3Off+hdrLen]
	totLen := int(binary.BigEndian.Uint16(ip[2:4]))
	segLen := totLen - hdrLen
	if segLen < 20 || l3Off+hdrLen+segLen > len(frame) {
		return false
	}
	tcp := frame[l3Off+hdrLen : l3Off+hdrLen+segLen]
	var pseudo uint32
	pseudo += uint32(binary.BigEndian.Uint16(ip[12:14])) + uint32(binary.BigEndian.Uint16(ip[14:16]))
	pseudo += uint32(binary.BigEndian.Uint16(ip[16:18])) + uint32(binary.BigEndian.Uint16(ip[18:20]))
	pseudo += 6 + uint32(segLen)
	return dao14Checksum(tcp, pseudo) == 0
}

// inlineSynCookieSetup enables the cookie engine for a watched IPv4 prefix and
// installs the rule that requests cookies.
func inlineSynCookieSetup(t *testing.T) *Manager {
	t.Helper()
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.SetConfig(CfgSynCookieEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.SetCookieSecret(0x0123456789abcdef, 0xfedcba9876543210); err != nil {
		t.Fatal(err)
	}
	p, err := ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PopulateTrie([]PrefixEntry{p}); err != nil {
		t.Fatal(err)
	}
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 91, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80, Action: "syn_cookie",
	})
	return m
}

func TestInlineProgram_SynAckLengthChecksum(t *testing.T) {
	m := inlineSynCookieSetup(t)
	syn := inlineTCPSYNCustom(t, "198.51.100.254", "192.0.2.1", 12345, 80, false, 5)
	ret, out := inlineRunOut(t, m, syn)
	if ret != xdpTx {
		t.Fatalf("SYN: xdp_inline = %d, want XDP_TX (%d)", ret, xdpTx)
	}
	ip := out[14:]
	if got := binary.BigEndian.Uint16(ip[2:4]); got != 44 {
		t.Fatalf("SYN-ACK tot_len = %d, want 44 (20-byte IP + 24-byte TCP)", got)
	}
	if !ipv4HeaderChecksumValid(out, 14, 20) {
		t.Fatal("SYN-ACK IPv4 header checksum is invalid")
	}
	if !tcpChecksumValid(out, 14, 20) {
		t.Fatal("SYN-ACK TCP checksum is invalid")
	}
}

func TestInlineProgram_SynAckIHL6(t *testing.T) {
	m := inlineSynCookieSetup(t)
	syn := inlineTCPSYNCustom(t, "198.51.100.254", "192.0.2.1", 12345, 80, false, 6)
	ret, out := inlineRunOut(t, m, syn)
	if ret != xdpTx {
		t.Fatalf("IHL=6 SYN: xdp_inline = %d, want XDP_TX (%d)", ret, xdpTx)
	}
	if ihl := int(out[14] & 0x0f); ihl != 6 {
		t.Fatalf("SYN-ACK IHL = %d, want 6 (options preserved)", ihl)
	}
	ip := out[14:]
	if got := binary.BigEndian.Uint16(ip[2:4]); got != 48 {
		t.Fatalf("SYN-ACK tot_len = %d, want 48 (24-byte IP + 24-byte TCP)", got)
	}
	if !ipv4HeaderChecksumValid(out, 14, 24) {
		t.Fatal("SYN-ACK IPv4 header checksum is invalid with options")
	}
	if !tcpChecksumValid(out, 14, 24) {
		t.Fatal("SYN-ACK TCP checksum is invalid with options")
	}
}

func TestInlineProgram_SynAckVLAN(t *testing.T) {
	m := inlineSynCookieSetup(t)
	syn := inlineTCPSYNCustom(t, "198.51.100.254", "192.0.2.1", 12345, 80, true, 5)
	ret, out := inlineRunOut(t, m, syn)
	if ret != xdpTx {
		t.Fatalf("VLAN SYN: xdp_inline = %d, want XDP_TX (%d)", ret, xdpTx)
	}
	if got := binary.BigEndian.Uint16(out[12:14]); got != 0x8100 {
		t.Fatalf("SYN-ACK EtherType = %#04x, want 0x8100 (tag preserved)", got)
	}
	if got := binary.BigEndian.Uint16(out[16:18]); got != 0x0800 {
		t.Fatalf("VLAN inner EtherType = %#04x, want 0x0800", got)
	}
	ip := out[18:]
	if got := binary.BigEndian.Uint16(ip[2:4]); got != 44 {
		t.Fatalf("VLAN SYN-ACK tot_len = %d, want 44", got)
	}
	if !ipv4HeaderChecksumValid(out, 18, 20) {
		t.Fatal("VLAN SYN-ACK IPv4 header checksum is invalid")
	}
	if !tcpChecksumValid(out, 18, 20) {
		t.Fatal("VLAN SYN-ACK TCP checksum is invalid")
	}
	// The reply reverses the original MAC pair.
	if string(out[0:6]) != string([]byte{2, 0, 0, 0, 0, 2}) ||
		string(out[6:12]) != string([]byte{2, 0, 0, 0, 0, 1}) {
		t.Fatalf("SYN-ACK MACs not swapped: dst=%x src=%x", out[0:6], out[6:12])
	}
}

func TestInlineProgram_BurstAlert(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.SetConfig(CfgAlertsEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.SetBurstThreshold(1); err != nil {
		t.Fatal(err)
	}
	p, err := ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PopulateTrie([]PrefixEntry{p}); err != nil {
		t.Fatal(err)
	}

	frame := dao8Frame(t, "192.0.2.1", false, false)
	// Two consecutive breached 100ms windows trigger the emergency alert on
	// the third packet (window counters are evaluated on window rollover).
	if got := inlineRun(t, m, frame); got != xdpPass {
		t.Fatalf("warmup packet: xdp_inline = %d, want XDP_PASS", got)
	}
	time.Sleep(120 * time.Millisecond)
	if got := inlineRun(t, m, frame); got != xdpPass {
		t.Fatalf("first breached window: xdp_inline = %d, want XDP_PASS", got)
	}
	time.Sleep(120 * time.Millisecond)
	if got := inlineRun(t, m, frame); got != xdpDrop {
		t.Fatalf("second breached window: xdp_inline = %d, want XDP_DROP (emergency armed)", got)
	}

	rd, err := ringbuf.NewReader(m.Objs.Alerts)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	rd.SetDeadline(time.Now().Add(2 * time.Second))
	rec, err := rd.Read()
	if err != nil {
		t.Fatalf("no burst alert emitted: %v", err)
	}
	a, err := readBurstAlert(rec.RawSample)
	if err != nil {
		t.Fatalf("decode burst alert: %v", err)
	}
	if got := a.DstIP().String(); got != "192.0.2.1" {
		t.Fatalf("alert dst = %s, want 192.0.2.1", got)
	}
	if a.IsV4 != 1 || a.Proto != 17 {
		t.Fatalf("alert = %+v, want IPv4/UDP", a)
	}
	if a.WindowPPS == 0 {
		t.Fatal("alert window_pps is zero")
	}
}

func TestInlineProgram_CookieRequiresRule(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.SetConfig(CfgSynCookieEnable, 1); err != nil {
		t.Fatal(err)
	}
	p, err := ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PopulateTrie([]PrefixEntry{p}); err != nil {
		t.Fatal(err)
	}

	// No rule requests cookies: a SYN to a watched destination must pass
	// through instead of being rewritten into a SYN-ACK.
	syn := inlineTCPFrameSeq(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02, 0, 0)
	if got := inlineRun(t, m, syn); got != xdpPass {
		t.Fatalf("SYN without a cookie rule: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
	// Burst accounting must run before any cookie/filter early return.
	var w burstWindowValue
	key := inlineAddrKey("192.0.2.1")
	if err := m.Objs.BurstWindows.Lookup(&key, &w); err != nil {
		t.Fatalf("burst window not created for watched SYN: %v", err)
	}
	if w.Count == 0 {
		t.Fatal("watched SYN did not increment the burst window")
	}
}

func TestInlineProgram_CookieAccountingBeforeReply(t *testing.T) {
	m := inlineSynCookieSetup(t)
	syn := inlineTCPFrameSeq(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02, 0, 0)
	if got := inlineRun(t, m, syn); got != xdpTx {
		t.Fatalf("cookie-rule SYN: xdp_inline = %d, want XDP_TX (%d)", got, xdpTx)
	}
	var w burstWindowValue
	key := inlineAddrKey("192.0.2.1")
	if err := m.Objs.BurstWindows.Lookup(&key, &w); err != nil {
		t.Fatalf("cookie reply bypassed burst accounting: %v", err)
	}
	if w.Count == 0 {
		t.Fatal("cookie-replied SYN did not increment the burst window")
	}
}

func TestInlineProgram_ValidatedClientStillFiltered(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	p, err := ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.PopulateTrie([]PrefixEntry{p}); err != nil {
		t.Fatal(err)
	}
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 95, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80,
		Action: "drop", Priority: 10,
	})

	src := "198.51.100.254"
	key := inlineAddrKey(src)
	expiry := MonotonicNowNS() + uint64(time.Minute)
	if err := m.Objs.ValidatedClients.Update(&key, &expiry, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	// Validation only bypasses the emergency micro-drop; explicit filter rules
	// still apply to the client's traffic.
	syn := inlineTCPFrameSeq(t, src, "192.0.2.1", 12345, 80, 0x02, 0, 0)
	if got := inlineRun(t, m, syn); got != xdpDrop {
		t.Fatalf("validated client bypassed a drop rule: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}
}

func TestInlineProgram_FilterConsiderBestMatch(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	key, val, err := EncodeInlineRule(InlineRuleSpec{
		ID: 1, DstIP: "192.0.2.1", DstPrefixLen: 0,
		Protocol: 6, DstPort: 80, Action: "drop", Priority: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Objs.ActiveFilterRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	if got := inlineRun(t, m, inlineTCPSYN(t)); got != xdpDrop {
		t.Fatalf("matching frame: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}
	miss := inlineTCPFrame(t, "198.51.100.254", "203.0.113.9", 12345, 80, 0x02)
	if got := inlineRun(t, m, miss); got != xdpPass {
		t.Fatalf("non-matching frame: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
}

func TestInlineProgram_ActiveSlotOne(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.SetConfig(CfgSynCookieEnable, 1); err != nil {
		t.Fatal(err)
	}
	p, err := ParsePrefix("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	// Starting from slot A, HotSwap populates B and activates it, then clears A.
	if err := m.HotSwap([]PrefixEntry{p}); err != nil {
		t.Fatal(err)
	}
	slot, err := m.ReadActiveSlot()
	if err != nil {
		t.Fatal(err)
	}
	if slot != 1 {
		t.Fatalf("active_slot = %d, want 1 after HotSwap", slot)
	}
	// Cookies are rule-driven; install the rule that requests them.
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 92, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80, Action: "syn_cookie",
	})

	// A SYN to the watched destination must enter the SYN-cookie path
	// (XDP_TX). Hardcoding slot A makes dst_watched false and yields PASS.
	frame := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02)
	if got := inlineRun(t, m, frame); got != xdpTx {
		t.Fatalf("watched dst in slot B: xdp_inline = %d, want XDP_TX (%d)", got, xdpTx)
	}
}

// inlineInstallExact writes one exact (hash) filter rule into the kernel map.
func inlineInstallExact(t *testing.T, m *Manager, spec InlineRuleSpec) {
	t.Helper()
	key, val, err := EncodeInlineRule(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Objs.ActiveFilterRules.Update(&key, &val, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
}

func TestInlineProgram_ExactWildcards(t *testing.T) {
	tcpMatch := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02)
	tcpOtherSrc := inlineTCPFrame(t, "203.0.113.9", "192.0.2.1", 12345, 80, 0x02)
	udpMatch := dao8Frame(t, "192.0.2.1", false, false)

	cases := []struct {
		name string
		spec InlineRuleSpec
		hit  []byte
		miss []byte
	}{
		{
			name: "src-only",
			spec: InlineRuleSpec{ID: 1, SrcIP: "198.51.100.254", Action: "drop"},
			hit:  tcpMatch, miss: tcpOtherSrc,
		},
		{
			name: "proto-only",
			spec: InlineRuleSpec{ID: 2, Protocol: 17, Action: "drop"},
			hit:  udpMatch, miss: tcpMatch,
		},
		{
			name: "dst-src-proto",
			spec: InlineRuleSpec{
				ID: 3, DstIP: "192.0.2.1", SrcIP: "198.51.100.254",
				Protocol: 6, Action: "drop",
			},
			hit: tcpMatch, miss: tcpOtherSrc,
		},
		{
			name: "global",
			spec: InlineRuleSpec{ID: 4, Action: "drop"},
			hit:  udpMatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := inlineProgramLoad(t)
			if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
				t.Fatal(err)
			}
			inlineInstallExact(t, m, tc.spec)
			if got := inlineRun(t, m, tc.hit); got != xdpDrop {
				t.Fatalf("matching frame: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
			}
			if tc.miss != nil {
				if got := inlineRun(t, m, tc.miss); got != xdpPass {
					t.Fatalf("non-matching frame: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
				}
				return
			}
			// A global IP rule does not touch non-IP frames (ARP passes first).
			if got := inlineRun(t, m, inlineARPFrame()); got != xdpPass {
				t.Fatalf("ARP frame: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
			}
		})
	}
}

func TestInlineProgram_SubnetDirection(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyInlineRules([]InlineRuleSpec{{
		ID: 10, SrcIP: "198.51.100.0", SrcPrefixLen: 24, Action: "drop",
	}}, ""); err != nil {
		t.Fatal(err)
	}

	from := dao14Frame(t, "192.0.2.1", "198.51.100.5", 60)
	if got := inlineRun(t, m, from); got != xdpDrop {
		t.Fatalf("traffic from src subnet: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}

	to := dao14Frame(t, "198.51.100.5", "192.0.2.1", 60)
	if got := inlineRun(t, m, to); got != xdpPass {
		t.Fatalf("traffic to src subnet: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
}

func TestInlineProgram_RateLimitClamp(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 20, DstIP: "192.0.2.1", Protocol: 17, DstPort: 54321,
		Action: "rate_limit", RateLimitPPS: 5,
	})

	// rate_limit_pps/10 truncates to zero; the kernel must clamp the window
	// budget to one packet instead of dropping every packet.
	if got := inlineRun(t, m, dao8Frame(t, "192.0.2.1", false, false)); got != xdpPass {
		t.Fatalf("first packet: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
	if got := inlineRun(t, m, dao8Frame(t, "192.0.2.1", false, false)); got != xdpDrop {
		t.Fatalf("second packet: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}
}

func TestInlineProgram_HostPrefixPerPortRules(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	// The controller emits /32 host-prefix rules per port for one target. The
	// LPM tries are keyed on address+prefix only, so writing these there makes
	// the second rule overwrite the first. Host prefixes must land in the
	// exact hash table instead.
	if err := m.ApplyInlineRules([]InlineRuleSpec{
		{ID: 1, DstIP: "192.0.2.1", DstPrefixLen: 32, Protocol: 6, DstPort: 80, Action: "drop", Priority: 10},
		{ID: 2, DstIP: "192.0.2.1", DstPrefixLen: 32, Protocol: 6, DstPort: 53, Action: "drop", Priority: 10},
	}, ""); err != nil {
		t.Fatal(err)
	}

	for _, port := range []uint16{80, 53} {
		frame := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, port, 0x02)
		if got := inlineRun(t, m, frame); got != xdpDrop {
			t.Fatalf("dst port %d: xdp_inline = %d, want XDP_DROP (%d)", port, got, xdpDrop)
		}
	}

	other := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 443, 0x02)
	if got := inlineRun(t, m, other); got != xdpPass {
		t.Fatalf("unmatched port: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
}

func TestInlineProgram_ExactAnySport(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	// dst+src+proto+dport with sport wildcard must be looked up in the hash
	// (the "any-sport" permutation).
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 30, DstIP: "192.0.2.1", SrcIP: "198.51.100.254",
		Protocol: 6, DstPort: 80, Action: "drop",
	})

	match := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 40000, 80, 0x02)
	if got := inlineRun(t, m, match); got != xdpDrop {
		t.Fatalf("any-sport match: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}

	otherSrc := inlineTCPFrame(t, "203.0.113.9", "192.0.2.1", 40000, 80, 0x02)
	if got := inlineRun(t, m, otherSrc); got != xdpPass {
		t.Fatalf("different src: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
}

func TestInlineProgram_DstSubnetProtoPortScope(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyInlineRules([]InlineRuleSpec{{
		ID: 40, DstIP: "192.0.2.0", DstPrefixLen: 24,
		Protocol: 6, DstPort: 8080, Action: "drop", Priority: 10,
	}}, ""); err != nil {
		t.Fatal(err)
	}

	match := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 8080, 0x02)
	if got := inlineRun(t, m, match); got != xdpDrop {
		t.Fatalf("matching subnet/port: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}

	wrongPort := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02)
	if got := inlineRun(t, m, wrongPort); got != xdpPass {
		t.Fatalf("subnet, other port: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}

	outside := inlineTCPFrame(t, "198.51.100.254", "203.0.113.9", 12345, 8080, 0x02)
	if got := inlineRun(t, m, outside); got != xdpPass {
		t.Fatalf("outside subnet: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
}

func TestInlineProgram_PriorityTieBreak(t *testing.T) {
	cases := []struct {
		name     string
		global   InlineRuleSpec
		specific InlineRuleSpec
		want     uint32
	}{
		{
			name:   "specific-pass-beats-global-drop",
			global: InlineRuleSpec{ID: 51, Action: "drop", Priority: 100},
			specific: InlineRuleSpec{
				ID: 52, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80,
				Action: "pass", Priority: 10,
			},
			want: xdpPass,
		},
		{
			name:   "specific-drop-beats-global-pass",
			global: InlineRuleSpec{ID: 53, Action: "pass", Priority: 100},
			specific: InlineRuleSpec{
				ID: 54, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80,
				Action: "drop", Priority: 10,
			},
			want: xdpDrop,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := inlineProgramLoad(t)
			if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
				t.Fatal(err)
			}
			inlineInstallExact(t, m, tc.global)
			inlineInstallExact(t, m, tc.specific)

			frame := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02)
			if got := inlineRun(t, m, frame); got != tc.want {
				t.Fatalf("xdp_inline = %d, want %d (lower priority number wins)", got, tc.want)
			}
		})
	}
}

func TestInlineProgram_GREEncapHeader(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	// Rule egress is 0, so the data plane must fall back to CFG_EGRESS_IFINDEX.
	if err := m.SetConfig(CfgEgressIfindex, uint64(lo.Index)); err != nil {
		t.Fatal(err)
	}
	saddr := binary.NativeEndian.Uint32(net.IP{192, 0, 2, 10}.To4())
	if err := m.SetConfig(CfgEgressSaddr, uint64(saddr)); err != nil {
		t.Fatal(err)
	}
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 80, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80,
		Action: "redirect", Encap: "gre", EncapDaddr: "203.0.113.9",
	})

	frame := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02)
	ret, out := inlineRunOut(t, m, frame)
	// BPF_PROG_RUN may not complete the actual redirect, but the header rewrite
	// happens first regardless of whether bpf_redirect() succeeds.
	if ret != xdpRedirect && ret != xdpDrop {
		t.Fatalf("redirect rule verdict = %d, want XDP_REDIRECT or XDP_DROP", ret)
	}

	// The kernel may return XDP_REDIRECT or XDP_DROP depending on whether the
	// test-run path can resolve the target; either way the header rewrite must
	// have happened before bpf_redirect().
	off := -1
	for i := 0; i+38 <= len(out); i++ {
		if out[i+12] == 0x08 && out[i+13] == 0x00 &&
			out[i+14] == 0x45 && out[i+23] == 47 {
			off = i
			break
		}
	}
	if off < 0 {
		t.Fatalf("no outer IPv4/GRE header found in post-run frame: % x", out[:96])
	}
	iph := out[off+14:]
	// Reading the header bytes big-endian yields the wire-format addresses.
	if got := binary.BigEndian.Uint32(iph[12:16]); got != 0xc000020a {
		t.Errorf("outer saddr = %#x, want 0xc000020a (192.0.2.10)", got)
	}
	if got := binary.BigEndian.Uint32(iph[16:20]); got != 0xcb007109 {
		t.Errorf("outer daddr = %#x, want 0xcb007109 (203.0.113.9)", got)
	}
	gre := iph[20:]
	if got := binary.BigEndian.Uint16(gre[2:4]); got != 0x6558 {
		t.Errorf("GRE payload protocol = %#x, want 0x6558 (TEB)", got)
	}
	// The encapsulated frame still starts with its Ethernet header.
	if out[off+38+12] != 0x08 || out[off+38+13] != 0x00 {
		t.Errorf("inner Ethernet type = %02x%02x, want 0800", out[off+38+12], out[off+38+13])
	}
}

func TestInlineProgram_RuleExpiryMonotonic(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}

	// A deadline one nanosecond in the future must stop matching after a short
	// sleep. Before the clock-domain fix the kernel compared wall-clock seconds
	// (or a raw epoch value) against seconds-since-boot, so this rule either
	// never expired or expired immediately for the wrong reason.
	now := MonotonicNowNS()
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 60, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80,
		Action: "drop", ExpiresNS: now + 1,
	})
	time.Sleep(5 * time.Millisecond)

	expired := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02)
	if got := inlineRun(t, m, expired); got != xdpPass {
		t.Fatalf("expired rule: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}

	// A fresh rule with a long monotonic deadline still matches.
	inlineInstallExact(t, m, InlineRuleSpec{
		ID: 61, DstIP: "192.0.2.1", Protocol: 6, DstPort: 81,
		Action: "drop", ExpiresNS: now + uint64(time.Hour),
	})
	fresh := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 81, 0x02)
	if got := inlineRun(t, m, fresh); got != xdpDrop {
		t.Fatalf("fresh rule: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}

	// Subnet rules are evaluated on the xdp_inline clock path; cover that too.
	if err := m.ApplyInlineRules([]InlineRuleSpec{{
		ID: 62, DstIP: "192.0.2.0", DstPrefixLen: 24, Protocol: 6, DstPort: 82,
		Action: "drop", ExpiresNS: now + 1,
	}}, ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	subnetExpired := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 82, 0x02)
	if got := inlineRun(t, m, subnetExpired); got != xdpPass {
		t.Fatalf("expired subnet rule: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
}

func TestInlineProgram_DefaultAction(t *testing.T) {
	cases := []struct {
		name     string
		defaultA string
		want     uint32
	}{
		{"drop", "drop", xdpDrop},
		{"pass", "pass", xdpPass},
		{"empty-is-pass", "", xdpPass},
		{"unknown-is-pass", "reject", xdpPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := inlineProgramLoad(t)
			if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
				t.Fatal(err)
			}
			if err := m.ApplyInlineRules(nil, tc.defaultA); err != nil {
				t.Fatal(err)
			}
			frame := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 443, 0x02)
			if got := inlineRun(t, m, frame); got != tc.want {
				t.Fatalf("default_action=%q unmatched frame: xdp_inline = %d, want %d",
					tc.defaultA, got, tc.want)
			}
		})
	}
}

func TestInlineProgram_DefaultDropSpecificPass(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyInlineRules([]InlineRuleSpec{{
		ID: 70, DstIP: "192.0.2.1", Protocol: 6, DstPort: 80,
		Action: "pass", Priority: 10,
	}}, "drop"); err != nil {
		t.Fatal(err)
	}

	passFrame := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 80, 0x02)
	if got := inlineRun(t, m, passFrame); got != xdpPass {
		t.Fatalf("specific PASS rule: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
	unmatched := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 443, 0x02)
	if got := inlineRun(t, m, unmatched); got != xdpDrop {
		t.Fatalf("unmatched under drop default: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}
}

func TestInlineProgram_DefaultDropRemovedOnWithdraw(t *testing.T) {
	m := inlineProgramLoad(t)
	if err := m.SetConfig(CfgInlineEnable, 1); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyInlineRules(nil, "drop"); err != nil {
		t.Fatal(err)
	}
	frame := inlineTCPFrame(t, "198.51.100.254", "192.0.2.1", 12345, 443, 0x02)
	if got := inlineRun(t, m, frame); got != xdpDrop {
		t.Fatalf("before withdraw: xdp_inline = %d, want XDP_DROP (%d)", got, xdpDrop)
	}
	if err := m.ApplyInlineRules(nil, "pass"); err != nil {
		t.Fatal(err)
	}
	if got := inlineRun(t, m, frame); got != xdpPass {
		t.Fatalf("after withdraw: xdp_inline = %d, want XDP_PASS (%d)", got, xdpPass)
	}
}

func TestInlineProgram_PassBaselines(t *testing.T) {
	m := inlineProgramLoad(t)
	for _, tt := range []struct {
		name  string
		frame []byte
	}{
		{"ARP", inlineARPFrame()},
		{"BenignUDP", dao8Frame(t, "192.0.2.1", false, false)},
		{"BenignTCPSYN", inlineTCPSYN(t)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := inlineRun(t, m, tt.frame); got != xdpPass {
				t.Fatalf("xdp_inline return = %d, want XDP_PASS (%d)", got, xdpPass)
			}
		})
	}
}
