//go:build linux

package bpf

import (
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
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
	}}); err != nil {
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
	}); err != nil {
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
	}}); err != nil {
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
