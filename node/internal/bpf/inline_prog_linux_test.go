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

const (
	xdpAborted = 0
	xdpDrop    = 1
	xdpPass    = 2
	xdpTx      = 3
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
