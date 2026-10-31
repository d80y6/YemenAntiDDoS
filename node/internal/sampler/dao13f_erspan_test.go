package sampler

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func dao13fEther(kind uint16, body []byte) []byte {
	h := make([]byte, 14)
	copy(h, []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(h[12:], kind)
	return append(h, body...)
}

func dao13fIP(v6 bool, protocol byte, src, dst string, body []byte) []byte {
	if v6 {
		h := make([]byte, 40)
		h[0], h[6], h[7] = 0x60, protocol, 49
		binary.BigEndian.PutUint16(h[4:], uint16(len(body)))
		copy(h[8:24], net.ParseIP(src).To16())
		copy(h[24:], net.ParseIP(dst).To16())
		return append(h, body...)
	}
	h := make([]byte, 20)
	h[0], h[8], h[9] = 0x45, 61, protocol
	binary.BigEndian.PutUint16(h[2:], uint16(len(h)+len(body)))
	copy(h[12:16], net.ParseIP(src).To4())
	copy(h[16:], net.ParseIP(dst).To4())
	var sum uint32
	for i := 0; i < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(h[10:], ^uint16(sum))
	return append(h, body...)
}

func dao13fL4(tcp bool) []byte {
	h := make([]byte, 8)
	if tcp {
		h = make([]byte, 20)
		h[12], h[13] = 0x50, 0x12
	} else {
		binary.BigEndian.PutUint16(h[4:], 8)
	}
	binary.BigEndian.PutUint16(h, 53)
	binary.BigEndian.PutUint16(h[2:], 40000)
	return h
}

func dao13fTunnel(inner []byte) []byte {
	gre := []byte{0x10, 0, 0x88, 0xbe, 0, 0, 0, 1, 0x10, 0, 0, 1, 0, 0, 0, 0}
	return dao13fEther(0x0800, dao13fIP(false, 47, "198.51.100.1", "198.51.100.2", append(gre, inner...)))
}

func dao13fFrames() map[string][]byte {
	v6 := dao13fIP(true, 17, "2001:db8:ffff::1", "2001:db8::10", dao13fL4(false))
	v4 := dao13fIP(false, 17, "192.0.2.1", "192.0.2.2", dao13fL4(false))
	v6tcp := dao13fIP(true, 6, "2001:db8:ffff::1", "2001:db8::10", dao13fL4(true))
	v4in6 := dao13fIP(true, 4, "2001:db8:ffff::1", "2001:db8::10", v4)
	v6in4 := dao13fIP(false, 41, "192.0.2.1", "192.0.2.2", v6)
	frames := map[string][]byte{
		"v6udp":   dao13fTunnel(dao13fEther(0x86dd, v6)),
		"v6tcp":   dao13fTunnel(dao13fEther(0x86dd, v6tcp)),
		"v4in6":   dao13fTunnel(dao13fEther(0x86dd, v4in6)),
		"v6in4":   dao13fTunnel(dao13fEther(0x0800, v6in4)),
		"v4":      dao13fTunnel(dao13fEther(0x0800, v4)),
		"sixin4":  dao13fEther(0x0800, v6in4),
		"grev6":   dao13fEther(0x0800, dao13fIP(false, 47, "198.51.100.1", "198.51.100.2", append([]byte{0, 0, 0x86, 0xdd}, v6...))),
		"plainv6": dao13fEther(0x86dd, v6),
	}
	// Full outer IPv4 and GRE, only four of the required eight ERSPAN bytes.
	frames["truncated"] = dao13fEther(0x0800, dao13fIP(false, 47, "198.51.100.1", "198.51.100.2", []byte{0x10, 0, 0x88, 0xbe, 0, 0, 0, 1, 0x10, 0, 0, 1}))
	return frames
}

func dao13fWant(frame []byte, src, dst string, protocol, ttl, flags uint32, ports bool) PacketSample {
	ps := PacketSample{RawHeader: frame, PacketLength: uint32(len(frame)), SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst), Protocol: protocol, TTL: ttl, TCPFlags: flags}
	if ps.SrcIP.To4() != nil {
		ps.SrcIP, ps.DstIP = ps.SrcIP.To4(), ps.DstIP.To4()
	}
	if ports {
		ps.SrcPort, ps.DstPort = 53, 40000
	}
	return ps
}

func dao13fEqual(t *testing.T, got, want PacketSample) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sample=%+v, want %+v", got, want)
	}
}

func TestDao13f_E1(t *testing.T) {
	for _, tc := range []struct {
		name, frame string
		proto, flag uint32
	}{
		{"InnerV6UDP", "v6udp", 17, 0},
		{"InnerV6TCP", "v6tcp", 6, 0x12},
		{"InnerV6Then4in6", "v4in6", 4, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := dao13fFrames()[tc.frame]
			got := NewPacketParser().ParseMode(frame, uint32(len(frame)), true)
			dao13fEqual(t, got, dao13fWant(frame, "2001:db8:ffff::1", "2001:db8::10", tc.proto, 49, tc.flag, true))
		})
	}
}

func TestDao13f_E2(t *testing.T) {
	for _, tc := range []struct {
		name, frame, src, dst string
		proto, ttl            uint32
		erspan, ports         bool
	}{
		{"MirrorModeErspanV6Unchanged", "v6udp", "198.51.100.1", "198.51.100.2", 47, 61, false, true},
		{"InnerV4Then6in4Unchanged", "v6in4", "192.0.2.1", "192.0.2.2", 41, 61, true, true},
		{"InnerV4Unchanged", "v4", "192.0.2.1", "192.0.2.2", 17, 61, true, true},
		{"SixInFourUnchanged", "sixin4", "192.0.2.1", "192.0.2.2", 41, 61, true, true},
		{"GREv6Unchanged/Mirror", "grev6", "198.51.100.1", "198.51.100.2", 47, 61, false, true},
		{"GREv6Unchanged/Erspan", "grev6", "198.51.100.1", "198.51.100.2", 47, 61, true, true},
		{"PlainV6", "plainv6", "2001:db8:ffff::1", "2001:db8::10", 17, 49, true, true},
		{"TruncatedErspanUnchanged", "truncated", "198.51.100.1", "198.51.100.2", 47, 61, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := dao13fFrames()[tc.frame]
			got := NewPacketParser().ParseMode(frame, uint32(len(frame)), tc.erspan)
			dao13fEqual(t, got, dao13fWant(frame, tc.src, tc.dst, tc.proto, tc.ttl, 0, tc.ports))
		})
	}
	t.Run("ParseEqualsModeFalse", func(t *testing.T) {
		for name, frame := range dao13fFrames() {
			t.Run(name, func(t *testing.T) {
				dao13fEqual(t, NewPacketParser().Parse(frame, uint32(len(frame))), NewPacketParser().ParseMode(frame, uint32(len(frame)), false))
			})
		}
	})
}

func TestDao13f_E3(t *testing.T) {
	t.Run("V6ThenTruncated", func(t *testing.T) {
		p, frames := NewPacketParser(), dao13fFrames()
		first := frames["v6udp"]
		dao13fEqual(t, p.ParseMode(first, uint32(len(first)), true),
			dao13fWant(first, "2001:db8:ffff::1", "2001:db8::10", 17, 49, 0, true))
		second := frames["truncated"]
		dao13fEqual(t, p.ParseMode(second, uint32(len(second)), true),
			dao13fWant(second, "198.51.100.1", "198.51.100.2", 47, 61, 0, false))
	})
	t.Run("ReuseNoLeak", func(t *testing.T) {
		p, frames := NewPacketParser(), dao13fFrames()
		for round := 0; round < 4; round++ {
			for i, name := range []string{"v6udp", "v4", "plainv6", "sixin4", "grev6", "truncated"} {
				frame := frames[name]
				mode := (i+round)%2 == 0
				dao13fEqual(t, p.ParseMode(frame, uint32(len(frame)), mode), NewPacketParser().ParseMode(frame, uint32(len(frame)), mode))
			}
		}
	})
}

func TestDao13f_E4(t *testing.T) {
	t.Run("PoolModeFixed", func(t *testing.T) {
		for _, mode := range []bool{true, false} {
			if wp := NewWorkerPool(1, NewFlowTable(), nil, mode); wp.erspan != mode {
				t.Fatalf("pool mode=%v, want %v", wp.erspan, mode)
			}
		}
	})
}

func TestDao13f_R0FixedE(t *testing.T) {
	t.Run("ErspanV6AttributedInner", func(t *testing.T) {
		frame := dao13fFrames()["v6udp"]
		legacy := NewPacketParser().Parse(frame, uint32(len(frame)))
		if legacy.DstPort != 40000 {
			t.Fatalf("precondition: DstPort=%d", legacy.DstPort)
		}
		got := NewPacketParser().ParseMode(frame, uint32(len(frame)), true)
		dao13fEqual(t, got, dao13fWant(frame, "2001:db8:ffff::1", "2001:db8::10", 17, 49, 0, true))
	})
}

func TestDao13f_GopacketPreflight(t *testing.T) {
	p := NewPacketParser()
	err := p.parser.DecodeLayers(dao13fFrames()["truncated"], &p.decoded)
	if err == nil {
		t.Fatal("truncated ERSPAN must produce a decoding error")
	}
	want := []gopacket.LayerType{layers.LayerTypeEthernet, layers.LayerTypeIPv4, layers.LayerTypeGRE}
	if !reflect.DeepEqual(p.decoded, want) {
		t.Fatalf("decoded layers=%v, want retained outer layers %v", p.decoded, want)
	}
	if layers.EthernetType(0x88be).LayerType() != layers.LayerTypeERSPANII ||
		layers.EthernetType(0x22eb).LayerType() != gopacket.LayerTypeZero ||
		layers.EthernetType(0x86dd).LayerType() != layers.LayerTypeIPv6 ||
		layers.IPProtocol(41).LayerType() != layers.LayerTypeIPv6 {
		t.Fatal("gopacket protocol registrations differ from the pinned precondition")
	}
}
