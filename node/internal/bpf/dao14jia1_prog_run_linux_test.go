//go:build linux

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

func dao14BPF(t *testing.T, cidrs ...string) *Manager {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("Dao14jia1 BPF gates require root; skips are forbidden")
	}
	m, ps := dao8Load(t, cidrs...)
	if err := m.HotSwap(ps); err != nil {
		t.Fatal(err)
	}
	if err := m.SetConfig(0, 1); err != nil {
		t.Fatal(err)
	}
	return m
}
func dao14Config(t *testing.T, m *Manager, k uint32, v uint64) {
	t.Helper()
	if err := m.SetConfig(k, v); err != nil {
		t.Fatal(err)
	}
}
func dao14Checksum(data []byte, initial uint32) uint16 {
	s := initial
	for len(data) >= 2 {
		s += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) > 0 {
		s += uint32(data[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}
func dao14Frame(t *testing.T, dst, src string, size int) []byte {
	t.Helper()
	base := dao8Frame(t, dst, false, false)
	if size < len(base) {
		t.Fatal("frame too short")
	}
	frame := make([]byte, size)
	copy(frame, base)
	for i := len(base); i < len(frame); i++ {
		frame[i] = byte(i*37 + 11)
	}
	copy(frame[26:30], net.ParseIP(src).To4())
	ip, udp := frame[14:34], frame[34:]
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(frame)-14))
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], dao14Checksum(ip, 0))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	udp[6], udp[7] = 0, 0
	var pseudo uint32
	for i := 12; i < 20; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	pseudo += 17 + uint32(len(udp))
	cs := dao14Checksum(udp, pseudo)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], cs)
	return frame
}
func dao14Program(t *testing.T, m *Manager, frame []byte) {
	t.Helper()
	ret, err := m.Objs.XsightMain.Run(&ebpf.RunOptions{Data: frame, Repeat: 1})
	if err != nil {
		t.Fatalf("BPF_PROG_RUN: %v", err)
	}
	if ret != 1 {
		t.Fatalf("XDP return=%d want DROP", ret)
	}
}
func dao14Reader(t *testing.T, m *Manager) *ringbuf.Reader {
	t.Helper()
	r, err := ringbuf.NewReader(m.Objs.Samples)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func dao14Records(t *testing.T, r *ringbuf.Reader) [][]byte {
	t.Helper()
	r.SetDeadline(time.Now().Add(200 * time.Millisecond))
	var records [][]byte
	for {
		rec, err := r.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, append([]byte(nil), rec.RawSample...))
	}
}

func TestDao14jia1_G8(t *testing.T) {
	for _, tt := range []struct {
		name       string
		slot       uint64
		size, want int
	}{
		{"Cap512", 512, 1000, 512}, {"Cap600", 600, 1000, 512}, {"Zero256", 0, 1000, 256},
		{"Cap128", 128, 1000, 128}, {"Cap256", 256, 1000, 256}, {"Cap511", 511, 1000, 511}, {"Short60", 512, 60, 60},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := dao14BPF(t, "192.0.2.0/24")
			dao14Config(t, m, 1, tt.slot)
			r := dao14Reader(t, m)
			frame := dao14Frame(t, "192.0.2.1", "198.51.100.254", tt.size)
			if tt.size >= 512 && frame[511] == 0 {
				t.Fatal("apparatus broken: byte 512 must be nonzero")
			}
			dao14Program(t, m, frame)
			records := dao14Records(t, r)
			if len(records) != 1 {
				t.Fatalf("records=%d want=1", len(records))
			}
			raw := records[0]
			if len(raw) < 8+tt.want {
				t.Fatalf("record length=%d", len(raw))
			}
			capLen, pktLen := binary.LittleEndian.Uint32(raw[:4]), binary.LittleEndian.Uint32(raw[4:8])
			if capLen != uint32(tt.want) || pktLen != uint32(tt.size) || !bytes.Equal(raw[8:8+tt.want], frame[:tt.want]) {
				t.Fatalf("cap_len=%d pkt_len=%d want=%d,%d; payload equal=%t", capLen, pktLen, tt.want, tt.size, bytes.Equal(raw[8:8+tt.want], frame[:tt.want]))
			}
		})
	}
}

func TestDao14jia1_G9(t *testing.T) {
	for _, tt := range []struct {
		name   string
		rate   uint64
		dual   bool
		lo, hi int
	}{
		{"DoubleMatchRate2", 2, true, 4700, 5300}, {"DoubleMatchRate10", 10, true, 820, 1180},
		{"InboundRate10", 10, false, 820, 1180}, {"Rate1All", 1, false, 10000, 10000},
		{"RateZeroAll", 0, false, 10000, 10000}, {"RateHugeNone", 1 << 32, false, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cidrs := []string{"192.0.2.0/24"}
			src := "198.51.100.254"
			if tt.dual {
				cidrs = append(cidrs, "203.0.113.0/24")
				src = "203.0.113.9"
			}
			m := dao14BPF(t, cidrs...)
			dao14Config(t, m, 0, tt.rate)
			r := dao14Reader(t, m)
			frame := dao14Frame(t, "192.0.2.9", src, 1000)
			for i := 0; i < 10000; i++ {
				dao14Program(t, m, frame)
			}
			c := len(dao14Records(t, r))
			t.Logf("single trial: n=10000 count=%d interval=[%d,%d]", c, tt.lo, tt.hi)
			if c < tt.lo || c > tt.hi {
				t.Fatalf("sample count=%d outside [%d,%d]; do not retry for a passing draw", c, tt.lo, tt.hi)
			}
		})
	}
}

func dao14GRE(t *testing.T, flags, protocol uint16, last byte) []byte {
	t.Helper()
	inner := dao14Frame(t, fmt.Sprintf("192.0.2.%d", last), "198.51.100.254", 60)
	gre := make([]byte, 4)
	binary.BigEndian.PutUint16(gre[:2], flags)
	binary.BigEndian.PutUint16(gre[2:], protocol)
	// Options are present in C, K, S order. R/version negative cases keep S-only layout.
	for _, bit := range []uint16{0x8000, 0x2000, 0x1000} {
		if flags&bit != 0 {
			gre = append(gre, 0, 0, 0, 0)
		}
	}
	if protocol == 0x22eb {
		gre = append(gre, make([]byte, 12)...)
	} else if flags&0x1000 != 0 {
		gre = append(gre, make([]byte, 8)...)
	}
	frame := make([]byte, 14+20)
	copy(frame[:12], []byte{2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame = append(frame, gre...)
	frame = append(frame, inner...)
	ip := frame[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, 47
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(frame)-14))
	copy(ip[12:16], net.IP{198, 51, 100, 1})
	copy(ip[16:20], net.IP{198, 51, 100, 2})
	binary.BigEndian.PutUint16(ip[10:12], dao14Checksum(ip, 0))
	return frame
}
func TestDao14jia1_G10(t *testing.T) {
	for _, tt := range []struct {
		name         string
		flags, proto uint16
		last         byte
		match        bool
	}{
		{"II_SK", 0x3000, 0x88be, 151, true}, {"II_SC", 0x9000, 0x88be, 152, true}, {"II_SKC", 0xb000, 0x88be, 153, true},
		{"I_K", 0x2000, 0x88be, 154, true}, {"III_SK", 0x3000, 0x22eb, 155, true},
		{"RBitDropped", 0x5000, 0x88be, 156, false}, {"VersionDropped", 0x1001, 0x88be, 157, false},
		{"II_S", 0x1000, 0x88be, 141, true}, {"III_S", 0x1000, 0x22eb, 142, true}, {"I_Plain", 0, 0x88be, 143, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := dao14BPF(t, "192.0.2.0/24")
			dao14Config(t, m, 2, 1)
			before := dao8Matched(t, m, false)
			dao14Program(t, m, dao14GRE(t, tt.flags, tt.proto, tt.last))
			delta := dao8Matched(t, m, false) - before
			key := LPMKey{Prefixlen: 32, Addr: [16]byte{192, 0, 2, tt.last}}
			var st DstIPStats
			err := dao8IPMap(t, m, false).Lookup(&key, &st)
			if tt.match {
				if err != nil || st.PktCount != 1 || delta != 1 {
					t.Fatalf("inner IP lookup=%v packets=%d matched delta=%d want=1", err, st.PktCount, delta)
				}
			} else {
				if !errors.Is(err, ebpf.ErrKeyNotExist) || delta != 0 {
					t.Fatalf("rejected GRE counted: lookup=%v packets=%d matched delta=%d", err, st.PktCount, delta)
				}
			}
		})
	}
}
