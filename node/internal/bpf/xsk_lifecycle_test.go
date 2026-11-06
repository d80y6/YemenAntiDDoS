//go:build linux

package bpf

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestRefillAllBoundedByNumFrames(t *testing.T) {
	var prod, cons uint32
	addrs := make([]uint64, DefaultFillRings)
	s := &XSK{
		numFrms: 4,
		frameSz: 4096,
		fill: xdpRing{
			producer: &prod,
			consumer: &cons,
			addrs:    addrs,
			size:     DefaultFillRings,
			mask:     DefaultFillRings - 1,
		},
	}
	s.refillAll()

	if prod != 4 {
		t.Fatalf("fill producer = %d, want 4 (bounded by numFrms)", prod)
	}
	for i := uint32(0); i < 4; i++ {
		if want := uint64(i) * 4096; addrs[i] != want {
			t.Errorf("addr[%d] = %d, want %d", i, addrs[i], want)
		}
	}
	if addrs[4] != 0 {
		t.Errorf("addr[4] = %d, want untouched 0", addrs[4])
	}
}

func TestCloseIdempotent(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[1])

	s := &XSK{fd: fds[0]}
	s.Close()
	s.Close()

	if s.fd != -1 {
		t.Fatalf("fd = %d, want -1 after Close", s.fd)
	}
	if _, err := unix.Write(fds[0], []byte("x")); err != unix.EBADF {
		t.Fatalf("write after Close = %v, want EBADF", err)
	}
}

func TestReapCompReturnsFramesToFill(t *testing.T) {
	var compProd, compCons, fillProd, fillCons uint32
	const addr = 0x3000
	fillAddrs := make([]uint64, 4)
	s := &XSK{
		fill: xdpRing{
			producer: &fillProd,
			consumer: &fillCons,
			addrs:    fillAddrs,
			size:     4,
			mask:     3,
		},
		comp: xdpRing{
			producer: &compProd,
			consumer: &compCons,
			addrs:    []uint64{addr},
			size:     1,
			mask:     0,
		},
	}
	compProd = 1

	s.reapComp()

	if compCons != 1 {
		t.Fatalf("comp consumer = %d, want 1", compCons)
	}
	if fillProd != 1 {
		t.Fatalf("fill producer = %d, want 1", fillProd)
	}
	if fillAddrs[0] != addr {
		t.Fatalf("fill addr = %#x, want %#x", fillAddrs[0], addr)
	}
}

func TestSendRawFrameKicksTX(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	var prod, cons uint32
	descs := make([]xdpDesc, 4)
	s := &XSK{
		fd: fds[0],
		tx: xdpRing{
			producer: &prod,
			consumer: &cons,
			desc:     descs,
			size:     4,
			mask:     3,
		},
	}
	defer s.Close()

	if !s.SendRawFrame(0x1000, 60) {
		t.Fatal("SendRawFrame returned false with an empty TX ring")
	}
	if prod != 1 {
		t.Fatalf("tx producer = %d, want 1", prod)
	}
	if descs[0].Addr != 0x1000 || descs[0].Len != 60 {
		t.Fatalf("tx desc = %+v, want addr 0x1000 len 60", descs[0])
	}
	if got := s.txDrop.Load(); got != 0 {
		t.Fatalf("txDrop = %d, want 0 (TX kick failed)", got)
	}
}

func TestSendRawFrameTXFull(t *testing.T) {
	var prod, cons uint32
	prod = 4
	s := &XSK{
		fd: -1,
		tx: xdpRing{
			producer: &prod,
			consumer: &cons,
			desc:     make([]xdpDesc, 4),
			size:     4,
			mask:     3,
		},
	}
	if s.SendRawFrame(0, 60) {
		t.Fatal("SendRawFrame returned true on a full TX ring")
	}
	if got := s.txDrop.Load(); got != 1 {
		t.Fatalf("txDrop = %d, want 1", got)
	}
	if prod != 4 {
		t.Fatalf("tx producer advanced to %d, want 4", prod)
	}
}
