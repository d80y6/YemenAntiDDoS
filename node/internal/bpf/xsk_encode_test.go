package bpf

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

// structBytes must serialize the concrete struct in native memory layout, not
// the 16-byte interface header that unsafe.Sizeof(interface) reports.
func TestStructBytesUmemReg(t *testing.T) {
	reg := xdpUmemReg{
		Addr:      0x1000,
		Len:       0x2000,
		ChunkSize: 4096,
		Headroom:  128,
		Flags:     xdpUmemUnalignedFlg,
	}
	got := structBytes(reg)

	if want := int(unsafe.Sizeof(reg)); len(got) != want {
		t.Fatalf("structBytes len = %d, want %d", len(got), want)
	}
	if len(got) != 32 {
		t.Fatalf("xdp_umem_reg bytes = %d, want 32", len(got))
	}
	if v := binary.NativeEndian.Uint64(got[0:8]); v != 0x1000 {
		t.Errorf("addr = %#x, want 0x1000", v)
	}
	if v := binary.NativeEndian.Uint64(got[8:16]); v != 0x2000 {
		t.Errorf("len = %#x, want 0x2000", v)
	}
	if v := binary.NativeEndian.Uint32(got[16:20]); v != 4096 {
		t.Errorf("chunk_size = %d, want 4096", v)
	}
	if v := binary.NativeEndian.Uint32(got[20:24]); v != 128 {
		t.Errorf("headroom = %d, want 128", v)
	}
	if v := binary.NativeEndian.Uint32(got[24:28]); v != xdpUmemUnalignedFlg {
		t.Errorf("flags = %#x, want %#x", v, xdpUmemUnalignedFlg)
	}
	if v := binary.NativeEndian.Uint32(got[28:32]); v != 0 {
		t.Errorf("pad = %d, want 0", v)
	}
}
