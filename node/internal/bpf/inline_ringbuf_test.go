//go:build linux

package bpf

import (
	"encoding/binary"
	"testing"
)

func TestReadBurstAlert_KernelLayout40(t *testing.T) {
	raw := make([]byte, 40)
	binary.LittleEndian.PutUint64(raw[0:8], 12345)
	copy(raw[8:24], []byte{192, 0, 2, 1})
	binary.LittleEndian.PutUint32(raw[24:28], 1)
	binary.LittleEndian.PutUint32(raw[28:32], 9000)
	binary.LittleEndian.PutUint32(raw[32:36], 6)
	binary.LittleEndian.PutUint32(raw[36:40], 2)
	a, err := readBurstAlert(raw)
	if err != nil {
		t.Fatalf("40-byte kernel record rejected: %v", err)
	}
	if a.WindowPPS != 9000 || a.Proto != 6 || a.IsV4 != 1 {
		t.Fatalf("decode mismatch: %+v", a)
	}
}
