package bpf

import "testing"

// AF_XDP rings are not mapped at the offsets the kernel reports in
// XDP_MMAP_OFFSETS; they use the fixed PGOFF magic values from if_xdp.h.
func TestRingPgoffConstants(t *testing.T) {
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"rx", xdpPgoffRXRing, 0},
		{"tx", xdpPgoffTXRing, 0x80000000},
		{"fill", xdpPgoffFillRing, 0x100000000},
		{"comp", xdpPgoffCompRing, 0x180000000},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s pgoff = %#x, want %#x", tc.name, tc.got, tc.want)
		}
	}
}

// fill/completion rings hold __u64 UMEM offsets (8 bytes); rx/tx hold
// struct xdp_desc (16 bytes).
func TestRingDescriptorStrides(t *testing.T) {
	if xskRingDescSize != 16 {
		t.Errorf("packet ring desc stride = %d, want 16", xskRingDescSize)
	}
	if xskUmemDescSize != 8 {
		t.Errorf("umem ring desc stride = %d, want 8", xskUmemDescSize)
	}
}

func TestRingMapSize(t *testing.T) {
	ro := xdpRingOffset{Producer: 0, Consumer: 4, Desc: 256, Flags: 8}
	if got, want := ringMapSize(ro, 2048, xskRingDescSize), uintptr(256+2048*16); got != want {
		t.Errorf("packet ring size = %d, want %d", got, want)
	}
	if got, want := ringMapSize(ro, 2048, xskUmemDescSize), uintptr(256+2048*8); got != want {
		t.Errorf("umem ring size = %d, want %d", got, want)
	}
}

func TestRingMapPlans(t *testing.T) {
	plans := ringMapPlans(4096)
	want := [4]ringPlan{
		{name: "rx", pgoff: xdpPgoffRXRing, nmemb: 4096, descSize: xskRingDescSize},
		{name: "tx", pgoff: xdpPgoffTXRing, nmemb: 4096, descSize: xskRingDescSize},
		{name: "fill", pgoff: xdpPgoffFillRing, nmemb: DefaultFillRings, descSize: xskUmemDescSize},
		{name: "comp", pgoff: xdpPgoffCompRing, nmemb: DefaultCompRings, descSize: xskUmemDescSize},
	}
	if plans != want {
		t.Fatalf("ringMapPlans = %+v, want %+v", plans, want)
	}
}
