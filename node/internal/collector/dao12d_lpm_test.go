package collector

import (
	"net"
	"testing"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
)

func TestDao12d_G4b(t *testing.T) {
	parse := func(cidr string) bpf.PrefixKeyGo {
		p, err := bpf.ParsePrefix(cidr)
		if err != nil {
			t.Fatal(err)
		}
		return p.PrefixKey()
	}
	parent, child := parse("192.0.2.0/24"), parse("192.0.2.128/25")
	prefixes := map[bpf.PrefixKeyGo]bpf.PrefixStats{parent: {}, child: {}}
	for _, tc := range []struct {
		name, ip string
		p, c     uint32
	}{
		{"Child", "192.0.2.200", 0, 1},
		{"Parent", "192.0.2.10", 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := bpf.LPMKey{Prefixlen: 32}
			copy(key.Addr[:4], net.ParseIP(tc.ip).To4())
			deltas := []IPDelta{{Key: key, Stats: bpf.DstIPStats{PktCount: 1}}}
			for i := 0; i < 64; i++ {
				got := (&Collector{}).countActiveIPsPerPrefix(deltas, prefixes)
				if got[parent] != tc.p || got[child] != tc.c {
					t.Fatalf("iteration %d: parent=%d child=%d, want %d/%d", i, got[parent], got[child], tc.p, tc.c)
				}
			}
		})
	}
}
