package reporter

import (
	"bytes"
	"net"
	"testing"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
	"github.com/d80y6/YemenDDoS/node/internal/collector"
	pb "github.com/d80y6/YemenDDoS/node/internal/pb"
)

func TestDao8_N7_PrefixWireFormat(t *testing.T) {
	v4 := bpf.PrefixKeyGo{Prefixlen: 120}
	copy(v4.Addr[:], net.ParseIP("::ffff:192.0.2.0").To16())
	v6 := bpf.PrefixKeyGo{Prefixlen: 32}
	copy(v6.Addr[:], net.ParseIP("2001:db8::").To16())
	deltas := []collector.PrefixDelta{{Key: v4}, {Key: v6}}
	msg := reportToProto(&collector.Report{PrefixDeltas: deltas, SrcPrefixDeltas: deltas}, "dao8", "test", 1, 0, nil, 0)
	for _, direction := range []struct {
		name  string
		stats []*pb.PrefixStatsMsg
	}{
		{"inbound", msg.PrefixStats}, {"outbound", msg.SrcPrefixStats},
	} {
		t.Run(direction.name, func(t *testing.T) {
			if len(direction.stats) != 2 {
				t.Fatalf("prefix count = %d, want 2", len(direction.stats))
			}
			for i, tc := range []struct {
				name string
				ip   net.IP
				bits uint32
			}{
				{"v4", net.IP{192, 0, 2, 0}, 24}, {"v6", net.ParseIP("2001:db8::").To16(), 32},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got := direction.stats[i]
					if len(got.Prefix) != len(tc.ip) || !bytes.Equal(got.Prefix, tc.ip) || got.PrefixLen != tc.bits {
						t.Errorf("wire prefix = %x (%d bytes) /%d, want %x (%d bytes) /%d",
							got.Prefix, len(got.Prefix), got.PrefixLen, []byte(tc.ip), len(tc.ip), tc.bits)
					}
				})
			}
		})
	}
}
