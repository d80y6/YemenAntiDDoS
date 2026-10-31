package ingestion

import (
	"net"
	"testing"
	"time"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
)

func dao12dPrefixes(t *testing.T, cidrs []string) []*pb.PrefixStatsMsg {
	t.Helper()
	var result []*pb.PrefixStatsMsg
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		bits, _ := n.Mask.Size()
		result = append(result, &pb.PrefixStatsMsg{Prefix: n.IP, PrefixLen: uint32(bits), PktCount: 11})
	}
	return result
}

func TestDao12d_G1(t *testing.T) {
	for _, tc := range []struct {
		name                string
		outbound            []bool
		cidrs, ips, targets []string
	}{
		{"In", []bool{false}, []string{"192.0.2.0/24", "192.0.2.128/25"}, []string{"192.0.2.200"}, []string{"192.0.2.128/25"}},
		{"Out", []bool{true}, []string{"192.0.2.0/24", "192.0.2.128/25"}, []string{"192.0.2.200"}, []string{"192.0.2.128/25"}},
		{"Outside", []bool{false, true}, []string{"192.0.2.0/24", "192.0.2.128/25"}, []string{"192.0.2.10"}, []string{"192.0.2.0/24"}},
		{"V6", []bool{false, true}, []string{"2001:db8::/32", "2001:db8:1::/48"}, []string{"2001:db8:1::200"}, []string{"2001:db8:1::/48"}},
		{"Mixed", []bool{false, true}, []string{"192.0.2.0/24", "2001:db8::/32", "192.0.2.128/25", "2001:db8:1::/48"}, []string{"192.0.2.200", "2001:db8:1::200"}, []string{"192.0.2.128/25", "2001:db8:1::/48"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, outbound := range tc.outbound {
				rings := ring.New(ring.DefaultLimits())
				report := &pb.StatsReport{Timestamp: time.Now().Unix()}
				prefixes := dao12dPrefixes(t, tc.cidrs)
				var ips []*pb.IPStats
				for _, ip := range tc.ips {
					ips = append(ips, &pb.IPStats{DstIp: net.ParseIP(ip), PktCount: 7})
				}
				get := rings.GetIPRingByKey
				report.PrefixStats, report.IpStats = prefixes, ips
				if outbound {
					report.PrefixStats, report.IpStats = nil, nil
					report.SrcPrefixStats, report.SrcIpStats = prefixes, ips
					get = rings.GetSrcIPRingByKey
				}
				NewStatsWriter(rings).HandleStats("dao12d", report)
				for i, ip := range tc.ips {
					for _, cidr := range tc.cidrs {
						got := get("dao12d", cidr, ip)
						if cidr != tc.targets[i] {
							if got != nil {
								t.Errorf("outbound=%v IP %s unexpectedly belongs to %s", outbound, ip, cidr)
							}
						} else if got == nil || len(got.Latest(1)) != 1 || got.Latest(1)[0].PPS != 7 {
							t.Errorf("outbound=%v IP %s missing PPS 7 under %s", outbound, ip, cidr)
						}
					}
				}
			}
		})
	}
}

func TestDao12d_G2(t *testing.T) {
	t.Run("Align", func(t *testing.T) {
		rings := ring.New(ring.DefaultLimits())
		prefixes := []*pb.PrefixStatsMsg{
			{Prefix: []byte{192, 0, 2, 0}, PrefixLen: 24, PktCount: 11, ByteCount: 110},
			{Prefix: []byte{1, 2, 3}, PrefixLen: 24, PktCount: 22, ByteCount: 220},
			{Prefix: []byte{192, 0, 2, 128}, PrefixLen: 25, PktCount: 33, ByteCount: 330},
		}
		NewStatsWriter(rings).HandleStats("dao12d", &pb.StatsReport{
			Timestamp: time.Now().Unix(), PrefixStats: prefixes, SrcPrefixStats: prefixes,
		})
		for _, get := range []func(string, string) *ring.PrefixRing{rings.GetPrefixRing, rings.GetSrcPrefixRing} {
			for i, cidr := range []string{"192.0.2.0/24", "192.0.2.128/25"} {
				pr := get("dao12d", cidr)
				if pr == nil {
					t.Fatalf("prefix ring absent: %s", cidr)
				}
				points := pr.Latest(10)
				want := []int64{11, 33}[i]
				if len(points) != 1 || points[0].PPS != want || points[0].BPS != want*80 {
					t.Errorf("%s points=%+v, want PPS=%d BPS=%d", cidr, points, want, want*80)
				}
			}
		}
	})
}

func TestDao12d_G3b(t *testing.T) {
	w := &FlowWriter{ch: make(chan flowBatch, 1)}
	w.HandleFlows("dao12d", &pb.StatsReport{
		PrefixStats: dao12dPrefixes(t, []string{"192.0.2.0/24", "192.0.2.128/25"}),
		TopFlows:    []*pb.FlowSample{{SrcIp: net.ParseIP("203.0.113.9"), DstIp: net.ParseIP("192.0.2.200"), Packets: 7}},
	})
	select {
	case batch := <-w.ch:
		if len(batch.flows) != 1 || batch.flows[0].Prefix == nil {
			t.Fatal("expected one flow with a non-nil prefix")
		}
		if got := *batch.flows[0].Prefix; got != "192.0.2.128/25" {
			t.Errorf("flow prefix=%s, want 192.0.2.128/25", got)
		}
	default:
		t.Fatal("flow batch absent")
	}
}
