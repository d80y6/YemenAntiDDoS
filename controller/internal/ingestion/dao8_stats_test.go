package ingestion

import (
	"net"
	"testing"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
)

func TestDao8_C6_InvalidMiddlePrefix(t *testing.T) {
	for _, direction := range []string{"inbound", "outbound"} {
		t.Run(direction, func(t *testing.T) {
			rings := ring.New(ring.DefaultLimits())
			report := &pb.StatsReport{Timestamp: time.Now().Unix(), UpstreamSampleRate: 1}
			prefixes := []*pb.PrefixStatsMsg{
				{Prefix: []byte{192, 0, 2, 0}, PrefixLen: 24, PktCount: 11},
				{Prefix: []byte{1, 2, 3}, PrefixLen: 24, PktCount: 22},
				{Prefix: []byte{198, 51, 100, 0}, PrefixLen: 24, PktCount: 33},
			}
			ips := []*pb.IPStats{{DstIp: []byte{198, 51, 100, 1}, PktCount: 7}}
			if direction == "inbound" {
				report.PrefixStats = prefixes
				report.IpStats = ips
			} else {
				report.SrcPrefixStats = prefixes
				report.SrcIpStats = ips
			}
			NewStatsWriter(rings).HandleStats("dao8", report)
			getPrefix := rings.GetPrefixRing
			getIP := rings.GetIPRingByKey
			if direction == "outbound" {
				getPrefix = rings.GetSrcPrefixRing
				getIP = rings.GetSrcIPRingByKey
			}
			pr := getPrefix("dao8", "198.51.100.0/24")
			if pr == nil {
				t.Fatal("C prefix ring absent")
			}
			points := pr.Latest(10)
			if len(points) != 1 || points[0].PPS != 33 {
				t.Errorf("C prefix points = %+v, want exactly one point with PPS 33 (never B's 22)", points)
			}
			ipr := getIP("dao8", "198.51.100.0/24", "198.51.100.1")
			if ipr == nil || len(ipr.Latest(1)) != 1 || ipr.Latest(1)[0].PPS != 7 {
				t.Error("IP after invalid placeholder was not matched to C")
			}
		})
	}
}

func TestDao8_C7_IPv6Report(t *testing.T) {
	rings := ring.New(ring.DefaultLimits())
	report := &pb.StatsReport{
		Timestamp: time.Now().Unix(), UpstreamSampleRate: 1,
		PrefixStats: []*pb.PrefixStatsMsg{{Prefix: net.ParseIP("2001:db8::").To16(), PrefixLen: 32, PktCount: 33}},
		IpStats:     []*pb.IPStats{{DstIp: net.ParseIP("2001:db8::1").To16(), PktCount: 7}},
	}
	NewStatsWriter(rings).HandleStats("dao8", report)
	ipr := rings.GetIPRingByKey("dao8", "2001:db8::/32", "2001:db8::1")
	if ipr == nil {
		t.Fatal("IPv6 per-IP ring absent")
	}
	points := ipr.Latest(1)
	if len(points) != 1 || points[0].PPS != 7 {
		t.Fatalf("IPv6 IP points = %+v, want PPS 7", points)
	}
}
