package flow

import (
	"net"
	"testing"

	"github.com/littlewolf9527/xsight/shared/decoder"
)

const dao7jiaSecond = int64(12345)
const dao7jiaPrefix = "10.0.0.0/8"

func dao7jiaIP(i int) net.IP { return net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)) }

// Feed the same per-second path used by Add, with an explicit bucket so neither
// wall-clock boundaries nor sleeps determine the result.
func dao7jiaAdd(a *FlowAggregator, b *secondBucket, src bool, i int, pkts uint64) {
	decoders := [MaxDecoderHits]int{decoder.UDP}
	if src {
		a.addOutbound(b, dao7jiaPrefix, dao7jiaIP(i), decoders, 1, pkts, pkts*64)
	} else {
		a.addInbound(b, dao7jiaPrefix, dao7jiaIP(i), decoders, 1, pkts, pkts*64)
	}
}

func dao7jiaFill(t *testing.T, src bool, count int) (*FlowAggregator, *secondBucket) {
	t.Helper()
	if maxBucketIPs != 10_000 {
		t.Fatalf("maxBucketIPs=%d, want 10000", maxBucketIPs)
	}
	a := newTestAggregator([]string{dao7jiaPrefix})
	b := a.getBucket(dao7jiaSecond)
	for i := 1; i <= count; i++ {
		dao7jiaAdd(a, b, src, i, 1)
	}
	return a, b
}

func dao7jiaBucketLimit(t *testing.T, src bool) {
	count := maxBucketIPs + 500
	a, b := dao7jiaFill(t, src, count)
	ips, prefixes, truncated := b.ipStats, b.prefixStats, b.ipTruncated
	global, bytes := b.globalPkts, b.globalBytes
	if src {
		ips, prefixes, truncated = b.srcIPStats, b.srcPrefixStats, b.srcIPTruncated
		global, bytes = b.srcGlobalPkts, b.srcGlobalBytes
	}
	if len(ips) != maxBucketIPs || !truncated {
		t.Errorf("bucket IPs=%d truncated=%t, want %d/true", len(ips), truncated, maxBucketIPs)
	}
	// First arrivals are retained, later arrivals never displace them.
	for i := 1; i <= count; i++ {
		_, exists := ips[dao7jiaIP(i).String()]
		if exists != (i <= maxBucketIPs) {
			t.Fatalf("first-arrival set mismatch at IP %d: exists=%t", i, exists)
		}
	}
	pf := prefixes[dao7jiaPrefix]
	if pf == nil {
		t.Fatal("missing prefix")
	}
	if global != uint64(count) || pf.Pkts != uint64(count) || bytes != uint64(count)*64 || pf.Bytes != bytes {
		t.Errorf("lost input: global=%d prefix=%d bytes=%d prefixBytes=%d", global, pf.Pkts, bytes, pf.Bytes)
	}
	msg := a.FlushAt(dao7jiaSecond, "dao7jia", "flow", 1)
	if msg == nil {
		t.Fatal("missing flushed report")
	}
	reported, prefixReports, total, flag := msg.IpStats, msg.PrefixStats, msg.TotalActiveIps, msg.IpStatsTruncated
	matched, decoderPkts := msg.GlobalStats.MatchedPkts, msg.GlobalStats.DecoderCounts
	otherFlag := msg.SrcIpStatsTruncated
	if src {
		reported, prefixReports, total, flag = msg.SrcIpStats, msg.SrcPrefixStats, msg.TotalActiveSrcIps, msg.SrcIpStatsTruncated
		matched, decoderPkts = msg.GlobalStats.SrcMatchedPkts, msg.GlobalStats.SrcDecoderCounts
		otherFlag = msg.IpStatsTruncated
	}
	if len(reported) != maxBucketIPs || total != maxBucketIPs || !flag || otherFlag {
		t.Errorf("report entries=%d active=%d flag=%t otherFlag=%t", len(reported), total, flag, otherFlag)
	}
	if len(prefixReports) != 1 {
		t.Fatalf("prefix report count=%d, want 1", len(prefixReports))
	}
	if matched != uint64(count) || msg.GlobalStats.TotalPkts != uint64(count) || prefixReports[0].PktCount != uint64(count) {
		t.Errorf("flushed packets: matched=%d total=%d prefix=%d want=%d", matched, msg.GlobalStats.TotalPkts, prefixReports[0].PktCount, count)
	}
	if len(decoderPkts) <= decoder.UDP || decoderPkts[decoder.UDP] != uint32(count) || prefixReports[0].DecoderCounts[decoder.UDP] != uint32(count) {
		t.Error("truncation lost global/prefix decoder packets")
	}
}

func TestDao7jia_F1_InboundBucketLimit(t *testing.T)  { dao7jiaBucketLimit(t, false) }
func TestDao7jia_F1_OutboundBucketLimit(t *testing.T) { dao7jiaBucketLimit(t, true) }

func TestDao7jia_F2_BelowLimitAndDuplicates(t *testing.T) {
	for _, src := range []bool{false, true} {
		name := "inbound"
		if src {
			name = "outbound"
		}
		t.Run(name, func(t *testing.T) {
			a, b := dao7jiaFill(t, src, maxBucketIPs-1)
			for i := 0; i < 1000; i++ {
				dao7jiaAdd(a, b, src, 1, 1)
			}
			ips, prefixes := b.ipStats, b.prefixStats
			if src {
				ips, prefixes = b.srcIPStats, b.srcPrefixStats
			}
			if len(ips) != maxBucketIPs-1 || len(prefixes[dao7jiaPrefix].ActiveIPs) != maxBucketIPs-1 || b.ipTruncated || b.srcIPTruncated {
				t.Errorf("duplicates changed cardinality or flags: ips=%d inbound=%t outbound=%t", len(ips), b.ipTruncated, b.srcIPTruncated)
			}
			if ips[dao7jiaIP(1).String()].Pkts != 1001 {
				t.Error("existing IP stopped accumulating")
			}
			msg := a.FlushAt(dao7jiaSecond, "dao7jia", "flow", 1)
			if msg == nil {
				t.Fatal("missing report")
			}
			total := msg.TotalActiveIps
			if src {
				total = msg.TotalActiveSrcIps
			}
			if total != maxBucketIPs-1 || msg.IpStatsTruncated || msg.SrcIpStatsTruncated {
				t.Errorf("active=%d inbound=%t outbound=%t", total, msg.IpStatsTruncated, msg.SrcIpStatsTruncated)
			}
			if msg.GlobalStats.TotalPkts != maxBucketIPs-1+1000 {
				t.Errorf("global packets=%d", msg.GlobalStats.TotalPkts)
			}
		})
	}
}

func TestDao7jia_F2_ExactlyFullRetainsExisting(t *testing.T) {
	a, b := dao7jiaFill(t, false, maxBucketIPs)
	for i := 1; i <= maxBucketIPs; i++ {
		dao7jiaAdd(a, b, true, i, 1)
	}
	dao7jiaAdd(a, b, false, 1, 1000)
	dao7jiaAdd(a, b, true, 1, 1000)
	msg := a.FlushAt(dao7jiaSecond, "dao7jia", "flow", 1)
	if msg == nil {
		t.Fatal("missing report")
	}
	if msg.IpStatsTruncated || msg.SrcIpStatsTruncated || msg.TotalActiveIps != maxBucketIPs || msg.TotalActiveSrcIps != maxBucketIPs {
		t.Error("exactly full bucket/duplicate must not mark either direction truncated")
	}
	if b.ipStats[dao7jiaIP(1).String()].Pkts != 1001 || b.srcIPStats[dao7jiaIP(1).String()].Pkts != 1001 {
		t.Error("existing IP must keep accumulating at the cap")
	}
}

func TestDao7jia_F3_ActiveIPsBounded(t *testing.T) {
	a, b := dao7jiaFill(t, false, maxBucketIPs+500)
	for i := 1; i <= maxBucketIPs+500; i++ {
		dao7jiaAdd(a, b, true, i, 1)
	}
	for _, prefixes := range []map[string]*prefixDelta{b.prefixStats, b.srcPrefixStats} {
		if got := len(prefixes[dao7jiaPrefix].ActiveIPs); got != maxBucketIPs {
			t.Errorf("ActiveIPs size=%d, want %d", got, maxBucketIPs)
		}
	}
	msg := a.FlushAt(dao7jiaSecond, "dao7jia", "flow", 1)
	if msg == nil || len(msg.PrefixStats) != 1 || len(msg.SrcPrefixStats) != 1 {
		t.Fatal("both prefix reports are required")
	}
	if msg.PrefixStats[0].ActiveIps != maxBucketIPs || msg.SrcPrefixStats[0].ActiveIps != maxBucketIPs {
		t.Errorf("reported active inbound=%d outbound=%d", msg.PrefixStats[0].ActiveIps, msg.SrcPrefixStats[0].ActiveIps)
	}
}

func TestDao7jia_F4_ExistingAggregatorRegression(t *testing.T) {
	t.Run("InboundMatch", TestAggregatorInboundMatch)
	t.Run("OutboundMatch", TestAggregatorOutboundMatch)
	t.Run("InternalToInternalDualCount", TestAggregatorInternalToInternalDualCount)
	t.Run("SampleRateExpansion", TestAggregatorSampleRateExpansion)
	t.Run("NoMatchNoFlush", TestAggregatorNoMatchNoFlush)
	t.Run("TopFlowsOnlyMatched", TestAggregatorTopFlowsOnlyMatched)
	t.Run("BytesToIPv4", TestBytesToIPv4)
	t.Run("BytesToIPv6", TestBytesToIPv6)
	t.Run("TimeSpreadEven", TestAggregatorTimeSpreadEven)
	t.Run("TimeSpreadRemainder", TestAggregatorTimeSpreadRemainder)
	t.Run("TimeSpreadClampMaxDuration", TestAggregatorTimeSpreadClampMaxDuration)
	t.Run("TimeSpreadZeroDurationFallback", TestAggregatorTimeSpreadZeroDurationFallback)
	t.Run("TimeSpreadDurationZeroOrNegative", TestAggregatorTimeSpreadDurationZeroOrNegative)
	t.Run("TimeSpreadBothDirections", TestAggregatorTimeSpreadBothDirections)
	t.Run("HealthSourceActive", TestCollectHealthSourceActive)
	t.Run("HealthSourceOffline", TestCollectHealthSourceOffline)
	t.Run("HealthSourceNeverSeen", TestCollectHealthSourceNeverSeen)
	t.Run("HealthNoListeners", TestCollectHealthNoListeners)
	t.Run("MetricsTemplateMisses", TestCollectMetricsTemplateMisses)
}
