package ingestion

import (
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/netutil"
	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store/ring"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

const malformedWarnInterval = time.Minute

type parsedPrefix struct {
	cidr  string
	ipnet *net.IPNet
}

// GlobalPrefixChecker is implemented by threshold.Tree to report
// whether 0.0.0.0/0 is an enabled watched prefix.
type GlobalPrefixChecker interface {
	HasGlobalPrefix() bool
}

// StatsWriter receives StatsReports and writes to the Ring Buffer.
type StatsWriter struct {
	rings         *ring.RingStore
	globalChecker GlobalPrefixChecker // nil-safe; if nil, global ring is never written
	warnMu        sync.Mutex
	badWarnAt     map[string]time.Time
}

func NewStatsWriter(rings *ring.RingStore) *StatsWriter {
	return &StatsWriter{rings: rings}
}

// SetGlobalChecker sets the source for checking if 0.0.0.0/0 is active.
func (w *StatsWriter) SetGlobalChecker(gc GlobalPrefixChecker) {
	w.globalChecker = gc
}

// HandleStats processes a StatsReport into ring buffer data points.
func (w *StatsWriter) HandleStats(nodeID string, report *pb.StatsReport) {
	var badPrefix, badIP, badFlow, firstLen int
	var firstPlen uint32
	recordFirst := func(raw []byte, plen uint32) {
		if badPrefix+badIP+badFlow == 0 {
			firstLen, firstPlen = len(raw), plen
		}
	}
	ts := time.Unix(report.Timestamp, 0)
	// BPF ip_stats/prefix_stats count EVERY matched packet (not subsampled by local_sample_rate).
	// Only upstream_sample_rate needs restoration. local_sample_rate only affects ring buffer sampling.
	upstreamMul := uint64(1)
	if report.UpstreamSampleRate > 1 {
		upstreamMul = uint64(report.UpstreamSampleRate)
	}

	// Pre-parse prefix CIDRs for IP→prefix matching (avoid re-parsing per IP)
	var prefixNets []parsedPrefix
	for _, ps := range report.PrefixStats {
		cidr, ipnet, ok := netutil.CanonicalPrefix(ps.Prefix, ps.PrefixLen)
		if !ok {
			recordFirst(ps.Prefix, ps.PrefixLen)
			badPrefix++
			prefixNets = append(prefixNets, parsedPrefix{})
			continue
		}
		prefixNets = append(prefixNets, parsedPrefix{cidr, ipnet})
	}

	// Write prefix-level data points
	for i, ps := range report.PrefixStats {
		if i >= len(prefixNets) {
			break
		}
		if prefixNets[i].ipnet == nil {
			continue
		}
		mul64 := int64(upstreamMul)
		dp := ring.DataPoint{
			Time:      ts,
			PPS:       int64(ps.PktCount) * mul64,
			BPS:       int64(ps.ByteCount) * 8 * mul64,
			ActiveIPs: ps.ActiveIps,
			Overflow:  ps.OverflowCount,
		}
		decoderCounts := ps.GetDecoderCounts()
		if len(decoderCounts) > 0 {
			for j := 0; j < len(decoderCounts) && j < decoder.MaxDecoders; j++ {
				dp.DecoderPPS[j] = int32(int64(decoderCounts[j]) * mul64)
			}
		} else {
			// Fallback: read deprecated fixed fields (old node compatibility)
			dp.DecoderPPS[decoder.TCP] = int32(int64(ps.GetTcpCount()) * mul64)
			dp.DecoderPPS[decoder.TCPSyn] = int32(int64(ps.GetTcpSynCount()) * mul64)
			dp.DecoderPPS[decoder.UDP] = int32(int64(ps.GetUdpCount()) * mul64)
			dp.DecoderPPS[decoder.ICMP] = int32(int64(ps.GetIcmpCount()) * mul64)
			dp.DecoderPPS[decoder.Frag] = int32(int64(ps.GetFragCount()) * mul64)
		}
		decoderByteCounts := ps.GetDecoderByteCounts()
		for j := 0; j < len(decoderByteCounts) && j < decoder.MaxDecoders; j++ {
			dp.DecoderBPS[j] = int64(decoderByteCounts[j]) * 8 * mul64
		}
		w.rings.PushPrefix(nodeID, prefixNets[i].cidr, dp)
	}

	// Write per-IP data points
	matchNets := sortedForMatch(prefixNets)
	for _, ip := range report.IpStats {
		if _, ok := netutil.CanonicalIP(ip.DstIp); !ok {
			recordFirst(ip.DstIp, 0)
			badIP++
			continue
		}
		dstIP := net.IP(ip.DstIp)
		prefix := matchPrefix(matchNets, dstIP)
		if prefix == "" {
			continue // skip IPs outside all watched prefixes
		}

		mul64 := int64(upstreamMul)
		dp := ring.DataPoint{
			Time: ts,
			PPS:  int64(ip.PktCount) * mul64,
			BPS:  int64(ip.ByteCount) * 8 * mul64,
		}
		decoderCounts := ip.GetDecoderCounts()
		if len(decoderCounts) > 0 {
			for j := 0; j < len(decoderCounts) && j < decoder.MaxDecoders; j++ {
				dp.DecoderPPS[j] = int32(int64(decoderCounts[j]) * mul64)
			}
		} else {
			dp.DecoderPPS[decoder.TCP] = int32(int64(ip.GetTcpCount()) * mul64)
			dp.DecoderPPS[decoder.TCPSyn] = int32(int64(ip.GetTcpSynCount()) * mul64)
			dp.DecoderPPS[decoder.UDP] = int32(int64(ip.GetUdpCount()) * mul64)
			dp.DecoderPPS[decoder.ICMP] = int32(int64(ip.GetIcmpCount()) * mul64)
			dp.DecoderPPS[decoder.Frag] = int32(int64(ip.GetFragCount()) * mul64)
		}
		decoderByteCounts := ip.GetDecoderByteCounts()
		for j := 0; j < len(decoderByteCounts) && j < decoder.MaxDecoders; j++ {
			dp.DecoderBPS[j] = int64(decoderByteCounts[j]) * 8 * mul64
		}
		w.rings.PushIP(nodeID, prefix, dstIP, dp)
	}

	if report.IpStatsTruncated {
		log.Printf("ring: node=%s truncated ip_stats (total=%d reported=%d)",
			nodeID, report.TotalActiveIps, len(report.IpStats))
	}

	// Write global_stats to virtual 0.0.0.0/0 prefix ring (for global threshold detection)
	if gs := report.GetGlobalStats(); gs != nil && w.globalChecker != nil && w.globalChecker.HasGlobalPrefix() {
		mul64 := int64(upstreamMul)
		dp := ring.DataPoint{
			Time: ts,
			PPS:  int64(gs.MatchedPkts) * mul64,
			BPS:  int64(gs.MatchedBytes) * 8 * mul64,
		}
		// Per-decoder breakdown
		decoderCounts := gs.GetDecoderCounts()
		for j := 0; j < len(decoderCounts) && j < decoder.MaxDecoders; j++ {
			dp.DecoderPPS[j] = int32(int64(decoderCounts[j]) * mul64)
		}
		decoderByteCounts := gs.GetDecoderByteCounts()
		for j := 0; j < len(decoderByteCounts) && j < decoder.MaxDecoders; j++ {
			dp.DecoderBPS[j] = int64(decoderByteCounts[j]) * 8 * mul64
		}
		w.rings.PushPrefix(nodeID, "0.0.0.0/0", dp)

		// Outbound global ring (for 0.0.0.0/0 + direction=sends)
		srcDp := ring.DataPoint{
			Time: ts,
			PPS:  int64(gs.GetSrcMatchedPkts()) * mul64,
			BPS:  int64(gs.GetSrcMatchedBytes()) * 8 * mul64,
		}
		srcDC := gs.GetSrcDecoderCounts()
		for j := 0; j < len(srcDC) && j < decoder.MaxDecoders; j++ {
			srcDp.DecoderPPS[j] = int32(int64(srcDC[j]) * mul64)
		}
		srcDBC := gs.GetSrcDecoderByteCounts()
		for j := 0; j < len(srcDBC) && j < decoder.MaxDecoders; j++ {
			srcDp.DecoderBPS[j] = int64(srcDBC[j]) * 8 * mul64
		}
		w.rings.PushSrcPrefix(nodeID, "0.0.0.0/0", srcDp)
	}

	// Write outbound (src_ip matched) prefix and IP data to src rings
	var srcPrefixNets []parsedPrefix
	for _, sps := range report.GetSrcPrefixStats() {
		cidr, ipnet, ok := netutil.CanonicalPrefix(sps.Prefix, sps.PrefixLen)
		if !ok {
			recordFirst(sps.Prefix, sps.PrefixLen)
			badPrefix++
			srcPrefixNets = append(srcPrefixNets, parsedPrefix{})
			continue
		}
		srcPrefixNets = append(srcPrefixNets, parsedPrefix{cidr, ipnet})
	}

	for i, sps := range report.GetSrcPrefixStats() {
		if i >= len(srcPrefixNets) {
			break
		}
		if srcPrefixNets[i].ipnet == nil {
			continue
		}
		mul64 := int64(upstreamMul)
		dp := ring.DataPoint{
			Time:      ts,
			PPS:       int64(sps.PktCount) * mul64,
			BPS:       int64(sps.ByteCount) * 8 * mul64,
			ActiveIPs: sps.ActiveIps,
			Overflow:  sps.OverflowCount,
		}
		srcDC := sps.GetDecoderCounts()
		for j := 0; j < len(srcDC) && j < decoder.MaxDecoders; j++ {
			dp.DecoderPPS[j] = int32(int64(srcDC[j]) * mul64)
		}
		srcDBC := sps.GetDecoderByteCounts()
		for j := 0; j < len(srcDBC) && j < decoder.MaxDecoders; j++ {
			dp.DecoderBPS[j] = int64(srcDBC[j]) * 8 * mul64
		}
		w.rings.PushSrcPrefix(nodeID, srcPrefixNets[i].cidr, dp)
	}

	srcMatchNets := sortedForMatch(srcPrefixNets)
	for _, sip := range report.GetSrcIpStats() {
		if _, ok := netutil.CanonicalIP(sip.DstIp); !ok {
			recordFirst(sip.DstIp, 0)
			badIP++
			continue
		}
		srcIP := net.IP(sip.DstIp) // proto reuses dst_ip bytes for src_ip
		prefix := matchPrefix(srcMatchNets, srcIP)
		if prefix == "" {
			continue
		}
		mul64 := int64(upstreamMul)
		dp := ring.DataPoint{
			Time: ts,
			PPS:  int64(sip.PktCount) * mul64,
			BPS:  int64(sip.ByteCount) * 8 * mul64,
		}
		srcDC := sip.GetDecoderCounts()
		for j := 0; j < len(srcDC) && j < decoder.MaxDecoders; j++ {
			dp.DecoderPPS[j] = int32(int64(srcDC[j]) * mul64)
		}
		srcDBC := sip.GetDecoderByteCounts()
		for j := 0; j < len(srcDBC) && j < decoder.MaxDecoders; j++ {
			dp.DecoderBPS[j] = int64(srcDBC[j]) * 8 * mul64
		}
		w.rings.PushSrcIP(nodeID, prefix, srcIP, dp)
	}

	for _, flow := range report.GetTopFlows() {
		if _, ok := netutil.CanonicalIP(flow.SrcIp); !ok {
			recordFirst(flow.SrcIp, 0)
			badFlow++
		}
		if _, ok := netutil.CanonicalIP(flow.DstIp); !ok {
			recordFirst(flow.DstIp, 0)
			badFlow++
		}
	}
	if badPrefix+badIP+badFlow > 0 {
		w.warnMalformed(nodeID, badPrefix, badIP, badFlow, firstLen, firstPlen)
	}
}

func (w *StatsWriter) warnMalformed(nodeID string, prefixes, ips, flows, firstLen int, firstPlen uint32) {
	w.warnMu.Lock()
	defer w.warnMu.Unlock()
	now := time.Now()
	if last := w.badWarnAt[nodeID]; !last.IsZero() && now.Sub(last) < malformedWarnInterval {
		return
	}
	if w.badWarnAt == nil {
		w.badWarnAt = make(map[string]time.Time)
	}
	w.badWarnAt[nodeID] = now
	log.Printf("WARN ingestion: node=%s skipped %d malformed address entries (prefix=%d ip=%d flow=%d, first: len=%d plen=%d); next warning for this node in ≥1m",
		nodeID, prefixes+ips+flows, prefixes, ips, flows, firstLen, firstPlen)
}

func sortedForMatch(nets []parsedPrefix) []parsedPrefix {
	matches := make([]parsedPrefix, 0, len(nets))
	for _, n := range nets {
		if n.ipnet != nil {
			matches = append(matches, n)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		a, _ := matches[i].ipnet.Mask.Size()
		b, _ := matches[j].ipnet.Mask.Size()
		return a > b
	})
	return matches
}

// matchPrefix returns the first match; callers pass a longest-first list.
func matchPrefix(nets []parsedPrefix, dstIP net.IP) string {
	for _, n := range nets {
		if n.ipnet != nil && n.ipnet.Contains(dstIP) {
			return n.cidr
		}
	}
	return ""
}
