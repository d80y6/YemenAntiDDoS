// Package collector reads BPF maps every second, computes deltas, adjusts
// the dynamic sample rate, and outputs results for verification (P3) or
// upstream consumption (P5+).
package collector

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
	"github.com/d80y6/YemenDDoS/node/internal/sampler"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

// ----- configuration constants -----

const (
	// DefaultTargetSPS is the default target samples per second fed to gopacket.
	DefaultTargetSPS = 100_000

	// maxIPDelta is the ip_stats truncation threshold (brainstorm: 10 000).
	maxIPDelta = 10_000

	// topKTerminal is how many IPs to print in the terminal output.
	topKTerminal = 10

	// ewmaAlpha is the EWMA smoothing factor for sample rate (brainstorm: α=0.3).
	ewmaAlpha = 0.3

	// Write BPF only when |smoothed-applied| >= frac*applied.
	hysteresisFrac = 0.1

	// minHoldTime prevents sample rate oscillation (brainstorm: 3 s).
	minHoldTime = 3 * time.Second

	// maxSampleRate clamps the upper bound (brainstorm: 1000).
	maxSampleRate = 1000
)

// ----- public types -----

var ipIdleTicks uint16 = 300

var testHookAfterSkipDecision func() // test-only; nil in production

const maxIdleDeletesPerTick = 10_000

// IPDelta is a single IP's per-second delta.
type IPDelta struct {
	Key   bpf.LPMKey
	Stats bpf.DstIPStats
}

// PrefixDelta is a single prefix's per-second delta plus active-IP count.
type PrefixDelta struct {
	Key       bpf.PrefixKeyGo
	Stats     bpf.PrefixStats
	ActiveIPs uint32
}

// GlobalDelta is the per-second delta for global counters.
// v2.11: added MatchedBytes + per-decoder breakdown for 0.0.0.0/0 global threshold.
// v2.11 Phase 2: added outbound (src_ip matched) counters.
type GlobalDelta struct {
	TotalPkts         uint64
	TotalBytes        uint64
	MatchedPkts       uint64
	MatchedBytes      uint64                      // bytes within watch scope
	SampleDrops       uint64                      // ring buffer reserve failures this tick
	DecoderCounts     [decoder.MaxDecoders]uint32 // per-decoder PPS (inbound matched only)
	DecoderByteCounts [decoder.MaxDecoders]uint64 // per-decoder BPS (inbound matched only)
	// Outbound (src_ip matched) global counters
	SrcMatchedPkts       uint64
	SrcMatchedBytes      uint64
	SrcDecoderCounts     [decoder.MaxDecoders]uint32
	SrcDecoderByteCounts [decoder.MaxDecoders]uint64
}

// HealthStatus represents Node health per brainstorm spec.
type HealthStatus struct {
	Status  string // "healthy" | "degraded" | "unhealthy"
	Message string
}

// Report is the output of a single collection tick.
type Report struct {
	Timestamp    time.Time
	Global       GlobalDelta
	IPDeltas     []IPDelta
	PrefixDeltas []PrefixDelta
	// v2.11 Phase 2: outbound (src_ip matched) deltas
	SrcIPDeltas       []IPDelta
	SrcPrefixDeltas   []PrefixDelta
	SrcTruncated      bool
	TotalActiveSrcIPs int
	Truncated         bool
	TotalActiveIPs    int
	SampleRate        uint32
	UpstreamRate      uint32 // zero falls back to the reporter's startup rate
	Health            HealthStatus
	TopFlows          []sampler.FlowEntry // top-N flows from flow table this tick
}

// ----- collector -----

// Collector reads BPF maps every second and computes deltas.
type Collector struct {
	mgr *bpf.Manager

	// Reports channel delivers each tick's report to the reporter (P5).
	// Buffered so collection is not blocked by slow consumers.
	Reports chan *Report

	// snapshots from last tick (inbound)
	lastGlobal   bpf.GlobalStats
	lastGlobalAt time.Time // when lastGlobal was committed
	lastIP       map[bpf.LPMKey]bpf.DstIPStats
	lastPrefix   map[bpf.PrefixKeyGo]bpf.PrefixStats
	// snapshots from last tick (outbound)
	lastSrcIP     map[bpf.LPMKey]bpf.DstIPStats
	lastSrcPrefix map[bpf.PrefixKeyGo]bpf.PrefixStats
	idleIP        map[bpf.LPMKey]uint16
	idleSrc       map[bpf.LPMKey]uint16

	// report channel drop counter (rate-limited log)
	reportDrops uint64

	// dynamic sample rate state
	smoothedRate   float64
	appliedRate    uint32 // last successful slot 0 write by this process; Report.SampleRate
	lastRateChange time.Time

	// backpressure: consecutive ticks with increasing sample_drops
	dropTicks int

	// health: count consecutive ticks with zero global_stats growth
	zeroTicks int

	// HotSwap: skip next tick's deltas to avoid cumulative-as-delta spike
	skipNextTick atomic.Bool
	upstreamRate atomic.Uint32

	// config
	targetSPS float64

	// Flow table (optional, set via SetFlowTable)
	flowTable *sampler.FlowTable
}

// New creates a Collector that reads maps from mgr.
// targetSPS is the target samples-per-second (0 = DefaultTargetSPS).
func New(mgr *bpf.Manager, targetSPS float64) *Collector {
	if targetSPS <= 0 {
		targetSPS = DefaultTargetSPS
	}
	c := &Collector{
		mgr:           mgr,
		Reports:       make(chan *Report, 4),
		lastIP:        make(map[bpf.LPMKey]bpf.DstIPStats),
		lastPrefix:    make(map[bpf.PrefixKeyGo]bpf.PrefixStats),
		lastSrcIP:     make(map[bpf.LPMKey]bpf.DstIPStats),
		lastSrcPrefix: make(map[bpf.PrefixKeyGo]bpf.PrefixStats),
		idleIP:        make(map[bpf.LPMKey]uint16),
		idleSrc:       make(map[bpf.LPMKey]uint16),
		smoothedRate:  1,
		appliedRate:   1,
		targetSPS:     targetSPS,
	}
	c.skipNextTick.Store(true) // skip first tick to establish baseline
	if mgr != nil {
		if gs, err := mgr.GlobalStats(); err == nil {
			c.lastGlobal = *gs
			c.lastGlobalAt = time.Now()
		} else {
			log.Printf("collector: initial global_stats baseline: %v", err)
		}
		if err := mgr.SetSampleRate(1); err != nil {
			log.Printf("collector: reset sample_rate to 1: %v", err)
		}
	}
	return c
}

// SetUpstreamRate binds the upstream multiplier to subsequent collection ticks.
func (c *Collector) SetUpstreamRate(v uint32) {
	c.upstreamRate.Store(v)
}

// SetFlowTable sets the flow table used to drain top-N flows each tick.
// Must be called before Run().
func (c *Collector) SetFlowTable(ft *sampler.FlowTable) {
	c.flowTable = ft
}

// NotifyHotSwap tells the collector that a BPF map slot swap happened.
// The next tick will update baselines but skip delta reporting to avoid
// cumulative-as-delta spikes (BPF counters reset to new slot baseline).
func (c *Collector) NotifyHotSwap() {
	c.skipNextTick.Store(true)
}

// Run starts the 1-second collection loop.  Blocks until ctx is cancelled.
func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			report, err := c.collect()
			if err != nil {
				log.Printf("collector: %v", err)
				continue
			}
			c.logReport(report)
			// Non-blocking send to Reports channel for P5 reporter
			select {
			case c.Reports <- report:
			default:
				c.reportDrops++
				if c.reportDrops == 1 || c.reportDrops%60 == 0 {
					log.Printf("collector: report channel full, dropping tick (total_drops=%d)", c.reportDrops)
				}
			}
		}
	}
}

// ----- internal -----

func (c *Collector) collect() (*Report, error) {
	fail := func(err error) (*Report, error) {
		c.skipNextTick.Store(true)
		return nil, err
	}
	now := time.Now()

	// 1. Read global_stats
	gs, err := c.mgr.GlobalStats()
	if err != nil {
		return fail(fmt.Errorf("global_stats: %w", err))
	}
	k := tickSpan(c.lastGlobalAt, now)
	gd := GlobalDelta{
		TotalPkts:    gs.TotalPkts - c.lastGlobal.TotalPkts,
		TotalBytes:   gs.TotalBytes - c.lastGlobal.TotalBytes,
		MatchedPkts:  gs.MatchedPkts - c.lastGlobal.MatchedPkts,
		MatchedBytes: gs.MatchedBytes - c.lastGlobal.MatchedBytes,
		SampleDrops:  gs.SampleDrops - c.lastGlobal.SampleDrops,
	}
	// Per-decoder global deltas (inbound)
	for i := 0; i < decoder.MaxDecoders; i++ {
		gd.DecoderCounts[i] = gs.DecoderCounts[i] - c.lastGlobal.DecoderCounts[i]
		gd.DecoderByteCounts[i] = gs.DecoderByteCounts[i] - c.lastGlobal.DecoderByteCounts[i]
	}
	// Outbound global deltas
	gd.SrcMatchedPkts = gs.SrcMatchedPkts - c.lastGlobal.SrcMatchedPkts
	gd.SrcMatchedBytes = gs.SrcMatchedBytes - c.lastGlobal.SrcMatchedBytes
	for i := 0; i < decoder.MaxDecoders; i++ {
		gd.SrcDecoderCounts[i] = gs.SrcDecoderCounts[i] - c.lastGlobal.SrcDecoderCounts[i]
		gd.SrcDecoderByteCounts[i] = gs.SrcDecoderByteCounts[i] - c.lastGlobal.SrcDecoderByteCounts[i]
	}
	c.lastGlobal = *gs
	c.lastGlobalAt = now

	// 2. Read prefix_stats
	prefixNow := make(map[bpf.PrefixKeyGo]bpf.PrefixStats)
	{
		iter := c.mgr.IterPrefixStats()
		var k bpf.PrefixKeyGo
		var v bpf.PrefixStats
		for iter.Next(&k, &v) {
			prefixNow[k] = v
		}
		if err := iter.Err(); err != nil {
			return fail(fmt.Errorf("prefix_stats iter: %w", err))
		}
	}

	// 3. Read ip_stats (active slot) — batch syscalls for performance
	slot, err := c.mgr.ReadActiveSlot()
	if err != nil {
		return fail(err)
	}
	ipNow, err := c.mgr.BatchReadIPStats()
	if err != nil {
		return fail(fmt.Errorf("ip_stats: %w", err))
	}

	// 4. Compute IP deltas (only entries with pkt_count delta > 0)
	var ipDeltas []IPDelta
	for k, cur := range ipNow {
		prev := c.lastIP[k]
		d := subtractIPStats(cur, prev)
		if d.PktCount > 0 {
			ipDeltas = append(ipDeltas, IPDelta{Key: k, Stats: d})
		}
	}
	totalActiveIPs := len(ipDeltas)

	// Truncation: if > maxIPDelta, keep top-K by pkt_count
	truncated := false
	if len(ipDeltas) > maxIPDelta {
		truncated = true
		sort.Slice(ipDeltas, func(i, j int) bool {
			return ipDeltas[i].Stats.PktCount > ipDeltas[j].Stats.PktCount
		})
		ipDeltas = ipDeltas[:maxIPDelta]
	}

	// 5. Compute prefix deltas + active_ips per prefix
	prefixIPCount := c.countActiveIPsPerPrefix(ipDeltas, prefixNow)
	var prefixDeltas []PrefixDelta
	for k, cur := range prefixNow {
		prev := c.lastPrefix[k]
		d := subtractPrefixStats(cur, prev)
		if d.PktCount > 0 || d.OverflowCount > 0 {
			prefixDeltas = append(prefixDeltas, PrefixDelta{
				Key:       k,
				Stats:     d,
				ActiveIPs: prefixIPCount[k],
			})
		}
	}

	// 5b. Read outbound (src) maps — fail-closed, same as inbound
	srcPrefixNow := make(map[bpf.PrefixKeyGo]bpf.PrefixStats)
	{
		iter := c.mgr.IterSrcPrefixStats()
		var k bpf.PrefixKeyGo
		var v bpf.PrefixStats
		for iter.Next(&k, &v) {
			srcPrefixNow[k] = v
		}
		if err := iter.Err(); err != nil {
			return fail(fmt.Errorf("src_prefix_stats iter: %w", err))
		}
	}

	srcIPNow, err := c.mgr.BatchReadSrcIPStats()
	if err != nil {
		return fail(fmt.Errorf("src_ip_stats: %w", err))
	}

	var srcIPDeltas []IPDelta
	for k, cur := range srcIPNow {
		prev := c.lastSrcIP[k]
		d := subtractIPStats(cur, prev)
		if d.PktCount > 0 {
			srcIPDeltas = append(srcIPDeltas, IPDelta{Key: k, Stats: d})
		}
	}
	totalActiveSrcIPs := len(srcIPDeltas)
	srcTruncated := false
	if len(srcIPDeltas) > maxIPDelta {
		srcTruncated = true
		sort.Slice(srcIPDeltas, func(i, j int) bool {
			return srcIPDeltas[i].Stats.PktCount > srcIPDeltas[j].Stats.PktCount
		})
		srcIPDeltas = srcIPDeltas[:maxIPDelta]
	}

	srcPrefixIPCount := c.countActiveIPsPerPrefix(srcIPDeltas, srcPrefixNow)
	var srcPrefixDeltas []PrefixDelta
	for k, cur := range srcPrefixNow {
		prev := c.lastSrcPrefix[k]
		d := subtractPrefixStats(cur, prev)
		if d.PktCount > 0 || d.OverflowCount > 0 {
			srcPrefixDeltas = append(srcPrefixDeltas, PrefixDelta{
				Key:       k,
				Stats:     d,
				ActiveIPs: srcPrefixIPCount[k],
			})
		}
	}

	// 6. Backpressure tracking: consecutive ticks with ring buffer drops
	if gd.SampleDrops > 0 {
		c.dropTicks++
	} else {
		c.dropTicks = 0
	}

	// Health: detect stale global_stats (mirror port may be down)
	if gd.TotalPkts == 0 {
		c.zeroTicks++
	} else {
		c.zeroTicks = 0
	}
	health := HealthStatus{Status: "healthy"}
	if c.zeroTicks >= 10 {
		health = HealthStatus{Status: "degraded", Message: "global_stats not growing for 10+ seconds"}
	}

	scaleGlobalDelta(&gd, k)
	scaleIPDeltas(ipDeltas, k)
	scalePrefixDeltas(prefixDeltas, k)
	scaleIPDeltas(srcIPDeltas, k)
	scalePrefixDeltas(srcPrefixDeltas, k)

	// Store snapshots for next tick
	prevIP, prevSrc := c.lastIP, c.lastSrcIP
	c.lastIP = ipNow
	c.lastPrefix = prefixNow
	c.lastSrcIP = srcIPNow
	c.lastSrcPrefix = srcPrefixNow

	// HotSwap guard: skip deltas AND sample rate adjustment for one tick
	// after startup or slot swap. The matched count on this tick is cumulative
	// (not a 1-second delta), so feeding it into EWMA would produce a wildly
	// inflated local_sample_rate that persists for many subsequent ticks and
	// causes the upstream restoration (observed × upstream × local) to overshoot.
	skip := c.skipNextTick.Swap(false)
	if testHookAfterSkipDecision != nil {
		testHookAfterSkipDecision()
	}
	if skip {
		clear(c.idleIP)
		clear(c.idleSrc)
		log.Println("collector: skipping delta report + sample rate (baseline reset)")
		ipDeltas = nil
		prefixDeltas = nil
		// Keep current smoothedRate unchanged; use it as-is for this tick's report
		sampleRate := c.appliedRate
		return &Report{
			Timestamp:      now,
			Global:         gd,
			IPDeltas:       nil,
			PrefixDeltas:   nil,
			Truncated:      false,
			TotalActiveIPs: 0,
			SampleRate:     sampleRate,
			UpstreamRate:   c.upstreamRate.Load(),
			Health:         health,
		}, nil
	}

	// All reads and snapshot commits succeeded; no early returns remain.
	c.deleteIdle(false, slot, ipNow, prevIP, c.idleIP)
	c.deleteIdle(true, slot, srcIPNow, prevSrc, c.idleSrc)

	// 7. Dynamic sample rate adjustment (includes backpressure)
	// Dynamic sample rate uses total matched PPS (inbound + outbound)
	sampleRate := c.adjustSampleRate(gd.MatchedPkts+gd.SrcMatchedPkts, now)

	// 8. Drain flow table top-N for this tick
	var topFlows []sampler.FlowEntry
	if c.flowTable != nil {
		topFlows = c.flowTable.DrainTopN(100)
	}

	return &Report{
		Timestamp:         now,
		Global:            gd,
		IPDeltas:          ipDeltas,
		PrefixDeltas:      prefixDeltas,
		Truncated:         truncated,
		TotalActiveIPs:    totalActiveIPs,
		SrcIPDeltas:       srcIPDeltas,
		SrcPrefixDeltas:   srcPrefixDeltas,
		SrcTruncated:      srcTruncated,
		TotalActiveSrcIPs: totalActiveSrcIPs,
		SampleRate:        sampleRate,
		UpstreamRate:      c.upstreamRate.Load(),
		Health:            health,
		TopFlows:          topFlows,
	}, nil
}

func (c *Collector) deleteIdle(src bool, slot uint32, seen, prev map[bpf.LPMKey]bpf.DstIPStats, idle map[bpf.LPMKey]uint16) {
	for k := range idle {
		if _, ok := seen[k]; !ok {
			delete(idle, k)
		}
	}
	var keys []bpf.LPMKey
	for k, cur := range seen {
		if cur.PktCount != prev[k].PktCount {
			idle[k] = 0
		} else if idle[k] < math.MaxUint16 {
			idle[k]++
		}
		if idle[k] >= ipIdleTicks && len(keys) < maxIdleDeletesPerTick {
			keys = append(keys, k)
		}
	}
	deleted, _, err := c.mgr.DeleteIdleStats(src, slot, keys, seen)
	for _, k := range deleted {
		delete(seen, k) // seen is already committed as lastIP / lastSrcIP.
		delete(idle, k)
	}
	if err != nil {
		log.Printf("collector: delete idle stats src=%t: %v", src, err)
	}
}

// adjustSampleRate implements the EWMA + hysteresis + min-hold algorithm.
// Reference: brainstorm-node.md "Dynamic Sample Rate Mechanism"
func (c *Collector) adjustSampleRate(matchedPPS uint64, now time.Time) uint32 {
	s, cand, write := nextSampleRate(c.smoothedRate, c.appliedRate, c.lastRateChange, matchedPPS, c.dropTicks, c.targetSPS, now)
	c.smoothedRate = s
	if write {
		if err := c.mgr.SetSampleRate(cand); err != nil {
			log.Printf("collector: set sample_rate %d: %v (keeping %d)", cand, err, c.appliedRate)
		} else {
			c.appliedRate = cand
			c.lastRateChange = now
		}
	}
	if c.dropTicks >= 3 {
		log.Printf("collector: backpressure engaged (drops for %d ticks), sample_rate=%d", c.dropTicks, c.appliedRate)
	}
	return c.appliedRate
}

func nextSampleRate(smoothed float64, applied uint32, lastChange time.Time, matchedPPS uint64, dropTicks int, targetSPS float64, now time.Time) (newSmoothed float64, cand uint32, write bool) {
	raw := float64(matchedPPS) / targetSPS
	if raw < 2 {
		raw = 1
	}
	if dropTicks >= 3 && raw < maxSampleRate {
		raw = math.Max(raw*2, float64(applied)*2)
	}
	raw = math.Max(1, math.Min(raw, maxSampleRate))
	newSmoothed = ewmaAlpha*raw + (1-ewmaAlpha)*smoothed
	cand = max(1, uint32(math.Round(newSmoothed)))
	write = cand != applied && math.Abs(newSmoothed-float64(applied)) >= hysteresisFrac*float64(applied) && now.Sub(lastChange) >= minHoldTime
	return
}

func tickSpan(prev, now time.Time) uint64 {
	if prev.IsZero() {
		return 1
	}
	k := math.Round(now.Sub(prev).Seconds())
	if k < 1 {
		return 1
	}
	return uint64(k)
}

func scaleGlobalDelta(d *GlobalDelta, k uint64) {
	if k <= 1 {
		return
	}
	d.TotalPkts /= k
	d.TotalBytes /= k
	d.MatchedPkts /= k
	d.MatchedBytes /= k
	d.SampleDrops /= k
	d.SrcMatchedPkts /= k
	d.SrcMatchedBytes /= k
	for i := range d.DecoderCounts {
		d.DecoderCounts[i] = uint32(uint64(d.DecoderCounts[i]) / k)
		d.DecoderByteCounts[i] /= k
		d.SrcDecoderCounts[i] = uint32(uint64(d.SrcDecoderCounts[i]) / k)
		d.SrcDecoderByteCounts[i] /= k
	}
}

func scaleIPDeltas(ds []IPDelta, k uint64) {
	if k <= 1 {
		return
	}
	for i := range ds {
		d := &ds[i].Stats
		d.PktCount /= k
		d.ByteCount /= k
		d.SmallPkt = uint32(uint64(d.SmallPkt) / k)
		d.MediumPkt = uint32(uint64(d.MediumPkt) / k)
		d.LargePkt = uint32(uint64(d.LargePkt) / k)
		for j := range d.DecoderCounts {
			d.DecoderCounts[j] = uint32(uint64(d.DecoderCounts[j]) / k)
			d.DecoderByteCounts[j] /= k
		}
	}
}

func scalePrefixDeltas(ds []PrefixDelta, k uint64) {
	if k <= 1 {
		return
	}
	for i := range ds {
		d := &ds[i].Stats
		d.PktCount /= k
		d.ByteCount /= k
		d.OverflowCount = uint32(uint64(d.OverflowCount) / k)
		for j := range d.DecoderCounts {
			d.DecoderCounts[j] = uint32(uint64(d.DecoderCounts[j]) / k)
			d.DecoderByteCounts[j] /= k
		}
	}
}

type prefixNet struct {
	key bpf.PrefixKeyGo
	net net.IPNet
}

func sortLongestFirst(ps []prefixNet) {
	sort.SliceStable(ps, func(i, j int) bool {
		a, _ := ps[i].net.Mask.Size()
		b, _ := ps[j].net.Mask.Size()
		return a > b
	})
}

// countActiveIPsPerPrefix counts how many active IPs fall under each prefix.
func (c *Collector) countActiveIPsPerPrefix(
	ipDeltas []IPDelta,
	prefixNow map[bpf.PrefixKeyGo]bpf.PrefixStats,
) map[bpf.PrefixKeyGo]uint32 {
	// Build list of net.IPNet from known prefix keys
	var prefixes []prefixNet
	for k := range prefixNow {
		ipNet := PrefixKeyToIPNet(k)
		prefixes = append(prefixes, prefixNet{key: k, net: ipNet})
	}
	sortLongestFirst(prefixes)

	counts := make(map[bpf.PrefixKeyGo]uint32)
	for _, d := range ipDeltas {
		ip := LPMKeyToIP(d.Key)
		for _, p := range prefixes {
			if p.net.Contains(ip) {
				counts[p.key]++
				break
			}
		}
	}
	return counts
}

// ----- helpers -----

func subtractIPStats(cur, prev bpf.DstIPStats) bpf.DstIPStats {
	d := bpf.DstIPStats{
		PktCount:  cur.PktCount - prev.PktCount,
		ByteCount: cur.ByteCount - prev.ByteCount,
		SmallPkt:  cur.SmallPkt - prev.SmallPkt,
		MediumPkt: cur.MediumPkt - prev.MediumPkt,
		LargePkt:  cur.LargePkt - prev.LargePkt,
	}
	for i := 0; i < len(d.DecoderCounts); i++ {
		d.DecoderCounts[i] = cur.DecoderCounts[i] - prev.DecoderCounts[i]
	}
	for i := 0; i < len(d.DecoderByteCounts); i++ {
		d.DecoderByteCounts[i] = cur.DecoderByteCounts[i] - prev.DecoderByteCounts[i]
	}
	return d
}

func subtractPrefixStats(cur, prev bpf.PrefixStats) bpf.PrefixStats {
	d := bpf.PrefixStats{
		PktCount:      cur.PktCount - prev.PktCount,
		ByteCount:     cur.ByteCount - prev.ByteCount,
		OverflowCount: cur.OverflowCount - prev.OverflowCount,
	}
	for i := 0; i < len(d.DecoderCounts); i++ {
		d.DecoderCounts[i] = cur.DecoderCounts[i] - prev.DecoderCounts[i]
	}
	for i := 0; i < len(d.DecoderByteCounts); i++ {
		d.DecoderByteCounts[i] = cur.DecoderByteCounts[i] - prev.DecoderByteCounts[i]
	}
	return d
}

// LPMKeyToIP extracts a net.IP from an LPMKey (/32 → IPv4, /128 → IPv6).
func LPMKeyToIP(k bpf.LPMKey) net.IP {
	if k.Prefixlen == 32 {
		return net.IP(k.Addr[:4])
	}
	return net.IP(k.Addr[:16])
}

// PrefixKeyToIPNet builds a net.IPNet from a PrefixKeyGo.
func PrefixKeyToIPNet(k bpf.PrefixKeyGo) net.IPNet {
	return bpf.PrefixKeyToIPNet(k)
}

// formatIP returns a human-readable IP string from an LPMKey.
func formatIP(k bpf.LPMKey) string {
	return LPMKeyToIP(k).String()
}

// formatPrefix returns a CIDR string from a PrefixKeyGo.
func formatPrefix(k bpf.PrefixKeyGo) string {
	n := PrefixKeyToIPNet(k)
	return n.String()
}

// logReport prints the per-second delta to stdout for P3 verification.
// Will be replaced by gRPC reporting in P5.
func (c *Collector) logReport(r *Report) {
	var sb strings.Builder

	// Global line
	fmt.Fprintf(&sb, "--- %s | global: pps=%d bps=%d matched=%d | sample_rate=%d",
		r.Timestamp.Format("15:04:05"),
		r.Global.TotalPkts, r.Global.TotalBytes*8, r.Global.MatchedPkts,
		r.SampleRate)
	if r.Truncated {
		fmt.Fprintf(&sb, " | TRUNCATED active_ips=%d (showing top %d)", r.TotalActiveIPs, maxIPDelta)
	}
	sb.WriteString("\n")

	// Prefix summary
	if len(r.PrefixDeltas) > 0 {
		sb.WriteString("  prefixes:\n")
		for _, pd := range r.PrefixDeltas {
			fmt.Fprintf(&sb, "    %s  pps=%-8d bps=%-12d active_ips=%-5d overflow=%d\n",
				formatPrefix(pd.Key), pd.Stats.PktCount, pd.Stats.ByteCount*8,
				pd.ActiveIPs, pd.Stats.OverflowCount)
		}
	}

	// Top-N IP deltas
	if len(r.IPDeltas) > 0 {
		// Sort by pkt_count descending for display
		sorted := make([]IPDelta, len(r.IPDeltas))
		copy(sorted, r.IPDeltas)
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Stats.PktCount > sorted[j].Stats.PktCount
		})
		n := topKTerminal
		if n > len(sorted) {
			n = len(sorted)
		}
		fmt.Fprintf(&sb, "  top-%d IPs:\n", n)
		for _, d := range sorted[:n] {
			s := d.Stats
			fmt.Fprintf(&sb, "    %-40s pps=%-8d bps=%-12d tcp=%-5d syn=%-5d udp=%-5d icmp=%-5d frag=%-5d sm=%-5d md=%-5d lg=%-5d\n",
				formatIP(d.Key), s.PktCount, s.ByteCount*8,
				s.DecoderCounts[decoder.TCP], s.DecoderCounts[decoder.TCPSyn], s.DecoderCounts[decoder.UDP], s.DecoderCounts[decoder.ICMP], s.DecoderCounts[decoder.Frag],
				s.SmallPkt, s.MediumPkt, s.LargePkt)
		}
	}

	log.Print(sb.String())
}
