package threshold

import (
	"net"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"github.com/d80y6/YemenDDoS/shared/decoder"
)

const ringFreshnessWindow = 5 * time.Second
const defaultSustainWindow = 10

// Detector performs per-second threshold checking against ring buffer data.
type Detector struct {
	tree          *Tree
	rings         *ring.RingStore
	sustainWindow int
}

func NewDetector(tree *Tree, rings *ring.RingStore) *Detector {
	return &Detector{tree: tree, rings: rings}
}

// SetSustainWindow sets the history window before detection starts.
func (d *Detector) SetSustainWindow(n int) {
	if n > 0 {
		d.sustainWindow = n
	}
}

func (d *Detector) window() int {
	if d.sustainWindow > 0 {
		return d.sustainWindow
	}
	return defaultSustainWindow
}

// SustainWindow allows room for timestamp anomalies while bounding history by capacity.
// Compare before doubling to avoid integer overflow, even for invalid configuration.
func SustainWindow(hard, dynamic, capacity int) int {
	n := max(1, hard, dynamic)
	if capacity < 1 {
		return 1
	}
	if n > capacity/2 {
		return capacity
	}
	return 2 * n
}

// SustainedRun counts distinct breaching seconds in newest-first arrival order.
// A low point, reversed timestamp, or gap exceeding two seconds ends the run.
// Duplicate timestamps do not count; a single missing second is tolerated.
func SustainedRun(pts []ring.DataPoint, breached func(ring.DataPoint) bool) int {
	n := 0
	var prev time.Time
	for _, p := range pts {
		if !breached(p) {
			break
		}
		if n > 0 {
			gap := prev.Sub(p.Time)
			if gap == 0 {
				continue
			}
			if gap < 0 || gap > 2*time.Second {
				break
			}
		}
		n++
		prev = p.Time
	}
	return n
}

func sustained(r engine.ResolvedThreshold, pts []ring.DataPoint) int {
	n := SustainedRun(pts, func(p ring.DataPoint) bool {
		_, breached := evaluateRule(r, p)
		return breached
	})
	// The history read can race with replacement or eviction after the latest-point
	// read. Never turn that empty run into an unknown (zero) event that bypasses confirmation.
	if n < 1 {
		n = 1
	}
	return n
}

// Tick checks all active data against thresholds for each connected node.
// v2.11 Phase 2: rules are split by direction — receives checks inbound rings, sends checks outbound rings.
func (d *Detector) Tick(connectedNodes []string) []engine.ThresholdExceeded {
	var exceeded []engine.ThresholdExceeded

	for _, nodeID := range connectedNodes {
		for _, prefix := range d.tree.AllPrefixes() {
			// Pre-split by direction — zero allocation (cached at tree Rebuild time)
			subnetRecv, subnetSend, ipRecv, ipSend := d.tree.ForPrefixDirectionSplit(prefix)

			// --- Inbound (receives) subnet rules → inbound prefix ring ---
			if len(subnetRecv) > 0 {
				if dp, ok := d.rings.LatestPrefix(nodeID, prefix, ringFreshnessWindow); ok {
					var pts []ring.DataPoint
					loaded := false
					for _, r := range subnetRecv {
						if breach := checkRule(r, dp, prefix, nil, nodeID); breach != nil {
							if !loaded {
								pts = d.rings.LatestNPrefix(nodeID, prefix, d.window())
								loaded = true
							}
							breach.Sustained = sustained(r, pts)
							exceeded = append(exceeded, *breach)
						}
					}
				}
			}

			// --- Outbound (sends) subnet rules → outbound prefix ring ---
			if len(subnetSend) > 0 {
				if dp, ok := d.rings.LatestSrcPrefix(nodeID, prefix, ringFreshnessWindow); ok {
					var pts []ring.DataPoint
					loaded := false
					for _, r := range subnetSend {
						if breach := checkRule(r, dp, prefix, nil, nodeID); breach != nil {
							if !loaded {
								pts = d.rings.LatestNSrcPrefix(nodeID, prefix, d.window())
								loaded = true
							}
							breach.Sustained = sustained(r, pts)
							exceeded = append(exceeded, *breach)
						}
					}
				}
			}

			// --- Inbound (receives) per-IP rules → inbound IP rings ---
			// IPKeysForPrefix copies the key slice under RLock then releases it.
			// Do NOT use ForEach callback — it holds RLock during iteration,
			// causing self-deadlock when callback re-enters RLock and a writer is pending.
			if len(ipRecv) > 0 {
				for _, ipStr := range d.rings.IPKeysForPrefix(nodeID, prefix) {
					dp, ok := d.rings.LatestIPByKey(nodeID, prefix, ipStr, ringFreshnessWindow)
					if !ok {
						continue
					}
					var pts []ring.DataPoint
					loaded := false
					for _, r := range ipRecv {
						if breach := checkRuleStr(r, dp, prefix, ipStr, nodeID); breach != nil {
							if !loaded {
								pts = d.rings.LatestNIPByKey(nodeID, prefix, ipStr, d.window())
								loaded = true
							}
							breach.Sustained = sustained(r, pts)
							exceeded = append(exceeded, *breach)
						}
					}
				}
			}

			// --- Outbound (sends) per-IP rules → outbound IP rings ---
			if len(ipSend) > 0 {
				for _, ipStr := range d.rings.SrcIPKeysForPrefix(nodeID, prefix) {
					dp, ok := d.rings.LatestSrcIPByKey(nodeID, prefix, ipStr, ringFreshnessWindow)
					if !ok {
						continue
					}
					var pts []ring.DataPoint
					loaded := false
					for _, r := range ipSend {
						if breach := checkRuleStr(r, dp, prefix, ipStr, nodeID); breach != nil {
							if !loaded {
								pts = d.rings.LatestNSrcIPByKey(nodeID, prefix, ipStr, d.window())
								loaded = true
							}
							breach.Sustained = sustained(r, pts)
							exceeded = append(exceeded, *breach)
						}
					}
				}
			}
		}
	}

	return exceeded
}

// evaluateRule is the shared rule evaluation logic used by both checkRule and checkRuleStr.
// Returns (actual value, breached) or (-1, false) if the rule should be skipped.
func evaluateRule(r engine.ResolvedThreshold, dp ring.DataPoint) (int64, bool) {
	var actual int64
	if r.Decoder == "ip" {
		actual = selectUnit(r.Unit, dp.PPS, dp.BPS, dp.PPS)
	} else {
		idx := decoder.Index(r.Decoder)
		if idx < 0 {
			return -1, false
		}
		actual = selectUnit(r.Unit, int64(dp.DecoderPPS[idx]), dp.DecoderBPS[idx], dp.PPS)
	}

	switch r.Comparison {
	case "over":
		return actual, actual > r.Value
	case "under":
		return actual, actual < r.Value
	}
	return actual, false
}

// checkRule evaluates a threshold rule with a net.IP (used for subnet-level checks).
func checkRule(r engine.ResolvedThreshold, dp ring.DataPoint, prefix string, ip net.IP, nodeID string) *engine.ThresholdExceeded {
	actual, breached := evaluateRule(r, dp)
	if !breached {
		return nil
	}
	return &engine.ThresholdExceeded{
		DstIP:       ip,
		Prefix:      prefix,
		PrefixID:    r.PrefixID,
		Direction:   r.Direction,
		Decoder:     r.Decoder,
		Unit:        r.Unit,
		ThresholdID: r.ThresholdID,
		ResponseID:  r.ResponseID,
		Value:       r.Value,
		Actual:      actual,
		Domain:      r.Domain,
		NodeID:      nodeID,
	}
}

// checkRuleStr is the string-key variant for the hot detection path.
// It avoids net.ParseIP allocation by only parsing the IP on breach (rare).
func checkRuleStr(r engine.ResolvedThreshold, dp ring.DataPoint, prefix, ipStr, nodeID string) *engine.ThresholdExceeded {
	actual, breached := evaluateRule(r, dp)
	if !breached {
		return nil
	}
	return &engine.ThresholdExceeded{
		DstIP:       net.ParseIP(ipStr), // only allocates on breach (rare path)
		Prefix:      prefix,
		PrefixID:    r.PrefixID,
		Direction:   r.Direction,
		Decoder:     r.Decoder,
		Unit:        r.Unit,
		ThresholdID: r.ThresholdID,
		ResponseID:  r.ResponseID,
		Value:       r.Value,
		Actual:      actual,
		Domain:      r.Domain,
		NodeID:      nodeID,
	}
}

func selectUnit(unit string, pps, bps, totalPPS int64) int64 {
	switch unit {
	case "bps":
		return bps
	case "pct":
		if totalPPS == 0 {
			return 0
		}
		return pps * 100 / totalPPS
	default:
		return pps
	}
}
