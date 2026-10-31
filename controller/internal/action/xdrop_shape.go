package action

import (
	"fmt"
	"net"

	"github.com/littlewolf9527/xsight/controller/internal/store"
	sharedDecoder "github.com/littlewolf9527/xsight/shared/decoder"
)

type xdropShapeConfig struct {
	NarrowPct        int
	MinSamplePackets uint64
}

var xdropShapeSettings = xdropShapeConfig{NarrowPct: 80, MinSamplePackets: 1000}

// SetXDropShapeConfig installs the validated configuration before the engine starts.
func SetXDropShapeConfig(narrowPct int, minSamplePackets uint64) {
	xdropShapeSettings = xdropShapeConfig{NarrowPct: narrowPct, MinSamplePackets: minSamplePackets}
}

type thresholdLookup func(id int) (*store.Threshold, error)

type xdropTopKConfig struct {
	Pct int
	Max int
}

var xdropTopKSettings = xdropTopKConfig{Pct: 80, Max: 8}

// SetXDropTopKConfig installs the validated T2 and per-dispatch rule limit.
func SetXDropTopKConfig(pct, max int) {
	xdropTopKSettings = xdropTopKConfig{Pct: pct, Max: max}
}

// xdropTopK uses the full filtered sample count, including port zero. A
// single-port rule belongs exclusively to T1, even when T2 is below T1.
func xdropTopK(rank []PortCount, samples uint64) (k, pct int) {
	cfg := xdropTopKSettings
	var sum uint64
	for i, candidate := range rank {
		if i >= cfg.Max {
			break
		}
		sum += candidate.Packets
		if i >= 1 && sum*100 >= uint64(cfg.Pct)*samples {
			return i + 1, int(sum * 100 / samples)
		}
	}
	return 0, 0
}

func xdropTopKChoice(tpl, body map[string]any, fa *FlowAnalysis, decoder string) (dim string, rank []PortCount, k, pct int) {
	if xdropTopKSettings.Max < 2 || fa == nil || fa.SamplePackets == 0 || fa.SamplePackets < xdropShapeSettings.MinSamplePackets || sharedDecoder.GetDispatchClass(decoder) != sharedDecoder.Ported {
		return
	}
	for _, candidate := range []struct {
		key         string
		placeholder string
		rank        []PortCount
		dominantPct int
	}{
		{"src_port", "{dominant_src_port}", fa.SrcPortRank, fa.DominantSrcPortPct},
		{"dst_port", "{dominant_dst_port}", fa.DstPortRank, fa.DominantDstPortPct},
	} {
		if tpl[candidate.key] != candidate.placeholder {
			continue
		}
		ck, cpct := 1, candidate.dominantPct
		if !(candidate.dominantPct >= xdropShapeSettings.NarrowPct && xdropShapePortSet(body[candidate.key])) {
			ck, cpct = xdropTopK(candidate.rank, fa.SamplePackets)
		}
		// Source is considered first and wins equal-sized selections.
		if ck > 0 && (k == 0 || ck < k) {
			dim, rank, k, pct = candidate.key, candidate.rank, ck, cpct
		}
	}
	return
}

// shapeXDropBodies preserves the original single-body path exactly. Only a
// selected T2 port set expands the body; literals and operator rates survive.
func shapeXDropBodies(tpl map[string]any, body map[string]any, fa *FlowAnalysis, attack *store.Attack, decoder string, operatorRateLimit bool, lookup thresholdLookup) ([]map[string]any, []string, []string) {
	dim, rank, k, pct := xdropTopKChoice(tpl, body, fa, decoder)
	if k < 2 {
		return []map[string]any{body}, shapeXDropBody(tpl, body, fa, attack, decoder, operatorRateLimit, lookup), nil
	}
	hints := []string{fmt.Sprintf("shape: topk %s=%d %d%%", dim, k, pct)}
	for _, other := range []struct {
		key         string
		placeholder string
		pct         int
	}{
		{"dst_port", "{dominant_dst_port}", fa.DominantDstPortPct},
		{"src_port", "{dominant_src_port}", fa.DominantSrcPortPct},
	} {
		if other.key != dim && tpl[other.key] == other.placeholder {
			delete(body, other.key)
			hints = append(hints, fmt.Sprintf("shape: dropped %s=%d%%", other.key, other.pct))
		}
	}
	if tpl["src_ip"] == "{src_ip}" {
		decision := "kept"
		if fa.TopSrcIPPct < xdropShapeSettings.NarrowPct || !xdropShapeSourceValid(body["src_ip"]) {
			delete(body, "src_ip")
			decision = "dropped"
		}
		hints = append(hints, fmt.Sprintf("shape: %s src_ip=%d%%", decision, fa.TopSrcIPPct))
	}
	bodies := make([]map[string]any, k)
	itemHints := make([]string, k)
	for i := range bodies {
		item := make(map[string]any, len(body))
		for key, value := range body {
			item[key] = value
		}
		item[dim] = rank[i].Port
		bodies[i] = item
		itemHints[i] = fmt.Sprintf("shape: item %d/%d %s=%d", i+1, k, dim, rank[i].Port)
	}
	return bodies, hints, itemHints
}

// shapeXDropBody narrows only fields permitted by the unexpanded template.
// The body has already passed type correction and decoder sanitization; final
// address and protocol normalization remains the responsibility of finalize.
func shapeXDropBody(tpl map[string]any, body map[string]any, fa *FlowAnalysis, attack *store.Attack, decoder string, operatorRateLimit bool, lookup thresholdLookup) (hints []string) {
	ported := sharedDecoder.GetDispatchClass(decoder) == sharedDecoder.Ported
	allowDst := ported && tpl["dst_port"] == "{dominant_dst_port}"
	allowSrc := ported && tpl["src_port"] == "{dominant_src_port}"
	allowIP := tpl["src_ip"] == "{src_ip}"
	if !allowDst && !allowSrc && !allowIP {
		return nil
	}

	cfg := xdropShapeSettings
	var samples uint64
	var dstPct, srcPct, ipPct int
	if fa != nil {
		samples = fa.SamplePackets
		dstPct, srcPct, ipPct = fa.DominantDstPortPct, fa.DominantSrcPortPct, fa.TopSrcIPPct
	}
	kept := false
	if samples < cfg.MinSamplePackets {
		for key, allowed := range map[string]bool{"dst_port": allowDst, "src_port": allowSrc, "src_ip": allowIP} {
			if allowed {
				delete(body, key)
			}
		}
		hints = append(hints, fmt.Sprintf("shape: samples %d < %d", samples, cfg.MinSamplePackets))
	} else {
		keepDst := allowDst && dstPct >= cfg.NarrowPct && xdropShapePortSet(body["dst_port"])
		keepSrc := allowSrc && srcPct >= cfg.NarrowPct && xdropShapePortSet(body["src_port"])
		keepIP := allowIP && ipPct >= cfg.NarrowPct && xdropShapeSourceValid(body["src_ip"])
		// Both candidates would produce one rule: the source port wins the tie.
		if keepDst && keepSrc {
			keepDst = false
		}
		for _, dim := range []struct {
			key     string
			allowed bool
			keep    bool
			pct     int
		}{
			{"dst_port", allowDst, keepDst, dstPct},
			{"src_port", allowSrc, keepSrc, srcPct},
			{"src_ip", allowIP, keepIP, ipPct},
		} {
			if !dim.allowed {
				continue
			}
			decision := "dropped"
			if dim.keep {
				decision = "kept"
				kept = true
			} else {
				delete(body, dim.key)
			}
			hints = append(hints, fmt.Sprintf("shape: %s %s=%d%%", decision, dim.key, dim.pct))
		}
	}

	// A literal condition blocks protocol-level fallback only while it is
	// still effective after cleaning. Never rewrite the literal itself.
	literalEffective := false
	for key, placeholder := range map[string]string{"dst_port": "{dominant_dst_port}", "src_port": "{dominant_src_port}", "src_ip": "{src_ip}"} {
		value, exists := tpl[key]
		if exists && value != nil && value != "" && value != placeholder {
			if key == "src_ip" {
				literalEffective = literalEffective || xdropShapeSourceValid(body[key])
			} else {
				literalEffective = literalEffective || xdropShapePortSet(body[key])
			}
		}
	}
	if kept || literalEffective || operatorRateLimit || decoder == "fragment" || isAnomalyDecoder(decoder) {
		return hints
	}
	if action, exists := body["action"]; exists && action != "drop" {
		return hints
	}

	unavailable := func(reason string) []string {
		return append(hints, "fallback rate unavailable: "+reason)
	}
	if attack == nil || attack.ThresholdRuleID == nil {
		return unavailable("missing threshold rule ID")
	}
	if lookup == nil {
		return unavailable("threshold lookup unavailable")
	}
	th, err := lookup(*attack.ThresholdRuleID)
	if err != nil {
		return unavailable(fmt.Sprintf("threshold lookup: %v", err))
	}
	if th == nil {
		return unavailable("threshold rule not found")
	}
	if th.Unit != "pps" {
		return unavailable(fmt.Sprintf("threshold unit %q is not pps", th.Unit))
	}
	if th.Value <= 0 {
		return unavailable("threshold pps must be positive")
	}
	rate := int64(th.Value)
	if rate > 4294967295 {
		rate = 4294967295
	}
	body["action"], body["rate_limit"] = "rate_limit", rate
	return append(hints, fmt.Sprintf("shape: fallback rate_limit=%d", rate))
}

func xdropShapePortSet(value any) bool {
	switch port := value.(type) {
	case float64: // JSON-decoded body
		return port != 0
	case int:
		return port != 0
	case int64:
		return port != 0
	default:
		return false
	}
}

func xdropShapeSourceValid(value any) bool {
	address, _ := value.(string)
	host, _ := splitIPOrCIDR(address)
	ip := net.ParseIP(host)
	return ip != nil && !ip.IsUnspecified()
}
