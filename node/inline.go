// Inline scrubbing engine wiring for xsight-node.
//
// This file keeps main.go readable: it owns the xdp_inline lifecycle
// (program selection, attach mode, kernel engine configuration), the
// CriticalEventStream feed from the kernel burst ringbuf, CPU pinning and
// the AF_XDP L7 inspection socket.

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
	"github.com/d80y6/YemenDDoS/node/internal/config"
	"github.com/d80y6/YemenDDoS/node/internal/l7collector"
	"github.com/d80y6/YemenDDoS/node/internal/pb"

	"golang.org/x/sys/unix"
)

// cookieSecret holds the current SYN-cookie siphash secret (rotated hourly).
type cookieSecret struct {
	lo, hi atomic.Uint64
}

func (c *cookieSecret) set(lo, hi uint64) {
	c.lo.Store(lo)
	c.hi.Store(hi)
}

func (c *cookieSecret) get() (uint64, uint64) { return c.lo.Load(), c.hi.Load() }

// randomCookieSecret returns a fresh 128-bit siphash key.
func randomCookieSecret() (uint64, uint64, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, 0, err
	}
	return binary.LittleEndian.Uint64(b[0:8]), binary.LittleEndian.Uint64(b[8:16]), nil
}

// rotateCookieSecret installs a fresh random secret every hour so a leaked
// seed cannot be replayed indefinitely.
func rotateCookieSecret(ctx context.Context, mgr *bpf.Manager, cs *cookieSecret) {
	gen := func() {
		lo, hi, err := randomCookieSecret()
		if err != nil {
			log.Printf("inline: cookie secret rand: %v", err)
			return
		}
		cs.set(lo, hi)
		if err := mgr.SetCookieSecret(lo, hi); err != nil {
			log.Printf("inline: push cookie secret: %v", err)
		}
	}
	gen()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gen()
			// Old cookies become invalid with the new secret; drop the
			// validated-client cache so stale entries cannot slip through.
			if err := mgr.ClearValidatedClients(); err != nil {
				log.Printf("inline: clear validated clients: %v", err)
			}
			log.Println("inline: rotated SYN-cookie secret")
		}
	}
}

// inlineDefaultEncap is the configured clean-pipe encapsulation used for
// redirect rules that do not specify their own. It is set once at startup,
// before any ControlStream config push is applied.
var inlineDefaultEncap string

// firstIPv4 returns the interface's first IPv4 address, if any.
func firstIPv4(ifi *net.Interface) net.IP {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if ip4 := v.IP.To4(); ip4 != nil {
				return ip4
			}
		case *net.IPAddr:
			if ip4 := v.IP.To4(); ip4 != nil {
				return ip4
			}
		}
	}
	return nil
}

// setupInlineEngine configures the kernel data plane and attaches the inline
// program. Returns the resolved egress interface name for posture reporting.
func setupInlineEngine(cfg *config.Config, mgr *bpf.Manager, ifaceName string) (string, error) {
	mgr.SetInlineProgram(true)

	if err := mgr.SetInlineEnabled(true); err != nil {
		return "", fmt.Errorf("enable inline engine: %w", err)
	}
	// Inline mode can receive a later controller push that enables cookies, so
	// install a secret unconditionally before that switch can be turned on.
	lo, hi, err := randomCookieSecret()
	if err != nil {
		return "", fmt.Errorf("generate cookie secret: %w", err)
	}
	if err := mgr.SetCookieSecret(lo, hi); err != nil {
		return "", fmt.Errorf("install cookie secret: %w", err)
	}
	if err := mgr.SetSynCookieEnabled(cfg.Inline.SynCookie); err != nil {
		return "", fmt.Errorf("syn cookie enable: %w", err)
	}
	if err := mgr.SetDNSProtect(cfg.Inline.DNSProtect); err != nil {
		return "", fmt.Errorf("dns protect enable: %w", err)
	}
	// Burst alerts are a runtime ringbuf gate: array-map slots default to 0, so
	// the data plane stays silent unless userspace writes an explicit 1. Keep
	// them off when offload is requested (ringbuf is not offloadable); main
	// re-enables them after attach if the node falls back to driver/generic.
	alertsOn := cfg.XDPModeOrDefault() != "offload"
	if err := mgr.SetAlertsEnabled(alertsOn); err != nil {
		return "", fmt.Errorf("enable burst alerts: %w", err)
	}
	if cfg.Inline.BurstPPS > 0 {
		if err := mgr.SetBurstThreshold(cfg.Inline.BurstPPS); err != nil {
			return "", fmt.Errorf("burst threshold: %w", err)
		}
	}
	if err := mgr.SetInlineSampleRate(cfg.Inline.SampleRate); err != nil {
		return "", fmt.Errorf("inline sample rate: %w", err)
	}

	// Clean-pipe egress: resolve the interface index for XDP_REDIRECT.
	egress := ""
	if cfg.Inline.CleanPipe != "" {
		ifi, err := net.InterfaceByName(cfg.Inline.CleanPipe)
		if err != nil {
			log.Printf("inline: clean-pipe egress %q unavailable: %v (redirect disabled)",
				cfg.Inline.CleanPipe, err)
		} else {
			if err := mgr.SetEgressIfindex(uint32(ifi.Index)); err != nil {
				return "", fmt.Errorf("egress ifindex: %w", err)
			}
			egress = cfg.Inline.CleanPipe

			// GRE outer source address. Without a usable IPv4 address the
			// data plane falls back to 0 (invalid for routing) and logs here
			// so the operator can fix the clean-pipe link.
			var saddr uint32
			if ip4 := firstIPv4(ifi); ip4 != nil {
				// Store the byte image the header needs (network order).
				saddr = binary.NativeEndian.Uint32(ip4)
			} else {
				log.Printf("warning: inline: clean-pipe egress %q has no IPv4 address; GRE outer saddr will be 0",
					cfg.Inline.CleanPipe)
			}
			if err := mgr.SetEgressSaddr(saddr); err != nil {
				return "", fmt.Errorf("egress saddr: %w", err)
			}
		}
	}

	// Default encapsulation for redirect rules that do not name one.
	inlineDefaultEncap = cfg.Inline.CleanPipeEncap

	// Record the requested attach mode; main's attach loop performs the
	// actual attach through AttachXDP → AttachXDPMode.
	mgr.SetAttachMode(cfg.XDPModeOrDefault())
	log.Printf("inline: engine configured (burst_pps=%d syn_cookie=%v dns_protect=%v sample=%d egress=%q mode=%s)",
		cfg.Inline.BurstPPS, cfg.Inline.SynCookie, cfg.Inline.DNSProtect,
		cfg.Inline.SampleRate, egress, cfg.XDPModeOrDefault())
	return egress, nil
}

// inlinePosture builds the NodePosture snapshot reported with every stats tick.
type inlinePosture struct {
	mgr     *bpf.Manager
	nodeID  string
	mode    string
	egress  string
	pins    []int
	xsk     *bpf.XSKManager
	enabled bool
}

func (p *inlinePosture) snapshot() *pb.NodePosture {
	if p == nil {
		return nil
	}
	st := p.mgr.InlineCounters()
	posture := &pb.NodePosture{
		XdpMode:             p.mode,
		InlineEnabled:       p.enabled,
		FilterRules:         st.ActiveFilterRules,
		ValidatedClients:    st.ValidatedClients,
		SynCookiesReply:     st.CookieReplies,
		SynCookiesValidated: st.CookieValidated,
		SynCookiesDropped:   st.CookieDropped,
		EmergencyDrops:      st.EmergencyDrops,
		CleanpipeEgress:     p.egress,
	}
	for _, c := range p.pins {
		posture.CpuPins = append(posture.CpuPins, int64(c))
	}
	if p.xsk != nil {
		posture.AfXdpActive = true
		for _, s := range p.xsk.Sockets() {
			xs := s.Stats()
			posture.AfXdpRx += xs.RX
			posture.AfXdpUmemDrops += xs.RXDropped
		}
	}
	return posture
}

// streamBurstAlerts drains the kernel burst ringbuf and pushes each alert
// straight onto CriticalEventStream — the sub-second detection path that
// bypasses the 1s stats batching in the Controller.
func streamBurstAlerts(ctx context.Context, mgr *bpf.Manager, rpt criticalSender, nodeID, iface string) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			err := mgr.DrainAlerts(func(a bpf.BurstAlert) {
				dst := a.DstIP()
				now := time.Now()
				rpt.SendCriticalEvent(&pb.CriticalEvent{
					NodeId:         nodeID,
					InterfaceName:  iface,
					Timestamp:      now.Unix(),
					TimestampNs:    now.UnixNano(),
					DstIp:          dst,
					TargetIp:       dst,
					EventType:      "burst_emergency",
					Decoder:        decoderForProto(a.Proto),
					CurrentPps:     uint64(a.WindowPPS),
					AttackType:     attackTypeForProto(a.Proto),
					LocalMitigated: true,
					Counters: map[string]uint64{
						"window_pps": uint64(a.WindowPPS),
						"proto":      uint64(a.Proto),
						"tcp_flags":  uint64(a.TCPFlags),
						"emergency":  1,
					},
				})
			})
			if err != nil {
				log.Printf("inline: alert reader stopped: %v", err)
				return
			}
		}
	}()
}

// criticalSender is the subset of the reporter used for alert streaming.
type criticalSender interface {
	SendCriticalEvent(ev *pb.CriticalEvent)
}

func decoderForProto(proto uint32) string {
	switch proto {
	case 6:
		return "tcp_syn"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return "ip"
	}
}

func attackTypeForProto(proto uint32) string {
	switch proto {
	case 6:
		return "syn_flood"
	case 17:
		return "udp_flood"
	case 1:
		return "icmp_flood"
	default:
		return "volumetric_generic"
	}
}

// inlineRuleSink is the kernel-facing surface used by inlineRulesApplier.
type inlineRuleSink interface {
	ApplyInlineRules(specs []bpf.InlineRuleSpec, defaultAction string) error
	SetSynCookieEnabled(on bool) error
}

// inlineRulesApplier applies controller rule-set snapshots. It owns the
// monotonic version guard and the SYN-cookie tri-state so a stale or
// rules-only push cannot roll back node state.
type inlineRulesApplier struct {
	sink        inlineRuleSink
	lastApplied atomic.Uint64
}

// inlineCookieRuleIDBase separates synthetic cookie-target rule IDs from the
// controller's IDs, which stay well below it.
const inlineCookieRuleIDBase = uint64(1) << 62

// apply converts controller-pushed proto rules into kernel specs and installs
// them. A nil rule set means "unchanged"; an empty list clears.
func (a *inlineRulesApplier) apply(rs *pb.InlineRuleSet) error {
	if rs == nil {
		return nil
	}
	version := rs.GetVersion()
	if version != 0 {
		// A freshly started controller numbers pushes from 1 again; treat
		// that as a new epoch so a node reconnecting after a controller
		// restart is not stuck rejecting every push forever. Otherwise an
		// older snapshot must never overwrite a newer one.
		if last := a.lastApplied.Load(); version < last && version != 1 {
			return fmt.Errorf("inline: reject stale rule set v%d (already applied v%d)",
				version, last)
		}
	}

	specs := make([]bpf.InlineRuleSpec, 0, len(rs.GetRules()))
	nowWall := time.Now().Unix()
	nowNS := bpf.MonotonicNowNS()
	for _, r := range rs.GetRules() {
		encap := r.GetEncap()
		if encap == "" && r.GetAction() == "redirect" {
			encap = inlineDefaultEncap
		}
		specs = append(specs, bpf.InlineRuleSpec{
			ID:            r.GetId(),
			DstIP:         ipString(r.GetDstIp()),
			DstPrefixLen:  int(r.GetDstPrefixLen()),
			SrcIP:         ipString(r.GetSrcIp()),
			SrcPrefixLen:  int(r.GetSrcPrefixLen()),
			Protocol:      r.GetProtocol(),
			DstPort:       r.GetDstPort(),
			SrcPort:       r.GetSrcPort(),
			Action:        r.GetAction(),
			RateLimitPPS:  r.GetRateLimitPps(),
			Priority:      r.GetPriority(),
			ExpiresUnix:   r.GetExpiresUnix(),
			ExpiresNS:     bpf.RuleExpiryNS(r.GetExpiresUnix(), nowWall, nowNS),
			EgressIfindex: r.GetEgressIfindex(),
			Encap:         encap,
			EncapDaddr:    r.GetEncapDaddr(),
		})
	}
	specs = append(specs, cookieTargetSpecs(rs.GetCookieTargets(), specs)...)

	if err := a.sink.ApplyInlineRules(specs, rs.GetDefaultAction()); err != nil {
		return err
	}
	if err := a.applyCookieSwitch(rs); err != nil {
		return fmt.Errorf("apply cookie switch: %w", err)
	}
	if version != 0 {
		a.lastApplied.Store(version)
	}
	log.Printf("inline: config push v%d applied (%d rules, cookie=%v, default=%s)",
		version, len(specs), rs.GetSynCookieEnabled(), rs.GetDefaultAction())
	return nil
}

// applyCookieSwitch implements tri-state SYN-cookie control on top of the
// proto's plain bool. syn_cookie_enabled=false is indistinguishable from an
// unset field, so a push only turns cookies on when it carries intent (the
// switch is true or protected targets are named); a rules-only push leaves
// the node's current setting (local config or an earlier push) intact. An
// explicit disable therefore requires the local config or a proto change to
// an optional field.
func (a *inlineRulesApplier) applyCookieSwitch(rs *pb.InlineRuleSet) error {
	if !rs.GetSynCookieEnabled() && len(rs.GetCookieTargets()) == 0 {
		return nil
	}
	return a.sink.SetSynCookieEnabled(true)
}

// cookieTargetSpecs converts protected CIDR prefixes into rule-driven
// SYN-cookie entries. The data plane only answers cookies for flows that
// match a syn_cookie rule, so the proto field must reach the filter tables
// instead of being silently dropped.
func cookieTargetSpecs(targets []string, existing []bpf.InlineRuleSpec) []bpf.InlineRuleSpec {
	if len(targets) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(existing))
	for _, s := range existing {
		if s.Action == "syn_cookie" {
			seen[cookieRuleKey(s.DstIP, s.DstPrefixLen, s.Protocol)] = struct{}{}
		}
	}
	out := make([]bpf.InlineRuleSpec, 0, len(targets))
	for i, cidr := range targets {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("inline: skip cookie target %q: %v", cidr, err)
			continue
		}
		ones, _ := ipnet.Mask.Size()
		key := cookieRuleKey(ipnet.IP.String(), ones, 6)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, bpf.InlineRuleSpec{
			ID:           inlineCookieRuleIDBase + uint64(i+1),
			DstIP:        ipnet.IP.String(),
			DstPrefixLen: ones,
			Protocol:     6,
			Action:       "syn_cookie",
			Priority:     10,
		})
	}
	return out
}

func cookieRuleKey(ip string, prefixLen int, protocol uint32) string {
	return fmt.Sprintf("%s/%d/%d", ip, prefixLen, protocol)
}

// ipString renders proto IP bytes for rule conversion ("" for empty).
func ipString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return net.IP(b).String()
}

// applyPostureConfig applies controller-pushed hardware settings.
func applyPostureConfig(mgr *bpf.Manager, pc *pb.NodePostureConfig, xsk *bpf.XSKManager) {
	if pc == nil {
		return
	}
	if pc.GetAfXdpEnabled() {
		if xsk == nil {
			log.Printf("inline: posture requests AF_XDP queue=%d but no socket manager is running",
				pc.GetAfXdpQueue())
		}
	}
	if len(pc.GetCpuPins()) > 0 {
		if err := applyCPUPins(intSlice(pc.GetCpuPins())); err != nil {
			log.Printf("inline: posture cpu pins: %v", err)
		}
	}
}

func intSlice(in []int64) []int {
	out := make([]int, 0, len(in))
	for _, v := range in {
		out = append(out, int(v))
	}
	return out
}

// applyCPUPins pins the whole node process (all goroutines) to the given
// cores. Hot-path threads are short-lived, so process-wide affinity is the
// practical knob for keeping XDP/AF_XDP work off management cores.
func applyCPUPins(cores []int) error {
	if len(cores) == 0 {
		return nil
	}
	var set unix.CPUSet
	set.Zero()
	for _, c := range cores {
		if c < 0 {
			continue
		}
		set.Set(c)
	}
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		return fmt.Errorf("sched_setaffinity %v: %w", cores, err)
	}
	log.Printf("perf: process pinned to cores %v", cores)
	return nil
}

// startAFXDP opens the zero-copy inspection socket feeding the L7 collector.
// A failure is non-fatal: L7 evidence then comes from the ringbuf sampler.
func startAFXDP(cfg *config.Config, mgr *bpf.Manager, l7c *l7collector.Collector,
	issuer *l7collector.ChallengeIssuer, iface string) (*bpf.XSKManager, error) {
	if !cfg.AFXDP.Enabled {
		return nil, nil
	}
	frames := cfg.AFXDP.Frames
	if frames == 0 {
		frames = bpf.DefaultUmemFrames
	}
	frameSize := cfg.AFXDP.FrameSize
	if frameSize == 0 {
		frameSize = bpf.DefaultFrameSize
	}

	xsk, err := bpf.StartXSK(mgr, iface, cfg.AFXDP.Queue, frames, frameSize,
		cfg.AFXDP.ZeroCopy, func(f bpf.XSKFrame) {
			if l7c == nil {
				return
			}
			l7c.Observe(f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.TCPFlags, f.Payload, time.Now())
			if issuer != nil && issuer.Enabled() {
				// Challenge evaluation happens on the L7 tick, which has the
				// aggregated view; here we only report the evidence.
				_ = issuer
			}
		})
	if err != nil {
		return nil, err
	}
	log.Printf("af_xdp: zero-copy inspection active on %s queue=%d", iface, cfg.AFXDP.Queue)
	return xsk, nil
}
