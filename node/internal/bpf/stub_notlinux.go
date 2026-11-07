//go:build !linux

// This file provides stub types so that `go build` on non-Linux platforms
// produces a clear runtime error instead of cryptic "undefined: xsightObjects".
//
// xsight-node requires Linux with BPF support. The bpf2go generated bindings
// (xsight_bpfel.go, xsight_bpfel.o) are only produced on Linux via:
//
//	cd xsight/node && make generate build
//
// See internal/bpf/gen.go for the go:generate directive.
package bpf

import (
	"net"

	"github.com/cilium/ebpf"
)

// stubObjects mirrors the bpf2go-generated xsightObjects so that callers
// (e.g. main.go accessing mgr.Objs.Samples) compile on non-Linux.
type stubObjects struct {
	Samples           *ebpf.Map
	XsightMain        *ebpf.Program
	GlobalStats       *ebpf.Map
	WatchTrieA        *ebpf.Map
	WatchTrieB        *ebpf.Map
	IpStatsA          *ebpf.Map
	IpStatsB          *ebpf.Map
	SrcStatsA         *ebpf.Map
	SrcStatsB         *ebpf.Map
	ActiveSlot        *ebpf.Map
	PrefixStatsMap    *ebpf.Map
	SrcPrefixStatsMap *ebpf.Map
	XsightConfig      *ebpf.Map
}

func (s *stubObjects) Close() error { return nil }

// Manager holds the loaded BPF collection and all XDP attachments.
// On non-Linux platforms, Load() returns ErrNotLinux.
type Manager struct {
	Objs        *stubObjects
	Attachments []XDPAttachment
	PinPath     string
	Recovered   bool
}

// XDPAttachment is a stub on non-Linux.
type XDPAttachment struct {
	Iface   string
	PinPath string
}

const errMsg = "xsight-node requires Linux with BPF support; build with: make generate build (on Linux)"

type notLinuxError struct{}

func (notLinuxError) Error() string { return errMsg }

// ErrNotLinux is returned by all BPF operations on non-Linux platforms.
var ErrNotLinux error = notLinuxError{}

func Load(ifaceName string, maxEntries uint32) (*Manager, error)         { return nil, ErrNotLinux }
func (m *Manager) AttachXDP(ifaceName string) error                      { return ErrNotLinux }
func (m *Manager) PopulateTrie(prefixes []PrefixEntry) error             { return ErrNotLinux }
func (m *Manager) Close()                                                {}
func (m *Manager) Unload()                                               {}
func (m *Manager) SetConfig(index uint32, value uint64) error            { return ErrNotLinux }
func (m *Manager) ApplyInterfaceConfig(mode string, sb, ur uint32) error { return ErrNotLinux }
func (m *Manager) GlobalStats() (*GlobalStats, error)                    { return nil, ErrNotLinux }
func (m *Manager) ReadActiveSlot() (uint32, error)                       { return 0, ErrNotLinux }
func (m *Manager) IterIPStats() (*ebpf.MapIterator, error)               { return nil, ErrNotLinux }
func (m *Manager) BatchReadIPStats() (map[LPMKey]DstIPStats, error)      { return nil, ErrNotLinux }
func (m *Manager) IterPrefixStats() *ebpf.MapIterator                    { return nil }
func (m *Manager) IterSrcPrefixStats() *ebpf.MapIterator                 { return nil }
func (m *Manager) BatchReadSrcIPStats() (map[LPMKey]DstIPStats, error)   { return nil, ErrNotLinux }
func (m *Manager) SetSampleRate(rate uint32) error                       { return ErrNotLinux }
func (m *Manager) HotSwap(prefixes []PrefixEntry) error                  { return ErrNotLinux }

func (m *Manager) DeleteIdleStats(src bool, slot uint32, keys []LPMKey, seen map[LPMKey]DstIPStats) ([]LPMKey, bool, error) {
	return nil, false, ErrNotLinux
}

// ---------------------------------------------------------------------------
// Inline data-plane surface (Linux implementations live in inline.go/xsk.go).
// These stubs keep `GOOS=darwin go build ./...` working; every operation
// fails with ErrNotLinux at runtime.
// ---------------------------------------------------------------------------

// InlineStats mirrors the posture counters returned by InlineCounters.
type InlineStats struct {
	CookieReplies     uint64
	CookieValidated   uint64
	CookieDropped     uint64
	EmergencyDrops    uint64
	FilterDrops       uint64
	DNSDrops          uint64
	RedirectOK        uint64
	RedirectErr       uint64
	XSKSteered        uint64
	FilterPass        uint64
	ValidatedClients  uint64
	ActiveFilterRules uint64
}

// InlineRuleSpec mirrors the controller rule shape used by node/inline.go.
type InlineRuleSpec struct {
	ID            uint64
	DstIP         string
	DstPrefixLen  int
	SrcIP         string
	SrcPrefixLen  int
	Protocol      uint32
	DstPort       uint32
	SrcPort       uint32
	Action        string
	RateLimitPPS  uint64
	Priority      uint32
	ExpiresUnix   int64
	ExpiresNS     uint64
	EgressIfindex uint32
	Encap         string
	EncapDaddr    string
}

// BurstAlert mirrors the kernel burst-ringbuf record.
type BurstAlert struct {
	TimestampNS uint64
	DstAddr     [16]byte
	IsV4        uint32
	WindowPPS   uint32
	Proto       uint32
	TCPFlags    uint32
}

// DstIP returns the alerted destination as a Go IP.
func (a BurstAlert) DstIP() net.IP { return nil }

// XSKFrame is one AF_XDP received frame.
type XSKFrame struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	TCPFlags         uint8
	Payload          []byte
}

// XSKStats exposes socket health for the posture report.
type XSKStats struct {
	RX          uint64
	RXDropped   uint64
	TX          uint64
	TXDropped   uint64
	ParseErrors uint64
}

// XSK is a bound AF_XDP socket (stub).
type XSK struct{}

func (s *XSK) Stats() XSKStats { return XSKStats{} }

// XSKManager owns the AF_XDP sockets (stub).
type XSKManager struct{}

func (x *XSKManager) Close()                   {}
func (x *XSKManager) Sockets() map[uint32]*XSK { return nil }

const (
	DefaultUmemFrames = 4096
	DefaultFrameSize  = 4096
)

func StartXSK(m *Manager, iface string, queue uint32, frames, frameSize uint32,
	zeroCopy bool, handler func(XSKFrame)) (*XSKManager, error) {
	return nil, ErrNotLinux
}

// MonotonicNowNS returns 0 off-Linux so deadline arithmetic fails closed.
func MonotonicNowNS() uint64 { return 0 }

// RuleExpiryNS converts a wall-clock expiry into a monotonic deadline.
func RuleExpiryNS(expiresUnix, nowUnix int64, nowNS uint64) uint64 { return 0 }

// Inline engine control (stub).
func (m *Manager) SetInlineProgram(on bool)                  {}
func (m *Manager) SetAttachMode(mode string)                 {}
func (m *Manager) EffectiveXDPMode() string                  { return "" }
func (m *Manager) SetInlineEnabled(on bool) error            { return ErrNotLinux }
func (m *Manager) SetAlertsEnabled(on bool) error            { return ErrNotLinux }
func (m *Manager) SetDNSProtect(on bool) error               { return ErrNotLinux }
func (m *Manager) SetBurstThreshold(pps uint64) error        { return ErrNotLinux }
func (m *Manager) SetInlineSampleRate(rate uint32) error     { return ErrNotLinux }
func (m *Manager) SetEgressIfindex(idx uint32) error         { return ErrNotLinux }
func (m *Manager) SetEgressSaddr(saddr uint32) error         { return ErrNotLinux }
func (m *Manager) SetCookieSecret(lo, hi uint64) error       { return ErrNotLinux }
func (m *Manager) CookieSecret() (uint64, uint64, error)     { return 0, 0, ErrNotLinux }
func (m *Manager) SetSynCookieEnabled(on bool) error         { return ErrNotLinux }
func (m *Manager) ClearValidatedClients() error              { return ErrNotLinux }
func (m *Manager) ConfigValue(index uint32) (uint64, error)  { return 0, ErrNotLinux }
func (m *Manager) InlineCounters() InlineStats               { return InlineStats{} }
func (m *Manager) DrainAlerts(handle func(BurstAlert)) error { return ErrNotLinux }

func (m *Manager) ApplyInlineRules(specs []InlineRuleSpec, defaultAction string) error {
	return ErrNotLinux
}
