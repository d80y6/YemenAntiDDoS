// Package mitigation provides data models, cryptographic primitives,
// and rule evaluation contracts for inline packet scrubbing and autonomous mitigation.
package mitigation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// ActionType defines the forwarding or filtering decision applied to packets.
type ActionType uint8

const (
	// ActionPass lets the packet continue through the normal network stack.
	ActionPass ActionType = iota
	// ActionDrop discards the packet immediately at line rate.
	ActionDrop
	// ActionRedirect diverts the packet to a clean-pipe egress interface or tunnel.
	ActionRedirect
	// ActionRateLimit imposes a token-bucket rate limiter in hardware or XDP.
	ActionRateLimit
	// ActionChallenge invokes stateless SYN Cookie or L7 cryptographic challenge.
	ActionChallenge
)

func (a ActionType) String() string {
	switch a {
	case ActionPass:
		return "pass"
	case ActionDrop:
		return "drop"
	case ActionRedirect:
		return "redirect"
	case ActionRateLimit:
		return "rate_limit"
	case ActionChallenge:
		return "challenge"
	default:
		return "unknown"
	}
}

// InlineRule defines a granular line-rate filtering rule for XDP or hardware offload.
type InlineRule struct {
	ID             string     `json:"id"`
	TargetPrefix   string     `json:"target_prefix"` // Destination prefix (CIDR)
	Protocol       uint8      `json:"protocol"`      // 6=TCP, 17=UDP, 1=ICMP, 0=Any
	SrcPrefix      string     `json:"src_prefix"`    // Source prefix (CIDR or empty)
	DstPort        uint16     `json:"dst_port"`      // 0 = any port
	SrcPort        uint16     `json:"src_port"`      // 0 = any port
	Action         ActionType `json:"action"`
	RateLimitPPS   uint64     `json:"rate_limit_pps,omitempty"`
	RedirectIfindex int32     `json:"redirect_ifindex,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
}

// Validate checks if the inline rule has consistent addresses and valid ranges.
func (r *InlineRule) Validate() error {
	if r.ID == "" {
		return errors.New("rule id cannot be empty")
	}
	if _, _, err := net.ParseCIDR(r.TargetPrefix); err != nil {
		if ip := net.ParseIP(r.TargetPrefix); ip == nil {
			return errors.New("invalid target prefix or IP")
		}
	}
	if r.SrcPrefix != "" {
		if _, _, err := net.ParseCIDR(r.SrcPrefix); err != nil {
			if ip := net.ParseIP(r.SrcPrefix); ip == nil {
				return errors.New("invalid src prefix or IP")
			}
		}
	}
	if r.Action == ActionRateLimit && r.RateLimitPPS == 0 {
		return errors.New("rate_limit action requires positive rate_limit_pps")
	}
	return nil
}

// GenerateSYNCookie computes a stateless, truncated 32-bit TCP Sequence Number cookie.
// Formula uses HMAC-SHA256 truncated over 4-tuple, client ISN, timestamp (mod 64s), and a secret key.
func GenerateSYNCookie(srcIP, dstIP net.IP, srcPort, dstPort uint16, clientISN uint32, t time.Time, secret []byte) uint32 {
	h := hmac.New(sha256.New, secret)

	var buf [16]byte
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint32(buf[4:8], clientISN)

	// Time slot in 64-second windows (2 bits in cookie sequence)
	timeSlot := uint32(t.Unix() / 64)
	binary.BigEndian.PutUint32(buf[8:12], timeSlot)

	h.Write(srcIP.To16())
	h.Write(dstIP.To16())
	h.Write(buf[:12])

	mac := h.Sum(nil)
	hashPart := binary.BigEndian.Uint32(mac[:4]) & 0x00FFFFFF // 24-bit hash
	timePart := (timeSlot & 0xFF) << 24                       // 8-bit time window

	return timePart | hashPart
}

// VerifySYNCookie verifies if an incoming ACK sequence number corresponds to a valid SYN cookie.
// Allows for a 128-second clock window (current slot and previous slot).
func VerifySYNCookie(srcIP, dstIP net.IP, srcPort, dstPort uint16, clientISN uint32, ackSeq uint32, now time.Time, secret []byte) bool {
	cookie := ackSeq - 1
	cookieTimeSlot := (cookie >> 24) & 0xFF

	currentSlot := uint32(now.Unix() / 64)
	for i := uint32(0); i <= 2; i++ {
		slot := currentSlot - i
		if (slot & 0xFF) == cookieTimeSlot {
			expected := GenerateSYNCookie(srcIP, dstIP, srcPort, dstPort, clientISN, time.Unix(int64(slot*64), 0), secret)
			if expected == cookie {
				return true
			}
		}
	}
	return false
}

// MicroMitigationAlert represents an emergency sub-second trigger emitted by eBPF/XDP.
type MicroMitigationAlert struct {
	NodeID       string     `json:"node_id"`
	TimestampNs  int64      `json:"timestamp_ns"`
	TargetIP     string     `json:"target_ip"`
	Protocol     uint8      `json:"protocol"`
	BurstPPS     uint64     `json:"burst_pps"`
	BurstBPS     uint64     `json:"burst_bps"`
	ActionTaken  ActionType `json:"action_taken"`
	DurationSec  uint32     `json:"duration_sec"`
}
