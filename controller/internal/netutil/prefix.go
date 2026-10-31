// Package netutil provides shared network utility functions.
package netutil

import (
	"fmt"
	"net"
)

// FormatPrefix converts raw IP bytes + prefix length to a CIDR string.
// e.g. ([]byte{10,2,0,0}, 24) → "10.2.0.0/24"
func FormatPrefix(raw []byte, prefixLen uint32) string {
	ip := net.IP(raw)
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%s/%d", ip4.String(), prefixLen)
	}
	return fmt.Sprintf("%s/%d", ip.String(), prefixLen)
}

// CanonicalPrefix accepts only valid prefixes with no host bits set.
// The input is never modified, and accepted strings retain FormatPrefix semantics.
func CanonicalPrefix(raw []byte, prefixLen uint32) (string, *net.IPNet, bool) {
	if len(raw) != net.IPv4len && len(raw) != net.IPv6len {
		return "", nil, false
	}
	ip := net.IP(raw)
	bits := 128
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		bits = 32
	}
	if prefixLen > uint32(bits) {
		return "", nil, false
	}
	mask := net.CIDRMask(int(prefixLen), bits)
	masked := ip.Mask(mask)
	if !masked.Equal(ip) {
		return "", nil, false
	}
	return FormatPrefix(raw, prefixLen), &net.IPNet{IP: masked, Mask: mask}, true
}

// CanonicalIP formats an address only when its byte length is valid.
func CanonicalIP(raw []byte) (string, bool) {
	if len(raw) != net.IPv4len && len(raw) != net.IPv6len {
		return "", false
	}
	return net.IP(raw).String(), true
}
