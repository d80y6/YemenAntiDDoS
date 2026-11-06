// Package cookie mirrors the kernel SYN-cookie formula implemented in
// node/bpf/xsight.c (xsight_siphash24 + syn_cookie_compute) so the Controller
// test harness and the Node agent can both validate handshake handoffs.
//
// Formula (keep in lockstep with the BPF C code):
//
//	cookie = siphash-2-4(key = secret_lo|secret_hi,
//	                      msg = sip[0:8] | sip[8:16] | dip[0:8] | dip[8:16] |
//	                            sport_wire_le16 | 0 | dport_wire_le16 | 0)
//
// IPv4 addresses occupy the first four bytes of a 16-byte buffer; the
// remaining bytes are zero. The ports are the raw wire values: syn_cookie_compute
// memcpy's the two network-order bytes into a __u16 (so the value is byte-swapped
// on a little-endian target) and packs them into a little-endian __u64 with
// sport in the low 32 bits. Compute() takes host-order ports and performs the
// same transformation so both sides hash byte-for-byte identical messages.
package cookie

import (
	"encoding/binary"
	"time"
)

// ValidatedTTL is how long a validated client bypasses emergency drops;
// mirrors VALIDATED_CLIENT_TTL_NS in xsight.h.
const ValidatedTTL = 60 * time.Second

// SIPROUND constants (RFC 6334 reference implementation).
const (
	sipC0 = 0x736f6d6570736575
	sipC1 = 0x646f72616e646f6d
	sipC2 = 0x6c7967656e657261
	sipC3 = 0x7465646279746573
)

func rotl(x uint64, n uint) uint64 {
	return (x << n) | (x >> (64 - n))
}

func sipRound(v0, v1, v2, v3 *uint64) {
	*v0 += *v1
	*v1 = rotl(*v1, 13)
	*v1 ^= *v0
	*v0 = rotl(*v0, 32)
	*v2 += *v3
	*v3 = rotl(*v3, 16)
	*v3 ^= *v2
	*v0 += *v3
	*v3 = rotl(*v3, 21)
	*v3 ^= *v0
	*v2 += *v1
	*v1 = rotl(*v1, 17)
	*v1 ^= *v2
	*v2 = rotl(*v2, 32)
}

// Addr16 normalizes an IPv4/IPv6 address into the 16-byte BPF key layout
// (IPv4 in the first four bytes, zero-padded).
func Addr16(ip []byte) [16]byte {
	var out [16]byte
	switch len(ip) {
	case 4:
		copy(out[:4], ip)
	case 16:
		copy(out[:], ip)
	}
	// Anything else yields the zero key rather than a partial address: a
	// truncated key would silently produce cookies for a different tuple.
	return out
}

// Compute returns the SYN cookie for a tuple, mirroring syn_cookie_compute
// in xsight.c byte for byte.
func Compute(secretLo, secretHi uint64, sip, dip [16]byte, sport, dport uint16) uint64 {
	var msg [40]byte
	copy(msg[0:8], sip[0:8])
	copy(msg[8:16], sip[8:16])
	copy(msg[16:24], dip[0:8])
	copy(msg[24:32], dip[8:16])
	// Mirror the kernel's (__u64)sport | (__u64)dport<<32 over wire-order values:
	// msg[32:34] = sport bytes (network order), msg[34:36] = 0,
	// msg[36:38] = dport bytes (network order), msg[38:40] = 0.
	ports := uint64(swap16(sport)) | uint64(swap16(dport))<<32
	binary.LittleEndian.PutUint64(msg[32:40], ports)

	return siphash24(secretLo, secretHi, msg[:])
}

// swap16 reverses the two bytes of a host-order port, yielding the value the
// kernel observes after memcpy'ing wire bytes into a little-endian __u16.
func swap16(v uint16) uint16 { return v<<8 | v>>8 }

// siphash24 is the standard SipHash-2-4 with a 128-bit key split into two
// little-endian 64-bit halves. It is exposed to tests so the primitive can be
// checked against the published vectors; the BPF side uses the same constants
// (xsight_siphash24 in xsight.c).
func siphash24(k0, k1 uint64, msg []byte) uint64 {
	v0 := sipC0 ^ k0
	v1 := sipC1 ^ k1
	v2 := sipC2 ^ k0
	v3 := sipC3 ^ k1

	full := len(msg) &^ 7
	for i := 0; i < full; i += 8 {
		m := binary.LittleEndian.Uint64(msg[i : i+8])
		v3 ^= m
		sipRound(&v0, &v1, &v2, &v3)
		sipRound(&v0, &v1, &v2, &v3)
		v0 ^= m
	}

	// Final partial word: remaining bytes plus the length in the top byte.
	var last uint64 = uint64(len(msg)) << 56
	for i, b := range msg[full:] {
		last |= uint64(b) << (8 * uint(i))
	}
	v3 ^= last
	sipRound(&v0, &v1, &v2, &v3)
	sipRound(&v0, &v1, &v2, &v3)
	v0 ^= last

	v2 ^= 0xff
	for i := 0; i < 4; i++ {
		sipRound(&v0, &v1, &v2, &v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

// ISN returns the 32-bit initial sequence number a SYN-ACK carries.
func ISN(secretLo, secretHi uint64, sip, dip [16]byte, sport, dport uint16) uint32 {
	return uint32(Compute(secretLo, secretHi, sip, dip, sport, dport))
}

// ValidAck reports whether a client's final ACK validates the cookie: ack_seq
// must equal cookie+1. The client's own sequence number is unrelated to the
// cookie and is deliberately not an input. Mirrors validate_cookie_ack in
// xsight.c.
func ValidAck(cookie, ackNum uint32) bool {
	return ackNum == cookie+1
}
