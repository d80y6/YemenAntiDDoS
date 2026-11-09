package cookie

import (
	"encoding/hex"
	"testing"
)

// TestSipHash24Vectors checks the primitive against the published SipHash-2-4
// reference vectors (key 000102…0f, message 00 01 02 …). Keeping the primitive
// honest is what makes the BPF/Go lockstep meaningful: any change to the rounds
// or constants shows up here before it silently desynchronises SYN cookies.
func TestSipHash24Vectors(t *testing.T) {
	const k0 = 0x0706050403020100
	const k1 = 0x0f0e0d0c0b0a0908
	msg := make([]byte, 16)
	for i := range msg {
		msg[i] = byte(i)
	}
	cases := []struct {
		n    int
		want uint64
	}{
		{0, 0x726fdb47dd0e0e31},
		{1, 0x74f839c593dc67fd},
		{8, 0x93f5f5799a932462},
		{15, 0xa129ca6149be45e5},
	}
	for _, c := range cases {
		if got := siphash24(k0, k1, msg[:c.n]); got != c.want {
			t.Errorf("siphash24(len=%d) = %#016x, want %#016x", c.n, got, c.want)
		}
	}
}

func tuple() (sip, dip [16]byte) {
	copy(sip[:], []byte{203, 0, 113, 9})
	copy(dip[:], []byte{198, 51, 100, 20})
	return
}

// TestComputeKnownAnswer pins the tuple formula. This value must match the C
// implementation in node/bpf/xsight.c; if the message layout (addresses, port
// packing, 40-byte length block) changes on either side, this test breaks.
func TestComputeKnownAnswer(t *testing.T) {
	sip, dip := tuple()
	got := Compute(0x0123456789abcdef, 0xfedcba9876543210, sip, dip, 40000, 443)
	// Cross-checked against a harness compiled from the byte-exact C source
	// in node/bpf/xsight.c (syn_cookie_compute): sport/dport passed as the
	// wire-order __u16 values the kernel memcpy's from the packet.
	const want uint64 = 0x18eedb92e1c360a7
	if got != want {
		t.Fatalf("Compute = %#016x, want %#016x (update the C/Go pair together, not just this constant)", got, want)
	}
}

func TestComputeSensitivity(t *testing.T) {
	sip, dip := tuple()
	base := Compute(1, 2, sip, dip, 40000, 443)

	otherSip := sip
	otherSip[0] ^= 0xff
	otherDip := dip
	otherDip[0] ^= 0xff

	if Compute(1, 2, otherSip, dip, 40000, 443) == base {
		t.Fatal("cookie must depend on the source address")
	}
	if Compute(1, 2, sip, otherDip, 40000, 443) == base {
		t.Fatal("cookie must depend on the destination address")
	}
	if Compute(1, 2, sip, dip, 40001, 443) == base {
		t.Fatal("cookie must depend on the source port")
	}
	if Compute(1, 2, sip, dip, 40000, 444) == base {
		t.Fatal("cookie must depend on the destination port")
	}
	if Compute(1, 3, sip, dip, 40000, 443) == base {
		t.Fatal("cookie must depend on the secret")
	}
	if Compute(1, 2, sip, dip, 40000, 443) != base {
		t.Fatal("cookie must be deterministic for a fixed tuple")
	}
}

func TestValidAck(t *testing.T) {
	sip, dip := tuple()
	isn := ISN(7, 8, sip, dip, 1234, 443)
	if !ValidAck(isn, isn+1) {
		t.Fatal("valid handshake ACK rejected")
	}
	if ValidAck(isn, isn) {
		t.Fatal("ACK without the +1 must be rejected")
	}
	if ValidAck(isn, isn+2) {
		t.Fatal("ACK with the wrong cookie+1 must be rejected")
	}
	if ValidAck(isn+5, isn+1) {
		t.Fatal("ACK validated against the wrong cookie must be rejected")
	}
}

// TestValidAckIgnoresClientSeq documents the wire contract: a real client's
// final ACK carries its own arbitrary sequence number, unrelated to the
// cookie. Only ack_seq == cookie+1 is meaningful, so ValidAck takes no client
// sequence argument at all.
func TestValidAckIgnoresClientSeq(t *testing.T) {
	sip, dip := tuple()
	isn := ISN(11, 12, sip, dip, 5555, 53)
	for _, clientSeq := range []uint32{0, 1, isn, isn + 1, 0xdeadbeef, ^uint32(0)} {
		_ = clientSeq // client ISN is deliberately not an input to validation
		if !ValidAck(isn, isn+1) {
			t.Fatalf("ACK with client seq %#x rejected", clientSeq)
		}
	}
}

func TestAddr16(t *testing.T) {
	v4 := Addr16([]byte{1, 2, 3, 4})
	if v4[0] != 1 || v4[3] != 4 || v4[4] != 0 || v4[15] != 0 {
		t.Fatalf("IPv4 layout = %s, want first four bytes then zero padding",
			hex.EncodeToString(v4[:]))
	}
	v6raw := make([]byte, 16)
	for i := range v6raw {
		v6raw[i] = byte(0xa0 + i)
	}
	v6 := Addr16(v6raw)
	if v6 != (func() (out [16]byte) { copy(out[:], v6raw); return })() {
		t.Fatal("IPv6 address must be copied verbatim")
	}
	if Addr16([]byte{9, 9}) != ([16]byte{}) {
		t.Fatal("malformed short input must not panic or produce a partial key")
	}
}
