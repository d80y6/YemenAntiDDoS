package sampler

import (
	"encoding/hex"
	"testing"
)

func dao13fTypeIFrame(t *testing.T) []byte {
	t.Helper()
	// Fixed review frame: GRE 0x88be without sequence or an ERSPAN header.
	// The real IPv6 NextHeader/HopLimit bytes mimic an Ethernet IPv6 type
	// after gopacket incorrectly consumes eight bytes as ERSPAN Type II.
	raw, err := hex.DecodeString("02000000000102000000000208004500005e000000003d2f2907c6336401c6336402000088be02000000000102000000000286dd60000000001086dd6000000000013b4020010db80001000220010db800020003000400050006000700000000000000000000000000000000")
	if err != nil || len(raw) != 108 {
		t.Fatalf("fixed Type I frame: length=%d error=%v", len(raw), err)
	}
	return raw
}

func TestDao13f_E5(t *testing.T) {
	t.Run("OuterSequenceSurvivesInnerGRE", func(t *testing.T) {
		inner4 := dao13fIP(false, 17, "192.0.2.1", "192.0.2.2", dao13fL4(false))
		innerGRE := append([]byte{0, 0, 0x08, 0}, inner4...)
		inner6 := dao13fIP(true, 47, "2001:db8:ffff::1", "2001:db8::10", innerGRE)
		raw := dao13fTunnel(dao13fEther(0x86dd, inner6))
		p := NewPacketParser()
		got := p.ParseMode(raw, uint32(len(raw)), true)
		// The final shared GRE struct has no sequence, but the GRE adjacent
		// to ERSPAN Type II did have it when that outer layer was decoded.
		if p.gre.SeqPresent {
			t.Fatal("precondition: the deeper GRE must overwrite SeqPresent with false")
		}
		dao13fEqual(t, got, dao13fWant(raw, "2001:db8:ffff::1", "2001:db8::10", 47, 49, 0, true))
	})
	t.Run("TypeIUnchanged", func(t *testing.T) {
		raw := dao13fTypeIFrame(t)
		// The complete expected sample is independently checked on cb4cefa.
		want := dao13fWant(raw, "198.51.100.1", "198.51.100.2", 47, 61, 0, false)
		legacy := NewPacketParser().Parse(raw, uint32(len(raw)))
		dao13fEqual(t, legacy, want)
		for _, tc := range []struct {
			name   string
			erspan bool
		}{{"Mirror", false}, {"Erspan", true}} {
			t.Run(tc.name, func(t *testing.T) {
				got := NewPacketParser().ParseMode(raw, uint32(len(raw)), tc.erspan)
				dao13fEqual(t, got, legacy)
				dao13fEqual(t, got, want)
			})
		}
	})
	// A reused parser must not carry GRE sequence qualification from the
	// previous frame in either direction.
	t.Run("ReusedParserSequenceNoLeak", func(t *testing.T) {
		typeII, typeI := dao13fFrames()["v6udp"], dao13fTypeIFrame(t)
		wantII := dao13fWant(typeII, "2001:db8:ffff::1", "2001:db8::10", 17, 49, 0, true)
		wantI := dao13fWant(typeI, "198.51.100.1", "198.51.100.2", 47, 61, 0, false)
		t.Run("IIThenI", func(t *testing.T) {
			p := NewPacketParser()
			dao13fEqual(t, p.ParseMode(typeII, uint32(len(typeII)), true), wantII)
			dao13fEqual(t, p.ParseMode(typeI, uint32(len(typeI)), true), wantI)
		})
		t.Run("IThenII", func(t *testing.T) {
			p := NewPacketParser()
			dao13fEqual(t, p.ParseMode(typeI, uint32(len(typeI)), true), wantI)
			dao13fEqual(t, p.ParseMode(typeII, uint32(len(typeII)), true), wantII)
		})
	})
}
