package l7

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// helloBuilder assembles a realistic TLS 1.3 ClientHello record.
type helloBuilder struct{ body []byte }

func (b *helloBuilder) u8(v uint8)   { b.body = append(b.body, v) }
func (b *helloBuilder) u16(v uint16) { b.body = append(b.body, byte(v>>8), byte(v)) }
func (b *helloBuilder) bytes(p []byte) {
	b.body = append(b.body, p...)
}
func (b *helloBuilder) vec16(p []byte) {
	b.u16(uint16(len(p)))
	b.bytes(p)
}
func (b *helloBuilder) vec8(p []byte) {
	b.u8(uint8(len(p)))
	b.bytes(p)
}

func (b *helloBuilder) extension(typ uint16, payload []byte) {
	b.u16(typ)
	b.vec16(payload)
}

// buildClientHello returns a record-layer ClientHello with GREASE sprinkled in
// (cipher 0x0a0a, group 0x2a2a, extension type 0x3a3a, supported_version
// 0x4a4a) so the parser's GREASE stripping is exercised.
func buildFullClientHello() []byte {
	b := &helloBuilder{}
	b.u16(0x0303) // legacy_version
	b.bytes(make([]byte, 32))
	b.vec8(nil) // session id

	cs := &helloBuilder{}
	for _, c := range []uint16{0x0a0a, 0x1301, 0x1302, 0xc02b} {
		cs.u16(c)
	}
	b.vec16(cs.body)
	b.vec8([]byte{0}) // compression: null

	ext := &helloBuilder{}

	// server_name = example.com
	sni := &helloBuilder{}
	sni.vec16([]byte{0x00, 0x00, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'})
	ext.extension(0x0000, sni.body)

	// supported_groups
	groups := &helloBuilder{}
	g := &helloBuilder{}
	for _, c := range []uint16{0x2a2a, 0x001d, 0x0017} {
		g.u16(c)
	}
	groups.vec16(g.body)
	ext.extension(0x000a, groups.body)

	// ec_point_formats
	ext.extension(0x000b, []byte{0x01, 0x00})

	// signature_algorithms
	sigs := &helloBuilder{}
	s := &helloBuilder{}
	for _, c := range []uint16{0x0403, 0x0804} {
		s.u16(c)
	}
	sigs.vec16(s.body)
	ext.extension(0x000d, sigs.body)

	// ALPN h2, http/1.1
	alpn := &helloBuilder{}
	a := &helloBuilder{}
	a.vec8([]byte("h2"))
	a.vec8([]byte("http/1.1"))
	alpn.vec16(a.body)
	ext.extension(0x0010, alpn.body)

	// supported_versions
	vers := &helloBuilder{}
	vers.u8(6)
	vers.u16(0x4a4a)
	vers.u16(0x0304)
	vers.u16(0x0303)
	ext.extension(0x002b, vers.body)

	// GREASE extension type: must be dropped entirely.
	ext.extension(0x3a3a, []byte{0x00})

	b.vec16(ext.body)

	hs := &helloBuilder{}
	hs.u8(0x01)
	hs.bytes([]byte{byte(len(b.body) >> 16), byte(len(b.body) >> 8), byte(len(b.body))})
	hs.bytes(b.body)

	rec := &helloBuilder{}
	rec.u8(0x16)
	rec.u16(0x0301)
	rec.vec16(hs.body)
	return rec.body
}

func TestParseClientHelloFields(t *testing.T) {
	h, ok := ParseTLSClientHelloFull(buildFullClientHello())
	if !ok {
		t.Fatal("valid ClientHello rejected")
	}
	if h.Version != 0x0303 || h.SupportedVer != 0x0304 {
		t.Fatalf("versions = (%#x, %#x), want (0x303, 0x304)", h.Version, h.SupportedVer)
	}
	if !h.GREASE {
		t.Fatal("GREASE cipher 0x0a0a should set GREASE")
	}
	wantCiphers := []uint16{0x1301, 0x1302, 0xc02b}
	if len(h.CipherSuites) != len(wantCiphers) {
		t.Fatalf("ciphers = %#x, want %#x", h.CipherSuites, wantCiphers)
	}
	for i := range wantCiphers {
		if h.CipherSuites[i] != wantCiphers[i] {
			t.Fatalf("ciphers = %#x, want %#x", h.CipherSuites, wantCiphers)
		}
	}
	if h.SNI != "example.com" || h.SNIMissing {
		t.Fatalf("sni = %q missing=%v, want example.com", h.SNI, h.SNIMissing)
	}
	if len(h.EllipticCurves) != 2 || h.EllipticCurves[0] != 0x001d {
		t.Fatalf("groups = %#x, want [0x1d 0x17]", h.EllipticCurves)
	}
	if len(h.PointsFmt) != 1 || h.PointsFmt[0] != 0 {
		t.Fatalf("points = %v, want [0]", h.PointsFmt)
	}
	if len(h.SigAlgs) != 2 || h.SigAlgs[0] != 0x0403 {
		t.Fatalf("sigalgs = %#x", h.SigAlgs)
	}
	if len(h.ALPNs) != 2 || h.ALPNs[0] != "h2" || h.ALPNs[1] != "http/1.1" {
		t.Fatalf("alpn = %v", h.ALPNs)
	}
	for _, e := range h.Extensions {
		if e == 0x3a3a {
			t.Fatal("GREASE extension type leaked into the fingerprint")
		}
	}
}

func TestJA3CanonicalStringAndMD5(t *testing.T) {
	h, _ := ParseTLSClientHelloFull(buildFullClientHello())
	str, fp := h.JA3()

	const wantStr = "771,4865-4866-49195,0-10-11-13-16-43,29-23,0"
	if str != wantStr {
		t.Fatalf("JA3 string = %q, want %q", str, wantStr)
	}
	sum := md5.Sum([]byte(wantStr))
	if want := hex.EncodeToString(sum[:]); fp != want {
		t.Fatalf("JA3 md5 = %s, want %s", fp, want)
	}
	if Ja3Of(h) != fp {
		t.Fatal("Ja3Of must return the same md5 as JA3")
	}
}

func TestJA4Segments(t *testing.T) {
	h, _ := ParseTLSClientHelloFull(buildFullClientHello())
	got := h.JA4()
	parts := strings.Split(got, "_")
	if len(parts) != 3 {
		t.Fatalf("JA4 = %q, want three underscore segments", got)
	}
	if parts[0] != "t13d0306h2" {
		t.Fatalf("JA4_a = %q, want t13d0306h2", parts[0])
	}
	cs := sha256.Sum256([]byte("4865,4866,49195"))
	if want := hex.EncodeToString(cs[:])[:12]; parts[1] != want {
		t.Fatalf("JA4_b = %q, want %s", parts[1], want)
	}
	es := sha256.Sum256([]byte("10,11,13,43"))
	if want := hex.EncodeToString(es[:])[:12]; parts[2] != want {
		t.Fatalf("JA4_c = %q, want %s", parts[2], want)
	}
}

func TestClientHelloWithoutSNI(t *testing.T) {
	payload := buildFullClientHello()
	// Remove the server_name extension by rewriting the extension block: build
	// a minimal hello with no SNI instead of byte-surgery on the fixture.
	b := &helloBuilder{}
	b.u16(0x0303)
	b.bytes(make([]byte, 32))
	b.vec8(nil)
	cs := &helloBuilder{}
	cs.u16(0x1301)
	b.vec16(cs.body)
	b.vec8([]byte{0})
	b.vec16(nil)

	hs := &helloBuilder{}
	hs.u8(0x01)
	hs.bytes([]byte{0, byte(len(b.body) >> 8), byte(len(b.body))})
	hs.bytes(b.body)
	rec := &helloBuilder{}
	rec.u8(0x16)
	rec.u16(0x0301)
	rec.vec16(hs.body)

	h, ok := ParseTLSClientHelloFull(rec.body)
	if !ok {
		t.Fatal("minimal ClientHello rejected")
	}
	if !h.SNIMissing || h.SNI != "" {
		t.Fatalf("sni missing=%v value=%q, want missing", h.SNIMissing, h.SNI)
	}
	if !strings.HasPrefix(h.JA4(), "t12r") {
		t.Fatalf("JA4 = %q, want no-SNI TLS 1.2 marker t12r", h.JA4())
	}
	_ = payload
}

func TestParseClientHelloNeverPanicsOnTruncation(t *testing.T) {
	full := buildFullClientHello()
	for n := 0; n <= len(full); n++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic at prefix length %d: %v", n, r)
				}
			}()
			if h, ok := ParseTLSClientHelloFull(full[:n]); ok {
				// Whatever the parser accepts must still be safe to fingerprint.
				_, _ = h.JA3()
				_ = h.JA4()
			}
		}()
	}
	if _, ok := ParseTLSClientHelloFull([]byte{0x15, 0x03, 0x01, 0x00, 0x00}); ok {
		t.Fatal("non-handshake record must be rejected")
	}
}

func TestGREASEValues(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0xfafa} {
		if !isGREASE(v) {
			t.Errorf("%#x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x0000, 0x1301, 0x0b0b, 0x1a1b} {
		if isGREASE(v) {
			t.Errorf("%#x should not be GREASE", v)
		}
	}
}
