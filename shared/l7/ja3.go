// JA3 / JA4 TLS ClientHello fingerprinting.
//
// JA3 (Salesforce) hashes the MD5 of the comma-joined SSLVersion,Cipher,
// Extension,EllipticCurve,EllipticCurvePointFmt fields. We compute the
// pre-hash string and, because crypto/md5 adds no external dependency, also
// the canonical JA3 md5.
//
// JA4 (FoxIO) encodes protocol/version/SNI/ciphers/extensions/alpn/sigalgs
// into "t13d1516h2_8daaf6152771_b186095e22b6"-style strings. We implement the
// canonical a/b/c segment rules for ClientHello samples.
//
// All functions are total: truncated or malformed input returns ok=false
// rather than panicking — the XDP/AF_XDP hot path feeds bounded prefixes.

package l7

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

// TLSHandshake is the extracted ClientHello evidence.
type TLSHandshake struct {
	Version        uint16   // record layer version (legacy)
	CipherSuites   []uint16 // offered ciphers, wire order
	Extensions     []uint16 // offered extension types, wire order
	SupportedVer   uint16   // supported_versions extension max (e.g. 0x0304)
	EllipticCurves []uint16 // supported_groups extension
	PointsFmt      []uint8  // ec_point_formats
	ALPNs          []string // application_layer_protocol_negotiation entries
	SigAlgs        []uint16 // signature_algorithms
	SNI            string
	SNIMissing     bool
	GREASE         bool // first cipher is a GREASE value (bots often skip them)
}

// JA3 returns the JA3 pre-hash string ("769,47-53,0-11,...") per the
// canonical definition, plus the md5 fingerprint.
func (h TLSHandshake) JA3() (string, string) {
	ver := h.Version
	if h.SupportedVer != 0 {
		// JA3 canonical behavior keeps the legacy record version; bots that
		// hardcode it are visible in the fingerprint distribution.
		ver = h.Version
	}
	ciphers := make([]string, 0, len(h.CipherSuites))
	for _, c := range h.CipherSuites {
		ciphers = append(ciphers, u16s(c))
	}
	exts := make([]string, 0, len(h.Extensions))
	for _, e := range h.Extensions {
		exts = append(exts, u16s(e))
	}
	curves := make([]string, 0, len(h.EllipticCurves))
	for _, c := range h.EllipticCurves {
		curves = append(curves, u16s(c))
	}
	fmts := make([]string, 0, len(h.PointsFmt))
	for _, f := range h.PointsFmt {
		fmts = append(fmts, u8s(f))
	}
	s := strings.Join([]string{
		u16s(ver),
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(fmts, "-"),
	}, ",")
	sum := md5.Sum([]byte(s))
	return s, hex.EncodeToString(sum[:])
}

// JA4 builds the canonical FoxIO-style JA4 ClientHello fingerprint:
//
//	<proto><ver><sni><#ciphers><#exts><alpn>_<ciph>_<ext>_<sigalgs>
//
// proto is fixed "t" (TCP). ver comes from supported_versions when present
// ("13"/"12"/"11"/"10", else "00"). sni is "d" for a domain name and "i"
// otherwise (absent SNI or an IP literal). Counts are two digits, capped at
// 99, with GREASE already stripped by the parser. alpn is the first+last
// character of the first ALPN protocol, "00" when none.
//
// The three digests are the first 4 characters of SHA-256 over the comma-
// joined 4-char lowercase hex values: ciphers sorted, extension types sorted
// (excluding SNI and ALPN), and signature_algorithms in wire order.
func (h TLSHandshake) JA4() string {
	proto := "t"

	verVal := h.Version
	if h.SupportedVer != 0 {
		verVal = h.SupportedVer
	}
	ver := "00"
	switch verVal {
	case 0x0304:
		ver = "13"
	case 0x0303:
		ver = "12"
	case 0x0302:
		ver = "11"
	case 0x0301:
		ver = "10"
	}

	// "d" for a domain SNI; "i" when the SNI is absent or an IP literal.
	sni := "d"
	if h.SNI == "" || net.ParseIP(h.SNI) != nil {
		sni = "i"
	}

	cipherCount := formatCount(cipherCountCaps(len(h.CipherSuites)))
	extCount := formatCount(cipherCountCaps(len(h.Extensions)))

	alpn := "00"
	if len(h.ALPNs) > 0 {
		first := h.ALPNs[0]
		if first != "" {
			alpn = strings.ToLower(first[:1]) + strings.ToLower(first[len(first)-1:])
			if len(first) == 1 {
				alpn = strings.ToLower(first) + strings.ToLower(first)
			}
		}
	}

	ciphers := append([]uint16(nil), h.CipherSuites...)
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })
	cipherHash := sha256Hex4(hex4Join(ciphers))

	// JA4_c excludes SNI (0) and ALPN (16) extensions.
	var extsNoSNI []uint16
	for _, e := range h.Extensions {
		if e == 0x0000 || e == 0x0010 {
			continue
		}
		extsNoSNI = append(extsNoSNI, e)
	}
	if len(extsNoSNI) == 0 {
		extsNoSNI = append(extsNoSNI, 0) // canonical "0" when nothing remains
	}
	sort.Slice(extsNoSNI, func(i, j int) bool { return extsNoSNI[i] < extsNoSNI[j] })
	extHash := sha256Hex4(hex4Join(extsNoSNI))

	// Signature algorithms keep wire order.
	sigHash := sha256Hex4(hex4Join(h.SigAlgs))

	return strings.Join([]string{
		proto + ver + sni + cipherCount + extCount + alpn,
		cipherHash,
		extHash,
		sigHash,
	}, "_")
}

// Ja3Of is a convenience wrapper returning just the md5 fingerprint.
func Ja3Of(h TLSHandshake) string {
	_, fp := h.JA3()
	return fp
}

// --- internals -------------------------------------------------------------

func u16s(v uint16) string {
	return trimPadInt(uint64(v))
}

func u8s(v uint8) string {
	return trimPadInt(uint64(v))
}

func trimPadInt(v uint64) string {
	// Canonical JA3 uses decimal without padding.
	var buf [20]byte
	i := len(buf)
	if v == 0 {
		return "0"
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// hex4Join renders uint16s as 4-char lowercase hex, comma-joined.
func hex4Join(vals []uint16) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, fmt.Sprintf("%04x", v))
	}
	return strings.Join(parts, ",")
}

// cipherCountCaps caps the two-digit cipher count at "99" per FoxIO spec.
func cipherCountCaps(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

func formatCount(n int) string {
	if n < 10 {
		return "0" + trimPadInt(uint64(n))
	}
	return trimPadInt(uint64(n))
}

// sha256Hex4 computes SHA-256 and returns the first 4 lowercase hex characters.
func sha256Hex4(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:4]
}

// ParseTLSClientHelloFull extracts the complete TLSHandshake structure from
// a payload starting at the TLS record header. ok=false when the payload is
// not a ClientHello or is truncated before the fields we need.
func ParseTLSClientHelloFull(payload []byte) (TLSHandshake, bool) {
	var h TLSHandshake
	// TLS record: type(1) ver(2) len(2)
	if len(payload) < 5 || payload[0] != 0x16 {
		return h, false
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recLen < 0 {
		return h, false
	}
	end := 5 + recLen
	if end > len(payload) {
		end = len(payload) // truncated capture: parse what we have
	}
	// Handshake: type(1) len(3)
	if end-5 < 4 {
		return h, false
	}
	if payload[5] != 0x01 { // ClientHello only
		return h, false
	}
	hsLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	hs := payload[9:min(9+hsLen, end)]
	if len(hs) < 34 {
		return h, false
	}
	// JA3/JA4 use the ClientHello legacy_version, not the record-layer version
	// (bots frequently pin the record version to 0x0301 on every hello).
	h.Version = binary.BigEndian.Uint16(hs[0:2])
	pos := 34 // random
	if pos >= len(hs) {
		return h, false
	}
	sidLen := int(hs[pos])
	pos += 1 + sidLen
	if pos+2 > len(hs) {
		return h, false
	}
	csLen := int(binary.BigEndian.Uint16(hs[pos:]))
	pos += 2
	if pos+csLen > len(hs) || csLen%2 != 0 {
		return h, false
	}
	for i := 0; i < csLen; i += 2 {
		c := binary.BigEndian.Uint16(hs[pos+i:])
		if isGREASE(c) {
			h.GREASE = true
			continue
		}
		h.CipherSuites = append(h.CipherSuites, c)
	}
	pos += csLen
	if pos+1 > len(hs) {
		return h, false
	}
	cmLen := int(hs[pos])
	pos += 1 + cmLen
	if pos+2 > len(hs) {
		return h, false
	}
	extLen := int(binary.BigEndian.Uint16(hs[pos:]))
	pos += 2
	extEnd := pos + extLen
	if extEnd > len(hs) {
		extEnd = len(hs)
	}
	hasSNIExt := false
	for pos+4 <= extEnd {
		etype := binary.BigEndian.Uint16(hs[pos:])
		elen := int(binary.BigEndian.Uint16(hs[pos+2:]))
		pos += 4
		if pos+elen > extEnd {
			break
		}
		data := hs[pos : pos+elen]
		pos += elen

		if isGREASE(etype) {
			continue
		}
		h.Extensions = append(h.Extensions, etype)

		switch etype {
		case 0x0000: // server_name
			hasSNIExt = true
			h.SNI = parseSNIExt(data)
			if h.SNI == "" {
				h.SNIMissing = true
			}
		case 0x000a: // supported_groups
			if len(data) >= 2 {
				n := int(binary.BigEndian.Uint16(data[0:2]))
				for i := 2; i+1 < 2+n && i+1 < len(data); i += 2 {
					g := binary.BigEndian.Uint16(data[i:])
					if !isGREASE(g) {
						h.EllipticCurves = append(h.EllipticCurves, g)
					}
				}
			}
		case 0x000b: // ec_point_formats
			if len(data) >= 1 {
				n := int(data[0])
				for i := 1; i < 1+n && i < len(data); i++ {
					h.PointsFmt = append(h.PointsFmt, data[i])
				}
			}
		case 0x000d: // signature_algorithms
			if len(data) >= 2 {
				n := int(binary.BigEndian.Uint16(data[0:2]))
				for i := 2; i+1 < 2+n && i+1 < len(data); i += 2 {
					h.SigAlgs = append(h.SigAlgs, binary.BigEndian.Uint16(data[i:]))
				}
			}
		case 0x0010: // ALPN
			h.ALPNs = parseALPN(data)
		case 0x002b: // supported_versions
			if len(data) >= 1 {
				n := int(data[0])
				best := uint16(0)
				for i := 1; i+1 < 1+n && i+1 < len(data); i += 2 {
					v := binary.BigEndian.Uint16(data[i:])
					if !isGREASE(v) && v > best {
						best = v
					}
				}
				h.SupportedVer = best
			}
		}
	}
	if !hasSNIExt {
		h.SNIMissing = true
	}
	return h, true
}

// parseSNIExt parses the server_name extension payload (list + entries).
// Distinct from l7.go's parseSNI which receives the pre-trimmed entry.
func parseSNIExt(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen == 0 || 2+listLen > len(data) {
		return ""
	}
	nameType := data[2]
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if nameType != 0 || nameLen == 0 || 5+nameLen > len(data) {
		return ""
	}
	return string(data[5 : 5+nameLen])
}

func parseALPN(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if listLen == 0 || 2+listLen > len(data) {
		return nil
	}
	var out []string
	for i := 2; i < 2+listLen; {
		l := int(data[i])
		i++
		if l == 0 || i+l > 2+listLen || i+l > len(data) {
			break
		}
		out = append(out, string(data[i:i+l]))
		i += l
	}
	return out
}

func isGREASE(v uint16) bool {
	return (v & 0x0F0F) == 0x0A0A
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
