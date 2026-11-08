// JS-PoW challenge responder for traffic steered by the data plane's
// FILTER_ACTION_CHALLENGE rule.
//
// The responder owns the challenged TCP conversation while the rule matches:
// it completes handshakes (deterministic per-boot ISNs so retransmissions are
// stable), answers unsolved HTTP requests with an HTTP 307 to the PoW page,
// serves that page, and admits solved clients into the data plane's
// validated_clients map so their follow-up connections reach the host stack.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
	"github.com/d80y6/YemenDDoS/node/internal/l7collector"
)

// challengeISNSecret differentiates this boot's SYN-ACK sequence numbers from
// other installations while staying stable for retransmitted SYNs.
var challengeISNSecret = func() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}()

// challengeISN derives the responder's ISN for a connection from the 4-tuple
// and the client's ISN, so a retransmitted SYN produces the same SYN-ACK.
func challengeISN(f bpf.XSKFrame, clientISN uint32) uint32 {
	h := sha256.New()
	h.Write(challengeISNSecret)
	h.Write(f.SrcIP.To4())
	h.Write(f.DstIP.To4())
	var t [8]byte
	binary.BigEndian.PutUint16(t[0:2], f.SrcPort)
	binary.BigEndian.PutUint16(t[2:4], f.DstPort)
	binary.BigEndian.PutUint32(t[4:8], clientISN)
	h.Write(t[:])
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
}

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
)

// challengeResponder answers challenged TCP frames. admit and send are
// dependency seams (validated_clients insert and UMEM TX respectively).
type challengeResponder struct {
	issuer *l7collector.ChallengeIssuer
	admit  func(f bpf.XSKFrame) error
	send   func(f bpf.XSKFrame, reply []byte) bool
	now    func() time.Time
}

// handle processes one steered frame.
func (r *challengeResponder) handle(f bpf.XSKFrame) {
	if r == nil || r.issuer == nil || !r.issuer.Enabled() || r.send == nil {
		return
	}
	if len(f.EthHdr) < 14 || f.SrcIP.To4() == nil || f.DstIP.To4() == nil {
		return // cannot reply without L2 + IPv4
	}
	now := time.Now()
	if r.now != nil {
		now = r.now()
	}

	// Handshake: complete it here so the HTTP exchange can happen.
	if f.TCPFlags&tcpFlagSYN != 0 && f.TCPFlags&tcpFlagACK == 0 && len(f.Payload) == 0 {
		r.reply(f, challengeISN(f, f.Seq), f.Seq+1, tcpFlagSYN|tcpFlagACK, nil)
		return
	}
	if len(f.Payload) == 0 {
		return // pure ACK / FIN — nothing to answer
	}

	target, ok := httpTarget(f.Payload)
	if !ok {
		return
	}
	// First data segment: their ISN is seq-1 (HTTP is the first payload).
	theirISN := f.Seq - uint32(len(f.Payload))
	ourSeq := challengeISN(f, theirISN) + 1
	ack := f.Seq + uint32(len(f.Payload))

	path, query := splitTarget(target)
	if path == r.issuer.Path() {
		// Serve the PoW page; `n` carries the original request target.
		next := query.Get("n")
		if next == "" {
			next = "/"
		}
		page := l7collector.RenderChallengePage(query.Get("t"), r.issuer.POWBits(), next)
		r.reply(f, ourSeq, ack, tcpFlagFIN|tcpFlagACK, page)
		return
	}

	if tok := query.Get("t"); tok != "" {
		pow := query.Get("xsight_pow")
		if r.issuer.VerifyPoW(tok, pow) && r.issuer.Validate(tok, f.SrcIP.String(), now) {
			// Solved: admit the client, then send it on to the original
			// location (follow-up connections pass the data plane).
			if r.admit != nil {
				if err := r.admit(f); err != nil {
					log.Printf("challenge: admit %s: %v", f.SrcIP, err)
				}
			}
			r.reply(f, ourSeq, ack, tcpFlagFIN|tcpFlagACK,
				l7collector.RenderChallenge307(challengeNext(path, query)))
			return
		}
	}

	// Unverified request → 307 to the challenge page; `n` remembers the target.
	_, loc := r.issuer.Mint(f.SrcIP.String(), now)
	if loc == "" {
		return
	}
	loc += "&n=" + url.QueryEscape(target)
	r.reply(f, ourSeq, ack, tcpFlagFIN|tcpFlagACK, l7collector.RenderChallenge307(loc))
}

func (r *challengeResponder) reply(f bpf.XSKFrame, seq, ack uint32, flags uint8, payload []byte) {
	out := buildTCPReply(f, seq, ack, flags, payload)
	if out == nil {
		return
	}
	if !r.send(f, out) {
		log.Printf("challenge: TX failed dst=%s port=%d", f.SrcIP, f.SrcPort)
	}
}

// httpTarget returns the request-target of an HTTP/1.x request line.
func httpTarget(payload []byte) (string, bool) {
	line := payload
	if i := bytes.IndexByte(line, '\r'); i >= 0 {
		line = line[:i]
	}
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 3 {
		return "", false
	}
	switch fields[0] {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH":
	default:
		return "", false
	}
	if !strings.HasPrefix(fields[2], "HTTP/1.") {
		return "", false
	}
	return fields[1], true
}

// splitTarget splits a request-target into path and query values.
func splitTarget(target string) (string, url.Values) {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		q, _ := url.ParseQuery(target[i+1:])
		return target[:i], q
	}
	return target, url.Values{}
}

// challengeNext rebuilds the original location without challenge parameters.
func challengeNext(path string, q url.Values) string {
	for _, k := range []string{"t", "xsight_pow", "n"} {
		q.Del(k)
	}
	if enc := q.Encode(); enc != "" {
		return path + "?" + enc
	}
	return path
}

// buildTCPReply swaps L2/L3/L4 roles and wraps payload in a fresh IPv4+TCP
// segment with computed checksums. Returns nil when the frame cannot be
// replied to (needs L2 header and IPv4 endpoints).
func buildTCPReply(f bpf.XSKFrame, seq, ack uint32, flags uint8, payload []byte) []byte {
	src := f.SrcIP.To4()
	dst := f.DstIP.To4()
	eth := f.EthHdr
	if len(eth) < 14 || len(eth) > 18 || src == nil || dst == nil {
		return nil
	}
	total := 20 + 20 + len(payload)
	if total > 0xffff {
		return nil
	}

	ip := make([]byte, 20)
	ip[0] = 0x45 // IPv4, 5 words
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	ip[8] = 64
	ip[9] = 6            // TCP
	copy(ip[12:16], dst) // server → client
	copy(ip[16:20], src)
	binary.BigEndian.PutUint16(ip[10:12], checksumWords(ip))

	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], f.DstPort)
	binary.BigEndian.PutUint16(tcp[2:4], f.SrcPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // data offset
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(dst, src, tcp))

	out := make([]byte, 0, len(eth)+len(ip)+len(tcp))
	swapped := append([]byte(nil), eth...)
	for i := 0; i < 6; i++ {
		swapped[i], swapped[6+i] = swapped[6+i], swapped[i]
	}
	out = append(out, swapped...)
	out = append(out, ip...)
	out = append(out, tcp...)
	return out
}

// checksumWords folds bytes as big-endian 16-bit words (odd tail padded).
func checksumWords(parts ...[]byte) uint16 {
	var sum uint32
	for _, b := range parts {
		n := len(b) &^ 1
		for i := 0; i < n; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)&1 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the IPv4 pseudo-header + segment.
func tcpChecksum(src, dst []byte, tcp []byte) uint16 {
	var pseudo [12]byte
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 6 // protocol TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	return checksumWords(pseudo[:], tcp)
}
