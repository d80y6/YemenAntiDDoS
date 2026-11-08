package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
	"github.com/d80y6/YemenDDoS/node/internal/l7collector"
)

type capturedReply struct {
	offset uint64
	data   []byte
}

func challengeTestIssuer(t *testing.T) *l7collector.ChallengeIssuer {
	t.Helper()
	return l7collector.NewChallengeIssuer(l7collector.ChallengeConfig{
		Enabled:     true,
		Secret:      []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL:    time.Hour,
		RedirectTo:  "/.xsight-challenge",
		POWDiffBits: 8,
	})
}

// challengeFrame builds a synthetic steered IPv4/TCP frame with L2 bytes.
func challengeFrame(flags uint8, seq, ack uint32, payload string) bpf.XSKFrame {
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})  // server MAC
	copy(eth[6:12], []byte{0x02, 0, 0, 0, 0, 0x01}) // client MAC
	eth[12], eth[13] = 0x08, 0x00
	return bpf.XSKFrame{
		SrcIP:       []byte{203, 0, 113, 5},
		DstIP:       []byte{198, 51, 100, 7},
		SrcPort:     40000,
		DstPort:     80,
		TCPFlags:    flags,
		Seq:         seq,
		Ack:         ack,
		FrameOffset: 4096 * 3,
		EthHdr:      eth,
		Payload:     []byte(payload),
	}
}

func newTestResponder(t *testing.T) (*challengeResponder, *l7collector.ChallengeIssuer, *[]capturedReply, *int) {
	t.Helper()
	issuer := challengeTestIssuer(t)
	var got []capturedReply
	admitted := 0
	r := &challengeResponder{
		issuer: issuer,
		admit: func(f bpf.XSKFrame) error {
			admitted++
			return nil
		},
		send: func(f bpf.XSKFrame, reply []byte) bool {
			got = append(got, capturedReply{offset: f.FrameOffset, data: append([]byte(nil), reply...)})
			return true
		},
		now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	return r, issuer, &got, &admitted
}

// parseReply tears a built reply back into TCP header + body.
func parseReply(t *testing.T, data []byte) (flags uint8, seq, ack uint32, body string) {
	t.Helper()
	if len(data) < 14+20+20 {
		t.Fatalf("reply too short: %d bytes", len(data))
	}
	ip := data[14:]
	if ip[0]>>4 != 4 || ip[9] != 6 {
		t.Fatalf("reply is not IPv4/TCP: %#x", ip[:12])
	}
	ihl := int(ip[0]&0x0F) * 4
	if got := checksumWords(ip[:ihl]); got != 0 {
		t.Errorf("IP checksum invalid (fold = %#04x)", got)
	}
	src, dst := ip[12:16], ip[16:20]
	if src[0] != 198 || dst[0] != 203 {
		t.Errorf("reply IPs not swapped: src=%v dst=%v", src, dst)
	}
	tcp := ip[ihl:]
	if got := tcpChecksum(dst, src, tcp); got != 0 {
		t.Errorf("TCP checksum invalid (fold = %#04x)", got)
	}
	if int(tcp[0])<<8|int(tcp[1]) != 80 {
		t.Errorf("reply sport = %d, want 80", int(tcp[0])<<8|int(tcp[1]))
	}
	if int(tcp[2])<<8|int(tcp[3]) != 40000 {
		t.Errorf("reply dport = %d, want 40000", int(tcp[2])<<8|int(tcp[3]))
	}
	return tcp[13], uint32(tcp[4])<<24 | uint32(tcp[5])<<16 | uint32(tcp[6])<<8 | uint32(tcp[7]),
		uint32(tcp[8])<<24 | uint32(tcp[9])<<16 | uint32(tcp[10])<<8 | uint32(tcp[11]),
		string(tcp[20:])
}

func TestChallengeHandshakeCompletes(t *testing.T) {
	r, _, got, _ := newTestResponder(t)
	f := challengeFrame(0x02, 0x11223344, 0, "") // SYN
	r.handle(f)
	r.handle(f) // retransmission must be deterministic
	if len(*got) != 2 {
		t.Fatalf("replies = %d, want 2 (SYN-ACK + retransmission)", len(*got))
	}
	flags, _, ack, body := parseReply(t, (*got)[0].data)
	if flags&0x12 != 0x12 || flags&0x01 != 0 {
		t.Fatalf("flags = %#x, want SYN-ACK without FIN", flags)
	}
	if ack != 0x11223344+1 {
		t.Fatalf("ack = %#x, want client ISN+1", ack)
	}
	if body != "" {
		t.Fatalf("SYN-ACK carries %d payload bytes", len(body))
	}
	if string((*got)[0].data) != string((*got)[1].data) {
		t.Fatal("retransmitted SYN produced a different SYN-ACK (ISN not stable)")
	}
	if (*got)[0].offset != f.FrameOffset {
		t.Fatalf("reply offset = %d, want %d", (*got)[0].offset, f.FrameOffset)
	}
}

func TestChallengeRedirectsUnsolvedRequest(t *testing.T) {
	r, _, got, _ := newTestResponder(t)
	f := challengeFrame(0x18, 1000, 5000,
		"GET /admin?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	r.handle(f)
	if len(*got) != 1 {
		t.Fatalf("replies = %d, want 1", len(*got))
	}
	flags, _, _, body := parseReply(t, (*got)[0].data)
	if flags&0x11 != 0x11 {
		t.Fatalf("flags = %#x, want FIN-ACK", flags)
	}
	if !strings.HasPrefix(body, "HTTP/1.1 307") {
		t.Fatalf("reply = %q, want 307", firstLine(body))
	}
	if !strings.Contains(body, "Location: /.xsight-challenge?t=") {
		t.Fatalf("307 drops the minted token: %q", firstLine(body))
	}
	if !strings.Contains(body, "&n=%2Fadmin%3Fx%3D1") {
		t.Fatalf("307 does not carry the original target: %q", body)
	}
}

func TestChallengeServesPageWithToken(t *testing.T) {
	r, _, got, _ := newTestResponder(t)
	f := challengeFrame(0x18, 2000, 6000,
		"GET /.xsight-challenge?t=deadbeef&n=/admin HTTP/1.1\r\nHost: example.com\r\n\r\n")
	r.handle(f)
	if len(*got) != 1 {
		t.Fatalf("replies = %d, want 1", len(*got))
	}
	_, _, _, body := parseReply(t, (*got)[0].data)
	if !strings.HasPrefix(body, "HTTP/1.1 200") {
		t.Fatalf("page reply = %q, want 200", firstLine(body))
	}
	if !strings.Contains(body, "deadbeef") || !strings.Contains(body, "xsight_pow=") {
		t.Fatalf("page must carry the token and PoW submit: %s", body)
	}
	if !strings.Contains(body, "'t='+encodeURIComponent(token)") {
		t.Fatalf("page navigation drops the token: %s", body)
	}
}

func TestChallengeAdmitsSolvedClient(t *testing.T) {
	r, issuer, got, admitted := newTestResponder(t)

	// Mint a token and search a valid PoW nonce with the same byte
	// representation the page uses.
	token, _ := issuer.Mint("203.0.113.5", time.Unix(1_700_000_000, 0))
	var nonce string
	for n := 0; n < 200000; n++ {
		cand := fmt.Sprintf("%02x", n)
		if issuer.VerifyPoW(token, cand) {
			nonce = cand
			break
		}
	}
	if nonce == "" {
		t.Fatal("no PoW nonce found for 8-bit target")
	}

	f := challengeFrame(0x18, 3000, 7000,
		"GET /admin?a=1&t="+token+"&xsight_pow="+nonce+" HTTP/1.1\r\nHost: example.com\r\n\r\n")
	r.handle(f)
	if *admitted != 1 {
		t.Fatalf("admitted = %d, want 1 (solved client)", *admitted)
	}
	_, _, _, body := parseReply(t, (*got)[len(*got)-1].data)
	if !strings.HasPrefix(body, "HTTP/1.1 307") {
		t.Fatalf("solved reply = %q, want 307", firstLine(body))
	}
	if !strings.Contains(body, "Location: /admin?a=1\r\n") {
		t.Fatalf("solved 307 must send the client to the original target: %q", body)
	}

	// The token is single-use: replaying the solved request re-challenges
	// instead of admitting again.
	before := *admitted
	r.handle(f)
	if *admitted != before {
		t.Fatalf("replay admitted again (%d)", *admitted)
	}
	replay := (*got)[len(*got)-1].data
	if !strings.Contains(string(replay), "HTTP/1.1 307") {
		t.Fatal("replay must be re-challenged")
	}
}

func TestChallengeIgnoresNonHTTPAndPureAcks(t *testing.T) {
	r, _, got, _ := newTestResponder(t)
	r.handle(challengeFrame(0x10, 1, 1, "")) // pure ACK
	r.handle(challengeFrame(0x18, 1, 1, "SSH-2.0-OpenSSH\r\n"))
	if len(*got) != 0 {
		t.Fatalf("replies = %d, want 0 for non-HTTP traffic", len(*got))
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\r'); i >= 0 {
		return s[:i]
	}
	return s
}
