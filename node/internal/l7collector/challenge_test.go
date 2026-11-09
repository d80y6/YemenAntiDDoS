package l7collector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testIssuer(t *testing.T, ttl time.Duration, bits int) *ChallengeIssuer {
	t.Helper()
	return NewChallengeIssuer(ChallengeConfig{
		Enabled:     true,
		Secret:      []byte("0123456789abcdef0123456789abcdef"),
		TokenTTL:    ttl,
		RedirectTo:  "/challenge",
		POWDiffBits: bits,
	})
}

func TestMintValidateSingleUse(t *testing.T) {
	ci := testIssuer(t, 10*time.Minute, 8)
	now := time.Unix(1_700_000_000, 0)
	token, location := ci.Mint("203.0.113.5", now)
	if token == "" || location == "" {
		t.Fatal("enabled issuer must mint a token and location")
	}
	if !strings.HasPrefix(location, "/challenge?t=") {
		t.Fatalf("location = %q, want challenge path with token", location)
	}
	if !ci.Validate(token, "203.0.113.5", now.Add(time.Second)) {
		t.Fatal("fresh token rejected")
	}
	if ci.Validate(token, "203.0.113.5", now.Add(2*time.Second)) {
		t.Fatal("token must be single-use")
	}
}

func TestValidateRejectsExpiredAndTampered(t *testing.T) {
	ci := testIssuer(t, time.Minute, 8)
	now := time.Unix(1_700_000_000, 0)
	token, _ := ci.Mint("203.0.113.5", now)

	if ci.Validate(token, "203.0.113.5", now.Add(2*time.Minute)) {
		t.Fatal("expired token accepted")
	}

	raw, err := hex.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xff
	if ci.Validate(hex.EncodeToString(raw), "203.0.113.5", now) {
		t.Fatal("tampered signature accepted")
	}

	other := NewChallengeIssuer(ChallengeConfig{
		Enabled: true, Secret: []byte("another-secret"), TokenTTL: time.Minute,
	})
	fresh, _ := other.Mint("203.0.113.5", now)
	if ci.Validate(fresh, "203.0.113.5", now) {
		t.Fatal("token signed by a different secret accepted")
	}

	if ci.Validate("", "203.0.113.5", now) {
		t.Fatal("empty token accepted")
	}
	if ci.Validate("zzzz", "203.0.113.5", now) {
		t.Fatal("non-hex token accepted")
	}
}

func TestDisabledIssuer(t *testing.T) {
	ci := NewChallengeIssuer(ChallengeConfig{Enabled: false})
	if ci.Enabled() {
		t.Fatal("disabled issuer reports enabled")
	}
	if token, location := ci.Mint("203.0.113.5", time.Now()); token != "" || location != "" {
		t.Fatal("disabled issuer must not mint")
	}
	if !ci.Validate("anything", "203.0.113.5", time.Now()) {
		// Validate returns false when disabled (no admission through this path).
		return
	}
	t.Fatal("disabled issuer must not validate tokens")
}

func TestVerifyPoW(t *testing.T) {
	ci := testIssuer(t, time.Minute, 8)
	now := time.Unix(1_700_000_000, 0)
	token, _ := ci.Mint("203.0.113.5", now)

	var nonce string
	found := false
	for n := 0; n < 100000; n++ {
		candidate := hex.EncodeToString([]byte{byte(n >> 8), byte(n)})
		if ci.VerifyPoW(token, candidate) {
			nonce, found = candidate, true
			break
		}
	}
	if !found {
		t.Fatal("no PoW solution found within the search budget")
	}
	if !ci.VerifyPoW(token, nonce) {
		t.Fatal("valid PoW solution rejected")
	}
	if ci.VerifyPoW(token, "") || ci.VerifyPoW(token, "zz") {
		t.Fatal("malformed nonce accepted")
	}
	if ci.VerifyPoW(token, strings.Repeat("0", 20)) {
		t.Fatal("oversized nonce accepted")
	}

	// A harder target must reject the easy solution.
	strict := testIssuer(t, time.Minute, 24)
	strictToken, _ := strict.Mint("203.0.113.5", now)
	if strict.VerifyPoW(strictToken, nonce) {
		t.Fatal("8-bit solution must not satisfy a 24-bit target")
	}
}

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		b    []byte
		want int
	}{
		{[]byte{0xff}, 0},
		{[]byte{0x00, 0xff}, 8},
		{[]byte{0x0f}, 4},
		{[]byte{0x00, 0x01}, 15},
		{[]byte{0x00, 0x00}, 16},
	}
	for _, c := range cases {
		if got := leadingZeroBits(c.b); got != c.want {
			t.Errorf("leadingZeroBits(%x) = %d, want %d", c.b, got, c.want)
		}
	}
}

func TestRenderChallenge307(t *testing.T) {
	out := string(RenderChallenge307("/challenge?t=abc"))
	for _, want := range []string{
		"HTTP/1.1 307 Temporary Redirect\r\n",
		"Location: /challenge?t=abc\r\n",
		"Cache-Control: no-store\r\n",
		"Content-Length: 0\r\n\r\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("307 response missing %q:\n%s", want, out)
		}
	}
}

func TestRenderChallengePage(t *testing.T) {
	page := string(RenderChallengePage("deadbeef", 12, "/admin?x=1"))
	if !strings.HasPrefix(page, "HTTP/1.1 200 OK\r\n") {
		t.Fatal("challenge page must be a 200 response")
	}
	if !strings.Contains(page, "Content-Type: text/html; charset=utf-8") {
		t.Fatal("challenge page must be HTML")
	}
	if !strings.Contains(page, `deadbeef`) || !strings.Contains(page, `bits=12`) {
		t.Fatal("challenge page must embed the token and difficulty")
	}
	if !strings.Contains(page, "xsight_pow=") {
		t.Fatal("challenge page must submit the PoW nonce")
	}
	if strings.Contains(page, "%!") {
		t.Fatal("challenge page has a formatting error")
	}
}

func TestBase64Path(t *testing.T) {
	if got := base64Path("1.2.3.4"); got != hex.EncodeToString([]byte("1.2.3.4")) {
		t.Fatalf("base64Path = %q", got)
	}
}

// TestTrackEvictionOrder pins the bounded-map behavior under Mint floods:
// a single source can never hold more than maxTokensPerIP live slots, the
// soonest-expiring token goes first when the table is full (never a random
// one), and the most recently minted token always survives — a client that
// was just challenged must not lose its token before it can solve.
func TestTrackEvictionOrder(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	// Per-IP cap: one IP minting far more than its quota keeps exactly the
	// cap live, and its freshest token survives.
	perIP := testIssuer(t, time.Hour, 8)
	perIP.maxLive = 4 * maxTokensPerIP
	var lastTok string
	for i := 0; i < maxTokensPerIP+10; i++ {
		lastTok, _ = perIP.Mint("203.0.113.5", now)
	}
	if len(perIP.issued) != maxTokensPerIP {
		t.Fatalf("live tokens = %d, want per-IP cap %d", len(perIP.issued), maxTokensPerIP)
	}
	if _, ok := perIP.issued[lastTok]; !ok {
		t.Fatal("most recently minted token was evicted")
	}

	// Global cap: a second IP squeezes the table down to maxLive, evicting
	// the soonest-expiring tokens first until the newcomer's oldest tokens
	// are all that is left.
	global := testIssuer(t, time.Hour, 8)
	global.maxLive = 4
	for i := 0; i < 5; i++ {
		global.Mint("203.0.113.5", now)
	}
	for i := 0; i < 5; i++ {
		lastTok, _ = global.Mint("198.51.100.9", now)
	}
	if len(global.issued) > global.maxLive {
		t.Fatalf("live tokens = %d, exceed maxLive %d", len(global.issued), global.maxLive)
	}
	if _, ok := global.issued[lastTok]; !ok {
		t.Fatal("fresh token evicted despite free capacity accounting")
	}
	if got := global.perIP["198.51.100.9"]; got != 4 {
		t.Fatalf("second IP holds %d live tokens, want the full table", got)
	}
	if got := global.perIP["203.0.113.5"]; got != 0 {
		t.Fatalf("first IP retains %d live tokens after being fully evicted", got)
	}
}

func TestPoWAgreesWithJSRepresentation(t *testing.T) {
	// The challenge page hashes ASCII(token + nonceHex) with WebCrypto; Go
	// must hash the exact same bytes or no solution ever validates.
	ci := testIssuer(t, time.Minute, 8)
	token := "cafebabe00112233"
	solutions := 0
	for n := 0; n < 5000; n++ {
		nonceHex := fmt.Sprintf("%02x", n)
		sum := sha256.Sum256([]byte(token + nonceHex))
		jsOK := leadingZeroBits(sum[:]) >= 8
		goOK := ci.VerifyPoW(token, nonceHex)
		if jsOK != goOK {
			t.Fatalf("PoW disagreement at nonce %q: js=%v go=%v (JS hashes ASCII token+nonceHex)",
				nonceHex, jsOK, goOK)
		}
		if jsOK {
			solutions++
		}
	}
	if solutions == 0 {
		t.Fatal("no solution found: 8-bit target must hit within 5000 tries")
	}
}

func TestChallengePageCarriesToken(t *testing.T) {
	page := string(RenderChallengePage("deadbeef", 12, "/admin?x=1"))
	// The solved navigation must resubmit the token; otherwise Validate can
	// never see it on the follow-up request.
	if !strings.Contains(page, `'t='+encodeURIComponent(token)`) {
		t.Fatalf("challenge page navigation drops the token:\n%s", page)
	}
	if !strings.Contains(page, `xsight_pow=`) {
		t.Fatal("challenge page navigation drops the PoW nonce")
	}
}
