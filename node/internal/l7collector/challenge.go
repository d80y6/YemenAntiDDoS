// Anti-bot challenge generation for HTTP Layer-7 mitigation.
//
// Unverified clients hitting an attacked destination receive an automated
// HTTP 307 redirect to a challenge endpoint carrying a signed token. The
// challenge page runs a small proof-of-work snippet and re-submits the
// original request with the solved token; subsequent requests bearing a
// valid token are admitted by the inline data plane (validated_clients).
//
// Tokens are HMAC-SHA256 signed with the node's cookie secret seed, carry
// an expiry, and are single-use from the responder's perspective.

package l7collector

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ChallengeConfig controls token issuance and validation.
type ChallengeConfig struct {
	Enabled     bool
	Secret      []byte        // HMAC seed (defaults to a random per-boot key)
	TokenTTL    time.Duration // default 10m
	RedirectTo  string        // challenge endpoint path, default "/.xsight-challenge"
	POWDiffBits int           // leading zero bits required, default 12
}

// DefaultChallengeConfig returns production-safe defaults.
func DefaultChallengeConfig() ChallengeConfig {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return ChallengeConfig{
		Enabled:     true,
		Secret:      secret,
		TokenTTL:    10 * time.Minute,
		RedirectTo:  "/.xsight-challenge",
		POWDiffBits: 12,
	}
}

func (c ChallengeConfig) normalize() ChallengeConfig {
	d := DefaultChallengeConfig()
	if c.TokenTTL <= 0 {
		c.TokenTTL = d.TokenTTL
	}
	if c.RedirectTo == "" {
		c.RedirectTo = d.RedirectTo
	}
	if c.POWDiffBits <= 0 {
		c.POWDiffBits = d.POWDiffBits
	}
	if len(c.Secret) == 0 {
		c.Secret = d.Secret
	}
	return c
}

// ChallengeIssuer mints and validates PoW challenge tokens.
type ChallengeIssuer struct {
	cfg ChallengeConfig

	mu      sync.Mutex
	issued  map[string]time.Time // token → expiry (single-use tracking)
	maxLive int
}

// NewChallengeIssuer builds an issuer. A zero config enables defaults.
func NewChallengeIssuer(cfg ChallengeConfig) *ChallengeIssuer {
	cfg = cfg.normalize()
	return &ChallengeIssuer{
		cfg:     cfg,
		issued:  make(map[string]time.Time),
		maxLive: 65536,
	}
}

// Enabled reports whether challenges are active.
func (ci *ChallengeIssuer) Enabled() bool { return ci != nil && ci.cfg.Enabled }

// Mint creates a signed token binding a client IP to an expiry. Returns the
// token (hex) and the challenge URL for the 307 Location header.
func (ci *ChallengeIssuer) Mint(clientIP string, now time.Time) (token, location string) {
	if !ci.Enabled() {
		return "", ""
	}
	exp := uint64(now.Add(ci.cfg.TokenTTL).Unix())
	nonce := make([]byte, 8)
	_, _ = rand.Read(nonce)

	payload := make([]byte, 0, 8+len(nonce)+len(clientIP))
	var expB [8]byte
	binary.BigEndian.PutUint64(expB[:], exp)
	payload = append(payload, expB[:]...)
	payload = append(payload, nonce...)
	payload = append(payload, clientIP...)

	mac := hmac.New(sha256.New, ci.cfg.Secret)
	mac.Write(payload)
	sig := mac.Sum(nil)[:12]

	raw := append(payload, sig...)
	token = hex.EncodeToString(raw)
	ci.track(token, now)
	location = fmt.Sprintf("%s?t=%s&r=%s", ci.cfg.RedirectTo, url.QueryEscape(token),
		url.QueryEscape(base64Path(clientIP)))
	return token, location
}

// track records issued tokens for single-use enforcement with a bounded map.
func (ci *ChallengeIssuer) track(token string, now time.Time) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	if len(ci.issued) >= ci.maxLive {
		// Evict expired entries first, then oldest by expiry.
		for t, exp := range ci.issued {
			if exp.Before(now) {
				delete(ci.issued, t)
			}
		}
	}
	if len(ci.issued) >= ci.maxLive {
		for t := range ci.issued {
			delete(ci.issued, t)
			if len(ci.issued) < ci.maxLive {
				break
			}
		}
	}
	ci.issued[token] = now.Add(ci.cfg.TokenTTL)
}

// Validate checks a presented token: signature, freshness, single-use.
func (ci *ChallengeIssuer) Validate(token, clientIP string, now time.Time) bool {
	if !ci.Enabled() || token == "" {
		return false
	}
	raw, err := hex.DecodeString(token)
	if err != nil || len(raw) < 8+8+12 {
		return false
	}
	payload := raw[:len(raw)-12]
	sig := raw[len(raw)-12:]

	mac := hmac.New(sha256.New, ci.cfg.Secret)
	mac.Write(payload)
	want := mac.Sum(nil)[:12]
	if !hmac.Equal(sig, want) {
		return false
	}

	exp := binary.BigEndian.Uint64(payload[0:8])
	if now.After(time.Unix(int64(exp), 0)) {
		return false
	}
	_ = clientIP // IP binding is advisory (NAT clients share IPs)

	ci.mu.Lock()
	defer ci.mu.Unlock()
	expAt, ok := ci.issued[token]
	if !ok || expAt.Before(now) {
		return false // never issued by us, or already consumed/expired
	}
	delete(ci.issued, token) // single use
	return true
}

// VerifyPoW checks a client's proof-of-work solution: sha256(token || nonce)
// must start with POWDiffBits zero bits.
func (ci *ChallengeIssuer) VerifyPoW(token, nonceHex string) bool {
	if !ci.Enabled() {
		return true
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) == 0 || len(nonce) > 8 {
		return false
	}
	sum := sha256.Sum256(append([]byte(token), nonce...))
	return leadingZeroBits(sum[:]) >= ci.cfg.POWDiffBits
}

func leadingZeroBits(b []byte) int {
	n := 0
	for _, v := range b {
		if v == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if v&(1<<uint(bit)) != 0 {
				return n
			}
			n++
		}
	}
	return n
}

// RenderChallenge307 builds the full HTTP 307 redirect response directing
// the client to the PoW challenge page. Body stays empty per 307 semantics.
func RenderChallenge307(location string) []byte {
	var b strings.Builder
	b.WriteString("HTTP/1.1 307 Temporary Redirect\r\n")
	b.WriteString("Server: xSight-Challenge\r\n")
	b.WriteString("Cache-Control: no-store\r\n")
	b.WriteString("Connection: close\r\n")
	fmt.Fprintf(&b, "Location: %s\r\n", location)
	fmt.Fprintf(&b, "Content-Length: 0\r\n\r\n")
	return []byte(b.String())
}

// RenderChallengePage builds the JS proof-of-work challenge page served at
// the redirect target. Solving recomputes the original request automatically.
func RenderChallengePage(token string, powBits int, next string) []byte {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	b.WriteString("Server: xSight-Challenge\r\n")
	b.WriteString("Cache-Control: no-store\r\n")
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	b.WriteString("Connection: close\r\n")
	body := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Checking your browser</title></head>
<body><p>Verifying you are human. This may take a moment.</p>
<script>
(async function(){
  const token=%q, bits=%d, next=%q;
  const enc=new TextEncoder();
  function zeros(u8){let n=0;for(const b of u8){if(b===0){n+=8;continue;}
    for(let i=7;i>=0;i--){if(b&(1<<i))return n;n++;}}return n;}
  let n=0;
  for(;;n++){
    const nonce=hex(n);
    const data=enc.encode(token+nonce);
    const digest=await crypto.subtle.digest('SHA-256',data);
    if(zeros(new Uint8Array(digest))>=bits){
      const sep=next.includes('?')?'&':'?';
      location.replace(next+sep+'xsight_pow='+encodeURIComponent(nonce));
      return;
    }
  }
  function hex(v){return v.toString(16).padStart(2,'0');}
})();
</script></body></html>`, token, powBits, next)
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.WriteString(body)
	return []byte(b.String())
}

// base64Path renders an IP in a URL-safe compact form (hex) for the redirect.
func base64Path(ip string) string {
	return hex.EncodeToString([]byte(ip))
}
