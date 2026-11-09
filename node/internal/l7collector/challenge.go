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
	"encoding/json"
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
	POWDiffBits int           // leading zero bits required, default 16
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
		POWDiffBits: 16,
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

// maxTokensPerIP bounds the live tokens a single source can hold: a Mint
// flood from one IP evicts its own oldest tokens instead of starving every
// other client (including NAT users sharing that IP).
const maxTokensPerIP = 32

// issuedToken is one live, single-use token: when it expires, who holds it,
// and its mint sequence (tie-breaker so equal expiries evict oldest-first
// instead of whatever map iteration finds first).
type issuedToken struct {
	exp time.Time
	ip  string
	seq uint64
}

// ChallengeIssuer mints and validates PoW challenge tokens.
type ChallengeIssuer struct {
	cfg ChallengeConfig

	mu      sync.Mutex
	issued  map[string]issuedToken // token → expiry + source (single-use tracking)
	perIP   map[string]int         // source IP → live token count
	maxLive int
	nextSeq uint64 // mint sequence for eviction tie-breaking
}

// NewChallengeIssuer builds an issuer. A zero config enables defaults.
func NewChallengeIssuer(cfg ChallengeConfig) *ChallengeIssuer {
	cfg = cfg.normalize()
	return &ChallengeIssuer{
		cfg:     cfg,
		issued:  make(map[string]issuedToken),
		perIP:   make(map[string]int),
		maxLive: 65536,
	}
}

// Enabled reports whether challenges are active.
func (ci *ChallengeIssuer) Enabled() bool { return ci != nil && ci.cfg.Enabled }

// Path is the endpoint the HTTP 307 redirects to (where the page is served).
func (ci *ChallengeIssuer) Path() string {
	if ci == nil {
		return ""
	}
	return ci.cfg.RedirectTo
}

// POWBits is the leading-zero-bit target the challenge page must solve.
func (ci *ChallengeIssuer) POWBits() int {
	if ci == nil {
		return 0
	}
	return ci.cfg.POWDiffBits
}

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
	ci.track(token, clientIP, now)
	location = fmt.Sprintf("%s?t=%s&r=%s", ci.cfg.RedirectTo, url.QueryEscape(token),
		url.QueryEscape(base64Path(clientIP)))
	return token, location
}

// track records issued tokens for single-use enforcement with a bounded map.
// Eviction priority: expired entries first, then the caller's own
// soonest-expiring token once it is over its per-IP quota, then — when the
// table is full — the soonest-expiring token overall. Never random: the
// newest tokens (the clients actively solving right now) survive.
func (ci *ChallengeIssuer) track(token, clientIP string, now time.Time) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	for {
		victim := ci.pickVictim(clientIP, now)
		if victim == "" {
			break
		}
		ci.removeLocked(victim)
	}
	ci.nextSeq++
	ci.issued[token] = issuedToken{exp: now.Add(ci.cfg.TokenTTL), ip: clientIP, seq: ci.nextSeq}
	ci.perIP[clientIP]++
}

// pickVictim returns the token to evict before inserting another one for
// clientIP, or "" when nothing needs evicting.
func (ci *ChallengeIssuer) pickVictim(clientIP string, now time.Time) string {
	for t, e := range ci.issued {
		if !e.exp.After(now) {
			return t // expired: always evictable
		}
	}
	if ci.perIP[clientIP] >= maxTokensPerIP {
		return ci.soonestFor(clientIP)
	}
	if len(ci.issued) >= ci.maxLive {
		return ci.soonest()
	}
	return ""
}

// soonest returns the globally soonest-expiring token, breaking expiry ties
// by mint order (oldest inserted evicts first).
func (ci *ChallengeIssuer) soonest() string {
	var victim string
	var best issuedToken
	for t, e := range ci.issued {
		if victim == "" || e.exp.Before(best.exp) ||
			(e.exp.Equal(best.exp) && e.seq < best.seq) {
			victim, best = t, e
		}
	}
	return victim
}

// soonestFor returns the soonest-expiring token held by ip ("" when none).
func (ci *ChallengeIssuer) soonestFor(ip string) string {
	var victim string
	var best issuedToken
	for t, e := range ci.issued {
		if e.ip != ip {
			continue
		}
		if victim == "" || e.exp.Before(best.exp) ||
			(e.exp.Equal(best.exp) && e.seq < best.seq) {
			victim, best = t, e
		}
	}
	return victim
}

// removeLocked deletes a token and its per-IP accounting.
func (ci *ChallengeIssuer) removeLocked(token string) {
	if e, ok := ci.issued[token]; ok {
		delete(ci.issued, token)
		if ci.perIP[e.ip] > 0 {
			ci.perIP[e.ip]--
		}
		if ci.perIP[e.ip] == 0 {
			delete(ci.perIP, e.ip)
		}
	}
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
	e, ok := ci.issued[token]
	if !ok || !e.exp.After(now) {
		return false // never issued by us, or already consumed/expired
	}
	ci.removeLocked(token) // single use
	return true
}

// VerifyPoW checks a client's proof-of-work solution: sha256(token || nonce)
// must start with POWDiffBits zero bits, where both parts are hashed as their
// ASCII text — the exact byte representation the challenge page's WebCrypto
// digest sees (enc.encode(token+nonce)). The hex decode below is format
// validation only.
func (ci *ChallengeIssuer) VerifyPoW(token, nonceHex string) bool {
	if !ci.Enabled() {
		return true
	}
	// Format check only: the page's hex(n) can be odd-length ("100"), which
	// encoding/hex would reject. JS emits lowercase hex; cap at 16 chars (8
	// bytes) to match the historical bound.
	if nonceHex == "" || len(nonceHex) > 16 {
		return false
	}
	for _, ch := range nonceHex {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	sum := sha256.Sum256([]byte(token + nonceHex))
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
//
// token and next are embedded via encoding/json, whose default HTML escaping
// (\u003c, \u003e, \u0026) keeps a literal "</script>" inside the string from
// closing the script element — the values echo client input, so this is the
// injection boundary. Callers should still pre-validate (the responder does).
func RenderChallengePage(token string, powBits int, next string) []byte {
	var b strings.Builder
	b.WriteString("HTTP/1.1 200 OK\r\n")
	b.WriteString("Server: xSight-Challenge\r\n")
	b.WriteString("Cache-Control: no-store\r\n")
	b.WriteString("Content-Type: text/html; charset=utf-8\r\n")
	b.WriteString("Connection: close\r\n")
	tokJS, _ := json.Marshal(token)
	nextJS, _ := json.Marshal(next)
	body := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Checking your browser</title></head>
<body><p>Verifying you are human. This may take a moment.</p>
<script>
(async function(){
  const token=%s, bits=%d, next=%s;
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
      location.replace(next+sep+'t='+encodeURIComponent(token)+'&xsight_pow='+encodeURIComponent(nonce));
      return;
    }
  }
  function hex(v){return v.toString(16).padStart(2,'0');}
})();
</script></body></html>`, tokJS, powBits, nextJS)
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.WriteString(body)
	return []byte(b.String())
}

// base64Path renders an IP in a URL-safe compact form (hex) for the redirect.
func base64Path(ip string) string {
	return hex.EncodeToString([]byte(ip))
}
