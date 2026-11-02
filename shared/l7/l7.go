// Package l7 provides dependency-free Layer 7 inspection helpers for xSight.
//
// The XDP fast path only needs a bounded prefix of each payload, so every
// parser here is total: it never allocates unbounded memory and always reports
// "not enough data" instead of panicking. Detection policy (thresholds, EWMA)
// lives in the controller; this package only extracts evidence.
package l7

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// Decoder names reserved for the application layer. They are intentionally
// distinct from the L3/L4 decoder slots so existing thresholds keep working.
const (
	DecoderHTTPFlood  = "http_flood"
	DecoderTLSAnomaly = "tls_anomaly"
	DecoderSlowloris  = "slowloris"
)

// maxHeaderScan bounds how far into a payload we look for the end of headers.
// A legitimate request that exceeds this is treated as incomplete, which is
// exactly the Slowloris signal we want.
const maxHeaderScan = 8192

// HTTPRequest is the subset of a request line and headers xSight needs.
type HTTPRequest struct {
	Method         string
	Path           string
	Proto          string
	Host           string
	HeaderComplete bool
	ContentLength  int
}

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "HEAD": true, "PUT": true, "DELETE": true,
	"OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
}

// ParseHTTPRequest parses the beginning of an HTTP/1.x request. It returns
// ok=false when the payload does not look like a request line at all.
func ParseHTTPRequest(payload []byte) (HTTPRequest, bool) {
	var req HTTPRequest
	if len(payload) < 8 {
		return req, false
	}
	if len(payload) > maxHeaderScan {
		payload = payload[:maxHeaderScan]
	}
	end := bytes.Index(payload, []byte("\r\n"))
	if end < 0 {
		return req, false
	}
	parts := strings.Fields(string(payload[:end]))
	if len(parts) != 3 {
		return req, false
	}
	if !httpMethods[parts[0]] {
		return req, false
	}
	if !strings.HasPrefix(parts[1], "/") {
		return req, false
	}
	if !strings.HasPrefix(parts[2], "HTTP/1.") {
		return req, false
	}
	req.Method, req.Path, req.Proto = parts[0], parts[1], parts[2]

	rest := payload[end+2:]
	if i := bytes.Index(rest, []byte("\r\n\r\n")); i >= 0 {
		req.HeaderComplete = true
		rest = rest[:i]
	}
	for _, line := range bytes.Split(rest, []byte("\r\n")) {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := strings.ToLower(string(bytes.TrimSpace(line[:colon])))
		value := string(bytes.TrimSpace(line[colon+1:]))
		switch name {
		case "host":
			req.Host = value
		case "content-length":
			if n, err := parseUint(value); err == nil {
				req.ContentLength = n
			}
		}
	}
	return req, true
}

// TLSClientHello is the subset of a ClientHello used for anomaly detection.
type TLSClientHello struct {
	SNI          string
	CipherSuites int
	Version      uint16
	Length       int
}

// ParseTLSClientHello parses a TLS handshake record containing a ClientHello.
// It returns ok=false for anything that is not a well-formed ClientHello.
func ParseTLSClientHello(payload []byte) (TLSClientHello, bool) {
	var hello TLSClientHello
	if len(payload) < 6 {
		return hello, false
	}
	// ContentType handshake (0x16), legacy version major 0x03.
	if payload[0] != 0x16 || payload[1] != 0x03 {
		return hello, false
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen <= 0 || 5+recordLen > len(payload) {
		return hello, false
	}
	body := payload[5 : 5+recordLen]
	hello.Length = recordLen
	if len(body) < 4 || body[0] != 0x01 {
		return hello, false
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hsLen <= 0 || 4+hsLen > len(body) {
		return hello, false
	}
	hs := body[4 : 4+hsLen]
	// legacy_version(2) + random(32)
	if len(hs) < 34 {
		return hello, false
	}
	hello.Version = binary.BigEndian.Uint16(hs[0:2])
	off := 34
	if off >= len(hs) {
		return hello, false
	}
	sidLen := int(hs[off])
	off += 1 + sidLen
	if off+2 > len(hs) {
		return hello, false
	}
	csLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2
	if off+csLen > len(hs) {
		return hello, false
	}
	hello.CipherSuites = csLen / 2
	off += csLen
	if off >= len(hs) {
		return hello, true
	}
	compLen := int(hs[off])
	off += 1 + compLen
	if off+2 > len(hs) {
		return hello, true
	}
	extLen := int(binary.BigEndian.Uint16(hs[off : off+2]))
	off += 2
	end := off + extLen
	if end > len(hs) {
		end = len(hs)
	}
	for off+4 <= end {
		extType := binary.BigEndian.Uint16(hs[off : off+2])
		extSize := int(binary.BigEndian.Uint16(hs[off+2 : off+4]))
		off += 4
		if off+extSize > end {
			break
		}
		if extType == 0x0000 && extSize >= 5 {
			hello.SNI = parseSNI(hs[off : off+extSize])
		}
		off += extSize
	}
	return hello, true
}

func parseSNI(ext []byte) string {
	if len(ext) < 5 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(ext[3:5]))
	if 5+nameLen > len(ext) || nameLen == 0 {
		return ""
	}
	return string(ext[5 : 5+nameLen])
}

// SlowlorisState accumulates per-connection evidence that a peer is opening
// requests without ever completing the header block.
type SlowlorisState struct {
	Opened      int
	Completed   int
	LastPayload int
}

// Observe records one payload fragment. It reports true when the connection
// has sent more than maxOpen fragments without ever completing a header block,
// which is the Slowloris pattern.
func (s *SlowlorisState) Observe(payload []byte, maxOpen int) bool {
	if maxOpen <= 0 {
		maxOpen = 20
	}
	if _, ok := ParseHTTPRequest(payload); ok {
		s.Opened++
		if bytes.Contains(payload, []byte("\r\n\r\n")) {
			s.Completed++
		}
	}
	s.LastPayload = len(payload)
	return s.Completed == 0 && s.Opened > maxOpen
}

// Counter is a fixed-window rate counter keyed by an arbitrary string. It is
// safe for concurrent use because the node and controller both fan out samples.
type Counter struct {
	mu       sync.Mutex
	interval time.Duration
	start    time.Time
	counts   map[string]int
}

// NewCounter returns a Counter whose window rolls every interval.
func NewCounter(interval time.Duration) *Counter {
	if interval <= 0 {
		interval = time.Second
	}
	return &Counter{interval: interval, counts: make(map[string]int)}
}

// Add records n events for key at time now and returns the count inside the
// current window. When now crosses the window boundary the counter resets.
func (c *Counter) Add(key string, n int, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.start.IsZero() || now.Sub(c.start) >= c.interval {
		c.start = now
		c.counts = make(map[string]int)
	}
	c.counts[key] += n
	return c.counts[key]
}

// Rate returns the per-second rate for key in the current window.
func (c *Counter) Rate(key string, now time.Time) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.start.IsZero() || now.Sub(c.start) >= c.interval {
		return 0
	}
	elapsed := now.Sub(c.start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(c.counts[key]) / elapsed
}

func parseUint(s string) (int, error) {
	var n int
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errNotNumber
		}
		n = n*10 + int(s[i]-'0')
		if n > 1<<30 {
			return 0, errNotNumber
		}
	}
	if len(s) == 0 {
		return 0, errNotNumber
	}
	return n, nil
}

type constError string

func (e constError) Error() string { return string(e) }

const errNotNumber = constError("not a number")
