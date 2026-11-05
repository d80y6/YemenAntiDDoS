// Package l7collector turns per-packet Layer 7 evidence into the bounded,
// per-second aggregates that the Controller consumes over CriticalEventStream.
//
// It is deliberately stateless with respect to the capture loop: the hot path
// only calls Observe, while a single ticker goroutine calls Tick. All state is
// mutex-protected and every map is bounded, so a spoofed destination flood
// cannot grow memory without limit.
package l7collector

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d80y6/YemenDDoS/shared/l7"
)

// Config controls collection and when an event is emitted.
type Config struct {
	Enabled          bool
	Window           time.Duration // aggregation window, defaults to 1s
	HTTPRPS          uint64        // requests/s per destination before http_flood
	TLSHSPS          uint64        // ClientHellos/s per destination before tls_anomaly
	SlowlorisConns   uint64        // incomplete connections per destination
	MaxTracked       int           // distinct destinations kept in memory
	MaxFlows         int           // distinct Slowloris connections kept
	MaxOpenFragments int           // fragments before a connection is Slowloris
}

// DefaultConfig returns conservative 10Gbps-safe defaults. Thresholds are
// intentionally higher than a normal web tier so that only real floods fire.
func DefaultConfig() Config {
	return Config{
		Enabled:          true,
		Window:           time.Second,
		HTTPRPS:          2000,
		TLSHSPS:          1000,
		SlowlorisConns:   50,
		MaxTracked:       4096,
		MaxFlows:         65536,
		MaxOpenFragments: 20,
	}
}

func (c Config) normalize() Config {
	d := DefaultConfig()
	if c.Window <= 0 {
		c.Window = d.Window
	}
	if c.HTTPRPS == 0 {
		c.HTTPRPS = d.HTTPRPS
	}
	if c.TLSHSPS == 0 {
		c.TLSHSPS = d.TLSHSPS
	}
	if c.SlowlorisConns == 0 {
		c.SlowlorisConns = d.SlowlorisConns
	}
	if c.MaxTracked <= 0 {
		c.MaxTracked = d.MaxTracked
	}
	if c.MaxFlows <= 0 {
		c.MaxFlows = d.MaxFlows
	}
	if c.MaxOpenFragments <= 0 {
		c.MaxOpenFragments = d.MaxOpenFragments
	}
	return c
}

// Event is one threshold crossing for a protected destination.
type Event struct {
	Type     string
	SrcIP    net.IP
	DstIP    net.IP
	Counters map[string]uint64
	At       time.Time
}

// Stats exposes collection health for the node health line.
type Stats struct {
	Samples      uint64 `json:"samples"`
	HTTP         uint64 `json:"http"`
	TLS          uint64 `json:"tls"`
	Slowloris    uint64 `json:"slowloris"`
	Events       uint64 `json:"events"`
	Dropped      uint64 `json:"dropped"`
	TrackedDsts  int    `json:"tracked_destinations"`
	TrackedFlows int    `json:"tracked_flows"`
}

type bucket struct {
	http, tls, slow uint64
	uniqueSrc       map[string]struct{}
	methods         map[string]uint64
	paths           map[string]uint64
	snis            map[string]uint64
	sniMissing      uint64
	slowSrcs        map[string]struct{}

	// v4.0 anti-bot evidence: fingerprint + User-Agent distributions.
	ja3s map[string]uint64
	ja4s map[string]uint64
	uas  map[string]uint64
}

type slowEntry struct {
	state    l7.SlowlorisState
	lastSeen time.Time
	flagged  bool
}

// Collector aggregates L7 evidence. Safe for concurrent Observe/Tick.
type Collector struct {
	cfg Config

	mu      sync.Mutex
	buckets map[string]*bucket
	slow    map[string]*slowEntry

	samples   atomic.Uint64
	httpCount atomic.Uint64
	tlsCount  atomic.Uint64
	slowCount atomic.Uint64
	events    atomic.Uint64
	dropped   atomic.Uint64
}

// New builds a Collector. A zero Config yields DefaultConfig.
func New(cfg Config) *Collector {
	cfg = cfg.normalize()
	if cfg.Enabled {
		cfg.Enabled = true
	}
	return &Collector{
		cfg:     cfg,
		buckets: make(map[string]*bucket),
		slow:    make(map[string]*slowEntry),
	}
}

// Enabled reports whether collection is active.
func (c *Collector) Enabled() bool { return c != nil && c.cfg.Enabled }

func newBucket() *bucket {
	return &bucket{
		uniqueSrc: make(map[string]struct{}),
		methods:   make(map[string]uint64),
		paths:     make(map[string]uint64),
		snis:      make(map[string]uint64),
		slowSrcs:  make(map[string]struct{}),
		ja3s:      make(map[string]uint64),
		ja4s:      make(map[string]uint64),
		uas:       make(map[string]uint64),
	}
}

func bump(m map[string]uint64, key string, limit int) {
	if key == "" {
		return
	}
	if _, ok := m[key]; !ok && len(m) >= limit {
		return
	}
	m[key]++
}

func httpPort(p uint16) bool {
	switch p {
	case 80, 8000, 8008, 8080, 8081, 8888, 3128:
		return true
	}
	return false
}

func tlsPort(p uint16) bool {
	switch p {
	case 443, 8443, 9443:
		return true
	}
	return false
}

func looksHTTP(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	switch string(payload[:4]) {
	case "GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "PATC", "CONN", "TRAC":
		return true
	}
	return false
}

// Observe records one TCP payload. Non-TCP and empty payloads are ignored.
func (c *Collector) Observe(srcIP, dstIP net.IP, srcPort, dstPort uint16, tcpFlags uint8, payload []byte, at time.Time) {
	if !c.Enabled() || dstIP == nil || len(payload) == 0 {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	key := dstIP.String()
	src := srcIP.String()

	isHTTP := httpPort(dstPort) || looksHTTP(payload)
	isTLS := tlsPort(dstPort) || payload[0] == 0x16

	var req l7.HTTPRequest
	var reqOK bool
	var userAgent string
	if isHTTP {
		req, reqOK = l7.ParseHTTPRequest(payload)
		userAgent = extractUserAgent(payload)
	}
	var hello l7.TLSHandshake
	var helloOK bool
	if isTLS {
		hello, helloOK = l7.ParseTLSClientHelloFull(payload)
	}
	if !reqOK && !helloOK {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	b, ok := c.buckets[key]
	if !ok {
		if len(c.buckets) >= c.cfg.MaxTracked {
			c.dropped.Add(1)
			return
		}
		b = newBucket()
		c.buckets[key] = b
	}
	b.uniqueSrc[src] = struct{}{}
	c.samples.Add(1)

	if reqOK {
		b.http++
		c.httpCount.Add(1)
		bump(b.methods, req.Method, 8)
		bump(b.paths, req.Path, 8)
		bump(b.uas, userAgent, 16)
		if !req.HeaderComplete {
			c.observeSlow(src, key, dstPort, payload, at, b)
		}
	}
	if helloOK {
		b.tls++
		c.tlsCount.Add(1)
		if _, ja3 := hello.JA3(); ja3 != "" {
			bump(b.ja3s, ja3, 16)
		}
		if ja4 := hello.JA4(); ja4 != "" {
			bump(b.ja4s, ja4, 16)
		}
		if hello.SNI == "" {
			b.sniMissing++
		} else {
			bump(b.snis, hello.SNI, 8)
		}
	}
}

// extractUserAgent pulls the User-Agent header value from an HTTP request
// prefix. Returns "" when absent or the header is incomplete.
func extractUserAgent(payload []byte) string {
	head := payload
	if i := bytes.Index(head, []byte("\r\n\r\n")); i >= 0 {
		head = head[:i]
	}
	for _, line := range strings.Split(string(head), "\r\n") {
		if len(line) > 12 && strings.EqualFold(line[:11], "user-agent:") {
			return strings.TrimSpace(line[11:])
		}
	}
	return ""
}

// observeSlow must be called with c.mu held.
func (c *Collector) observeSlow(src, dst string, dstPort uint16, payload []byte, at time.Time, b *bucket) {
	key := fmt.Sprintf("%s|%s|%d", src, dst, dstPort)
	e, ok := c.slow[key]
	if !ok {
		if len(c.slow) >= c.cfg.MaxFlows {
			c.evictSlowLocked(at)
			if len(c.slow) >= c.cfg.MaxFlows {
				c.dropped.Add(1)
				return
			}
		}
		e = &slowEntry{}
		c.slow[key] = e
	}
	e.lastSeen = at
	if e.state.Observe(payload, c.cfg.MaxOpenFragments) && !e.flagged {
		e.flagged = true
		b.slow++
		b.slowSrcs[src] = struct{}{}
		c.slowCount.Add(1)
	}
}

// evictSlowLocked drops connections idle for more than 30s, then the oldest
// half if the map is still full. c.mu must be held.
func (c *Collector) evictSlowLocked(now time.Time) {
	for k, e := range c.slow {
		if now.Sub(e.lastSeen) > 30*time.Second {
			delete(c.slow, k)
		}
	}
	if len(c.slow) < c.cfg.MaxFlows {
		return
	}
	type aged struct {
		key string
		at  time.Time
	}
	list := make([]aged, 0, len(c.slow))
	for k, e := range c.slow {
		list = append(list, aged{k, e.lastSeen})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
	for i := 0; i < len(list)/2; i++ {
		delete(c.slow, list[i].key)
	}
}

// Tick closes the current window and returns any threshold crossings. The
// caller forwards the events and calls Tick again after cfg.Window.
func (c *Collector) Tick(now time.Time) []Event {
	if !c.Enabled() {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	window := c.cfg.Window.Seconds()
	if window <= 0 {
		window = 1
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var out []Event
	for key, b := range c.buckets {
		ip := net.ParseIP(key)
		var counters map[string]uint64
		ensure := func() map[string]uint64 {
			if counters == nil {
				counters = make(map[string]uint64)
			}
			return counters
		}
		if b.http > 0 {
			rps := uint64(float64(b.http) / window)
			if rps >= c.cfg.HTTPRPS {
				m := ensure()
				m["http_requests"] = b.http
				m["http_rps"] = rps
				m["http_unique_sources"] = uint64(len(b.uniqueSrc))
				addDetails(m, "http_method:", b.methods)
				addDetails(m, "http_path:", b.paths)
			}
		}
		if b.tls > 0 {
			hsps := uint64(float64(b.tls) / window)
			m := ensure()
			// v4.0: fingerprint distributions flow to the Controller in every
			// TLS event so the Console can chart JA3/JA4 without a new stream.
			addDetails(m, "tls_ja3:", b.ja3s)
			addDetails(m, "tls_ja4:", b.ja4s)
			if hsps >= c.cfg.TLSHSPS || b.sniMissing >= c.cfg.TLSHSPS {
				m["tls_handshakes"] = b.tls
				m["tls_hsps"] = hsps
				m["tls_unique_sources"] = uint64(len(b.uniqueSrc))
				m["tls_sni_missing"] = b.sniMissing
				addDetails(m, "tls_sni:", b.snis)
			}
		}
		if len(b.uas) > 0 {
			m := ensure()
			addDetails(m, "http_ua:", b.uas)
		}
		if b.slow > 0 && b.slow >= c.cfg.SlowlorisConns {
			m := ensure()
			m["slowloris_conns"] = b.slow
			m["slowloris_sources"] = uint64(len(b.slowSrcs))
			for src := range b.slowSrcs {
				if len(m) > 64 {
					break
				}
				m["src:"+src] = 1
			}
		}
		if counters == nil {
			continue
		}
		evType := l7.DecoderHTTPFlood
		if b.tls > 0 && (uint64(float64(b.tls)/window) >= c.cfg.TLSHSPS || b.sniMissing >= c.cfg.TLSHSPS) {
			evType = l7.DecoderTLSAnomaly
		} else if b.slow > 0 && b.slow >= c.cfg.SlowlorisConns {
			evType = l7.DecoderSlowloris
		}
		out = append(out, Event{Type: evType, DstIP: ip, Counters: counters, At: now})
		c.events.Add(1)
	}

	c.buckets = make(map[string]*bucket)
	for k, e := range c.slow {
		if now.Sub(e.lastSeen) > 30*time.Second {
			delete(c.slow, k)
		}
	}
	return out
}

func addDetails(m map[string]uint64, prefix string, values map[string]uint64) {
	if len(values) == 0 {
		return
	}
	type kv struct {
		k string
		v uint64
	}
	list := make([]kv, 0, len(values))
	for k, v := range values {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	for i, item := range list {
		if i >= 5 {
			break
		}
		m[prefix+item.k] = item.v
	}
}

// Stats returns a consistent snapshot of collector counters.
func (c *Collector) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	c.mu.Lock()
	dst, flows := len(c.buckets), len(c.slow)
	c.mu.Unlock()
	return Stats{
		Samples:      c.samples.Load(),
		HTTP:         c.httpCount.Load(),
		TLS:          c.tlsCount.Load(),
		Slowloris:    c.slowCount.Load(),
		Events:       c.events.Load(),
		Dropped:      c.dropped.Load(),
		TrackedDsts:  dst,
		TrackedFlows: flows,
	}
}
