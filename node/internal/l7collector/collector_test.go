package l7collector

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/shared/l7"
)

func httpReq(method, path, host string, complete bool) []byte {
	req := method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n"
	if complete {
		req += "\r\n"
	}
	return []byte(req)
}

func clientHello(sni string) []byte {
	var hs []byte
	hs = append(hs, 0x03, 0x03)
	hs = append(hs, make([]byte, 32)...)
	hs = append(hs, 0)                      // session id length
	hs = append(hs, 0x00, 0x02, 0x13, 0x01) // cipher suites
	hs = append(hs, 0x01, 0x00)             // compression
	var ext []byte
	if sni != "" {
		name := []byte(sni)
		listLen := 3 + len(name)
		body := []byte{byte(listLen >> 8), byte(listLen), 0x00, byte(len(name) >> 8), byte(len(name))}
		body = append(body, name...)
		ext = append(ext, 0x00, 0x00, byte(len(body)>>8), byte(len(body)))
		ext = append(ext, body...)
	}
	hs = append(hs, byte(len(ext)>>8), byte(len(ext)))
	hs = append(hs, ext...)
	handshake := append([]byte{0x01, byte(len(hs) >> 16), byte(len(hs) >> 8), byte(len(hs))}, hs...)
	record := append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	return record
}

func TestHTTPFloodEvent(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HTTPRPS = 100
	cfg.TLSHSPS = 1000
	c := New(cfg)
	dst := net.ParseIP("203.0.113.10")
	src := net.ParseIP("198.51.100.7")
	now := time.Unix(1700000000, 0)
	for i := 0; i < 150; i++ {
		c.Observe(src, dst, 40000, 80, 0x18, httpReq("GET", "/login", "example.com", true), now)
	}
	events := c.Tick(now.Add(time.Second))
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Type != l7.DecoderHTTPFlood {
		t.Fatalf("type = %q", ev.Type)
	}
	if ev.Counters["http_requests"] != 150 || ev.Counters["http_rps"] != 150 {
		t.Fatalf("counters = %v", ev.Counters)
	}
	if ev.Counters["http_path:/login"] != 150 || ev.Counters["http_method:GET"] != 150 {
		t.Fatalf("detail counters = %v", ev.Counters)
	}
	if len(c.Tick(now.Add(2*time.Second))) != 0 {
		t.Fatal("window must reset after Tick")
	}
}

func TestTLSAnomalyMissingSNI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.HTTPRPS = 10000
	cfg.TLSHSPS = 50
	c := New(cfg)
	dst := net.ParseIP("203.0.113.20")
	now := time.Unix(1700000000, 0)
	hello := clientHello("")
	for i := 0; i < 60; i++ {
		c.Observe(net.ParseIP("198.51.100.9"), dst, 50000, 443, 0x18, hello, now)
	}
	events := c.Tick(now.Add(time.Second))
	if len(events) != 1 || events[0].Type != l7.DecoderTLSAnomaly {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Counters["tls_sni_missing"] != 60 {
		t.Fatalf("missing = %d", events[0].Counters["tls_sni_missing"])
	}
}

func TestTLSWithSNI(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLSHSPS = 10
	c := New(cfg)
	dst := net.ParseIP("203.0.113.21")
	now := time.Unix(1700000000, 0)
	hello := clientHello("api.example.com")
	for i := 0; i < 20; i++ {
		c.Observe(net.ParseIP("198.51.100.10"), dst, 50000, 443, 0x18, hello, now)
	}
	events := c.Tick(now.Add(time.Second))
	if len(events) != 1 || events[0].Type != l7.DecoderTLSAnomaly {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Counters["tls_sni:api.example.com"] != 20 {
		t.Fatalf("sni counters = %v", events[0].Counters)
	}
}

func TestSlowloris(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SlowlorisConns = 1
	cfg.MaxOpenFragments = 2
	c := New(cfg)
	dst := net.ParseIP("203.0.113.30")
	src := net.ParseIP("198.51.100.11")
	now := time.Unix(1700000000, 0)
	partial := []byte("GET /index.html HTTP/1.1\r\nHost: victim\r\nX-Pad: 1\r\n")
	for i := 0; i < 4; i++ {
		c.Observe(src, dst, 51000, 80, 0x18, partial, now)
	}
	events := c.Tick(now.Add(time.Second))
	if len(events) != 1 || events[0].Type != l7.DecoderSlowloris {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Counters["slowloris_sources"] != 1 || events[0].Counters["src:198.51.100.11"] != 1 {
		t.Fatalf("counters = %v", events[0].Counters)
	}
}

func TestDisabledAndBounded(t *testing.T) {
	off := New(Config{Enabled: false})
	off.Observe(net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), 1, 80, 0, httpReq("GET", "/", "x", true), time.Now())
	if len(off.Tick(time.Now())) != 0 {
		t.Fatal("disabled collector must not emit")
	}

	cfg := DefaultConfig()
	cfg.MaxTracked = 2
	c := New(cfg)
	now := time.Unix(1700000000, 0)
	req := httpReq("GET", "/", "x", true)
	for i := 0; i < 5; i++ {
		c.Observe(net.ParseIP("1.1.1.1"), net.ParseIP(fmt.Sprintf("10.0.0.%d", i+1)), 1, 80, 0, req, now)
	}
	if c.Stats().Dropped == 0 {
		t.Fatal("expected dropped destinations to be counted")
	}
	if c.Stats().TrackedDsts > 2 {
		t.Fatalf("tracked = %d", c.Stats().TrackedDsts)
	}
}
