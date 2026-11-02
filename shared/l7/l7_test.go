package l7

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestParseHTTPRequest(t *testing.T) {
	req, ok := ParseHTTPRequest([]byte("GET /login?id=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 42\r\n\r\nbody"))
	if !ok {
		t.Fatal("expected valid request")
	}
	if req.Method != "GET" || req.Path != "/login?id=1" || req.Proto != "HTTP/1.1" {
		t.Fatalf("bad request line: %+v", req)
	}
	if req.Host != "example.com" || req.ContentLength != 42 || !req.HeaderComplete {
		t.Fatalf("bad headers: %+v", req)
	}
}

func TestParseHTTPRequestIncomplete(t *testing.T) {
	req, ok := ParseHTTPRequest([]byte("POST /api HTTP/1.1\r\nHost: example.com\r\nX-Partial: y"))
	if !ok {
		t.Fatal("expected request line to parse")
	}
	if req.HeaderComplete {
		t.Fatal("headers must be incomplete")
	}
}

func TestParseHTTPRequestRejectsGarbage(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte("\x16\x03\x01\x00\x05hello"),
		[]byte("GET / HTTP/1.1"), // no CRLF
		[]byte("NOTAMETHOD / HTTP/1.1\r\n\r\n"),
		[]byte("GET x HTTP/1.1\r\n\r\n"),
		[]byte("GET / HTTP/2.0\r\n\r\n"),
		[]byte("short"),
	} {
		if _, ok := ParseHTTPRequest(payload); ok {
			t.Fatalf("expected rejection for %q", payload)
		}
	}
}

func buildClientHello(sni string) []byte {
	name := []byte(sni)
	sniBody := make([]byte, 0, 5+len(name))
	sniBody = append(sniBody, 0, 0, 0, byte(len(name)>>8), byte(len(name)))
	binary.BigEndian.PutUint16(sniBody[0:2], uint16(3+len(name)))
	sniBody = append(sniBody, name...)

	ext := make([]byte, 0, 4+len(sniBody))
	ext = append(ext, 0, 0, byte(len(sniBody)>>8), byte(len(sniBody)))
	ext = append(ext, sniBody...)

	hs := make([]byte, 0, 64+len(ext))
	hs = append(hs, 0x03, 0x03)
	hs = append(hs, make([]byte, 32)...)
	hs = append(hs, 0)
	hs = append(hs, 0, 4, 0x13, 0x01, 0x13, 0x02)
	hs = append(hs, 1, 0)
	hs = append(hs, byte(len(ext)>>8), byte(len(ext)))
	hs = append(hs, ext...)

	body := make([]byte, 0, 4+len(hs))
	body = append(body, 0x01, byte(len(hs)>>16), byte(len(hs)>>8), byte(len(hs)))
	body = append(body, hs...)

	rec := make([]byte, 0, 5+len(body))
	rec = append(rec, 0x16, 0x03, 0x01, byte(len(body)>>8), byte(len(body)))
	rec = append(rec, body...)
	return rec
}

func TestParseTLSClientHello(t *testing.T) {
	hello, ok := ParseTLSClientHello(buildClientHello("example.com"))
	if !ok {
		t.Fatal("expected valid ClientHello")
	}
	if hello.SNI != "example.com" {
		t.Fatalf("SNI=%q", hello.SNI)
	}
	if hello.CipherSuites != 2 {
		t.Fatalf("cipher suites=%d", hello.CipherSuites)
	}
	if hello.Version != 0x0303 {
		t.Fatalf("version=0x%04x", hello.Version)
	}
}

func TestParseTLSClientHelloRejectsGarbage(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		[]byte{0x16, 0x03},
		{0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00},
		{0x17, 0x03, 0x03, 0x00, 0x02, 0x00, 0x00},
	} {
		if _, ok := ParseTLSClientHello(payload); ok {
			t.Fatalf("expected rejection for %x", payload)
		}
	}
}

func TestSlowlorisObserve(t *testing.T) {
	var s SlowlorisState
	frag := []byte("GET / HTTP/1.1\r\nX-Slow: 1\r\n")
	for i := 0; i < 5; i++ {
		if s.Observe(frag, 5) {
			t.Fatalf("flagged too early at %d", i)
		}
	}
	if !s.Observe(frag, 5) {
		t.Fatal("expected Slowloris flag")
	}

	var done SlowlorisState
	done.Observe([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), 1)
	if done.Observe([]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), 1) {
		t.Fatal("completed requests must not flag")
	}
}

func TestCounter(t *testing.T) {
	c := NewCounter(time.Second)
	now := time.Unix(1000, 0)
	if got := c.Add("1.2.3.4", 3, now); got != 3 {
		t.Fatalf("count=%d", got)
	}
	if got := c.Add("1.2.3.4", 2, now.Add(500*time.Millisecond)); got != 5 {
		t.Fatalf("count=%d", got)
	}
	if r := c.Rate("1.2.3.4", now.Add(500*time.Millisecond)); r != 10 {
		t.Fatalf("rate=%v", r)
	}
	if got := c.Add("1.2.3.4", 1, now.Add(2*time.Second)); got != 1 {
		t.Fatalf("window must reset, count=%d", got)
	}
}
