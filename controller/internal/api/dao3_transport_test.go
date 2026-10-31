package api

import (
	"bufio"
	"bytes"
	"context"
	"github.com/littlewolf9527/xsight/controller/internal/action"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// Select the production shared transport; preserve its settings in T4n.
func dao3APITransport() http.RoundTripper      { return action.WebhookTransport }
func dao3SetAPITransport(rt http.RoundTripper) { action.WebhookTransport = rt }

type dao3APIRoundTrip func(*http.Request) (*http.Response, error)

func (f dao3APIRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDao3_T4l_TestConnectorErrors(t *testing.T) {
	for _, code := range []int{400, 302} {
		t.Run(map[int]string{400: "4_body_guard", 302: "7_redirect"}[code], func(t *testing.T) {
			old := dao3APITransport()
			t.Cleanup(func() { dao3SetAPITransport(old) })
			calls := 0
			dao3SetAPITransport(dao3APIRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Header.Get("Authorization") != "Bearer t0ken" {
					t.Error("request did not use stored original")
				}
				h := make(http.Header)
				if code == 302 {
					h.Set("Location", "https://hooks.example/%zz?token=s3cret&echo=Bearer%20t0ken")
				}
				return &http.Response{StatusCode: code, Header: h, Body: io.NopCloser(strings.NewReader("Bearer t0ken")), Request: r}, nil
			}))
			s := dao3WebhookStore()
			s.connectors[0].URL = "https://hooks.example/?token=s3cret"
			w := dao3Call(t, s, "POST", "/api/settings/webhook-connectors/1/test", nil)
			dao3Status(t, w, 200)
			dao3Secret(t, w.Body.String())
			if calls != 1 {
				t.Fatalf("requests=%d", calls)
			}
			if !strings.Contains(w.Body.String(), `"success":false`) {
				t.Error("failed remote response treated as success")
			}
		})
	}
}

type dao3APILogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *dao3APILogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *dao3APILogBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

type dao3APIConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *dao3APIConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
func TestDao3_T4n_TestConnectorTransport(t *testing.T) {
	old := dao3APITransport()
	transport := old.(*http.Transport).Clone()
	buffer := &dao3APILogBuffer{}
	writer := log.Writer()
	log.SetOutput(buffer)
	defer log.SetOutput(writer)
	done, peerDone := make(chan struct{}), make(chan struct{})
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer close(peerDone)
			defer server.Close()
			req, err := http.ReadRequest(bufio.NewReader(server))
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, req.Body)
			req.Body.Close()
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nBearer t0ken")
		}()
		return &dao3APIConn{Conn: client, done: done}, nil
	}
	dao3SetAPITransport(transport)
	defer dao3SetAPITransport(old)
	defer transport.CloseIdleConnections()
	s := dao3WebhookStore()
	s.connectors[0].URL = "http://hooks.example/hook"
	w := dao3Call(t, s, "POST", "/api/settings/webhook-connectors/1/test", nil)
	<-done
	<-peerDone
	dao3Status(t, w, 200)
	if !strings.Contains(w.Body.String(), `"success":true`) {
		t.Fatalf("200 not successful: %s", w.Body.String())
	}
	if strings.Contains(buffer.String(), "t0ken") {
		t.Fatalf("transport leaked: %s", buffer.String())
	}
}
