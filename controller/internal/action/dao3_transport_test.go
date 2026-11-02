package action

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type dao3PipeConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *dao3PipeConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
func TestDao3_T4n_ActionTransport(t *testing.T) {
	old := WebhookTransport
	transport := old.(*http.Transport).Clone()
	buffer := dao3Capture(t)
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
		return &dao3PipeConn{Conn: client, done: done}, nil
	}
	WebhookTransport = transport
	defer func() { WebhookTransport = old }()
	defer transport.CloseIdleConnections()
	result, err := postWebhookWithFA(context.Background(), "http://hooks.example/hook", nil, &store.Attack{ID: 1}, "attack_start", nil)
	<-done
	<-peerDone
	if err != nil || result != "HTTP 200" {
		t.Fatalf("result=%q err=%v", result, err)
	}
	if strings.Contains(buffer.String(), "t0ken") {
		t.Fatalf("transport leaked: %s", buffer.String())
	}
}
