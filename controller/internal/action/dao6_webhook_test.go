package action

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Use the existing shared WebhookTransport seam. No listener, socket, or
// production HTTP injection change is required: this is a real Client.Do
// call blocked in a test RoundTripper, with real request contexts.
type dao6HTTP struct {
	mu                sync.Mutex
	b                 *dao6Barrier
	started, finished int
	badDeadline       bool
}

func (r *dao6HTTP) RoundTrip(req *http.Request) (*http.Response, error) {
	deadline, ok := req.Context().Deadline()
	r.mu.Lock()
	r.started++
	r.badDeadline = r.badDeadline || !ok || deadline.Sub(time.Now()) > 30*time.Second
	r.mu.Unlock()
	r.b.wait()
	r.mu.Lock()
	r.finished++
	r.badDeadline = r.badDeadline || req.Context().Err() != nil
	r.mu.Unlock()
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: make(http.Header), Request: req}, nil
}
func (r *dao6HTTP) snapshot() (int, int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.started, r.finished, r.badDeadline
}
func dao6HTTPFixture(t *testing.T) (*dao6Store, *dao6HTTP) {
	t.Helper()
	s := dao6NewStore()
	s.globals = []store.WebhookConnector{{ID: 1, URL: "http://192.0.2.1/dao6", Enabled: true, Global: true}}
	r := &dao6HTTP{b: dao6NewBarrier()}
	original := WebhookTransport
	WebhookTransport = r
	t.Cleanup(func() { WebhookTransport = original })
	return s, r
}

// E2 baseline evidence uses direct HandleEvent, which exists on HEAD.
func TestDao6_E2_HandleEventReturnsDuringWebhook(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, h := dao6HTTPFixture(t)
		e := NewEngine(s, "auto")
		done := make(chan struct{})
		go func() { e.HandleEvent(dao6Event(1)); close(done) }()
		defer func() { h.b.open(); <-done; synctest.Wait() }()
		<-h.b.entered
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("HandleEvent waits for global webhook")
		}
		_, _, bad := h.snapshot()
		if bad {
			t.Error("webhook context lacks bounded independent lifetime")
		}
	})
}

func TestDao6_G1_TrackerDuringWebhook(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, h := dao6HTTPFixture(t)
		e := NewEngine(s, "auto")
		stop := dao6Start(e)
		tk := dao6Tracker(s, dao6Wire(e))
		first := make(chan struct{})
		go func() { tk.Feed(dao6Threshold("192.0.2.10")); close(first) }()
		defer func() { h.b.open(); <-first; stop(); synctest.Wait() }()
		<-h.b.entered
		synctest.Wait()
		select {
		case <-first:
		default:
			t.Error("Feed waits for global webhook")
			return
		}
		done := make(chan struct{})
		go func() {
			// Exceed the production buffer by one event. With spare capacity,
			// queueing alone masks M9: synchronous HTTP stalls dispatch but a
			// small Feed still returns. This burst also exercises backpressure.
			rows := dao6Threshold("198.51.0.0")
			for i := 1; i < 4097; i++ {
				rows = append(rows, dao6Threshold(fmt.Sprintf("198.51.%d.%d", i/256, i%256))...)
			}
			tk.Feed(rows)
			tk.ActiveCount()
			close(done)
		}()
		defer func() { h.b.open(); <-done }()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("Feed/ActiveCount waits for global webhook")
			return
		}
		h.b.open()
		synctest.Wait()
		started, finished, bad := h.snapshot()
		if started != 4098 || finished != 4098 || bad {
			t.Errorf("webhooks started=%d finished=%d badDeadline=%v", started, finished, bad)
		}
	})
}

func TestDao6_E2_NextQueuedEventDuringWebhook(t *testing.T) {
	for _, branch := range []string{"no_response", "disabled_response", "enabled_response"} {
		t.Run(branch, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, h := dao6HTTPFixture(t)
				s.disabledResponse = branch == "disabled_response"
				e := NewEngine(s, "auto")
				e.Start()
				defer func() { h.b.open(); e.WaitIdle(); e.stop(); synctest.Wait() }()
				first := dao6Event(1)
				if branch == "no_response" {
					first.Attack.ResponseID = nil
				}
				e.Enqueue(first)
				<-h.b.entered
				next := dao6Event(2)
				next.Type = "updated" // no global webhook for this event
				e.Enqueue(next)
				synctest.Wait()
				calls, _ := s.snapshots()
				found := false
				for _, id := range calls {
					found = found || id == 2
				}
				if !found {
					t.Error("next HandleEvent did not start before webhook release")
				}
				h.b.open()
				e.WaitIdle()
				synctest.Wait()
				started, finished, bad := h.snapshot()
				if started != 1 || finished != 1 || bad {
					t.Errorf("webhook started=%d finished=%d invalid context=%v", started, finished, bad)
				}
			})
		})
	}
}
