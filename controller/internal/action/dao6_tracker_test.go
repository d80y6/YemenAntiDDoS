package action

import (
	"testing"
	"testing/synctest"

	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

// Baseline proof changes only these helpers to direct HEAD wiring.
// The final tests exercise the real queue and dispatcher.
func dao6Wire(e *Engine) tracker.ActionCallback { return e.Enqueue }
func dao6Start(e *Engine) func()                { e.Start(); return e.stop }

func dao6TrackerUnblocked(t *testing.T, secondFeed bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		s := dao6NewStore()
		b := dao6NewBarrier()
		s.responseGate = b
		s.blockedResponse = 1
		e := NewEngine(s, "auto")
		stop := dao6Start(e)
		tk := dao6Tracker(s, dao6Wire(e))
		first := make(chan struct{})
		go func() { tk.Feed(dao6Threshold("192.0.2.10")); close(first) }()
		// Release barriers and join senders BEFORE stopping the dispatcher,
		// including all assertion failure paths.
		defer func() { b.open(); <-first; stop() }()
		<-b.entered
		synctest.Wait()
		select {
		case <-first:
		default:
			t.Error("first Feed still blocked by HandleEvent synchronous section")
			return
		}
		done := make(chan struct{})
		go func() {
			if secondFeed {
				tk.Feed(dao6Threshold("198.51.100.10"))
			} else {
				tk.ActiveCount()
				tk.ActiveTimers()
			}
			close(done)
		}()
		defer func() { b.open(); <-done }()
		synctest.Wait()
		select {
		case <-done:
		default:
			t.Error("tracker operation did not return before response barrier release")
		}
	})
}
func TestDao6_T1_ReadersDuringHandleEvent(t *testing.T) { dao6TrackerUnblocked(t, false) }
func TestDao6_T2_FeedDuringHandleEvent(t *testing.T)    { dao6TrackerUnblocked(t, true) }
