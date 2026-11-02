package action

import (
	"bytes"
	"log"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type dao6Log struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *dao6Log) Write(p []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.b.Write(p) }
func (b *dao6Log) text() string                { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func dao6CaptureLog(t *testing.T) *dao6Log {
	t.Helper()
	b := &dao6Log{}
	old := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(old) })
	return b
}
func dao6Counter(outcome string) float64 {
	return testutil.ToFloat64(metrics.ActionQueueEvents.WithLabelValues(outcome))
}
func dao6BlockedEngine() (*dao6Store, *Engine, *dao6Barrier) {
	s := dao6NewStore()
	b := dao6NewBarrier()
	s.responseGate = b
	s.blockedResponse = 1
	e := NewEngine(s, "auto")
	e.queue = make(chan dispatchItem, 2)
	e.Start()
	e.Enqueue(dao6Event(1))
	<-b.entered
	return s, e, b
}
func dao6WantCalls(t *testing.T, s *dao6Store, want []int) {
	t.Helper()
	got, _ := s.snapshots()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("HandleEvent response recorder=%v want=%v", got, want)
	}
}

func TestDao6_E1_DispatchFIFO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dao6NewStore()
		e := NewEngine(s, "auto")
		e.Start()
		defer e.stop()
		for id := 1; id <= 4; id++ {
			e.Enqueue(dao6Event(id))
		}
		synctest.Wait()
		dao6WantCalls(t, s, []int{1, 2, 3, 4})
	})
}

func TestDao6_E3_FullQueueBlocksAndReports(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		if cap(NewEngine(dao6NewStore(), "auto").queue) != 4096 {
			t.Fatal("production queue capacity must be 4096")
		}
		s, e, b := dao6BlockedEngine()
		capture := dao6CaptureLog(t)
		before := dao6Counter("full")
		e.Enqueue(dao6Event(2))
		e.Enqueue(dao6Event(3))
		sent := make(chan struct{})
		go func() { e.Enqueue(dao6Event(4)); close(sent) }()
		defer func() { b.open(); <-sent; e.WaitIdle(); e.stop() }()
		synctest.Wait()
		select {
		case <-sent:
			t.Error("full queue Enqueue returned before capacity was released")
		default:
		}
		if n := dao6Counter("full") - before; n != 1 {
			t.Errorf("queue full counter delta=%v want 1", n)
		}
		if n := strings.Count(capture.text(), "queue full;"); n != 1 {
			t.Errorf("queue full log count=%d want 1", n)
		}
		b.open()
		<-sent
		e.WaitIdle()
		dao6WantCalls(t, s, []int{1, 2, 3, 4})
	})
}

func TestDao6_E4_DrainWaitsForBacklog(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, b := dao6BlockedEngine()
		e.Enqueue(dao6Event(2))
		e.Enqueue(dao6Event(3))
		done := make(chan struct{})
		go func() { e.Drain(time.Second); close(done) }()
		defer func() { b.open(); <-done; e.stop() }()
		synctest.Wait()
		select {
		case <-done:
			t.Error("Drain returned before backlog synchronous sections completed")
		default:
		}
		b.open()
		<-done
		dao6WantCalls(t, s, []int{1, 2, 3})
	})
}

func TestDao6_E5_DrainDeadlineAndAbandonedMarker(t *testing.T) {
	for _, full := range []bool{true, false} {
		name := "marker_queued"
		if full {
			name = "queue_full"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, e, b := dao6BlockedEngine()
				e.Enqueue(dao6Event(2))
				if full {
					e.Enqueue(dao6Event(3))
				}
				capture := dao6CaptureLog(t)
				before := dao6Counter("drain_timeout")
				start := time.Now()
				result := make(chan time.Duration, 1)
				joined := make(chan struct{})
				go func() { e.Drain(time.Second); result <- time.Since(start); close(joined) }()
				var marker chan struct{}
				// While the dispatcher is blocked, retain the marker channel for
				// M7b cleanup. Do not receive from it until AFTER a failed assertion.
				synctest.Wait()
				if !full {
					first := <-e.queue
					second := <-e.queue
					marker = second.done
					e.queue <- first
					e.queue <- second
				}
				defer func() { b.open(); <-joined; e.stop() }()
				watchdog := time.NewTimer(2 * time.Second)
				<-watchdog.C
				select {
				case elapsed := <-result:
					if elapsed != time.Second {
						t.Errorf("Drain returned at %s want 1s", elapsed)
					}
				default:
					t.Error("Drain missed its 1s deadline (independent 2s watchdog)")
					b.open()
					<-result
				}
				if n := dao6Counter("drain_timeout") - before; n != 1 {
					t.Errorf("drain timeout counter delta=%v want 1", n)
				}
				if n := strings.Count(capture.text(), "queue drain timed out"); n != 1 {
					t.Errorf("drain timeout log count=%d want 1", n)
				}
				b.open()
				sent := make(chan struct{})
				go func() { e.Enqueue(dao6Event(99)); close(sent) }()
				defer func() { <-sent }()
				// E5 explicitly permits a bounded fake-clock check for the old
				// marker: M7b blocks the dispatcher on an abandoned unbuffered send.
				later := time.NewTimer(time.Second)
				<-later.C
				synctest.Wait()
				calls, _ := s.snapshots()
				found := false
				for _, id := range calls {
					found = found || id == 99
				}
				if !found {
					t.Error("event after timed-out Drain not processed; abandoned marker blocked dispatcher")
					if marker != nil {
						select {
						case <-marker:
						default:
						}
					}
				}
				<-sent
				synctest.Wait()
			})
		})
	}
}

func TestDao6_E6_RebreachSharesFIFO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, b := dao6BlockedEngine()
		defer func() { b.open(); e.stop() }()
		e.EnqueueRebreach(7)
		synctest.Wait()
		_, calls := s.snapshots()
		if len(calls) != 0 {
			t.Errorf("CancelDelaysForAttack before earlier HandleEvent returns: %v", calls)
		}
		b.open()
		e.WaitIdle()
		_, calls = s.snapshots()
		if !reflect.DeepEqual(calls, []int{7}) {
			t.Errorf("rebreach calls=%v want [7]", calls)
		}
	})
}

func TestDao6_E7_AcceptsAfterDrain(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "completed"
		if expired {
			name = "timed_out"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := dao6NewStore()
				e := NewEngine(s, "auto")
				var b *dao6Barrier
				if expired {
					b = dao6NewBarrier()
					s.responseGate = b
					s.blockedResponse = 1
				}
				e.Start()
				defer func() {
					if b != nil {
						b.open()
					}
					e.stop()
				}()
				if b != nil {
					e.Enqueue(dao6Event(1))
					<-b.entered
				}
				e.Drain(time.Second)
				e.Enqueue(dao6Event(2))
				if b != nil {
					b.open()
				}
				e.WaitIdle()
				want := []int{2}
				if expired {
					want = []int{1, 2}
				}
				dao6WantCalls(t, s, want)
			})
		})
	}
}

func TestDao6_E8_InFlightExpiredSurvivesDrainTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := dao6NewStore()
		dispatch := dao6NewBarrier()
		get := dao6NewBarrier()
		s.responseGate = dispatch
		s.blockedResponse = 999
		s.getGate = get
		s.actions = []store.ResponseAction{{ID: 10, ResponseID: 1, ActionType: "xdrop", TriggerPhase: "on_expired", RunMode: "once", Enabled: true}}
		e := NewEngine(s, "observe")
		e.Start()
		tk := dao6Tracker(s, e.Enqueue)
		tk.Feed(dao6Threshold("192.0.2.10"))
		e.WaitIdle()
		e.Enqueue(dao6Event(999))
		<-dispatch.entered
		producer := make(chan struct{})
		go func() { tk.ForceExpire(1); close(producer) }()
		defer func() { get.open(); dispatch.open(); <-producer; e.stop() }()
		<-get.entered        // ended_at was written; no expired event was handed off yet
		e.Drain(time.Second) // deliberately less than tracker DB context's 5s
		get.open()
		<-producer
		// The dispatcher is still held. Retain and restore its FIFO contents
		// to identify the exact event (expired, DBID 1), then use the real
		// synchronous on_expired skip log below as its completion recorder.
		queuedExpired := 0
		queued := make([]dispatchItem, len(e.queue))
		for i := range queued {
			queued[i] = <-e.queue
			if queued[i].event.Type == "expired" && queued[i].event.DBID == 1 {
				queuedExpired++
			}
		}
		for _, item := range queued {
			e.queue <- item
		}
		dispatch.open()
		e.WaitIdle()
		hits := 0
		for _, row := range s.logSnapshot() {
			if row.AttackID == 1 && row.TriggerPhase == "on_expired" {
				hits++
			}
		}
		if hits != 1 || queuedExpired != 1 {
			t.Errorf("expired HandleEvent target DBID=1 hits=%d exact queued expired=%d want 1 each", hits, queuedExpired)
		}
	})
}

func TestDao6_E9_ConcurrentDrainDeadlinesIndependent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, e, b := dao6BlockedEngine()
		start := time.Now()
		long := make(chan time.Duration, 1)
		short := make(chan time.Duration, 1)
		go func() { e.Drain(3 * time.Second); long <- time.Since(start) }()
		synctest.Wait() // long deadline is established first (M13)
		go func() { e.Drain(time.Second); short <- time.Since(start) }()
		defer func() { b.open(); e.stop() }()
		if elapsed := <-short; elapsed != time.Second {
			t.Errorf("short Drain elapsed=%s want 1s", elapsed)
		}
		if elapsed := <-long; elapsed != 3*time.Second {
			t.Errorf("long Drain elapsed=%s want 3s", elapsed)
		}
	})
}
