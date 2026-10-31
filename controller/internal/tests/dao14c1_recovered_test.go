package tests

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/sys/unix"
)

func dao14c1RecoveredResult(t *testing.T, f *dao14c1Rig, label string, id, gen int) {
	t.Helper()
	dao14c1Check(t, label+".Commands", f.no(t, "192.0.2.10/32"), 1)
	r := f.row(t, 1)
	dao14c1Check(t, label+".Row", r.Status == "withdrawn" && r.Refcount == 0 && f.detached(t, 20), true)
	dao14c1Check(t, label+".Schedule", f.scheduled(id).Status, "completed")
	logs := f.ms.actionExecLog.snapshotLogs()
	good := len(logs) == 2
	if good {
		l := logs[1]
		good = l.ActionType == "bgp" && l.TriggerPhase == "on_expired" && l.AttackID == 0 && l.Status == "success" && strings.Contains(l.Detail, "announcement_id=1")
	}
	dao14c1Check(t, label+".ExecLog", good, true)
	dao14c1Check(t, label+".Gen", r.Gen, gen)
}
func TestDao14c1_B1(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, true)
		id := f.schedule(t, false)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao14c1RecoveredResult(t, f, "B1", id, 0)
	})
}
func TestDao14c1_B2(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, false, true)
		id := f.schedule(t, false)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao14c1Check(t, "B2.LiveKept", f.no(t, "192.0.2.10/32") == 0 && f.row(t, 1).Status == "active" && f.scheduled(id).Status == "completed" && len(f.ms.actionExecLog.snapshotLogs()) == 1, true)
	})
}
func TestDao14c1_B3(t *testing.T) {
	for _, enable := range []bool{false, true} {
		name := "Kept"
		if enable {
			name = "ThenEnabled"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, false)
				id := f.schedule(t, false)
				before := dao14c1Metrics()
				dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
				synctest.Wait()
				if enable {
					f.put(t, `{"enabled":true}`)
					synctest.Wait()
					dao14c1Check(t, "B3b.ThenEnabled", f.no(t, "192.0.2.10/32") == 1 && f.row(t, 1).Status == "withdrawn", true)
				} else {
					dao14c1Check(t, "B3a.Kept", f.no(t, "192.0.2.10/32") == 0 && f.row(t, 1).Status == "active" && f.scheduled(id).Status == "completed", true)
					dao14c1Check(t, "B3a.Metric", dao14c1Delta(before), map[string]float64{})
				}
			})
		})
	}
}
func TestDao14c1_B4(t *testing.T) { dao14c1Inflight(t, true) }
func TestDao14c1_B5(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, true)
		id := f.schedule(t, true)
		var mu sync.Mutex
		seen := map[string][]time.Duration{}
		for _, key := range []string{"get_connector", "list_attacks", "live", "reconcile"} {
			f.p.hook(key, func(c context.Context, _ int) error {
				d, ok := c.Deadline()
				v := time.Duration(-1)
				if ok {
					v = time.Until(d)
				}
				mu.Lock()
				seen[key] = append(seen[key], v)
				mu.Unlock()
				return nil
			})
		}
		f.e.ReconcileOnStartup(context.Background())
		synctest.Wait()
		dao14c1RecoveredResult(t, f, "B5", id, 0)
		for _, key := range []string{"get_connector", "list_attacks", "live", "reconcile"} {
			mu.Lock()
			values := append([]time.Duration(nil), seen[key]...)
			mu.Unlock()
			ok := len(values) > 0 && values[0] >= 0 && values[0] <= 10*time.Second
			dao14c1Check(t, "B5.Deadline."+key, ok, true)
			t.Logf("DEADLINES %s %v", key, values)
		}
	})
}
func TestDao14c1_B6(t *testing.T) {
	for _, detail := range []bool{false, true} {
		name := "Guard"
		if detail {
			name = "Detached"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := dao14c1New(t, true, true)
				f.add(1, 21, 7, "192.0.2.10/32", false)
				id := f.schedule(t, false)
				dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
				synctest.Wait()
				if detail {
					dao14c1Check(t, "B6b.Detached", f.detached(t, 20) && !f.detached(t, 21) && f.row(t, 1).Refcount == 1, true)
				} else {
					dao14c1Check(t, "B6a.Kept", f.no(t, "192.0.2.10/32") == 0 && f.row(t, 1).Status == "active" && f.scheduled(id).Status == "completed", true)
				}
			})
		})
	}
}
func TestDao14c1_B7(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, true)
		f.ms.bgpAnnouncements.announcements[0].Refcount = 2
		id := f.schedule(t, false)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao14c1Check(t, "B7.Kept", f.no(t, "192.0.2.10/32") == 0 && f.row(t, 1).Status == "active" && f.scheduled(id).Status == "completed" && !f.detached(t, 20), true)
	})
}
func TestDao14c1_B8(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, true)
		f.p.hook("reconcile", func(context.Context, int) error { return errors.New("reconcile unavailable") })
		id := f.schedule(t, false)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao14c1Check(t, "B8.ScheduleFailed", f.scheduled(id).Status, "failed")
		dao14c1Check(t, "B8.Row", f.row(t, 1).Status, "active")
		dao14c1Check(t, "B8.NoCommand", f.no(t, "192.0.2.10/32"), 0)
	})
}
func TestDao14c1_B9(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, true)
		c, _ := f.ms.BGPConnectors().Get(context.Background(), 7)
		dao14c1Must(t, os.WriteFile(c.VtyshPath, []byte("#!/bin/sh\nexit 1\n"), 0700))
		id := f.schedule(t, false)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		r := f.row(t, 1)
		dao14c1Check(t, "B9.Row", r.Status == "failed" && r.Refcount == 0 && f.detached(t, 20), true)
		dao14c1Check(t, "B9.Schedule", f.scheduled(id).Status, "failed")
		ls := f.ms.actionExecLog.snapshotLogs()
		dao14c1Check(t, "B9.ExecLog", len(ls) == 2 && ls[len(ls)-1].Status == "failed", true)
		_, ok, err := f.ms.BGPAnnouncements().ClaimFailedWithdraw(context.Background(), 1, r.Gen)
		dao14c1Must(t, err)
		dao14c1Check(t, "B9.FailedClaimable", ok, true)
	})
}
func TestDao14c1_B10(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, true)
		var once atomic.Bool
		f.p.hook("list_attacks", func(context.Context, int) error {
			if once.CompareAndSwap(false, true) {
				f.ms.bgpAnnouncements.mu.Lock()
				f.ms.bgpAnnouncements.announcements[0].Gen++
				f.ms.bgpAnnouncements.mu.Unlock()
			}
			return nil
		})
		id := f.schedule(t, false)
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		synctest.Wait()
		dao14c1RecoveredResult(t, f, "B10", id, 1)
	})
}
func TestDao14c1_B12(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := dao14c1New(t, true, false)
		f.schedule(t, false)
		entered, release := dao14c1Gate(f.p, "complete")
		before := dao14c1Metrics()
		dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
		<-entered
		f.put(t, `{"enabled":true}`)
		synctest.Wait()
		dao14c1Check(t, "B12.Mid", f.no(t, "192.0.2.10/32"), 0)
		close(release)
		synctest.Wait()
		dao14c1Check(t, "B12.HandedBack", f.no(t, "192.0.2.10/32") == 1 && f.row(t, 1).Status == "withdrawn", true)
		dao14c1Check(t, "B12.Metric", dao14c1Delta(before), map[string]float64{"skipped_status": 1, "dispatched": 1})
	})
}

// Both FIFOs are opened O_RDWR before launching any process. Commands are
// recorded after release, so the record describes side-effect order.
type dao14c1ProcessGate struct {
	entered            chan struct{}
	ready, releaseFile *os.File
	released           atomic.Bool
}

func dao14c1Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func dao14c1Process(t *testing.T, f *dao14c1Rig, prefix string) *dao14c1ProcessGate {
	t.Helper()
	dir := t.TempDir()
	readyPath, releasePath := filepath.Join(dir, "entered"), filepath.Join(dir, "release")
	for _, p := range []string{readyPath, releasePath} {
		dao14c1Must(t, unix.Mkfifo(p, 0600))
	}
	r, err := os.OpenFile(readyPath, os.O_RDWR, 0600)
	dao14c1Must(t, err)
	w, err := os.OpenFile(releasePath, os.O_RDWR, 0600)
	dao14c1Must(t, err)
	g := &dao14c1ProcessGate{entered: make(chan struct{}), ready: r, releaseFile: w}
	go func() {
		var b [1]byte
		if n, _ := r.Read(b[:]); n == 1 {
			close(g.entered)
		}
	}()
	c, err := f.ms.BGPConnectors().Get(context.Background(), 7)
	dao14c1Must(t, err)
	body := "#!/bin/sh\nif [ \"$1\" = --prime ]; then exit 0; fi\ncase \"$*\" in\n*" + dao14c1Quote("no network "+prefix+" route-map") + "*)\n if mkdir " + dao14c1Quote(filepath.Join(dir, "first")) + " 2>/dev/null; then\n  printf x > " + dao14c1Quote(readyPath) + "\n  read release < " + dao14c1Quote(releasePath) + "\n fi;;\nesac\nprintf '%s\\n' \"$@\" >> " + dao14c1Quote(f.record) + "\n"
	dao14c1Must(t, os.WriteFile(c.VtyshPath, []byte(body), 0700))
	dao14c1Must(t, exec.Command(c.VtyshPath, "--prime").Run())
	t.Cleanup(func() { g.release(); _ = r.Close(); _ = w.Close() })
	return g
}
func (g *dao14c1ProcessGate) release() {
	if g.released.CompareAndSwap(false, true) {
		_, _ = g.releaseFile.Write([]byte("yes\n"))
	}
}
func dao14c1Await[T any](t *testing.T, name string, ch <-chan T, limit time.Duration) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(limit):
		t.Fatalf("DEVICE %s completion timeout", name)
		var zero T
		return zero
	}
}
func dao14c1SignalContext(f *dao14c1Rig) <-chan context.Context {
	contexts := make(chan context.Context, 8)
	f.p.hook("listed_active", func(c context.Context, _ int) error { contexts <- c; return nil })
	return contexts
}
func dao14c1Finished(t *testing.T, c context.Context, name string) {
	t.Helper()
	dao14c1Await(t, name, c.Done(), 5*time.Second)
	dao14c1Check(t, name+".CanceledAfterReturn", c.Err(), context.Canceled)
}
func (f *dao14c1Rig) force(t *testing.T, attack int, prefix string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f.e.ForceRemove(context.Background(), attack, 10, 7, prefix+"|RTBH") }()
	return done
}
func (f *dao14c1Rig) newAttack(t *testing.T) {
	t.Helper()
	f.ms.attacks.mu.Lock()
	f.ms.attacks.attacks = append(f.ms.attacks.attacks, store.Attack{ID: 30, DstIP: "192.0.2.10", ResponseID: intPtr(1)})
	f.ms.attacks.mu.Unlock()
	done := make(chan struct{}, 1)
	f.p.hook("logged", func(_ context.Context, id int) error {
		if id == 30 {
			done <- struct{}{}
		}
		return nil
	})
	f.e.HandleEvent(f.event("confirmed", 30))
	dao14c1Await(t, "new attack log", done, 2*time.Second)
}
func dao14c1ForceReached(f *dao14c1Rig) <-chan struct{} {
	done := make(chan struct{}, 4)
	f.p.hook("found", func(context.Context, int) error { done <- struct{}{}; return nil })
	return done
}
func dao14c1AssertResurrected(t *testing.T, f *dao14c1Rig, label string) {
	t.Helper()
	text := dao4Read(t, f.record)
	var seq []string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "no network 192.0.2.10/32") {
			seq = append(seq, "no")
		} else if strings.HasPrefix(line, "network 192.0.2.10/32") {
			seq = append(seq, "net")
		}
	}
	dao14c1Check(t, label+".Seq", seq, []string{"no", "net"})
	rows, err := f.ms.BGPAnnouncements().ListAttacks(context.Background(), 1)
	dao14c1Must(t, err)
	attached := false
	for _, r := range rows {
		attached = attached || r.AttackID == 30 && r.DetachedAt == nil
	}
	dao14c1Check(t, label+".Row", f.row(t, 1).Status == "active" && attached, true)
}
func TestDao14c1_B11(t *testing.T) {
	f := dao14c1New(t, true, true)
	retries := make(chan context.Context, 4)
	f.p.hook("get_connector", func(c context.Context, _ int) error {
		if d, ok := c.Deadline(); ok && time.Until(d) > 10*time.Second && time.Until(d) <= 30*time.Second {
			retries <- c
		}
		return nil
	})
	f.actions()
	f.add(2, 21, 7, "192.0.2.20/32", true)
	f.schedule(t, false)
	gate := dao14c1Process(t, f, "192.0.2.10/32")
	defer gate.release()
	workerDone := make(chan struct{}, 4)
	newLogged := make(chan struct{}, 1)
	f.p.hook("logged", func(_ context.Context, id int) error {
		if id == 0 {
			workerDone <- struct{}{}
		}
		if id == 30 {
			newLogged <- struct{}{}
		}
		return nil
	})
	dao14c1Must(t, f.e.RecoverScheduledActions(context.Background()))
	dao14c1Await(t, "worker process", gate.entered, 5*time.Second)
	tried := make(chan struct{}, 1)
	f.p.hook("attached", func(_ context.Context, id int) error {
		if id == 30 {
			tried <- struct{}{}
		}
		return nil
	})
	m := &dto.Metric{}
	_ = metrics.ActionQueueEvents.WithLabelValues("drain_timeout").Write(m)
	before := m.GetCounter().GetValue()
	f.e.Start()
	f.e.Enqueue(f.event("confirmed", 30))
	drained := make(chan struct{})
	go func() { f.e.Drain(2 * time.Second); close(drained) }()
	dao14c1Await(t, "dispatcher", drained, 3*time.Second)
	_ = metrics.ActionQueueEvents.WithLabelValues("drain_timeout").Write(m)
	dao14c1Check(t, "B11.Dispatcher", m.GetCounter().GetValue()-before, float64(0))
	dao14c1Await(t, "new attack Attach returned", tried, 2*time.Second)
	dao14c1Await(t, "new attack failure log", newLogged, 2*time.Second)
	rejected := false
	for _, entry := range f.ms.actionExecLog.snapshotLogs() {
		if entry.AttackID == 30 && strings.Contains(entry.ErrorMessage, "cannot attach to announcement 1 in status withdrawing") {
			rejected = true
		}
	}
	dao14c1Check(t, "B11.NewAttackTried", rejected, true)
	read := make(chan int, 1)
	go func() { read <- f.request(t, "GET", "/api/active-actions/bgp", "", f.e) }()
	dao14c1Check(t, "B11.APIRead", dao14c1Await(t, "API read", read, 2*time.Second), 200)
	dao14c1Check(t, "B11.OtherAnnouncement", dao14c1Await(t, "other force", f.force(t, 21, "192.0.2.20/32"), 2*time.Second), nil)
	dao14c1Check(t, "B11.OtherRow", f.row(t, 2).Status, "withdrawn")
	reached := dao14c1ForceReached(f)
	same := f.force(t, 20, "192.0.2.10/32")
	dao14c1Await(t, "same force lookup", reached, 2*time.Second)
	early := false
	var earlyErr error
	select {
	case earlyErr = <-same:
		early = true
	case <-time.After(300 * time.Millisecond):
	}
	dao14c1Check(t, "B11.SameAnnouncementWaits", early, false)
	gate.release()
	if early {
		dao14c1Check(t, "B11.SameAnnouncementNoop", earlyErr, nil)
	} else {
		dao14c1Check(t, "B11.SameAnnouncementNoop", dao14c1Await(t, "same force", same, 2*time.Second), nil)
	}
	// The normal worker writes its log before returning and releasing its lock.
	if !early {
		dao14c1Await(t, "worker log", workerDone, 2*time.Second)
	}
	c := dao14c1Await(t, "worker withdraw context", retries, 3*time.Second)
	dao14c1Finished(t, c, "B11.WithdrawComplete")
	dao14c1Check(t, "B11.Commands", f.no(t, "192.0.2.10/32"), 1)
	dao14c1Check(t, "B11.Row", f.row(t, 1).Status, "withdrawn")
}

// Keep the executing worker inside its claim call after the repository commit.
// The startup scanner still uses the real repository enumeration, and records
// exactly what it returned before any withdrawal can be attributed to the owner.
type dao14c1OwnedScanRepo struct {
	store.BGPAnnouncementRepo
	claimed chan struct{}
	resume  <-chan struct{}
	scanned chan []store.BGPAnnouncement
}

func (r dao14c1OwnedScanRepo) ReconcileAttachments(c context.Context, id int, ended []int, detach bool) (store.BGPReconcileResult, error) {
	result, err := r.BGPAnnouncementRepo.ReconcileAttachments(c, id, ended, detach)
	if err == nil && result.NeedWithdraw {
		close(r.claimed)
		<-r.resume
	}
	return result, err
}

func (r dao14c1OwnedScanRepo) ListByStatus(c context.Context, status string) ([]store.BGPAnnouncement, error) {
	rows, err := r.BGPAnnouncementRepo.ListByStatus(c, status)
	if status == "withdrawing" && err == nil {
		r.scanned <- rows
	}
	return rows, err
}

func TestDao14c1_B13(t *testing.T) {
	t.Run("NoLogOracle", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := dao14c1New(t, true, true)
			claimed, resume := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-resume:
				default:
					close(resume)
				}
			}()
			scanned := make(chan []store.BGPAnnouncement, 1)
			f.s.anns = dao14c1OwnedScanRepo{f.s.anns, claimed, resume, scanned}
			f.e = action.NewEngine(f.s, "auto")
			id := f.schedule(t, true)
			f.p.hook("status_withdrawing", func(context.Context, int) error {
				dao14c1Await(t, "committed worker claim", claimed, 3*time.Second)
				return nil
			})
			retries := make(chan context.Context, 4)
			f.p.hook("get_connector", func(c context.Context, _ int) error {
				if d, ok := c.Deadline(); ok && time.Until(d) > 10*time.Second && time.Until(d) <= 30*time.Second {
					retries <- c
				}
				return nil
			})
			logged := make(chan struct{}, 1)
			f.p.hook("logged", func(context.Context, int) error { logged <- struct{}{}; return nil })
			f.e.ReconcileOnStartup(context.Background())
			rows := dao14c1Await(t, "startup enumeration returned", scanned, 3*time.Second)
			if len(rows) != 1 || rows[0].ID != 1 || rows[0].Status != "withdrawing" {
				t.Fatalf("DEVICE startup scan did not enumerate the committed claim: %+v", rows)
			}
			// All unblocked goroutines, including an erroneous startup retry, run
			// to quiescence while the owner is still blocked on resume.
			synctest.Wait()
			dao14c1Check(t, "B13.NoDuplicateBeforeOwnerRuns", f.no(t, "192.0.2.10/32"), 0)
			close(resume)
			dao14c1Await(t, "executing worker log committed", logged, 3*time.Second)
			synctest.Wait()
			// Observe cancellation of every actual retry context. The decision
			// to join a retry never depends on production log contents.
			for len(retries) > 0 {
				dao14c1Finished(t, <-retries, "B13.DuplicateComplete")
			}
			dao14c1Check(t, "B13.Schedule", f.scheduled(id).Status, "completed")
			dao14c1Check(t, "B13.Commands", f.no(t, "192.0.2.10/32"), 1)
			dao14c1Check(t, "B13.Row", f.row(t, 1).Status, "withdrawn")
			dao14c1Check(t, "B13.OwnedLog", strings.Contains(f.log.text(), "owned by executing schedule — skipped"), true)
		})
	})
}
func TestDao14c1_B14(t *testing.T) {
	for _, fault := range []string{"ReconcileErr", "ConnGetErr"} {
		t.Run(fault, func(t *testing.T) {
			f := dao14c1New(t, true, true)
			f.add(2, 21, 7, "192.0.2.20/32", true)
			id := f.schedule(t, true)
			contexts := dao14c1SignalContext(f)
			gate := dao14c1Process(t, f, "192.0.2.20/32")
			defer gate.release()
			var hit atomic.Bool
			retryContexts := make(chan context.Context, 8)
			duplicate := false
			key := "list_attacks"
			terminal := "failed"
			if fault == "ConnGetErr" {
				key = "get_connector"
				terminal = "completed"
			}
			f.p.hook("get_connector", func(c context.Context, _ int) error {
				if d, ok := c.Deadline(); ok && time.Until(d) > 10*time.Second && time.Until(d) <= 30*time.Second {
					retryContexts <- c
				}
				if key == "get_connector" && hit.CompareAndSwap(false, true) {
					return errors.New("one recoverable query failure")
				}
				return nil
			})
			if key == "list_attacks" {
				f.p.hook(key, func(_ context.Context, id int) error {
					if (key == "get_connector" || id == 1) && hit.CompareAndSwap(false, true) {
						return errors.New("one recoverable query failure")
					}
					return nil
				})
			}
			f.p.hook("status_withdrawing", func(context.Context, int) error {
				select {
				case <-gate.entered:
					duplicate = true
				case <-time.After(3 * time.Second):
				}
				return nil
			})
			f.e.ReconcileOnStartup(context.Background())
			gate.release()
			if !hit.Load() {
				t.Logf("DEVICE observation B14 faultHit=false noA=%d noB=%d", f.no(t, "192.0.2.10/32"), f.no(t, "192.0.2.20/32"))
				t.Fatalf("DEVICE B14 fault injection was not reached")
			}
			c := dao14c1Await(t, "hand-back sweep context", contexts, 5*time.Second)
			// This is the sweep's deferred cancellation, not a timer-as-completion.
			dao14c1Finished(t, c, "B14.SweepComplete")
			retries := 1
			if duplicate {
				retries = 3
			}
			for i := 0; i < retries; i++ {
				c := dao14c1Await(t, "withdraw retry context", retryContexts, 3*time.Second)
				dao14c1Finished(t, c, "B14.RetryComplete")
			}
			dao14c1Check(t, "B14.FaultHit", hit.Load(), true)
			dao14c1Check(t, "B14.Schedule", f.scheduled(id).Status, terminal)
			a, b := f.no(t, "192.0.2.10/32"), f.no(t, "192.0.2.20/32")
			t.Logf("RESULT B14.%s noA=%d noB=%d statusA=%s statusB=%s", fault, a, b, f.row(t, 1).Status, f.row(t, 2).Status)
			dao14c1Check(t, "B14.PerPrefixAtMostOnce", a <= 1 && b <= 1, true)
			dao14c1Check(t, "B14.OtherUntouched", b == 0 && f.row(t, 2).Status == "active", true)
			dao14c1Check(t, "B14.OwnWithdrawn", a == 1 && f.row(t, 1).Status == "withdrawn", true)
		})
	}
}
