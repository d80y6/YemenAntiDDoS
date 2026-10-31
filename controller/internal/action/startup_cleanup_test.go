package action

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/metrics"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/sys/unix"
)

// G1/G10 use package-local fixtures so the production wait limit stays private.
// Every mutable repository field is read/written under mu after seeding; gates
// are immutable after seeding and are never awaited while holding mu.
type fzWaitStore struct {
	store.Store
	mu       sync.Mutex
	anns     []store.BGPAnnouncement
	detached map[int]bool
	queries  map[int]int
	path     string
	gate     <-chan struct{}
	finished chan int
}
type fzWaitAnns struct {
	store.BGPAnnouncementRepo
	s *fzWaitStore
}
type fzWaitConns struct {
	store.BGPConnectorRepo
	s *fzWaitStore
}
type fzWaitAttacks struct{ store.AttackRepo }
type fzWaitSchedules struct{ store.ScheduledActionRepo }
type fzWaitRules struct{ store.XDropActiveRuleRepo }

func (s *fzWaitStore) BGPAnnouncements() store.BGPAnnouncementRepo { return fzWaitAnns{s: s} }
func (s *fzWaitStore) BGPConnectors() store.BGPConnectorRepo       { return fzWaitConns{s: s} }
func (s *fzWaitStore) Attacks() store.AttackRepo                   { return fzWaitAttacks{} }
func (s *fzWaitStore) ScheduledActions() store.ScheduledActionRepo { return fzWaitSchedules{} }
func (s *fzWaitStore) XDropActiveRules() store.XDropActiveRuleRepo { return fzWaitRules{} }
func (fzWaitAttacks) LiveIDs(context.Context, []int) (map[int]bool, error) {
	return map[int]bool{}, nil
}
func (fzWaitSchedules) ListPending(context.Context) ([]store.ScheduledAction, error) { return nil, nil }
func (fzWaitSchedules) ListExecuting(context.Context) ([]store.ScheduledAction, error) {
	return nil, nil
}
func (fzWaitRules) ListActive(context.Context) ([]store.XDropActiveRule, error) { return nil, nil }
func (r fzWaitAnns) ListActive(context.Context) ([]store.BGPAnnouncement, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return append([]store.BGPAnnouncement(nil), r.s.anns...), nil
}
func (r fzWaitAnns) ListAttacks(_ context.Context, id int) ([]store.BGPAnnouncementAttack, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	row := store.BGPAnnouncementAttack{AnnouncementID: id, AttackID: id}
	if r.s.detached[id] {
		now := time.Now()
		row.DetachedAt = &now
	}
	return []store.BGPAnnouncementAttack{row}, nil
}
func (r fzWaitAnns) ReconcileAttachments(_ context.Context, id int, ended []int, detach bool) (store.BGPReconcileResult, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if !detach || len(ended) != 1 || ended[0] != id {
		return store.BGPReconcileResult{}, fmt.Errorf("unexpected reconciliation: id=%d ended=%v detach=%v", id, ended, detach)
	}
	r.s.detached[id] = true
	r.s.anns[id-1].Refcount, r.s.anns[id-1].Status = 0, "withdrawing"
	return store.BGPReconcileResult{Detached: []int{id}, RefcountBefore: 1, NeedWithdraw: true}, nil
}
func (r fzWaitAnns) setStatus(id int, status string) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.anns[id-1].Status = status
}
func (r fzWaitAnns) MarkWithdrawn(_ context.Context, id int, gen int) error {
	r.setStatus(id, "withdrawn")
	r.s.finished <- id
	return nil
}
func (r fzWaitAnns) MarkFailedWithdraw(_ context.Context, id int, gen int, _ string) error {
	r.setStatus(id, "failed")
	r.s.finished <- id
	return nil
}
func (r fzWaitConns) Get(_ context.Context, id int) (*store.BGPConnector, error) {
	r.s.mu.Lock()
	r.s.queries[id]++
	n, gate, path := r.s.queries[id], r.s.gate, r.s.path
	r.s.mu.Unlock()
	if n == 2 && gate != nil {
		<-gate
	} // Async helper's query, after cleanup's query.
	return &store.BGPConnector{ID: id, Enabled: true, VtyshPath: path, BGPASN: 64512}, nil
}
func fzWaitCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func fzWaitQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func fzWaitNew(t *testing.T, n int, fifo string, gate <-chan struct{}) (*fzWaitStore, string) {
	t.Helper()
	dir := t.TempDir()
	output, script := filepath.Join(dir, "calls"), filepath.Join(dir, "vtysh")
	fzWaitCheck(t, os.WriteFile(output, nil, 0600))
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + fzWaitQuote(output) + "\n"
	if fifo != "" {
		body += "case \"$*\" in *192.0.2.71/32*) read release < " + fzWaitQuote(fifo) + " ;; esac\n"
	}
	fzWaitCheck(t, os.WriteFile(script, []byte(body+"exit 0\n"), 0700))
	s := &fzWaitStore{detached: map[int]bool{}, queries: map[int]int{}, path: script, gate: gate, finished: make(chan int, n)}
	for id := 1; id <= n; id++ {
		s.anns = append(s.anns, store.BGPAnnouncement{ID: id, Prefix: fmt.Sprintf("192.0.2.%d/32", 70+id), RouteMap: "RTBH", ConnectorID: id, Refcount: 1, Status: "active"})
	}
	return s, output
}
func (s *fzWaitStore) state(t *testing.T, id int, status string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.anns[id-1]
	if a.Refcount != 0 || a.Status != status || !s.detached[id] {
		t.Errorf("announcement %d: refcount=%d status=%s detached=%t; want 0/%s/true", id, a.Refcount, a.Status, s.detached[id], status)
	}
}
func fzWaitCalls(t *testing.T, path string, want int) {
	t.Helper()
	b, err := os.ReadFile(path)
	fzWaitCheck(t, err)
	if got := strings.Count(string(b), "no network"); got != want {
		t.Errorf("no network count=%d want=%d", got, want)
	}
}
func fzWaitCounter() float64 {
	return testutil.ToFloat64(metrics.StartupCleanup.WithLabelValues("bgp", "dispatched"))
}
func fzWaitLimit(t *testing.T) {
	t.Helper()
	old := cleanupWithdrawWait
	cleanupWithdrawWait = 200 * time.Millisecond
	t.Cleanup(func() { cleanupWithdrawWait = old })
}

func TestFuzhuo_G1_EndedWithdrawal(t *testing.T) {
	fzWaitLimit(t)
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		s, output := fzWaitNew(t, 1, "", gate)
		logs, before, start := dao6CaptureLog(t), fzWaitCounter(), time.Now()
		NewEngine(s, "auto").CleanupEndedAttachments(context.Background(), StartupScheduleSnapshot{}, nil)
		if elapsed := time.Since(start); elapsed != 200*time.Millisecond {
			t.Errorf("fake wait=%v want 200ms", elapsed)
		}
		s.state(t, 1, "withdrawing")
		if delta := fzWaitCounter() - before; delta != 1 {
			t.Errorf("dispatched delta=%v want 1", delta)
		}
		if text := logs.text(); strings.Count(text, "WARN") != 1 || !strings.Contains(text, "unfinished=1") {
			t.Errorf("timeout WARN: %s", text)
		}
		fzWaitCalls(t, output, 0)
		close(gate)
		synctest.Wait()
		s.state(t, 1, "withdrawn")
		fzWaitCalls(t, output, 1)
	})
}

func TestFuzhuo_G10_AsyncWithdrawDoesNotBlockStartup(t *testing.T) {
	fzWaitLimit(t)
	fifo := filepath.Join(t.TempDir(), "release")
	fzWaitCheck(t, unix.Mkfifo(fifo, 0600))
	gate, err := os.OpenFile(fifo, os.O_RDWR, 0600)
	fzWaitCheck(t, err)
	defer gate.Close()
	var once sync.Once
	release := func() { once.Do(func() { _, err := gate.WriteString("release\n"); fzWaitCheck(t, err) }) }
	defer release()
	s, output := fzWaitNew(t, 2, fifo, nil)
	logs, before := dao6CaptureLog(t), fzWaitCounter()
	done := make(chan struct{})
	go func() {
		NewEngine(s, "auto").CleanupEndedAttachments(context.Background(), StartupScheduleSnapshot{}, nil)
		close(done)
	}()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	select {
	case <-done:
	case <-deadline.C:
		release()
		<-done
		t.Fatal("CleanupEndedAttachments waited for blocked vtysh (5s deadline)")
	}
	if delta := fzWaitCounter() - before; delta != 2 {
		t.Errorf("dispatched delta=%v want 2", delta)
	}
	if text := logs.text(); strings.Count(text, "WARN") != 1 || !strings.Contains(text, "unfinished=") {
		t.Errorf("timeout WARN: %s", text)
	}
	s.state(t, 1, "withdrawing")
	release()
	for range 2 {
		select {
		case <-s.finished:
		case <-deadline.C:
			t.Fatal("withdrawal did not finish after FIFO release")
		}
	}
	s.state(t, 1, "withdrawn")
	s.state(t, 2, "withdrawn")
	fzWaitCalls(t, output, 2)
}
