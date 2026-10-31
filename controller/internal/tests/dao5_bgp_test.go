package tests

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
	"golang.org/x/sys/unix"
)

type dao5LogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *dao5LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *dao5LogBuffer) text() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func dao5CaptureLog(t *testing.T) *dao5LogBuffer {
	t.Helper()
	b := &dao5LogBuffer{}
	old := log.Writer()
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(old) })
	return b
}

type dao5BGPStore struct {
	*MockStore
	mu    sync.Mutex
	anns  *dao5BGPAnnouncements
	sched store.ScheduledActionRepo
}

func (s *dao5BGPStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.anns }
func (s *dao5BGPStore) ScheduledActions() store.ScheduledActionRepo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sched != nil {
		return s.sched
	}
	return s.MockStore.ScheduledActions()
}
func (s *dao5BGPStore) setSchedules(r store.ScheduledActionRepo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sched = r
}

type dao5BGPAnnouncements struct {
	store.BGPAnnouncementRepo
	mu                        sync.Mutex
	failWithdrawn, failFailed int
	onFailure                 func()
}

func (r *dao5BGPAnnouncements) inject(withdrawn, failed int, hook func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failWithdrawn, r.failFailed, r.onFailure = withdrawn, failed, hook
}

func (r *dao5BGPAnnouncements) stateWrite(ctx context.Context, failed bool, id, gen int, msg string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	n := &r.failWithdrawn
	if failed {
		n = &r.failFailed
	}
	fail := *n > 0
	if fail {
		*n--
	}
	hook := r.onFailure
	r.mu.Unlock()
	if fail {
		if hook != nil {
			hook()
		}
		return dao5Fault
	}
	if failed {
		return r.BGPAnnouncementRepo.MarkFailedWithdraw(ctx, id, gen, msg)
	}
	return r.BGPAnnouncementRepo.MarkWithdrawn(ctx, id, gen)
}
func (r *dao5BGPAnnouncements) MarkWithdrawn(ctx context.Context, id int, gen int) error {
	return r.stateWrite(ctx, false, id, gen, "")
}
func (r *dao5BGPAnnouncements) MarkFailedWithdraw(ctx context.Context, id int, gen int, msg string) error {
	return r.stateWrite(ctx, true, id, gen, msg)
}

type dao5ScheduleFailure struct {
	store.ScheduledActionRepo
	entered  chan struct{}
	deadline bool
}

func (r dao5ScheduleFailure) Schedule(ctx context.Context, _ *store.ScheduledAction) (int, error) {
	if r.entered != nil {
		close(r.entered)
	}
	if r.deadline {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 0, dao5Fault
}
func dao5BGPFixture(t *testing.T, delay int) (*dao5BGPStore, *action.Engine, tracker.AttackEvent, *store.BGPConnector, int) {
	t.Helper()
	ms, _, ev := dao4Fixture("bgp", "once", "on_expired")
	ms.responses.actions[0].BGPConnectorID = intPtr(7)
	ms.responses.actions[0].BGPRouteMap = "RTBH"
	conn := &store.BGPConnector{ID: 7, Name: "dao5", Enabled: true, VtyshPath: "/usr/bin/true", BGPASN: 64512}
	ms.bgpConnectors.connectors = []store.BGPConnector{*conn}
	s := &dao5BGPStore{MockStore: ms, anns: &dao5BGPAnnouncements{BGPAnnouncementRepo: ms.BGPAnnouncements()}}
	result, err := s.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 20, ActionID: intPtr(10), DelayMinutes: delay})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BGPAnnouncements().MarkAnnounced(context.Background(), result.AnnouncementID, dao5bCurrentGen(t, s.BGPAnnouncements(), result.AnnouncementID)); err != nil {
		t.Fatal(err)
	}
	ev.Type = "expired"
	return s, action.NewEngine(s, "auto"), ev, conn, result.AnnouncementID
}
func dao5AttachNew(t *testing.T, s store.Store, id int) {
	t.Helper()
	r, err := s.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21, ActionID: intPtr(10)})
	if err != nil || r.AnnouncementID != id {
		t.Fatalf("new Attach=%+v err=%v", r, err)
	}
	if r.NeedAnnounce {
		if err := s.BGPAnnouncements().MarkAnnounced(context.Background(), id, r.Gen); err != nil {
			t.Fatal(err)
		}
	}
	dao5Active(t, s, id)
}
func dao5Active(t *testing.T, s store.Store, id int) {
	t.Helper()
	row, err := s.BGPAnnouncements().Get(context.Background(), id)
	if err != nil || row.Status != "active" || row.Refcount != 1 {
		t.Fatalf("new lifecycle overwritten: row=%+v err=%v; want active/refcount=1", row, err)
	}
}
func dao5BGPError(t *testing.T, b *dao5LogBuffer, id int) {
	t.Helper()
	output := b.text()
	if !strings.Contains(output, "ERROR") || !strings.Contains(output, fmt.Sprintf("announcement_id=%d", id)) {
		t.Errorf("missing ERROR with announcement_id: %s", output)
	}
}

// A real, independently controlled process: the first invocation signals via
// FIFO then blocks opening a different FIFO. Later invocations exit normally.
// There is no shared process lock, sleep, network, or fake-time process kill.
func dao5BlockedVtysh(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	dir := t.TempDir()
	entered := make(chan struct{})
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	ready, block := filepath.Join(dir, "ready"), filepath.Join(dir, "block")
	for _, p := range []string{ready, block} {
		if err := unix.Mkfifo(p, 0600); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		f, err := os.Open(ready)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()
		_, err = io.ReadAll(f)
		if err != nil {
			t.Error(err)
		}
		close(entered)
	}()
	script := filepath.Join(dir, "vtysh")
	body := "#!/bin/sh\nif mkdir " + quote(filepath.Join(dir, "first")) + " 2>/dev/null; then\n printf entered > " + quote(ready) + "\n read gate < " + quote(block) + "\nfi\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	return script, entered
}
func TestDao5_A6b_VtyshDeadlineIsObservable(t *testing.T) {
	s, _, _, conn, id := dao5BGPFixture(t, 0)
	_, gen, err := s.BGPAnnouncements().ForceWithdraw(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	path, entered := dao5BlockedVtysh(t)
	conn.VtyshPath = path
	b := dao5CaptureLog(t)
	metric := dao5Metrics(t, s, nil)
	before := metric("bgp_ann_state")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := action.PerformBGPWithdrawForOrphan(ctx, s, conn, store.ResponseAction{}, "192.0.2.10/32", "RTBH", id, gen)
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("fake vtysh did not enter before deadline")
	}
	if err := <-done; err == nil {
		t.Error("blocked vtysh succeeded")
	}
	row, _ := s.BGPAnnouncements().Get(context.Background(), id)
	if row.Status != "failed" {
		t.Errorf("deadline state=%s; want failed", row.Status)
	}
	if delta := metric("bgp_ann_state") - before; delta != 0 {
		t.Errorf("bgp_ann_state delta=%v; want 0", delta)
	}
	if strings.Contains(b.text(), "ERROR") {
		t.Errorf("unexpected ERROR: %s", b.text())
	}
}
func TestDao5_A6c_SuccessLogRetainsStateWriteError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, ev, _, id := dao5BGPFixture(t, 0)
		s.anns.inject(3, 0, nil)
		b := dao5CaptureLog(t)
		metric := dao5Metrics(t, s, nil)
		before := metric("bgp_ann_state")
		e.HandleEvent(ev)
		synctest.Wait()
		logs := s.actionExecLog.snapshotLogs()
		if len(logs) != 1 || logs[0].Status != "success" || !strings.Contains(logs[0].ErrorMessage, "state write failed") {
			t.Errorf("saved execution log=%+v; want success with state write failed", logs)
		}
		if delta := metric("bgp_ann_state") - before; delta != 1 {
			t.Errorf("bgp_ann_state delta=%v; want 1", delta)
		}
		dao5BGPError(t, b, id)
	})
}
func TestDao5_A6d_DelayedCompensationFailureVisible(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, ev, _, id := dao5BGPFixture(t, 1)
		s.setSchedules(dao5ScheduleFailure{ScheduledActionRepo: s.MockStore.ScheduledActions()})
		s.anns.inject(0, 3, nil)
		b := dao5CaptureLog(t)
		metric := dao5Metrics(t, s, nil)
		before := metric("bgp_ann_state")
		e.HandleEvent(ev)
		synctest.Wait()
		if delta := metric("bgp_ann_state") - before; delta != 1 {
			t.Errorf("bgp_ann_state delta=%v; want 1", delta)
		}
		dao5BGPError(t, b, id)
	})
}
func TestDao5_A6e_CompensationRetriesUntilStale(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, ev, _, id := dao5BGPFixture(t, 1)
		s.setSchedules(dao5ScheduleFailure{ScheduledActionRepo: s.MockStore.ScheduledActions()})
		s.anns.inject(0, 1, func() { dao5AttachNew(t, s, id) })
		r := &dao5bObservedRepo{BGPAnnouncementRepo: s.anns}
		done := make(chan store.ActionExecutionLog, 10)
		wrapped := dao5bLogStore{dao5bStore{Store: s, anns: r}, dao5bLogRepo{s.ActionExecLog(), done}}
		e := action.NewEngine(wrapped, "auto")
		e.HandleEvent(ev)
		<-done
		synctest.Wait()
		if writes := r.snapshot("failed_withdraw"); len(writes) != 2 {
			t.Errorf("compensation attempts=%d; want transient error then stale (2)", len(writes))
		}
		dao5Active(t, s, id)
	})
}
func TestDao5_A6f_CompensationUsesFreshContextAndGeneration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, _, ev, _, id := dao5BGPFixture(t, 1)
		s.bgpAnnouncements.announcements[0].Gen = 7
		entered := make(chan struct{})
		s.setSchedules(dao5ScheduleFailure{ScheduledActionRepo: s.MockStore.ScheduledActions(), entered: entered, deadline: true})
		r := &dao5bObservedRepo{BGPAnnouncementRepo: s.anns}
		done := make(chan store.ActionExecutionLog, 10)
		wrapped := dao5bLogStore{dao5bStore{Store: s, anns: r}, dao5bLogRepo{s.ActionExecLog(), done}}
		e := action.NewEngine(wrapped, "auto")
		e.HandleEvent(ev)
		<-entered
		dao5AttachNew(t, s, id)
		<-done
		synctest.Wait()
		writes := r.snapshot("failed_withdraw")
		if len(writes) != 1 || writes[0].gen != 7 || writes[0].ctxErr != nil || writes[0].budget <= 0 || writes[0].budget > 5*time.Second {
			t.Errorf("compensation writes=%+v; want one fresh 5s context with gen=7", writes)
		}
		dao5Active(t, s, id)
	})
}
func TestDao5_A6g_ParallelWithdrawCannotOverwriteNewLifecycle(t *testing.T) {
	s, e, _, conn, id := dao5BGPFixture(t, 0)
	_, gen, err := s.BGPAnnouncements().ForceWithdraw(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	path, entered := dao5BlockedVtysh(t)
	conn.VtyshPath = path
	if err := s.BGPConnectors().Update(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := action.PerformBGPWithdrawForOrphan(ctx, s, conn, store.ResponseAction{}, "192.0.2.10/32", "RTBH", id, gen)
		done <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("W1 did not enter")
	}
	if err := e.ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH"); err != nil {
		t.Fatal(err)
	}
	row, _ := s.BGPAnnouncements().Get(context.Background(), id)
	if row.Status != "withdrawn" {
		t.Fatalf("W2 state=%s; want withdrawn", row.Status)
	}
	dao5AttachNew(t, s, id)
	if err := <-done; err == nil {
		t.Error("W1 unexpectedly succeeded")
	}
	dao5Active(t, s, id)
}

type dao5ForceWriteStore struct{ *dao5BGPStore }
type dao5FailedOverrides struct{ store.ActionManualOverrideRepo }

func (r dao5FailedOverrides) Create(ctx context.Context, _ *store.ActionManualOverride) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 0, dao5Fault
}

type dao5FailedExecLogs struct{ store.ActionExecLogRepo }

func (r dao5FailedExecLogs) Create(ctx context.Context, _ *store.ActionExecutionLog) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return 0, dao5Fault
}
func (s dao5ForceWriteStore) ManualOverrides() store.ActionManualOverrideRepo {
	return dao5FailedOverrides{s.dao5BGPStore.ManualOverrides()}
}
func (s dao5ForceWriteStore) ActionExecLog() store.ActionExecLogRepo {
	return dao5FailedExecLogs{s.dao5BGPStore.ActionExecLog()}
}

func TestDao5_F2_BGPAttachmentWriteFailuresObservable(t *testing.T) {
	base, _, _, _, id := dao5BGPFixture(t, 0)
	s := dao5ForceWriteStore{base}
	metric := dao5Metrics(t, s, nil)
	before := metric("force_remove_override")
	b := dao5CaptureLog(t)
	if err := action.NewEngine(s, "auto").ForceRemove(context.Background(), 20, 10, 7, "192.0.2.10/32|RTBH"); err != nil {
		t.Fatalf("override/log failure changed removal return: %v", err)
	}
	if delta := metric("force_remove_override") - before; delta != 2 {
		t.Errorf("two attached-claim writes: force_remove_override delta=%v; want 2", delta)
	}
	for _, message := range []string{"ERROR action: bgp manual_override index", "ERROR action: bgp manual_override log"} {
		if !strings.Contains(b.text(), message) {
			t.Errorf("missing %q in %s", message, b.text())
		}
	}
	row, err := s.BGPAnnouncements().Get(context.Background(), id)
	if err != nil || row.Status != "withdrawn" {
		t.Fatalf("override failure prevented withdraw: row=%+v err=%v", row, err)
	}
}
