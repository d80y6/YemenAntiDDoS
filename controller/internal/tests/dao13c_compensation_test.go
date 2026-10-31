package tests

import (
	"context"
	"errors"
	"fmt"
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
)

type dao13cWrite struct {
	id, gen int
	ctxErr  error
	budget  time.Duration
}

type dao13cCompensation struct {
	store.BGPAnnouncementRepo
	mu        sync.Mutex
	writes    []dao13cWrite
	id, gen   int
	shared    bool
	failures  int
	stale     bool
	callerCtx chan context.Context
}

func (r *dao13cCompensation) Attach(c context.Context, p store.BGPAttachParams) (store.BGPAttachResult, error) {
	result, err := r.BGPAnnouncementRepo.Attach(c, p)
	if err != nil {
		return result, err
	}
	r.mu.Lock()
	r.id, r.gen = result.AnnouncementID, result.Gen
	r.mu.Unlock()
	if r.shared && result.NeedAnnounce {
		p.AttackID = 21
		if _, err := r.BGPAnnouncementRepo.Attach(c, p); err != nil {
			return result, err
		}
	}
	if r.callerCtx != nil {
		r.callerCtx <- c
	}
	return result, nil
}

func (r *dao13cCompensation) MarkFailedAnnounce(c context.Context, id, gen int, msg string) error {
	deadline, _ := c.Deadline()
	r.mu.Lock()
	r.writes = append(r.writes, dao13cWrite{id, gen, c.Err(), time.Until(deadline)})
	n := len(r.writes)
	r.mu.Unlock()
	if r.stale {
		return store.ErrStaleAnnouncement
	}
	if n <= r.failures {
		return errors.New("compensation unavailable")
	}
	if err := c.Err(); err != nil {
		return err
	}
	return r.BGPAnnouncementRepo.MarkFailedAnnounce(c, id, gen, msg)
}

func (r *dao13cCompensation) snapshot() ([]dao13cWrite, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]dao13cWrite(nil), r.writes...), r.id, r.gen
}

func TestDao13c_P1_Definite(t *testing.T) {
	for _, branch := range []string{"OrdinaryVtysh", "StartupLookup", "StartupToken", "StartupVtysh"} {
		t.Run(branch, func(t *testing.T) {
			outcomes := []string{"SingleDeleted", "SharedFailed", "ThirdAttemptSucceeds", "Exhausted", "StaleStops"}
			if branch != "OrdinaryVtysh" {
				outcomes = []string{"SingleDeleted", "SharedFailed"}
			}
			for _, outcome := range outcomes {
				t.Run(outcome, func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						f := dao11jNew(t)
						f.set("announcing", 0)
						r := &dao13cCompensation{BGPAnnouncementRepo: f.base.anns, id: f.id, gen: 0}
						switch outcome {
						case "SharedFailed":
							r.shared = true
						case "ThirdAttemptSucceeds":
							r.failures = 2
						case "Exhausted":
							r.failures = 3
						case "StaleStops":
							r.stale = true
						}
						ordinary := branch == "OrdinaryVtysh"
						if ordinary {
							dao5bCheck(t, f.base.anns.MarkFailedAnnounce(context.Background(), f.id, 0, "fresh fixture reset"))
						} else if r.shared {
							_, err := f.base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21})
							dao5bCheck(t, err)
						}
						if branch == "StartupLookup" {
							f.c.before = func(int64) error { return errors.New("connector lookup unavailable") }
						} else if branch == "StartupToken" {
							f.base.bgpAnnouncements.announcements[0].RouteMap = "RTBH invalid"
						} else {
							dao5bCheck(t, os.WriteFile(f.failPath, nil, 0600))
						}
						s := dao13cStore{dao11jStore{f.base, f.r, f.c, f.sched}, r}
						metric := dao5bMetrics(t, s)
						failureBefore := metric(dao5bFailureMetric, "bgp_ann_state")
						staleBefore := metric(dao5bStaleMetric, "failed_announce")
						logs := dao5CaptureLog(t)
						beforeRow, _ := f.base.anns.Get(context.Background(), f.id)
						beforeAttacks, _ := f.base.anns.ListAttacks(context.Background(), f.id)
						vtyshBefore := dao13dVtyshFailed()
						e := action.NewEngine(s, "auto")
						if ordinary {
							ev := f.ev
							ev.Type = "confirmed"
							e.HandleEvent(ev)
						} else {
							e.ReconcileOnStartup(context.Background())
						}
						synctest.Wait()
						writes, id, gen := r.snapshot()
						if !ordinary {
							reason := map[string]string{"StartupLookup": "connector lookup unavailable", "StartupToken": "unsafe vtysh token", "StartupVtysh": "exit status 1"}[branch]
							dao13dRetryAssert(t, f.base, id, beforeRow, beforeAttacks, logs.text(), len(writes), metric(dao5bFailureMetric, "bgp_ann_state")-failureBefore, reason)
							if branch == "StartupVtysh" {
								dao11jWant(t, "P1.Startup.VtyshFailedDelta", dao13dVtyshFailed()-vtyshBefore, float64(1))
							}
						} else {
							wantCalls := 1
							if outcome == "ThirdAttemptSucceeds" || outcome == "Exhausted" {
								wantCalls = 3
							}
							dao11jWant(t, "P1."+branch+"."+outcome+".Calls", len(writes), wantCalls)
							for _, write := range writes {
								dao11jWant(t, "P1."+branch+".FreshContext", write.ctxErr == nil && write.budget > 0 && write.budget <= 5*time.Second, true)
								dao11jWant(t, "P1."+branch+".OriginalID", write.id, id)
								dao11jWant(t, "P1."+branch+".OriginalGen", write.gen, gen)
							}
							row, err := f.base.anns.Get(context.Background(), id)
							dao5bCheck(t, err)
							if outcome == "SharedFailed" {
								dao11jWant(t, "P1.Shared.Failed", row != nil && row.Status == "failed" && row.Refcount == 2, true)
							} else if outcome == "Exhausted" || outcome == "StaleStops" {
								dao11jWant(t, "P1.Unapplied.Retained", row != nil && row.Status == "announcing", true)
							} else {
								dao11jWant(t, "P1.Single.Deleted", row == nil, true)
							}
							wantFailure, wantStale := float64(0), float64(0)
							if outcome == "Exhausted" {
								wantFailure = 1
								dao11jWant(t, "P1.Exhausted.ErrorLog", strings.Contains(logs.text(), "ERROR") && strings.Contains(logs.text(), fmt.Sprintf("announcement_id=%d", id)), true)
							}
							if outcome == "StaleStops" {
								wantStale = 1
							}
							dao11jWant(t, "P1.Exhausted.MetricDelta", metric(dao5bFailureMetric, "bgp_ann_state")-failureBefore, wantFailure)
							dao11jWant(t, "P1.Stale.MetricDelta", metric(dao5bStaleMetric, "failed_announce")-staleBefore, wantStale)

						}
						if strings.HasPrefix(branch, "Startup") {
							dao11jWant(t, "P1.Startup.NoExecutionLogs", len(f.base.actionExecLog.snapshotLogs()), 0)
						}
						if branch == "StartupLookup" || branch == "StartupToken" {
							dao11jWant(t, "P1.BeforeVtysh.NoCommands", dao4Read(t, f.record), "")
						}
					})
				})
			}
		})
	}
}

// These timeout cases deliberately use the real 30-second action deadline.
func dao13cUnknown(t *testing.T, applied bool) {
	t.Helper()
	f := dao11jNew(t)
	f.set("announcing", 0)
	dao5bCheck(t, f.base.anns.MarkFailedAnnounce(context.Background(), f.id, 0, "fresh fixture reset"))
	body := "sleep 60 &\nwait"
	if applied {
		conn, err := f.base.BGPConnectors().Get(context.Background(), 7)
		dao5bCheck(t, err)
		body = dao13cQuote(conn.VtyshPath) + " \"$@\"\n" + body
	}
	path := dao13cProcess(t, body)
	conn, err := f.base.BGPConnectors().Get(context.Background(), 7)
	dao5bCheck(t, err)
	conn.VtyshPath = path
	dao5bCheck(t, f.base.BGPConnectors().Update(context.Background(), conn))
	r := &dao13cCompensation{BGPAnnouncementRepo: f.base.anns}
	done := make(chan store.ActionExecutionLog, 4)
	s := dao5bLogStore{dao5bStore{Store: f.base, anns: r}, dao5bLogRepo{f.base.ActionExecLog(), done}}
	e := action.NewEngine(s, "auto")
	ev := f.ev
	ev.Type = "confirmed"
	logs := dao5CaptureLog(t)
	var entry store.ActionExecutionLog
	// The child is killed and joined after the action deadline, even on HEAD.
	dao13cAwait(t, path, 35*time.Second, func() { e.HandleEvent(ev); entry = <-done })
	writes, id, _ := r.snapshot()
	dao11jWant(t, "P1.Unknown.NoCompensation", len(writes), 0)
	row, err := f.base.anns.Get(context.Background(), id)
	dao5bCheck(t, err)
	dao11jWant(t, "P1.Unknown.KeepsAnnouncing", row != nil && row.Status == "announcing" && row.Refcount == 1, true)
	attachments, err := f.base.anns.ListAttacks(context.Background(), id)
	dao5bCheck(t, err)
	dao11jWant(t, "P1.Unknown.KeepsAttachment", len(attachments) == 1 && attachments[0].DetachedAt == nil, true)
	for _, text := range []string{"WARN", "outcome unknown (ctx ended)", fmt.Sprintf("announcement_id=%d", id), "prefix=192.0.2.10/32", "route_map=RTBH"} {
		dao11jWant(t, "P1.Unknown.Warning."+text, strings.Contains(logs.text(), text), true)
	}
	// This mock ignores the log context; TestDao14c2_E1/BGP.Unknown verifies it.
	dao11jWant(t, "P1.Unknown.ExecutionLog", entry.Status == "failed" && strings.Contains(entry.ErrorMessage, "outcome unknown"), true)
	record, err := os.ReadFile(filepath.Join(filepath.Dir(path), "calls"))
	dao5bCheck(t, err)
	dao11jWant(t, "P1.Unknown.AttemptedAnnounce", strings.Contains(string(record), "network 192.0.2.10/32 route-map RTBH"), true)
	applyRecord := dao4Read(t, f.record)
	dao11jWant(t, "P1.Unknown.AppliedMarker", strings.Contains(applyRecord, "network 192.0.2.10/32 route-map RTBH"), applied)
}

func TestDao13c_P1_Unknown(t *testing.T) {
	t.Run("AppliedThenTimeout.KeepsOwnership", func(t *testing.T) { dao13cUnknown(t, true) })
	t.Run("TimeoutBeforeApply.KeepsAnnouncing", func(t *testing.T) { dao13cUnknown(t, false) })
	t.Run("StartupAppliedThenTimeout.KeepsOwnership", dao13cStartupUnknown)
}

type dao13cStartupConnector struct {
	store.BGPConnectorRepo
	seen chan context.Context
}

func (r dao13cStartupConnector) Get(c context.Context, id int) (*store.BGPConnector, error) {
	r.seen <- c
	return r.BGPConnectorRepo.Get(c, id)
}

type dao13cStartupStore struct {
	store.Store
	conn store.BGPConnectorRepo
}

func (s dao13cStartupStore) BGPConnectors() store.BGPConnectorRepo { return s.conn }

type dao13cStartupCompensation struct {
	*dao13cCompensation
	complete func()
}

func (r dao13cStartupCompensation) MarkFailedAnnounce(c context.Context, id, gen int, msg string) error {
	defer r.complete()
	return r.dao13cCompensation.MarkFailedAnnounce(c, id, gen, msg)
}

type dao13cStartupLog struct {
	*dao5LogBuffer
	terminal string
	complete func()
}

func (w dao13cStartupLog) Write(p []byte) (int, error) {
	n, err := w.dao5LogBuffer.Write(p)
	if strings.Contains(string(p), w.terminal) {
		w.complete()
	}
	return n, err
}

// The public startup path uses its real 30-second vtysh context. The terminal
// warning (or the mutation's completed compensation) occurs after runVtysh has
// joined its command. dao13cAwait also joins our waiting fixture and kills every
// recorded process that inherited an output pipe.
func dao13cStartupUnknown(t *testing.T) {
	f := dao11jNew(t)
	f.set("announcing", 0)
	c := context.Background()
	original := f.row(t)
	conn, err := f.base.BGPConnectors().Get(c, original.ConnectorID)
	dao5bCheck(t, err)
	// Replace the wrapper with the blocking process so this context test
	// does not wait on an unrelated descendant's inherited output pipe.
	path := dao13cProcess(t, dao13cQuote(conn.VtyshPath)+" \"$@\"\nexec sleep 60")
	conn.VtyshPath = path
	dao5bCheck(t, f.base.BGPConnectors().Update(c, conn))
	recorded := &dao13cCompensation{BGPAnnouncementRepo: f.base.anns, id: original.ID, gen: original.Gen}
	finished := make(chan struct{})
	var once sync.Once
	complete := func() { once.Do(func() { close(finished) }) }
	caller := make(chan context.Context, 1)
	s := dao13cStartupStore{
		dao13cStore{f.base, dao13cStartupCompensation{recorded, complete}},
		dao13cStartupConnector{f.base.BGPConnectors(), caller},
	}
	e := action.NewEngine(s, "auto")
	logs := &dao5LogBuffer{}
	oldWriter := log.Writer()
	log.SetOutput(dao13cStartupLog{logs, fmt.Sprintf("outcome unknown (ctx ended) announcement_id=%d", original.ID), complete})
	defer log.SetOutput(oldWriter)
	beforeLogs := len(f.base.actionExecLog.snapshotLogs())
	observedTerminal := false
	var callCtx context.Context
	_, timely := dao13cAwait(t, path, 35*time.Second, func() {
		e.ReconcileOnStartup(c)
		callCtx = <-caller
		select {
		case <-finished:
			observedTerminal = true
		case <-time.After(34 * time.Second):
		}
	})
	writes, id, gen := recorded.snapshot()
	t.Logf("RESULT P1.StartupUnknown original_id=%d original_gen=%d compensation_calls=%d execution_logs_before=%d execution_logs_after=%d",
		original.ID, original.Gen, len(writes), beforeLogs, len(f.base.actionExecLog.snapshotLogs()))
	for _, write := range writes {
		t.Logf("RESULT P1.StartupUnknown compensation_id=%d compensation_gen=%d ctx_error=%v budget=%s", write.id, write.gen, write.ctxErr, write.budget)
		dao11jWant(t, "P1.StartupUnknown.CompensationOriginalID", write.id, original.ID)
		dao11jWant(t, "P1.StartupUnknown.CompensationOriginalGen", write.gen, original.Gen)
	}
	dao11jWant(t, "P1.StartupUnknown.Bounded", timely && observedTerminal, true)
	dao11jWant(t, "P1.StartupUnknown.CallerDeadlineEnded", errors.Is(callCtx.Err(), context.DeadlineExceeded), true)
	dao11jWant(t, "P1.StartupUnknown.OriginalID", id, original.ID)
	dao11jWant(t, "P1.StartupUnknown.OriginalGen", gen, original.Gen)
	dao11jWant(t, "P1.StartupUnknown.NoCompensation", len(writes), 0)
	row, err := f.base.anns.Get(c, original.ID)
	dao5bCheck(t, err)
	dao11jWant(t, "P1.StartupUnknown.KeepsOwnership", row != nil && row.ID == original.ID && row.Gen == original.Gen && row.Status == "announcing" && row.Refcount == original.Refcount, true)
	attachments, err := f.base.anns.ListAttacks(c, original.ID)
	dao5bCheck(t, err)
	dao11jWant(t, "P1.StartupUnknown.KeepsAttachment", len(attachments) == 1 && attachments[0].DetachedAt == nil, true)
	for _, text := range []string{"WARN", "outcome unknown (ctx ended)", fmt.Sprintf("announcement_id=%d", original.ID), "prefix=" + original.Prefix, "route_map=" + original.RouteMap} {
		dao11jWant(t, "P1.StartupUnknown.Warning."+text, strings.Contains(logs.text(), text), true)
	}
	dao11jWant(t, "P1.StartupUnknown.NoExecutionLogs", len(f.base.actionExecLog.snapshotLogs())-beforeLogs, 0)
	dao11jWant(t, "P1.StartupUnknown.AppliedMarker", strings.Contains(dao4Read(t, f.record), "network "+original.Prefix+" route-map "+original.RouteMap), true)
}
