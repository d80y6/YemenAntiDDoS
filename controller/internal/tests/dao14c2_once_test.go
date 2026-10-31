package tests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao14c2Barrier struct {
	calls            atomic.Int32
	entered, release chan struct{}
}

func dao14c2NewBarrier() *dao14c2Barrier {
	return &dao14c2Barrier{entered: make(chan struct{}), release: make(chan struct{})}
}
func (b *dao14c2Barrier) hit() {
	if b.calls.Add(1) == 1 {
		close(b.entered)
		<-b.release
	}
}

type dao14c2Attach struct {
	store.BGPAnnouncementRepo
	before func()
}

func (r dao14c2Attach) Attach(ctx context.Context, p store.BGPAttachParams) (store.BGPAttachResult, error) {
	if r.before != nil {
		r.before()
	}
	return r.BGPAnnouncementRepo.Attach(ctx, p)
}

type dao14c2NotifyLogs struct {
	store.ActionExecLogRepo
	done   chan struct{}
	before func(*store.ActionExecutionLog) error
}

func (r dao14c2NotifyLogs) Create(ctx context.Context, row *store.ActionExecutionLog) (int, error) {
	defer func() { r.done <- struct{}{} }()
	if r.before != nil {
		if err := r.before(row); err != nil {
			return 0, err
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return r.ActionExecLogRepo.Create(ctx, row)
}
func dao14c2Join(done <-chan struct{}, n int) {
	for i := 0; i < n; i++ {
		<-done
	}
	synctest.Wait()
}

func dao14c2Inflight(t *testing.T, kind, mode, phase, policy, first, second string) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, ev := dao4Fixture(kind, mode, phase)
		ev.Type = first
		ms.responses.actions[0].ExecutionPolicy = policy
		b := dao14c2NewBarrier()
		done := make(chan struct{}, 8)
		s := dao14c2Store{Store: ms, logs: dao14c2NotifyLogs{ActionExecLogRepo: ms.ActionExecLog(), done: done}}
		switch kind {
		case "webhook":
			d.handler = func(*http.Request) int { b.hit(); return 200 }
		case "shell":
			ms.responses.actions[0].ShellConnectorID = intPtr(7)
			s.shell = dao14c2Shell{before: b.hit, enabled: true}
		case "bgp":
			dao14c2BGP(ms)
			s.anns = dao14c2Attach{ms.BGPAnnouncements(), b.hit}
		}
		e := action.NewEngine(s, "auto")
		e.HandleEvent(ev)
		<-b.entered
		synctest.Wait()
		ev.Type = second
		e.HandleEvent(ev)
		close(b.release)
		dao14c2Join(done, 2)
		rows := ms.actionExecLog.snapshotLogs()
		var skips []store.ActionExecutionLog
		nonSkip := 0
		for _, row := range rows {
			if row.Status == "skipped" {
				skips = append(skips, row)
			} else {
				nonSkip++
			}
		}
		dao14c2Want(t, "SideEffects", b.calls.Load() == 1, b.calls.Load())
		dao14c2Want(t, "Rows", len(rows) == 2 && len(skips) == 1 && nonSkip == 1, rows)
		dao14c2Want(t, "Reason", len(skips) == 1 && skips[0].SkipReason == action.SkipReasonAlreadyExecuted, skips)
		dao14c2Want(t, "Detail", len(skips) == 1 && strings.Contains(skips[0].ErrorMessage, "in flight"), skips)
		dao14c2Want(t, "Phase", len(skips) == 1 && skips[0].TriggerPhase == phase, skips)
	})
}
func TestDao14c2_O1(t *testing.T) {
	for _, kind := range []string{"Webhook", "Shell", "BGP"} {
		t.Run("Once.Inflight."+kind, func(t *testing.T) {
			dao14c2Inflight(t, strings.ToLower(kind), "once", "on_detected", "", "confirmed", "type_upgrade")
		})
	}
}
func TestDao14c2_O2(t *testing.T) {
	for _, event := range []string{"type_upgrade", "updated"} {
		t.Run("Retry.Inflight."+event, func(t *testing.T) {
			dao14c2Inflight(t, "webhook", "retry_until_success", "on_detected", "", "confirmed", event)
		})
	}
}
func TestDao14c2_O3(t *testing.T) {
	t.Run("Once.OnExpired.Inflight", func(t *testing.T) { dao14c2Inflight(t, "webhook", "once", "on_expired", "", "expired", "expired") })
}
func TestDao14c2_O4(t *testing.T) {
	// Normal writes reject empty TriggerPhase (validation and migration default).
	// Manual SQL can still create it; the approved scope includes these policies.
	for _, policy := range []string{"once_on_enter", "retry_until_success", "once_on_exit"} {
		t.Run("Legacy."+policy+".Inflight", func(t *testing.T) {
			first, second := "confirmed", "type_upgrade"
			if policy == "once_on_exit" {
				first, second = "expired", "expired"
			}
			dao14c2Inflight(t, "webhook", "", "", policy, first, second)
		})
	}
}

func TestDao14c2_O5(t *testing.T) {
	t.Run("Barrier.LogNotYetWritten", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			d := dao4HTTP(t)
			ms, _, ev := dao4Fixture("webhook", "once", "on_detected")
			b := dao14c2NewBarrier()
			done := make(chan struct{}, 8)
			r := dao14c2NotifyLogs{ActionExecLogRepo: ms.ActionExecLog(), done: done, before: func(row *store.ActionExecutionLog) error {
				if row.Status == "success" {
					b.hit()
				}
				return nil
			}}
			e := action.NewEngine(dao14c2Store{Store: ms, logs: r}, "auto")
			e.HandleEvent(ev)
			<-b.entered
			// Drain the action before redispatch: MF2 releases its count here.
			synctest.Wait()
			dao14c2Want(t, "Device", len(ms.actionExecLog.snapshotLogs()) == 0 && d.count() == 1, ms.actionExecLog.snapshotLogs())
			ev.Type = "type_upgrade"
			e.HandleEvent(ev)
			close(b.release)
			dao14c2Join(done, 2)
			dao14c2Want(t, "SideEffects", d.count() == 1, d.count())
			rows := ms.actionExecLog.snapshotLogs()
			found := false
			for _, row := range rows {
				found = found || row.Status == "skipped" && row.SkipReason == action.SkipReasonAlreadyExecuted && strings.Contains(row.ErrorMessage, "in flight")
			}
			dao14c2Want(t, "Reason", found, rows)
		})
	})
}

type dao14c2QueryLogs struct {
	store.ActionExecLogRepo
	calls           atomic.Int32
	calculated, ret chan struct{}
	result          bool
	err             error
	rowsBefore      int
}

func (r *dao14c2QueryLogs) AllTargetsDone(ctx context.Context, a, b int, phase string) (bool, error) {
	result, err := r.ActionExecLogRepo.AllTargetsDone(ctx, a, b, phase)
	if r.calls.Add(1) == 2 {
		rows, _ := r.ActionExecLogRepo.ListByAttack(ctx, a)
		r.rowsBefore = len(rows)
		r.result = result
		r.err = err
		close(r.calculated)
		<-r.ret
	}
	return result, err
}

type dao14c2LegacyQueryLogs struct {
	store.ActionsLogRepo
	calls           atomic.Int32
	calculated, ret chan struct{}
	result          *store.ActionLog
	err             error
}

func (r *dao14c2LegacyQueryLogs) FindByAttackAndAction(ctx context.Context, attackID, actionID int) (*store.ActionLog, error) {
	result, err := r.ActionsLogRepo.FindByAttackAndAction(ctx, attackID, actionID)
	if r.calls.Add(1) == 2 {
		r.result, r.err = result, err
		close(r.calculated)
		<-r.ret
	}
	return result, err
}

type dao14c2QueryStore struct {
	dao14c2Store
	legacy store.ActionsLogRepo
}

func (s dao14c2QueryStore) ActionsLog() store.ActionsLogRepo {
	if s.legacy != nil {
		return s.legacy
	}
	return s.dao14c2Store.ActionsLog()
}

func TestDao14c2_O8(t *testing.T) {
	for _, tc := range []struct {
		name, mode, policy, first, second string
	}{
		{"V2.once", "once", "", "confirmed", "type_upgrade"},
		{"V2.retry_until_success", "retry_until_success", "", "confirmed", "type_upgrade"},
		{"Legacy.once_on_enter", "", "once_on_enter", "confirmed", "type_upgrade"},
		{"Legacy.once_on_exit", "", "once_on_exit", "expired", "expired"},
		{"Legacy.retry_until_success", "", "retry_until_success", "confirmed", "type_upgrade"},
	} {
		t.Run("Barrier.QueryThenRelease."+tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := dao4HTTP(t)
				ms, _, ev := dao4Fixture("webhook", tc.mode, "on_detected")
				ev.Type = tc.first
				if tc.policy != "" {
					ms.responses.actions[0].TriggerPhase = ""
					ms.responses.actions[0].ExecutionPolicy = tc.policy
				}
				b := dao14c2NewBarrier()
				d.handler = func(*http.Request) int { b.hit(); return 200 }
				calculated, ret := make(chan struct{}), make(chan struct{})
				r := &dao14c2QueryLogs{ActionExecLogRepo: ms.ActionExecLog(), calculated: calculated, ret: ret}
				legacy := &dao14c2LegacyQueryLogs{ActionsLogRepo: ms.ActionsLog(), calculated: calculated, ret: ret}
				s := dao14c2QueryStore{dao14c2Store: dao14c2Store{Store: ms}}
				if tc.policy == "" {
					s.logs = r
				} else {
					// Every legacy policy queries ActionsLog first; legacy retry never
					// queries AllTargetsDone. Legacy once also checks a phase that
					// differs from the raw event phase in its execution log.
					s.legacy = legacy
				}
				e := action.NewEngine(s, "auto")
				e.HandleEvent(ev)
				<-b.entered
				ev.Type = tc.second
				returned := make(chan struct{})
				go func() { e.HandleEvent(ev); close(returned) }()
				<-calculated
				rowsBefore := len(ms.actionExecLog.snapshotLogs())
				queryOK := r.calls.Load() == 2 && !r.result && r.err == nil && r.rowsBefore == 0
				if tc.policy != "" {
					queryOK = legacy.calls.Load() == 2 && legacy.result == nil && legacy.err == nil
				}
				close(b.release)
				// Finish the first action, including its log commit and deferred
				// in-flight release, while the second query still cannot return.
				synctest.Wait()
				rows := ms.actionExecLog.snapshotLogs()
				if !queryOK || rowsBefore != 0 || len(rows) != 1 || rows[0].Status != "success" || d.count() != 1 {
					t.Fatalf("DEVICE queryOK=%v rows before=%d rows now=%v HTTP=%d", queryOK, rowsBefore, rows, d.count())
				}
				t.Log("ASSERT Device PASS: second query found no prior success before first commit; first action finished before query return")
				close(ret)
				<-returned
				synctest.Wait()
				dao14c2Want(t, "SideEffects", d.count() == 1, d.count())
				rows = ms.actionExecLog.snapshotLogs()
				skips := 0
				for _, row := range rows {
					if row.Status == "skipped" && row.SkipReason == action.SkipReasonAlreadyExecuted && strings.Contains(row.ErrorMessage, "in flight") {
						skips++
					}
				}
				dao14c2Want(t, "Reason", skips == 1, rows)
			})
		})
	}
}

func TestDao14c2_O6(t *testing.T) {
	for _, name := range []string{"Settled.SkipsByLog", "Periodic.InflightStillRuns", "TwoOnceActions.BothRun", "DifferentAttack.Independent", "FailedThenReleased", "CreateErrorThenReleased", "PhaseDistinct.Independent", "RunModeEmpty.Untouched", "Legacy.once_on_enter.SettledSameAsHEAD", "Legacy.retry_until_success.SettledSameAsHEAD", "Legacy.once_on_exit.SettledSameAsHEAD"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := dao4HTTP(t)
				ms, _, ev := dao4Fixture("webhook", "once", "on_detected")
				settled := strings.Contains(name, "Settled") || strings.HasSuffix(name, "Released")
				if strings.HasPrefix(name, "Legacy.") {
					policy := strings.Split(name, ".")[1]
					ms.responses.actions[0].TriggerPhase = ""
					ms.responses.actions[0].RunMode = ""
					ms.responses.actions[0].ExecutionPolicy = policy
					if policy == "once_on_exit" {
						ev.Type = "expired"
					}
				}
				if name == "Periodic.InflightStillRuns" {
					ms.responses.actions[0].RunMode = "periodic"
				}
				if name == "RunModeEmpty.Untouched" {
					ms.responses.actions[0].RunMode = ""
				}
				if name == "TwoOnceActions.BothRun" {
					a := ms.responses.actions[0]
					a.ID = 11
					ms.responses.actions = append(ms.responses.actions, a)
				}
				b := dao14c2NewBarrier()
				if !settled {
					d.handler = func(*http.Request) int { b.hit(); return 200 }
				}
				if name == "FailedThenReleased" {
					d.setStatus(500)
				}
				done := make(chan struct{}, 8)
				var attempts atomic.Int32
				r := dao14c2NotifyLogs{ActionExecLogRepo: ms.ActionExecLog(), done: done}
				if name == "CreateErrorThenReleased" {
					r.before = func(row *store.ActionExecutionLog) error {
						if attempts.Add(1) == 1 {
							return errors.New("injected Create failure")
						}
						return nil
					}
				}
				e := action.NewEngine(dao14c2Store{Store: ms, logs: r}, "auto")
				e.HandleEvent(ev)
				if settled {
					dao14c2Join(done, 1)
				} else {
					<-b.entered
					synctest.Wait()
				}
				if name != "TwoOnceActions.BothRun" {
					if ev.Type != "expired" {
						ev.Type = "type_upgrade"
					}
					if name == "DifferentAttack.Independent" {
						cp := *ev.Attack
						cp.ID = 21
						ev.Attack = &cp
						ev.DBID = 21
					}
					if name == "PhaseDistinct.Independent" {
						ms.responses.mu.Lock()
						ms.responses.actions[0].TriggerPhase = "on_expired"
						ms.responses.mu.Unlock()
						ev.Type = "expired"
					}
					if name == "FailedThenReleased" {
						d.setStatus(200)
					}
					e.HandleEvent(ev)
				}
				if !settled {
					close(b.release)
					dao14c2Join(done, 2)
				} else {
					dao14c2Join(done, 1)
				}
				want := 2
				if name == "Settled.SkipsByLog" {
					want = 1
				}
				dao14c2Want(t, "SideEffects", d.count() == want, fmt.Sprintf("HTTP=%d want=%d", d.count(), want))
				if name == "Settled.SkipsByLog" {
					rows := ms.actionExecLog.snapshotLogs()
					dao14c2Want(t, "Detail", len(rows) == 2 && rows[1].ErrorMessage == "run_mode=once: already executed", rows)
				}
			})
		})
	}
	t.Run("ExhaustedThenReleased", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ms, _, ev := dao4Fixture("shell", "once", "on_detected")
			ms.responses.actions[0].ShellConnectorID = intPtr(7)
			probe := &dao14c2Probe{}
			responses := &dao14c2Responses{ResponseRepo: ms.Responses(), probe: probe, repeat: true}
			var gets atomic.Int32
			logs := &dao14c2Logs{ActionExecLogRepo: ms.ActionExecLog(), probe: probe}
			e := action.NewEngine(dao14c2Store{Store: ms, responses: responses, logs: logs, shell: dao14c2Shell{enabled: true, before: func() { gets.Add(1) }}}, "auto")
			e.HandleEvent(ev)
			synctest.Wait()
			<-time.After(31 * time.Second)
			synctest.Wait()
			if probe.current() == nil || probe.current().Err() == nil {
				t.Fatal("DEVICE first action did not expire")
			}
			ev.Type = "type_upgrade"
			e.HandleEvent(ev)
			synctest.Wait()
			<-time.After(31 * time.Second)
			synctest.Wait()
			dao14c2Want(t, "SideEffects", gets.Load() == 2, gets.Load())
		})
	})
	t.Run("GateSkippedNoLeak.FirstMatch", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ms, _, ev := dao4Fixture("bgp", "once", "on_detected")
			dao14c2BGP(ms)
			a := ms.responses.actions[0]
			a.ID = 11
			ms.responses.actions = append(ms.responses.actions, a)
			// An active shared route keeps this gate test independent of subprocess timing.
			seed, err := ms.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{AttackID: 99, Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7})
			if err != nil {
				t.Fatal(err)
			}
			if err := ms.BGPAnnouncements().MarkAnnounced(context.Background(), seed.AnnouncementID, seed.Gen); err != nil {
				t.Fatal(err)
			}
			var attaches atomic.Int32
			e := action.NewEngine(dao14c2Store{Store: ms, anns: dao14c2Attach{ms.BGPAnnouncements(), func() { attaches.Add(1) }}}, "auto")
			e.HandleEvent(ev)
			synctest.Wait()
			rows := ms.actionExecLog.snapshotLogs()
			suppressed := false
			for _, row := range rows {
				suppressed = suppressed || row.ActionID == 11 && row.SkipReason == action.SkipReasonFirstMatchSuppressed
			}
			if !suppressed {
				t.Fatalf("DEVICE first-match seed: %v", rows)
			}
			ev.Type = "type_upgrade"
			e.HandleEvent(ev)
			synctest.Wait()
			rows = ms.actionExecLog.snapshotLogs()
			aSkip, bRun := false, false
			for _, row := range rows {
				aSkip = aSkip || row.ActionID == 10 && row.SkipReason == action.SkipReasonAlreadyExecuted
				bRun = bRun || row.ActionID == 11 && row.Status == "success"
			}
			dao14c2Want(t, "SideEffects", attaches.Load() == 2 && aSkip && bRun, rows)
		})
	})
	t.Run("XDropChild.NoSweepDelete", dao14c2XDropChild)
}

type dao14c2FailSchedule struct {
	store.ScheduledActionRepo
	barrier *dao14c2Barrier
}

func (r dao14c2FailSchedule) Schedule(context.Context, *store.ScheduledAction) (int, error) {
	r.barrier.hit()
	return 0, errors.New("injected Schedule failure")
}

type dao14c2FailRule struct {
	store.XDropActiveRuleRepo
	failed atomic.Int32
}

func (r *dao14c2FailRule) MarkFailed(context.Context, int, int, int, string, string) error {
	r.failed.Add(1)
	return errors.New("injected MarkFailed failure")
}
func dao14c2XDropChild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, _, ev := dao4XDrop()
		ev.Type = "expired"
		ms.responses.actions[0].UnblockDelayMinutes = 1
		dao4SeedRule(t, ms, "active", "rule-1", false)
		b := dao14c2NewBarrier()
		rules := &dao14c2FailRule{XDropActiveRuleRepo: ms.XDropActiveRules()}
		e := action.NewEngine(dao14c2Store{Store: ms, schedules: dao14c2FailSchedule{ms.ScheduledActions(), b}, rules: rules}, "auto")
		e.HandleEvent(ev)
		<-b.entered
		synctest.Wait()
		e.HandleEvent(ev)
		close(b.release)
		synctest.Wait()
		pending, err := ms.ScheduledActions().ListPending(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if rules.failed.Load() == 0 || len(pending) != 0 {
			t.Fatalf("DEVICE Schedule/MarkFailed errors not exercised: failures=%d pending=%v", rules.failed.Load(), pending)
		}
		t.Log("ASSERT Device PASS: Schedule and MarkFailed failed; no persisted schedule")
		rows, err := ms.XDropActiveRules().ListByAttack(context.Background(), 20)
		if err != nil || len(rows) != 1 || rows[0].Status != "withdrawn" {
			t.Fatalf("rule not withdrawn: %+v %v", rows, err)
		}
		dao14c2Want(t, "SideEffects", d.count() == 1, fmt.Sprintf("DELETE calls=%d", d.count()))
	})
}

func TestDao14c2_W1_Integration(t *testing.T) {
	for _, event := range []string{"expired", "evicted"} {
		t.Run(event, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := dao4HTTP(t)
				var body map[string]any
				d.handler = func(r *http.Request) int {
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					return 200
				}
				ms, e, ev := dao4Fixture("webhook", "once", "on_expired")
				ev.Type = event
				want := "expired"
				if event == "evicted" {
					ev.Attack.ReasonCodes = []string{"evicted_by_cap"}
					want = "evicted_by_cap"
				}
				e.HandleEvent(ev)
				synctest.Wait()
				dao14c2Want(t, "EndReason", body["end_reason"] == want, body)
				dao14c2Want(t, "Event", body["event"] == event, body)
				_, ended := body["ended_at"]
				dao14c2Want(t, "EndedAt", !ended, body)
				dao14c2Want(t, "Rows", len(ms.actionExecLog.snapshotLogs()) == 1, ms.actionExecLog.snapshotLogs())
			})
		})
	}
}
