package tests

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestTD104_E17_ConcurrentFailedWithdrawal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyXDrop()
		f.disable(t)
		f.d.setStatus(500)
		first, second := make(chan struct{}), make(chan struct{})
		f.s.hook("listed_rules", func() {
			if f.s.count("listed_rules") == 1 {
				<-first
			} else if f.s.count("listed_rules") == 2 {
				<-second
			}
		})
		f.e.HandleEvent(f.event)
		synctest.Wait()
		f.e.HandleEvent(f.event)
		synctest.Wait()
		fzEqual(t, "both active snapshots", f.s.count("listed_rules"), 2)
		close(first)
		synctest.Wait()
		rows, err := f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
		fzCheck(t, err)
		fzEqual(t, "first DELETE failed", rows[0].Status, "failed")
		close(second)
		synctest.Wait()
		fzEqual(t, "DELETE total", f.d.count(), 1)
		f.delta(t, map[string]float64{"xdrop/dispatched": 1, "xdrop/skipped_claimed": 1})
		f.s.hook("listed_rules", nil)
		f.d.setStatus(204)
		ctx, cancel := context.WithCancel(context.Background())
		go f.e.RunXDropReconcile(ctx, time.Second)
		time.Sleep(2*time.Minute + time.Second)
		synctest.Wait()
		cancel()
		synctest.Wait()
		fzEqual(t, "retry DELETE total", f.d.count(), 2)
		rows, err = f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
		fzCheck(t, err)
		fzEqual(t, "retry terminal", rows[0].Status, "withdrawn")

	})
}
func TestTD104_E18_MarkDelayedFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 1)
		f.onlyXDrop()
		f.s.fail("mark_delayed")
		f.run()
		rows, err := f.s.ScheduledActions().ListPending(fzCtx)
		fzCheck(t, err)
		fzEqual(t, "pending plan", len(rows), 1)
		fzEqual(t, "DELETE", f.d.count(), 0)
		f.delta(t, map[string]float64{"xdrop/skipped_scheduled": 1})
		f.cancel()
	})
}
func TestTD104_E19_SnapshotBecomesDelayed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyXDrop()
		f.disable(t)
		gate := make(chan struct{})
		f.s.hook("listed_rules", func() { <-gate })
		f.e.HandleEvent(f.event)
		synctest.Wait()
		fzEqual(t, "active snapshot obtained", f.s.count("listed_rules"), 1)
		fzCheck(t, f.s.MockStore.XDropActiveRules().MarkDelayed(fzCtx, 20, 30, 7, "rule-1", 1))
		close(gate)
		synctest.Wait()
		fzEqual(t, "DELETE", f.d.count(), 0)
		f.delta(t, map[string]float64{"xdrop/skipped_claimed": 1})
	})
}
func TestTD104_E20_ScheduledOwner(t *testing.T) {
	for _, status := range []string{"pending", "executing"} {
		t.Run(status, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := td104New(t, 0)
				f.onlyXDrop()
				f.disable(t)
				f.s.scheduledActions.appendRecords(store.ScheduledAction{ID: 1, AttackID: 20, ActionID: 30, ConnectorID: 7, ExternalRuleID: "rule-1", ActionType: "xdrop_unblock", Status: status})
				f.run()
				fzEqual(t, "DELETE", f.d.count(), 0)
				f.delta(t, map[string]float64{"xdrop/skipped_scheduled": 1})
			})
		})
	}
}

// Both events traverse the real FIFO. A repository barrier holds the first
// event's already-dispatched child; synctest proves negative ordering assertions.
func td104CrossEvent(t *testing.T, kind string) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 1)
		gate := make(chan struct{})
		hook := "detach"
		if kind == "xdrop" {
			f.onlyXDrop()
			hook = "before_delay"
		} else {
			f.onlyBGP()
		}
		if kind == "legacy" {
			f.s.responses.actions[1].TriggerPhase = ""
			f.s.responses.actions[1].ExecutionPolicy = "once_on_exit"
			hook = "response"
		}
		f.s.hook(hook, func() {
			if kind != "legacy" || f.s.count("response") == 2 {
				<-gate
			}
		})
		f.e.Start()
		f.e.Enqueue(f.event)
		synctest.Wait()
		fzEqual(t, "child reached barrier", f.s.count(hook) > 0, true)
		beforeRules := f.s.count("rules")
		f.disable(t)
		f.e.Enqueue(f.event)
		synctest.Wait()
		fzEqual(t, "attachment scans before release", f.s.count("attachments"), 0)
		fzEqual(t, "reconcile before release", f.s.count("reconcile"), 0)
		fzEqual(t, "rule scans while child held", f.s.count("rules")-beforeRules, 0)
		close(gate)
		synctest.Wait()
		if kind == "legacy" {
			f.state(t, "withdrawn", "", 1, 0)
			fzEqual(t, "bgp/dispatched", f.values(t)["bgp/dispatched"]-f.before["bgp/dispatched"], float64(1))
			found := false
			for _, l := range f.s.actionExecLog.snapshotLogs() {
				if l.Status == "skipped" && strings.Contains(l.ErrorMessage, "unknown trigger_phase: expired") {
					found = true
				}
			}
			fzEqual(t, "legacy HEAD skip preserved", found, true)
		} else if kind == "xdrop" {
			r, err := f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
			fzCheck(t, err)
			fzEqual(t, "rule delayed", r[0].Status, "delayed")
			p, err := f.s.ScheduledActions().ListPending(fzCtx)
			fzCheck(t, err)
			fzEqual(t, "pending plan", len(p), 1)
			fzEqual(t, "DELETE", f.d.count(), 0)
			f.delta(t, nil)
		} else {
			f.state(t, "delayed", "", 0, 0)
			f.delta(t, nil)
		}
		f.cancel()
		f.stopQueue()
	})
}
func TestTD104_E21_LegacyBGPInflight(t *testing.T)    { td104CrossEvent(t, "legacy") }
func TestTD104_E22_CrossEventXDropDelay(t *testing.T) { td104CrossEvent(t, "xdrop") }
func TestTD104_E24_CrossEventBGPDelay(t *testing.T)   { td104CrossEvent(t, "bgp") }
func TestTD104_E21b_LegacyXDropChild(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyXDrop()
		f.s.responses.actions[1].TriggerPhase = ""
		f.s.responses.actions[1].ExecutionPolicy = "once_on_exit"
		f.run()
		fzEqual(t, "DELETE", f.d.count(), 1)
		fzEqual(t, "child and sweep read rules", f.s.count("rules") >= 2, true)
		rows, err := f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
		fzCheck(t, err)
		fzEqual(t, "rule terminal", rows[0].Status, "withdrawn")
		f.delta(t, nil)
	})
}
func TestTD104_E23_AlreadyExecutedOwnsRule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyXDrop()
		f.s.fail("mark_withdrawing")
		f.s.fail("mark_withdrawn")
		f.run()
		rows, err := f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
		fzCheck(t, err)
		fzEqual(t, "rule remains active", rows[0].Status, "active")
		fzEqual(t, "claim error prevents DELETE", f.d.count(), 0)
		for _, l := range f.s.actionExecLog.snapshotLogs() {
			if l.ActionID == 30 && l.Status == "success" {
				t.Fatal("success before terminal state")
			}
		}
		f.s.mu.Lock()
		delete(f.s.faults, "mark_withdrawing")
		delete(f.s.faults, "mark_withdrawn")
		f.s.mu.Unlock()
		time.Sleep(2*time.Minute + time.Second)
		f.run()
		fzEqual(t, "recovered DELETE", f.d.count(), 1)
		rows, err = f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
		fzCheck(t, err)
		fzEqual(t, "rule terminal", rows[0].Status, "withdrawn")
		f.run()
		fzEqual(t, "repeat event no duplicate DELETE", f.d.count(), 1)
	})
}
