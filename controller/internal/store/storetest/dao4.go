package storetest

import (
	"fmt"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func dao4Contracts(run runner) {
	type outcome struct {
		target int
		status string
		second int
	}
	for _, tc := range []struct {
		name string
		rows []outcome
		want bool
	}{
		{"Empty", nil, false},
		{"OnlySkipped", []outcome{{0, "skipped", 10}}, false},
		{"SingleSuccess", []outcome{{7, "success", 10}}, true},
		{"SingleScheduled", []outcome{{7, "scheduled", 10}}, true},
		{"SingleFailed", []outcome{{7, "failed", 10}}, false},
		{"ScheduledThenFailed", []outcome{{7, "scheduled", 10}, {7, "failed", 20}}, false},
		{"SuccessThenSkip", []outcome{{7, "success", 10}, {7, "skipped", 20}}, true},
		{"MixedDone", []outcome{{7, "success", 10}, {8, "scheduled", 20}}, true},
		{"MixedFailed", []outcome{{7, "success", 10}, {8, "failed", 20}}, false},
		{"OlderNullFailure", []outcome{{0, "failed", 10}, {7, "success", 20}}, true},
		{"NewerNullFailure", []outcome{{7, "success", 10}, {0, "failed", 20}}, false},
		{"OnlyNullSuccess", []outcome{{0, "success", 10}}, true},
		{"OnlyNullFailed", []outcome{{0, "failed", 10}}, false},
		{"NullThenTargetSameTimeID", []outcome{{0, "failed", 10}, {7, "success", 10}}, true},
		{"TargetThenNullSameTimeID", []outcome{{7, "success", 10}, {0, "failed", 10}}, false},
		{"SameTargetTieIDFailed", []outcome{{7, "success", 10}, {7, "failed", 10}}, false},
		{"SameTargetTieIDSuccess", []outcome{{7, "failed", 10}, {7, "success", 10}}, true},
		{"TimestampBeforeID", []outcome{{7, "failed", 20}, {7, "success", 10}}, false},
	} {
		run("B22/AllTargetsDone/"+tc.name, func(t *testing.T, b Backend) {
			s := b.Store()
			for _, row := range tc.rows {
				var connector *int
				if row.target != 0 {
					connector = ptr(row.target)
				}
				id, err := s.ActionExecLog().Create(ctx, &store.ActionExecutionLog{AttackID: 20, ActionID: 10, TriggerPhase: "on_detected", Status: row.status, ConnectorID: connector})
				check(t, err)
				setTime(t, b, "action_execution_log", "id", id, "executed_at", row.second)
			}
			got, err := s.ActionExecLog().AllTargetsDone(ctx, 20, 10, "on_detected")
			check(t, err)
			equal(t, got, tc.want)
		})
	}
	for _, key := range []string{"attack", "action", "phase"} {
		run("B22/AllTargetsDone/Isolation/"+key, func(t *testing.T, b Backend) {
			s := b.Store()
			row := store.ActionExecutionLog{AttackID: 20, ActionID: 10, TriggerPhase: "on_detected", Status: "success", ConnectorID: ptr(7)}
			_, err := s.ActionExecLog().Create(ctx, &row)
			check(t, err)
			if key == "attack" {
				row.AttackID++
			}
			if key == "action" {
				row.ActionID++
			}
			if key == "phase" {
				row.TriggerPhase = "on_expired"
			}
			row.Status = "failed"
			_, err = s.ActionExecLog().Create(ctx, &row)
			check(t, err)
			got, err := s.ActionExecLog().AllTargetsDone(ctx, 20, 10, "on_detected")
			check(t, err)
			equal(t, got, true)
			got, err = s.ActionExecLog().AllTargetsDone(ctx, row.AttackID, row.ActionID, row.TriggerPhase)
			check(t, err)
			equal(t, got, false)
		})
	}
	for _, method := range []string{"MarkDelayed", "MarkFailed"} {
		for _, status := range []string{"withdrawn", "active", "failed", "delayed", "withdrawing"} {
			run("B22/XDrop/"+method+"/"+status, func(t *testing.T, b Backend) {
				r := b.Store().XDropActiveRules()
				_, err := r.Upsert(ctx, &store.XDropActiveRule{AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: "r", Status: status})
				check(t, err)
				want := status
				if method == "MarkDelayed" {
					check(t, r.MarkDelayed(ctx, 20, 10, 7, "r", 3))
					if status == "active" || status == "failed" {
						want = "delayed"
					}
				} else {
					check(t, r.MarkFailed(ctx, 20, 10, 7, "r", "failure"))
					if status != "withdrawn" {
						want = "failed"
					}
				}
				rows, err := r.ListByAttack(ctx, 20)
				check(t, err)
				equal(t, len(rows), 1)
				equal(t, rows[0].Status, want)
			})
		}
	}
	run("B22/XDrop/MarkWithdrawing/Failed", func(t *testing.T, b Backend) {
		r := b.Store().XDropActiveRules()
		_, err := r.Upsert(ctx, &store.XDropActiveRule{AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: "r", Status: "failed"})
		check(t, err)
		ok, err := r.MarkWithdrawing(ctx, 20, 10, 7, "r")
		check(t, err)
		equal(t, ok, true)
		ok, err = r.MarkWithdrawing(ctx, 20, 10, 7, "r")
		check(t, err)
		equal(t, ok, false)
	})
	run("B22/XDrop/Upsert/PreservesWithdrawnAndID", func(t *testing.T, b Backend) {
		r := b.Store().XDropActiveRules()
		row := store.XDropActiveRule{AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: "r", Status: "active"}
		id, err := r.Upsert(ctx, &row)
		check(t, err)
		check(t, r.MarkWithdrawn(ctx, 20, 10, 7, "r"))
		again, err := r.Upsert(ctx, &row)
		check(t, err)
		equal(t, again, id)
		rows, err := r.ListByAttack(ctx, 20)
		check(t, err)
		equal(t, len(rows), 1)
		equal(t, rows[0].Status, "withdrawn")
	})
	for _, status := range []string{"active", "announcing", "delayed"} {
		run("B22/BGP/Attach/"+status, func(t *testing.T, b Backend) {
			r := b.Store().BGPAnnouncements()
			p := store.BGPAttachParams{AttackID: 20, ActionID: ptr(10), ConnectorID: 7, Prefix: "192.0.2.10/32", RouteMap: "RTBH"}
			if status == "delayed" {
				p.DelayMinutes = 5
			}
			a, err := r.Attach(ctx, p)
			check(t, err)
			if status != "announcing" {
				check(t, r.MarkAnnounced(ctx, a.AnnouncementID, dao5bCurrentGen(t, r, a.AnnouncementID)))
			}
			if status == "delayed" {
				_, err = r.Detach(ctx, 20, p.Prefix, p.RouteMap, 7)
				check(t, err)
			}
			for i := 0; i < 2; i++ {
				_, err = r.Attach(ctx, p)
				check(t, err)
			}
			got, err := r.Get(ctx, a.AnnouncementID)
			check(t, err)
			equal(t, got.Refcount, 1)
			d, err := r.Detach(ctx, 20, p.Prefix, p.RouteMap, 7)
			check(t, err)
			equal(t, d.RefcountAfter, 0)
			if status == "delayed" {
				equal(t, d.Delayed, true)
			} else {
				equal(t, d.NeedWithdraw, true)
			}
		})
	}
	run("B22/BGP/ForceWithdraw/ActualDetachedSet", func(t *testing.T, b Backend) {
		r := b.Store().BGPAnnouncements()
		id := 0
		for i := 0; i < 2; i++ {
			a, err := r.Attach(ctx, store.BGPAttachParams{AttackID: 20 + i, ActionID: ptr(10 + i), ConnectorID: 7, Prefix: "192.0.2.10/32", RouteMap: "RTBH"})
			check(t, err)
			id = a.AnnouncementID
		}
		rows, _, err := r.ForceWithdraw(ctx, id)
		check(t, err)
		got := map[string]bool{}
		for _, a := range rows {
			if a.ActionID == nil {
				t.Fatal("action ID missing")
			}
			got[fmt.Sprintf("%d/%d", a.AttackID, *a.ActionID)] = true
		}
		equal(t, got, map[string]bool{"20/10": true, "21/11": true})
		rows, _, err = r.ForceWithdraw(ctx, id)
		check(t, err)
		equal(t, len(rows), 0)
	})
}
