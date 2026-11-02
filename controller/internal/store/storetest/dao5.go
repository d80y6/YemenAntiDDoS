package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// CheckDao5NotPending is shared with the action package's v3Schedules fixture.
func CheckDao5NotPending(t *testing.T, r store.ScheduledActionRepo, id int) {
	t.Helper()
	if err := r.MarkExecuting(ctx, id); !errors.Is(err, store.ErrNotPending) {
		t.Fatalf("MarkExecuting(%d)=%v; want errors.Is(ErrNotPending)", id, err)
	}
}

func runDao5Contract(t *testing.T, open func(*testing.T) Backend) {
	for _, state := range []string{"missing", "pending", "executing", "cancelled", "completed", "failed"} {
		t.Run("ScheduledActions/Dao5_C1_MarkExecuting/"+state, func(t *testing.T) {
			r := open(t).Store().ScheduledActions()
			if state == "missing" {
				CheckDao5NotPending(t, r, 999999)
				return
			}
			id, err := r.Schedule(ctx, &store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: 10, ActionID: 20, ConnectorID: 7, ExternalRuleID: "dao5", ScheduledFor: stamp(0)})
			check(t, err)
			switch state {
			case "pending":
				check(t, r.MarkExecuting(ctx, id))
				return
			case "executing":
				check(t, r.MarkExecuting(ctx, id))
			case "cancelled":
				check(t, r.Cancel(ctx, id, "dao5"))
			case "completed":
				check(t, r.Complete(ctx, id))
			case "failed":
				check(t, r.Fail(ctx, id, "dao5"))
			}
			CheckDao5NotPending(t, r, id)
		})
	}
	for _, kind := range []string{"same", "same_microsecond", "ended", "dst_ip", "direction", "decoder_family", "different_microsecond"} {
		t.Run("Attacks/Dao5_C2_Create/"+kind, func(t *testing.T) {
			s := open(t).Store()
			a := store.Attack{DstIP: "192.0.2.1", Direction: "receives", DecoderFamily: "udp", StartedAt: stamp(0).Add(123456101 * time.Nanosecond)}
			id, err := s.Attacks().Create(ctx, &a)
			check(t, err)
			if kind == "ended" {
				a.ID = id
				a.EndedAt = ptr(stamp(10))
				check(t, s.Attacks().Update(ctx, &a))
				a.EndedAt = nil
			}
			switch kind {
			case "same_microsecond":
				a.StartedAt = a.StartedAt.Add(800 * time.Nanosecond)
			case "dst_ip":
				a.DstIP = "192.0.2.2"
			case "direction":
				a.Direction = "sends"
			case "decoder_family":
				a.DecoderFamily = "tcp"
			case "different_microsecond":
				a.StartedAt = a.StartedAt.Add(time.Microsecond)
			}
			second, err := s.Attacks().Create(ctx, &a)
			check(t, err)
			n, err := s.Attacks().Count(ctx, store.AttackFilter{})
			check(t, err)
			if kind == "same" || kind == "same_microsecond" {
				if second != id || n != 1 {
					t.Fatalf("same identity: IDs=%d,%d rows=%d; want same ID, one row", id, second, n)
				}
			} else if second == id || n != 2 {
				t.Fatalf("different identity/end: IDs=%d,%d rows=%d; want new ID, two rows", id, second, n)
			}
		})
	}
}
