package storetest

import (
	"reflect"
	"testing"
)

// RunDao11jC1 checks the conditional claim and every preserved field.
func RunDao11jC1(t *testing.T, open func(*testing.T) Dao5bBackend) {
	for _, status := range []string{"withdrawing", "withdrawing_wrong_gen", "announcing", "active", "delayed", "withdrawn", "failed", "orphan", "dismissed", "dismissed_on_upgrade", "missing"} {
		t.Run(status, func(t *testing.T) {
			b := open(t)
			state, gen := status, 7
			if status == "withdrawing_wrong_gen" {
				state, gen = "withdrawing", 6
			}
			if status == "missing" {
				state = "withdrawing"
			}
			r, id := dao5bSeed(t, b, state, 2)
			before, err := r.Get(ctx, id)
			check(t, err)
			attachments, err := r.ListAttacks(ctx, id)
			check(t, err)
			events, err := r.ListEvents(ctx, id)
			check(t, err)
			claimID := id
			if status == "missing" {
				claimID = 999999
			}
			newGen, ok, err := r.ClaimWithdrawing(ctx, claimID, gen)
			t.Run("Outcome", func(t *testing.T) {
				if status == "withdrawing" {
					if err != nil || !ok || newGen != 8 {
						t.Errorf("claim=(%d,%v,%v); want (8,true,nil)", newGen, ok, err)
					}
				} else if err != nil || ok || newGen != 0 {
					t.Errorf("claim=(%d,%v,%v); want (0,false,nil)", newGen, ok, err)
				}
			})
			after, err := r.Get(ctx, id)
			check(t, err)
			if status == "withdrawing" {
				before.Gen = 8
			}
			t.Run("Row", func(t *testing.T) {
				if !reflect.DeepEqual(before, after) {
					t.Errorf("row=%+v; want %+v with no other changes", after, before)
				}
			})
			laterAttachments, err := r.ListAttacks(ctx, id)
			check(t, err)
			laterEvents, err := r.ListEvents(ctx, id)
			check(t, err)
			t.Run("Attachments", func(t *testing.T) {
				if !reflect.DeepEqual(attachments, laterAttachments) {
					t.Errorf("attachments changed: before=%+v after=%+v", attachments, laterAttachments)
				}
			})
			t.Run("Events", func(t *testing.T) {
				if !reflect.DeepEqual(events, laterEvents) {
					t.Errorf("events changed: before=%+v after=%+v", events, laterEvents)
				}
			})
		})
	}
}
