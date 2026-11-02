package storetest

import (
	"context"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// RunTD104Contract shares the same backend lifecycle as RunContract.
func RunTD104Contract(t *testing.T, open func(*testing.T) Backend) {
	RunXDrop2AContract(t, open)
	t.Run("C1_DeletedResponseUpdate", func(t *testing.T) {
		s := open(t).Store()
		x := seedResponse(t, s, "TD104")
		id := seedAttack(t, s, store.Attack{ResponseID: &x})
		a, err := s.Attacks().Get(ctx, id)
		check(t, err)
		check(t, s.Responses().Delete(ctx, x)) // committed deletion precedes Update
		a.EndedAt = ptr(stamp(50))
		check(t, s.Attacks().Update(ctx, a))
		got, err := s.Attacks().Get(ctx, id)
		check(t, err)
		equal(t, got.EndedAt != nil, true)
		equal(t, got.ResponseID == nil, true)
	})
	t.Run("C2_ReconcileContracts", func(t *testing.T) { runFuzhuoContract(t, open) })
	for _, status := range []string{"active", "delayed", "failed", "withdrawing", "withdrawn"} {
		t.Run("C3_ClaimActive/"+status, func(t *testing.T) {
			s := open(t).Store()
			r := s.XDropActiveRules()
			_, err := r.Upsert(ctx, &store.XDropActiveRule{AttackID: 20, ActionID: 30, ConnectorID: 7, ExternalRuleID: "td104", Status: status})
			check(t, err)
			claim, ok := r.(interface {
				ClaimActive(context.Context, int, int, int, string) (bool, error)
			})
			if !ok {
				t.Fatal("ClaimActive method unavailable")
			}
			claimed, err := claim.ClaimActive(ctx, 20, 30, 7, "td104")
			check(t, err)
			equal(t, claimed, status == "active")
			rows, err := r.ListByAttack(ctx, 20)
			check(t, err)
			equal(t, len(rows), 1)
			want := status
			if status == "active" {
				want = "withdrawing"
			}
			equal(t, rows[0].Status, want)
			claimed, err = claim.ClaimActive(ctx, 20, 30, 7, "td104")
			check(t, err)
			equal(t, claimed, false)
		})
	}
}
