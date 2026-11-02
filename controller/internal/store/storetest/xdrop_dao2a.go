package storetest

import (
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// RunXDrop2AContract is shared by the offline mock and the existing TD104
// PostgreSQL runner. The latter stays on the fixed local exclusion list.
func RunXDrop2AContract(t *testing.T, open func(*testing.T) Backend) {
	for _, status := range []string{"active", "delayed", "withdrawing", "failed", "withdrawn"} {
		t.Run("CountLiveByConnector/"+status, func(t *testing.T) {
			r := open(t).Store().XDropActiveRules()
			for i, rule := range []string{"real-rule", "failed-create-20-30"} {
				_, err := r.Upsert(ctx, &store.XDropActiveRule{AttackID: 20, ActionID: 30 + i, ConnectorID: 7, ExternalRuleID: rule, Status: status})
				check(t, err)
			}
			_, err := r.Upsert(ctx, &store.XDropActiveRule{AttackID: 20, ActionID: 32, ConnectorID: 8, ExternalRuleID: "other-connector", Status: "active"})
			check(t, err)
			n, err := r.CountLiveByConnector(ctx, 7)
			check(t, err)
			want := 2
			if status == "withdrawn" {
				want = 0
			}
			equal(t, n, want)
			n, err = r.CountLiveByConnector(ctx, 8)
			check(t, err)
			equal(t, n, 1)
			n, err = r.CountLiveByConnector(ctx, 9)
			check(t, err)
			equal(t, n, 0)
		})
	}
}
