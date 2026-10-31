package tests

import (
	"context"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Behavior C17, mock contract: failed (with error_message) -> withdrawing -> MarkWithdrawn leaves error_message empty.
// In upsert_failed the error comes from Upsert (a synthetic row for failed creation); in mark_failed it comes from MarkFailed (failed withdrawal).
// Seed M17 detects MarkWithdrawn updating only status / withdrawn_at without clearing the error.
// SQL and database checks are in store/postgres/xdrop_dao2b_sql_test.go; SQL checks run offline, and database checks require XSIGHT_TEST_ADMIN_DSN.
func TestD2B_C17_WithdrawnClearsError(t *testing.T) {
	for _, kind := range []string{"upsert_failed", "mark_failed"} {
		t.Run("mock/"+kind, func(t *testing.T) {
			ctx := context.Background()
			r := NewMockStore().XDropActiveRules()
			row := &store.XDropActiveRule{AttackID: 20, ActionID: 30, ConnectorID: 7, ExternalRuleID: "td204", Status: "failed", ErrorMessage: "HTTP 503 unavailable: retry"}
			if kind == "mark_failed" {
				row.Status, row.ErrorMessage = "active", ""
			}
			if _, err := r.Upsert(ctx, row); err != nil {
				t.Fatal(err)
			}
			if kind == "mark_failed" {
				if err := r.MarkFailed(ctx, 20, 30, 7, "td204", "HTTP 503 unavailable: retry"); err != nil {
					t.Fatal(err)
				}
			}
			rows, _ := r.ListByAttack(ctx, 20)
			if len(rows) != 1 || rows[0].Status != "failed" || rows[0].ErrorMessage == "" {
				t.Fatalf("device: seeded rows=%+v; want one failed row with error_message", rows)
			}
			ok, err := r.MarkWithdrawing(ctx, 20, 30, 7, "td204")
			if err != nil || !ok {
				t.Fatalf("device: MarkWithdrawing ok=%v err=%v", ok, err)
			}
			if err := r.MarkWithdrawn(ctx, 20, 30, 7, "td204"); err != nil {
				t.Fatal(err)
			}
			rows, _ = r.ListByAttack(ctx, 20)
			if len(rows) != 1 || rows[0].Status != "withdrawn" {
				t.Fatalf("rows after MarkWithdrawn=%+v; want one withdrawn row", rows)
			}
			if rows[0].ErrorMessage != "" {
				t.Errorf("withdrawn row error_message=%q; want empty", rows[0].ErrorMessage)
			}
		})
	}
}
