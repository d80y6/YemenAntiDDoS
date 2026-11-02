package postgres

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// Behavior C17: SQL and database checks for clearing withdrawal errors.
// sql_static reads MarkWithdrawn in xdrop_active_rules.go offline and requires its SET clause to clear error_message.
// postgres checks failed (with error_message) -> withdrawing -> MarkWithdrawn -> empty error_message; it skips without a DSN.
// Seed: M17.
func TestD2B_C17_WithdrawnClearsError(t *testing.T) {
	t.Run("sql_static", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "xdrop_active_rules.go", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "MarkWithdrawn" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				q, err := strconv.Unquote(lit.Value)
				if err != nil || !strings.Contains(q, "xdrop_active_rules") {
					return true
				}
				found++
				compact := strings.ReplaceAll(strings.Join(strings.Fields(q), " "), " = ", "=")
				set := compact
				if i := strings.Index(compact, " WHERE "); i >= 0 {
					set = compact[:i]
				}
				if !strings.Contains(set, "error_message=''") {
					t.Errorf("MarkWithdrawn SET clause=%q; want error_message='' (TD-204)", set)
				}
				return true
			})
		}
		if found != 1 {
			t.Fatalf("MarkWithdrawn SQL literals=%d want 1", found)
		}
	})
	t.Run("postgres", func(t *testing.T) {
		if os.Getenv("XSIGHT_TEST_ADMIN_DSN") == "" {
			t.Skip("XSIGHT_TEST_ADMIN_DSN is not set")
		}
		ctx := context.Background()
		r := newPostgresContractBackend(t).Store().XDropActiveRules()
		if _, err := r.Upsert(ctx, &store.XDropActiveRule{AttackID: 20, ActionID: 30, ConnectorID: 7, ExternalRuleID: "td204", Status: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := r.MarkFailed(ctx, 20, 30, 7, "td204", "HTTP 503 unavailable: retry"); err != nil {
			t.Fatal(err)
		}
		rows, err := r.ListByAttack(ctx, 20)
		if err != nil || len(rows) != 1 || rows[0].Status != "failed" || rows[0].ErrorMessage == "" {
			t.Fatalf("device: seeded rows=%+v err=%v; want one failed row with error_message", rows, err)
		}
		if ok, err := r.MarkWithdrawing(ctx, 20, 30, 7, "td204"); err != nil || !ok {
			t.Fatalf("device: MarkWithdrawing ok=%v err=%v", ok, err)
		}
		if err := r.MarkWithdrawn(ctx, 20, 30, 7, "td204"); err != nil {
			t.Fatal(err)
		}
		rows, err = r.ListByAttack(ctx, 20)
		if err != nil || len(rows) != 1 || rows[0].Status != "withdrawn" {
			t.Fatalf("rows after MarkWithdrawn=%+v err=%v; want one withdrawn row", rows, err)
		}
		if rows[0].ErrorMessage != "" {
			t.Errorf("withdrawn row error_message=%q; want empty", rows[0].ErrorMessage)
		}
	})
}
