package postgres

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// This offline guard executes against the actual repository source. The same
// state inputs also run through the shared store contract in a DB-enabled lab.
func TestD2A_M12_CountLiveSQL(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "xdrop_active_rules.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	queries := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "CountLiveByConnector" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "QueryRow" {
				return true
			}
			queries++
			if len(call.Args) != 3 {
				t.Fatal("CountLive query must bind connector ID")
			}
			literal, ok := call.Args[1].(*ast.BasicLit)
			if !ok {
				t.Fatal("missing concrete count query")
			}
			query, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			query = strings.Join(strings.Fields(query), " ")
			want := "SELECT COUNT(*) FROM xdrop_active_rules WHERE connector_id=$1 AND status IN ('active','delayed','withdrawing','failed')"
			if query != want {
				t.Errorf("live count SQL=%q; want all four live states and connector binding", query)
			}
			arg, ok := call.Args[2].(*ast.Ident)
			if !ok || arg.Name != "connectorID" {
				t.Error("wrong connector binding")
			}
			return true
		})
	}
	if queries != 1 {
		t.Fatalf("count queries=%d want 1", queries)
	}
}
