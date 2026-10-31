package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestD2A_M15_MainWiring(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var recovered token.Pos
	starts := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "recoverOnStartup" {
				recovered = call.Pos()
			}
		}
		g, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		sel, ok := g.Call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RunXDropReconcile" {
			return true
		}
		starts++
		if recovered == 0 || g.Pos() < recovered {
			t.Error("loop must start after startup recovery")
		}
		if len(g.Call.Args) != 2 {
			t.Fatal("loop needs main ctx and interval")
		}
		ctx, ok := g.Call.Args[0].(*ast.Ident)
		if !ok || ctx.Name != "ctx" {
			t.Error("loop does not share main shutdown context")
		}
		interval, ok := g.Call.Args[1].(*ast.BinaryExpr)
		if !ok || interval.Op != token.MUL {
			t.Fatal("missing two-minute default")
		}
		number, ok := interval.X.(*ast.BasicLit)
		unit, unitOK := interval.Y.(*ast.SelectorExpr)
		if !ok || number.Value != "2" || !unitOK || unit.Sel.Name != "Minute" {
			t.Error("default interval must be 2 minutes")
		}
		return true
	})
	if starts != 1 {
		t.Fatalf("main xdrop loop starts=%d want 1", starts)
	}
}
