package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func dao14b2Function(t *testing.T, path, name string) *ast.FuncDecl {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("function %s not found in %s", name, path)
	return nil
}

func TestDao14b2_S5(t *testing.T) {
	t.Run("P95DirectionFilter", func(t *testing.T) {
		for _, name := range []string{"QueryHourP95", "QueryWindowP95"} {
			t.Run(name, func(t *testing.T) {
				fn := dao14b2Function(t, "internal/store/postgres/stats.go", name)
				queries := 0
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Query" {
						return true
					}
					queries++
					if len(call.Args) < 2 {
						t.Error("Query lacks SQL argument")
						return true
					}
					lit, ok := call.Args[1].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						t.Error("Query SQL is not a string literal")
						return true
					}
					sql, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(sql, "direction = 'receives'") {
						t.Errorf("%s Query lacks inbound predicate: %s", name, sql)
					}
					return true
				})
				if queries != 1 {
					t.Errorf("Query calls=%d; want 1", queries)
				}
			})
		}
	})
}

func TestDao14b2_S4(t *testing.T) {
	t.Run("MainWiring", func(t *testing.T) {
		fn := dao14b2Function(t, "main.go", "main")
		configs, wired := 0, 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			sel, ok := lit.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Config" {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "tracker" {
				return true
			}
			configs++
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "ManualExpireHoldSeconds" {
					continue
				}
				call, ok := kv.Value.(*ast.CallExpr)
				if !ok {
					continue
				}
				method, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || method.Sel.Name != "ResolvedManualExpireHoldSeconds" || len(call.Args) != 0 {
					continue
				}
				detection, ok := method.X.(*ast.SelectorExpr)
				if !ok || detection.Sel.Name != "Detection" {
					continue
				}
				base, ok := detection.X.(*ast.Ident)
				if ok && base.Name == "cfg" {
					wired++
				}
			}
			return true
		})
		if configs != 1 || wired != 1 {
			t.Errorf("tracker.Config literals=%d resolved hold assignments=%d; want 1/1", configs, wired)
		}
	})
}
