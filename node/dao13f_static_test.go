package main

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func dao13fRoot(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("DAO13F_SOURCE_ROOT"); root != "" {
		return root
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "node", "go.mod")); err == nil {
			return root
		}
		next := filepath.Dir(root)
		if next == root {
			t.Fatal("repository root not found")
		}
		root = next
	}
}

func dao13fAST(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dao13fRoot(t), path), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func dao13fText(n ast.Node) string {
	if n == nil {
		return ""
	}
	var b bytes.Buffer
	if err := format.Node(&b, token.NewFileSet(), n); err != nil {
		panic(err)
	}
	return b.String()
}

func dao13fFunc(t *testing.T, f *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	var found *ast.FuncDecl
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			if found != nil {
				t.Fatalf("duplicate function %s", name)
			}
			found = fn
		}
	}
	if found == nil {
		t.Fatalf("missing function %s", name)
	}
	return found
}

func dao13fWalk(n ast.Node, fn func(ast.Node)) {
	ast.Inspect(n, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if _, literal := n.(*ast.FuncLit); literal {
			return false
		}
		fn(n)
		return true
	})
}

func dao13fCalls(n ast.Node, name string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	dao13fWalk(n, func(n ast.Node) {
		if c, ok := n.(*ast.CallExpr); ok && dao13fText(c.Fun) == name {
			calls = append(calls, c)
		}
	})
	return calls
}

func TestDao13f_S4(t *testing.T) {
	t.Run("MainWiring", func(t *testing.T) {
		f := dao13fAST(t, "node/main.go")
		fn := dao13fFunc(t, f, "main")
		var cfg, primary *ast.Ident
		var cfgAssign *ast.AssignStmt
		for _, s := range fn.Body.List {
			a, ok := s.(*ast.AssignStmt)
			if !ok {
				continue
			}
			if len(a.Lhs) == 2 && len(a.Rhs) == 1 && dao13fText(a.Rhs[0]) == "config.Load(*configPath)" {
				cfg, _ = a.Lhs[0].(*ast.Ident)
				cfgAssign = a
			}
			if len(a.Lhs) == 1 && len(a.Rhs) == 1 && dao13fText(a.Rhs[0]) == "cfg.Interfaces[0]" {
				primary, _ = a.Lhs[0].(*ast.Ident)
			}
		}
		if cfg == nil || primary == nil || cfg.Obj == nil || primary.Obj == nil {
			t.Fatal("missing bound cfg or primaryIface")
		}
		t.Run("ImmutableConfig", func(t *testing.T) {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if a, ok := n.(*ast.AssignStmt); ok && a != cfgAssign {
					for _, lhs := range a.Lhs {
						if id, ok := lhs.(*ast.Ident); ok && id.Obj == cfg.Obj {
							t.Error("startup cfg is reassigned")
						}
					}
				}
				return true
			})
		})
		var hup []*ast.CaseClause
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CaseClause); ok {
				for _, v := range c.List {
					if dao13fText(v) == "syscall.SIGHUP" {
						hup = append(hup, c)
					}
				}
			}
			return true
		})
		boundMode := func(e ast.Expr) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Mode" {
				return false
			}
			id, ok := sel.X.(*ast.Ident)
			return ok && id.Obj == primary.Obj
		}
		t.Run("ReloadArguments", func(t *testing.T) {
			if len(hup) != 1 {
				t.Fatalf("SIGHUP clauses=%d", len(hup))
			}
			calls := dao13fCalls(hup[0], "reloadConfig")
			if len(calls) != 1 || len(calls[0].Args) != 4 {
				t.Fatal("SIGHUP must call reloadConfig once with four arguments")
			}
			a := calls[0].Args
			if dao13fText(a[0]) != "*configPath" || !boundMode(a[1]) ||
				dao13fText(a[2]) != "mgr.ApplyInterfaceConfig" || dao13fText(a[3]) != "coll.SetUpstreamRate" {
				t.Fatalf("unexpected reload call: %s", dao13fText(calls[0]))
			}
		})
		t.Run("PoolModeArgument", func(t *testing.T) {
			calls := dao13fCalls(fn.Body, "sampler.NewWorkerPool")
			if len(calls) != 1 || len(calls[0].Args) != 4 {
				t.Fatal("pool must receive a fourth argument")
			}
			b, ok := calls[0].Args[3].(*ast.BinaryExpr)
			if !ok || b.Op != token.EQL || !boundMode(b.X) || dao13fText(b.Y) != `"erspan"` {
				t.Fatal("pool mode must compare the bound primaryIface.Mode to erspan")
			}
		})
		t.Run("ApplyBeforeAttach", func(t *testing.T) {
			apply, attach := -1, -1
			for i, s := range fn.Body.List {
				if len(dao13fCalls(s, "mgr.ApplyInterfaceConfig")) != 0 {
					apply = i
				}
				if r, ok := s.(*ast.RangeStmt); ok && dao13fText(r.X) == "cfg.Interfaces" && len(dao13fCalls(r.Body, "mgr.AttachXDP")) != 0 {
					attach = i
				}
			}
			if apply < 0 || attach < 0 || apply >= attach {
				t.Fatalf("apply index=%d attach index=%d", apply, attach)
			}
		})
	})
}

func TestDao13f_R0FixedR(t *testing.T) {
	t.Run("ReloadGuardedAndWired", func(t *testing.T) {
		f := dao13fAST(t, "node/main.go")
		main := dao13fFunc(t, f, "main")
		if len(dao13fCalls(main.Body, "reloadConfig")) != 1 {
			t.Fatal("main must delegate reload validation")
		}
		reload := dao13fFunc(t, f, "reloadConfig")
		guard, apply := -1, -1
		for i, s := range reload.Body.List {
			if b, ok := s.(*ast.IfStmt); ok && dao13fText(b.Cond) == "newCfg.IsFlowMode() || len(newCfg.Interfaces) == 0" {
				guard = i
			}
			if len(dao13fCalls(s, "apply")) != 0 {
				apply = i
			}
		}
		if guard < 0 || apply <= guard {
			t.Fatalf("guard index=%d apply index=%d", guard, apply)
		}
	})
}
