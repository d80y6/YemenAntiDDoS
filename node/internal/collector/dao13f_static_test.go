package collector

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

func TestDao13f_S1(t *testing.T) {
	t.Run("CollectErrorsGoThroughFail", func(t *testing.T) {
		f := dao13fAST(t, "node/internal/collector/collector.go")
		fn := dao13fFunc(t, f, "collect")
		if len(fn.Body.List) == 0 {
			t.Fatal("empty collect")
		}
		a, ok := fn.Body.List[0].(*ast.AssignStmt)
		if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 || a.Tok != token.DEFINE {
			t.Fatal("first statement must define fail")
		}
		fail, ok := a.Lhs[0].(*ast.Ident)
		if !ok || fail.Name != "fail" || fail.Obj == nil {
			t.Fatal("missing fail binding")
		}
		closure, ok := a.Rhs[0].(*ast.FuncLit)
		if !ok || len(closure.Body.List) != 2 ||
			dao13fText(closure.Body.List[0]) != "c.skipNextTick.Store(true)" ||
			dao13fText(closure.Body.List[1]) != "return nil, err" {
			t.Fatal("fail closure must store true then return nil, err")
		}
		count, bare := 0, 0
		dao13fWalk(fn.Body, func(n ast.Node) {
			r, ok := n.(*ast.ReturnStmt)
			if !ok {
				return
			}
			if len(r.Results) == 2 && dao13fText(r.Results[0]) == "nil" {
				bare++
			}
			if len(r.Results) == 1 {
				if c, ok := r.Results[0].(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && id.Obj == fail.Obj {
						count++
					}
				}
			}
		})
		if bare != 0 || count != 6 {
			t.Fatalf("bare errors=%d fail returns=%d, want 0 and 6", bare, count)
		}
	})
}

func TestDao13f_S6(t *testing.T) {
	t.Run("SkipConsumedBySwap", func(t *testing.T) {
		f := dao13fAST(t, "node/internal/collector/collector.go")
		fn := dao13fFunc(t, f, "collect")
		calls := dao13fCalls(fn.Body, "c.skipNextTick.Swap")
		if len(calls) != 1 || len(calls[0].Args) != 1 || dao13fText(calls[0].Args[0]) != "false" {
			t.Fatal("collect must consume skip with exactly one Swap(false)")
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := sel.X.(*ast.SelectorExpr)
			if ok && receiver.Sel.Name == "skipNextTick" &&
				(sel.Sel.Name == "Load" || sel.Sel.Name == "Store" && len(c.Args) == 1 && dao13fText(c.Args[0]) == "false") {
				t.Errorf("forbidden skip operation: %s", dao13fText(c))
			}
			return true
		})
		at := -1
		for i, s := range fn.Body.List {
			a, ok := s.(*ast.AssignStmt)
			if ok && len(a.Lhs) == 1 && len(a.Rhs) == 1 && a.Rhs[0] == calls[0] && dao13fText(a.Lhs[0]) == "skip" {
				at = i
			}
		}
		if at < 0 || at+2 >= len(fn.Body.List) {
			t.Fatal("missing top-level skip decision")
		}
		hook, ok := fn.Body.List[at+1].(*ast.IfStmt)
		if !ok || dao13fText(hook.Cond) != "testHookAfterSkipDecision != nil" ||
			len(hook.Body.List) != 1 || dao13fText(hook.Body.List[0]) != "testHookAfterSkipDecision()" {
			t.Fatal("decision hook must immediately follow Swap assignment")
		}
		branch, ok := fn.Body.List[at+2].(*ast.IfStmt)
		if !ok || dao13fText(branch.Cond) != "skip" {
			t.Fatal("skip branch must immediately follow hook")
		}
	})
}
