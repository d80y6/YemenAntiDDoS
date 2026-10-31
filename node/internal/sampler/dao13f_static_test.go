package sampler

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

func TestDao13f_S5(t *testing.T) {
	t.Run("WorkerPassesMode", func(t *testing.T) {
		f := dao13fAST(t, "node/internal/sampler/worker_pool.go")
		for _, name := range []string{"runDirect", "workerLoop"} {
			fn := dao13fFunc(t, f, name)
			// runDirect's callback is part of the worker path being checked.
			var mode []*ast.CallExpr
			legacy := 0
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if dao13fText(c.Fun) == "parser.ParseMode" {
					mode = append(mode, c)
				}
				if dao13fText(c.Fun) == "parser.Parse" {
					legacy++
				}
				return true
			})
			if legacy != 0 || len(mode) != 1 || len(mode[0].Args) != 3 || dao13fText(mode[0].Args[2]) != "wp.erspan" {
				t.Errorf("%s must pass wp.erspan to exactly one ParseMode call", name)
			}
		}
		ctor := dao13fFunc(t, f, "NewWorkerPool")
		if len(ctor.Type.Params.List) != 4 || len(ctor.Type.Params.List[3].Names) != 1 {
			t.Fatal("missing fourth constructor parameter")
		}
		param := ctor.Type.Params.List[3].Names[0]
		stored := 0
		dao13fWalk(ctor.Body, func(n ast.Node) {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok || dao13fText(kv.Key) != "erspan" {
				return
			}
			id, ok := kv.Value.(*ast.Ident)
			if ok && id.Obj != nil && id.Obj == param.Obj {
				stored++
			}
		})
		if stored != 1 {
			t.Fatalf("fourth parameter stored %d times, want one", stored)
		}
	})
}
