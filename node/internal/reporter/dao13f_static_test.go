package reporter

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

func TestDao13f_S2(t *testing.T) {
	t.Run("ReporterRateReads", func(t *testing.T) {
		f := dao13fAST(t, "node/internal/reporter/reporter.go")
		stats := dao13fFunc(t, f, "runStatsStream")
		calls := dao13fCalls(stats.Body, "reportToProto")
		if len(calls) != 1 || len(calls[0].Args) != 7 || dao13fText(calls[0].Args[3]) != "rate" {
			t.Fatal("Stats conversion must take the report-bound rate")
		}
		reads, fallback := 0, false
		dao13fWalk(stats.Body, func(n ast.Node) {
			if s, ok := n.(*ast.SelectorExpr); ok && dao13fText(s) == "r.cfg.UpstreamRate" {
				reads++
			}
			if b, ok := n.(*ast.IfStmt); ok && dao13fText(b.Cond) == "rate == 0" &&
				len(b.Body.List) == 1 && dao13fText(b.Body.List[0]) == "rate = r.cfg.UpstreamRate" {
				fallback = true
			}
		})
		if reads != 1 || !fallback {
			t.Fatalf("startup-rate reads=%d zero fallback=%v", reads, fallback)
		}
		stores := dao13fCalls(stats.Body, "r.upstreamRate.Store")
		if len(stores) != 1 || len(stores[0].Args) != 1 || dao13fText(stores[0].Args[0]) != "rate" {
			t.Fatal("Stats must publish its effective rate")
		}
		sample := dao13fFunc(t, f, "runSampleStream")
		batches := dao13fCalls(sample.Body, "batchToProto")
		if len(batches) != 1 || len(batches[0].Args) != 5 ||
			dao13fText(batches[0].Args[3]) != "r.upstreamRate.Load()" || dao13fText(batches[0].Args[4]) != "r.localRate.Load()" {
			t.Fatal("Sample conversion must load the atomic Stats rates")
		}
		for _, name := range []string{"New", "NewFlow"} {
			init := dao13fCalls(dao13fFunc(t, f, name).Body, "r.upstreamRate.Store")
			if len(init) != 1 || len(init[0].Args) != 1 || dao13fText(init[0].Args[0]) != "cfg.UpstreamRate" {
				t.Errorf("%s must initialize the upstream rate", name)
			}
		}
	})
}
