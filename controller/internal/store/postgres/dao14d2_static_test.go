package postgres

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func dao14d2Function(t *testing.T, path, name string) *ast.FuncDecl {
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
	t.Fatalf("function %s missing in %s", name, path)
	return nil
}

func dao14d2Source(n ast.Node) string {
	var b bytes.Buffer
	if err := format.Node(&b, token.NewFileSet(), n); err != nil {
		panic(err)
	}
	return b.String()
}

func TestDao14d2_S23(t *testing.T) {
	fn := dao14d2Function(t, "postgres.go", "AutoMigrate")
	calls := map[string][]token.Pos{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
				calls[sel.Sel.Name] = append(calls[sel.Sel.Name], c.Pos())
			}
		}
		return true
	})
	for name, want := range map[string]int{"ensureCagg": 1, "applyChunkInterval": 2, "applyCaggRefreshPolicy": 1} {
		if got := len(calls[name]); got != want {
			t.Fatalf("S23 anchor %s count=%d want=%d", name, got, want)
		}
	}
	receiver := fn.Recv.List[0].Names[0].Name
	ctx := fn.Type.Params.List[0].Names[0].Name
	conforming := 0
	for _, st := range fn.Body.List {
		guard, ok := st.(*ast.IfStmt)
		if !ok || guard.Init != nil || guard.Else != nil || len(guard.Body.List) != 1 {
			continue
		}
		cond, ok := guard.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.GTR || dao14d2Source(cond.Y) != "0" {
			continue
		}
		field, ok := cond.X.(*ast.SelectorExpr)
		if !ok || field.Sel.Name != "TSStatsCaggDays" {
			continue
		}
		owner, ok := field.X.(*ast.Ident)
		if !ok {
			continue
		}
		want := fmt.Sprintf(`%s.applyCaggChunkInterval(%s, "ts_stats_5min", resolveChunkDays(0, %s.TSStatsCaggDays))`, receiver, ctx, owner.Name)
		if dao14d2Source(guard.Body.List[0]) != want {
			continue
		}
		position := guard.Pos()
		if position > calls["ensureCagg"][0] && position > calls["applyChunkInterval"][0] && position > calls["applyChunkInterval"][1] && position < calls["applyCaggRefreshPolicy"][0] {
			conforming++
		}
	}
	t.Logf("S23 total=%d conforming=%d anchors ensure=1 raw=2 refresh=1", len(calls["applyCaggChunkInterval"]), conforming)
	if len(calls["applyCaggChunkInterval"]) != 1 || conforming != 1 {
		t.Error("S23 requires exactly one complete guarded call after both raw chunk calls and before refresh")
	}
}

func TestDao14d2_S32(t *testing.T) {
	fn := dao14d2Function(t, "stats.go", "queryTimeseriesFromCagg")
	var guards []*ast.BlockStmt
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if g, ok := n.(*ast.IfStmt); ok && dao14d2Source(g.Cond) == "filter.IncludeExtras" {
			guards = append(guards, g.Body)
		}
		return true
	})
	total, unguarded := 0, 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(value, "AS extra_decoder_pps") && !strings.Contains(value, "AS extra_decoder_bps") {
			return true
		}
		total++
		for _, body := range guards {
			if lit.Pos() > body.Pos() && lit.End() < body.End() {
				return true
			}
		}
		unguarded++
		return true
	})
	t.Logf("S32 alias literals=%d unguarded=%d", total, unguarded)
	if total == 0 || unguarded != 0 {
		t.Error("S32 every outer extras alias must be guarded by filter.IncludeExtras")
	}
}
