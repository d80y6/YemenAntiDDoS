package main

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func dao13dRoot(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("XSIGHT_DAO13D_SOURCE_ROOT"); root != "" {
		return root
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source root unavailable")
	}
	return filepath.Dir(filepath.Dir(file))
}
func dao13dParse(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dao13dRoot(t), "controller", path), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func dao13dExpr(n ast.Node) string {
	var b bytes.Buffer
	_ = format.Node(&b, token.NewFileSet(), n)
	return b.String()
}
func dao13dName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}
func dao13dString(n ast.Node) string {
	if v, ok := n.(*ast.BasicLit); ok && v.Kind == token.STRING {
		s, _ := strconv.Unquote(v.Value)
		return s
	}
	return ""
}
func dao13dFn(t *testing.T, f *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("missing function %s", name)
	return nil
}
func dao13dCalls(n ast.Node, name string) int {
	count := 0
	ast.Inspect(n, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && dao13dName(c) == name {
			count++
		}
		return true
	})
	return count
}
func dao13dContains(n ast.Node, text string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if strings.Contains(dao13dString(n), text) {
			found = true
		}
		return true
	})
	return found
}
func dao13dValue(t *testing.T, f *ast.File, name string) ast.Expr {
	t.Helper()
	for _, d := range f.Decls {
		if g, ok := d.(*ast.GenDecl); ok {
			for _, spec := range g.Specs {
				if v, ok := spec.(*ast.ValueSpec); ok {
					for i, n := range v.Names {
						if n.Name == name && i < len(v.Values) {
							return v.Values[i]
						}
					}
				}
			}
		}
	}
	t.Fatalf("missing descriptor/value %s", name)
	return nil
}
func TestDao13d_G2(t *testing.T) {
	t.Run("S1", func(t *testing.T) {
		fn := dao13dFn(t, dao13dParse(t, "internal/store/postgres/postgres.go"), "AutoMigrate")
		var loop *ast.RangeStmt
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if r, ok := n.(*ast.RangeStmt); ok && dao13dExpr(r.X) == "migrations" {
				loop = r
			}
			return true
		})
		if loop == nil {
			t.Fatal("S1 migrations loop missing")
		}
		probe := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && dao13dName(c) == "QueryRow" && dao13dContains(c, "information_schema.tables") && c.Pos() < loop.Pos() {
				probe = true
			}
			return true
		})
		if !probe {
			t.Error("S1 pre-loop table probe missing")
		}
		for _, call := range []string{"Begin", "Commit", "Rollback"} {
			if dao13dCalls(loop.Body, call) == 0 {
				t.Errorf("S1 loop missing %s", call)
			}
		}
		refs := false
		ast.Inspect(loop.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "bootstrapSegments" {
				refs = true
			}
			return true
		})
		if !refs {
			t.Error("S1 loop does not use bootstrap descriptor")
		}
	})
	t.Run("S2", func(t *testing.T) {
		f := dao13dParse(t, "internal/store/postgres/postgres.go")
		desc, ok := dao13dValue(t, f, "bootstrapSegments").(*ast.CompositeLit)
		if !ok || len(desc.Elts) != 2 {
			t.Fatal("S2 descriptor must have exactly two segments")
		}
		expected := [][]string{{"webhook_connectors", "createWebhookConnectors", "copyLegacyWebhooks", "copyLegacyWebhooks"}, {"bgp_announcements", "createBGPAnnouncements", "bootstrapBGPAttachments", "bootstrapBGPAnnouncements", "bootstrapBGPAttachments"}}
		total := 0
		for i, e := range desc.Elts {
			row, ok := e.(*ast.CompositeLit)
			if !ok || len(row.Elts) != 4 {
				t.Fatal("S2 invalid segment")
			}
			if dao13dString(row.Elts[0]) != expected[i][0] || dao13dExpr(row.Elts[1]) != expected[i][1] || dao13dExpr(row.Elts[2]) != expected[i][2] {
				t.Error("S2 segment boundary changed")
			}
			gated, ok := row.Elts[3].(*ast.CompositeLit)
			if !ok || len(gated.Elts) != len(expected[i])-3 {
				t.Fatal("S2 gated statements changed")
			}
			for j, g := range gated.Elts {
				total++
				if dao13dExpr(g) != expected[i][j+3] {
					t.Error("S2 unexpected gated statement")
				}
				sql := dao13dString(dao13dValue(t, f, dao13dExpr(g)))
				if !strings.HasPrefix(sql, "INSERT INTO "+map[string]string{"copyLegacyWebhooks": "webhook_connectors", "bootstrapBGPAnnouncements": "bgp_announcements", "bootstrapBGPAttachments": "bgp_announcement_attacks"}[dao13dExpr(g)]) {
					t.Error("S2 gated SQL changed")
				}
			}
		}
		if total != 3 {
			t.Error("S2 expected three gated statements")
		}
		ms, ok := dao13dValue(t, f, "migrations").(*ast.CompositeLit)
		if !ok {
			t.Fatal("S2 migrations not a literal")
		}
		for _, table := range []string{"xdrop_active_rules", "action_manual_overrides"} {
			n := 0
			for _, e := range ms.Elts {
				if strings.HasPrefix(dao13dString(e), "INSERT INTO "+table) {
					n++
				}
			}
			if n != 1 {
				t.Errorf("S2 %s must remain direct in migrations", table)
			}
		}
	})
	t.Run("S3", func(t *testing.T) {
		f := dao13dParse(t, "internal/store/postgres/postgres.go")
		for _, name := range []string{"removeRetentionPolicy", "removeCompressionPolicy"} {
			fn := dao13dFn(t, f, name)
			checked := false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				i, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				a, ok := i.Init.(*ast.AssignStmt)
				if !ok || len(a.Lhs) != 2 || len(a.Rhs) != 1 {
					return true
				}
				err, ok := a.Lhs[1].(*ast.Ident)
				if !ok || err.Name == "_" {
					return true
				}
				c, ok := a.Rhs[0].(*ast.CallExpr)
				if ok && dao13dName(c) == "Exec" && dao13dExpr(i.Cond) == err.Name+" != nil" {
					checked = true
				}
				return true
			})
			if !checked {
				t.Errorf("S3 %s must test named Exec error", name)
			}
		}
	})
	t.Run("S4", func(t *testing.T) {
		f := dao13dParse(t, "main.go")
		configOK, flowOperand := false, false
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.CompositeLit); ok && dao13dExpr(lit.Type) == "retention.Config" {
				values := map[string]string{}
				for _, e := range lit.Elts {
					if kv, ok := e.(*ast.KeyValueExpr); ok {
						values[dao13dExpr(kv.Key)] = dao13dExpr(kv.Value)
					}
				}
				_, old := values["HasTimescale"]
				configOK = !old && values["TSStatsHypertable"] == "db.IsHypertable(\"ts_stats\")" && values["FlowLogsHypertable"] == "db.IsHypertable(\"flow_logs\")"
			}
			if i, ok := n.(*ast.IfStmt); ok && dao13dCalls(i.Body, "New") > 0 && strings.Contains(dao13dExpr(i.Body), "retention.Config") {
				var visit func(ast.Expr)
				visit = func(e ast.Expr) {
					if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.LOR {
						visit(b.X)
						visit(b.Y)
					} else if dao13dExpr(e) == "cfg.Retention.FlowLogsDays > 0" {
						flowOperand = true
					}
				}
				if b, ok := i.Cond.(*ast.BinaryExpr); ok && b.Op == token.LOR {
					visit(i.Cond)
				}
			}
			return true
		})
		if !configOK {
			t.Error("S4 per-table cleaner configuration missing")
		}
		if !flowOperand {
			t.Error("S4 independent flow-only startup operand missing")
		}
	})
	t.Run("S5", func(t *testing.T) {
		f := dao13dParse(t, "internal/api/router.go")
		routes := 0
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || len(c.Args) != 2 {
				return true
			}
			method, path := dao13dName(c), dao13dString(c.Args[0])
			if (method == "POST" && path == "/webhooks") || ((method == "PUT" || method == "DELETE") && path == "/webhooks/:id") {
				routes++
				h, ok := c.Args[1].(*ast.CallExpr)
				if !ok || dao13dName(h) != "retiredLegacyWebhookWrite" {
					t.Errorf("S5 %s route not retired", method)
				}
			}
			return true
		})
		if routes != 3 {
			t.Error("S5 expected three legacy write routes")
		}
		paths, err := filepath.Glob(filepath.Join(dao13dRoot(t), "controller/internal/api/*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			f := dao13dParse(t, "internal/api/"+filepath.Base(path))
			ast.Inspect(f, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Create" || sel.Sel.Name == "Update" || sel.Sel.Name == "Delete") {
					if receiver, ok := sel.X.(*ast.CallExpr); ok && dao13dName(receiver) == "Webhooks" {
						t.Errorf("S5 legacy store write remains: %s", path)
					}
				}
				return true
			})
		}
	})
	t.Run("S6", func(t *testing.T) {
		fn := dao13dFn(t, dao13dParse(t, "internal/store/postgres/bgp_announcements.go"), "MarkFailedAnnounce")
		found := false
		ast.Inspect(fn, func(n ast.Node) bool {
			i, ok := n.(*ast.IfStmt)
			if !ok || !dao13dContains(i.Body, "DELETE FROM bgp_announcements") {
				return true
			}
			terms := map[string]bool{}
			var visit func(ast.Expr)
			visit = func(e ast.Expr) {
				if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.LAND {
					visit(b.X)
					visit(b.Y)
				} else {
					terms[dao13dExpr(e)] = true
				}
			}
			visit(i.Cond)
			if terms["status == \"announcing\""] && terms["refcount == 1"] && terms["currentGen == 0"] {
				found = true
			}
			return true
		})
		if !found {
			t.Error("S6 deletion must require announcing, refcount 1 and currentGen 0")
		}
	})
	t.Run("S7", func(t *testing.T) {
		// Production call sites only: exclude *_test.go and internal/store/storetest.
		// AST CallExpr excludes interface declarations and method definitions.
		total := 0
		for _, module := range []string{"controller", "node", "shared"} {
			err := filepath.WalkDir(filepath.Join(dao13dRoot(t), module), func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(filepath.Join(dao13dRoot(t), "controller"), path)
				if d.IsDir() && (rel == "console" || rel == "internal/store/storetest") {
					return filepath.SkipDir
				}
				if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
					return nil
				}
				total += dao13dCalls(dao13dParse(t, rel), "MarkFailedAnnounce")
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		bgp := dao13dFn(t, dao13dParse(t, "internal/action/bgp.go"), "bgpAnnounce")
		protected := 0
		ast.Inspect(bgp, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && dao13dName(c) == "retryBGPStateWrite" && len(c.Args) == 1 {
				if lit, ok := c.Args[0].(*ast.FuncLit); ok {
					protected += dao13dCalls(lit, "MarkFailedAnnounce")
				}
			}
			return true
		})
		engine := dao13dParse(t, "internal/action/engine.go")
		engineCalls := dao13dCalls(engine, "MarkFailedAnnounce")
		if total != 1 || dao13dCalls(bgp, "MarkFailedAnnounce") != 1 || protected != 1 || engineCalls != 0 {
			t.Errorf("S7 compensation calls total=%d protected=%d engine=%d; want 1/1/0", total, protected, engineCalls)
		}
		retry := dao13dFn(t, engine, "retryBGPAnnounce")
		warnings := 0
		ast.Inspect(retry, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || dao13dName(c) != "Printf" || len(c.Args) == 0 {
				return true
			}
			format := dao13dString(c.Args[0])
			if !strings.HasPrefix(format, "WARN action: retry announce") {
				return true
			}
			warnings++
			if len(c.Args) != 6 || !strings.Contains(format, "prefix=%q route_map=%q") || dao13dExpr(c.Args[2]) != "ann.Prefix" || dao13dExpr(c.Args[3]) != "ann.RouteMap" {
				t.Error("S7 new definite-failure WARN must quote prefix and route_map")
			}
			return true
		})
		if warnings != 3 {
			t.Errorf("S7 definite-failure warnings=%d; want 3", warnings)
		}
	})
}
