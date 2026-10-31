package tracker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestDao12g_G1(t *testing.T) {
	t.Run("Table", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			pps, bps int64
			want     string
		}{
			{"critical_pps_equal", 1_000_000, 0, "high"},
			{"critical_pps_above", 1_000_001, 0, "critical"},
			{"critical_bps_equal", 0, 10_000_000_000, "high"},
			{"critical_bps_above", 0, 10_000_000_001, "critical"},
			{"high_pps_equal", 100_000, 0, "medium"},
			{"high_pps_above", 100_001, 0, "high"},
			{"high_bps_equal", 0, 1_000_000_000, "medium"},
			{"high_bps_above", 0, 1_000_000_001, "high"},
			{"medium_pps_equal", 10_000, 0, "low"},
			{"medium_pps_above", 10_001, 0, "medium"},
			{"medium_bps_equal", 0, 100_000_000, "low"},
			{"medium_bps_above", 0, 100_000_001, "medium"},
			{"zero", 0, 0, "low"},
			{"max_int64", 9_223_372_036_854_775_807, 0, "critical"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := classifySeverity(tc.pps, tc.bps); got != tc.want {
					t.Errorf("classifySeverity(%d, %d) = %q, want %q", tc.pps, tc.bps, got, tc.want)
				}
			})
		}
	})
	t.Run("Consts", func(t *testing.T) {
		file, err := parser.ParseFile(token.NewFileSet(), "tracker.go", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var fn *ast.FuncDecl
		consts := map[*ast.Object]bool{}
		for _, decl := range file.Decls {
			if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == "classifySeverity" {
				fn = f
			}
			if g, ok := decl.(*ast.GenDecl); ok && g.Tok == token.CONST {
				for _, spec := range g.Specs {
					v := spec.(*ast.ValueSpec)
					for _, id := range v.Names {
						consts[id.Obj] = !id.IsExported() && v.Type == nil && len(v.Values) > 0
					}
				}
			}
		}
		if fn == nil || fn.Body == nil {
			t.Fatal("classifySeverity body not found")
		}
		seen := map[string]bool{"severityCriticalPPS": false, "severityCriticalBPS": false,
			"severityHighPPS": false, "severityHighBPS": false, "severityMediumPPS": false, "severityMediumBPS": false}
		thresholds := map[int64]bool{1_000_000: true, 10_000_000_000: true, 100_000: true,
			1_000_000_000: true, 10_000: true, 100_000_000: true}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.INT {
				value, err := strconv.ParseInt(strings.ReplaceAll(lit.Value, "_", ""), 0, 64)
				if err != nil || thresholds[value] {
					t.Errorf("unexpected threshold literal or invalid integer: %s", lit.Value)
				}
			}
			if id, ok := n.(*ast.Ident); ok {
				if _, required := seen[id.Name]; required {
					seen[id.Name] = true
					if !consts[id.Obj] {
						t.Errorf("%s must resolve to a private package const without an explicit type", id.Name)
					}
				}
			}
			return true
		})
		for name, found := range seen {
			if !found {
				t.Errorf("classifySeverity does not reference %s", name)
			}
		}
	})
}
