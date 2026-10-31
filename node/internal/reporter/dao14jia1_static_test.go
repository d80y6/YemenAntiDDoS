package reporter

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"

	"github.com/littlewolf9527/xsight/node/internal/collector"
)

func dao14ReporterText(n ast.Node) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, token.NewFileSet(), n)
	return b.String()
}

func TestDao14jia1_G7c(t *testing.T) {
	t.Run("RealXDPReportCarriesGlobal", func(t *testing.T) {
		if reportToProto(&collector.Report{}, "n1", "xdp", 1, 0, nil, 0).GlobalStats == nil {
			t.Fatal("real XDP reports must carry global stats")
		}
	})
}

func TestDao14jia1_S11(t *testing.T) {
	t.Run("IdleCaseUsesFlowIdle", func(t *testing.T) {
		f, err := parser.ParseFile(token.NewFileSet(), "reporter.go", nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		funcs := map[string]*ast.FuncDecl{}
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok {
				funcs[fn.Name.Name] = fn
			}
		}
		fn := funcs["runStatsStream"]
		if fn == nil {
			t.Fatal("missing runStatsStream")
		}
		idleCases := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CommClause)
			if !ok || c.Comm == nil || dao14ReporterText(c.Comm) != "<-idle.C" {
				return true
			}
			idleCases++
			calls, direct := 0, 0
			for _, s := range c.Body {
				ast.Inspect(s, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						switch dao14ReporterText(call.Fun) {
						case "r.flowIdle":
							calls++
						case "sendFlow", "sendWithTimeout", "r.heartbeat":
							direct++
						}
					}
					return true
				})
			}
			if calls != 1 || direct != 0 {
				t.Errorf("flowIdle calls=%d direct sends=%d", calls, direct)
			}
			return true
		})
		if idleCases != 1 {
			t.Errorf("idle cases=%d want=1", idleCases)
		}
		idle := funcs["flowIdle"]
		if idle == nil {
			t.Fatal("missing function flowIdle")
		}
		if len(idle.Body.List) < 2 {
			t.Fatal("flowIdle missing prechecks")
		}
		i, ok := idle.Body.List[0].(*ast.IfStmt)
		if !ok || dao14ReporterText(i.Cond) != "ctx.Err() != nil" {
			t.Error("first statement must check ctx.Err()")
		}
		if _, ok := idle.Body.List[1].(*ast.SelectStmt); !ok {
			t.Error("second statement must pre-read flowReports")
		}
	})
}
