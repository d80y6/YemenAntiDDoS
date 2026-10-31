package collector

import (
	"go/ast"
	"strings"
	"testing"
)

func TestDao14jia1_S7(t *testing.T) {
	f := dao13fAST(t, "node/internal/collector/collector.go")
	t.Run("LastGlobalAtAdjacent", func(t *testing.T) {
		total := 0
		for _, name := range []string{"New", "collect"} {
			fn := dao13fFunc(t, f, name)
			count := 0
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				b, ok := n.(*ast.BlockStmt)
				if !ok {
					return true
				}
				for i, s := range b.List {
					a, ok := s.(*ast.AssignStmt)
					if !ok {
						continue
					}
					for _, lhs := range a.Lhs {
						if dao13fText(lhs) == "c.lastGlobalAt" {
							count++
							if i == 0 || dao13fText(b.List[i-1]) != "c.lastGlobal = *gs" {
								t.Error("lastGlobalAt must immediately follow lastGlobal in the same block")
							}
						}
					}
				}
				return true
			})
			if count != 1 {
				t.Errorf("%s timestamp assignments=%d want=1", name, count)
			}
			total += count
		}
		all := 0
		ast.Inspect(f, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range a.Lhs {
					if dao13fText(lhs) == "c.lastGlobalAt" {
						all++
					}
				}
			}
			return true
		})
		if total != 2 || all != 2 {
			t.Errorf("timestamp assignments=%d targeted=%d want=2", all, total)
		}
	})
	t.Run("ScaleBetweenChecksAndSkip", func(t *testing.T) {
		fn := dao13fFunc(t, f, "collect")
		span, commit, checks, skip := -1, -1, -1, -1
		var scales []int
		for i, s := range fn.Body.List {
			txt := dao13fText(s)
			switch txt {
			case "k := tickSpan(c.lastGlobalAt, now)":
				span = i
			case "c.lastGlobal = *gs":
				commit = i
			case "skip := c.skipNextTick.Swap(false)":
				skip = i
			}
			if c, ok := s.(*ast.IfStmt); ok && dao13fText(c.Cond) == "gd.TotalPkts == 0" {
				checks = i
			}
			if e, ok := s.(*ast.ExprStmt); ok {
				if c, ok := e.X.(*ast.CallExpr); ok && strings.HasPrefix(dao13fText(c.Fun), "scale") {
					scales = append(scales, i)
				}
			}
		}
		if span < 0 || commit <= span {
			t.Error("tickSpan must precede global baseline commit")
		}
		if len(scales) != 5 || checks < 0 || skip < 0 {
			t.Errorf("scale calls=%d checks=%d skip=%d", len(scales), checks, skip)
		}
		for _, i := range scales {
			if i <= checks || i >= skip {
				t.Errorf("scale index %d outside (%d,%d)", i, checks, skip)
			}
		}
	})
}

func TestDao14jia1_S8(t *testing.T) {
	f := dao13fAST(t, "node/internal/collector/collector.go")
	t.Run("RateWiring", func(t *testing.T) {
		fn := dao13fFunc(t, f, "adjustSampleRate")
		if len(dao13fCalls(fn.Body, "c.mgr.SetSampleRate")) != 1 {
			t.Error("expected exactly one SetSampleRate call")
		}
		matched := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			i, ok := n.(*ast.IfStmt)
			if !ok || i.Init == nil || dao13fText(i.Init) != "err := c.mgr.SetSampleRate(cand)" {
				return true
			}
			matched++
			b, ok := i.Else.(*ast.BlockStmt)
			if dao13fText(i.Cond) != "err != nil" || !ok {
				t.Error("write must have error/success branches")
				return true
			}
			found := map[string]bool{}
			for _, s := range b.List {
				found[dao13fText(s)] = true
			}
			if !found["c.appliedRate = cand"] || !found["c.lastRateChange = now"] {
				t.Error("success branch must commit applied and timestamp")
			}
			return true
		})
		if matched != 1 {
			t.Errorf("guarded write count=%d", matched)
		}
		assignments := 0
		ast.Inspect(f, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range a.Lhs {
					s := dao13fText(lhs)
					if s == "c.appliedRate" || s == "c.lastRateChange" {
						assignments++
					}
				}
			}
			return true
		})
		if assignments != 2 {
			t.Errorf("applied/timestamp assignment count=%d want=2", assignments)
		}
		if len(fn.Body.List) == 0 || dao13fText(fn.Body.List[len(fn.Body.List)-1]) != "return c.appliedRate" {
			t.Error("must return applied rate")
		}
		logs := 0
		for _, c := range dao13fCalls(fn.Body, "log.Printf") {
			if len(c.Args) > 0 && strings.Contains(dao13fText(c.Args[0]), "backpressure engaged") {
				logs++
				found := false
				for _, arg := range c.Args[1:] {
					if dao13fText(arg) == "c.appliedRate" {
						found = true
					}
				}
				if !found {
					t.Error("backpressure log must report applied rate")
				}
			}
		}
		if logs != 1 {
			t.Errorf("backpressure logs=%d", logs)
		}
	})
	t.Run("SkipAndNew", func(t *testing.T) {
		fn := dao13fFunc(t, f, "collect")
		count := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok && dao13fText(a) == "sampleRate := c.appliedRate" {
				count++
			}
			return true
		})
		if count != 1 {
			t.Errorf("skip applied rate assignments=%d", count)
		}
		n := dao13fFunc(t, f, "New")
		count = 0
		for _, s := range n.Body.List {
			if i, ok := s.(*ast.IfStmt); ok && dao13fText(i.Cond) == "mgr != nil" {
				count += len(dao13fCalls(i.Body, "mgr.SetSampleRate"))
			}
		}
		if count != 1 {
			t.Errorf("New reset calls=%d want=1", count)
		}
	})
}
