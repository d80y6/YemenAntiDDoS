package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func dao14Parse(t *testing.T, source string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "gate.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func dao14Source(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func dao14Function(f *ast.File, name, receiver string) *ast.FuncDecl {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		if receiver == "" && fn.Recv == nil {
			return fn
		}
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			ptr, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if ok && dao14Path(ptr.X, receiver) {
				return fn
			}
		}
	}
	return nil
}

func dao14Path(e ast.Expr, parts ...string) bool {
	if len(parts) == 1 {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == parts[0]
	}
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == parts[len(parts)-1] && dao14Path(sel.X, parts[:len(parts)-1]...)
}

func dao14One(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "1"
}

// S1: inspect the four actual non-nil breach blocks, not comments or other functions.
func dao14S1(f *ast.File) bool {
	fn := dao14Function(f, "Tick", "Detector")
	if fn == nil {
		return false
	}
	blocks, assignments := 0, 0
	valid := true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		st, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		cond, ok := st.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.NEQ || !dao14Path(cond.X, "breach") || !dao14Path(cond.Y, "nil") {
			return true
		}
		blocks++
		count := 0
		ast.Inspect(st.Body, func(n ast.Node) bool {
			if a, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range a.Lhs {
					if dao14Path(lhs, "breach", "Sustained") {
						count++
					}
				}
			}
			return true
		})
		assignments += count
		valid = valid && count == 1
		return true
	})
	return valid && blocks == 4 && assignments == 4
}

func dao14DynamicCalls(f *ast.File) []*ast.CallExpr {
	fn := dao14Function(f, "main", "")
	var calls []*ast.CallExpr
	if fn == nil {
		return calls
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		lit, ok := goStmt.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(lit.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && dao14Path(call.Fun, "dynamicBreaches") {
				calls = append(calls, call)
			}
			return true
		})
		return false
	})
	return calls
}

func dao14S2(f *ast.File) bool {
	fn := dao14Function(f, "dynamicBreaches", "")
	if fn == nil || len(dao14DynamicCalls(f)) != 1 {
		return false
	}
	count, valid := 0, true
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || !dao14Path(lit.Type, "engine", "ThresholdExceeded") {
			return true
		}
		dynamic, sustained := false, false
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if dao14Path(kv.Key, "Source") {
				value, ok := kv.Value.(*ast.BasicLit)
				dynamic = ok && value.Value == `"dynamic"`
			}
			sustained = sustained || dao14Path(kv.Key, "Sustained")
		}
		if dynamic {
			count++
			valid = valid && sustained
		}
		return true
	})
	return valid && count == 1
}

func dao14S3(f *ast.File) bool {
	fn := dao14Function(f, "main", "")
	if fn == nil {
		return false
	}
	var setters []*ast.CallExpr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetSustainWindow" {
				setters = append(setters, call)
			}
		}
		return true
	})
	if len(setters) != 1 || len(setters[0].Args) != 1 {
		return false
	}
	x, ok := setters[0].Args[0].(*ast.Ident)
	if !ok {
		return false
	}
	definitions := 0
	var rhs ast.Expr
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || (a.Tok != token.ASSIGN && a.Tok != token.DEFINE) {
			return true
		}
		for i, lhs := range a.Lhs {
			if dao14Path(lhs, x.Name) {
				definitions++
				if len(a.Rhs) == len(a.Lhs) {
					rhs = a.Rhs[i]
				}
			}
		}
		return true
	})
	call, ok := rhs.(*ast.CallExpr)
	if definitions != 1 || !ok || !dao14Path(call.Fun, "threshold", "SustainWindow") || len(call.Args) != 3 {
		return false
	}
	for i, want := range []string{"HardThresholdConfirmSeconds", "DynamicThresholdConfirmSeconds", "MaxPointsPerIP"} {
		sel, ok := call.Args[i].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != want {
			return false
		}
	}
	dynamic := dao14DynamicCalls(f)
	return len(dynamic) == 1 && len(dynamic[0].Args) == 5 && dao14Path(dynamic[0].Args[4], x.Name)
}

func dao14S4(f *ast.File) bool {
	for _, name := range []string{"LatestNPrefix", "LatestNSrcPrefix", "LatestNIPByKey", "LatestNSrcIPByKey"} {
		fn := dao14Function(f, name, "RingStore")
		if fn == nil {
			return false
		}
		locks, unlocks, reentries := 0, 0, 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if dao14Path(call.Fun, "s", "mu", "RLock") {
					locks++
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && dao14Path(sel.X, "s") {
					reentries++
				}
			}
			if d, ok := n.(*ast.DeferStmt); ok && dao14Path(d.Call.Fun, "s", "mu", "RUnlock") {
				unlocks++
			}
			return true
		})
		if locks != 1 || unlocks != 1 || reentries != 0 {
			return false
		}
	}
	return true
}

func dao14Reads(n ast.Node) map[token.Pos]bool {
	reads, writes := map[token.Pos]bool{}, map[token.Pos]bool{}
	ast.Inspect(n, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok && (a.Tok == token.ASSIGN || a.Tok == token.DEFINE) {
			for _, lhs := range a.Lhs {
				if dao14Path(lhs, "a", "tickSustained") {
					writes[lhs.Pos()] = true
				}
			}
		}
		if sel, ok := n.(*ast.SelectorExpr); ok && dao14Path(sel, "a", "tickSustained") {
			reads[sel.Pos()] = true
		}
		return true
	})
	for pos := range writes {
		delete(reads, pos)
	}
	return reads
}

func dao14S5(f *ast.File) bool {
	fn := dao14Function(f, "tick", "Tracker")
	if fn == nil {
		return false
	}
	reads := dao14Reads(fn.Body)
	if len(reads) == 0 {
		return false
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CaseClause); ok && len(c.List) == 1 && dao14Path(c.List[0], "StateConfirming") {
			for pos := range dao14Reads(c) {
				delete(reads, pos)
			}
		}
		return true
	})
	return len(reads) == 0
}

func dao14S6(f *ast.File) bool {
	for _, name := range []string{"countActive", "findLowestActive"} {
		fn := dao14Function(f, name, "Tracker")
		if fn == nil {
			return false
		}
		states := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if b, ok := n.(*ast.BinaryExpr); ok && (b.Op == token.EQL || b.Op == token.NEQ) {
				var other ast.Expr
				if dao14Path(b.X, "a", "State") {
					other = b.Y
				} else if dao14Path(b.Y, "a", "State") {
					other = b.X
				}
				if id, ok := other.(*ast.Ident); ok {
					states[id.Name] = true
				}
			}
			return true
		})
		if len(states) != 2 || !states["StateActive"] || !states["StateExpiring"] {
			return false
		}
	}
	return true
}

func dao14S7(f *ast.File) bool {
	fn := dao14Function(f, "transitionToActive", "Tracker")
	if fn == nil {
		return false
	}
	for _, comments := range f.Comments {
		if comments.Pos() >= fn.Pos() && comments.End() <= fn.End() && strings.Contains(comments.Text(), "will be discarded next tick") {
			return false
		}
	}
	return true
}

func dao14S8(f *ast.File) bool {
	fn := dao14Function(f, "dynamicBreaches", "")
	if fn == nil {
		return false
	}
	count := 0
	for _, stmt := range fn.Body.List {
		st, ok := stmt.(*ast.IfStmt)
		if !ok || st.Init != nil || st.Else != nil {
			continue
		}
		cond, ok := st.Cond.(*ast.BinaryExpr)
		if !ok || cond.Op != token.LSS || !dao14Path(cond.X, "window") || !dao14One(cond.Y) || len(st.Body.List) != 1 {
			continue
		}
		a, ok := st.Body.List[0].(*ast.AssignStmt)
		if ok && a.Tok == token.ASSIGN && len(a.Lhs) == 1 && len(a.Rhs) == 1 && dao14Path(a.Lhs[0], "window") && dao14One(a.Rhs[0]) {
			count++
		}
	}
	return count == 1
}

func TestDao14b1V04_Static(t *testing.T) {
	// Each scanner also rejects an in-memory defective copy. Baseline controls
	// lack the S1 assignments, dynamic helper, setter, history readers, or S5 reads;
	// baseline S6 selects only active candidates and S7 retains the obsolete comment.
	for _, gate := range []struct {
		name, path, old, replacement string
		check                        func(*ast.File) bool
	}{
		{"S1_DetectorSustainedField", "internal/engine/threshold/detector.go", "breach.Sustained = sustained(r, pts)", "_ = sustained(r, pts)", dao14S1},
		{"S2_DynamicSustainedField", "main.go", "Sustained: max(n, 1),", "", dao14S2},
		{"S3_SharedSustainWindow", "main.go", "threshold.SustainWindow(cfg.Detection.HardThresholdConfirmSeconds, cfg.Detection.DynamicThresholdConfirmSeconds, cfg.Ring.MaxPointsPerIP)", "10", dao14S3},
		{"S4_LatestNLockShape", "internal/store/ring/buffer.go", "s.mu.RLock()", "", dao14S4},
		{"S5_ConfirmingOnlyReads", "internal/tracker/tracker.go", "case StateActive:", "case StateActive:\n_ = a.tickSustained", dao14S5},
		{"S6_CapCandidateSet", "internal/tracker/tracker.go", "a.State == StateActive || a.State == StateExpiring", "a.State == StateActive", dao14S6},
		{"S7_SuppressionComment", "internal/tracker/tracker.go", "func (t *Tracker) transitionToActive(a *trackedAttack, now time.Time) {", "func (t *Tracker) transitionToActive(a *trackedAttack, now time.Time) {\n// will be discarded next tick", dao14S7},
		{"S8_DynamicWindowGuard", "main.go", "if window < 1 {\n\t\twindow = 1\n\t}", "", dao14S8},
	} {
		t.Run(gate.name, func(t *testing.T) {
			source := dao14Source(t, gate.path)
			if !gate.check(dao14Parse(t, source)) {
				t.Errorf("%s production AST does not satisfy the gate", gate.name)
			}
			control := strings.ReplaceAll(source, gate.old, gate.replacement)
			if control == source {
				t.Log("positive control anchor already absent in this mutation")
				return
			}
			if gate.check(dao14Parse(t, control)) {
				t.Error("positive control was not rejected by the same scanner")
			} else {
				t.Log("positive control rejected")
			}
		})
	}
}
