package action

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestDao14c1_LegacyMessageExact(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		want    string
	}{
		{
			name: "enabled", enabled: true,
			want: "legacy bgp_withdraw without announcement row: 192.0.2.10/32 route-map=RTBH connector=dao4 (id=7) may remain in FRR and was not withdrawn automatically; Active Mitigations > BGP Routing > orphan banner > Force Withdraw; if listed under dismissed orphans (incl. Dismissed on upgrade), Un-dismiss first, then Force Withdraw",
		},
		{
			name: "disabled", enabled: false,
			want: "legacy bgp_withdraw without announcement row: 192.0.2.10/32 route-map=RTBH connector=dao4 (id=7) may remain in FRR and was not withdrawn automatically; Active Mitigations > BGP Routing > orphan banner > Force Withdraw; if listed under dismissed orphans (incl. Dismissed on upgrade), Un-dismiss first, then Force Withdraw; connector is disabled: enable it and restart the controller (startup orphan scan), or run `no network` on the FRR host",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := legacyNoRowMessage("192.0.2.10/32", "RTBH", &store.BGPConnector{ID: 7, Name: "dao4", Enabled: tc.enabled})
			if got != tc.want {
				t.Errorf("ASSERT LegacyMessageExact.%s FAIL got=%q want=%q", tc.name, got, tc.want)
			} else {
				t.Logf("ASSERT LegacyMessageExact.%s PASS got=%q", tc.name, got)
			}
		})
	}
}

func dao14c1Function(t *testing.T, file, name string) *ast.FuncDecl {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatalf("DEVICE parse %s: %v", file, err)
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}
func dao14c1Call(n ast.Node, name string) bool {
	c, ok := n.(*ast.CallExpr)
	if !ok {
		return false
	}
	s, ok := c.Fun.(*ast.SelectorExpr)
	return ok && s.Sel.Name == name
}
func dao14c1Contains(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if v, ok := n.(*ast.Ident); ok && v.Name == name {
			found = true
		}
		return true
	})
	return found
}
func dao14c1StaticCheck(t *testing.T, name string, ok bool) {
	t.Helper()
	if !ok {
		t.Errorf("ASSERT %s FAIL", name)
	} else {
		t.Logf("ASSERT %s PASS", name)
	}
}
func TestDao14c1_S1(t *testing.T) {
	f := dao14c1Function(t, "../api/bgp_connector.go", "updateBGPConnector")
	if f == nil {
		t.Fatal("DEVICE update function missing")
	}
	var update token.Pos
	valid := false
	ast.Inspect(f.Body, func(n ast.Node) bool {
		if dao14c1Call(n, "Update") {
			update = n.Pos()
		}
		if cond, ok := n.(*ast.IfStmt); ok {
			ast.Inspect(cond.Body, func(n ast.Node) bool {
				if g, ok := n.(*ast.GoStmt); ok && dao14c1Call(g.Call, "SweepEnabledBGPConnector") {
					valid = dao14c1Contains(cond.Cond, "conn") && dao14c1Contains(cond.Cond, "Enabled") && !dao14c1Contains(cond.Cond, "old") && update > 0 && g.Pos() > update
				}
				return true
			})
		}
		return true
	})
	if update == 0 {
		t.Fatal("DEVICE scanner did not find Update positive control")
	}
	dao14c1StaticCheck(t, "S1.EnabledUpdateDispatch", valid)
}
func TestDao14c1_S2(t *testing.T) {
	f := dao14c1Function(t, "engine.go", "executeRecoveredBGPWithdrawByAnnouncement")
	if f == nil {
		t.Fatal("DEVICE recovery function missing")
	}
	found, solo := false, false
	ast.Inspect(f.Body, func(n ast.Node) bool {
		if sw, ok := n.(*ast.SwitchStmt); ok {
			sel, ok := sw.Tag.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Status" {
				return true
			}
			for _, s := range sw.Body.List {
				c, ok := s.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, v := range c.List {
					if l, ok := v.(*ast.BasicLit); ok {
						value, _ := strconv.Unquote(l.Value)
						if value == "active" {
							found = true
							solo = len(c.List) == 1
						}
					}
				}
			}
		}
		return true
	})
	if !found {
		t.Fatal("DEVICE scanner did not find active case positive control")
	}
	dao14c1StaticCheck(t, "S2.ActiveSeparate", solo)
}
func TestDao14c1_S3(t *testing.T) {
	f := dao14c1Function(t, "bgp.go", "bgpAnnounce")
	if f == nil {
		t.Fatal("DEVICE announce function missing")
	}
	comp, valid := false, false
	ast.Inspect(f.Body, func(n ast.Node) bool {
		if dao14c1Call(n, "MarkFailedAnnounce") {
			comp = true
		}
		if first, ok := n.(*ast.IfStmt); ok && dao14c1Contains(first.Cond, "Err") {
			if second, ok := first.Else.(*ast.IfStmt); ok && dao14c1Contains(second.Cond, "Exited") {
				if block, ok := second.Else.(*ast.BlockStmt); ok {
					ast.Inspect(block, func(n ast.Node) bool {
						if dao14c1Call(n, "MarkFailedAnnounce") {
							valid = true
						}
						return true
					})
				}
			}
		}
		return true
	})
	if !comp {
		t.Fatal("DEVICE compensation positive control missing")
	}
	dao14c1StaticCheck(t, "S3.SignalBeforeCompensation", valid)
}
func dao14c1LockShape(f *ast.FuncDecl, lock string) bool {
	if f == nil {
		return false
	}
	var lp, rp token.Pos
	async := false
	ast.Inspect(f.Body, func(n ast.Node) bool {
		if dao14c1Call(n, lock) {
			lp = n.Pos()
		}
		if dao14c1Call(n, "retryBGPWithdraw") {
			rp = n.Pos()
		}
		if g, ok := n.(*ast.GoStmt); ok {
			ast.Inspect(g, func(n ast.Node) bool {
				if dao14c1Call(n, "retryBGPWithdraw") {
					async = true
				}
				return true
			})
		}
		return true
	})
	return lp > 0 && rp > lp && !async
}
func TestDao14c1_S4(t *testing.T) {
	if !dao14c1LockShape(dao14c1Function(t, "withdrawing_reconcile.go", "reconcileWithdrawing"), "tryLockAnnouncement") {
		t.Fatal("DEVICE lock scanner positive control failed")
	}
	dao14c1StaticCheck(t, "S4.LockedSynchronousSweep", dao14c1LockShape(dao14c1Function(t, "startup_cleanup.go", "sweepEnabledAnnouncement"), "LockAnnouncement"))
}
func TestDao14c1_S5(t *testing.T) {
	f := dao14c1Function(t, "engine.go", "reconcileBGPWithdrawing")
	start := dao14c1Function(t, "engine.go", "ReconcileOnStartup")
	if f == nil || start == nil {
		t.Fatal("DEVICE startup functions missing")
	}
	var guard, retry token.Pos
	ast.Inspect(f.Body, func(n ast.Node) bool {
		if g, ok := n.(*ast.GoStmt); ok && dao14c1Call(g.Call, "retryBGPWithdraw") {
			retry = g.Pos()
		}
		if v, ok := n.(*ast.IfStmt); ok && dao14c1Contains(v.Cond, "owned") {
			ast.Inspect(v.Body, func(n ast.Node) bool {
				if b, ok := n.(*ast.BranchStmt); ok && b.Tok == token.CONTINUE {
					guard = v.Pos()
				}
				return true
			})
		}
		return true
	})
	name := ""
	passed := false
	ast.Inspect(start.Body, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok && len(a.Rhs) == 1 && dao14c1Call(a.Rhs[0], "reconcileExecutingSchedules") && len(a.Lhs) == 1 {
			if id, ok := a.Lhs[0].(*ast.Ident); ok {
				name = id.Name
			}
		}
		if c, ok := n.(*ast.CallExpr); ok && dao14c1Call(c, "reconcileBGPWithdrawing") && len(c.Args) == 2 {
			if id, ok := c.Args[1].(*ast.Ident); ok {
				passed = name != "" && id.Name == name
			}
		}
		return true
	})
	if retry == 0 {
		t.Fatal("DEVICE retry scanner positive control failed")
	}
	dao14c1StaticCheck(t, "S5.OwnedSkip", guard > 0 && guard < retry)
	dao14c1StaticCheck(t, "S5.OwnershipPassed", passed)
}
