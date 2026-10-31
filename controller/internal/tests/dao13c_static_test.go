package tests

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func dao13cSourceRoot(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("XSIGHT_DAO13C_SOURCE_ROOT"); root != "" {
		return root
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source tree")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../.."))
}

func dao13cParse(t *testing.T, path string) *ast.File {
	t.Helper()
	tree, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dao13cSourceRoot(t), path), nil, parser.ParseComments)
	dao5bCheck(t, err)
	return tree
}

func dao13cCallName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	default:
		return ""
	}
}

func dao13cHasCall(node ast.Node, name string) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && dao13cCallName(c) == name {
			found = true
		}
		return true
	})
	return found
}

func dao13cReturnsFalse(block *ast.BlockStmt) bool {
	for _, stmt := range block.List {
		if ret, ok := stmt.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
			if ident, ok := ret.Results[0].(*ast.Ident); ok && ident.Name == "false" {
				return true
			}
		}
	}
	return false
}

func TestDao13c_G2_AST(t *testing.T) {
	t.Run("ClaimUnderLockAndRetryAfterOK", func(t *testing.T) {
		tree := dao13cParse(t, "controller/internal/action/withdrawing_reconcile.go")
		var body *ast.BlockStmt
		for _, decl := range tree.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "reconcileFailedWithdraw" {
				body = fn.Body
			}
		}
		if body == nil {
			t.Fatal("missing reconcileFailedWithdraw")
		}
		lock, lockGuard, unlock, claim, okGuard, retry := -1, -1, -1, -1, -1, -1
		for i, stmt := range body.List {
			if dao13cHasCall(stmt, "tryLockAnnouncement") {
				lock = i
			}
			if dao13cHasCall(stmt, "ClaimFailedWithdraw") {
				claim = i
			}
			if dao13cHasCall(stmt, "retryBGPWithdraw") {
				retry = i
			}
			if deferStmt, ok := stmt.(*ast.DeferStmt); ok && dao13cCallName(deferStmt.Call) == "unlock" {
				unlock = i
			}
			if conditional, ok := stmt.(*ast.IfStmt); ok {
				if not, ok := conditional.Cond.(*ast.UnaryExpr); ok && not.Op == token.NOT {
					if ident, ok := not.X.(*ast.Ident); ok && dao13cReturnsFalse(conditional.Body) {
						switch ident.Name {
						case "locked":
							lockGuard = i
						case "ok":
							okGuard = i
						}
					}
				}
			}
		}
		dao11jWant(t, "G2.A.ClaimUnderLock", lock >= 0 && lock < lockGuard && lockGuard < unlock && unlock < claim, true)
		dao11jWant(t, "G2.A.RetryAfterOK", claim >= 0 && claim < okGuard && okGuard < retry, true)
	})
	t.Run("AllFourCompensationsUseRetryLiteral", func(t *testing.T) {
		total, protected := 0, 0
		for _, path := range []string{"controller/internal/action/bgp.go", "controller/internal/action/engine.go"} {
			tree := dao13cParse(t, path)
			before := total
			ast.Inspect(tree, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if dao13cCallName(c) == "MarkFailedAnnounce" {
					total++
				}
				if dao13cCallName(c) == "retryBGPStateWrite" && len(c.Args) == 1 {
					if literal, ok := c.Args[0].(*ast.FuncLit); ok {
						ast.Inspect(literal, func(n ast.Node) bool {
							if inner, ok := n.(*ast.CallExpr); ok && dao13cCallName(inner) == "MarkFailedAnnounce" {
								protected++
								if len(inner.Args) == 0 {
									t.Error("missing compensation context")
								} else if arg, ok := inner.Args[0].(*ast.Ident); !ok || arg.Name != literal.Type.Params.List[0].Names[0].Name {
									t.Error("compensation does not use the retry callback context")
								}
							}
							return true
						})
					}
				}
				return true
			})
			want := 0
			if strings.HasSuffix(path, "/bgp.go") {
				want = 1
			}
			dao11jWant(t, "G2.B.FileCompensations."+path, total-before, want)
		}
		dao11jWant(t, "G2.B.TotalCompensations", total, 1)
		dao11jWant(t, "G2.B.RetryProtectedCompensations", protected, 1)
	})
	t.Run("ShellWaitDelay", func(t *testing.T) {
		tree := dao13cParse(t, "controller/internal/action/shell.go")
		found := false
		ast.Inspect(tree, func(n ast.Node) bool {
			a, ok := n.(*ast.AssignStmt)
			if !ok || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
				return true
			}
			sel, ok := a.Lhs[0].(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "WaitDelay" {
				return true
			}
			value, ok := a.Rhs[0].(*ast.Ident)
			found = ok && value.Name == "shellWaitDelay"
			return true
		})
		dao11jWant(t, "G2.C.ShellWaitDelay", found, true)
	})
}

func TestDao13c_G2_Copy(t *testing.T) {
	presentAtBase := map[string]bool{
		"Readme.EN": true, "Readme.ZH": true,
		"Guide.EN.Shared": true, "Guide.ZH.Shared": true,
	}
	for _, gate := range dao13cCopyGates {
		t.Run(gate.name, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(dao13cSourceRoot(t), gate.path))
			dao5bCheck(t, err)
			text := string(content)
			if strings.Contains(text, gate.before) {
				t.Errorf("ASSERT G2.Copy.%s FAIL obsolete promise remains: %q", gate.name, gate.before)
			} else {
				t.Logf("ASSERT G2.Copy.%s PASS", gate.name)
			}
			if presentAtBase[gate.name] {
				dao11jWant(t, "G2.Copy."+gate.name+".Present", strings.Contains(text, gate.after), true)
			}
			if strings.HasPrefix(gate.name, "I18n.") {
				dao11jWant(t, "G2.Copy."+gate.name+".Key", strings.Contains(text, "\"confirmDetachFromShared\":"), true)
				dao11jWant(t, "G2.Copy."+gate.name+".FullWithdrawalImpact", gate.after != "" && strings.Contains(text, gate.after), true)
			}
		})
	}
}

var dao13cCopyGates = []struct{ name, path, before, after string }{
	{"I18n.EN", "controller/console/src/i18n/en.ts", "This announcement is shared with {remaining} other attack(s). Detach only this attack — the route stays up for the remaining attacks. Continue?", "This route is shared with {remaining} other attack(s). Force Remove withdraws the entire route, so those attacks also lose protection. Continue?"},
	{"I18n.ZH", "controller/console/src/i18n/zh.ts", "本 announcement 还和 {remaining} 条其他 attack 共享。仅 detach 本 attack，路由为剩余 attack 保留，是否继续？", "该路由还与另外 {remaining} 个攻击共享。强制移除会撤回整条路由，这些攻击也将失去保护。是否继续？"},
	{"API.ViewType", "controller/internal/api/attacks.go", "// a differentiated prompt (single-attack withdraw vs shared-detach\n// affecting N siblings) without a second round-trip.", "// a route-withdraw prompt that warns about every other attached\n// attack losing protection, without a second round-trip."},
	{"API.RefcountField", "controller/internal/api/attacks.go", "// when refcount<=1, shared-detach warning when refcount>1).", "// when refcount<=1, full shared-route withdrawal warning when refcount>1)."},
	{"API.FailedRemove", "controller/internal/api/active_actions.go", "// lookup. Only on success — failed force-remove doesn't suppress\n\t\t// future auto execution. Idempotent via ON CONFLICT in repo.Create.", "// lookup after success. BGP ForceRemove already persists overrides\n\t\t// for every detached attachment before vtysh, even if withdrawal fails.\n\t\t// Idempotent via ON CONFLICT in repo.Create."},
	{"API.EN", "controller/API.md", "For BGP this detaches the attack from the announcement (and withdraws via vtysh when refcount drops to 0);", "For BGP this detaches all attacks from the shared announcement and withdraws the entire route via vtysh, removing protection for every attached attack;"},
	{"API.ZH", "controller/API.zh.md", "BGP 会把该攻击从公告解绑（refcount 降为 0 时通过 vtysh 撤回）；", "BGP 会解绑共享公告上的全部攻击，并通过 vtysh 撤回整条路由，所有挂载攻击都会失去该路由的保护；"},
	{"Readme.EN", "README.md", "per-attack Force Remove so a single attack can be detached without withdrawing the shared route.", "for BGP, it withdraws the entire shared route, removing protection for every attached attack."},
	{"Readme.ZH", "README.zh.md", "逐攻击 Force Remove，可在不撤回共享路由的情况下解绑单个攻击。", "对 BGP 执行该操作会撤回整条共用路由，所有挂载攻击都会失去该路由的保护。"},
	{"Guide.EN.ActionsLog", "docs/user-guide.md", "A per-attack **Force Remove** button lets you detach this attack from a shared BGP announcement or remove its xDrop rule without affecting other attached attacks", "The **Force Remove** button withdraws the entire shared BGP route, removing protection for all attached attacks, or removes this attack's xDrop rule"},
	{"Guide.EN.Shared", "docs/user-guide.md", "To detach a single attack without withdrawing the shared route, use the per-attack Force Remove button on the Attack Detail page.", "**Force Withdraw** (BGP) detaches all attached attacks and withdraws the entire shared route."},
	{"Guide.ZH.ActionsLog", "docs/user-guide.zh.md", "逐攻击 **Force Remove** 按钮允许在不影响其他 attach 攻击的情况下，把本攻击从共享 BGP 公告解绑，或删除其 xDrop 规则", "**Force Remove** 按钮会解绑共享 BGP 公告上的全部攻击并撤回整条路由，所有挂载攻击都会失去该路由的保护；对 xDrop 则删除本攻击的规则"},
	{"Guide.ZH.Shared", "docs/user-guide.zh.md", "若只想解绑单个攻击而不影响共享路由，请在 Attack Detail 页面使用逐攻击的 Force Remove 按钮。", "**强制撤回**（BGP）解绑全部挂载攻击并撤回整条共享路由。"},
	{"Architecture.EN.Manual", "docs/architecture.md", "1. The actual removal is executed first (vtysh withdraw or xDrop DELETE).\n2. A `manual_override` execution log entry is written with the artifact's business key.", "1. For BGP, Force Remove first commits detachment of all attached attacks, then writes their manual overrides and audit logs, and finally runs vtysh withdrawal. Every attached attack loses the shared route's protection; a failed withdrawal does not undo the recorded overrides.\n2. For xDrop, the rule is DELETEd first and a `manual_override` execution log entry is written with the artifact's business key."},
	{"Architecture.ZH.Manual", "docs/architecture.zh.md", "1. 首先执行实际的移除操作（vtysh 撤回或 xDrop DELETE）。\n2. 写入一条 `manual_override` 执行日志条目，携带该制品的业务键。", "1. BGP 强制移除先提交全部挂载攻击的解绑，再写入这些攻击的 manual override 和审计日志，最后执行 vtysh 撤回。所有挂载攻击都会失去共享路由的保护；撤回失败不会撤销已记录的 override。\n2. xDrop 先 DELETE 规则，再写入携带该制品业务键的 `manual_override` 执行日志条目。"},
}
