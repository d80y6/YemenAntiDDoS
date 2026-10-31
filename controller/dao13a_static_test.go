package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func dao13aFunction(t *testing.T, path, name string, required bool) *ast.FuncDecl {
	t.Helper()
	root := os.Getenv("XSIGHT_DAO13A_SOURCE")
	if root == "" {
		root = "."
	}
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, path), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok && f.Name.Name == name {
			return f
		}
	}
	if required {
		t.Fatalf("target function %s missing in %s", name, path)
	}
	return nil
}

func dao13aExprName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return dao13aExprName(e.X) + "." + e.Sel.Name
	}
	return ""
}

func dao13aReturnsBool(body *ast.BlockStmt, want string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if r, ok := n.(*ast.ReturnStmt); ok {
			for _, e := range r.Results {
				if dao13aExprName(e) == want {
					found = true
				}
			}
		}
		return true
	})
	return found
}

func dao13aUnparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// Only flatten top-level conjunctions; do not infer constants or aliases.
func dao13aUpgradeCondition(e ast.Expr) (inbound, literal bool) {
	e = dao13aUnparen(e)
	if cmp, ok := e.(*ast.BinaryExpr); ok {
		if cmp.Op == token.LAND {
			leftGuard, leftLiteral := dao13aUpgradeCondition(cmp.X)
			rightGuard, rightLiteral := dao13aUpgradeCondition(cmp.Y)
			return leftGuard || rightGuard, leftLiteral || rightLiteral
		}
		if direction, ok := dao13aUnparen(cmp.X).(*ast.SelectorExpr); ok && direction.Sel.Name == "Direction" {
			if key, ok := dao13aUnparen(direction.X).(*ast.SelectorExpr); ok && key.Sel.Name == "Key" {
				value, ok := dao13aUnparen(cmp.Y).(*ast.BasicLit)
				return cmp.Op == token.NEQ && ok && value.Kind == token.STRING && value.Value == `"sends"`, false
			}
		}
	}
	name := dao13aExprName(e)
	return false, name == "true" || name == "false"
}

func dao13aNonliteral(e ast.Expr) bool {
	switch e := dao13aUnparen(e).(type) {
	case nil, *ast.BasicLit, *ast.CompositeLit, *ast.FuncLit:
		return false
	case *ast.Ident:
		return e.Name != "true" && e.Name != "false" && e.Name != "nil"
	}
	return true
}

func dao13aUpgradeOperation(n ast.Node) string {
	switch n := n.(type) {
	case *ast.AssignStmt:
		for _, lhs := range n.Lhs {
			if field, ok := dao13aUnparen(lhs).(*ast.SelectorExpr); ok && field.Sel.Name == "AttackType" {
				return "type assignment"
			}
		}
	case *ast.CallExpr:
		if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Update" {
			if repo, ok := sel.X.(*ast.CallExpr); ok {
				if method, ok := repo.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Attacks" {
					return "database update"
				}
			}
		}
		if method, ok := n.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "notifyAction" {
			return "upgrade notification"
		}
	}
	return ""
}

func TestDao13a_G2(t *testing.T) {
	t.Run("ShouldSuppressSelfBeforeSpecific", func(t *testing.T) {
		f := dao13aFunction(t, "internal/engine/dedup/dedup.go", "ShouldSuppress", true)
		var self, specific token.Pos
		ast.Inspect(f.Body, func(n ast.Node) bool {
			if loop, ok := n.(*ast.RangeStmt); ok {
				if idx, ok := loop.X.(*ast.IndexExpr); ok && dao13aExprName(idx.X) == "suppressedBy" && dao13aExprName(idx.Index) == "evt.Decoder" {
					specific = loop.Pos()
				}
			}
			check, ok := n.(*ast.IfStmt)
			if !ok || !dao13aReturnsBool(check.Body, "false") {
				return true
			}
			idx, ok := check.Cond.(*ast.IndexExpr)
			if !ok || dao13aExprName(idx.X) != "d.active" {
				return true
			}
			key, ok := idx.Index.(*ast.CompositeLit)
			if ok && dao13aExprName(key.Type) == "attackKey" && len(key.Elts) == 3 &&
				dao13aExprName(key.Elts[0]) == "dstIP" && dao13aExprName(key.Elts[1]) == "evt.Direction" && dao13aExprName(key.Elts[2]) == "evt.Decoder" {
				self = check.Pos()
			}
			return true
		})
		if self == token.NoPos || specific == token.NoPos || self >= specific {
			t.Fatalf("self-key exemption position=%d; suppression range position=%d", self, specific)
		}
	})
	t.Run("AncestorVisited", func(t *testing.T) {
		f := dao13aFunction(t, "internal/engine/threshold/tree.go", "collectAncestorChain", true)
		guard, mark, seeded := false, false, false
		ast.Inspect(f.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, e := range n.Lhs {
					if idx, ok := e.(*ast.IndexExpr); ok && dao13aExprName(idx.X) == "visited" {
						mark = len(n.Rhs) == 1 && dao13aExprName(n.Rhs[0]) == "true"
					}
				}
				for _, e := range n.Rhs {
					if lit, ok := e.(*ast.CompositeLit); ok {
						if _, ok := lit.Type.(*ast.MapType); ok {
							for _, elt := range lit.Elts {
								if kv, ok := elt.(*ast.KeyValueExpr); ok && dao13aExprName(kv.Key) == "node.ID" && dao13aExprName(kv.Value) == "true" {
									seeded = true
								}
							}
						}
					}
				}
			case *ast.IfStmt:
				if idx, ok := n.Cond.(*ast.IndexExpr); ok && dao13aExprName(idx.X) == "visited" && dao13aReturnsBool(n.Body, "true") {
					guard = true
				}
			}
			return true
		})
		if !guard || !mark || !seeded {
			t.Fatalf("visited guard=%v mark=%v start seed=%v", guard, mark, seeded)
		}
	})
	t.Run("InboundUpgrade", func(t *testing.T) {
		f := dao13aFunction(t, "internal/tracker/tracker.go", "UpgradeType", true)
		operations := map[string]int{"type assignment": 0, "database update": 0, "upgrade notification": 0}
		var ancestors []ast.Node
		ast.Inspect(f.Body, func(n ast.Node) bool {
			if n == nil {
				ancestors = ancestors[:len(ancestors)-1]
				return false
			}
			if operation := dao13aUpgradeOperation(n); operation != "" {
				guarded, allowed := false, true
				contains := func(parent ast.Node) bool {
					return parent != nil && n.Pos() >= parent.Pos() && n.End() <= parent.End()
				}
				for i, ancestor := range ancestors {
					switch a := ancestor.(type) {
					case *ast.FuncLit:
						allowed = false // Inspect its operations, including immediately invoked closures.
					case *ast.IfStmt:
						// An initializer executes in the containing block, before this if.
						// It cannot acquire a guard from the if's condition.
						if a.Init != nil && contains(a.Init) {
							continue
						}
						guard, literal := dao13aUpgradeCondition(a.Cond)
						allowed = allowed && contains(a.Body) && !literal
						guarded = guarded || (contains(a.Body) && guard)
					case *ast.RangeStmt:
						allowed = allowed && contains(a.Body) && dao13aNonliteral(a.X)
					case *ast.ForStmt:
						_, literal := dao13aUpgradeCondition(a.Cond)
						allowed = allowed && contains(a.Body) && dao13aNonliteral(a.Cond) && !literal
					case *ast.BlockStmt:
						if a == f.Body {
							continue
						}
						// A bare block or a switch/select body is outside this gate's grammar.
						switch parent := ancestors[i-1].(type) {
						case *ast.IfStmt:
							allowed = allowed && a == parent.Body
						case *ast.RangeStmt:
							allowed = allowed && a == parent.Body
						case *ast.ForStmt:
							allowed = allowed && a == parent.Body
						default:
							allowed = false
						}
					case *ast.AssignStmt, *ast.ExprStmt:
						// Simple statements containing an operation do not add control flow.
					default:
						if _, statement := ancestor.(ast.Stmt); statement {
							allowed = false
						}
					}
				}
				operations[operation]++
				if !guarded || !allowed {
					t.Errorf("%s violates the upgrade path grammar (inbound guard=%v allowed ancestors=%v)", operation, guarded, allowed)
				}
			}
			ancestors = append(ancestors, n)
			return true
		})
		for operation, count := range operations {
			if count == 0 {
				t.Errorf("UpgradeType has no %s to check", operation)
			}
		}
	})
	t.Run("StartupRebuildWiring", func(t *testing.T) {
		f := dao13aFunction(t, "main.go", "main", true)
		found := false
		ast.Inspect(f.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && dao13aExprName(call.Fun) == "threshTree.Rebuild" {
				found = len(call.Args) == 2 && dao13aExprName(call.Args[0]) == "ctx" && dao13aExprName(call.Args[1]) == "db"
			}
			return true
		})
		if !found {
			t.Fatal("startup no longer invokes the shared Tree.Rebuild")
		}
	})
	t.Run("RecoverNoConfigLookup", func(t *testing.T) {
		for _, name := range []string{"RecoverFromDB", "canonicalHostKey"} {
			f := dao13aFunction(t, "internal/tracker/tracker.go", name, name == "RecoverFromDB")
			if f == nil {
				continue // HEAD legitimately lacks the helper; recovery must exist.
			}
			ast.Inspect(f.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "Thresholds" || sel.Sel.Name == "Prefixes") {
						t.Errorf("%s consults current configuration through %s", name, sel.Sel.Name)
					}
				}
				return true
			})
		}
	})
}
