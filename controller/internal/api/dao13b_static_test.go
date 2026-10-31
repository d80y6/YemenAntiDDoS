package api

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func dao13bSourceRoot() string {
	if root := os.Getenv("DAO13B_SOURCE_ROOT"); root != "" {
		return root
	}
	return "../.."
}
func dao13bAST(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func dao13bExpr(n ast.Node) string {
	var out bytes.Buffer
	_ = format.Node(&out, token.NewFileSet(), n)
	return out.String()
}
func dao13bFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}
func dao13bCalls(n ast.Node, name string) int {
	if n == nil {
		return 0
	}
	count := 0
	ast.Inspect(n, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && dao13bExpr(c.Fun) == name {
			count++
		}
		return true
	})
	return count
}

func TestDao13b_G2(t *testing.T) {
	root := dao13bSourceRoot()
	auth := dao13bAST(t, filepath.Join(root, "internal/api/auth.go"))
	router := dao13bAST(t, filepath.Join(root, "internal/api/router.go"))
	mainFile := dao13bAST(t, filepath.Join(root, "main.go"))
	t.Run("1", func(t *testing.T) {
		paths, err := filepath.Glob(filepath.Join(root, "internal/api/*.go"))
		if err != nil {
			t.Fatal(err)
		}
		count, owned := 0, 0
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			f := dao13bAST(t, path)
			owner := dao13bFunc(f, "requireAdminForWrites")
			ast.Inspect(f, func(n ast.Node) bool {
				if s, ok := n.(*ast.SelectorExpr); ok && dao13bExpr(s) == "http.StatusForbidden" {
					count++
					if owner != nil && s.Pos() > owner.Body.Pos() && s.End() < owner.Body.End() {
						owned++
					}
				}
				return true
			})
		}
		if count != 1 || owned != 1 {
			t.Errorf("StatusForbidden total=%d authorization-owned=%d; want 1/1", count, owned)
		}
	})
	t.Run("2", func(t *testing.T) {
		fn := dao13bFunc(router, "NewRouter")
		if fn == nil {
			t.Fatal("NewRouter missing")
		}
		found := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok || dao13bExpr(c.Fun) != "api.Use" {
				return true
			}
			found++
			if len(c.Args) != 2 {
				t.Errorf("api.Use arguments=%d want=2", len(c.Args))
				return true
			}
			a, okA := c.Args[0].(*ast.CallExpr)
			b, okB := c.Args[1].(*ast.CallExpr)
			if !okA || !okB || dao13bExpr(a.Fun) != "authMiddleware" || dao13bExpr(b.Fun) != "requireAdminForWrites" {
				t.Errorf("middleware order=%s", dao13bExpr(c))
			}
			return true
		})
		if found != 1 {
			t.Errorf("api.Use count=%d", found)
		}
	})
	t.Run("4", func(t *testing.T) {
		ast.Inspect(auth, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok && s.Sel.Name == "ClientIP" {
				t.Error("authentication uses ClientIP")
			}
			if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
				v, _ := strconv.Unquote(l.Value)
				if v == "X-Forwarded-For" || v == "X-Real-IP" {
					t.Errorf("authentication reads proxy header %s", v)
				}
			}
			return true
		})
	})
	fn := dao13bFunc(mainFile, "main")
	if fn == nil {
		t.Fatal("main missing")
	}
	t.Run("5a", func(t *testing.T) {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && dao13bExpr(c.Fun) == "[]byte" && len(c.Args) == 1 && dao13bExpr(c.Args[0]) == `"admin"` {
				t.Error("main contains default-password seed")
			}
			return true
		})
	})
	t.Run("5b", func(t *testing.T) {
		calls := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && dao13bExpr(c.Fun) == "api.EnsureInitialAdmin" {
				calls++
				if len(c.Args) != 3 || dao13bExpr(c.Args[2]) != "cfg.Auth.InitialAdminPassword" {
					t.Errorf("initial-admin arguments=%s", dao13bExpr(c))
				}
			}
			return true
		})
		if calls != 1 {
			t.Errorf("EnsureInitialAdmin calls=%d", calls)
		}
	})
	t.Run("5c", func(t *testing.T) {
		migrateIndex, ensureIndex := -1, -1
		for i, s := range fn.Body.List {
			if branch, ok := s.(*ast.IfStmt); ok && dao13bExpr(branch.Cond) == "*migrateOnly" {
				returns := 0
				ast.Inspect(branch.Body, func(n ast.Node) bool {
					if _, ok := n.(*ast.ReturnStmt); ok {
						returns++
					}
					return true
				})
				if returns > 0 {
					migrateIndex = i
				}
			}
			if dao13bCalls(s, "api.EnsureInitialAdmin") > 0 {
				ensureIndex = i
			}
		}
		if migrateIndex < 0 || ensureIndex <= migrateIndex {
			t.Errorf("top-level order: migrate=%d initial-admin=%d", migrateIndex, ensureIndex)
		}
	})
	t.Run("5d", func(t *testing.T) {
		valid := 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			branch, ok := n.(*ast.IfStmt)
			if !ok || branch.Init == nil || dao13bCalls(branch.Init, "api.EnsureInitialAdmin") == 0 {
				return true
			}
			if dao13bExpr(branch.Cond) != "err != nil" {
				t.Errorf("error condition=%s", dao13bExpr(branch.Cond))
			}
			if dao13bCalls(branch.Body, "log.Fatalf")+dao13bCalls(branch.Body, "log.Fatal") == 0 {
				t.Error("initial-admin failure is not fatal")
			} else {
				valid++
			}
			return true
		})
		if valid != 1 {
			t.Errorf("fatal initial-admin guards=%d", valid)
		}
	})
	t.Run("7", func(t *testing.T) {
		scan := func(fn *ast.FuncDecl) (int, int) {
			if fn == nil {
				return 0, 0
			}
			calls, selectors := dao13bCalls(fn.Body, "publishAfterChange"), 0
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if s, ok := n.(*ast.SelectorExpr); ok && s.Sel.Name == "ConfigPub" {
					selectors++
				}
				return true
			})
			return calls, selectors
		}
		for file, names := range map[string][]string{"users.go": {"createUser", "updateUser", "deleteUser", "auditDirect"}, "nodes.go": {"createNode", "updateNode", "deleteNode"}} {
			f := dao13bAST(t, filepath.Join(root, "internal/api", file))
			for _, name := range names {
				t.Run(name, func(t *testing.T) {
					calls, selectors := scan(dao13bFunc(f, name))
					if calls != 0 || selectors != 0 {
						t.Errorf("%s publishes: calls=%d ConfigPub selectors=%d", name, calls, selectors)
					}
				})
			}
		}
		t.Run("PositiveControl", func(t *testing.T) {
			f := dao13bAST(t, filepath.Join(root, "internal/api/shell_connectors.go"))
			calls, _ := scan(dao13bFunc(f, "createShellConnector"))
			if calls < 1 {
				t.Fatal("STOP: shell publication positive control missing")
			}
		})
	})
}

const dao13bDocPattern = "admin / admin|admin/admin|`admin`[[:space:]]*/[[:space:]]*`admin`|\\*\\*admin\\*\\*[[:space:]]*/[[:space:]]*\\*\\*admin\\*\\*"

func dao13bDocHits(t *testing.T, paths ...string) string {
	t.Helper()
	args := append([]string{"-nE", dao13bDocPattern}, paths...)
	out, err := exec.Command("/usr/bin/grep", args...).CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			t.Fatalf("grep error=%v output=%s", err, out)
		}
	}
	return string(out)
}
func TestDao13b_DocGate(t *testing.T) {
	root := filepath.Join(dao13bSourceRoot(), "..")
	var paths []string
	for _, pattern := range []string{"controller/API*.md", "controller/README*.md", "README.md", "README.zh.md", "GETTING_STARTED.md", "GETTING_STARTED.zh.md", "docs/user-guide*.md", "docs/architecture*.md"} {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) == 0 {
			t.Fatalf("document pattern has no files: %s", pattern)
		}
		paths = append(paths, matches...)
	}
	t.Run("Clean", func(t *testing.T) {
		if hits := dao13bDocHits(t, paths...); hits != "" {
			t.Errorf("default credentials remain:\n%s", hits)
		}
	})
	t.Run("RestoreUserGuideLineIsRed", func(t *testing.T) {
		for _, tc := range []struct{ lang, line string }{
			{"en", "2. Sign in with the default credentials: **admin** / **admin**."},
			{"zh", "2. \u4f7f\u7528\u9ed8\u8ba4\u51ed\u636e\u767b\u5f55\uff1a**admin** / **admin**\u3002"},
		} {
			t.Run(tc.lang, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "user-guide.md")
				if err := os.WriteFile(path, []byte(tc.line+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if hits := dao13bDocHits(t, path); hits == "" {
					t.Fatal("restored default-credential line did not make the gate red")
				}
			})
		}
	})
}
