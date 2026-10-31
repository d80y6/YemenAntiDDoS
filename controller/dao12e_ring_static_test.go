package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func dao12eSourceRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source file")
	}
	root := filepath.Dir(file)
	if _, err := os.ReadFile(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	return root
}

func dao12eParse(t *testing.T, file string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func dao12eSelectors(t *testing.T, file string, names map[string]bool) int {
	t.Helper()
	count := 0
	ast.Inspect(dao12eParse(t, file), func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && names[s.Sel.Name] {
			count++
		}
		return true
	})
	return count
}

func dao12ePath(e ast.Expr, parts ...string) bool {
	if len(parts) == 1 {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == parts[0]
	}
	s, ok := e.(*ast.SelectorExpr)
	return ok && s.Sel.Name == parts[len(parts)-1] && dao12ePath(s.X, parts[:len(parts)-1]...)
}

func TestDao12e_G1(t *testing.T) {
	root := dao12eSourceRoot(t)
	for _, gate := range []struct {
		name, control string
		names         map[string]bool
		min           int
	}{
		{"NoLockFreeLatest", "internal/store/ring/buffer.go", map[string]bool{"LatestOne": true}, 4},
		{"NoProdGetRing", "internal/ingestion/dao8_stats_test.go", map[string]bool{
			"GetPrefixRing": true, "GetSrcPrefixRing": true, "GetIPRing": true,
			"GetIPRingByKey": true, "GetSrcIPRingByKey": true,
		}, 4},
	} {
		t.Run(gate.name, func(t *testing.T) {
			count := 0
			err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if path == filepath.Join(root, "internal/store/ring") {
					return filepath.SkipDir
				}
				if !entry.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
					count += dao12eSelectors(t, path, gate.names)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			control := dao12eSelectors(t, filepath.Join(root, gate.control), gate.names)
			t.Logf("production selectors=%d; positive control=%d", count, control)
			if count != 0 {
				t.Errorf("production selectors=%d, want 0", count)
			}
			if control < gate.min {
				t.Errorf("positive control=%d, want >=%d", control, gate.min)
			}
		})
	}
	t.Run("LatestShape", func(t *testing.T) {
		wanted := map[string]bool{"LatestPrefix": true, "LatestSrcPrefix": true, "LatestIPByKey": true, "LatestSrcIPByKey": true}
		for _, decl := range dao12eParse(t, filepath.Join(root, "internal/store/ring/buffer.go")).Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !wanted[fn.Name.Name] || fn.Recv == nil {
				continue
			}
			recv, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
			if !ok || !dao12ePath(recv.X, "RingStore") {
				continue
			}
			delete(wanted, fn.Name.Name)
			locks, unlocks, reentries := 0, 0, 0
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if dao12ePath(call.Fun, "s", "mu", "RLock") {
						locks++
					}
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && dao12ePath(sel.X, "s") {
						reentries++
					}
				}
				if d, ok := n.(*ast.DeferStmt); ok && dao12ePath(d.Call.Fun, "s", "mu", "RUnlock") {
					unlocks++
				}
				return true
			})
			if locks != 1 || unlocks != 1 || reentries != 0 {
				t.Errorf("%s: RLock=%d deferred RUnlock=%d receiver calls=%d", fn.Name.Name, locks, unlocks, reentries)
			}
		}
		for name := range wanted {
			t.Errorf("missing RingStore.%s", name)
		}
	})
}
