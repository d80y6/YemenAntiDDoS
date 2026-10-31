package api

import (
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This gate covers the explicit data-flow rules in the plan. It does not model
// reflection, cross-package forwarding, or storage in fields and global state.
type dao14d1Scan struct {
	info       *types.Info
	pkg        *types.Package
	errorType  *types.Interface
	sanitizers map[types.Object]bool
	sources    map[types.Object][]ast.Expr
	parents    map[ast.Node]ast.Node
}

func (s *dao14d1Scan) object(e ast.Expr) types.Object {
	switch e := e.(type) {
	case *ast.Ident:
		return s.info.ObjectOf(e)
	case *ast.SelectorExpr:
		return s.info.ObjectOf(e.Sel)
	}
	return nil
}

func (s *dao14d1Scan) cleanCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	return ok && s.sanitizers[s.object(call.Fun)]
}

func (s *dao14d1Scan) stringType(e ast.Expr) bool {
	typ := s.info.TypeOf(e)
	return typ != nil && types.Identical(typ, types.Typ[types.String])
}

func (s *dao14d1Scan) tainted(e ast.Expr, seen map[types.Object]bool) bool {
	if e == nil || s.cleanCall(e) {
		return false
	}
	if typ := s.info.TypeOf(e); typ != nil && types.Implements(typ, s.errorType) {
		return true
	}
	if literal, ok := e.(*ast.FuncLit); ok {
		bad := false
		ast.Inspect(literal.Body, func(node ast.Node) bool {
			if ret, ok := node.(*ast.ReturnStmt); ok {
				for _, result := range ret.Results {
					bad = bad || s.tainted(result, seen)
				}
			}
			return true
		})
		return bad
	}
	if id, ok := e.(*ast.Ident); ok {
		object := s.info.ObjectOf(id)
		if !seen[object] {
			seen[object] = true
			defer delete(seen, object)
			for _, source := range s.sources[object] {
				if s.tainted(source, seen) {
					return true
				}
			}
		}
		return false
	}
	if call, ok := e.(*ast.CallExpr); ok {
		if object := s.object(call.Fun); object != nil && !seen[object] {
			seen[object] = true
			defer delete(seen, object)
			for _, source := range s.sources[object] {
				if literal, ok := source.(*ast.FuncLit); ok {
					bad := false
					ast.Inspect(literal.Body, func(node ast.Node) bool {
						if ret, ok := node.(*ast.ReturnStmt); ok {
							for _, result := range ret.Results {
								bad = bad || s.tainted(result, seen)
							}
						}
						return true
					})
					if bad {
						return true
					}
				}
			}
		}
	}
	bad := false
	ast.Inspect(e, func(node ast.Node) bool {
		if node == e {
			return true
		}
		if child, ok := node.(ast.Expr); ok {
			bad = bad || s.tainted(child, seen)
			return false
		}
		return true
	})
	return bad
}

func (s *dao14d1Scan) derived(e ast.Expr, marked map[types.Object]bool) bool {
	if e == nil || s.cleanCall(e) {
		return false
	}
	switch e := e.(type) {
	case *ast.Ident:
		return marked[s.info.ObjectOf(e)]
	case *ast.ParenExpr:
		return s.derived(e.X, marked)
	case *ast.StarExpr:
		return s.derived(e.X, marked)
	case *ast.TypeAssertExpr:
		return s.derived(e.X, marked)
	case *ast.IndexExpr:
		return s.derived(e.X, marked)
	case *ast.SliceExpr:
		return s.derived(e.X, marked)
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (s.derived(e.X, marked) || s.derived(e.Y, marked))
	case *ast.SelectorExpr:
		return s.stringType(e) && s.derived(e.X, marked)
	case *ast.CallExpr:
		if s.info.Types[e.Fun].IsType() {
			return len(e.Args) == 1 && s.derived(e.Args[0], marked)
		}
		object := s.object(e.Fun)
		allowedArgs := false
		if object != nil && object.Pkg() != nil {
			path, name := object.Pkg().Path(), object.Name()
			allowedArgs = path == "fmt" && (name == "Sprint" || name == "Sprintf" || name == "Sprintln")
			allowedArgs = allowedArgs || path == "strings" && name == "Join"
			allowedArgs = allowedArgs || object.Pkg() == s.pkg && s.stringType(e)
		}
		if allowedArgs {
			for _, arg := range e.Args {
				if s.derived(arg, marked) {
					return true
				}
			}
		}
		if selector, ok := e.Fun.(*ast.SelectorExpr); ok && s.stringType(e) {
			return s.derived(selector.X, marked)
		}
	}
	return false
}

func (s *dao14d1Scan) collect(body *ast.BlockStmt) {
	s.sources = make(map[types.Object][]ast.Expr)
	add := func(id ast.Expr, values []ast.Expr) {
		if id, ok := id.(*ast.Ident); ok {
			if object, ok := s.info.ObjectOf(id).(*types.Var); ok {
				s.sources[object] = append(s.sources[object], values...)
			}
		}
	}
	ast.Inspect(body, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.AssignStmt:
			for i, lhs := range node.Lhs {
				if len(node.Rhs) == len(node.Lhs) {
					add(lhs, node.Rhs[i:i+1])
				} else {
					add(lhs, node.Rhs)
				}
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if len(node.Values) == len(node.Names) {
					add(name, node.Values[i:i+1])
				} else {
					add(name, node.Values)
				}
			}
		case *ast.RangeStmt:
			add(node.Key, []ast.Expr{node.X})
			add(node.Value, []ast.Expr{node.X})
		}
		return true
	})
}

func (s *dao14d1Scan) code(e ast.Expr) int64 {
	value := s.info.Types[e].Value
	if value == nil || value.Kind() != constant.Int {
		return -1
	}
	n, ok := constant.Int64Val(value)
	if !ok {
		return -1
	}
	return n
}

func (s *dao14d1Scan) errorValue(lit *ast.CompositeLit) ast.Expr {
	typ, ok := s.info.TypeOf(lit).(*types.Named)
	if !ok || typ.Obj().Pkg() == nil || typ.Obj().Pkg().Path() != "github.com/gin-gonic/gin" || typ.Obj().Name() != "H" {
		return nil
	}
	for _, element := range lit.Elts {
		if pair, ok := element.(*ast.KeyValueExpr); ok {
			value := s.info.Types[pair.Key].Value
			if value != nil && value.Kind() == constant.String && constant.StringVal(value) == "error" {
				return pair.Value
			}
		}
	}
	return nil
}

func TestDao14d1_G3(t *testing.T) {
	dir := os.Getenv("DAO14D1_STATIC_API_DIR")
	external := dir != ""
	if dir == "" {
		dir = "."
	}
	fset := token.NewFileSet()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed []*ast.File
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(source), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//go:build") {
				t.Errorf("build constraint excludes a source file: %s", path)
			}
		}
		file, err := parser.ParseFile(fset, path, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, file)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}, Selections: map[*ast.SelectorExpr]*types.Selection{}}
	config := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := config.Check("github.com/littlewolf9527/xsight/controller/internal/api", fset, parsed, info)
	if err != nil {
		t.Fatalf("type-check scanner input: %v", err)
	}
	scan := &dao14d1Scan{info: info, pkg: pkg, errorType: types.Universe.Lookup("error").Type().Underlying().(*types.Interface), sanitizers: map[types.Object]bool{}, parents: map[ast.Node]ast.Node{}}
	var missing []string
	for _, name := range []string{"storeFailure", "storeInternal", "dbError", "forceRemoveFailure"} {
		object := pkg.Scope().Lookup(name)
		if object == nil {
			missing = append(missing, name)
		} else {
			scan.sanitizers[object] = true
		}
	}
	errResponseObject := pkg.Scope().Lookup("errResponse")
	if errResponseObject == nil {
		t.Fatal("missing errResponse object")
	}
	white := map[string]int{"queryXDropDelivery/S1": 0, "listBGPRoutes/S1": 0, "testBGPConnector/S1": 0, "testWebhookConnector/S2": 0, "testXDropConnector/S2": 0}
	var violations []string
	report := func(rule, name string, node ast.Node) {
		violations = append(violations, rule+" "+fset.Position(node.Pos()).String()+" "+name)
	}
	for _, file := range parsed {
		var stack []ast.Node
		ast.Inspect(file, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) > 0 {
				scan.parents[node] = stack[len(stack)-1]
			}
			stack = append(stack, node)
			return true
		})
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			scan.collect(fn.Body)
			marked := map[types.Object]bool{}
			for _, field := range fn.Type.Params.List {
				for _, param := range field.Names {
					marked[info.ObjectOf(param)] = true
				}
			}
			for changed := true; changed; {
				changed = false
				for object, sources := range scan.sources {
					if marked[object] {
						continue
					}
					for _, source := range sources {
						if scan.derived(source, marked) {
							marked[object], changed = true, true
						}
					}
				}
			}
			forwarded := false
			isSanitizer := scan.sanitizers[info.ObjectOf(fn.Name)]
			signature := info.ObjectOf(fn.Name).Type().(*types.Signature)
			pairResult := signature.Results().Len() == 2 && types.Identical(signature.Results().At(0).Type(), types.Typ[types.Int]) && types.Identical(signature.Results().At(1).Type(), types.Typ[types.String])
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.Ident:
					if info.Uses[node] == errResponseObject {
						call, ok := scan.parents[node].(*ast.CallExpr)
						if !ok || call.Fun != node {
							report("R-i", name, node)
						}
					}
				case *ast.CallExpr:
					object := scan.object(node.Fun)
					if object == errResponseObject && len(node.Args) == 3 {
						code, msg := scan.code(node.Args[1]), node.Args[2]
						forwarded = forwarded || scan.derived(msg, marked)
						if code < 400 || code >= 500 {
							if scan.tainted(msg, map[types.Object]bool{}) {
								key := name + "/S1"
								if _, ok := white[key]; ok && code == 502 {
									white[key]++
								} else {
									report("S1", name, node)
								}
							}
						}
					}
					if scan.sanitizers[object] {
						for _, arg := range node.Args {
							if scan.stringType(arg) && scan.tainted(arg, map[types.Object]bool{}) {
								report("S4", name, arg)
							}
						}
					}
				case *ast.CompositeLit:
					if msg := scan.errorValue(node); msg != nil {
						forwarded = forwarded || scan.derived(msg, marked)
						if name != "errResponse" && info.Types[msg].Value == nil {
							key := name + "/S2"
							if _, ok := white[key]; ok {
								white[key]++
							} else {
								report("S2", name, node)
							}
						}
					}
				case *ast.ReturnStmt:
					if isSanitizer {
						for _, result := range node.Results {
							if scan.tainted(result, map[types.Object]bool{}) {
								report("S5", name, result)
							}
						}
					} else if pairResult && len(node.Results) == 2 {
						code := scan.code(node.Results[0])
						if (code < 400 || code >= 500) && scan.tainted(node.Results[1], map[types.Object]bool{}) {
							report("S3", name, node)
						}
					}
				}
				return true
			})
			if forwarded {
				t.Logf("FORWARDER %s", name)
				if name != "errResponse" {
					report("R-ii", name, fn)
				}
			}
		}
	}
	hits := 0
	for key, n := range white {
		hits += n
		if !external && n != 1 {
			t.Errorf("whitelist %s hits=%d, want 1", key, n)
		}
	}
	t.Logf("DAO14D1_STATIC non_whitelist=%d whitelist=%d total=%d", len(violations), hits, len(violations)+hits)
	for _, violation := range violations {
		t.Log(violation)
	}
	cell := "Delivery"
	if external || len(missing) != 0 {
		cell = "HEAD"
	}
	t.Run(cell, func(t *testing.T) {
		if len(missing) != 0 {
			t.Errorf("missing sanitizers: %s", strings.Join(missing, ", "))
		}
		if len(violations) != 0 {
			t.Error(strconv.Itoa(len(violations)) + " unsafe HTTP error paths")
		}
	})
}
