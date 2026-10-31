package postgres

import (
	_ "embed"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Embed the build's source so a go -overlay mutation is also seen by the parser.
// The assertion below inspects only the SQL literal used by (*attackRepo).List.
//
//go:embed attack.go
var feQBAttackSource string

func TestFEQB_W13_ListSQLOrder(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "attack.go", feQBAttackSource, 0)
	if err != nil {
		t.Fatal(err)
	}
	var list *ast.FuncDecl
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "List" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		ptr, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		receiver, ok := ptr.X.(*ast.Ident)
		if ok && receiver.Name == "attackRepo" {
			if list != nil {
				t.Fatal("multiple (*attackRepo).List declarations")
			}
			list = fn
		}
	}
	if list == nil || list.Body == nil {
		t.Fatal("(*attackRepo).List body not found")
	}

	var queryName, sql string
	templates := 0
	// Any fmt.Sprintf outside the single assignment form (e.g. a var declaration
	// feeding the query) is counted too, so a second template cannot hide.
	sprintfs := 0
	ast.Inspect(list.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Sprintf" {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "fmt" {
					sprintfs++
				}
			}
		}
		return true
	})
	if sprintfs != 1 {
		t.Fatalf("List fmt.Sprintf calls=%d want=1", sprintfs)
	}
	ast.Inspect(list.Body, func(n ast.Node) bool {
		assignment, ok := n.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Sprintf" {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok || pkg.Name != "fmt" {
			return true
		}
		templates++
		name, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok || len(call.Args) == 0 {
			t.Fatal("List SQL assignment must name the fmt.Sprintf result")
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatal("List fmt.Sprintf SQL template must be a string literal")
		}
		sql, err = strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		queryName = name.Name
		if len(call.Args) != 6 {
			t.Fatal("List fmt.Sprintf must have template and five arguments")
		}
		order, ok := call.Args[3].(*ast.CallExpr)
		if !ok || len(order.Args) != 1 {
			t.Fatal("List ORDER BY argument must call attackListOrder(f.Sort)")
		}
		orderName, ok := order.Fun.(*ast.Ident)
		if !ok || orderName.Name != "attackListOrder" {
			t.Fatal("List ORDER BY argument must call attackListOrder")
		}
		sortField, ok := order.Args[0].(*ast.SelectorExpr)
		if !ok || sortField.Sel.Name != "Sort" {
			t.Fatal("attackListOrder argument must be f.Sort")
		}
		filterName, ok := sortField.X.(*ast.Ident)
		if !ok || filterName.Name != "f" {
			t.Fatal("attackListOrder must use the List filter")
		}
		return true
	})
	if templates != 1 {
		t.Fatalf("List SQL template count=%d want=1", templates)
	}

	// Confirm that the selected template supplies the production pool.Query call.
	queries := 0
	ast.Inspect(list.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Query" {
			return true
		}
		pool, ok := selector.X.(*ast.SelectorExpr)
		if !ok || pool.Sel.Name != "pool" {
			return true
		}
		receiver, ok := pool.X.(*ast.Ident)
		if !ok || len(list.Recv.List[0].Names) != 1 || receiver.Name != list.Recv.List[0].Names[0].Name {
			return true
		}
		query, ok := call.Args[1].(*ast.Ident)
		if ok && query.Name == queryName {
			queries++
		}
		return true
	})
	if queries != 1 {
		t.Fatalf("List pool.Query calls using SQL template=%d want=1", queries)
	}
	// The query variable must be bound exactly once (no later rewrite such as
	// strings.ReplaceAll before pool.Query).
	bindings := 0
	ast.Inspect(list.Body, func(n ast.Node) bool {
		if assignment, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range assignment.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == queryName {
					bindings++
				}
			}
		}
		if spec, ok := n.(*ast.ValueSpec); ok {
			for _, id := range spec.Names {
				if id.Name == queryName {
					bindings++
				}
			}
		}
		return true
	})
	if bindings != 1 {
		t.Fatalf("List SQL variable %q bindings=%d want=1", queryName, bindings)
	}
	// Exact template match: the order must be real SQL, not a comment or substring.
	sql = strings.Join(strings.Fields(sql), " ")
	const want = "SELECT %s FROM attacks%s ORDER BY %s LIMIT %d OFFSET %d"
	if sql != want {
		t.Fatalf("List SQL template: got %q; want %q", sql, want)
	}
	for _, tc := range []struct{ sort, want string }{
		{"", "started_at DESC, id DESC"},
		{"started_at", "started_at DESC, id DESC"},
		{"peak_pps", "peak_pps DESC, started_at DESC, id DESC"},
		{"x; DROP", "started_at DESC, id DESC"},
	} {
		if got := attackListOrder(tc.sort); got != tc.want {
			t.Errorf("attackListOrder(%q)=%q want=%q", tc.sort, got, tc.want)
		}
	}
}
