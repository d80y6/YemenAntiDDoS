package reporter

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"testing"
	"time"
)

func TestDao12d_G5(t *testing.T) {
	t.Run("Table", func(t *testing.T) {
		for _, tc := range []struct {
			name               string
			cur, attempt, want time.Duration
		}{
			{"Long", 30, 31, 1},
			{"Below", 30, 29, 30},
			{"Short", 4, 5, 4},
			{"Boundary", 8, 30, 1},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got := nextBackoff(tc.cur*time.Second, tc.attempt*time.Second); got != tc.want*time.Second {
					t.Errorf("nextBackoff(%vs,%vs)=%v, want %vs", tc.cur, tc.attempt, got, tc.want)
				}
			})
		}
	})
	t.Run("Shape", dao12dBackoffShape)
}

func dao12dBackoffShape(t *testing.T) {
	path := "reporter.go"
	if source := os.Getenv("DAO12D_REPORTER_SOURCE"); source != "" {
		path = source // Use the source under test when a mutation overlay is used.
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	text := func(node ast.Node) string {
		var b bytes.Buffer
		if err := format.Node(&b, fset, node); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	assign := func(stmt ast.Stmt, kind token.Token, lhs, rhs string) *ast.AssignStmt {
		a, ok := stmt.(*ast.AssignStmt)
		if !ok || a.Tok != kind || len(a.Lhs) != 1 || len(a.Rhs) != 1 || text(a.Lhs[0]) != lhs || text(a.Rhs[0]) != rhs {
			t.Fatalf("expected %s %s %s; got %s", lhs, kind, rhs, text(stmt))
		}
		return a
	}
	bound := func(got, declaration ast.Expr) {
		a, okA := got.(*ast.Ident)
		b, okB := declaration.(*ast.Ident)
		if !okA || !okB || a.Obj == nil || a.Obj != b.Obj {
			t.Fatalf("binding mismatch: %s versus %s", text(got), text(declaration))
		}
	}
	call := func(expr ast.Expr, name string, argc int) *ast.CallExpr {
		c, ok := expr.(*ast.CallExpr)
		if !ok || text(c.Fun) != name || len(c.Args) != argc {
			t.Fatalf("expected %s with %d arguments; got %s", name, argc, text(expr))
		}
		return c
	}
	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Run" && fn.Recv != nil {
			if run != nil {
				t.Fatal("multiple Run methods")
			}
			run = fn
		}
	}
	if run == nil || len(run.Recv.List) != 1 || text(run.Recv.List[0].Type) != "*Reporter" ||
		len(run.Recv.List[0].Names) != 1 || len(run.Type.Params.List) != 1 ||
		len(run.Type.Params.List[0].Names) != 1 || run.Body == nil || len(run.Body.List) != 2 {
		t.Fatal("expected Reporter.Run with a backoff declaration and one reconnect loop")
	}
	initial := assign(run.Body.List[0], token.DEFINE, "backoff", "time.Second")
	loop, ok := run.Body.List[1].(*ast.ForStmt)
	if !ok || loop.Init != nil || loop.Cond != nil || loop.Post != nil {
		t.Fatal("unconditional reconnect loop absent")
	}
	body, at := loop.Body.List, -1
	for i, stmt := range body {
		a, ok := stmt.(*ast.AssignStmt)
		if ok && len(a.Rhs) == 1 && text(a.Rhs[0]) == "r.connectAndServe(ctx)" {
			if at >= 0 {
				t.Fatal("multiple connection attempts in the loop body")
			}
			at = i
		}
	}
	if at < 1 || at+5 >= len(body) {
		t.Fatal("connection timing/reset sequence absent")
	}
	start := assign(body[at-1], token.DEFINE, "start", "time.Now()")
	connect := assign(body[at], token.DEFINE, "err", "r.connectAndServe(ctx)")
	connectCall := call(connect.Rhs[0], "r.connectAndServe", 1)
	bound(connectCall.Fun.(*ast.SelectorExpr).X, run.Recv.List[0].Names[0])
	bound(connectCall.Args[0], run.Type.Params.List[0].Names[0])
	elapsed := assign(body[at+1], token.DEFINE, "elapsed", "time.Since(start)")
	bound(call(elapsed.Rhs[0], "time.Since", 1).Args[0], start.Lhs[0])
	reset := assign(body[at+2], token.ASSIGN, "backoff", "nextBackoff(backoff, elapsed)")
	resetCall := call(reset.Rhs[0], "nextBackoff", 2)
	bound(reset.Lhs[0], initial.Lhs[0])
	bound(resetCall.Args[0], initial.Lhs[0])
	bound(resetCall.Args[1], elapsed.Lhs[0])
	// Only the error log and cleanup may intervene before this attempt's wait.
	logIf, ok := body[at+3].(*ast.IfStmt)
	if !ok || logIf.Init != nil || logIf.Else != nil || text(logIf.Cond) != "err != nil" || len(logIf.Body.List) != 1 {
		t.Fatal("error log must follow reset without another backoff assignment")
	}
	bound(logIf.Cond.(*ast.BinaryExpr).X, connect.Lhs[0])
	logStmt, ok := logIf.Body.List[0].(*ast.ExprStmt)
	if !ok {
		t.Fatal("error log must be a direct call")
	}
	logCall := call(logStmt.X, "log.Printf", 3)
	bound(logCall.Args[1], connect.Lhs[0])
	bound(logCall.Args[2], initial.Lhs[0])
	cleanup, ok := body[at+4].(*ast.ExprStmt)
	if !ok {
		t.Fatal("post-connection disconnect absent")
	}
	cleanupCall := call(cleanup.X, "r.disconnect", 0)
	bound(cleanupCall.Fun.(*ast.SelectorExpr).X, run.Recv.List[0].Names[0])
	wait, ok := body[at+5].(*ast.SelectStmt)
	if !ok {
		t.Fatal("wait select must follow reset, error log and post-connection disconnect")
	}
	waits := 0
	for _, stmt := range wait.Body.List {
		clause := stmt.(*ast.CommClause)
		expr, ok := clause.Comm.(*ast.ExprStmt)
		if !ok {
			continue
		}
		receive, ok := expr.X.(*ast.UnaryExpr)
		if !ok || receive.Op != token.ARROW {
			continue
		}
		if text(receive.X) == "time.After(backoff)" {
			bound(call(receive.X, "time.After", 1).Args[0], initial.Lhs[0])
			waits++
		}
	}
	if waits != 1 {
		t.Fatalf("time.After(backoff) wait count=%d, want 1", waits)
	}
}
