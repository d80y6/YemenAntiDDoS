package action

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dao14c2Parse(t *testing.T, path string, src any) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func dao14c2Function(f *ast.File, name string) *ast.FuncDecl {
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	return nil
}
func dao14c2Ident(n ast.Node, name string) bool {
	id, ok := n.(*ast.Ident)
	return ok && id.Name == name
}
func dao14c2Create(call *ast.CallExpr) bool {
	s, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != "Create" {
		return false
	}
	r, ok := s.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	m, ok := r.Fun.(*ast.SelectorExpr)
	return ok && m.Sel.Name == "ActionExecLog"
}
func dao14c2Counts(n ast.Node) (creates, writes int) {
	ast.Inspect(n, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if dao14c2Create(call) {
				creates++
			}
			if dao14c2Ident(call.Fun, "writeExecLog") {
				writes++
			}
		}
		return true
	})
	return
}
func dao14c2Source(n ast.Node) string {
	var b bytes.Buffer
	_ = format.Node(&b, token.NewFileSet(), n)
	return b.String()
}

func TestDao14c2_S1(t *testing.T) {
	for _, tc := range []struct {
		file, fn string
		count    int
	}{{"engine.go", "executeAction", 9}, {"engine.go", "executeRecoveredBGPWithdraw", 1}, {"engine.go", "executeRecoveredBGPWithdrawByAnnouncement", 1}, {"bgp.go", "bgpDelayedWithdrawWorker", 1}} {
		t.Run(tc.fn, func(t *testing.T) {
			fn := dao14c2Function(dao14c2Parse(t, tc.file, nil), tc.fn)
			if fn == nil {
				t.Fatalf("DEVICE missing existing function %s", tc.fn)
			}
			creates, writes := dao14c2Counts(fn.Body)
			t.Logf("SCANNER %s Create=%d writeExecLog=%d", tc.fn, creates, writes)
			dao14c2Assert(t, "NoDirectCreate", creates == 0, creates)
			dao14c2Assert(t, "WriteCount", writes == tc.count, writes)
		})
	}
}
func TestDao14c2_S1b(t *testing.T) {
	fn := dao14c2Function(dao14c2Parse(t, "bgp.go", nil), "bgpAnnounce")
	count, bad := 0, 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && dao14c2Ident(c.Fun, "writeSkipLog") {
			count++
			if len(c.Args) == 0 || dao14c2Ident(c.Args[0], "ctx") {
				bad++
			}
		}
		return true
	})
	dao14c2Assert(t, "OverrideContext", count == 1 && bad == 0, fmt.Sprintf("calls=%d action-ctx=%d", count, bad))
}
func TestDao14c2_S1c(t *testing.T) {
	f := dao14c2Parse(t, "engine.go", nil)
	ctx := dao14c2Function(f, "execLogContext")
	write := dao14c2Function(f, "writeExecLog")
	ctxOK := false
	if ctx != nil && len(ctx.Body.List) == 1 {
		ret, ok := ctx.Body.List[0].(*ast.ReturnStmt)
		ctxOK = ok && len(ret.Results) == 1 && dao14c2Source(ret.Results[0]) == "context.WithTimeout(context.Background(), dbOperationTimeout)"
	}
	dao14c2Assert(t, "FreshBackgroundBudget", ctxOK, ctx != nil)
	writeOK := false
	if write != nil && len(write.Body.List) == 3 {
		assign, aOK := write.Body.List[0].(*ast.AssignStmt)
		deferCall, dOK := write.Body.List[1].(*ast.DeferStmt)
		ret, rOK := write.Body.List[2].(*ast.ReturnStmt)
		writeOK = aOK && dOK && rOK && dao14c2Source(assign) == "ctx, cancel := execLogContext()" && dao14c2Source(deferCall.Call) == "cancel()" && len(ret.Results) == 1 && dao14c2Source(ret.Results[0]) == "s.ActionExecLog().Create(ctx, l)"
	}
	dao14c2Assert(t, "SynchronousWriteAndCancel", writeOK, write != nil)
}
func TestDao14c2_S2(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		creates := 0
		for _, d := range dao14c2Parse(t, file, nil).Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Body != nil {
				n, _ := dao14c2Counts(fn.Body)
				creates += n
			}
		}
		want := 0
		switch file {
		case "engine.go":
			want = 3
		case "xdrop.go":
			want = 4
		}
		t.Logf("SCANNER %s Create=%d", file, creates)
		dao14c2Assert(t, file+".Inventory", creates == want, fmt.Sprintf("Create=%d want=%d", creates, want))
	}
	// r2: all unified withdrawal log paths use the independently budgeted
	// writeExecLog helper. S1c continues to freeze that helper's context contract.
	f := dao14c2Parse(t, "xdrop_withdraw.go", nil)
	for _, name := range []string{"xdropLog", "scheduleXDrop"} {
		fn := dao14c2Function(f, name)
		if fn == nil {
			t.Fatalf("DEVICE missing withdrawal log path %s", name)
		}
		creates, writes := dao14c2Counts(fn.Body)
		dao14c2Assert(t, name+".IndependentLog", creates == 0 && writes == 1,
			fmt.Sprintf("Create=%d writeExecLog=%d", creates, writes))
	}
}

type dao14c2DispatchScan struct{ calls, methodValues, invalid int }

func dao14c2ScanDispatch(f *ast.File, path string) (out dao14c2DispatchScan) {
	var stack []ast.Node
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "HandleEvent" {
			parent := stack[len(stack)-1]
			call, isCall := parent.(*ast.CallExpr)
			if !isCall || call.Fun != sel {
				out.methodValues++
			} else {
				out.calls++
				_, expr := stack[len(stack)-2].(*ast.ExprStmt)
				inStart, inFor, inGo := false, false, false
				for _, ancestor := range stack {
					switch a := ancestor.(type) {
					case *ast.FuncDecl:
						inStart = a.Name.Name == "Start"
					case *ast.ForStmt:
						inFor = true
					case *ast.GoStmt:
						inGo = true
					}
				}
				if !expr || !inStart || !inFor || !inGo || filepath.Base(path) != "engine.go" {
					out.invalid++
				}
			}
		}
		stack = append(stack, n)
		return true
	})
	return
}
func TestDao14c2_S3(t *testing.T) {
	total := dao14c2DispatchScan{}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		r := dao14c2ScanDispatch(dao14c2Parse(t, path, nil), path)
		total.calls += r.calls
		total.methodValues += r.methodValues
		total.invalid += r.invalid
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	dao14c2Assert(t, "SerialCall", total.calls == 1 && total.invalid == 0, total)
	dao14c2Assert(t, "NoMethodValues", total.methodValues == 0, total)
	src, err := os.ReadFile("engine.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, replacement string }{{"GoCall", "go e.HandleEvent(item.event)"}, {"MethodValue", "f := e.HandleEvent; f(item.event)"}} {
		mutated := strings.Replace(string(src), "e.HandleEvent(item.event)", tc.replacement, 1)
		if mutated == string(src) {
			t.Fatal("DEVICE dispatcher mutation did not apply")
		}
		r := dao14c2ScanDispatch(dao14c2Parse(t, "engine.go", mutated), "engine.go")
		dao14c2Assert(t, "SelfCheck."+tc.name, r.calls != 1 || r.invalid != 0 || r.methodValues != 0, r)
	}
}
