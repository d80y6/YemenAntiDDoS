package ingestion

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

func dao14QueueText(n ast.Node) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, token.NewFileSet(), n)
	return b.String()
}
func dao14QueueBody(t *testing.T, source string) *ast.BlockStmt {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", "package p;func fixture()"+source, 0)
	if err != nil {
		t.Fatal(err)
	}
	return f.Decls[0].(*ast.FuncDecl).Body
}

// This is the 3c781a6 real-report enqueue select. Comments do not affect comparison.
const dao14RealBranch = `{
select {
case queue <- msg:
default:
    h.StatsDropped.Add(1)
    select {
    case <-queue:
    default:
    }
    queue <- msg
    log.Printf("grpc: stats queue full for node=%s, dropped report (total_dropped=%d)",
        msg.NodeId, h.StatsDropped.Load())
}
}`

const dao14Consumer = `{
defer func() { done <- nil }()
serve:
for {
    select {
    case msg, ok := <-queue:
        if !ok { break serve }
        handle(msg)
        continue
    default:
    }
    select {
    case msg, ok := <-queue:
        if !ok { break serve }
        handle(msg)
    case hb := <-hbQueue:
        handle(hb)
    }
}
select {
case hb := <-hbQueue:
    handle(hb)
default:
}
}`

func TestDao14jia1_S12(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "grpc_handler.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if x, ok := d.(*ast.FuncDecl); ok && x.Name.Name == "StatsStream" {
			fn = x
		}
	}
	if fn == nil {
		t.Fatal("StatsStream missing")
	}
	t.Run("RealBranchVerbatim", func(t *testing.T) {
		var matches []*ast.SelectStmt
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			s, ok := n.(*ast.SelectStmt)
			if !ok || len(s.Body.List) == 0 {
				return true
			}
			c := s.Body.List[0].(*ast.CommClause)
			if send, ok := c.Comm.(*ast.SendStmt); ok && dao14QueueText(send) == "queue <- msg" {
				matches = append(matches, s)
			}
			return true
		})
		if len(matches) != 1 {
			t.Fatalf("queue-first selects=%d want=1", len(matches))
		}
		want := dao14QueueText(dao14QueueBody(t, dao14RealBranch).List[0])
		if got := dao14QueueText(matches[0]); got != want {
			t.Errorf("real branch changed:\n%s\nwant:\n%s", got, want)
		}
	})
	t.Run("HeartbeatNeverEntersQueue", func(t *testing.T) {
		q, hb := 0, 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if s, ok := n.(*ast.SendStmt); ok {
				switch dao14QueueText(s.Chan) {
				case "queue":
					q++
				case "hbQueue":
					hb++
				}
			}
			return true
		})
		if q != 2 || hb != 1 {
			t.Errorf("queue sends=%d heartbeat sends=%d want=2,1", q, hb)
		}
	})
	t.Run("ConsumerPrefersQueue", func(t *testing.T) {
		var bodies []*ast.BlockStmt
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if g, ok := n.(*ast.GoStmt); ok {
				if l, ok := g.Call.Fun.(*ast.FuncLit); ok {
					bodies = append(bodies, l.Body)
				}
			}
			return true
		})
		if len(bodies) != 1 {
			t.Fatalf("consumer goroutines=%d", len(bodies))
		}
		want := dao14QueueText(dao14QueueBody(t, dao14Consumer))
		if got := dao14QueueText(bodies[0]); got != want {
			t.Errorf("consumer shape changed:\n%s\nwant:\n%s", got, want)
		}
	})
}
