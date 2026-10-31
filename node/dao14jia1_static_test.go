package main

import (
	"go/ast"
	"testing"
)

func TestDao14jia1_S9(t *testing.T) {
	f := dao13fAST(t, "node/flow_main.go")
	fn := dao13fFunc(t, f, "runFlowMode")
	t.Run("FlowLoopUnchanged", func(t *testing.T) {
		sends, guarded, definitions := 0, 0, 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if s, ok := n.(*ast.SendStmt); ok && dao13fText(s.Chan) == "flowReports" {
				sends++
			}
			if a, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range a.Lhs {
					if dao13fText(lhs) == "msg" {
						definitions++
						if dao13fText(a) != "msg := aggregator.Flush(cfg.NodeID, \"flow\", 1)" {
							t.Errorf("unexpected msg definition: %s", dao13fText(a))
						}
					}
				}
			}
			if i, ok := n.(*ast.IfStmt); ok && dao13fText(i.Cond) == "msg != nil" {
				ast.Inspect(i.Body, func(n ast.Node) bool {
					if s, ok := n.(*ast.SendStmt); ok && dao13fText(s.Chan) == "flowReports" {
						guarded++
					}
					return true
				})
			}
			return true
		})
		if sends != 1 || guarded != 1 || definitions != 1 {
			t.Errorf("sends=%d guarded=%d msg definitions=%d", sends, guarded, definitions)
		}
	})
	t.Run("HeartbeatWiredToReporter", func(t *testing.T) {
		set, heartbeats := 0, 0
		at, run := -1, -1
		for i, s := range fn.Body.List {
			if g, ok := s.(*ast.GoStmt); ok && dao13fText(g.Call) == "rpt.Run(ctx)" {
				run = i
			}
			if e, ok := s.(*ast.ExprStmt); ok {
				if c, ok := e.X.(*ast.CallExpr); ok && dao13fText(c.Fun) == "rpt.SetHeartbeat" {
					at = i
				}
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch dao13fText(c.Fun) {
			case "rpt.SetHeartbeat":
				set++
				if len(c.Args) != 1 {
					t.Error("SetHeartbeat needs one constructor")
					return true
				}
				lit, ok := c.Args[0].(*ast.FuncLit)
				if !ok || len(lit.Body.List) != 1 || dao13fText(lit.Body.List[0]) != "return aggregator.Heartbeat(cfg.NodeID, \"flow\", 1)" {
					t.Error("heartbeat constructor mismatch")
				}
			case "aggregator.Heartbeat":
				heartbeats++
			}
			return true
		})
		if set != 1 || heartbeats != 1 || at < 0 || run <= at {
			t.Errorf("SetHeartbeat=%d Heartbeat=%d wiring index=%d Run=%d", set, heartbeats, at, run)
		}
	})
}
