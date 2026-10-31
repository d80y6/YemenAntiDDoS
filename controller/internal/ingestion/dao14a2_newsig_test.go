package ingestion

import (
	"reflect"
	"sync"
	"testing"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
)

type dao14FakeCS struct {
	pb.XSightService_ControlStreamServer
	id int
}

func TestDao14a2_G5c(t *testing.T) {
	a, b := &dao14FakeCS{id: 1}, &dao14FakeCS{id: 2}
	t.Run("SetASetBClearA", func(t *testing.T) {
		ns := NewNodeState()
		ns.SetControlStream("n1", a)
		ns.TouchStats("n1")
		ns.UpdateSourceStatuses("n1", []SourceStatus{{DeviceIP: "192.0.2.1"}})
		ns.UpdateListenerStatuses("n1", []ListenerStatus{{ListenAddr: "x"}})
		statsAt := ns.LastStatsAt("n1")
		sources, listeners := ns.GetSourceStatuses("n1"), ns.GetListenerStatuses("n1")
		ns.SetControlStream("n1", b)
		at := ns.ConnectedAt("n1")
		ns.ClearControlStream("n1", a)
		if ns.GetControlStream("n1") != b || ns.ConnectedAt("n1") != at || ns.LastStatsAt("n1") != statsAt ||
			!reflect.DeepEqual(ns.GetSourceStatuses("n1"), sources) || !reflect.DeepEqual(ns.GetListenerStatuses("n1"), listeners) {
			t.Fatal("B state not kept")
		}
	})
	t.Run("SetAClearASetB", func(t *testing.T) {
		ns := NewNodeState()
		ns.SetControlStream("n1", a)
		ns.ClearControlStream("n1", a)
		ns.SetControlStream("n1", b)
		if ns.GetControlStream("n1") != b {
			t.Fatal("want B")
		}
	})
	t.Run("BothClose", func(t *testing.T) {
		for _, order := range [][2]*dao14FakeCS{{a, b}, {b, a}} {
			ns := NewNodeState()
			ns.SetControlStream("n1", a)
			ns.SetControlStream("n1", b)
			ns.ClearControlStream("n1", order[0])
			if order[0] == b {
				ns.TouchStats("n1")
			}
			ns.ClearControlStream("n1", order[1])
			if ns.GetControlStream("n1") != nil || len(ns.ConnectedNodes()) != 0 {
				t.Fatalf("order %d,%d: not empty", order[0].id, order[1].id)
			}
			if order[0] == b && ns.LastStatsAt("n1").IsZero() {
				t.Fatal("Clear(A) after Clear(B) deleted later stats")
			}
		}
	})
	t.Run("EmptyClear", func(t *testing.T) {
		ns := NewNodeState()
		ns.ClearControlStream("n1", a)
		if len(ns.ConnectedNodes()) != 0 {
			t.Fatal("changed")
		}
	})
}

func TestDao14a2_G5r(t *testing.T) {
	a, b := &dao14FakeCS{id: 1}, &dao14FakeCS{id: 2}
	for i := 0; i < 1000; i++ {
		ns := NewNodeState()
		ns.SetControlStream("n1", a)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); ns.SetControlStream("n1", b) }()
		go func() { defer wg.Done(); ns.ClearControlStream("n1", a) }()
		wg.Wait()
		if ns.GetControlStream("n1") != b {
			t.Fatalf("round %d: final stream != B", i)
		}
	}
}
