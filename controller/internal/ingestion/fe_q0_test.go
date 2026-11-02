package ingestion

import (
	"context"
	"io"
	"reflect"
	"sync"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type q0CaptureStream struct {
	grpc.ServerStream
	messages []*pb.StatsReport
	index    int
}

func (s *q0CaptureStream) Context() context.Context          { return context.Background() }
func (s *q0CaptureStream) SendAndClose(*emptypb.Empty) error { return nil }
func (s *q0CaptureStream) Recv() (*pb.StatsReport, error) {
	if s.index == len(s.messages) {
		return nil, io.EOF
	}
	m := s.messages[s.index]
	s.index++
	return m, nil
}

func TestFEQ0_G2_B7_StatsStream(t *testing.T) {
	for _, heartbeat := range []bool{false, true} {
		name := "Data"
		if heartbeat {
			name = "Heartbeat"
		}
		t.Run(name, func(t *testing.T) {
			ns := NewNodeState()
			h := NewGRPCHandler(GRPCHandlerConfig{Store: &dao7Store{}, NodeState: ns})
			res, err := h.Handshake(context.Background(), &pb.NodeHandshake{NodeId: "n1", ApiKey: "dao7-test-key", Interfaces: []string{"eth0"}})
			if err != nil || !res.Accepted {
				t.Fatalf("handshake=%v err=%v", res, err)
			}
			messages := []*pb.StatsReport{{NodeId: "n1", InterfaceName: "eth0", UpstreamSampleRate: 10}, {NodeId: "n1", InterfaceName: "eth0", UpstreamSampleRate: 20}, {NodeId: "n1", InterfaceName: "", UpstreamSampleRate: 900}}
			if !heartbeat {
				for _, m := range messages {
					m.GlobalStats = &pb.GlobalStatsMsg{}
				}
			}
			if err := h.StatsStream(&q0CaptureStream{messages: messages}); err != nil {
				t.Fatal(err)
			}
			if got := ns.GetCapture("n1"); !reflect.DeepEqual(got, map[string]uint32{"eth0": 20}) {
				t.Fatalf("capture=%v want eth0=20 only", got)
			}
			if ns.LastStatsAt("n1").IsZero() {
				t.Fatal("stats heartbeat missing")
			}
		})
	}
}

func TestFEQ0_G2_B7_Snapshots(t *testing.T) {
	ns := NewNodeState()
	names := []string{"eth0"}
	ns.NoteHandshake("n1", names)
	names[0] = "changed"
	gotNames := ns.GetInterfaces("n1")
	gotNames[0] = "changed again"
	if !reflect.DeepEqual(ns.GetInterfaces("n1"), []string{"eth0"}) {
		t.Fatal("interfaces snapshot aliases input/state")
	}
	ns.NoteCapture("n1", "eth0", 10)
	capture := ns.GetCapture("n1")
	capture["eth0"] = 999
	if ns.GetCapture("n1")["eth0"] != 10 {
		t.Fatal("capture snapshot aliases state")
	}
	ns.SetControlStream("n1", nil)
	ns.ClearControlStream("n1", nil)
	if ns.GetCapture("n1")["eth0"] != 10 || len(ns.GetInterfaces("n1")) != 1 {
		t.Fatal("disconnect must retain collection metadata")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			ns.NoteCapture("n1", "eth0", uint32(i))
			ns.NoteHandshake("n2", []string{"eth1"})
		}
	}()
	for i := 0; i < 500; i++ {
		snapshot := ns.GetCapture("n1")
		snapshot["local"] = 42
		_ = ns.GetInterfaces("n2")
	}
	wg.Wait()
	if _, ok := ns.GetCapture("n1")["local"]; ok {
		t.Fatal("mutating snapshot polluted stored capture")
	}
}
