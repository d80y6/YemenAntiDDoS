package ingestion

import (
	"context"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type dao14StatsStream struct {
	grpc.ServerStream
	messages []*pb.StatsReport
	at       int
	before   func(int)
	drained  chan struct{}
	hold     chan struct{}
}

func (s *dao14StatsStream) Context() context.Context          { return context.Background() }
func (s *dao14StatsStream) SendAndClose(*emptypb.Empty) error { return nil }
func (s *dao14StatsStream) Recv() (*pb.StatsReport, error) {
	if s.at == len(s.messages) {
		close(s.drained)
		<-s.hold
		return nil, io.EOF
	}
	if s.before != nil {
		s.before(s.at)
	}
	m := s.messages[s.at]
	s.at++
	return m, nil
}
func dao14Wait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture barrier timed out")
	}
}

func TestDao14jia1_Q1(t *testing.T) {
	for _, name := range []string{"HeartbeatDoesNotEvict", "FifteenThenHeartbeatThenReal", "RealPreferredOverHeartbeat", "HeartbeatDeliveredWhenIdle", "RealReportStillEvictsOldest", "TopFlowsOnlyRealDelivered"} {
		t.Run(name, func(t *testing.T) {
			real := func(i int64) *pb.StatsReport {
				return &pb.StatsReport{NodeId: "n1", Timestamp: i, GlobalStats: &pb.GlobalStatsMsg{}}
			}
			hb := func(i int64) *pb.StatsReport {
				return &pb.StatsReport{NodeId: "n1", Timestamp: i, Health: &pb.NodeHealth{}, SamplingMetrics: &pb.SamplingMetrics{}}
			}
			var script []*pb.StatsReport
			var want []int64
			var dropped uint64
			switch name {
			case "HeartbeatDoesNotEvict":
				for i := int64(1); i <= 17; i++ {
					script = append(script, real(i))
					want = append(want, i)
				}
				script = append(script, hb(99))
				want = append(want, 99)
			case "FifteenThenHeartbeatThenReal":
				for i := int64(1); i <= 16; i++ {
					script = append(script, real(i))
					want = append(want, i)
				}
				script = append(script, hb(99), real(17))
				want = append(want, 17, 99)
			case "RealPreferredOverHeartbeat":
				script = []*pb.StatsReport{real(1), hb(98), hb(99), real(2), real(3)}
				want = []int64{1, 2, 3, 98}
				dropped = 1
			case "HeartbeatDeliveredWhenIdle":
				script = []*pb.StatsReport{hb(99)}
				want = []int64{99}
			case "TopFlowsOnlyRealDelivered":
				script = []*pb.StatsReport{real(1), hb(98), {
					NodeId: "n1", Timestamp: 2, TopFlows: []*pb.FlowSample{{Packets: 1}},
				}}
				// Only delivery is required; HEAD processes H98 before R2.
				want = []int64{1, 98, 2}
			case "RealReportStillEvictsOldest":
				for i := int64(1); i <= 18; i++ {
					script = append(script, real(i))
					if i != 2 {
						want = append(want, i)
					}
				}
				dropped = 1
			}
			entered, gate := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(gate) }) }
			calls := make(chan int64, 64)
			ns := NewNodeState()
			h := NewGRPCHandler(GRPCHandlerConfig{Store: &dao7Store{}, NodeState: ns, OnStats: func(_ string, m *pb.StatsReport) {
				if m.Timestamp == 1 {
					close(entered)
					<-gate
				}
				calls <- m.Timestamp
			}})
			resp, err := h.Handshake(context.Background(), &pb.NodeHandshake{NodeId: "n1", ApiKey: "dao7-test-key"})
			if err != nil || !resp.GetAccepted() {
				t.Fatalf("handshake=%v err=%v", resp, err)
			}
			s := &dao14StatsStream{messages: script, drained: make(chan struct{}), hold: make(chan struct{})}
			var beforeHeartbeat time.Time
			s.before = func(i int) {
				if i == 1 {
					dao14Wait(t, entered)
				}
				if name == "HeartbeatDoesNotEvict" && script[i].Timestamp == 99 {
					beforeHeartbeat = ns.LastStatsAt("n1")
					time.Sleep(time.Millisecond)
				}
			}
			done := make(chan error, 1)
			go func() { done <- h.StatsStream(s) }()
			t.Cleanup(func() {
				release()
				close(s.hold)
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("StatsStream: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Error("StatsStream did not drain")
				}
			})
			dao14Wait(t, s.drained)
			if name == "HeartbeatDoesNotEvict" && !ns.LastStatsAt("n1").After(beforeHeartbeat) {
				t.Error("heartbeat did not advance LastStatsAt")
			}
			release()
			var got []int64
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
		read:
			for len(got) < len(want) {
				select {
				case x := <-calls:
					got = append(got, x)
				case <-deadline.C:
					break read
				}
			}
			// The receive stream remains open throughout these assertions.
			if name == "TopFlowsOnlyRealDelivered" {
				delivered := false
				for _, timestamp := range got {
					if timestamp == 2 {
						delivered = true
					}
				}
				if !delivered {
					t.Errorf("TopFlows-only R2 did not reach onStats: processed=%v", got)
				}
			} else if !reflect.DeepEqual(got, want) {
				t.Errorf("processed=%v want=%v", got, want)
			}
			if h.StatsDropped.Load() != dropped {
				t.Errorf("dropped=%d want=%d", h.StatsDropped.Load(), dropped)
			}
		})
	}
}

// This is a channel-protocol replay, not a test of production execution paths.
// S12 binds the protocol to production; Q1 supplies production behavior checks.
func dao14Replay(protocol string, n int) (dropped, processed []int) {
	q := make(chan int, 16)
	hb := make(chan int, 1)
	if protocol == "v04" {
		q <- 0
	}
	if protocol == "v05" {
		hb <- 0
	}
	for i := 1; i <= n; i++ {
		select {
		case q <- i:
		default:
			// Barrier: advance the consumer after the full decision, before eviction.
			select {
			case x := <-q:
				processed = append(processed, x)
			default:
				select {
				case x := <-hb:
					processed = append(processed, x)
				default:
				}
			}
			select {
			case x := <-q:
				if x != 0 {
					dropped = append(dropped, x)
				}
			default:
			}
			q <- i
		}
	}
	return
}
func TestDao14jia1_Q2(t *testing.T) {
	t.Run("EvictWindow", func(t *testing.T) {
		for _, n := range []int{16, 17} {
			head, hp := dao14Replay("HEAD", n)
			fixed, fp := dao14Replay("v05", n)
			var want []int
			if n == 17 {
				want = []int{2}
			}
			if !reflect.DeepEqual(head, want) || !reflect.DeepEqual(fixed, head) {
				t.Errorf("n=%d HEAD=%v delivery=%v want=%v", n, head, fixed, want)
			}
			if n == 17 && (!reflect.DeepEqual(hp, []int{1}) || !reflect.DeepEqual(fp, []int{1})) {
				t.Errorf("consumer must process R1: HEAD=%v delivery=%v", hp, fp)
			}
		}
		old, _ := dao14Replay("v04", 16)
		if !reflect.DeepEqual(old, []int{1}) {
			t.Fatalf("apparatus broken: v0.4 dropped=%v want=[1]", old)
		}
	})
}
