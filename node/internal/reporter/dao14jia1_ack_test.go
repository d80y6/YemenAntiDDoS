package reporter

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/node/internal/collector"
	"github.com/d80y6/YemenDDoS/node/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// G6 is the sole TCP fixture authorized for execution outside the sandbox.
// It deliberately uses connectAndServe without a production test seam.
type dao14ACKServer struct {
	pb.UnimplementedXSightServiceServer
	response *pb.HandshakeResponse
	push     bool
	acks     chan *pb.ConfigAck
}

func (s *dao14ACKServer) Handshake(context.Context, *pb.NodeHandshake) (*pb.HandshakeResponse, error) {
	return s.response, nil
}
func (s *dao14ACKServer) StatsStream(stream grpc.ClientStreamingServer[pb.StatsReport, emptypb.Empty]) error {
	<-stream.Context().Done()
	return stream.Context().Err()
}
func (s *dao14ACKServer) SampleStream(stream grpc.ClientStreamingServer[pb.SampleBatch, emptypb.Empty]) error {
	<-stream.Context().Done()
	return stream.Context().Err()
}
func (s *dao14ACKServer) ControlStream(stream grpc.BidiStreamingServer[pb.ControlMessage, pb.ControlMessage]) error {
	first := true
	for {
		m, err := stream.Recv()
		if err != nil {
			return err
		}
		if a := m.GetConfigAck(); a != nil {
			s.acks <- a
			if first && s.push {
				if err := stream.Send(&pb.ControlMessage{Payload: &pb.ControlMessage_ConfigPush{ConfigPush: &pb.ConfigPush{DeliveryVersionCurrent: 11, WatchConfig: &pb.WatchConfig{Prefixes: []*pb.WatchPrefix{{Prefix: []byte{192, 0, 2, 0}, PrefixLen: 24}}}}}}); err != nil {
					return err
				}
			}
			first = false
		}
	}
}

func TestDao14jia1_G6(t *testing.T) {
	type ack struct {
		version uint64
		success bool
	}
	for _, tt := range []struct {
		name                                     string
		initial, current                         uint64
		config, fail, push, pushFail, secondOnly bool
		want                                     []ack
		final                                    uint64
	}{
		{name: "FailSendsOnlyFailure", initial: 9, current: 10, config: true, fail: true, want: []ack{{10, false}}, final: 9},
		{name: "FailVersionZero", current: 0, config: true, fail: true, want: []ack{{0, false}}},
		{name: "FailThenPushFail", initial: 9, current: 10, config: true, fail: true, push: true, pushFail: true, want: []ack{{10, false}, {11, false}}, final: 9},
		{name: "OKSendsSuccess", initial: 9, current: 10, config: true, want: []ack{{10, true}}, final: 10},
		{name: "SnapshotOnlyAck", initial: 9, current: 10, want: []ack{{9, true}}, final: 9},
		{name: "NoAckWhenZero", current: 10},
		{name: "FailThenPush", initial: 9, current: 10, config: true, fail: true, push: true, secondOnly: true, want: []ack{{10, false}, {11, true}}, final: 11},
	} {
		t.Run(tt.name, func(t *testing.T) {
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s := &dao14ACKServer{response: &pb.HandshakeResponse{Accepted: true, DeliveryVersionCurrent: tt.current}, push: tt.push, acks: make(chan *pb.ConfigAck, 16)}
			if tt.config {
				s.response.WatchConfig = &pb.WatchConfig{Prefixes: []*pb.WatchPrefix{{Prefix: []byte{192, 0, 2, 0}, PrefixLen: 24}}}
			}
			server := grpc.NewServer()
			pb.RegisterXSightServiceServer(server, s)
			served := make(chan struct{})
			go func() { defer close(served); _ = server.Serve(lis) }()
			defer func() { server.Stop(); _ = lis.Close(); <-served }()
			r := New(Config{ControllerAddr: lis.Addr().String(), NodeID: "n1"}, make(chan *collector.Report), func(_ *pb.WatchConfig, v uint64) error {
				if (v == tt.current && tt.fail) || (v == 11 && tt.pushFail) {
					return errors.New("write shadow trie: no space left on device")
				}
				return nil
			})
			r.SetDeliveryVersion(tt.initial)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- r.connectAndServe(ctx) }()
			var got []*pb.ConfigAck
			deadline := time.NewTimer(3 * time.Second)
		collect:
			for {
				select {
				case a := <-s.acks:
					got = append(got, a)
					if len(got) >= len(tt.want) && len(tt.want) > 0 {
						break collect
					}
				case <-deadline.C:
					break collect
				}
			}
			deadline.Stop()
			settle := time.NewTimer(500 * time.Millisecond)
		extra:
			for {
				select {
				case a := <-s.acks:
					got = append(got, a)
				case <-settle.C:
					break extra
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("connectAndServe did not stop")
			}
			r.disconnect()
			if tt.secondOnly {
				if len(got) < 2 || got[1].DeliveryVersionApplied != 11 || !got[1].Success {
					t.Errorf("second ACK=%v want={11,true}", got)
				}
			} else {
				if len(got) != len(tt.want) {
					t.Errorf("ACK sequence=%v want=%v", got, tt.want)
				}
				for i, w := range tt.want {
					if i >= len(got) {
						break
					}
					a := got[i]
					if a.DeliveryVersionApplied != w.version || a.Success != w.success || (!w.success && a.ErrorMessage == "") {
						t.Errorf("ACK[%d]=%v want={%d,%t,error-if-failed}", i, a, w.version, w.success)
					}
				}
			}
			if r.deliveryVersion != tt.final {
				t.Errorf("deliveryVersion=%d want=%d", r.deliveryVersion, tt.final)
			}
		})
	}
}
