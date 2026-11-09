package ingestion

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

type fakeCriticalStream struct {
	grpc.ClientStreamingServer[pb.CriticalEvent, emptypb.Empty]

	mu    sync.Mutex
	evs   []*pb.CriticalEvent
	recvs int
}

func (f *fakeCriticalStream) Context() context.Context { return context.Background() }

func (f *fakeCriticalStream) Recv() (*pb.CriticalEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.recvs >= len(f.evs) {
		return nil, io.EOF
	}
	msg := f.evs[f.recvs]
	f.recvs++
	return msg, nil
}

func (f *fakeCriticalStream) recvCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recvs
}

func (f *fakeCriticalStream) SendAndClose(*emptypb.Empty) error { return nil }

func TestCriticalEventStreamDoesNotBlockOnStalledHandler(t *testing.T) {
	unblock := make(chan struct{})
	var calls atomic.Int64
	h := NewGRPCHandler(GRPCHandlerConfig{
		OnCritical: func(string, *pb.CriticalEvent) {
			calls.Add(1)
			<-unblock // first handler call stalls until released
		},
	})
	h.handshaked["n1"] = struct{}{}

	const total = 200
	evs := make([]*pb.CriticalEvent, 0, total)
	for i := 0; i < total; i++ {
		evs = append(evs, &pb.CriticalEvent{NodeId: "n1", EventType: "burst_emergency"})
	}
	fs := &fakeCriticalStream{evs: evs}

	errCh := make(chan error, 1)
	go func() { errCh <- h.CriticalEventStream(fs) }()

	// Recv must keep draining even though the handler never returns: a stalled
	// onCritical would otherwise block stream receipt during an attack.
	deadline := time.Now().Add(2 * time.Second)
	for fs.recvCount() < total {
		if time.Now().After(deadline) {
			close(unblock)
			t.Fatalf("Recv stalled at %d/%d events with a stalled handler", fs.recvCount(), total)
		}
		time.Sleep(5 * time.Millisecond)
	}

	if got := h.EventsReceived.Load(); got != total {
		t.Errorf("EventsReceived = %d, want %d", got, total)
	}
	if h.EventsDropped.Load() == 0 {
		t.Error("EventsDropped = 0, want drops with a bounded queue")
	}

	close(unblock)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CriticalEventStream: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not finish after the handler unblocked")
	}
	// Drop-oldest eviction: every event is either handled or counted dropped.
	want := int64(h.EventsReceived.Load() - h.EventsDropped.Load())
	if calls.Load() != want {
		t.Errorf("handler calls = %d, want %d (received - dropped)", calls.Load(), want)
	}
}
