package ingestion

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
)

// serializingFakeStream detects overlapping Send calls, which gRPC forbids.
type serializingFakeStream struct {
	pb.XSightService_ControlStreamServer
	inFlight   atomic.Int32
	concurrent atomic.Bool
	sends      atomic.Int32
}

func (f *serializingFakeStream) Send(*pb.ControlMessage) error {
	if f.inFlight.Add(1) != 1 {
		f.concurrent.Store(true)
	}
	time.Sleep(200 * time.Microsecond)
	f.inFlight.Add(-1)
	f.sends.Add(1)
	return nil
}

func TestSendInlineRulePushSerializesPerNode(t *testing.T) {
	ns := NewNodeState()
	stream := &serializingFakeStream{}
	ns.SetControlStream("n1", stream)
	h := &GRPCHandler{nodeState: ns}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.SendInlineRulePush("n1", &pb.InlineRuleSet{Version: 1}); err != nil {
				t.Errorf("SendInlineRulePush: %v", err)
			}
		}()
	}
	wg.Wait()

	if stream.concurrent.Load() {
		t.Fatal("concurrent Send calls on one ControlStream")
	}
	if got := stream.sends.Load(); got != 16 {
		t.Fatalf("sends = %d, want 16", got)
	}
}
