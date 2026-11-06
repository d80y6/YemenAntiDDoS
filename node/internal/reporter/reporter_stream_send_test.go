package reporter

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// blockingStream models a gRPC stream whose SendMsg occupies the wire until
// released, and counts how many SendMsg calls are ever in flight at once.
type blockingStream struct {
	grpc.ClientStream
	ctx         context.Context
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	entered     chan struct{}
	release     chan struct{}
}

func (b *blockingStream) SendMsg(any) error {
	n := b.inFlight.Add(1)
	for {
		m := b.maxInFlight.Load()
		if n <= m || b.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	defer b.inFlight.Add(-1)
	select {
	case b.entered <- struct{}{}:
	default:
	}
	select {
	case <-b.release:
		return nil
	case <-b.ctx.Done():
		return b.ctx.Err()
	}
}

func (b *blockingStream) Context() context.Context { return b.ctx }

// TestStreamSenderSerializesSends: a second SendMsg must not enter the stream
// while the first is still in flight (the old sendWithTimeout allowed this by
// returning before its send goroutine finished).
func TestStreamSenderSerializesSends(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bs := &blockingStream{
		ctx:     ctx,
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
	ss := newStreamSender(bs)

	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- ss.Send(ctx, "first") }()
	<-bs.entered

	go func() { secondDone <- ss.Send(ctx, "second") }()

	select {
	case <-bs.entered:
		t.Fatal("second SendMsg entered the stream while the first was in flight")
	case <-time.After(200 * time.Millisecond):
	}

	close(bs.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first send: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second send: %v", err)
	}
	if got := bs.maxInFlight.Load(); got != 1 {
		t.Fatalf("max concurrent SendMsg = %d, want 1", got)
	}
}

// TestStreamSenderNoGoroutineLeakOnCancel: Send is synchronous, so cancelling
// the context unblocks it and leaves no orphaned sender goroutine behind (the
// old wrapper leaked one per timed-out send).
func TestStreamSenderNoGoroutineLeakOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	bs := &blockingStream{
		ctx:     ctx,
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
	ss := newStreamSender(bs)

	before := runtime.NumGoroutine()
	errCh := make(chan error, 1)
	go func() { errCh <- ss.Send(ctx, "blocked") }()
	<-bs.entered
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("send returned nil after cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not return on cancellation (send runs without a cancel path)")
	}

	time.Sleep(100 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines %d -> %d: orphaned sender goroutine", before, after)
	}
}

// TestStreamSenderRejectsCanceledContext: a pre-cancelled context fails fast
// without entering the stream.
func TestStreamSenderRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bs := &blockingStream{
		ctx:     context.Background(),
		entered: make(chan struct{}, 8),
		release: make(chan struct{}),
	}
	close(bs.release)
	ss := newStreamSender(bs)
	if err := ss.Send(ctx, "nope"); err == nil {
		t.Fatal("expected error for cancelled context")
	}
	select {
	case <-bs.entered:
		t.Fatal("stream entered despite cancelled context")
	default:
	}
}
