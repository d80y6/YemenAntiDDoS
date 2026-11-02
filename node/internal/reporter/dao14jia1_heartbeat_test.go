package reporter

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/node/internal/pb"
	"google.golang.org/protobuf/proto"
)

func dao14Flow(t *testing.T, ch chan *pb.StatsReport) (*Reporter, chan *pb.StatsReport) {
	t.Helper()
	sent := make(chan *pb.StatsReport, 64)
	r := NewFlow(Config{NodeID: "n1", Mode: "flow"}, ch, nil)
	r.client = &dao13fClient{stats: &dao13fStream[pb.StatsReport]{send: func(m *pb.StatsReport) error { sent <- proto.Clone(m).(*pb.StatsReport); return nil }}}
	return r, sent
}

func dao14RunFlow(t *testing.T, r *Reporter, d time.Duration, gap uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if err := r.runStatsStream(ctx, gap); err != nil {
		t.Fatalf("stats stream: %v", err)
	}
}

func TestDao14jia1_G7b(t *testing.T) {
	t.Run("IdleSendsHeartbeat", func(t *testing.T) {
		r, sent := dao14Flow(t, make(chan *pb.StatsReport, 8))
		r.SetHeartbeat(func() *pb.StatsReport { return &pb.StatsReport{NodeId: "n1"} })
		dao14RunFlow(t, r, 2500*time.Millisecond, 7)
		if len(sent) != 2 {
			t.Fatalf("sends=%d want=2", len(sent))
		}
		for i, want := range []uint32{7, 0} {
			m := <-sent
			if m.GlobalStats != nil || m.GapSeconds != want {
				t.Errorf("heartbeat %d=%v want gap=%d", i, m, want)
			}
		}
	})
	t.Run("RealReportsSuppressHeartbeat", func(t *testing.T) {
		ch := make(chan *pb.StatsReport, 8)
		r, sent := dao14Flow(t, ch)
		var calls atomic.Int32
		r.SetHeartbeat(func() *pb.StatsReport { calls.Add(1); return &pb.StatsReport{} })
		ctx, cancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
		defer cancel()
		producer := make(chan struct{})
		go func() {
			defer close(producer)
			ticker := time.NewTicker(300 * time.Millisecond)
			defer ticker.Stop()
			for i := int64(1); i <= 8; i++ {
				select {
				case <-ticker.C:
					ch <- &pb.StatsReport{Timestamp: i, GlobalStats: &pb.GlobalStatsMsg{}}
				case <-ctx.Done():
					return
				}
			}
		}()
		if err := r.runStatsStream(ctx, 7); err != nil {
			t.Fatal(err)
		}
		<-producer
		if calls.Load() != 0 || len(sent) != 8 {
			t.Fatalf("heartbeat calls=%d sends=%d", calls.Load(), len(sent))
		}
		for i := 0; i < 8; i++ {
			m := <-sent
			want := uint32(0)
			if i == 0 {
				want = 7
			}
			if m.GlobalStats == nil || m.GapSeconds != want {
				t.Errorf("report=%v want gap=%d", m, want)
			}
		}
	})
	t.Run("NoHeartbeatWhileDisconnected", func(t *testing.T) {
		ch := make(chan *pb.StatsReport, 8)
		r, sent := dao14Flow(t, ch)
		var calls atomic.Int32
		r.SetHeartbeat(func() *pb.StatsReport { calls.Add(1); return &pb.StatsReport{} })
		<-time.After(1200 * time.Millisecond)
		if calls.Load() != 0 || len(ch) != 0 {
			t.Fatal("disconnected reporter generated a heartbeat")
		}
		ch <- &pb.StatsReport{Timestamp: 42, GlobalStats: &pb.GlobalStatsMsg{}}
		dao14RunFlow(t, r, 300*time.Millisecond, 7)
		if len(sent) != 1 {
			t.Fatalf("sends=%d", len(sent))
		}
		m := <-sent
		if m.Timestamp != 42 || m.GlobalStats == nil || m.GapSeconds != 7 || calls.Load() != 0 {
			t.Fatalf("first report=%v heartbeat calls=%d", m, calls.Load())
		}
	})
	t.Run("NilHeartbeatSendsNothing", func(t *testing.T) {
		r, sent := dao14Flow(t, make(chan *pb.StatsReport, 8))
		dao14RunFlow(t, r, 1500*time.Millisecond, 7)
		if len(sent) != 0 {
			t.Fatal("unexpected send")
		}
	})
}

func TestDao14jia1_G7d(t *testing.T) {
	t.Run("IdleBranchPrefersBacklog", func(t *testing.T) {
		ch := make(chan *pb.StatsReport, 8)
		for i := int64(1); i <= 8; i++ {
			ch <- &pb.StatsReport{Timestamp: i, GlobalStats: &pb.GlobalStatsMsg{}}
		}
		r, _ := dao14Flow(t, ch)
		var calls atomic.Int32
		r.SetHeartbeat(func() *pb.StatsReport { calls.Add(1); return &pb.StatsReport{} })
		gate := make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(gate) }) }
		defer release()
		seen := make(chan *pb.StatsReport, 1)
		s := &dao13fStream[pb.StatsReport]{send: func(m *pb.StatsReport) error { seen <- proto.Clone(m).(*pb.StatsReport); <-gate; return nil }}
		gap := uint32(5)
		type result struct {
			closed bool
			err    error
		}
		done := make(chan result, 1)
		go func() { closed, err := r.flowIdle(context.Background(), s, &gap); done <- result{closed, err} }()
		select {
		case m := <-seen:
			if m.Timestamp != 1 || m.GlobalStats == nil || m.GapSeconds != 5 {
				t.Errorf("first send=%v", m)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("send did not reach gate")
		}
		if len(ch) != 7 || calls.Load() != 0 {
			t.Errorf("backlog=%d heartbeat calls=%d", len(ch), calls.Load())
		}
		release()
		got := <-done
		if got.closed || got.err != nil || gap != 0 {
			t.Fatalf("result=%+v gap=%d", got, gap)
		}
	})
	t.Run("IdleBranchHeartbeatWhenEmpty", func(t *testing.T) {
		r, sent := dao14Flow(t, make(chan *pb.StatsReport, 8))
		var calls atomic.Int32
		r.SetHeartbeat(func() *pb.StatsReport { calls.Add(1); return &pb.StatsReport{} })
		gap := uint32(5)
		closed, err := r.flowIdle(context.Background(), r.client.(*dao13fClient).stats, &gap)
		if closed || err != nil || len(sent) != 1 || calls.Load() != 1 {
			t.Fatalf("closed=%t err=%v sends=%d calls=%d", closed, err, len(sent), calls.Load())
		}
		if m := <-sent; m.GlobalStats != nil {
			t.Fatalf("heartbeat=%v", m)
		}
	})
	t.Run("CancelWinsOverIdle", func(t *testing.T) {
		ch := make(chan *pb.StatsReport, 8)
		ch <- &pb.StatsReport{Timestamp: 1, GlobalStats: &pb.GlobalStatsMsg{}}
		r, sent := dao14Flow(t, ch)
		var calls atomic.Int32
		r.SetHeartbeat(func() *pb.StatsReport { calls.Add(1); return &pb.StatsReport{} })
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		gap := uint32(5)
		closed, err := r.flowIdle(ctx, r.client.(*dao13fClient).stats, &gap)
		if !closed || err != nil || len(sent) != 0 || calls.Load() != 0 || len(ch) != 1 {
			t.Fatalf("closed=%t err=%v sends=%d calls=%d backlog=%d", closed, err, len(sent), calls.Load(), len(ch))
		}
	})
	t.Run("HeartbeatSendFailReconnects", func(t *testing.T) {
		ch := make(chan *pb.StatsReport, 8)
		r, _ := dao14Flow(t, ch)
		r.SetHeartbeat(func() *pb.StatsReport { return &pb.StatsReport{} })
		broken := errors.New("stream broken")
		r.client = &dao13fClient{stats: &dao13fStream[pb.StatsReport]{send: func(*pb.StatsReport) error { return broken }}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := r.runStatsStream(ctx, 3); !errors.Is(err, broken) {
			t.Fatalf("send failure=%v", err)
		}
		ch <- &pb.StatsReport{Timestamp: 42, GlobalStats: &pb.GlobalStatsMsg{}}
		sent := make(chan *pb.StatsReport, 8)
		r.client = &dao13fClient{stats: &dao13fStream[pb.StatsReport]{send: func(m *pb.StatsReport) error { sent <- proto.Clone(m).(*pb.StatsReport); return nil }}}
		dao14RunFlow(t, r, 300*time.Millisecond, 9)
		if len(sent) != 1 {
			t.Fatalf("reconnect sends=%d", len(sent))
		}
		if m := <-sent; m.Timestamp != 42 || m.GapSeconds != 9 {
			t.Fatalf("reconnect report=%v", m)
		}
	})
}
