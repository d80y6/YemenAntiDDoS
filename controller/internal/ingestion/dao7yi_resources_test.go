package ingestion

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type dao7Store struct {
	store.Store
	prefixErr error
}
type dao7Nodes struct{ store.NodeRepo }
type dao7Prefixes struct {
	store.PrefixRepo
	err error
}
type dao7Thresholds struct{ store.ThresholdRepo }
type dao7BGP struct{ store.BGPAnnouncementRepo }
type dao7XDrop struct{ store.XDropActiveRuleRepo }
type dao7Scheduled struct{ store.ScheduledActionRepo }

func (s *dao7Store) Nodes() store.NodeRepo { return dao7Nodes{} }
func (s *dao7Store) Prefixes() store.PrefixRepo {
	return dao7Prefixes{err: s.prefixErr}
}
func (s *dao7Store) Thresholds() store.ThresholdRepo             { return dao7Thresholds{} }
func (s *dao7Store) BGPAnnouncements() store.BGPAnnouncementRepo { return dao7BGP{} }
func (s *dao7Store) XDropActiveRules() store.XDropActiveRuleRepo { return dao7XDrop{} }
func (s *dao7Store) ScheduledActions() store.ScheduledActionRepo { return dao7Scheduled{} }
func (dao7Nodes) Get(_ context.Context, id string) (*store.Node, error) {
	if id != "n1" {
		return nil, errors.New("node not registered")
	}
	return &store.Node{ID: id, APIKey: "dao7-test-key", Enabled: true, DeliveryVersionCurrent: 1}, nil
}
func (dao7Nodes) UpdateMode(context.Context, string, string) error          { return nil }
func (r dao7Prefixes) List(context.Context) ([]store.WatchPrefix, error)    { return nil, r.err }
func (dao7Thresholds) List(context.Context) ([]store.Threshold, error)      { return nil, nil }
func (dao7BGP) CountByStatus(context.Context) (map[string]int, error)       { return nil, nil }
func (dao7XDrop) CountByStatus(context.Context) (map[string]int, error)     { return nil, nil }
func (dao7Scheduled) CountByStatus(context.Context) (map[string]int, error) { return nil, nil }

// Each accepted in-memory transport has a distinct server-side peer address.
type dao7Addr string

func (a dao7Addr) Network() string { return "bufconn" }
func (a dao7Addr) String() string  { return string(a) }

type dao7Conn struct {
	net.Conn
	addr net.Addr
}

func (c dao7Conn) RemoteAddr() net.Addr { return c.addr }

type dao7Listener struct {
	*bufconn.Listener
	seq atomic.Int64
}

func (l *dao7Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return dao7Conn{c, dao7Addr(fmt.Sprintf("peer-%d", l.seq.Add(1)))}, nil
}

type dao7Fixture struct {
	h      *GRPCHandler
	s      *Server
	pool   *SampleWorkerPool
	reg    *prometheus.Registry
	lis    *dao7Listener
	calls  [3]atomic.Int64
	events [3]chan struct{}
	peers  chan string
}

func dao7New(t *testing.T, interceptor grpc.StreamServerInterceptor) *dao7Fixture {
	t.Helper()
	f := &dao7Fixture{lis: &dao7Listener{Listener: bufconn.Listen(1 << 20)}, peers: make(chan string, 16)}
	for i := range f.events {
		f.events[i] = make(chan struct{}, 64)
	}
	record := func(i int) { f.calls[i].Add(1); f.events[i] <- struct{}{} }
	f.pool = NewSampleWorkerPool(func(string, *pb.SampleBatch) { record(1) })
	s := &dao7Store{}
	f.h = NewGRPCHandler(GRPCHandlerConfig{Store: s, NodeState: NewNodeState(), SamplePool: f.pool,
		OnStats: func(string, *pb.StatsReport) { record(0) }, OnCritical: func(string, *pb.CriticalEvent) { record(2) }})
	f.reg = prometheus.NewRegistry()
	if err := metrics.Register(f.reg, s, &tracker.Tracker{}); err != nil {
		t.Fatal(err)
	}
	f.s = NewServer(f.h, nil)
	// Production NewServer stays unchanged; intercept only the test server.
	f.s.grpcServer = grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		f.peers <- peerAddr(ctx)
		return next(ctx, req)
	}), grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		f.peers <- peerAddr(ss.Context())
		if interceptor != nil {
			return interceptor(srv, ss, info, next)
		}
		return next(srv, ss)
	}))
	pb.RegisterXSightServiceServer(f.s.grpcServer, f.h)
	served := make(chan struct{})
	go func() { defer close(served); _ = f.s.grpcServer.Serve(f.lis) }()
	t.Cleanup(func() { f.s.grpcServer.Stop(); <-served; f.pool.Close() })
	return f
}

func (f *dao7Fixture) dial(t *testing.T) (*grpc.ClientConn, pb.XSightServiceClient) {
	t.Helper()
	c, err := grpc.NewClient("passthrough:///dao7", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return f.lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, pb.NewXSightServiceClient(c)
}
func dao7Handshake(t *testing.T, c pb.XSightServiceClient) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := c.Handshake(ctx, &pb.NodeHandshake{NodeId: "n1", ApiKey: "dao7-test-key"})
	if err != nil || !r.GetAccepted() {
		t.Fatalf("handshake: %v %v", r, err)
	}
}

var dao7Streams = []string{"stats", "sample", "critical"}

func dao7Stream(t *testing.T, c pb.XSightServiceClient, i int, id string) (grpc.ClientStream, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	var s grpc.ClientStream
	var err error
	var msg any
	switch i {
	case 0:
		s, err = c.StatsStream(ctx)
		msg = &pb.StatsReport{NodeId: id, Timestamp: 7112233}
	case 1:
		s, err = c.SampleStream(ctx)
		msg = &pb.SampleBatch{NodeId: id, Samples: []*pb.PacketSample{{}}}
	case 2:
		s, err = c.CriticalEventStream(ctx)
		msg = &pb.CriticalEvent{NodeId: id, EventType: "dao7-unique-marker"}
	}
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = s.SendMsg(msg); err != nil {
		cancel()
		t.Fatal(err)
	}
	return s, cancel
}
func (f *dao7Fixture) rejects(t *testing.T) [3]float64 {
	t.Helper()
	var values [3]float64
	fs, err := f.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range fs {
		if mf.GetName() != "xsight_grpc_identity_rejects_total" {
			continue
		}
		for _, m := range mf.Metric {
			for _, l := range m.Label {
				if l.GetName() == "stream" {
					for i, name := range dao7Streams {
						if name == l.GetValue() {
							values[i] = m.GetCounter().GetValue()
						}
					}
				}
			}
		}
	}
	return values
}
func (f *dao7Fixture) expectCounts(t *testing.T, want [3]int64) {
	t.Helper()
	for i := range want {
		if got := f.calls[i].Load(); got != want[i] {
			t.Errorf("%s downstream total=%d want=%d", dao7Streams[i], got, want[i])
		}
	}
}
func (f *dao7Fixture) accept(t *testing.T, c pb.XSightServiceClient, i int) {
	t.Helper()
	s, cancel := dao7Stream(t, c, i, "n1")
	defer cancel()
	if err := s.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if err := s.RecvMsg(&emptypb.Empty{}); err != nil {
		t.Fatalf("%s legitimate stream: %v", dao7Streams[i], err)
	}
	select {
	case <-f.events[i]:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s callback missing", dao7Streams[i])
	}
}
func dao7Reject(t *testing.T, c pb.XSightServiceClient, i int, id string) {
	t.Helper()
	s, cancel := dao7Stream(t, c, i, id)
	defer cancel()
	if err := s.RecvMsg(&emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("%s close code=%v want Unauthenticated (err=%v)", dao7Streams[i], status.Code(err), err)
	}
}

func TestDao7yi_I1_UnknownIDsCloseStreams(t *testing.T) {
	f := dao7New(t, nil)
	_, c := f.dial(t)
	before := f.rejects(t)
	var wg sync.WaitGroup
	for i := range dao7Streams {
		wg.Add(1)
		go func(i int) { defer wg.Done(); dao7Reject(t, c, i, "x1") }(i)
	}
	wg.Wait()
	f.expectCounts(t, [3]int64{})
	if !f.h.nodeState.LastStatsAt("x1").IsZero() {
		t.Error("NodeState polluted: x1 last-stats must be zero")
	}
	if got := f.pool.Metrics.ReceivedTotal.Load(); got != 0 {
		t.Errorf("Submit received=%d want=0", got)
	}
	after := f.rejects(t)
	for i := range after {
		if after[i]-before[i] != 1 {
			t.Errorf("%s gathered rejects delta=%v want=1", dao7Streams[i], after[i]-before[i])
		}
	}
}
func TestDao7yi_I2_Impersonation(t *testing.T) {
	for i, name := range dao7Streams {
		t.Run(name, func(t *testing.T) {
			f := dao7New(t, nil)
			_, c := f.dial(t)
			dao7Handshake(t, c)
			before := f.rejects(t)
			dao7Reject(t, c, i, "n2")
			f.expectCounts(t, [3]int64{})
			after := f.rejects(t)
			if after[i]-before[i] != 1 {
				t.Errorf("reject delta=%v want=1", after[i]-before[i])
			}
			f.accept(t, c, i)
			var want [3]int64
			want[i] = 1
			f.expectCounts(t, want)
		})
	}
}

func TestDao7yi_I2_ImpersonationAfterAcceptedMessage(t *testing.T) {
	unknownReports := []any{
		&pb.StatsReport{NodeId: "n2", Timestamp: 7112234},
		&pb.SampleBatch{NodeId: "n2", Samples: []*pb.PacketSample{{}}},
		&pb.CriticalEvent{NodeId: "n2", EventType: "dao7-i2-second-message"},
	}
	for i, name := range dao7Streams {
		t.Run(name, func(t *testing.T) {
			f := dao7New(t, nil)
			_, c := f.dial(t)
			dao7Handshake(t, c)
			before := f.rejects(t)
			s, cancel := dao7Stream(t, c, i, "n1")
			defer cancel()

			// Keep this stream open and wait for n1's callback before sending n2.
			select {
			case <-f.events[i]:
			case <-time.After(5 * time.Second):
				t.Fatalf("%s first n1 callback missing", name)
			}
			var wantCalls [3]int64
			wantCalls[i] = 1
			f.expectCounts(t, wantCalls)
			if err := s.SendMsg(unknownReports[i]); err != nil {
				t.Fatalf("%s second message send: %v", name, err)
			}
			if err := s.RecvMsg(&emptypb.Empty{}); status.Code(err) != codes.Unauthenticated {
				t.Errorf("%s second message close code=%v want Unauthenticated (err=%v)", name, status.Code(err), err)
			}
			f.expectCounts(t, wantCalls)
			if name == "stats" && !f.h.nodeState.LastStatsAt("n2").IsZero() {
				t.Error("second message polluted NodeState: n2 last-stats must be zero")
			}
			after := f.rejects(t)
			var gotDelta, wantDelta [3]float64
			wantDelta[i] = 1
			for j := range after {
				gotDelta[j] = after[j] - before[j]
			}
			if gotDelta != wantDelta {
				t.Errorf("gathered second-message rejects delta=%v want=%v (stats/sample/critical)", gotDelta, wantDelta)
			}
		})
	}
}

func TestDao7yi_I3_NormalNode(t *testing.T) {
	f := dao7New(t, nil)
	_, c := f.dial(t)
	dao7Handshake(t, c)
	before := f.rejects(t)
	for i := range dao7Streams {
		f.accept(t, c, i)
	}
	f.expectCounts(t, [3]int64{1, 1, 1})
	if after := f.rejects(t); after != before {
		t.Errorf("rejects changed: %v -> %v", before, after)
	}
}
func TestDao7yi_I4_TransportRebuild(t *testing.T) {
	f := dao7New(t, nil)
	p1, c1 := f.dial(t)
	dao7Handshake(t, c1)
	addr1 := <-f.peers
	if err := p1.Close(); err != nil {
		t.Fatal(err)
	}
	_, c2 := f.dial(t)
	before := f.rejects(t)
	f.accept(t, c2, 0)
	addr2 := <-f.peers
	if addr1 == addr2 || addr1 == "" || addr2 == "" {
		t.Fatalf("peer addresses must differ: P1=%q P2=%q", addr1, addr2)
	}
	t.Logf("server peer P1=%s P2=%s", addr1, addr2)
	f.expectCounts(t, [3]int64{1, 0, 0})
	if after := f.rejects(t); after != before {
		t.Errorf("rejects changed: %v -> %v", before, after)
	}
}
func TestDao7yi_I5_RestartRehandshake(t *testing.T) {
	a := dao7New(t, nil)
	_, ca := a.dial(t)
	dao7Handshake(t, ca)
	b := dao7New(t, nil)
	_, cb := b.dial(t)
	dao7Reject(t, cb, 0, "n1")
	b.expectCounts(t, [3]int64{})
	dao7Handshake(t, cb)
	b.accept(t, cb, 0)
	b.expectCounts(t, [3]int64{1, 0, 0})
}
func TestDao7yi_M_handshake_FailureNotAdmitted(t *testing.T) {
	for _, reason := range []string{"bad_key", "watch_config", "invalid_mode"} {
		t.Run(reason, func(t *testing.T) {
			f := dao7New(t, nil)
			_, c := f.dial(t)
			req := &pb.NodeHandshake{NodeId: "n1", ApiKey: "dao7-test-key"}
			switch reason {
			case "bad_key":
				req.ApiKey = "wrong"
			case "watch_config":
				f.h.store.(*dao7Store).prefixErr = errors.New("injected watch config failure")
			case "invalid_mode":
				req.Mode = "invalid"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			r, err := c.Handshake(ctx, req)
			if err != nil || r.GetAccepted() {
				t.Fatalf("expected rejected handshake: %v %v", r, err)
			}
			for i := range dao7Streams {
				dao7Reject(t, c, i, "n1")
			}
			f.expectCounts(t, [3]int64{})
		})
	}
}

func dao7Logs(t *testing.T) *bytes.Buffer {
	t.Helper()
	old := log.Writer()
	b := new(bytes.Buffer)
	log.SetOutput(b)
	t.Cleanup(func() { log.SetOutput(old) })
	return b
}
func dao7Limit(t *testing.T) {
	t.Helper()
	old := grpcStopLimit
	grpcStopLimit = 200 * time.Millisecond
	t.Cleanup(func() { grpcStopLimit = old })
}
func TestDao7yi_S1_BoundedGracefulStop(t *testing.T) {
	dao7Limit(t)
	logs := dao7Logs(t)
	f := dao7New(t, nil)
	_, c := f.dial(t)
	dao7Handshake(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := c.StatsStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Send(&pb.StatsReport{NodeId: "n1"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.events[0]:
	case <-time.After(5 * time.Second):
		t.Fatal("stream handler not entered")
	}
	done := make(chan struct{})
	start := time.Now()
	go func() { f.s.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		f.s.grpcServer.Stop()
		<-done
		t.Fatal("GracefulStop did not return within 5s")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("GracefulStop elapsed=%v >5s", elapsed)
	}
	if err = s.RecvMsg(&emptypb.Empty{}); err == nil {
		t.Error("open client stream must receive an error")
	}
	if n := strings.Count(logs.String(), "WARN grpc: graceful stop exceeded"); n != 1 {
		t.Errorf("WARN lines=%d want=1; logs=%s", n, logs.String())
	}
}

type dao7BarrierStream struct {
	grpc.ServerStream
	entered chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (s *dao7BarrierStream) RecvMsg(m any) error {
	err := s.ServerStream.RecvMsg(m)
	if err == nil {
		s.once.Do(func() { close(s.entered); <-s.release })
	}
	return err
}
func TestDao7yi_S2_HandlerExitsBeforeWrapper(t *testing.T) {
	dao7Limit(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var events []string
	var releasedAt time.Time
	record := func(s string) { mu.Lock(); events = append(events, s); mu.Unlock() }
	f := dao7New(t, func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		if !strings.HasSuffix(info.FullMethod, "/SampleStream") {
			return next(srv, ss)
		}
		defer record("handler exit")
		return next(srv, &dao7BarrierStream{ServerStream: ss, entered: entered, release: release})
	})
	_, c := f.dial(t)
	dao7Handshake(t, c)
	s, cancel := dao7Stream(t, c, 1, "n1")
	defer cancel()
	_ = s
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("pre-Submit barrier not entered")
	}
	// Independent scheduled event: release never depends on wrapper return.
	timer := time.AfterFunc(600*time.Millisecond, func() { mu.Lock(); releasedAt = time.Now(); mu.Unlock(); close(release) })
	defer timer.Stop()
	done := make(chan struct{})
	var returnedAt time.Time
	go func() { f.s.GracefulStop(); returnedAt = time.Now(); record("wrapper return"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wrapper did not return")
	}
	mu.Lock()
	got := strings.Join(events, ",")
	released := releasedAt
	mu.Unlock()
	if got != "handler exit,wrapper return" {
		t.Errorf("event order=%s want handler exit,wrapper return", got)
	}
	if released.IsZero() || returnedAt.Before(released) {
		t.Errorf("wrapper returned %v before release %v", returnedAt, released)
	}
	// Even if a mutant returns early, wait for the independent event before cleanup.
	<-release
	f.s.grpcServer.GracefulStop()
	f.pool.Close()
}
func TestDao7yi_S3_NoStreams(t *testing.T) {
	dao7Limit(t)
	logs := dao7Logs(t)
	s := NewServer(NewGRPCHandler(GRPCHandlerConfig{}), nil)
	done := make(chan struct{})
	go func() { s.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no-stream shutdown did not return")
	}
	if msg := logs.String(); strings.Contains(msg, "WARN") && !strings.Contains(msg, "serving PLAINTEXT gRPC") {
		t.Errorf("unexpected warning: %s", msg)
	}
}
func TestDao7yi_W1_EleventhNodeGetsWorker(t *testing.T) {
	called := make(chan string, 32)
	p := NewSampleWorkerPool(func(id string, _ *pb.SampleBatch) { called <- id })
	defer p.Close()
	for i := 0; i < 10; i++ {
		p.Submit(fmt.Sprintf("node-%d", i), &pb.SampleBatch{})
	}
	p.mu.RLock()
	before := p.workerCount
	p.mu.RUnlock()
	if before != 20 {
		t.Fatalf("setup workers=%d want=20", before)
	}
	p.Submit("node-11", &pb.SampleBatch{})
	p.mu.RLock()
	after := p.workerCount
	p.mu.RUnlock()
	if after-before != 1 {
		t.Errorf("node-11 workers=%d want=1", after-before)
	}
	deadline := time.After(5 * time.Second)
wait:
	for {
		select {
		case id := <-called:
			if id == "node-11" {
				break wait
			}
		case <-deadline:
			t.Error("node-11 callback missing within 5s")
			break wait
		}
	}
	src, err := os.ReadFile("sample_worker.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "shares channel only") {
		t.Error("misleading shares channel only text remains")
	}
}
func TestDao7yi_W2_ConcurrentSubmitThenClose(t *testing.T) {
	var calls atomic.Int64
	p := NewSampleWorkerPool(func(string, *pb.SampleBatch) { calls.Add(1) })
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				p.Submit(fmt.Sprintf("node-%d", i), &pb.SampleBatch{})
			}
		}(i)
	}
	wg.Wait()
	p.Close()
	if got := calls.Load(); got != 480 {
		t.Errorf("callbacks=%d want=480", got)
	}
}
