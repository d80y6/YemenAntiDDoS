package ingestion

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

// ---- shared helpers ----

func dao14CaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
}

var dao14WarnRE = regexp.MustCompile(`WARN ingestion: node=(\S+) skipped (\d+) malformed address entries \(prefix=(\d+) ip=(\d+) flow=(\d+)`)

func dao14Warns(buf *bytes.Buffer, node string) [][]string {
	var out [][]string
	for _, m := range dao14WarnRE.FindAllStringSubmatch(buf.String(), -1) {
		if m[1] == node {
			out = append(out, m)
		}
	}
	return out
}

var dao14Legal = &pb.PrefixStatsMsg{Prefix: []byte{198, 51, 100, 0}, PrefixLen: 24, PktCount: 5}

// ---- G1w: rate-limited WARN and per-branch counting ----

func TestDao14a2_G1w(t *testing.T) {
	badPrefix := &pb.PrefixStatsMsg{Prefix: []byte{192, 0, 2}, PrefixLen: 24, PktCount: 1}
	t.Run("Window", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			buf := dao14CaptureLog(t)
			w := NewStatsWriter(ring.New(ring.DefaultLimits()))
			rep := func() *pb.StatsReport {
				return &pb.StatsReport{Timestamp: time.Now().Unix(), PrefixStats: []*pb.PrefixStatsMsg{badPrefix, dao14Legal}}
			}
			w.HandleStats("bad", rep())
			if n := len(dao14Warns(buf, "bad")); n != 1 {
				t.Fatalf("first report warns=%d want 1", n)
			}
			for i := 0; i < 5; i++ {
				time.Sleep(10 * time.Second)
				if i == 4 {
					time.Sleep(9 * time.Second) // 59 s after the first
				}
				w.HandleStats("bad", rep())
			}
			if n := len(dao14Warns(buf, "bad")); n != 1 {
				t.Errorf("within 59s warns=%d want 1", n)
			}
			time.Sleep(time.Second)
			w.HandleStats("bad", rep())
			if n := len(dao14Warns(buf, "bad")); n != 2 {
				t.Errorf("after 60s warns=%d want 2", n)
			}
			w.HandleStats("bad2", rep())
			if n := len(dao14Warns(buf, "bad2")); n != 1 {
				t.Errorf("bad2 warns=%d want 1 (per-node limiter)", n)
			}
			w.HandleStats("clean", &pb.StatsReport{Timestamp: time.Now().Unix(), PrefixStats: []*pb.PrefixStatsMsg{dao14Legal}})
			if n := len(dao14Warns(buf, "clean")); n != 0 {
				t.Errorf("legal-only warns=%d want 0", n)
			}
		})
	})
	// Each cell has exactly one malformed entry; field = which WARN counter must be 1.
	cells := []struct {
		name, field string
		rep         *pb.StatsReport
	}{
		{"InPrefix", "prefix", &pb.StatsReport{PrefixStats: []*pb.PrefixStatsMsg{badPrefix}}},
		{"InPrefixHostBits", "prefix", &pb.StatsReport{PrefixStats: []*pb.PrefixStatsMsg{{Prefix: []byte{192, 0, 2, 5}, PrefixLen: 24}}}},
		{"OutPrefix", "prefix", &pb.StatsReport{SrcPrefixStats: []*pb.PrefixStatsMsg{badPrefix}}},
		{"InIP", "ip", &pb.StatsReport{IpStats: []*pb.IPStats{{DstIp: []byte{192, 0, 2}}}}},
		{"OutIP", "ip", &pb.StatsReport{SrcIpStats: []*pb.IPStats{{DstIp: []byte{192, 0, 2}}}}},
		{"FlowSrc", "flow", &pb.StatsReport{TopFlows: []*pb.FlowSample{{SrcIp: []byte{1, 2, 3}, DstIp: net.ParseIP("198.51.100.7")}}}},
		{"FlowDst", "flow", &pb.StatsReport{TopFlows: []*pb.FlowSample{{SrcIp: net.ParseIP("203.0.113.9"), DstIp: []byte{1, 2, 3}}}}},
	}
	idx := map[string]int{"prefix": 3, "ip": 4, "flow": 5}
	for _, c := range cells {
		t.Run("Sole/"+c.name, func(t *testing.T) {
			buf := dao14CaptureLog(t)
			w := NewStatsWriter(ring.New(ring.DefaultLimits()))
			c.rep.Timestamp = time.Now().Unix()
			w.HandleStats("n-"+c.name, c.rep)
			ws := dao14Warns(buf, "n-"+c.name)
			if len(ws) != 1 {
				t.Fatalf("warns=%d want 1", len(ws))
			}
			if ws[0][2] != "1" {
				t.Errorf("total=%s want 1", ws[0][2])
			}
			for f, i := range idx {
				want := "0"
				if f == c.field {
					want = "1"
				}
				if ws[0][i] != want {
					t.Errorf("%s=%s want %s (line %q)", f, ws[0][i], want, ws[0][0])
				}
			}
		})
	}
}

// ---- G1h / G1x ring half / G1f / G1hc ----

func TestDao14a2_G1h(t *testing.T) {
	for _, out := range []bool{false, true} {
		t.Run(fmt.Sprintf("RingPlaceholder/out=%v", out), func(t *testing.T) {
			rings := ring.New(ring.DefaultLimits())
			ps := []*pb.PrefixStatsMsg{
				{Prefix: []byte{192, 0, 2, 0}, PrefixLen: 24, PktCount: 11},
				{Prefix: []byte{198, 51, 100, 5}, PrefixLen: 24, PktCount: 22},
				{Prefix: []byte{198, 51, 100, 0}, PrefixLen: 24, PktCount: 33},
			}
			ips := []*pb.IPStats{{DstIp: []byte{198, 51, 100, 1}, PktCount: 7}}
			r := &pb.StatsReport{Timestamp: time.Now().Unix(), UpstreamSampleRate: 1}
			getP, getIP := rings.GetPrefixRing, rings.GetIPRingByKey
			if out {
				r.SrcPrefixStats, r.SrcIpStats = ps, ips
				getP, getIP = rings.GetSrcPrefixRing, rings.GetSrcIPRingByKey
			} else {
				r.PrefixStats, r.IpStats = ps, ips
			}
			NewStatsWriter(rings).HandleStats("n", r)
			c := getP("n", "198.51.100.0/24")
			if c == nil || len(c.Latest(10)) != 1 || c.Latest(1)[0].PPS != 33 {
				t.Errorf("C ring wrong")
			}
			if getP("n", "198.51.100.5/24") != nil {
				t.Errorf("host-bit prefix got a ring")
			}
			if ipr := getIP("n", "198.51.100.0/24", "198.51.100.1"); ipr == nil || ipr.Latest(1)[0].PPS != 7 {
				t.Errorf("IP not under C")
			}
		})
	}
	t.Run("Flow", func(t *testing.T) {
		w := &FlowWriter{ch: make(chan flowBatch, 1)}
		w.HandleFlows("n", &pb.StatsReport{
			PrefixStats: []*pb.PrefixStatsMsg{{Prefix: []byte{192, 0, 2, 5}, PrefixLen: 24}, {Prefix: []byte{198, 51, 100, 0}, PrefixLen: 24}},
			TopFlows: []*pb.FlowSample{
				{SrcIp: net.ParseIP("203.0.113.9"), DstIp: net.ParseIP("192.0.2.7")},
				{SrcIp: net.ParseIP("203.0.113.9"), DstIp: net.ParseIP("198.51.100.7")},
			},
		})
		b := <-w.ch
		if len(b.flows) != 2 || b.flows[0].Prefix != nil || b.flows[1].Prefix == nil || *b.flows[1].Prefix != "198.51.100.0/24" {
			t.Errorf("flows=%+v", b.flows)
		}
	})
}

func TestDao14a2_G1xRing(t *testing.T) {
	canon := &pb.PrefixStatsMsg{Prefix: []byte{192, 0, 2, 0}, PrefixLen: 24, PktCount: 1000}
	host := &pb.PrefixStatsMsg{Prefix: []byte{192, 0, 2, 5}, PrefixLen: 24, PktCount: 0}
	for _, out := range []bool{false, true} {
		for _, order := range [][]*pb.PrefixStatsMsg{{canon, host}, {host, canon}} {
			name := fmt.Sprintf("out=%v/canonFirst=%v", out, order[0] == canon)
			t.Run(name, func(t *testing.T) {
				rings := ring.New(ring.DefaultLimits())
				r := &pb.StatsReport{Timestamp: time.Now().Unix()}
				get := rings.GetPrefixRing
				if out {
					r.SrcPrefixStats, get = order, rings.GetSrcPrefixRing
				} else {
					r.PrefixStats = order
				}
				NewStatsWriter(rings).HandleStats("n", r)
				pr := get("n", "192.0.2.0/24")
				if pr == nil || len(pr.Latest(10)) != 1 || pr.Latest(1)[0].PPS != 1000 {
					t.Errorf("canonical ring wrong: %v", pr)
				}
				if get("n", "192.0.2.5/24") != nil {
					t.Errorf("host-bit ring exists")
				}
			})
		}
	}
}

func TestDao14a2_G1f(t *testing.T) {
	w := &FlowWriter{ch: make(chan flowBatch, 1)}
	w.HandleFlows("n", &pb.StatsReport{TopFlows: []*pb.FlowSample{
		{SrcIp: []byte{1, 2, 3}, DstIp: net.ParseIP("198.51.100.7")},
		{SrcIp: net.ParseIP("203.0.113.9"), DstIp: []byte{1, 2, 3}},
		{SrcIp: net.ParseIP("203.0.113.9"), DstIp: net.ParseIP("198.51.100.8")},
	}})
	b := <-w.ch
	if len(b.flows) != 1 || b.flows[0].SrcIP != "203.0.113.9" || b.flows[0].DstIP != "198.51.100.8" {
		t.Errorf("flows=%+v", b.flows)
	}
}

func TestDao14a2_G1hc(t *testing.T) {
	for _, c := range []struct {
		name       string
		raw, ip    []byte
		cidr, addr string
		plen       uint32
	}{
		{"V4", []byte{192, 0, 2, 0}, []byte{192, 0, 2, 7}, "192.0.2.0/24", "192.0.2.7", 24},
		{"V6", net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::7"), "2001:db8::/32", "2001:db8::7", 32},
		{"Mapped", net.ParseIP("::ffff:192.0.2.0"), net.ParseIP("::ffff:192.0.2.7"), "192.0.2.0/24", "192.0.2.7", 24},
	} {
		for _, out := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/out=%v", c.name, out), func(t *testing.T) {
				rings := ring.New(ring.DefaultLimits())
				ps := []*pb.PrefixStatsMsg{{Prefix: c.raw, PrefixLen: c.plen, PktCount: 10, ByteCount: 100}}
				ips := []*pb.IPStats{{DstIp: c.ip, PktCount: 4, ByteCount: 40}}
				r := &pb.StatsReport{Timestamp: time.Now().Unix(), UpstreamSampleRate: 3}
				getP, getIP := rings.GetPrefixRing, rings.GetIPRingByKey
				if out {
					r.SrcPrefixStats, r.SrcIpStats = ps, ips
					getP, getIP = rings.GetSrcPrefixRing, rings.GetSrcIPRingByKey
				} else {
					r.PrefixStats, r.IpStats = ps, ips
				}
				NewStatsWriter(rings).HandleStats("n", r)
				pr, ir := getP("n", c.cidr), getIP("n", c.cidr, c.addr)
				if pr == nil || ir == nil {
					t.Fatal("literal ring key absent")
				}
				p, i := pr.Latest(1)[0], ir.Latest(1)[0]
				if p.PPS != 30 || p.BPS != 2400 || i.PPS != 12 || i.BPS != 960 {
					t.Errorf("multiplier: prefix=%d/%d ip=%d/%d", p.PPS, p.BPS, i.PPS, i.BPS)
				}
				w := &FlowWriter{ch: make(chan flowBatch, 1)}
				w.HandleFlows("n", &pb.StatsReport{PrefixStats: ps, TopFlows: []*pb.FlowSample{{SrcIp: net.ParseIP("203.0.113.9"), DstIp: c.ip}}})
				b := <-w.ch
				if len(b.flows) != 1 || b.flows[0].Prefix == nil || *b.flows[0].Prefix != c.cidr || b.flows[0].SrcIP != "203.0.113.9" || b.flows[0].DstIP != c.addr {
					t.Errorf("flows=%+v", b.flows)
				}
			})
		}
	}
}

// ---- G1i: per-node write isolation ----

type dao14RejectRepo struct {
	store.StatsRepo
	mu      sync.Mutex
	reject  map[string]bool
	calls   int
	rows    []store.StatPoint
	block   map[string]chan struct{} // node -> released when closed; blocks single-node group calls
	entered chan string
}

func (r *dao14RejectRepo) BulkInsert(_ context.Context, pts []store.StatPoint) error {
	r.mu.Lock()
	r.calls++
	nodes := map[string]bool{}
	for _, p := range pts {
		nodes[p.NodeID] = true
	}
	var ch chan struct{}
	if len(nodes) == 1 {
		for n := range nodes {
			ch = r.block[n]
		}
	}
	r.mu.Unlock()
	if ch != nil {
		r.entered <- "retry"
		<-ch
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for n := range nodes {
		if r.reject[n] {
			return errors.New("rejected node " + n)
		}
	}
	r.rows = append(r.rows, pts...)
	return nil
}

func (r *dao14RejectRepo) rowsFor(node string) []store.StatPoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []store.StatPoint
	for _, p := range r.rows {
		if p.NodeID == node {
			out = append(out, p)
		}
	}
	return out
}

func dao14Pt(node string, pps int64, at time.Time) store.StatPoint {
	pfx := "198.51.100.0/24"
	if node != "good" {
		pfx = "192.0.2.0/24"
	}
	p := store.StatPoint{Time: at, NodeID: node, Prefix: &pfx, Direction: "receives", PPS: pps, BPS: pps * 8}
	for i := range p.DecoderPPS {
		p.DecoderPPS[i] = int32(pps) + int32(i)
		p.DecoderBPS[i] = pps*8 + int64(i)
	}
	return p
}

func TestDao14a2_G1i(t *testing.T) {
	ctx := context.Background()
	t0 := time.Unix(1_700_000_000, 0)
	for _, stage := range []string{"Isolates", "NoDuplicateOfSucceeded", "TickWeightKept"} {
		t.Run(stage, func(t *testing.T) {
			buf := dao14CaptureLog(t)
			repo := &dao14RejectRepo{reject: map[string]bool{"poison": true}}
			w := NewDBWriter(nil, repo, 5*time.Second)
			w.Enqueue([]store.StatPoint{dao14Pt("good", 10, t0), dao14Pt("poison", 10, t0)})
			w.Enqueue([]store.StatPoint{dao14Pt("poison", 30, t0.Add(time.Second))})
			w.flush(ctx)
			if g := repo.rowsFor("good"); len(g) != 1 || len(repo.rowsFor("poison")) != 0 {
				t.Fatalf("Isolates: good=%d poison=%d", len(g), len(repo.rowsFor("poison")))
			}
			if n := strings.Count(buf.String(), "db_writer: per-node retry:"); n != 1 {
				t.Errorf("retry summaries=%d want 1", n)
			}
			if stage == "Isolates" {
				return
			}
			w.Enqueue([]store.StatPoint{dao14Pt("good", 20, t0.Add(5*time.Second))})
			w.flush(ctx)
			if g := repo.rowsFor("good"); len(g) != 2 || g[1].PPS != 20 {
				t.Fatalf("NoDuplicateOfSucceeded: good rows=%+v", g)
			}
			if stage == "NoDuplicateOfSucceeded" {
				return
			}
			repo.mu.Lock()
			repo.reject["poison"] = false
			repo.mu.Unlock()
			w.Enqueue([]store.StatPoint{dao14Pt("poison", 50, t0.Add(10*time.Second))})
			w.flush(ctx)
			if p := repo.rowsFor("poison"); len(p) != 1 || p[0].PPS != 30 {
				t.Fatalf("TickWeightKept: poison rows=%+v", p)
			}
		})
	}
	t.Run("AllFailEqualsToday", func(t *testing.T) {
		buf := dao14CaptureLog(t)
		repo := &dao14RejectRepo{reject: map[string]bool{"a": true, "b": true, "c": true}}
		w := NewDBWriter(nil, repo, 5*time.Second)
		for _, n := range []string{"a", "b", "c"} {
			w.Enqueue([]store.StatPoint{dao14Pt(n, 10, t0), dao14Pt(n, 30, t0.Add(time.Second))})
		}
		want := make(map[statKey]statAcc)
		for k, a := range w.pending {
			want[k] = *a
		}
		w.flush(ctx)
		if n := strings.Count(buf.String(), "db_writer: per-node retry:"); n != 1 {
			t.Errorf("retry summaries=%d want 1", n)
		}
		if len(w.pending) != len(want) {
			t.Errorf("pending keys=%d want %d", len(w.pending), len(want))
		}
		for k, a := range want {
			if got := w.pending[k]; got == nil || *got != a {
				t.Errorf("accumulator %v=%+v want %+v", k, got, a)
			}
		}
		if repo.calls != 4 {
			t.Errorf("calls=%d want 4", repo.calls)
		}
		for _, n := range []string{"a", "b", "c"} {
			pfx := "192.0.2.0/24"
			acc := w.pending[statKey{NodeID: n, Prefix: pfx, Direction: "receives"}]
			if acc == nil || acc.Ticks != 2 || acc.PPS != 40 || !acc.FirstTime.Equal(t0) || !acc.LastTime.Equal(t0.Add(time.Second)) {
				t.Errorf("%s acc=%+v", n, acc)
			}
		}
	})
	t.Run("SingleGroupNoRetry", func(t *testing.T) {
		repo := &dao14RejectRepo{reject: map[string]bool{"poison": true}}
		w := NewDBWriter(nil, repo, 5*time.Second)
		w.Enqueue([]store.StatPoint{dao14Pt("poison", 10, t0)})
		w.flush(ctx)
		if repo.calls != 1 {
			t.Errorf("calls=%d want 1", repo.calls)
		}
	})
	many := func(node string, n int) []store.StatPoint {
		pts := make([]store.StatPoint, n)
		for i := range pts {
			s := net.IPv4(198, 18+byte(i>>16), byte(i>>8), byte(i)).String()
			pts[i] = store.StatPoint{Time: t0, NodeID: node, DstIP: &s, Direction: "receives", PPS: 1}
		}
		return pts
	}
	t.Run("RetryCapSingle", func(t *testing.T) {
		repo := &dao14RejectRepo{reject: map[string]bool{"poison": true}}
		w := NewDBWriter(nil, repo, 5*time.Second)
		w.Enqueue(many("poison", 100_001))
		w.flush(ctx)
		if len(w.pending) != 100_000 {
			t.Errorf("pending=%d want 100000", len(w.pending))
		}
	})
	t.Run("IsolationUnderCap", func(t *testing.T) {
		repo := &dao14RejectRepo{reject: map[string]bool{"poison": true}}
		w := NewDBWriter(nil, repo, 5*time.Second)
		w.Enqueue(many("poison", 100_001))
		w.Enqueue([]store.StatPoint{dao14Pt("good", 10, t0)})
		w.flush(ctx)
		if len(repo.rowsFor("good")) != 1 {
			t.Errorf("good rows=%d want 1", len(repo.rowsFor("good")))
		}
		if len(w.pending) > 100_000 {
			t.Errorf("pending=%d", len(w.pending))
		}
		for k := range w.pending {
			if k.NodeID == "good" {
				t.Errorf("good key re-queued")
			}
		}
	})
	t.Run("ConcurrentEnqueueDuringRetry", func(t *testing.T) {
		release := make(chan struct{})
		repo := &dao14RejectRepo{reject: map[string]bool{"poison": true},
			block: map[string]chan struct{}{"poison": release}, entered: make(chan string, 1)}
		w := NewDBWriter(nil, repo, 5*time.Second)
		poisonKey := statKey{NodeID: "poison", Prefix: "192.0.2.0/24", Direction: "receives"}
		w.Enqueue([]store.StatPoint{dao14Pt("good", 10, t0), dao14Pt("poison", 10, t0)})
		old := w.pending[poisonKey]
		w.Enqueue([]store.StatPoint{dao14Pt("poison", 30, t0.Add(4*time.Second))})
		// Both old ticks must belong to the accumulator detached by the first flush.
		if old == nil || w.pending[poisonKey] != old || old.Ticks != 2 || old.PPS != 40 || old.BPS != 320 {
			t.Fatalf("old accumulator before flush=%+v; want the same accumulator with ticks=2 PPS=40 BPS=320", old)
		}
		done := make(chan struct{})
		go func() { w.flush(ctx); close(done) }()
		released := false
		defer func() {
			if !released {
				close(release)
			}
			<-done
		}()
		select {
		case <-repo.entered:
		case <-done:
			t.Fatal("flush returned without entering the per-node retry")
		case <-time.After(5 * time.Second):
			t.Fatal("neither retry nor flush return within 5s")
		}
		if rows := repo.rowsFor("good"); len(rows) != 1 || rows[0].PPS != 10 {
			t.Fatalf("good group before concurrent Enqueue=%+v; want one row with PPS=10", rows)
		}
		enq := make(chan struct{})
		go func() {
			w.Enqueue([]store.StatPoint{dao14Pt("poison", 50, t0.Add(2*time.Second)), dao14Pt("good", 40, t0.Add(2*time.Second))})
			close(enq)
		}()
		select {
		case <-enq:
		case <-time.After(5 * time.Second):
			t.Fatal("Enqueue blocked while flush retries (w.mu held)")
		}
		// The new tick is separate until the failed old accumulator is requeued.
		w.mu.Lock()
		incoming := w.pending[poisonKey]
		separate := incoming != nil && incoming != old && incoming.Ticks == 1 && incoming.PPS == 50 && incoming.BPS == 400 && old.Ticks == 2 && old.PPS == 40 && old.BPS == 320
		w.mu.Unlock()
		if !separate {
			t.Fatal("retry barrier did not separate the old two-tick accumulator from the new one-tick accumulator")
		}
		close(release)
		released = true
		<-done
		pk := w.pending[poisonKey]
		gk := w.pending[statKey{NodeID: "good", Prefix: "198.51.100.0/24", Direction: "receives"}]
		if pk == nil || pk != incoming || pk.Ticks != 3 || pk.PPS != 90 || pk.BPS != 720 || !pk.FirstTime.Equal(t0) || !pk.LastTime.Equal(t0.Add(4*time.Second)) {
			t.Errorf("poison merged accumulator=%+v; want the incoming accumulator with ticks=3 PPS=90 BPS=720 first=t0 last=t0+4s", pk)
		}
		if gk == nil || gk.Ticks != 1 || gk.PPS != 40 {
			t.Errorf("good acc=%+v", gk)
		}
		if len(repo.rowsFor("good")) != 1 {
			t.Errorf("good old tick not written")
		}
		repo.mu.Lock()
		repo.reject["poison"] = false
		delete(repo.block, "poison")
		repo.mu.Unlock()
		w.flush(ctx)
		if rows := repo.rowsFor("poison"); len(rows) != 1 || rows[0].PPS != 30 || rows[0].BPS != 240 {
			t.Errorf("poison persisted rows=%+v; want one row with PPS=30 BPS=240", rows)
		}
	})
}

func dao14Eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		runtime.Gosched()
	}
}

func dao14OpenControl(t *testing.T, c pb.XSightServiceClient) (pb.XSightService_ControlStreamClient, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s, err := c.ControlStream(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return s, cancel
}

// ---- G5a / G5b ----

func TestDao14a2_G5(t *testing.T) {
	var exited chan struct{} // per subtest: a previous subtest's late handler exit must not count
	newF := func(t *testing.T) *dao7Fixture {
		ch := make(chan struct{}, 8)
		exited = ch
		return dao7New(t, func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, next grpc.StreamHandler) error {
			err := next(srv, ss)
			if strings.HasSuffix(info.FullMethod, "/ControlStream") {
				ch <- struct{}{}
			}
			return err
		})
	}
	t.Run("G5a_OldCloseKeepsNew", func(t *testing.T) {
		f := newF(t)
		ns := f.h.nodeState
		_, ca := f.dial(t)
		dao7Handshake(t, ca)
		_, cancelA := dao14OpenControl(t, ca)
		dao14Eventually(t, "A registered", func() bool { return ns.GetControlStream("n1") != nil })
		sA := ns.GetControlStream("n1")
		_, cb := f.dial(t)
		dao7Handshake(t, cb)
		streamB, cancelB := dao14OpenControl(t, cb)
		defer cancelB()
		dao14Eventually(t, "B registered", func() bool { s := ns.GetControlStream("n1"); return s != nil && s != sA })
		ns.TouchStats("n1")
		cancelA()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Fatal("A handler did not exit")
		}
		if ns.GetControlStream("n1") == nil || len(ns.ConnectedNodes()) != 1 || ns.ConnectedAt("n1").IsZero() || ns.LastStatsAt("n1").IsZero() {
			t.Fatalf("B state lost: stream=%v connected=%v connectedAt=%v lastStats=%v", ns.GetControlStream("n1"), ns.ConnectedNodes(), ns.ConnectedAt("n1"), ns.LastStatsAt("n1"))
		}
		if err := f.h.SendConfigPush("n1", &pb.WatchConfig{}, 7); err != nil {
			t.Fatal(err)
		}
		m, err := streamB.Recv()
		if err != nil || m.GetConfigPush().GetDeliveryVersionCurrent() != 7 {
			t.Fatalf("B recv=%v err=%v", m, err)
		}
	})
	t.Run("G5b_SingleCloseClears", func(t *testing.T) {
		f := newF(t)
		ns := f.h.nodeState
		_, ca := f.dial(t)
		dao7Handshake(t, ca)
		_, cancelA := dao14OpenControl(t, ca)
		dao14Eventually(t, "A registered", func() bool { return ns.GetControlStream("n1") != nil })
		ns.TouchStats("n1")
		cancelA()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Fatal("A handler did not exit")
		}
		if ns.GetControlStream("n1") != nil || len(ns.ConnectedNodes()) != 0 || !ns.ConnectedAt("n1").IsZero() || !ns.LastStatsAt("n1").IsZero() {
			t.Fatal("single close did not clear")
		}
		_, cb := f.dial(t)
		dao7Handshake(t, cb)
		_, cancelB := dao14OpenControl(t, cb)
		defer cancelB()
		dao14Eventually(t, "B registered after A closed", func() bool { return ns.GetControlStream("n1") != nil })
		if ns.ConnectedAt("n1").IsZero() {
			t.Fatal("B has no connected time")
		}
	})
}

// ---- G6a ----

type dao14ACK struct {
	method string
	id     string
	v      int64
}

type dao14Nodes struct {
	dao7Nodes
	mu       sync.Mutex
	calls    []dao14ACK
	markErr  error
	returned []error
}

func (r *dao14Nodes) UpdateACK(_ context.Context, id string, v int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, dao14ACK{"UpdateACK", id, v})
	return nil
}

// MarkConfigFailed is defined even on the baseline, where it is not part of NodeRepo.
func (r *dao14Nodes) MarkConfigFailed(_ context.Context, id string, v int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, dao14ACK{"MarkConfigFailed", id, v})
	r.returned = append(r.returned, r.markErr)
	return r.markErr
}

func (r *dao14Nodes) snapshot() []dao14ACK {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]dao14ACK(nil), r.calls...)
}

type dao14Store struct {
	dao7Store
	nodes *dao14Nodes
}

func (s *dao14Store) Nodes() store.NodeRepo { return s.nodes }

func dao14ACKFixture(t *testing.T, nodes *dao14Nodes) pb.XSightServiceClient {
	t.Helper()
	lis := &dao7Listener{Listener: bufconn.Listen(1 << 20)}
	h := NewGRPCHandler(GRPCHandlerConfig{Store: &dao14Store{nodes: nodes}, NodeState: NewNodeState()})
	srv := grpc.NewServer()
	pb.RegisterXSightServiceServer(srv, h)
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.Stop(); <-done })
	f := &dao7Fixture{lis: lis}
	_, c := f.dial(t)
	return c
}

func dao14SendACKs(t *testing.T, c pb.XSightServiceClient, handshake bool, acks ...*pb.ConfigAck) pb.XSightService_ControlStreamClient {
	t.Helper()
	if handshake {
		dao7Handshake(t, c)
	}
	s, cancel := dao14OpenControl(t, c)
	t.Cleanup(cancel)
	for _, a := range acks {
		if err := s.Send(&pb.ControlMessage{Payload: &pb.ControlMessage_ConfigAck{ConfigAck: a}}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func TestDao14a2_G6a(t *testing.T) {
	barrier := &pb.ConfigAck{DeliveryVersionApplied: 91, Success: true}
	waitBarrier := func(t *testing.T, n *dao14Nodes) []dao14ACK {
		dao14Eventually(t, "barrier ACK", func() bool {
			for _, c := range n.snapshot() {
				if c.method == "UpdateACK" && c.v == 91 {
					return true
				}
			}
			return false
		})
		return n.snapshot()
	}
	t.Run("FailureCallsMark", func(t *testing.T) { // behaviour
		n := &dao14Nodes{}
		c := dao14ACKFixture(t, n)
		dao14SendACKs(t, c, true, &pb.ConfigAck{DeliveryVersionApplied: 88, ErrorMessage: "no space"}, &pb.ConfigAck{DeliveryVersionApplied: 91, ErrorMessage: "no space"}, barrier)
		got := waitBarrier(t, n)
		want := []dao14ACK{{"MarkConfigFailed", "n1", 88}, {"MarkConfigFailed", "n1", 91}, {"UpdateACK", "n1", 91}}
		if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
			t.Fatalf("calls=%v want %v", got, want)
		}
	})
	t.Run("SuccessOnlyNoMark", func(t *testing.T) { // guard
		n := &dao14Nodes{}
		c := dao14ACKFixture(t, n)
		dao14SendACKs(t, c, true, &pb.ConfigAck{DeliveryVersionApplied: 88, Success: true}, barrier)
		for _, x := range waitBarrier(t, n) {
			if x.method == "MarkConfigFailed" {
				t.Fatalf("MarkConfigFailed called: %v", x)
			}
		}
	})
	t.Run("MarkErrorKeepsReading", func(t *testing.T) { // behaviour: Mark must be called AND returned the injected error
		n := &dao14Nodes{markErr: errors.New("injected")}
		c := dao14ACKFixture(t, n)
		dao14SendACKs(t, c, true, &pb.ConfigAck{DeliveryVersionApplied: 88}, barrier)
		got := waitBarrier(t, n)
		n.mu.Lock()
		returned := append([]error(nil), n.returned...)
		n.mu.Unlock()
		if len(returned) != 1 || returned[0] != n.markErr {
			t.Errorf("returned=%v want injected error", returned)
		}
		if len(got) != 2 || got[0] != (dao14ACK{"MarkConfigFailed", "n1", 88}) || got[1] != (dao14ACK{"UpdateACK", "n1", 91}) {
			t.Fatalf("calls=%v: MarkConfigFailed(88) returning the injected error must precede the barrier", got)
		}
	})
	t.Run("UnknownPeerNoCalls", func(t *testing.T) { // guard
		n := &dao14Nodes{}
		c := dao14ACKFixture(t, n)
		s := dao14SendACKs(t, c, false, &pb.ConfigAck{DeliveryVersionApplied: 88}, barrier)
		// Barrier: half-close; the handler returns only after it has consumed every message.
		if err := s.CloseSend(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Recv(); err != io.EOF {
			t.Fatalf("recv after CloseSend = %v, want io.EOF", err)
		}
		if got := n.snapshot(); len(got) != 0 {
			t.Fatalf("calls=%v want none", got)
		}
	})
}
func dao14Function(t *testing.T, path, name string) *ast.FuncDecl {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("function %s absent in %s", name, path)
	return nil
}

func TestDao14a2_G5s(t *testing.T) {
	t.Run("AtomicCompareDelete", func(t *testing.T) {
		fn := dao14Function(t, "node_state.go", "ClearControlStream")
		var params []*ast.Ident
		for _, f := range fn.Type.Params.List {
			params = append(params, f.Names...)
		}
		if len(params) != 2 {
			t.Fatalf("ClearControlStream parameters=%d want 2", len(params))
		}
		locks, rlocks := 0, 0
		var lockPos, deletePos, guardPos token.Pos
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if s, ok := c.Fun.(*ast.SelectorExpr); ok {
					if mu, ok := s.X.(*ast.SelectorExpr); ok && mu.Sel.Name == "mu" {
						if recv, ok := mu.X.(*ast.Ident); ok && recv.Name == "ns" {
							switch s.Sel.Name {
							case "Lock":
								locks++
								lockPos = c.Pos()
							case "RLock":
								rlocks++
							}
						}
					}
				}
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "delete" && (deletePos == 0 || c.Pos() < deletePos) {
					deletePos = c.Pos()
				}
			}
			if i, ok := n.(*ast.IfStmt); ok {
				if b, ok := i.Cond.(*ast.BinaryExpr); ok && b.Op == token.NEQ {
					index, ok := b.X.(*ast.IndexExpr)
					if !ok {
						return true
					}
					sel, ok := index.X.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "controlStream" {
						return true
					}
					recv, ok := sel.X.(*ast.Ident)
					if !ok || recv.Name != "ns" {
						return true
					}
					key, kok := index.Index.(*ast.Ident)
					arg, aok := b.Y.(*ast.Ident)
					if kok && aok && key.Obj == params[0].Obj && arg.Obj == params[1].Obj {
						guardPos = i.Pos()
					}
				}
			}
			return true
		})
		if locks != 1 || rlocks != 0 || guardPos <= lockPos || deletePos <= guardPos {
			t.Fatalf("locks=%d rlocks=%d positions lock=%d guard=%d delete=%d", locks, rlocks, lockPos, guardPos, deletePos)
		}
	})
	t.Run("DeferUsesOwnStream", func(t *testing.T) {
		fn := dao14Function(t, "grpc_handler.go", "ControlStream")
		param := fn.Type.Params.List[0].Names[0]
		sets, clears := 0, 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "SetControlStream" {
					if len(c.Args) == 2 {
						if id, ok := c.Args[1].(*ast.Ident); ok && id.Name == "stream" && id.Obj == param.Obj {
							sets++
						}
					}
				}
			}
			if d, ok := n.(*ast.DeferStmt); ok {
				ast.Inspect(d.Call, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "ClearControlStream" {
							if len(c.Args) == 2 {
								if id, ok := c.Args[1].(*ast.Ident); ok && id.Name == "stream" && id.Obj == param.Obj {
									clears++
								}
							}
						}
					}
					return true
				})
			}
			return true
		})
		if sets != 1 || clears != 1 {
			t.Fatalf("own stream arguments: Set=%d deferred Clear=%d want 1/1", sets, clears)
		}
	})
}
