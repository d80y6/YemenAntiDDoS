package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/ingestion"
	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/shared/decoder"
)

type dao14PGLike struct {
	store.StatsRepo
	mu    sync.Mutex
	rows  []store.StatPoint
	fails int
}

func (p *dao14PGLike) BulkInsert(_ context.Context, pts []store.StatPoint) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, sp := range pts {
		if sp.Prefix != nil {
			pf, err := netip.ParsePrefix(*sp.Prefix)
			if err != nil || pf != pf.Masked() {
				p.fails++
				return errors.New("bad cidr " + *sp.Prefix)
			}
		}
		if sp.DstIP != nil {
			if _, err := netip.ParseAddr(*sp.DstIP); err != nil {
				p.fails++
				return errors.New("bad inet " + *sp.DstIP)
			}
		}
	}
	p.rows = append(p.rows, pts...)
	return nil
}

func (p *dao14PGLike) count(node, prefix string) (n int, last int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.rows {
		if r.NodeID == node && (prefix == "" || (r.Prefix != nil && *r.Prefix == prefix)) {
			n++
			last = r.PPS
		}
	}
	return
}

var dao14LegalPrefix = &pb.PrefixStatsMsg{Prefix: []byte{198, 51, 100, 0}, PrefixLen: 24, PktCount: 5}

func dao14BadReports() map[string]*pb.StatsReport {
	p := func(raw []byte, l uint32) []*pb.PrefixStatsMsg {
		return []*pb.PrefixStatsMsg{{Prefix: raw, PrefixLen: l, PktCount: 1}, dao14LegalPrefix}
	}
	ip := []*pb.IPStats{{DstIp: []byte{192, 0, 2}, PktCount: 1}}
	return map[string]*pb.StatsReport{
		"InLen3": {PrefixStats: p([]byte{192, 0, 2}, 24)}, "InLen33": {PrefixStats: p([]byte{192, 0, 2, 0}, 33)},
		"InHost": {PrefixStats: p([]byte{192, 0, 2, 5}, 24)}, "InIP3": {PrefixStats: p([]byte{198, 51, 100, 0}, 24)[1:], IpStats: ip},
		"OutLen3": {SrcPrefixStats: p([]byte{192, 0, 2}, 24)}, "OutLen33": {SrcPrefixStats: p([]byte{192, 0, 2, 0}, 33)},
		"OutHost": {SrcPrefixStats: p([]byte{192, 0, 2, 5}, 24)}, "OutIP3": {SrcPrefixStats: p([]byte{198, 51, 100, 0}, 24)[1:], SrcIpStats: ip},
	}
}

func TestDao14a2_G1b(t *testing.T) {
	for name, r := range dao14BadReports() {
		t.Run(name, func(t *testing.T) {
			pts := reportToStatPoints("bad", r)
			if len(pts) != 1 || pts[0].Prefix == nil || *pts[0].Prefix != "198.51.100.0/24" {
				var got []string
				for _, p := range pts {
					if p.Prefix != nil {
						got = append(got, *p.Prefix)
					}
					if p.DstIP != nil {
						got = append(got, "ip:"+*p.DstIP)
					}
				}
				t.Errorf("points=%v want only 198.51.100.0/24", got)
			}
		})
	}
}

func TestDao14a2_G1c(t *testing.T) {
	for _, c := range []struct {
		name       string
		raw, ip    []byte
		cidr, addr string
		plen       uint32
	}{
		{"V4", []byte{192, 0, 2, 0}, []byte{192, 0, 2, 1}, "192.0.2.0/24", "192.0.2.1", 24},
		{"V6", net.ParseIP("2001:db8::"), net.ParseIP("2001:db8::1"), "2001:db8::/32", "2001:db8::1", 32},
		{"Mapped", net.ParseIP("::ffff:192.0.2.0"), net.ParseIP("::ffff:192.0.2.1"), "192.0.2.0/24", "192.0.2.1", 24},
	} {
		t.Run(c.name, func(t *testing.T) {
			ps := []*pb.PrefixStatsMsg{{Prefix: c.raw, PrefixLen: c.plen, PktCount: 2, ByteCount: 5, DecoderCounts: []uint32{1, 2, 3, 4, 5}, DecoderByteCounts: []uint64{2, 3, 4, 5, 6}}}
			ips := []*pb.IPStats{{DstIp: c.ip, PktCount: 2, ByteCount: 5, DecoderCounts: []uint32{1, 2, 3, 4, 5}, DecoderByteCounts: []uint64{2, 3, 4, 5, 6}}}
			r := &pb.StatsReport{Timestamp: 1, UpstreamSampleRate: 3, PrefixStats: ps, IpStats: ips, SrcPrefixStats: ps, SrcIpStats: ips}
			got := reportToStatPoints("n", r)
			var want []store.StatPoint
			for _, dir := range []string{"receives", "sends"} {
				p := store.StatPoint{Time: time.Unix(1, 0), NodeID: "n", Direction: dir, PPS: 6, BPS: 120}
				copy(p.DecoderPPS[:], []int32{3, 6, 9, 12, 15})
				copy(p.DecoderBPS[:], []int64{48, 72, 96, 120, 144})
				p.Prefix = &c.cidr
				want = append(want, p)
				p.Prefix = nil
				p.DstIP = &c.addr
				want = append(want, p)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("points=%+v want %+v", got, want)
			}
		})
	}
	t.Run("InboundFixedFallback", func(t *testing.T) {
		r := &pb.StatsReport{UpstreamSampleRate: 3, PrefixStats: []*pb.PrefixStatsMsg{{Prefix: []byte{192, 0, 2, 0}, PrefixLen: 24, TcpCount: 1, TcpSynCount: 2, UdpCount: 3, IcmpCount: 4, FragCount: 5}}, IpStats: []*pb.IPStats{{DstIp: []byte{192, 0, 2, 1}, TcpCount: 1, TcpSynCount: 2, UdpCount: 3, IcmpCount: 4, FragCount: 5}}}
		got := reportToStatPoints("n", r)
		if len(got) != 2 {
			t.Fatalf("points=%d", len(got))
		}
		for i, p := range got {
			for slot, v := range map[int]int32{decoder.TCP: 3, decoder.TCPSyn: 6, decoder.UDP: 9, decoder.ICMP: 12, decoder.Frag: 15} {
				if p.DecoderPPS[slot] != v {
					t.Errorf("point %d decoder %d=%d want %d", i, slot, p.DecoderPPS[slot], v)
				}
			}
		}
	})
}

func dao14RunWriter(t *testing.T, repo store.StatsRepo, feed func(w *ingestion.DBWriter)) {
	ctx, cancel := context.WithCancel(context.Background())
	w := ingestion.NewDBWriter(nil, repo, 5*time.Second)
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	synctest.Wait()
	feed(w)
	time.Sleep(16 * time.Second)
	synctest.Wait()
	cancel()
	<-done
}

func TestDao14a2_G1a(t *testing.T) {
	good := &pb.StatsReport{PrefixStats: []*pb.PrefixStatsMsg{{Prefix: []byte{203, 0, 113, 0}, PrefixLen: 24, PktCount: 5}}}
	for name, bad := range dao14BadReports() {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				repo := &dao14PGLike{}
				ctx, cancel := context.WithCancel(context.Background())
				w := ingestion.NewDBWriter(nil, repo, 5*time.Second)
				done := make(chan struct{})
				go func() { w.Run(ctx); close(done) }()
				defer func() { cancel(); <-done }()
				synctest.Wait()
				w.Enqueue(reportToStatPoints("good", good))
				time.Sleep(5 * time.Second)
				synctest.Wait()
				before, _ := repo.count("good", "")
				if before < 1 {
					t.Fatal("positive control did not flush")
				}
				w.Enqueue(reportToStatPoints("good", good))
				w.Enqueue(reportToStatPoints("bad", bad))
				for range 3 {
					time.Sleep(5 * time.Second)
					synctest.Wait()
				}

				g, _ := repo.count("good", "")
				b, _ := repo.count("bad", "198.51.100.0/24")
				if g-before < 1 || b < 1 || repo.fails != 0 {
					t.Errorf("good=%d badLegal=%d fails=%d", g, b, repo.fails)
				}
			})
		})
	}
}

func TestDao14a2_G1xDB(t *testing.T) {
	canon := &pb.PrefixStatsMsg{Prefix: []byte{192, 0, 2, 0}, PrefixLen: 24, PktCount: 1000}
	host := &pb.PrefixStatsMsg{Prefix: []byte{192, 0, 2, 5}, PrefixLen: 24, PktCount: 0}
	for _, out := range []bool{false, true} {
		for _, first := range []bool{true, false} {
			order := []*pb.PrefixStatsMsg{canon, host}
			if !first {
				order = []*pb.PrefixStatsMsg{host, canon}
			}
			name := map[bool]string{false: "in", true: "out"}[out] + map[bool]string{true: "/canonFirst", false: "/hostFirst"}[first]
			t.Run(name, func(t *testing.T) {
				r := &pb.StatsReport{Timestamp: 1}
				if out {
					r.SrcPrefixStats = order
				} else {
					r.PrefixStats = order
				}
				pts := reportToStatPoints("n", r)
				if len(pts) != 1 || pts[0].Prefix == nil || *pts[0].Prefix != "192.0.2.0/24" || pts[0].PPS != 1000 {
					t.Errorf("points: %d", len(pts))
				}
				synctest.Test(t, func(t *testing.T) {
					repo := &dao14PGLike{}
					dao14RunWriter(t, repo, func(w *ingestion.DBWriter) { w.Enqueue(pts) })
					if n, pps := repo.count("n", "192.0.2.0/24"); n != 1 || pps != 1000 || repo.fails != 0 {
						t.Errorf("rows=%d pps=%d fails=%d", n, pps, repo.fails)
					}
				})
			})
		}
	}
}

func TestDao14a2_G1bMixed(t *testing.T) {
	r := &pb.StatsReport{PrefixStats: []*pb.PrefixStatsMsg{{Prefix: []byte{192, 0, 2}, PrefixLen: 24}, dao14LegalPrefix}, IpStats: []*pb.IPStats{{DstIp: []byte{192, 0, 2}}, {DstIp: []byte{198, 51, 100, 1}}}, SrcPrefixStats: []*pb.PrefixStatsMsg{{Prefix: []byte{192, 0, 2, 5}, PrefixLen: 24}, dao14LegalPrefix}, SrcIpStats: []*pb.IPStats{{DstIp: []byte{192, 0, 2}}, {DstIp: []byte{198, 51, 100, 2}}}}
	pts := reportToStatPoints("n", r)
	var got []string
	for _, p := range pts {
		if p.Prefix != nil {
			got = append(got, fmt.Sprintf("%s:%s", p.Direction, *p.Prefix))
		}
		if p.DstIP != nil {
			got = append(got, fmt.Sprintf("%s:%s", p.Direction, *p.DstIP))
		}
	}
	want := []string{"receives:198.51.100.0/24", "receives:198.51.100.1", "sends:198.51.100.0/24", "sends:198.51.100.2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("points=%v want %v", got, want)
	}
}
