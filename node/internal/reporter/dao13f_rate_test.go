package reporter

import (
	"context"
	"reflect"
	"testing"

	"github.com/littlewolf9527/xsight/node/internal/collector"
	"github.com/littlewolf9527/xsight/node/internal/pb"
	"github.com/littlewolf9527/xsight/node/internal/sampler"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// The fake streams exercise the production stream loops without sockets.
type dao13fStream[T any] struct {
	grpc.ClientStream
	send func(*T) error
}

func (s *dao13fStream[T]) Send(v *T) error { return s.send(v) }
func (s *dao13fStream[T]) SendMsg(v any) error {
	return s.send(v.(*T))
}
func (s *dao13fStream[T]) CloseAndRecv() (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}

type dao13fClient struct {
	pb.XSightServiceClient
	stats   *dao13fStream[pb.StatsReport]
	samples *dao13fStream[pb.SampleBatch]
}

func (c *dao13fClient) StatsStream(context.Context, ...grpc.CallOption) (pb.XSightService_StatsStreamClient, error) {
	return c.stats, nil
}

func (c *dao13fClient) SampleStream(context.Context, ...grpc.CallOption) (pb.XSightService_SampleStreamClient, error) {
	return c.samples, nil
}

func dao13fRates(t *testing.T, flow bool, rates []uint32) ([]uint32, uint32) {
	t.Helper()
	reports := make(chan *collector.Report, len(rates))
	for _, rate := range rates {
		reports <- &collector.Report{UpstreamRate: rate, SampleRate: 7}
	}
	close(reports)
	cfg := Config{NodeID: "dao13f", UpstreamRate: 1000}
	r := New(cfg, reports, nil)
	if flow {
		r = NewFlow(cfg, nil, nil)
	}
	var stats []uint32
	var sample uint32
	r.client = &dao13fClient{
		stats: &dao13fStream[pb.StatsReport]{send: func(v *pb.StatsReport) error {
			stats = append(stats, v.UpstreamSampleRate)
			return nil
		}},
		samples: &dao13fStream[pb.SampleBatch]{send: func(v *pb.SampleBatch) error {
			sample = v.UpstreamSampleRate
			return nil
		}},
	}
	if len(rates) != 0 {
		if err := r.runStatsStream(context.Background(), 0); err != nil {
			t.Fatal(err)
		}
	}
	r.batches <- []sampler.PacketSample{{PacketLength: 64}}
	close(r.batches)
	if err := r.runSampleStream(context.Background()); err != nil {
		t.Fatal(err)
	}
	return stats, sample
}

func TestDao13f_R1(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rates []uint32
		want  []uint32
	}{
		{"ZeroFallsBackToConfig", []uint32{0}, []uint32{1000}},
		{"StatsUsesReportRate", []uint32{10}, []uint32{10}},
		{"SampleFollowsLatestStats", []uint32{10, 20}, []uint32{10, 20}},
		{"QueuedReportKeepsItsRate", []uint32{3, 8, 2}, []uint32{3, 8, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats, sample := dao13fRates(t, false, tc.rates)
			if !reflect.DeepEqual(stats, tc.want) {
				t.Fatalf("Stats wire rates=%v, want %v", stats, tc.want)
			}
			if sample != tc.want[len(tc.want)-1] {
				t.Fatalf("Sample wire rate=%d, want latest Stats rate %d", sample, tc.want[len(tc.want)-1])
			}
		})
	}
	t.Run("SampleBeforeFirstStatsUsesConfig", func(t *testing.T) {
		for _, name := range []string{"New", "NewFlow"} {
			t.Run(name, func(t *testing.T) {
				stats, sample := dao13fRates(t, name == "NewFlow", nil)
				if len(stats) != 0 || sample != 1000 {
					t.Fatalf("Stats=%v Sample rate=%d, want no Stats and startup rate 1000", stats, sample)
				}
			})
		}
	})
}
