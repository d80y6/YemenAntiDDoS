package ingestion

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao14d1WatchStore struct {
	store.Store
	thresholdError                             error
	rows                                       []store.Threshold
	nodeLists, versions, modes, audits, pushes int
}
type dao14d1WatchPrefixes struct{ store.PrefixRepo }
type dao14d1WatchThresholds struct {
	store.ThresholdRepo
	s *dao14d1WatchStore
}
type dao14d1WatchNodes struct {
	store.NodeRepo
	s *dao14d1WatchStore
}
type dao14d1WatchAudit struct {
	store.AuditLogRepo
	s *dao14d1WatchStore
}
type dao14d1WatchListeners struct{ store.FlowListenerRepo }

func (s *dao14d1WatchStore) Prefixes() store.PrefixRepo            { return dao14d1WatchPrefixes{} }
func (s *dao14d1WatchStore) Thresholds() store.ThresholdRepo       { return dao14d1WatchThresholds{s: s} }
func (s *dao14d1WatchStore) Nodes() store.NodeRepo                 { return dao14d1WatchNodes{s: s} }
func (s *dao14d1WatchStore) AuditLog() store.AuditLogRepo          { return dao14d1WatchAudit{s: s} }
func (s *dao14d1WatchStore) FlowListeners() store.FlowListenerRepo { return dao14d1WatchListeners{} }
func (dao14d1WatchPrefixes) List(context.Context) ([]store.WatchPrefix, error) {
	return []store.WatchPrefix{{ID: 1, Prefix: "192.0.2.0/24", Enabled: true}}, nil
}
func (r dao14d1WatchThresholds) List(context.Context) ([]store.Threshold, error) {
	return r.s.rows, r.s.thresholdError
}
func (r dao14d1WatchNodes) List(context.Context) ([]store.Node, error) {
	r.s.nodeLists++
	return []store.Node{{ID: "n1", Enabled: true, Mode: "xdp", DeliveryVersionCurrent: 1}}, nil
}
func (r dao14d1WatchNodes) Get(context.Context, string) (*store.Node, error) {
	return &store.Node{ID: "n1", APIKey: "k", Enabled: true, Mode: "xdp", DeliveryVersionCurrent: 1}, nil
}
func (r dao14d1WatchNodes) UpdateDeliveryVersionCurrent(context.Context, string, int64) error {
	r.s.versions++
	return nil
}
func (r dao14d1WatchNodes) UpdateMode(context.Context, string, string) error { r.s.modes++; return nil }
func (r dao14d1WatchAudit) Create(context.Context, *store.AuditLog) error    { r.s.audits++; return nil }
func (dao14d1WatchListeners) List(context.Context, string) ([]store.FlowListener, error) {
	return nil, nil
}
func (s *dao14d1WatchStore) SendConfigPush(string, *pb.WatchConfig, uint64) error {
	s.pushes++
	return nil
}

func TestDao14d1_G8(t *testing.T) {
	marker := errors.New("MARKER-thresholds")
	t.Run("Build", func(t *testing.T) {
		s := &dao14d1WatchStore{thresholdError: marker}
		cfg, err := NewGRPCHandler(GRPCHandlerConfig{Store: s}).buildWatchConfig(context.Background())
		if cfg != nil || !errors.Is(err, marker) || !strings.Contains(err.Error(), "load thresholds") {
			t.Errorf("config=%+v error=%v; want nil config and wrapped threshold error", cfg, err)
		}
	})

	t.Run("Handshake", func(t *testing.T) {
		s := &dao14d1WatchStore{thresholdError: marker}
		response, err := NewGRPCHandler(GRPCHandlerConfig{Store: s}).Handshake(context.Background(), &pb.NodeHandshake{NodeId: "n1", ApiKey: "k"})
		if err != nil {
			t.Fatal(err)
		}
		if response.Accepted || !strings.Contains(response.RejectReason, "load thresholds") {
			t.Errorf("handshake=%+v; want rejection identifying threshold load", response)
		}
		if s.modes != 0 || s.versions != 0 || s.audits != 0 || s.pushes != 0 {
			t.Errorf("after build failure: modes=%d versions=%d audits=%d pushes=%d; want all zero", s.modes, s.versions, s.audits, s.pushes)
		}
	})

	for _, name := range []string{"HappyPath", "Ctl_SinglePPS"} {
		t.Run(name, func(t *testing.T) {
			s := &dao14d1WatchStore{rows: []store.Threshold{
				{Enabled: true, Comparison: "over", Domain: "internal_ip", Unit: "pps", Value: 9000},
				{Enabled: true, Comparison: "over", Domain: "internal_ip", Unit: "pps", Value: 5000},
				{Enabled: true, Comparison: "over", Domain: "internal_ip", Unit: "bps", Value: 80000000},
			}}
			if name == "Ctl_SinglePPS" {
				s.rows = s.rows[1:]
			}
			cfg, err := NewGRPCHandler(GRPCHandlerConfig{Store: s}).buildWatchConfig(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if cfg == nil || cfg.HardThresholds == nil {
				t.Fatal("missing watch configuration")
			}
			if cfg.HardThresholds.Pps != 5000 || cfg.HardThresholds.Bps != 80000000 {
				t.Errorf("hard thresholds=%+v; want pps=5000 bps=80000000", cfg.HardThresholds)
			}
		})
	}
}
