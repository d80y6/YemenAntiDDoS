package configpub

import (
	"context"
	"net"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao3PushStore struct {
	store.Store
	rows []store.WatchPrefix
}
type dao3PushPrefixes struct {
	store.PrefixRepo
	s *dao3PushStore
}
type dao3PushThresholds struct{ store.ThresholdRepo }

func (s *dao3PushStore) Prefixes() store.PrefixRepo      { return dao3PushPrefixes{s: s} }
func (s *dao3PushStore) Thresholds() store.ThresholdRepo { return dao3PushThresholds{} }
func (r dao3PushPrefixes) List(context.Context) ([]store.WatchPrefix, error) {
	return append([]store.WatchPrefix(nil), r.s.rows...), nil
}
func (dao3PushThresholds) List(context.Context) ([]store.Threshold, error) { return nil, nil }
func TestDao3_T5d_Publisher(t *testing.T) {
	s := &dao3PushStore{rows: []store.WatchPrefix{{Prefix: "::/0", Enabled: true}, {Prefix: "2001:db8::/32", Enabled: true}, {Prefix: "0.0.0.0/0", Enabled: true}}}
	p := New(s, nil, nil)
	cfg, err := p.buildWatchConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Prefixes) != 1 || cfg.Prefixes[0].PrefixLen != 32 || !net.IP(cfg.Prefixes[0].Prefix).Equal(net.ParseIP("2001:db8::")) {
		t.Fatalf("pushed prefixes=%v; want only 2001:db8::/32", cfg.Prefixes)
	}
}
