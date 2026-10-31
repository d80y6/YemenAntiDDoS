package configpub

import (
	"context"
	"errors"
	"reflect"
	"testing"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao14PublishNodes struct {
	store.NodeRepo
	pending []int64
	failed  []int64
}

func (n *dao14PublishNodes) List(context.Context) ([]store.Node, error) {
	return []store.Node{{ID: "n1", Enabled: true, Mode: "xdp", DeliveryVersionCurrent: 87}}, nil
}
func (n *dao14PublishNodes) UpdateDeliveryVersionCurrent(_ context.Context, id string, v int64) error {
	if id != "n1" {
		return errors.New("unexpected node")
	}
	n.pending = append(n.pending, v)
	return nil
}
func (n *dao14PublishNodes) MarkConfigFailed(_ context.Context, _ string, v int64) error {
	n.failed = append(n.failed, v)
	return nil
}

type dao14PublishAudit struct{ store.AuditLogRepo }

func (dao14PublishAudit) Create(context.Context, *store.AuditLog) error { return nil }

type dao14PublishStore struct {
	*dao3PushStore
	nodes *dao14PublishNodes
}

func (s *dao14PublishStore) Nodes() store.NodeRepo        { return s.nodes }
func (s *dao14PublishStore) AuditLog() store.AuditLogRepo { return dao14PublishAudit{} }

type dao14Pusher struct {
	err   error
	calls int
}

func (p *dao14Pusher) SendConfigPush(string, *pb.WatchConfig, uint64) error { p.calls++; return p.err }

func TestDao14a2_G6c(t *testing.T) {
	counts := make([]int, 2)
	for i, fail := range []bool{false, true} {
		n := &dao14PublishNodes{}
		s := &dao14PublishStore{dao3PushStore: &dao3PushStore{}, nodes: n}
		push := &dao14Pusher{}
		if fail {
			push.err = errors.New("injected send failure")
		}
		p := New(s, push, func() []string { return []string{"n1"} })
		v, err := p.Publish(context.Background(), nil, "prefix", "1", "update", nil)
		if err != nil || v != 88 || push.calls != 1 {
			t.Fatalf("fail=%v version=%d err=%v pushes=%d", fail, v, err, push.calls)
		}
		if len(n.failed) != 0 {
			t.Errorf("send failure=%v MarkConfigFailed calls=%v want none", fail, n.failed)
		}
		want := []int64{88}
		if fail {
			want = append(want, 88)
		}
		if !reflect.DeepEqual(n.pending, want) {
			t.Errorf("send failure=%v pending=%v want %v", fail, n.pending, want)
		}
		counts[i] = len(n.pending)
	}
	if counts[1] != counts[0]+1 {
		t.Errorf("pending updates: success=%d failure=%d", counts[0], counts[1])
	}
}
