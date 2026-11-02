package action

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type dao12hContractStore struct {
	*dao3BGPStore
	connectors    store.BGPConnectorRepo
	announcements store.BGPAnnouncementRepo
}

func (s dao12hContractStore) BGPConnectors() store.BGPConnectorRepo       { return s.connectors }
func (s dao12hContractStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.announcements }

type dao12hContextConnector struct {
	store.BGPConnectorRepo
	received           context.Context
	errAtGet           error
	calledAt, deadline time.Time
	hasDeadline        bool
}

func (r *dao12hContextConnector) Get(ctx context.Context, _ int) (*store.BGPConnector, error) {
	// Snapshot inside Get: the independent context is canceled on return.
	r.received, r.calledAt, r.errAtGet = ctx, time.Now(), ctx.Err()
	r.deadline, r.hasDeadline = ctx.Deadline()
	return nil, errors.New("contract connector lookup failure")
}

type dao12hStaleAnnouncement struct{ store.BGPAnnouncementRepo }

func (dao12hStaleAnnouncement) MarkAnnounced(context.Context, int, int) error {
	return store.ErrStaleAnnouncement
}

func TestDao12h_C1_IndependentContext(t *testing.T) {
	base, _, _ := dao3BGPFixture(t)
	conn := &dao12hContextConnector{BGPConnectorRepo: base.BGPConnectors()}
	s := dao12hContractStore{base, conn, base.BGPAnnouncements()}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	got := NewEngine(s, "auto").reconcileAnnouncing(parent, store.BGPAnnouncement{ID: 1, ConnectorID: 7})
	dao12bWant(t, "C1.CtxNotCanceled", conn.received != nil && conn.errAtGet == nil, conn.errAtGet)
	budget := conn.deadline.Sub(conn.calledAt)
	dao12bWant(t, "C1.Deadline30s", conn.hasDeadline && budget > 29*time.Second && budget <= 30*time.Second, budget)
	dao12bWant(t, "C1.ReturnsFalse", !got, got)
}

func TestDao12h_C2_StaleReturnsTrue(t *testing.T) {
	base, _, _ := dao3BGPFixture(t)
	path, _ := dao12bScript(t, `case "$2" in
"show running-config") printf 'router bgp 64512\n address-family ipv4 unicast\n  network 192.0.2.10/32 route-map RTBH\n exit-address-family\n';;
"show bgp ipv4 unicast json") printf '%s\n' '{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}';;
*) exit 3;;
esac`)
	base.conn.VtyshPath = path
	s := dao12hContractStore{base, base.BGPConnectors(), dao12hStaleAnnouncement{base.BGPAnnouncements()}}
	counter := func(outcome string) float64 {
		return testutil.ToFloat64(metrics.BGPAnnouncingReconcile.WithLabelValues(outcome))
	}
	stale, failed := counter("stale"), counter("state_write_error")
	got := NewEngine(s, "auto").reconcileAnnouncing(context.Background(), store.BGPAnnouncement{ID: 1, ConnectorID: 7, Prefix: "192.0.2.10/32", RouteMap: "RTBH"})
	dao12bWant(t, "C2.ReturnsTrue", got, got)
	dao12bWant(t, "C2.StaleDelta", counter("stale")-stale == 1, counter("stale")-stale)
	dao12bWant(t, "C2.NoStateWriteError", counter("state_write_error")-failed == 0, counter("state_write_error")-failed)
}

func TestDao12h_C3_InvalidPrefix(t *testing.T) {
	ann := store.BGPAnnouncement{Prefix: "not-a-prefix", RouteMap: "RTBH"}
	config := "router bgp 64512\n address-family ipv4 unicast\n  network not-a-prefix route-map RTBH\n exit-address-family\n"
	rib := `{"routes":{"not-a-prefix":[{"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`
	dao12bWant(t, "C3.ConfigRejected", !announcingConfigContains(config, 64512, ann), config)
	present, err := announcingRIBContains(rib, ann.Prefix)
	dao12bWant(t, "C3.RIBRejected", !present && err == nil, []any{present, err})
	ann.Prefix = "192.0.2.10/32"
	config = "router bgp 64512\n address-family ipv4 unicast\n  network 192.0.2.10/32 route-map RTBH\n exit-address-family\n"
	rib = `{"routes":{"192.0.2.10/32":[{"weight":32768,"path":"","peerId":"(unspec)","nexthops":[{"ip":"0.0.0.0"}]}]}}`
	present, err = announcingRIBContains(rib, ann.Prefix)
	dao12bWant(t, "C3.PositiveControl", announcingConfigContains(config, 64512, ann) && present && err == nil, []any{present, err})
}
