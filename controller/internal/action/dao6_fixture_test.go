package action

import (
	"context"
	"net"
	"sync"

	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/engine/dedup"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

type dao6Barrier struct {
	entered, release       chan struct{}
	enterOnce, releaseOnce sync.Once
}

func dao6NewBarrier() *dao6Barrier {
	return &dao6Barrier{entered: make(chan struct{}), release: make(chan struct{})}
}
func (b *dao6Barrier) wait() { b.enterOnce.Do(func() { close(b.entered) }); <-b.release }
func (b *dao6Barrier) open() { b.releaseOnce.Do(func() { close(b.release) }) }

// All writes after fixture seeding go through methods holding mu6 (or the
// embedded v3Store's mutex); barriers never hold a repository mutex.
type dao6Store struct {
	*v3Store
	mu6                   sync.Mutex
	rows                  map[int]store.Attack
	calls, cancels        []int
	responseGate, getGate *dao6Barrier
	blockedResponse       int
	disabledResponse      bool
	globals               []store.WebhookConnector
}

func dao6NewStore() *dao6Store {
	return &dao6Store{v3Store: newV3Store(""), rows: make(map[int]store.Attack)}
}

type dao6Responses struct {
	store.ResponseRepo
	s *dao6Store
}
type dao6Attacks struct {
	store.AttackRepo
	s *dao6Store
}
type dao6Schedules struct {
	store.ScheduledActionRepo
	s *dao6Store
}
type dao6Globals struct {
	store.WebhookConnectorRepo
	s *dao6Store
}

func (s *dao6Store) Responses() store.ResponseRepo {
	return dao6Responses{v3Responses{s: s.v3Store}, s}
}
func (s *dao6Store) Attacks() store.AttackRepo                     { return dao6Attacks{s: s} }
func (s *dao6Store) ScheduledActions() store.ScheduledActionRepo   { return dao6Schedules{s: s} }
func (s *dao6Store) WebhookConnectors() store.WebhookConnectorRepo { return dao6Globals{s: s} }
func (r dao6Responses) Get(_ context.Context, id int) (*store.Response, error) {
	r.s.mu6.Lock()
	r.s.calls = append(r.s.calls, id)
	b, blocked, disabled := r.s.responseGate, r.s.blockedResponse, r.s.disabledResponse
	r.s.mu6.Unlock()
	if b != nil && id == blocked {
		b.wait()
	}
	return &store.Response{ID: id, Enabled: !disabled}, nil
}
func dao6Copy(a store.Attack) store.Attack {
	a.NodeSources = append([]string(nil), a.NodeSources...)
	a.ReasonCodes = append([]string(nil), a.ReasonCodes...)
	if a.ResponseID != nil {
		v := *a.ResponseID
		a.ResponseID = &v
	}
	return a
}
func (r dao6Attacks) Create(_ context.Context, a *store.Attack) (int, error) {
	r.s.mu6.Lock()
	defer r.s.mu6.Unlock()
	v := dao6Copy(*a)
	v.ID = len(r.s.rows) + 1
	r.s.rows[v.ID] = v
	return v.ID, nil
}
func (r dao6Attacks) Update(_ context.Context, a *store.Attack) error {
	r.s.mu6.Lock()
	defer r.s.mu6.Unlock()
	v := r.s.rows[a.ID]
	v.EndedAt = a.EndedAt
	v.ReasonCodes = append([]string(nil), a.ReasonCodes...)
	r.s.rows[a.ID] = v
	return nil
}
func (r dao6Attacks) Get(_ context.Context, id int) (*store.Attack, error) {
	r.s.mu6.Lock()
	v := dao6Copy(r.s.rows[id])
	b := r.s.getGate
	r.s.mu6.Unlock()
	if b != nil && v.EndedAt != nil {
		b.wait()
	}
	return &v, nil
}
func (r dao6Schedules) CancelAllForAttack(_ context.Context, id int, _ string) (int, error) {
	r.s.mu6.Lock()
	defer r.s.mu6.Unlock()
	r.s.cancels = append(r.s.cancels, id)
	return 0, nil
}
func (r dao6Globals) ListGlobal(context.Context) ([]store.WebhookConnector, error) {
	r.s.mu6.Lock()
	defer r.s.mu6.Unlock()
	return append([]store.WebhookConnector(nil), r.s.globals...), nil
}
func (s *dao6Store) snapshots() ([]int, []int) {
	s.mu6.Lock()
	defer s.mu6.Unlock()
	return append([]int(nil), s.calls...), append([]int(nil), s.cancels...)
}
func dao6Event(id int) tracker.AttackEvent {
	return tracker.AttackEvent{Type: "confirmed", DBID: id, Attack: &store.Attack{ID: id, DstIP: "192.0.2.10", ResponseID: &id}}
}
func dao6Threshold(ip string) []engine.ThresholdExceeded {
	rid := 1
	return []engine.ThresholdExceeded{{DstIP: net.ParseIP(ip), Prefix: "192.0.2.0/24", Direction: "receives", Decoder: "udp", Unit: "pps", Actual: 20000, ResponseID: &rid, NodeID: "n1"}}
}
func dao6Tracker(s store.Store, cb tracker.ActionCallback) *tracker.Tracker {
	return tracker.New(tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 300}, s, nil, dedup.New(), cb)
}
