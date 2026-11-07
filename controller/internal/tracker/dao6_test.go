package tracker

import (
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

type dao6Store struct {
	store.Store
	mu   sync.Mutex
	next int
}
type dao6Repo struct {
	store.AttackRepo
	s *dao6Store
}

func (s *dao6Store) Attacks() store.AttackRepo { return dao6Repo{s: s} }
func (r dao6Repo) Create(context.Context, *store.Attack) (int, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.next++
	return r.s.next, nil
}
func (r dao6Repo) Update(context.Context, *store.Attack) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return nil
}
func (r dao6Repo) Get(context.Context, int) (*store.Attack, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	return nil, errors.New("exercise tracker expiry fallback")
}
func dao6Threshold() []engine.ThresholdExceeded {
	rid := 7
	return []engine.ThresholdExceeded{{DstIP: net.ParseIP("192.0.2.10"), Prefix: "192.0.2.0/24", Direction: "receives", Decoder: "udp", Unit: "pps", Actual: 20000, ResponseID: &rid, NodeID: "n1"}}
}
func dao6New(cb ActionCallback) *Tracker {
	return New(Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 300}, &dao6Store{}, nil, dedup.New(), cb)
}

func TestDao6_T7_ReadersShareLock(t *testing.T) {
	for _, name := range []string{"ActiveCount", "ActiveDstIPs"} {
		t.Run(name, func(t *testing.T) {
			tk := dao6New(nil)
			done := make(chan struct{})
			tk.mu.RLock()
			go func() {
				if name == "ActiveCount" {
					tk.ActiveCount()
				} else {
					tk.ActiveDstIPs()
				}
				close(done)
			}()
			defer func() { tk.mu.RUnlock(); <-done }()
			for {
				select {
				case <-done:
					return
				default:
				}
				if !tk.mu.TryRLock() {
					t.Error("reader requested write lock while original read lock held")
					return
				}
				tk.mu.RUnlock()
				runtime.Gosched() // no timeout/iteration-count verdict and no fake-clock mutex wait
			}
		})
	}
}

func TestDao6_T4_EventOwnsSharedFields(t *testing.T) {
	for _, kind := range []string{"confirmed", "updated", "type_upgrade", "evicted", "expired"} {
		t.Run(kind, func(t *testing.T) {
			var got *store.Attack
			tk := dao6New(func(e AttackEvent) {
				if e.Type == kind {
					got = e.Attack
				}
			})
			tk.Feed(dao6Threshold())
			tk.mu.Lock()
			var a *trackedAttack
			for _, v := range tk.attacks {
				a = v
			}
			switch kind {
			case "updated":
				tk.lastPeriodicUpdate = time.Now().Add(-6 * time.Minute)
				tk.tick(time.Now())
			case "evicted":
				tk.evictAttack(a, time.Now())
			case "expired":
				tk.transitionToExpired(a, time.Now())
			}
			tk.mu.Unlock()
			if kind == "type_upgrade" {
				tk.UpgradeType(net.ParseIP(a.Key.DstIP), "dns_amp", 0.95, []string{"classified"})
			}
			if got == nil {
				t.Fatal("expected event not emitted")
			}
			wantNodes := append([]string(nil), got.NodeSources...)
			wantReasons := append([]string(nil), got.ReasonCodes...)
			wantResponse := *got.ResponseID
			tk.mu.Lock()
			a.NodeSources[0] = "changed"
			a.ReasonCodes[0] = "changed"
			*a.ResponseID = 99
			tk.mu.Unlock()
			if !reflect.DeepEqual(got.NodeSources, wantNodes) || !reflect.DeepEqual(got.ReasonCodes, wantReasons) || *got.ResponseID != wantResponse {
				t.Errorf("event shares tracker fields: nodes=%v reasons=%v response=%d", got.NodeSources, got.ReasonCodes, *got.ResponseID)
			}
		})
	}
}

func TestDao6_T3_FeedCallbackOrder(t *testing.T) {
	var got []string
	tk := dao6New(func(e AttackEvent) { got = append(got, e.Type) })
	tk.SetRebreachCallback(func(int) { got = append(got, "rebreach") })
	tk.lastPeriodicUpdate = time.Now().Add(-6 * time.Minute)
	tk.Feed(dao6Threshold()) // one Feed: confirmed then updated
	tk.Feed(nil)
	tk.mu.Lock()
	tk.lastPeriodicUpdate = time.Now().Add(-6 * time.Minute)
	tk.mu.Unlock()
	tk.Feed(dao6Threshold()) // one Feed: rebreach then updated
	if want := []string{"confirmed", "updated", "rebreach", "updated"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("callbacks=%v want=%v", got, want)
	}
}

func TestDao6_T5_CallbackLockOwnership(t *testing.T) {
	for _, kind := range []string{"confirmed", "updated", "type_upgrade", "evicted", "expired_feed", "expired_force", "rebreach", "notify"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			tk := dao6New(nil)
			probe := func() {
				calls++
				unlocked := tk.mu.TryLock()
				if unlocked {
					tk.mu.Unlock()
				}
				if unlocked != (kind == "notify") {
					t.Errorf("callback TryLock=%v want %v", unlocked, kind == "notify")
				}
			}
			tk.onAction = func(e AttackEvent) {
				if e.Type == kind || e.Type == "expired" && (kind == "expired_feed" || kind == "expired_force" || kind == "notify") {
					probe()
				}
			}
			tk.SetRebreachCallback(func(int) {
				if kind == "rebreach" {
					probe()
				}
			})
			tk.Feed(dao6Threshold())
			switch kind {
			case "updated":
				tk.mu.Lock()
				tk.lastPeriodicUpdate = time.Now().Add(-6 * time.Minute)
				tk.mu.Unlock()
				tk.Feed(dao6Threshold())
			case "type_upgrade":
				tk.UpgradeType(net.ParseIP("192.0.2.10"), "dns_amp", 0.95, nil)
			case "evicted":
				tk.mu.Lock()
				tk.cfg.MaxActiveAttacks = 1
				tk.mu.Unlock()
				rows := dao6Threshold()
				rows[0].DstIP = net.ParseIP("192.0.2.11")
				rows[0].Actual = 2000000
				tk.Feed(append(dao6Threshold(), rows...))
			case "expired_force":
				tk.ForceExpire(1)
			case "expired_feed":
				tk.Feed(nil)
				tk.mu.Lock()
				for _, a := range tk.attacks {
					a.ExpiresAt = time.Now().Add(-time.Second)
				}
				tk.mu.Unlock()
				tk.Feed(nil)
			case "rebreach":
				tk.Feed(nil)
				tk.Feed(dao6Threshold())
			case "notify":
				tk.NotifyExpired(&store.Attack{ID: 1})
			}
			if calls != 1 {
				t.Errorf("callback probes=%d want 1", calls)
			}
		})
	}
}

func TestEndedHookDoesNotBlockExpiry(t *testing.T) {
	tk := dao6New(nil)
	tk.Feed(dao6Threshold())

	release := make(chan struct{})
	started := make(chan struct{})
	tk.SetInlineMitigatorHook(func(int) {
		close(started)
		<-release
	})

	done := make(chan struct{})
	go func() { tk.ForceExpire(1); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ForceExpire blocked on the inline-withdrawal hook")
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("inline-withdrawal hook did not run")
	}
	close(release)
}
