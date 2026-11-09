package action

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

type recoverAttackRepo struct {
	store.AttackRepo
	rows []store.Attack
}

func (r *recoverAttackRepo) ListAllActive(context.Context) ([]store.Attack, error) {
	return append([]store.Attack(nil), r.rows...), nil
}

type recoverStore struct {
	store.Store
	repo *recoverAttackRepo
}

func (s recoverStore) Attacks() store.AttackRepo { return s.repo }

func TestRecoveredAttackIsReconciled(t *testing.T) {
	pusher := newRecordingPusher("edge-a")
	m := NewInlineMitigator(testMitigatorConfig(time.Hour), nil)

	rows := []store.Attack{{
		ID:            42,
		DstIP:         "198.51.100.42",
		Direction:     "receives",
		DecoderFamily: "tcp_syn",
		AttackType:    "syn_flood",
		NodeSources:   []string{"edge-a"},
		PeakPPS:       123456,
		StartedAt:     time.Now().Add(-time.Minute),
	}}
	st := recoverStore{repo: &recoverAttackRepo{rows: rows}}
	tk := tracker.New(tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 300},
		st, nil, dedup.New(), nil)
	tk.SetRecoveredCallback(func(a *store.Attack) {
		m.Recover(a.ID, a.DstIP, a.DecoderFamily, a.AttackType, a.NodeSources, uint64(a.PeakPPS))
	})

	if err := tk.RecoverFromDB(context.Background()); err != nil {
		t.Fatalf("RecoverFromDB: %v", err)
	}

	// A Node reconnecting after the restart must receive the recovered rules,
	// not an empty snapshot that silently lifts the mitigation.
	m.SetPusher(pusher)
	if err := m.Reconcile("edge-a"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	set := pusher.last("edge-a")
	if set == nil || len(set.Rules) == 0 {
		t.Fatalf("reconcile pushed %+v, want recovered rules", set)
	}
	found := false
	for _, r := range set.Rules {
		if net.IP(r.DstIp).String() == "198.51.100.42" {
			found = true
		}
	}
	if !found {
		t.Fatalf("rules %+v do not target recovered attack 42", set.Rules)
	}
}
