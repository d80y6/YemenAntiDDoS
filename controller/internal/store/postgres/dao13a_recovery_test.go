package postgres

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/engine/dedup"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
)

type dao13aCountingStore struct {
	store.Store
	creates int
}
type dao13aCountingAttacks struct {
	store.AttackRepo
	s *dao13aCountingStore
}

func (s *dao13aCountingStore) Attacks() store.AttackRepo {
	return dao13aCountingAttacks{s.Store.Attacks(), s}
}
func (r dao13aCountingAttacks) Create(ctx context.Context, a *store.Attack) (int, error) {
	r.s.creates++
	return r.AttackRepo.Create(ctx, a)
}

func TestDao13a_B3_PostgresRecovery(t *testing.T) {
	s := newPostgresContractBackend(t).Store()
	ctx := context.Background()
	started := time.Now().Add(-time.Hour).Truncate(time.Microsecond)
	id, err := s.Attacks().Create(ctx, &store.Attack{
		DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: "udp", AttackType: "udp_flood",
		Severity: "medium", Confidence: .9, StartedAt: started, ReasonCodes: []string{"udp_exceeded"}, NodeSources: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.Attacks().ListActive(ctx, 1000)
	if err != nil || len(rows) != 1 {
		t.Fatalf("ListActive rows=%v err=%v", rows, err)
	}
	t.Logf("ListActive raw dst_ip=%q", rows[0].DstIP)
	if rows[0].DstIP != "192.0.2.10/32" {
		t.Fatalf("PostgreSQL inet text premise differs: %q", rows[0].DstIP)
	}
	counted := &dao13aCountingStore{Store: s}
	d := dedup.New()
	confirmed := 0
	tk := tracker.New(tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 10, MaxActiveAttacks: 8}, counted, nil, d,
		func(e tracker.AttackEvent) {
			if e.Type == "confirmed" {
				confirmed++
			}
		})
	if err := tk.RecoverFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	if !time.Now().After(started) {
		t.Fatal("live FirstSeen would not be later than the seed")
	}
	row := engine.ThresholdExceeded{DstIP: net.ParseIP("192.0.2.10"), Decoder: "udp", Direction: "receives", Unit: "pps", Actual: 20000}
	for i := 0; i < 3; i++ {
		var filtered []engine.ThresholdExceeded
		if !d.ShouldSuppress(row) {
			filtered = append(filtered, row)
		}
		tk.Feed(filtered)
	}
	timers := tk.ActiveTimers()
	if counted.creates != 0 || confirmed != 0 || tk.ActiveCount() != 1 || len(timers) != 1 || timers[id].State != tracker.StateActive {
		t.Fatalf("creates=%d confirmed=%d active=%d timers=%v original ID=%d", counted.creates, confirmed, tk.ActiveCount(), timers, id)
	}
	rows, err = s.Attacks().ListActive(ctx, 1000)
	if err != nil || len(rows) != 1 || rows[0].ID != id {
		t.Fatalf("database identity changed: rows=%v err=%v", rows, err)
	}
}
