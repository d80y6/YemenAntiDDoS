package tests

import (
	"context"
	"strings"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao5bWorkerStore struct {
	*dao5BGPStore
	r *dao5bWorkerRepo
}

func (s *dao5bWorkerStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.r }

type dao5bWorkerRepo struct {
	store.BGPAnnouncementRepo
	mu   sync.Mutex
	gens []int
}

func (r *dao5bWorkerRepo) MarkWithdrawing(ctx context.Context, id, gen int) (bool, error) {
	r.mu.Lock()
	r.gens = append(r.gens, gen)
	r.mu.Unlock()
	return r.BGPAnnouncementRepo.MarkWithdrawing(ctx, id, gen)
}

type dao5bWorkerSchedules struct {
	store.ScheduledActionRepo
	done chan string
}

func (r dao5bWorkerSchedules) Complete(ctx context.Context, id int) error {
	err := r.ScheduledActionRepo.Complete(ctx, id)
	r.done <- "completed"
	return err
}
func (r dao5bWorkerSchedules) Fail(ctx context.Context, id int, msg string) error {
	err := r.ScheduledActionRepo.Fail(ctx, id, msg)
	r.done <- "failed: " + msg
	return err
}

// This control drives the real bgpWithdraw delay branch. The nonzero fixture
// makes the mandatory worker generation assertion sensitive to M10.
func TestDao5b_B4_SameGenerationDelayed(t *testing.T) {
	dao5bWorkerCase(t, "same")
}
func TestDao5b_B4a_ReattachedActive(t *testing.T)            { dao5bWorkerCase(t, "active") }
func TestDao5b_B4bPrime_NewerGenerationDelayed(t *testing.T) { dao5bWorkerCase(t, "new") }
func dao5bWorkerCase(t *testing.T, change string) {
	var generation, behavior func(*testing.T)
	synctest.Test(t, func(t *testing.T) {
		base, _, ev, conn, id := dao5BGPFixture(t, 1)
		base.bgpAnnouncements.mu.Lock()
		base.bgpAnnouncements.findByIDLocked(id).Gen = 7
		base.bgpAnnouncements.mu.Unlock()
		path, record := dao4Vtysh(t)
		conn.VtyshPath = path
		if err := base.BGPConnectors().Update(context.Background(), conn); err != nil {
			t.Fatal(err)
		}
		r := &dao5bWorkerRepo{BGPAnnouncementRepo: base.anns}
		s := &dao5bWorkerStore{dao5BGPStore: base, r: r}
		done := make(chan string, 1)
		base.setSchedules(dao5bWorkerSchedules{base.MockStore.ScheduledActions(), done})
		e := action.NewEngine(s, "auto")
		e.HandleEvent(ev)
		synctest.Wait()
		before, err := s.BGPAnnouncements().Get(context.Background(), id)
		if err != nil || before.Status != "delayed" || before.Gen != 7 {
			t.Fatalf("before timer: %+v err=%v; want delayed gen=7", before, err)
		}
		_, pending := base.scheduledActions.dao5Snapshot()
		if len(pending) != 1 || pending[0].Status != "pending" {
			t.Fatalf("before timer schedules=%+v", pending)
		}
		wantState, wantGen, wantCalls := "withdrawn", 7, 1
		if change == "active" {
			dao5bNewAttack(t, base, 21)
			wantState, wantCalls = "active", 0
		} else if change == "new" {
			dao5bCheck(t, base.anns.MarkWithdrawn(context.Background(), id, 7))
			next, err := base.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21, ActionID: intPtr(10), DelayMinutes: 1})
			dao5bCheck(t, err)
			dao5bCheck(t, base.anns.MarkAnnounced(context.Background(), id, dao5bCurrentGen(t, base.anns, id)))
			_, err = base.anns.Detach(context.Background(), 21, "192.0.2.10/32", "RTBH", 7)
			dao5bCheck(t, err)
			if next.Gen != 8 {
				t.Errorf("revival gen=%d; want 8", next.Gen)
			}
			wantState, wantGen, wantCalls = "delayed", 8, 0
		}
		// Waiting for the completion notification allows synctest's clock to
		// advance to the worker timer; elapsed time is never the verdict.
		if outcome := <-done; outcome != "completed" {
			t.Errorf("schedule outcome=%s", outcome)
		}
		synctest.Wait()
		r.mu.Lock()
		gens := append([]int(nil), r.gens...)
		r.mu.Unlock()
		generation = func(t *testing.T) {
			if len(gens) != 1 || gens[0] != 7 {
				t.Errorf("worker gen=%v; want [7] (Detach generation)", gens)
			}
		}
		after, err := s.BGPAnnouncements().Get(context.Background(), id)
		n := strings.Count(dao4Read(t, record), "no network")
		_, rows := base.scheduledActions.dao5Snapshot()
		behavior = func(t *testing.T) {
			if err != nil || after.Status != wantState || after.Gen != wantGen {
				t.Errorf("after timer: %+v err=%v; want %s gen=%d", after, err, wantState, wantGen)
			}
			if n != wantCalls {
				t.Errorf("vtysh withdraw count=%d; want %d", n, wantCalls)
			}
			if len(rows) != 1 || rows[0].Status != "completed" {
				t.Errorf("final schedules=%+v", rows)
			}
		}
	})
	if generation != nil {
		t.Run("worker_generation", generation)
	}
	if behavior != nil {
		t.Run("behavior", behavior)
	}
}
