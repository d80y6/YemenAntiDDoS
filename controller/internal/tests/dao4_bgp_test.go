package tests

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

type dao4TimerStore struct {
	*MockStore
	schedules *dao4TimerRepo
}

func (s dao4TimerStore) ScheduledActions() store.ScheduledActionRepo { return s.schedules }

type dao4TimerRepo struct {
	store.ScheduledActionRepo
	mu     sync.Mutex
	done   chan struct{}
	closed bool
}

func (r *dao4TimerRepo) Complete(ctx context.Context, id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.ScheduledActionRepo.Complete(ctx, id); err != nil {
		return err
	}
	if !r.closed {
		close(r.done)
		r.closed = true
	}
	return nil
}

func dao4Vtysh(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "vtysh")
	record := filepath.Join(dir, "commands")
	// The path is test-owned; quote it for a literal shell argument.
	body := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> '" + strings.ReplaceAll(record, "'", "'\\''") + "'\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, nil, 0600); err != nil {
		t.Fatal(err)
	}
	return script, record
}
func dao4Read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func dao4RecoveryFixture(t *testing.T, status string) (*MockStore, int, string) {
	t.Helper()
	ms := NewMockStore()
	script, record := dao4Vtysh(t)
	ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "dao4", VtyshPath: script, BGPASN: 64512, Enabled: true}}
	ms.attacks.attacks = []store.Attack{{ID: 20, DstIP: "192.0.2.10", StartedAt: time.Now().Add(-time.Hour)}}
	ms.actionExecLog.logs = []store.ActionExecutionLog{bgpOnDetectedLog(20, 10, 7, 1, "192.0.2.10/32|RTBH", time.Now())}
	ms.bgpAnnouncements.announcements = []store.BGPAnnouncement{{ID: 1, Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, Status: status, Refcount: 1}}
	ms.bgpAnnouncements.attacks = []store.BGPAnnouncementAttack{{AnnouncementID: 1, AttackID: 20, ActionID: intPtr(10), AttachedAt: time.Now()}}
	return ms, 1, record
}
func TestDao4_B10_DelayedRecoveryReinjectsAndArmsTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms, id, record := dao4RecoveryFixture(t, "delayed")
		ended := time.Now()
		ms.attacks.attacks[0].EndedAt = &ended
		ms.attacks.expiredAttacks = append(ms.attacks.expiredAttacks, ms.attacks.attacks[0])
		ms.attacks.attacks = nil
		ctx := context.Background()
		_, err := ms.ScheduledActions().Schedule(ctx, &store.ScheduledAction{ActionType: "bgp_withdraw", AnnouncementID: &id, ScheduledFor: time.Now().Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		action.RecoverBGPRoutes(ctx, ms)
		commands := dao4Read(t, record)
		if !strings.Contains(commands, "network 192.0.2.10/32 route-map RTBH") || strings.Contains(commands, "no network") {
			t.Errorf("recovery commands=%q; want network only", commands)
		}
		schedules := &dao4TimerRepo{ScheduledActionRepo: ms.ScheduledActions(), done: make(chan struct{})}
		e := action.NewEngine(dao4TimerStore{ms, schedules}, "auto")
		e.ReconcileOnStartup(ctx)
		synctest.Wait()
		pending, _ := ms.ScheduledActions().ListPending(ctx)
		if len(pending) != 1 {
			t.Fatalf("pending schedule=%+v", pending)
		}
		// Blocking on completion advances virtual time to the restored timer.
		<-schedules.done
		synctest.Wait()
		row, err := ms.BGPAnnouncements().Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if row.Status != "withdrawn" {
			t.Errorf("timer state=%s; want withdrawn", row.Status)
		}
		if commands = dao4Read(t, record); strings.Count(commands, "no network") != 1 {
			t.Errorf("timer withdrawal commands=%q", commands)
		}
	})
}
func TestDao4_B11_WithdrawnRecoveryDoesNothing(t *testing.T) {
	ms, _, record := dao4RecoveryFixture(t, "withdrawn")
	action.RecoverBGPRoutes(context.Background(), ms)
	if commands := dao4Read(t, record); commands != "" {
		t.Fatalf("withdrawn recovery commands=%q; want none", commands)
	}
}
func TestDao4_B12_ActiveRecoveryReinjects(t *testing.T) {
	ms, _, record := dao4RecoveryFixture(t, "active")
	action.RecoverBGPRoutes(context.Background(), ms)
	if commands := dao4Read(t, record); !strings.Contains(commands, "network 192.0.2.10/32 route-map RTBH") || strings.Contains(commands, "no network") {
		t.Fatalf("active recovery commands=%q; want network only", commands)
	}
}

func TestDao4_B3b_MixedXDropTargetsRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		ms.responses.actions[0].RunMode = "retry_until_success"
		ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{ID: 8, Name: "C2", APIURL: "http://c2.invalid", Enabled: true})
		dao4Log(t, ms, "success", intPtr(7))
		dao4Log(t, ms, "failed", intPtr(8))
		b := &mockContractBackend{ms: ms}
		if err := b.SetTime("action_execution_log", "id", 1, "executed_at", time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		dao4Emit(t, ms, e, ev, "updated")
		dao4WantCount(t, d, 2)
	})
}
func TestDao4_B3c_AllXDropTargetsSkipTwice(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		ms.responses.actions[0].RunMode = "retry_until_success"
		ms.xdropConnectors.connectors = append(ms.xdropConnectors.connectors, store.XDropConnector{ID: 8, Name: "C2", APIURL: "http://c2.invalid", Enabled: true})
		dao4Log(t, ms, "success", intPtr(7))
		dao4Log(t, ms, "success", intPtr(8))
		for _, row := range ms.actionExecLog.snapshotLogs() {
			if err := (&mockContractBackend{ms: ms}).SetTime("action_execution_log", "id", row.ID, "executed_at", time.Now().Add(-time.Hour+time.Duration(row.ID))); err != nil {
				t.Fatal(err)
			}
		}
		dao4Emit(t, ms, e, ev, "updated")
		dao4Emit(t, ms, e, ev, "updated")
		dao4WantCount(t, d, 0)
	})
}
