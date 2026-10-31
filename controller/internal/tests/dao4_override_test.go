package tests

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/engine"
	"github.com/littlewolf9527/xsight/controller/internal/engine/dedup"
	"github.com/littlewolf9527/xsight/controller/internal/store"
	"github.com/littlewolf9527/xsight/controller/internal/tracker"
)

type dao4AnnouncementStore struct {
	*MockStore
	ann *dao4AnnouncementRepo
}

func (s dao4AnnouncementStore) BGPAnnouncements() store.BGPAnnouncementRepo { return s.ann }

type dao4AnnouncementRepo struct {
	store.BGPAnnouncementRepo
	mu          sync.Mutex
	attaches    int
	beforeForce func()
}

func (r *dao4AnnouncementRepo) Attach(ctx context.Context, p store.BGPAttachParams) (store.BGPAttachResult, error) {
	r.mu.Lock()
	r.attaches++
	r.mu.Unlock()
	return r.BGPAnnouncementRepo.Attach(ctx, p)
}
func (r *dao4AnnouncementRepo) ForceWithdraw(ctx context.Context, id int) ([]store.BGPAnnouncementAttack, int, error) {
	if r.beforeForce != nil {
		r.beforeForce()
	}
	return r.BGPAnnouncementRepo.ForceWithdraw(ctx, id)
}
func (r *dao4AnnouncementRepo) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.attaches }
func TestDao4_B18_ForceRemovedXDropPeriodicUpdate(t *testing.T) {
	for _, phase := range []string{"on_detected", "legacy_empty_phase"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := dao4HTTP(t)
				ms, _, e, _ := dao4XDrop()
				ms.responses.actions[0].RunMode = "periodic"
				if phase == "legacy_empty_phase" {
					ms.responses.actions[0].TriggerPhase = ""
					ms.responses.actions[0].ExecutionPolicy = "periodic"
				}
				tk := dao4Tracker(ms, e.HandleEvent)
				tk.Feed(dao4Threshold(false))
				synctest.Wait()
				dao4WantCount(t, d, 1)
				w := dao4Request(t, ms, e, "POST", "/api/active-actions/force-remove", `{"attack_id":1,"action_id":10,"connector_id":7,"external_rule_id":"rule-1"}`)
				if w.Code != 200 {
					t.Fatalf("force remove=%d %s", w.Code, w.Body)
				}
				dao4Tick(tk, dao4Threshold(false))
				synctest.Wait()
				dao4WantCount(t, d, 2)
				rows, _ := ms.XDropActiveRules().ListByAttack(context.Background(), 1)
				if len(rows) != 1 || rows[0].Status != "withdrawn" {
					t.Fatalf("post-override state=%+v; want withdrawn", rows)
				}
			})
		})
	}
}
func dao4SharedBGP(t *testing.T, shared bool) (*MockStore, *dao4AnnouncementRepo, *action.Engine, *tracker.Tracker, string, string, int) {
	t.Helper()
	ms, _, _ := dao4Fixture("bgp", "periodic", "on_detected")
	script, record := dao4Vtysh(t)
	ms.responses.actions[0].BGPConnectorID = intPtr(7)
	ms.responses.actions[0].BGPRouteMap = "RTBH"
	ms.responses.actions[0].Config = nil
	ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Name: "dao4", VtyshPath: script, BGPASN: 64512, Enabled: true}}
	for _, id := range []int{20, 21} {
		decoder := "udp"
		if id == 21 {
			decoder = "tcp"
		}
		ms.attacks.appendAttacks(store.Attack{ID: id, DstIP: "192.0.2.10", Direction: "receives", DecoderFamily: decoder, AttackType: decoder + "_flood", ResponseID: intPtr(1), StartedAt: time.Now(), Confidence: 0.9})
	}
	ctx := context.Background()
	a, err := ms.BGPAnnouncements().Attach(ctx, store.BGPAttachParams{AttackID: 20, ActionID: intPtr(10), ConnectorID: 7, Prefix: "192.0.2.10/32", RouteMap: "RTBH"})
	if err != nil {
		t.Fatal(err)
	}
	if shared {
		dao4AttachB(t, ms)
	}
	if err = ms.BGPAnnouncements().MarkAnnounced(ctx, a.AnnouncementID, dao5bCurrentGen(t, ms.BGPAnnouncements(), a.AnnouncementID)); err != nil {
		t.Fatal(err)
	}
	r := &dao4AnnouncementRepo{BGPAnnouncementRepo: ms.BGPAnnouncements()}
	e := action.NewEngine(dao4AnnouncementStore{ms, r}, "auto")
	tk := tracker.New(tracker.Config{HardConfirmSeconds: 1, ExpiryIntervalSeconds: 300}, ms, nil, dedup.New(), e.HandleEvent)
	if err = tk.RecoverFromDB(ctx); err != nil {
		t.Fatal(err)
	}
	return ms, r, e, tk, script, record, a.AnnouncementID
}
func dao4AttachB(t *testing.T, ms *MockStore) {
	t.Helper()
	if _, err := ms.BGPAnnouncements().Attach(context.Background(), store.BGPAttachParams{AttackID: 21, ActionID: intPtr(10), ConnectorID: 7, Prefix: "192.0.2.10/32", RouteMap: "RTBH"}); err != nil {
		t.Fatal(err)
	}
}
func dao4RemoveBGP(t *testing.T, ms *MockStore, e *action.Engine) int {
	t.Helper()
	return dao4Request(t, ms, e, "POST", "/api/active-actions/force-remove", `{"attack_id":20,"action_id":10,"connector_id":7,"external_rule_id":"192.0.2.10/32|RTBH"}`).Code
}
func dao4UpdatedB(tk *tracker.Tracker) {
	dao4Tick(tk, []engine.ThresholdExceeded{{DstIP: net.ParseIP("192.0.2.10"), Direction: "receives", Decoder: "tcp", Unit: "pps", Actual: 100, NodeID: "n1"}})
}
func dao4WantOverrides(t *testing.T, ms *MockStore, ids ...int) {
	t.Helper()
	for _, id := range ids {
		ok, err := ms.ManualOverrides().Exists(context.Background(), id, 10, 7, "192.0.2.10/32|RTBH")
		if err != nil || !ok {
			t.Errorf("attack %d override=%v err=%v; want true", id, ok, err)
		}
	}
}
func TestDao4_B18b_ForceRemovedBGPPeriodicAndUpgrade(t *testing.T) {
	for _, event := range []string{"updated", "type_upgrade"} {
		t.Run(event, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ms, r, e, tk, _, record, _ := dao4SharedBGP(t, false)
				if code := dao4RemoveBGP(t, ms, e); code != 200 {
					t.Fatal(code)
				}
				if event == "updated" {
					dao4Tick(tk, dao4Threshold(false))
				} else {
					tk.UpgradeType(net.ParseIP("192.0.2.10"), "dns_amp", 0.77, []string{"classified"})
				}
				synctest.Wait()
				if n := r.count(); n != 0 {
					t.Errorf("post-override Attach calls=%d; want 0", n)
				}
				commands := dao4Read(t, record)
				if strings.Count(commands, "network 192.0.2.10/32 route-map RTBH") != 1 || !strings.Contains(commands, "no network") {
					t.Fatalf("post-force commands=%q; want only withdrawal", commands)
				}
			})
		})
	}
}
func TestDao4_B18c_SharedForceRemoveSuppressesB(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms, r, e, tk, _, _, _ := dao4SharedBGP(t, true)
		if code := dao4RemoveBGP(t, ms, e); code != 200 {
			t.Fatal(code)
		}
		dao4WantOverrides(t, ms, 20, 21)
		dao4UpdatedB(tk)
		synctest.Wait()
		if n := r.count(); n != 0 {
			t.Fatalf("B Attach calls=%d; want 0", n)
		}
	})
}
func TestDao4_B18d_AttachCommitsBeforeForceRowLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ms, r, e, tk, _, _, _ := dao4SharedBGP(t, false)
		beforeLock := make(chan struct{})
		release := make(chan struct{})
		done := make(chan int, 1)
		// A pre-read mutation has already read attachments when it enters this
		// repository method. The real row lock is acquired by the delegate below.
		r.beforeForce = func() { close(beforeLock); <-release }
		go func() { done <- dao4RemoveBGP(t, ms, e) }()
		<-beforeLock
		dao4AttachB(t, ms)
		close(release)
		if code := <-done; code != 200 {
			t.Fatal(code)
		}
		dao4WantOverrides(t, ms, 20, 21)
		dao4UpdatedB(tk)
		synctest.Wait()
		if n := r.count(); n != 0 {
			t.Fatalf("late B Attach calls=%d; want 0", n)
		}
	})
}
func TestDao4_B18e_FailedVtyshIntentSurvivesRetry(t *testing.T) {
	ms, _, e, _, script, record, _ := dao4SharedBGP(t, true)
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(script, append(body, []byte("exit 1\n")...), 0700); err != nil {
		t.Fatal(err)
	}
	if code := dao4RemoveBGP(t, ms, e); code != 500 {
		t.Errorf("first force HTTP=%d; want 500", code)
	}
	dao4WantOverrides(t, ms, 20, 21)
	if err = os.WriteFile(script, body, 0700); err != nil {
		t.Fatal(err)
	}
	if code := dao4RemoveBGP(t, ms, e); code != 200 {
		t.Errorf("retry force HTTP=%d; want 200", code)
	}
	if n := strings.Count(dao4Read(t, record), "no network"); n != 2 {
		t.Fatalf("withdraw commands=%d; want 2 (%s)", n, fmt.Sprint(record))
	}
}
