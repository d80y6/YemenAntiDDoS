package tests

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/d80y6/YemenDDoS/controller/internal/action"
	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type dao4RuleStore struct {
	*MockStore
	rules store.XDropActiveRuleRepo
}

// Existing lookup tests now exercise the surviving repository entry directly;
// B18 and the withdrawal tests cover engine suppression with actual side effects.
func dao4LookupOverride(t *testing.T, s store.Store, ctx context.Context, attackID, actionID, connectorID int, rule string) bool {
	t.Helper()
	got, err := s.ManualOverrides().Exists(ctx, attackID, actionID, connectorID, rule)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (s dao4RuleStore) XDropActiveRules() store.XDropActiveRuleRepo { return s.rules }

type dao4Rules struct {
	store.XDropActiveRuleRepo
	mu              sync.Mutex
	marks           []string
	listErr         error
	nextMarkErr     error
	beforeMark      func()
	beforeWithdrawn func()
}

func (r *dao4Rules) MarkWithdrawn(ctx context.Context, a, b, c int, rule string) error {
	r.mu.Lock()
	before := r.beforeWithdrawn
	r.mu.Unlock()
	if before != nil {
		before()
	}
	return r.XDropActiveRuleRepo.MarkWithdrawn(ctx, a, b, c, rule)
}

func (r *dao4Rules) ListByAttack(ctx context.Context, a int) ([]store.XDropActiveRule, error) {
	r.mu.Lock()
	err := r.listErr
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return r.XDropActiveRuleRepo.ListByAttack(ctx, a)
}
func (r *dao4Rules) MarkWithdrawing(ctx context.Context, a, b, c int, rule string) (bool, error) {
	r.mu.Lock()
	r.marks = append(r.marks, fmt.Sprintf("%d/%d/%d/%s", a, b, c, rule))
	before := r.beforeMark
	err := r.nextMarkErr
	r.nextMarkErr = nil
	r.mu.Unlock()
	if before != nil {
		before()
	}
	if err != nil {
		return false, err
	}
	return r.XDropActiveRuleRepo.MarkWithdrawing(ctx, a, b, c, rule)
}
func (r *dao4Rules) failNextMark(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextMarkErr = err
}
func (r *dao4Rules) markCount() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.marks) }
func (r *dao4Rules) setHooks(beforeMark, beforeWithdrawn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.beforeMark, r.beforeWithdrawn = beforeMark, beforeWithdrawn
}
func dao4XDrop() (*MockStore, *dao4Rules, *action.Engine, tracker.AttackEvent) {
	ms, _, ev := dao4Fixture("xdrop", "once", "on_detected")
	ms.responses.actions[0].Config = nil
	ms.responses.actions = append(ms.responses.actions, store.ResponseAction{ID: 11, ResponseID: 1, ActionType: "xdrop", TriggerPhase: "on_expired", RunMode: "once", XDropAction: "unblock", Enabled: true})
	ms.xdropConnectors.connectors = []store.XDropConnector{{ID: 7, Name: "dao4", APIURL: "http://dao4.invalid", Enabled: true}}
	r := &dao4Rules{XDropActiveRuleRepo: ms.XDropActiveRules()}
	return ms, r, action.NewEngine(dao4RuleStore{ms, r}, "auto"), ev
}
func dao4SeedRule(t *testing.T, ms *MockStore, status, rule string, withLog bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := ms.XDropActiveRules().Upsert(ctx, &store.XDropActiveRule{AttackID: 20, ActionID: 10, ConnectorID: 7, ExternalRuleID: rule, Status: status}); err != nil {
		t.Fatal(err)
	}
	if withLog {
		status := "success"
		if strings.HasPrefix(rule, "failed-create-") {
			status = "failed"
		}
		if _, err := ms.ActionExecLog().Create(ctx, &store.ActionExecutionLog{AttackID: 20, ActionID: 10, ActionType: "xdrop", TriggerPhase: "on_detected", Status: status, ConnectorID: intPtr(7), ExternalRuleID: rule, ExecutedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
}
func dao4Request(t *testing.T, ms *MockStore, e *action.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := api.NewRouter(api.Dependencies{Store: ms, ActionEngine: e, JWTSecret: testJWTSecret, APIKey: "test-api-key"})
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}
func TestDao4_B3_ExpiredOnceThreeEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		dao4SeedRule(t, ms, "active", "rule-1", true)
		for i := 0; i < 3; i++ {
			dao4Emit(t, ms, e, ev, "expired")
		}
		dao4WantCount(t, d, 1)
	})
}
func TestDao4_B4_StateOnlyRule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		dao4SeedRule(t, ms, "active", "rule-1", false)
		dao4Emit(t, ms, e, ev, "expired")
		dao4WantCount(t, d, 1)
		d.mu.Lock()
		defer d.mu.Unlock()
		if r := d.requests[0]; r.Method != "DELETE" || r.URL.Query().Get("claim_ref") != "a20.x10" {
			t.Fatalf("DELETE claim: %s %s", r.Method, r.URL)
		}
	})
}
func TestDao4_B5_WithdrawnExcludedBeforeClaim(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, r, e, ev := dao4XDrop()
		dao4SeedRule(t, ms, "withdrawn", "rule-1", true)
		dao4Emit(t, ms, e, ev, "expired")
		if n := r.markCount(); n != 0 {
			t.Errorf("MarkWithdrawing calls=%d; want 0", n)
		}
		dao4WantCount(t, d, 0)
	})
}
func TestDao4_B6_FailedRealAndSynthetic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		dao4SeedRule(t, ms, "failed", "rule-real", true)
		dao4SeedRule(t, ms, "failed", "failed-create-20-10", true)
		dao4Emit(t, ms, e, ev, "expired")
		dao4WantCount(t, d, 1)
		rows, err := ms.XDropActiveRules().ListByAttack(context.Background(), 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Status != "withdrawn" {
				t.Errorf("%s status=%s; want withdrawn", r.ExternalRuleID, r.Status)
			}
		}
	})
}
func TestDao4_B7_WithdrawnTerminalGuards(t *testing.T) {
	for _, op := range []string{"MarkDelayed", "MarkFailed"} {
		t.Run(op, func(t *testing.T) {
			ms := NewMockStore()
			dao4SeedRule(t, ms, "withdrawn", "rule-1", false)
			r := ms.XDropActiveRules()
			ctx := context.Background()
			var err error
			if op == "MarkDelayed" {
				err = r.MarkDelayed(ctx, 20, 10, 7, "rule-1", 2)
			} else {
				err = r.MarkFailed(ctx, 20, 10, 7, "rule-1", "late error")
			}
			if err != nil {
				t.Fatal(err)
			}
			rows, _ := r.ListByAttack(ctx, 20)
			if rows[0].Status != "withdrawn" {
				t.Fatalf("%s changed withdrawn to %s", op, rows[0].Status)
			}
		})
	}
}
func TestDao4_B8c_ImmediateClaimLoser(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, r, e, ev := dao4XDrop()
		dao4SeedRule(t, ms, "active", "rule-1", true)
		arrived := make(chan struct{}, 2)
		release := make(chan struct{})
		r.setHooks(func() { arrived <- struct{}{}; <-release }, nil)
		ev.Type = "expired"
		e.HandleEvent(ev)
		// Separate engines preserve concurrent repository claimants despite per-engine once deduplication.
		action.NewEngine(dao4RuleStore{ms, r}, "auto").HandleEvent(ev)
		<-arrived
		<-arrived
		close(release)
		synctest.Wait()
		if r.markCount() != 2 {
			t.Fatal("both selectors must reach claim")
		}
		dao4WantCount(t, d, 1)
		for _, row := range ms.actionExecLog.snapshotLogs() {
			if row.TriggerPhase == "on_expired" && row.Status == "failed" {
				t.Errorf("claim loser recorded failure: %+v", row)
			}
		}
		r.setHooks(nil, nil)
		dao4NoReplay(t, ms, d)
	})
}

func dao4NoReplay(t *testing.T, ms *MockStore, d *dao4Transport) {
	t.Helper()
	stuck, err := ms.ScheduledActions().ListExecuting(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stuck) != 0 {
		t.Errorf("claim loser left executing schedules=%+v", stuck)
	}
	before := d.count()
	action.NewEngine(ms, "auto").ReconcileOnStartup(context.Background())
	synctest.Wait()
	if got := d.count(); got != before {
		t.Errorf("restart replayed DELETE: before=%d after=%d", before, got)
	}
}

func TestDao4_B8_DelayedClaimLoser(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, r, e, ev := dao4XDrop()
		dao4SeedRule(t, ms, "active", "rule-1", true)
		ms.responses.actions[0].UnblockDelayMinutes = 1
		other := ms.responses.actions[1]
		other.ID = 12
		other.Enabled = false
		ms.responses.actions = append(ms.responses.actions, other)
		dao4Emit(t, ms, e, ev, "expired")
		pending, _ := ms.ScheduledActions().ListPending(context.Background())
		if len(pending) != 1 {
			t.Fatalf("scheduled=%+v", pending)
		}
		origin, err := ms.Responses().GetAction(context.Background(), 10)
		if err != nil {
			t.Fatal(err)
		}
		origin.UnblockDelayMinutes = 0
		if err = ms.Responses().UpdateAction(context.Background(), origin); err != nil {
			t.Fatal(err)
		}
		first, err := ms.Responses().GetAction(context.Background(), 11)
		if err != nil {
			t.Fatal(err)
		}
		first.Enabled = false
		if err = ms.Responses().UpdateAction(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		other.Enabled = true
		if err = ms.Responses().UpdateAction(context.Background(), &other); err != nil {
			t.Fatal(err)
		}
		marks := make(chan struct{}, 2)
		atTerminal := make(chan struct{}, 2)
		release := make(chan struct{})
		r.setHooks(func() { marks <- struct{}{} }, func() { atTerminal <- struct{}{}; <-release })
		ev.Type = "expired"
		e.HandleEvent(ev)
		synctest.Wait()
		dao4WantCount(t, d, 0)
		if r.markCount() != 0 {
			t.Fatal("future delay was claimed early")
		}
		rows, _ := ms.XDropActiveRules().ListByAttack(context.Background(), 20)
		if len(rows) != 1 || rows[0].Status != "delayed" {
			t.Fatalf("future rule: %+v", rows)
		}
		pending, _ = ms.ScheduledActions().ListPending(context.Background())
		if len(pending) != 1 {
			t.Fatal("future schedule lost")
		}
		time.Sleep(time.Until(pending[0].ScheduledFor))
		<-marks
		<-atTerminal
		beforeMarks := r.markCount()
		beforeBusy := testutil.ToFloat64(metrics.XDropReconcile.WithLabelValues("busy"))
		loopCtx, cancel := context.WithCancel(context.Background())
		go e.RunXDropReconcile(loopCtx, time.Second)
		synctest.Wait()
		if testutil.ToFloat64(metrics.XDropReconcile.WithLabelValues("busy")) <= beforeBusy {
			t.Fatal("competitor did not observe busy row")
		}
		dao4WantCount(t, d, 1)
		if r.markCount() != beforeMarks {
			t.Fatal("competitor entered claim while terminal write held lock")
		}
		close(release)
		synctest.Wait()
		time.Sleep(time.Second)
		synctest.Wait()
		dao4WantCount(t, d, 1)
		rows, _ = ms.XDropActiveRules().ListByAttack(context.Background(), 20)
		if len(rows) != 1 || rows[0].Status != "withdrawn" {
			t.Fatalf("terminal rule: %+v", rows)
		}
		cancel()
		synctest.Wait()
		r.setHooks(nil, nil)
		dao4NoReplay(t, ms, d)
	})
}

// B8d/B8e (blind review r1 P1-2): a failed database claim is not a lost claim.
// The existing DELETE outcome still controls audit/state, including HTTP failure.
func TestDao4_B8d_ImmediateClaimErrorStillDeletes(t *testing.T) {
	dao4ClaimErrorStillDeletes(t, false)
}
func TestDao4_B8e_DelayedClaimErrorStillDeletes(t *testing.T) {
	dao4ClaimErrorStillDeletes(t, true)
}
func dao4ClaimErrorStillDeletes(t *testing.T, delayed bool) {
	t.Helper()
	for _, status := range []int{204, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				d := dao4HTTP(t)
				d.setStatus(status)
				ms, r, e, ev := dao4XDrop()
				dao4SeedRule(t, ms, "active", "rule-1", true)
				r.failNextMark(errors.New("dao4 claim write fault"))
				marked := make(chan struct{}, 1)
				r.setHooks(func() { marked <- struct{}{} }, nil)
				if delayed {
					ms.responses.actions[0].UnblockDelayMinutes = 1
				}
				dao4Emit(t, ms, e, ev, "expired")
				<-marked // virtual time advances to the delayed worker when needed
				synctest.Wait()
				dao4WantCount(t, d, 0)
				if n := r.markCount(); n != 1 {
					t.Errorf("claim calls=%d; want exactly one injected error", n)
				}
				rowsBefore, _ := ms.XDropActiveRules().ListByAttack(context.Background(), 20)
				if len(rowsBefore) != 1 || rowsBefore[0].Status == "withdrawn" {
					t.Fatal("claim error closed the rule")
				}
				beforeClaimErrors := testutil.ToFloat64(metrics.StateWriteFailures.WithLabelValues("xdrop_claim"))
				if beforeClaimErrors < 1 {
					t.Fatal("missing claim error metric")
				}
				r.setHooks(nil, nil)
				loopCtx, cancel := context.WithCancel(context.Background())
				go e.RunXDropReconcile(loopCtx, time.Second)
				time.Sleep(2 * time.Minute)
				synctest.Wait()
				cancel()
				synctest.Wait()
				dao4WantCount(t, d, 1)
				want := "withdrawn"
				logStatus := "success"
				if status == 500 {
					want, logStatus = "failed", "failed"
				}
				rows, _ := ms.XDropActiveRules().ListByAttack(context.Background(), 20)
				if len(rows) != 1 || rows[0].Status != want {
					t.Errorf("after claim error and DELETE HTTP %d: rows=%+v; want %s", status, rows, want)
				}
				found := false
				for _, l := range ms.actionExecLog.snapshotLogs() {
					if l.ActionID == 10 && l.ExternalRuleID == "rule-1" && l.TriggerPhase == "on_expired" && l.Status == logStatus {
						found = true
					}
				}
				if !found {
					t.Errorf("missing per-rule DELETE %s log", logStatus)
				}
				if status == 204 {
					dao4Emit(t, ms, e, ev, "expired")
					dao4WantCount(t, d, 1)
				}
			})
		})
	}
}
func TestDao4_B8b_ForceRemoveWithdrawing(t *testing.T) {
	for _, status := range []int{204, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			d := dao4HTTP(t)
			d.setStatus(status)
			ms, _, e, _ := dao4XDrop()
			dao4SeedRule(t, ms, "withdrawing", "rule-1", true)
			w := dao4Request(t, ms, e, "POST", "/api/active-actions/force-remove", `{"attack_id":20,"action_id":10,"connector_id":7,"external_rule_id":"rule-1"}`)
			dao4WantCount(t, d, 1)
			rows, _ := ms.XDropActiveRules().ListByAttack(context.Background(), 20)
			overrides, _ := ms.ManualOverrides().ListByAttack(context.Background(), 20)
			if status == 500 {
				if w.Code < 400 || len(overrides) != 0 || rows[0].Status != "withdrawing" {
					t.Fatalf("failed DELETE: API=%d overrides=%d state=%s", w.Code, len(overrides), rows[0].Status)
				}
			} else if w.Code != 200 || rows[0].Status != "withdrawn" {
				t.Fatalf("successful DELETE: API=%d state=%s body=%s", w.Code, rows[0].Status, w.Body)
			}
		})
	}
}
func TestDao4_B9_ListRulesFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, r, e, ev := dao4XDrop()
		r.listErr = errors.New("dao4 read fault")
		dao4Emit(t, ms, e, ev, "expired")
		dao4WantCount(t, d, 0)
		logs := ms.actionExecLog.snapshotLogs()
		if len(logs) == 0 {
			t.Fatal("missing failure log")
		}
		l := logs[len(logs)-1]
		if l.Status != "failed" || l.ErrorMessage != "list xdrop_active_rules: dao4 read fault" {
			t.Fatalf("failure log=%+v", l)
		}
	})
}
func TestDao4_B9b_LegacyEmptyPhase(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := dao4HTTP(t)
		ms, _, e, ev := dao4XDrop()
		ms.responses.actions[0].TriggerPhase = ""
		ms.responses.actions[0].ExecutionPolicy = "once_on_enter"
		ms.responses.actions[1].TriggerPhase = ""
		ms.responses.actions[1].ExecutionPolicy = "once_on_exit"
		dao4Emit(t, ms, e, ev, "confirmed")
		rows, _ := ms.XDropActiveRules().ListByAttack(context.Background(), 20)
		if len(rows) != 1 || rows[0].Status != "active" {
			t.Errorf("legacy create state=%+v; want one active row", rows)
		}
		dao4Emit(t, ms, e, ev, "expired")
		dao4WantCount(t, d, 2)
	})
}
func TestDao4_B9c_APIRejectsEmptyPhase(t *testing.T) {
	for _, method := range []string{"POST", "PUT"} {
		t.Run(method, func(t *testing.T) {
			ms, e, _ := dao4Fixture("webhook", "once", "on_detected")
			path := "/api/responses/1/actions"
			if method == "PUT" {
				path = "/api/actions/10"
			}
			w := dao4Request(t, ms, e, method, path, `{"name":"dao4","action_type":"webhook","connector_id":1,"trigger_phase":"","run_mode":"once","enabled":true}`)
			if w.Code != 400 {
				t.Fatalf("%s empty trigger_phase: status=%d body=%s; want 400", method, w.Code, w.Body)
			}
		})
	}
}
func TestDao4_B19_RepeatedAttachSingleDetach(t *testing.T) {
	ms := NewMockStore()
	ctx := context.Background()
	r := ms.BGPAnnouncements()
	p := store.BGPAttachParams{AttackID: 20, ActionID: intPtr(10), ConnectorID: 7, Prefix: "192.0.2.10/32", RouteMap: "RTBH"}
	a, err := r.Attach(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.MarkAnnounced(ctx, a.AnnouncementID, dao5bCurrentGen(t, r, a.AnnouncementID)); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Attach(ctx, p); err != nil {
		t.Fatal(err)
	}
	d, err := r.Detach(ctx, 20, p.Prefix, p.RouteMap, 7)
	if err != nil {
		t.Fatal(err)
	}
	row, _ := r.Get(ctx, a.AnnouncementID)
	if d.RefcountAfter != 0 || !d.NeedWithdraw || row.Status != "withdrawing" {
		t.Fatalf("detach=%+v state=%+v", d, row)
	}
}
