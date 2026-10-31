package action

// Barrier-based tests assert state at the reread and commit points.
// HTTP and store operations stay in memory; channels and synctest fix ordering without listeners or sleep-based interleaving.
import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func d2cR1Wait(t *testing.T, done <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("device: timed out waiting for %s", description)
	}
}

// C17：创建回读提交点在 S 强撤之前则接管，在之后则输给人工覆盖。
func TestD2C_C17_SyntheticForceVsSuccessCreate(t *testing.T) {
	for _, kind := range []string{"publish_after_owned_check", "publish_before_force_readback_after", "readback_before_force"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, e, x := d2cFixture(t)
				c.live = true
				d2cSeedSynthetic(t, c, e, x, "lost")
				ids := x.ruleIDs()
				if len(ids) != 1 || x.ourClaims() != 1 {
					t.Fatalf("device: synthetic seed rules=%v claims=%d", ids, x.ourClaims())
				}
				rk := xdropRuleKey{101, 11, 7, ids[0]}
				published, resume, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var logOnce, resumeOnce sync.Once
				release := func() { resumeOnce.Do(func() { close(resume) }) }
				defer release()
				c.setLogHook(func(l store.ActionExecutionLog) {
					if l.ExternalRuleID == rk.rule && l.Status == "success" && l.TriggerPhase == "updated" {
						logOnce.Do(func() {
							close(published)
							if kind == "publish_before_force_readback_after" {
								<-resume // 日志已提交，回读尚未进入。
							}
						})
					}
				})
				create := func() { defer close(finished); d2cCreate(c, e, x, "", "updated") }
				mark := x.mark()
				leak := d2bReconcileMetric("late_create_leak")
				forceDeletes := -1
				c.setWriteHook(func(write string, k xdropRuleKey) {
					if write == "override" && k == d2cSynthKey {
						forceDeletes = d2bCountKind(x.since(mark), "delete")
						release()
						// S 尚未写覆盖且强撤仍持 S；所有可运行回读先执行到阻塞。
						// M18 只拿 R，会在此完成错误的 active 回读；正确实现等 S。
						synctest.Wait()
					}
				})
				switch kind {
				case "publish_after_owned_check":
					c.hookMu.Lock()
					c.onGet = func() { // 恢复已读 R 无行，并持有 S→R。
						go create()
						d2cR1Wait(t, published, "successful create row/log publication")
						if d2cRow(c, rk) != "active" || x.ourClaims() != 1 {
							t.Fatal("device: R was not active with our ref before recovery DELETE")
						}
					}
					c.hookMu.Unlock()
				case "publish_before_force_readback_after":
					go create()
					d2cR1Wait(t, published, "published R before force")
					if d2cRow(c, rk) != "active" {
						t.Fatal("device: R was not published before force")
					}
				case "readback_before_force":
					create()
					if d2cRow(c, rk) != "active" || x.ourClaims() != 1 {
						t.Fatal("device: completed create did not own active R")
					}
				}
				if err := d2cForce(e, d2cSynthKey); err != nil {
					t.Fatalf("ForceRemove(S): %v", err)
				}
				d2cR1Wait(t, finished, "successful create readback")
				wantStatus, wantClaims, wantForceDeletes, wantDeletes := "withdrawn", 0, 0, 1
				if kind == "publish_after_owned_check" {
					wantForceDeletes, wantDeletes = 1, 2
				} else if kind == "readback_before_force" {
					wantStatus, wantClaims, wantDeletes = "active", 1, 0
				}
				if d2cRow(c, d2cSynthKey) != "withdrawn" || c.overrideCount(d2cSynthKey) != 1 {
					t.Errorf("S=%s overrides=%d; want withdrawn/1", d2cRow(c, d2cSynthKey), c.overrideCount(d2cSynthKey))
				}
				if d2cRow(c, rk) != wantStatus || x.ourClaims() != wantClaims {
					t.Errorf("R=%s claims=%d; want %s/%d", d2cRow(c, rk), x.ourClaims(), wantStatus, wantClaims)
				}
				if forceDeletes != wantForceDeletes {
					t.Errorf("force DELETE=%d want %d", forceDeletes, wantForceDeletes)
				}
				reqs := x.since(mark)
				if d2bCountKind(reqs, "delete") != wantDeletes || d2cDeletesTo(reqs, rk.rule) != wantDeletes || d2cDeletesTo(reqs, d2bSynthetic) != 0 {
					t.Errorf("DELETE total/to R=%d/%d want %d; reqs=%s", d2bCountKind(reqs, "delete"), d2cDeletesTo(reqs, rk.rule), wantDeletes, d2bDescribe(reqs))
				}
				if d2bCountKind(reqs, "create") != 1 || d2bCountKind(reqs, "validate") != 1 {
					t.Errorf("create/validate must be 1/1: %s", d2bDescribe(reqs))
				}
				if delta := d2bReconcileMetric("late_create_leak") - leak; delta != 0 {
					t.Errorf("late_create_leak delta=%g want 0", delta)
				}
				if d2cRefs(e, rk) != 0 || d2cRefs(e, d2cSynthKey) != 0 {
					t.Error("key lock references leaked")
				}
			})
		})
	}
}

const d2cR1ReadFailure = "injected d2c r1 real ListByAttack failure"

// 新门局部包装：只在预检完成后注入真键读错，包含测试 key 以验证脱敏。
type d2cR1Store struct {
	*d2cStore
	failRead atomic.Bool
}
type d2cR1Rules struct {
	store.XDropActiveRuleRepo
	s *d2cR1Store
}

func (s *d2cR1Store) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2cR1Rules{s.d2cStore.XDropActiveRules(), s}
}
func (r d2cR1Rules) ListByAttack(ctx context.Context, attackID int) ([]store.XDropActiveRule, error) {
	if r.s.failRead.Load() {
		return nil, errors.New(d2cR1ReadFailure + " api_key=" + v3TestKey)
	}
	return r.XDropActiveRuleRepo.ListByAttack(ctx, attackID)
}

// C18/C19：迟到失败日志提交前停住；强撤只看到 NotSent 证据。
func d2cR1Late(t *testing.T, owned, failRead bool) (*d2cStore, *d2bRemote, string, []store.ActionExecutionLog, map[string]float64, int) {
	t.Helper()
	c, _, x := d2cFixture(t)
	s := &d2cR1Store{d2cStore: c}
	e := NewEngine(s, "auto")
	c.live = true
	if owned {
		d2cSeedReal(t, c, e, x, false)
	}
	d2cNotSentCreate(c, e, x)
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var enterOnce, resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(resume) }) }
	defer release()
	c.setPreLogHook(func(l store.ActionExecutionLog) {
		if l.TriggerPhase == "updated" && l.Status == "failed" && l.ExternalRuleID == d2bSynthetic {
			enterOnce.Do(func() { close(entered); <-resume })
		}
	})
	go func() { defer close(done); d2cCreate(c, e, x, "lost", "updated") }()
	d2cR1Wait(t, entered, "late failed create log barrier")
	if x.ourClaims() != 1 {
		t.Fatal("device: late failed create did not commit our remote ref")
	}
	if err := d2cForce(e, d2cSynthKey); err != nil {
		t.Fatalf("ForceRemove(S): %v", err)
	}
	if failRead {
		d2HTTP(t, func(r *http.Request) (*http.Response, error) {
			response, err := x.roundTrip(r)
			if strings.HasSuffix(r.URL.Path, "/rules/batch") && r.URL.Query().Get("validate") == "1" {
				s.failRead.Store(true) // S 回读与 S 覆盖识别已成功，随后 R 读错。
			}
			return response, err
		})
	}
	before := c.logSnapshot()
	metrics := d2cReconcileSnapshot()
	mark := x.mark()
	captured := d2R4Capture(t)
	release()
	d2cR1Wait(t, done, "late failed create readback")
	return c, x, captured.text(), before, metrics, mark
}

func TestD2C_C18_LateManualNoExecLog(t *testing.T) {
	for _, kind := range []string{"released", "owned"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, x, _, before, metrics, mark := d2cR1Late(t, kind == "owned", false)
				newLogs := c.logSnapshot()[len(before):]
				recoveryLogs, createLogs := 0, 0
				for _, l := range newLogs {
					if l.ActionType != store.ActionTypeXDrop {
						continue
					}
					if xdropCreatePhase(l.TriggerPhase) {
						createLogs++
					} else {
						recoveryLogs++
					}
				}
				if createLogs == 0 {
					t.Fatal("device: no late create logs after barrier release")
				}
				if recoveryLogs != 0 {
					t.Errorf("manual late recovery xdrop execution logs=%d want 0", recoveryLogs)
				}
				for outcome, value := range d2cReconcileSnapshot() {
					if delta := value - metrics[outcome]; delta != 0 {
						t.Errorf("manual reconcile outcome=%s delta=%g want 0", outcome, delta)
					}
				}
				wantClaims, wantDeletes := 0, 1
				if kind == "owned" {
					wantClaims, wantDeletes = 1, 0
					ids := x.ruleIDs()
					if len(ids) != 1 || d2bRow(c.d2bStore, ids[0]).Status != "active" {
						t.Errorf("owned R must remain active: ids=%v", ids)
					}
				}
				if x.ourClaims() != wantClaims || d2bCountKind(x.since(mark), "delete") != wantDeletes || d2bCountKind(x.since(mark), "validate") != 1 {
					t.Errorf("claims=%d want %d; reqs=%s (want validate=1 DELETE=%d)", x.ourClaims(), wantClaims, d2bDescribe(x.since(mark)), wantDeletes)
				}
				if d2cRow(c, d2cSynthKey) != "withdrawn" || c.overrideCount(d2cSynthKey) != 1 {
					t.Errorf("S=%s overrides=%d want withdrawn/1", d2cRow(c, d2cSynthKey), c.overrideCount(d2cSynthKey))
				}
			})
		})
	}
}

func TestD2C_C19_LateManualFailureDiagnostic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, x, message, _, _, mark := d2cR1Late(t, false, true)
		prefix := "WARN action: xdrop late failed create rule=" + d2bSynthetic + " manual recovery failed"
		warning := ""
		summary := ""
		for _, line := range strings.Split(message, "\n") {
			if i := strings.Index(line, prefix); i >= 0 {
				warning = line
				summary = strings.TrimSpace(line[i+len(prefix):])
			}
		}
		if !strings.Contains(warning, "error="+d2cR1ReadFailure) || !strings.Contains(warning, "skip=") {
			t.Errorf("manual recovery WARN lost underlying error/skip fields: %q", warning)
		}
		if strings.Contains(message, v3TestKey) {
			t.Error("manual recovery WARN exposed the connector test API key")
		}
		if strings.HasPrefix(strings.TrimLeft(summary, ": "), "synthetic failed-create closed locally") {
			t.Errorf("manual failure summary claims local closure: %q", warning)
		}
		if x.ourClaims() != 1 || d2bCountKind(x.since(mark), "delete") != 0 || d2bCountKind(x.since(mark), "validate") != 1 {
			t.Errorf("read fault must retain ref with no DELETE: claims=%d reqs=%s", x.ourClaims(), d2bDescribe(x.since(mark)))
		}
	})
}

// 授权 r2 / C20：假时间只用于耗用明确的锁预算，不用于碰运气调度。
// refs 确认等锁位置；计时从回读首次等锁之前开始，S、R 总预算必须恰为 2T。
func TestD2C_C20_SuccessReadbackSharedBudget(t *testing.T) {
	for _, kind := range []string{"shared_budget", "S_timeout", "R_timeout"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, e, x := d2cFixture(t)
				k := d2cSeedReal(t, c, e, x, false)
				c.mu.Lock()
				c.conn.TimeoutMs = 100
				conn := c.conn
				c.mu.Unlock()
				beforeRow := d2bRow(c.d2bStore, k.rule)
				releaseS, releaseR := func() {}, func() {}
				if kind != "R_timeout" {
					releaseS = d2cHold(t, e, d2cSynthKey)
					defer releaseS()
				}
				if kind != "S_timeout" {
					releaseR = d2cHold(t, e, k)
					defer releaseR()
				}
				entry := store.ActionExecutionLog{AttackID: k.attack, ActionID: k.action, ExternalRuleID: k.rule, Status: "success"}
				mark, leak := x.mark(), d2bReconcileMetric("late_create_leak")
				done := make(chan time.Duration, 1)
				go func() {
					started := time.Now()
					e.xdropAfterCreate(conn, &entry, nil)
					done <- time.Since(started)
				}()
				synctest.Wait()
				wantS, wantR := 2, 1 // 测试持 S/R，回读正在等 S。
				if kind == "S_timeout" {
					wantR = 0 // S 未取得时不应先取 R。
				} else if kind == "R_timeout" {
					wantS, wantR = 1, 2 // 回读持 S，等待测试持有的 R。
				}
				if s, r := d2cRefs(e, d2cSynthKey), d2cRefs(e, k); s != wantS || r != wantR {
					t.Errorf("initial lock refs S/R=%d/%d want %d/%d", s, r, wantS, wantR)
				}
				if kind == "shared_budget" {
					<-time.After(150 * time.Millisecond) // 精确耗用原 200ms 预算中的 150ms。
					releaseS()
					synctest.Wait()
					if s, r := d2cRefs(e, d2cSynthKey), d2cRefs(e, k); s != 1 || r != 2 {
						t.Errorf("after S release refs S/R=%d/%d want 1/2", s, r)
					}
				}
				var elapsed time.Duration
				select {
				case elapsed = <-done:
				case <-time.After(time.Second):
					t.Error("success readback did not finish within the test deadline")
					releaseS()
					releaseR()
					elapsed = <-done
				}
				t.Logf("%s elapsed=%s Srefs=%d Rrefs=%d leak_delta=%g", kind, elapsed, d2cRefs(e, d2cSynthKey), d2cRefs(e, k), d2bReconcileMetric("late_create_leak")-leak)
				if elapsed != 200*time.Millisecond {
					t.Errorf("shared 2T lock budget elapsed=%s want exactly 200ms", elapsed)
				}
				wantS, wantR = 0, 1 // 只剩测试持有的 R。
				if kind == "S_timeout" {
					wantS, wantR = 1, 0 // 只剩测试持有的 S；R 从未取得。
				}
				if s, r := d2cRefs(e, d2cSynthKey), d2cRefs(e, k); s != wantS || r != wantR {
					t.Errorf("readback leaked lock refs S/R=%d/%d want %d/%d", s, r, wantS, wantR)
				}
				if kind != "S_timeout" {
					if unlock, ok := e.lockXDrop(context.Background(), d2cSynthKey, true); ok {
						unlock()
					} else {
						t.Error("S cannot be immediately reacquired after R timeout")
					}
				}
				releaseS()
				releaseR()
				if s, r := d2cRefs(e, d2cSynthKey), d2cRefs(e, k); s != 0 || r != 0 {
					t.Errorf("after releasing test locks S/R refs=%d/%d want 0/0", s, r)
				}
				if delta := d2bReconcileMetric("late_create_leak") - leak; delta != 1 {
					t.Errorf("late_create_leak delta=%g want 1", delta)
				}
				if reqs := x.since(mark); len(reqs) != 0 {
					t.Errorf("timeout must not send HTTP (including DELETE): %s", d2bDescribe(reqs))
				}
				if row := d2bRow(c.d2bStore, k.rule); row != beforeRow || x.ourClaims() != 1 {
					t.Errorf("timeout changed original row/ref: row=%+v claims=%d", row, x.ourClaims())
				}
			})
		})
	}
}

// 授权 r2 / C21：覆盖在创建日志已提交、回读尚未进入时落定。
// 阴性覆盖必须不影响本行，阳性覆盖与创建侧一样忽略 ExternalRuleID。
func TestD2C_C21_SuccessOverrideScope(t *testing.T) {
	for _, kind := range []string{"other_action", "other_connector", "other_attack", "same_action_connector_other_rule"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, e, x := d2cFixture(t)
				k := d2cSeedReal(t, c, e, x, false)
				override := store.ActionManualOverride{AttackID: k.attack, ActionID: k.action, ConnectorID: k.connector, ExternalRuleID: "different-rule"}
				switch kind {
				case "other_action":
					override.ActionID++
				case "other_connector":
					override.ConnectorID++
				case "other_attack":
					override.AttackID++
				}
				published, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var logOnce, resumeOnce sync.Once
				release := func() { resumeOnce.Do(func() { close(resume) }) }
				defer release()
				c.setLogHook(func(l store.ActionExecutionLog) {
					if l.ExternalRuleID == k.rule && l.TriggerPhase == "updated" && l.Status == "success" {
						logOnce.Do(func() { close(published); <-resume })
					}
				})
				mark, leak := x.mark(), d2bReconcileMetric("late_create_leak")
				go func() { defer close(done); d2cCreate(c, e, x, "", "updated") }()
				d2cR1Wait(t, published, "successful create log before inserting override")
				if d2cRow(c, k) != "active" || x.ourClaims() != 1 || d2bCountKind(x.since(mark), "create") != 1 {
					t.Fatal("device: expected active R with committed POST before override")
				}
				if _, err := c.ManualOverrides().Create(context.Background(), &override); err != nil {
					t.Fatalf("device: insert concurrent override: %v", err)
				}
				if c.overrideCount(xdropRuleKey{override.AttackID, override.ActionID, override.ConnectorID, override.ExternalRuleID}) != 1 {
					t.Fatal("device: concurrent override was not stored")
				}
				release()
				d2cR1Wait(t, done, "successful create readback after override")
				wantState, wantClaims, wantDeletes := "active", 1, 0
				if kind == "same_action_connector_other_rule" {
					wantState, wantClaims, wantDeletes = "withdrawn", 0, 1
				}
				reqs := x.since(mark)
				t.Logf("%s state=%s claims=%d DELETE=%d", kind, d2cRow(c, k), x.ourClaims(), d2bCountKind(reqs, "delete"))
				if d2cRow(c, k) != wantState || x.ourClaims() != wantClaims || d2bCountKind(reqs, "delete") != wantDeletes {
					t.Errorf("override scope mismatch: want %s/%d/%d", wantState, wantClaims, wantDeletes)
				}
				if d2cDeletesTo(reqs, k.rule) != wantDeletes || d2bCountKind(reqs, "create") != 1 || d2bCountKind(reqs, "validate") != 0 {
					t.Errorf("unexpected successful readback requests: %s", d2bDescribe(reqs))
				}
				if delta := d2bReconcileMetric("late_create_leak") - leak; delta != 0 {
					t.Errorf("late_create_leak delta=%g want 0", delta)
				}
				if d2cRefs(e, k) != 0 || d2cRefs(e, d2cSynthKey) != 0 {
					t.Error("successful scope readback leaked lock references")
				}
			})
		})
	}
}
