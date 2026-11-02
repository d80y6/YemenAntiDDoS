package action

// Tests for forced XDrop removal.
// C01-C12 are covered here; C13 is in the tests package.
// Reuse d2bFixture / d2bRemote (direct in-memory v3Mock.serve plus the rc2 read-only preflight fake), d2bRow, and d2bCountKind; no listeners.
// Exercise e.ForceRemove, using executeXDrop to seed creates; channels, lock-table ref counts, and synctest time fix interleavings.
// Cases distinguish behavior regressions from guards. Fixture self-check failures use t.Fatalf("device: ...").
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// ---------------------------------------------------------------- store 包装

// d2cStore 在 d2bStore 上补：
//   - ManualOverrides() 的 Create / ListByAttack / Exists（v3Overrides 只有 ListByAttack 且恒空；实施后引擎在锁内写覆盖）；
//   - XDropActiveRules().MarkWithdrawn 计数 + 写前钩子（C03 / C04）；
//   - XDropConnectors().ListEnabled 注错（C09）；
//   - ActionExecLog().Create 写后钩子（C04 创建执行日志写入信号）与写前钩子（C14 日志提交屏障，沿用 C31 装置形状）。
type d2cStore struct {
	*d2bStore
	ovMu           sync.Mutex
	overrides      []store.ActionManualOverride
	writes         map[string]int // "override|<key>" / "withdrawn|<key>" ⇒ 调用次数
	listEnabledErr atomic.Bool
	hkMu           sync.Mutex
	onWrite        func(kind string, k xdropRuleKey) // 覆盖 Create / MarkWithdrawn 落库前调用
	onLog          func(l store.ActionExecutionLog)  // 执行日志落库后调用
	preLog         func(l store.ActionExecutionLog)  // 执行日志落库前调用（可阻塞）
}

const d2cListEnabledErr = "injected d2c list enabled connectors failure"

type d2cOverrides struct{ c *d2cStore }
type d2cRules struct {
	store.XDropActiveRuleRepo
	c *d2cStore
}
type d2cConns struct {
	store.XDropConnectorRepo
	c *d2cStore
}
type d2cLogs struct {
	store.ActionExecLogRepo
	c *d2cStore
}

func (s *d2cStore) ManualOverrides() store.ActionManualOverrideRepo { return d2cOverrides{s} }
func (s *d2cStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2cRules{s.d2bStore.XDropActiveRules(), s}
}
func (s *d2cStore) XDropConnectors() store.XDropConnectorRepo {
	return d2cConns{s.d2bStore.XDropConnectors(), s}
}
func (s *d2cStore) ActionExecLog() store.ActionExecLogRepo {
	return d2cLogs{s.d2bStore.ActionExecLog(), s}
}

func (s *d2cStore) hook() (func(string, xdropRuleKey), func(store.ActionExecutionLog)) {
	s.hkMu.Lock()
	defer s.hkMu.Unlock()
	return s.onWrite, s.onLog
}
func (s *d2cStore) setWriteHook(f func(string, xdropRuleKey)) {
	s.hkMu.Lock()
	s.onWrite = f
	s.hkMu.Unlock()
}
func (s *d2cStore) setPreLogHook(f func(store.ActionExecutionLog)) {
	s.hkMu.Lock()
	s.preLog = f
	s.hkMu.Unlock()
}
func (s *d2cStore) takePreLog() func(store.ActionExecutionLog) {
	s.hkMu.Lock()
	defer s.hkMu.Unlock()
	return s.preLog
}
func (s *d2cStore) setLogHook(f func(store.ActionExecutionLog)) {
	s.hkMu.Lock()
	s.onLog = f
	s.hkMu.Unlock()
}
func (s *d2cStore) countWrite(kind string, k xdropRuleKey) {
	s.ovMu.Lock()
	defer s.ovMu.Unlock()
	if s.writes == nil {
		s.writes = map[string]int{}
	}
	s.writes[kind+"|"+k.String()]++
}
func (s *d2cStore) writeCount(kind string, k xdropRuleKey) int {
	s.ovMu.Lock()
	defer s.ovMu.Unlock()
	return s.writes[kind+"|"+k.String()]
}
func (s *d2cStore) overrideCount(k xdropRuleKey) int {
	s.ovMu.Lock()
	defer s.ovMu.Unlock()
	n := 0
	for _, o := range s.overrides {
		if (xdropRuleKey{o.AttackID, o.ActionID, o.ConnectorID, o.ExternalRuleID}) == k {
			n++
		}
	}
	return n
}

// Create 与 postgres ON CONFLICT 同口径：同业务键幂等，返回既有 ID。
func (r d2cOverrides) Create(_ context.Context, o *store.ActionManualOverride) (int, error) {
	k := xdropRuleKey{o.AttackID, o.ActionID, o.ConnectorID, o.ExternalRuleID}
	r.c.countWrite("override", k)
	if f, _ := r.c.hook(); f != nil {
		f("override", k)
	}
	r.c.ovMu.Lock()
	defer r.c.ovMu.Unlock()
	for _, cur := range r.c.overrides {
		if (xdropRuleKey{cur.AttackID, cur.ActionID, cur.ConnectorID, cur.ExternalRuleID}) == k {
			return cur.ID, nil
		}
	}
	cp := *o
	cp.ID = len(r.c.overrides) + 1
	cp.CreatedAt = time.Now()
	r.c.overrides = append(r.c.overrides, cp)
	return cp.ID, nil
}
func (r d2cOverrides) Exists(_ context.Context, a, b, c int, id string) (bool, error) {
	return r.c.overrideCount(xdropRuleKey{a, b, c, id}) > 0, nil
}
func (r d2cOverrides) ListByAttack(_ context.Context, attackID int) ([]store.ActionManualOverride, error) {
	r.c.ovMu.Lock()
	defer r.c.ovMu.Unlock()
	var out []store.ActionManualOverride
	for _, o := range r.c.overrides {
		if o.AttackID == attackID {
			out = append(out, o)
		}
	}
	return out, nil
}
func (r d2cRules) MarkWithdrawn(ctx context.Context, a, b, c int, id string) error {
	k := xdropRuleKey{a, b, c, id}
	r.c.countWrite("withdrawn", k)
	if f, _ := r.c.hook(); f != nil {
		f("withdrawn", k)
	}
	return r.XDropActiveRuleRepo.MarkWithdrawn(ctx, a, b, c, id)
}
func (r d2cConns) ListEnabled(ctx context.Context) ([]store.XDropConnector, error) {
	if r.c.listEnabledErr.Load() {
		return nil, errors.New(d2cListEnabledErr)
	}
	return r.XDropConnectorRepo.ListEnabled(ctx)
}
func (r d2cLogs) Create(ctx context.Context, l *store.ActionExecutionLog) (int, error) {
	if f := r.c.takePreLog(); f != nil {
		f(*l)
	}
	id, err := r.ActionExecLogRepo.Create(ctx, l)
	if _, f := r.c.hook(); f != nil && err == nil {
		f(*l)
	}
	return id, err
}

// ---------------------------------------------------------------- 装置与入口

func d2cFixture(t *testing.T) (*d2cStore, *Engine, *d2bRemote) {
	t.Helper()
	b, _, x := d2bFixture(t)
	c := &d2cStore{d2bStore: b}
	return c, NewEngine(c, "auto"), x
}

// d2cCreate = d2bCreate，但经 d2cStore（覆盖读写走 d2cOverrides、日志钩子生效）。
func d2cCreate(c *d2cStore, e *Engine, x *d2bRemote, mode, phase string) {
	x.setPost(mode)
	defer x.setPost("")
	a := v3Attack(101, "udp", "198.51.100.7")
	l, _ := executeXDrop(context.Background(), c, c.actions[0], a, "confirmed", a.DstIP, "draft", phase, 101, nil, e)
	if l != nil {
		_, _ = c.ActionExecLog().Create(context.Background(), l)
	}
}

var d2cSynthKey = xdropRuleKey{101, 11, 7, d2bSynthetic}

// d2cSeedReal：真实创建段得真 id 行 R（active、远端本 ref 认领 1）。shared ⇒ 先种另一持有方同身份（R = 其 id，DELETE 本 ref 后规则仍在）。
func d2cSeedReal(t *testing.T, c *d2cStore, e *Engine, x *d2bRemote, shared bool) xdropRuleKey {
	t.Helper()
	other := ""
	if shared {
		other = x.seedOther(t)
	}
	d2cCreate(c, e, x, "", "on_detected")
	var real string
	n := 0
	c.mu.Lock()
	for _, r := range c.rules {
		if r.Status == "active" {
			real = r.ExternalRuleID
			n++
		}
	}
	c.mu.Unlock()
	if n != 1 || real == "" || x.ourClaims() != 1 || shared && real != other {
		t.Fatalf("device: seed real active rows=%d real=%q other=%q ourClaims=%d; want 1 active row with our claim", n, real, other, x.ourClaims())
	}
	return xdropRuleKey{101, 11, 7, real}
}

// d2cSeedSynthetic：创建 POST 以 mode 失败 ⇒ 合成号 S failed + 1 份创建日志。
func d2cSeedSynthetic(t *testing.T, c *d2cStore, e *Engine, x *d2bRemote, mode string) []store.ActionExecutionLog {
	t.Helper()
	d2cCreate(c, e, x, mode, "on_detected")
	logs := d2bCreateLogs(c.d2bStore)
	if len(logs) != 1 || d2bRow(c.d2bStore, d2bSynthetic).Status != "failed" {
		t.Fatalf("device: synthetic seed logs=%d S=%q; want 1 failed create log and failed S row; logs=%s", len(logs), d2bRow(c.d2bStore, d2bSynthetic).Status, d2bLogTexts(c.d2bStore))
	}
	return logs
}

func d2cRow(c *d2cStore, k xdropRuleKey) string { return d2bRow(c.d2bStore, k.rule).Status }

func d2cRefs(e *Engine, k xdropRuleKey) int {
	e.xdropMu.Lock()
	defer e.xdropMu.Unlock()
	if l := e.xdropLocks[k.String()]; l != nil {
		return l.refs
	}
	return 0
}

func d2cRetryEntry(e *Engine, k xdropRuleKey) (xdropRetry, bool) {
	e.xdropMu.Lock()
	defer e.xdropMu.Unlock()
	r, ok := e.xdropRetries[k.String()]
	return r, ok
}

func d2cForce(e *Engine, k xdropRuleKey) error {
	return e.ForceRemove(context.Background(), k.attack, k.action, k.connector, k.rule)
}
func d2cForceAsync(e *Engine, k xdropRuleKey) chan error {
	ch := make(chan error, 1)
	go func() { ch <- d2cForce(e, k) }()
	return ch
}

// d2cAwait：测试自带截止观测强撤是否返回（synctest 假时间；截止只决定「何时看」，判据是返回与否及返回值）。
func d2cAwait(done chan error, deadline time.Duration) (error, bool) {
	select {
	case err := <-done:
		return err, true
	case <-time.After(deadline):
		return nil, false
	}
}

// d2cHold：测试先持 k 的每键锁（与引擎同一锁表）。装置自检：持锁成功且锁表 refs == 1。
func d2cHold(t *testing.T, e *Engine, k xdropRuleKey) func() {
	t.Helper()
	unlock, ok := e.lockXDrop(context.Background(), k, false)
	if !ok {
		t.Fatalf("device: test could not take key lock %s", k)
	}
	if n := d2cRefs(e, k); n != 1 {
		unlock()
		t.Fatalf("device: refs after test lock=%d want 1", n)
	}
	var once sync.Once
	return func() { once.Do(unlock) }
}

func d2cDeletesTo(reqs []d2bReq, rule string) int {
	n := 0
	for _, r := range reqs {
		if d2bKind(r) == "delete" && strings.HasSuffix(r.Path, "/rules/"+rule) {
			n++
		}
	}
	return n
}

func d2cXDropLogCount(c *d2cStore) int {
	n := 0
	for _, l := range c.logSnapshot() {
		if l.ActionType == store.ActionTypeXDrop {
			n++
		}
	}
	return n
}

// 与 metrics.go 预注册的 xsight_xdrop_reconcile_total outcome 闭集逐字一致。
var d2cOutcomes = []string{"candidate", "busy", "backoff", "skipped_live", "skipped_scheduled", "skipped_connector", "skipped_override", "skipped_synthetic", "list_error", "claimed", "withdrawn", "failed", "state_write_error", "synthetic_unrecoverable", "synthetic_identity_not_found", "late_create_leak"}

func d2cReconcileSnapshot() map[string]float64 {
	out := map[string]float64{}
	for _, o := range d2cOutcomes {
		out[o] = d2bReconcileMetric(o)
	}
	return out
}

// A WARN for manual local closure must start with the complete d2cWarnPrefix + S (S immediately follows rule=, then whitespace or end of line),
// and contain one of the three phrases below. Other prefixes or messages, such as `closed locally`, do not count.
const d2cWarnPrefix = "WARN action: xdrop force-remove synthetic rule="

var d2cLocalCloseWords = []string{"cannot be proven absent", "no recoverable create evidence", "no create execution logs"}

// d2cSyntheticWarns：closeLines = 同时匹配「完整前缀 + S」与三种正文之一的行数；
// releasedLines = 提到 S 的任一 WARN 行（不限前缀）含 `released` 的行数。
func d2cSyntheticWarns(text string) (closeLines, releasedLines int) {
	want := d2cWarnPrefix + d2bSynthetic
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "WARN "); i >= 0 && strings.Contains(line[i:], d2bSynthetic) && strings.Contains(line[i:], "released") {
			releasedLines++
		}
		i := strings.Index(line, want)
		if i < 0 {
			continue
		}
		rest := line[i+len(want):]
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			continue // rule= 后不是恰好 S
		}
		for _, w := range d2cLocalCloseWords {
			if strings.Contains(rest, w) {
				closeLines++
				break
			}
		}
	}
	return
}

// ---------------------------------------------------------------- C01–C04 锁与锁内落定

// 〔行为〕C01：测试先持真 id 键 k 的锁；goroutine 调 ForceRemove；以锁表 refs == 2 确认强撤在等。
// 判据：持锁期间 DELETE = 0、强撤未返回、refs == 2；放锁后 DELETE = 1、返回 nil。
// HEAD 红因：xDrop 支不取锁 ⇒ 持锁期间已 DELETE 1、已返回、refs == 1。种子：M01（DELETE 0 / 未返回）、M02（try-lock ⇒ 立即失败返回）。
func TestD2C_C01_ForceWaitsKeyLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		k := d2cSeedReal(t, c, e, x, false)
		release := d2cHold(t, e, k)
		defer release()
		mark := x.mark()
		done := d2cForceAsync(e, k)
		synctest.Wait()
		if d := d2bCountKind(x.since(mark), "delete"); d != 0 {
			t.Errorf("DELETE while key lock held by another holder=%d want 0; reqs=%s", d, d2bDescribe(x.since(mark)))
		}
		returned := false
		select {
		case err := <-done:
			returned = true
			t.Errorf("ForceRemove returned while key lock held (err=%v); want it to wait", err)
		default:
		}
		if n := d2cRefs(e, k); n != 2 {
			t.Errorf("lock refs while held=%d want 2 (holder + waiting force remove)", n)
		}
		release()
		synctest.Wait()
		if !returned {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("ForceRemove after lock released err=%v want nil", err)
				}
			default:
				t.Errorf("ForceRemove did not return after lock released")
			}
		}
		if d := d2bCountKind(x.since(mark), "delete"); d != 1 {
			t.Errorf("DELETE total=%d want 1; reqs=%s", d, d2bDescribe(x.since(mark)))
		}
	})
}

// 〔行为〕C02：连接器 TimeoutMs = 200；测试持锁不放（推进 1s 假时间）。
// 判据：有限时间内返回非 nil 且含 `busy`；DELETE = 0；行状态不变（active）；覆盖 0。
// HEAD 红因：不取锁 ⇒ 立即 DELETE 1、返回 nil。种子：M03（用调用方 ctx 等锁 ⇒ 推进 1s 后仍未返回）。
func TestD2C_C02_ForceLockTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		c.mu.Lock()
		c.conn.TimeoutMs = 200
		c.mu.Unlock()
		k := d2cSeedReal(t, c, e, x, false)
		release := d2cHold(t, e, k)
		defer release()
		mark := x.mark()
		done := d2cForceAsync(e, k)
		// 测试自带截止（1s = 5 × TimeoutMs，synctest 假时间）观测返回；业务 ctx 仍是不取消的 Background（同生产 gin ctx）。
		err, returned := d2cAwait(done, time.Second)
		if !returned {
			t.Errorf("ForceRemove still waiting 1s after start with TimeoutMs=200 (lock wait must be bounded by connector timeout)")
		}
		if returned && (err == nil || !strings.Contains(err.Error(), "busy")) {
			t.Errorf("ForceRemove err=%v; want non-nil containing \"busy\"", err)
		}
		if d := d2bCountKind(x.since(mark), "delete"); d != 0 {
			t.Errorf("DELETE while lock held=%d want 0; reqs=%s", d, d2bDescribe(x.since(mark)))
		}
		if st := d2cRow(c, k); st != "active" {
			t.Errorf("row status=%s want active (unchanged)", st)
		}
		if n := c.overrideCount(k); n != 0 {
			t.Errorf("overrides=%d want 0", n)
		}
		release() // 释放测试锁并回收 goroutine（M03 下它此刻才拿到锁）
		synctest.Wait()
		if !returned {
			<-done
		}
	})
}

// 〔行为〕C03：记录型 store：ManualOverrides().Create / XDropActiveRules().MarkWithdrawn 被调用时在回调里对 k 做 try-lock。
// 判据：强撤成功后两者由引擎（本格直调 e.ForceRemove，无 API）各调 1 次，且两次 try-lock 都失败（锁仍被强撤持有）。
// HEAD 红因：引擎不写覆盖 / withdrawn ⇒ 调用 0 次。种子：M04（写挪到解锁后 ⇒ try-lock 成功）、M05（只留 API 写 ⇒ 0 次）。
func TestD2C_C03_CommitUnderLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		k := d2cSeedReal(t, c, e, x, false)
		var mu sync.Mutex
		free := map[string]int{}
		var probeAnomaly []string
		// Probe with an independent uncanceled ctx, a running engine, and no third lock holder (lock-table refs <= 1, only forced removal itself); unlock immediately if the probe unexpectedly succeeds.
		c.setWriteHook(func(kind string, got xdropRuleKey) {
			if got != k {
				return
			}
			probe := context.Background()
			if e.xdropStopped(probe) {
				mu.Lock()
				probeAnomaly = append(probeAnomaly, kind+": engine stopped")
				mu.Unlock()
				return
			}
			if n := d2cRefs(e, got); n > 1 {
				mu.Lock()
				probeAnomaly = append(probeAnomaly, fmt.Sprintf("%s: refs=%d (third holder/waiter)", kind, n))
				mu.Unlock()
				return
			}
			if unlock, ok := e.lockXDrop(probe, got, true); ok {
				unlock()
				mu.Lock()
				free[kind]++
				mu.Unlock()
			}
		})
		if err := d2cForce(e, k); err != nil {
			t.Fatalf("ForceRemove err=%v want nil (DELETE 204 expected)", err)
		}
		mu.Lock()
		anomaly := append([]string(nil), probeAnomaly...)
		mu.Unlock()
		if len(anomaly) > 0 {
			t.Fatalf("device: try-lock probe preconditions violated: %v", anomaly)
		}
		for _, kind := range []string{"override", "withdrawn"} {
			if n := c.writeCount(kind, k); n != 1 {
				t.Errorf("engine %s writes for %s=%d want 1", kind, k, n)
			}
			mu.Lock()
			f := free[kind]
			mu.Unlock()
			if f != 0 {
				t.Errorf("%s write happened with key lock free (%d times); want written while force remove still holds the lock", kind, f)
			}
		}
		if st := d2cRow(c, k); st != "withdrawn" {
			t.Errorf("row status=%s want withdrawn", st)
		}
	})
}

// 〔行为〕C04（I-4）：live 攻击、真 id 行 R active、远端本 ref 认领 1（另一持有方共享身份 ⇒ DELETE 本 ref 后规则仍在、重建回同 id）。
// 假 XDrop 的屏障只装在**第一次** DELETE 上（delOnce；补撤 DELETE 直通），位置在 x.roundTrip 返回之后——此时 v3Mock.serve 已完成远端修改
// 并释放假远端互斥 m.mu——回 204 之前：起 goroutine 跑一次该攻击的周期创建（executeXDrop on_detected），只等其「创建执行日志已提交」信号
// （d2cLogs.Create 落库后钩子），⛔ 等整个 goroutine（它随后要等强撤持有的键锁）。强撤返回后再等创建 goroutine 结束。
// 引擎写覆盖 / withdrawn 前的钩子：等「创建 goroutine 结束」或 100ms 假时间（取先到者）——把 M04 的坏序（创建回读抢在锁外写之前）钉成确定；
// 正确实现下创建回读被锁挡住，钩子 100ms 后放行（假时间推进只在全体阻塞时发生，判据不靠它）。
// 判据：强撤返回 nil；创建 goroutine 结束后：远端本 ref 认领 0、另一 ref 认领仍 1、R 行 withdrawn、额外补撤 DELETE 1（DELETE 总 2）、创建 POST 1。
// 装置自检：强撤前 R 认领 2；结束后远端只有 R（迟到 POST 拿回同一 R）。
// HEAD 红因：引擎不取锁不写 ⇒ 回读见 active 不补撤 ⇒ 认领 1、行 active、DELETE 1。种子：M04、M05。
func TestD2C_C04_LateCreateDuringForce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		c.live = true
		k := d2cSeedReal(t, c, e, x, true)
		createLogged, createDone := make(chan struct{}), make(chan struct{})
		var logOnce, delOnce sync.Once
		var parked atomic.Bool
		c.setLogHook(func(l store.ActionExecutionLog) {
			if l.ExternalRuleID == k.rule && l.Status == "success" && l.TriggerPhase == "on_detected" {
				logOnce.Do(func() { close(createLogged) })
			}
		})
		c.setWriteHook(func(_ string, got xdropRuleKey) {
			if got != k {
				return
			}
			select {
			case <-createDone:
			case <-time.After(100 * time.Millisecond):
			}
		})
		d2HTTP(t, func(r *http.Request) (*http.Response, error) {
			resp, err := x.roundTrip(r)
			if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/rules/"+k.rule) {
				delOnce.Do(func() {
					go func() {
						defer close(createDone)
						d2cCreate(c, e, x, "", "on_detected")
					}()
					select {
					case <-createLogged:
						parked.Store(true)
					case <-time.After(30 * time.Second):
					}
				})
			}
			return resp, err
		})
		mark := x.mark()
		if x.m.claimCount(k.rule) != 2 {
			t.Fatalf("device: R claims=%d want 2 (ours + other holder)", x.m.claimCount(k.rule))
		}
		err := d2cForce(e, k)
		if !parked.Load() {
			t.Fatalf("device: periodic create did not write its execution log while the force DELETE was in flight; err=%v reqs=%s", err, d2bDescribe(x.since(mark)))
		}
		if err != nil {
			t.Errorf("ForceRemove err=%v want nil", err)
		}
		synctest.Wait()
		select {
		case <-createDone:
		default:
			t.Fatalf("periodic create goroutine did not finish after force remove returned")
		}
		reqs := x.since(mark)
		if ids := x.ruleIDs(); len(ids) != 1 || ids[0] != k.rule {
			t.Fatalf("device: remote rules=%v; want only R=%s (late POST must land on the same identity)", ids, k.rule)
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our remote claims after force + racing create=%d want 0 (I-4 leak)", n)
		}
		if n := x.m.claimCount(k.rule) - x.ourClaims(); n != 1 {
			t.Errorf("other holder claims on R=%d want 1 (untouched)", n)
		}
		if st := d2cRow(c, k); st != "withdrawn" {
			t.Errorf("row status=%s want withdrawn", st)
		}
		if d := d2bCountKind(reqs, "delete"); d != 2 {
			t.Errorf("DELETE total=%d want 2 (force + late-create readback release); reqs=%s", d, d2bDescribe(reqs))
		}
		if p := d2bCountKind(reqs, "create"); p != 1 {
			t.Errorf("create POST=%d want 1; reqs=%s", p, d2bDescribe(reqs))
		}
	})
}

// ---------------------------------------------------------------- C05–C08、C10 合成号

// 〔行为〕C05：live 攻击；S failed + 1 份 Uncertain 创建日志（lost：远端按 body 身份已建 R 且持本 ref、R 无本地行）。
// 判据：validate 1、DELETE /rules/R?claim_ref=a101.x11 = 1、对 failed-create-* 的 DELETE 0、POST /rules 0；本 ref 认领 0；S withdrawn；S 覆盖 1。
// HEAD 红因：直接 DELETE failed-create-*（替身 204）⇒ validate 0、空释放、认领 1、S 仍 failed、覆盖 0。种子：M06、M07（保留 live 门 ⇒ skipped_live）。
func TestD2C_C05_SyntheticForceRecovers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		c.live = true
		logs := d2cSeedSynthetic(t, c, e, x, "lost")
		ids := x.ruleIDs()
		if len(ids) != 1 || x.ourClaims() != 1 {
			t.Fatalf("device: remote rules=%v ourClaims=%d; want one real rule R holding our ref", ids, x.ourClaims())
		}
		real := ids[0]
		mark := x.mark()
		if err := d2cForce(e, d2cSynthKey); err != nil {
			t.Errorf("ForceRemove(S) err=%v want nil", err)
		}
		reqs := x.since(mark)
		d2bRecoveryCheck(t, reqs, 1, 1, d2bBodies(logs))
		if n := d2cDeletesTo(reqs, real); n != 1 {
			t.Errorf("DELETE /rules/%s=%d want 1; reqs=%s", real, n, d2bDescribe(reqs))
		}
		if n := d2cDeletesTo(reqs, d2bSynthetic); n != 0 {
			t.Errorf("DELETE on synthetic id=%d want 0; reqs=%s", n, d2bDescribe(reqs))
		}
		if n := d2bCountKind(reqs, "create"); n != 0 {
			t.Errorf("POST /rules=%d want 0", n)
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our remote claims=%d want 0", n)
		}
		if st := d2cRow(c, d2cSynthKey); st != "withdrawn" {
			t.Errorf("S status=%s want withdrawn", st)
		}
		if n := c.overrideCount(d2cSynthKey); n != 1 {
			t.Errorf("S overrides=%d want 1", n)
		}
	})
}

// 〔行为〕C06：同 C05，但 R 有 active 真行（先正常创建得 R，再 lost 创建同身份 ⇒ S failed + Uncertain，本 ref 认领仍 1 份）。
// 判据：validate 1、DELETE 0；S withdrawn；S 覆盖 1；R 行仍 active；远端本 ref 认领仍 1。
// HEAD 红因：DELETE failed-create-* 1、validate 0、S 仍 failed。种子：M08（已归真行仍 DELETE ⇒ DELETE 1、认领 0）。
func TestD2C_C06_SyntheticForceOwnedByReal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		c.live = true
		rk := d2cSeedReal(t, c, e, x, false)
		logs := d2cSeedSynthetic(t, c, e, x, "lost")
		if x.ourClaims() != 1 || d2cRow(c, rk) != "active" {
			t.Fatalf("device: ourClaims=%d R=%s; want 1 / active", x.ourClaims(), d2cRow(c, rk))
		}
		mark := x.mark()
		if err := d2cForce(e, d2cSynthKey); err != nil {
			t.Errorf("ForceRemove(S) err=%v want nil", err)
		}
		reqs := x.since(mark)
		d2bRecoveryCheck(t, reqs, 1, 0, d2bBodies(logs))
		if st := d2cRow(c, d2cSynthKey); st != "withdrawn" {
			t.Errorf("S status=%s want withdrawn", st)
		}
		if n := c.overrideCount(d2cSynthKey); n != 1 {
			t.Errorf("S overrides=%d want 1", n)
		}
		if st := d2cRow(c, rk); st != "active" {
			t.Errorf("R status=%s want active (owned by real row, untouched)", st)
		}
		if n := x.ourClaims(); n != 1 {
			t.Errorf("our remote claims=%d want 1 (left to R)", n)
		}
	})
}

// 〔行为〕C07：三子格 not_found（drop：远端未建 ⇒ 预检不存在）/ truncated（1024B 截断 body）/ missing（无创建日志）。
// 判据：DELETE 0；返回 nil；S withdrawn；S 覆盖 1；新增 xdrop 执行日志 0；xsight_xdrop_reconcile_total 各 outcome 不变；
// WARN 服务日志（v0.2b §4-2-3）：至少 1 行以完整前缀 `WARN action: xdrop force-remove synthetic rule=<S>` 开头且正文含
// `cannot be proven absent` / `no recoverable create evidence` / `no create execution logs` 之一；提到 S 的 WARN 行 ⛔ 含 `released`。
// HEAD 红因：DELETE failed-create-* 1、S 仍 failed。种子：M06（DELETE 1）、M09（写 xdrop 日志 / 计 synthetic_identity_not_found、synthetic_unrecoverable）。
func TestD2C_C07_SyntheticForceNoProof(t *testing.T) {
	// Fixture self-check: negative and positive WARN matcher controls cover two invalid messages, an extra character after the prefix, a valid match, and released counts.
	for _, tc := range []struct {
		line            string
		close, released int
	}{
		{"2000/01/01 08:00:00 WARN action: xdrop synthetic rule=" + d2bSynthetic + " closed locally", 0, 0},
		{"2000/01/01 08:00:00 WARN action: xdrop force-remove synthetic rule=" + d2bSynthetic + " closed locally", 0, 0},
		{"2000/01/01 08:00:00 WARN action: xdrop force-remove synthetic rule=" + d2bSynthetic + "1 claim cannot be proven absent", 0, 0},
		{"2000/01/01 08:00:00 WARN action: xdrop force-remove synthetic rule=" + d2bSynthetic + " identity not found; claim cannot be proven absent", 1, 0},
		{"2000/01/01 08:00:00 WARN action: xdrop force-remove synthetic rule=" + d2bSynthetic + " no create execution logs; released rule x", 1, 1},
	} {
		if c, r := d2cSyntheticWarns(tc.line); c != tc.close || r != tc.released {
			t.Fatalf("device: WARN matcher on %q = close %d released %d; want %d / %d", tc.line, c, r, tc.close, tc.released)
		}
	}
	for _, kind := range []string{"not_found", "truncated", "missing"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, e, x := d2cFixture(t)
				c.live = true
				switch kind {
				case "not_found":
					d2cSeedSynthetic(t, c, e, x, "drop")
					if len(x.ruleIDs()) != 0 {
						t.Fatalf("device: remote rules=%v want none", x.ruleIDs())
					}
				case "truncated":
					c.actions[0].XDropCustomPayload = json.RawMessage(`{"dst_ip":"198.51.100.7","action":"drop","comment":"` + strings.Repeat("c", 1500) + `"}`)
					logs := d2cSeedSynthetic(t, c, e, x, "lost")
					if json.Valid([]byte(logs[0].RequestBody)) || len(logs[0].RequestBody) != 1024 {
						t.Fatalf("device: want one truncated (1024B, invalid JSON) body; len=%d", len(logs[0].RequestBody))
					}
				case "missing":
					if _, err := c.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: d2bSynthetic, Status: "failed", ErrorMessage: "HTTP POST <url>: request timed out"}); err != nil {
						t.Fatalf("device: seed missing-evidence S row: %v", err)
					}
					if n := len(d2bCreateLogs(c.d2bStore)); n != 0 || d2cRow(c, d2cSynthKey) != "failed" {
						t.Fatalf("device: create logs=%d S=%s; want 0 / failed", n, d2cRow(c, d2cSynthKey))
					}
				}
				logsBefore := d2cXDropLogCount(c)
				metricsBefore := d2cReconcileSnapshot()
				mark := x.mark()
				captured := d2R4Capture(t)
				if err := d2cForce(e, d2cSynthKey); err != nil {
					t.Errorf("%s ForceRemove(S) err=%v want nil", kind, err)
				}
				if n := c.overrideCount(d2cSynthKey); n != 1 {
					t.Errorf("%s S overrides=%d want 1", kind, n)
				}
				closeLines, releasedLines := d2cSyntheticWarns(captured.text())
				if closeLines == 0 {
					t.Errorf("%s WARN lines with prefix %q and a local-close note %v = 0; want >=1; log=%q", kind, d2cWarnPrefix+d2bSynthetic, d2cLocalCloseWords, captured.text())
				}
				if releasedLines != 0 {
					t.Errorf("%s WARN lines naming %s that claim `released` = %d; want 0 (nothing was proven released); log=%q", kind, d2bSynthetic, releasedLines, captured.text())
				}
				reqs := x.since(mark)
				if d := d2bCountKind(reqs, "delete"); d != 0 {
					t.Errorf("%s DELETE=%d want 0; reqs=%s", kind, d, d2bDescribe(reqs))
				}
				if st := d2cRow(c, d2cSynthKey); st != "withdrawn" {
					t.Errorf("%s S status=%s want withdrawn", kind, st)
				}
				if n := d2cXDropLogCount(c) - logsBefore; n != 0 {
					t.Errorf("%s new xdrop execution logs=%d want 0 (manual mode records via manual_override only); logs=%s", kind, n, d2bLogTexts(c.d2bStore))
				}
				after := d2cReconcileSnapshot()
				for _, o := range d2cOutcomes {
					if d := after[o] - metricsBefore[o]; d != 0 {
						t.Errorf("%s xsight_xdrop_reconcile_total{outcome=%q} delta=%g want 0", kind, o, d)
					}
				}
			})
		})
	}
}

// 〔行为〕C08：预检 503。判据：返回非 nil；DELETE 0；S 仍 failed；覆盖 0。
// HEAD 红因：不预检、DELETE failed-create-* 204 ⇒ 返回 nil、DELETE 1。种子：M10（预检失败当成功 ⇒ nil / withdrawn / 覆盖 1）。
func TestD2C_C08_SyntheticForceValidateFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		c.live = true
		d2cSeedSynthetic(t, c, e, x, "lost")
		x.setValidate("503")
		mark := x.mark()
		if err := d2cForce(e, d2cSynthKey); err == nil {
			t.Errorf("ForceRemove(S) err=nil; want failure when validate returns 503")
		}
		reqs := x.since(mark)
		if d := d2bCountKind(reqs, "delete"); d != 0 {
			t.Errorf("DELETE=%d want 0; reqs=%s", d, d2bDescribe(reqs))
		}
		if st := d2cRow(c, d2cSynthKey); st != "failed" {
			t.Errorf("S status=%s want failed (unchanged)", st)
		}
		if n := c.overrideCount(d2cSynthKey); n != 0 {
			t.Errorf("S overrides=%d want 0", n)
		}
	})
}

// 〔行为〕C10：S failed + Uncertain（lost ⇒ R 有效、无真行）；连接器 TimeoutMs = 100（真键等锁预算 2 × 100ms）；测试持 R 锁不放，
// 用测试自带截止（1s 假时间）观测返回，随后释放测试锁并回收 goroutine。
// 判据：有限时间内返回非 nil 且文案含 `busy`；DELETE 0；S 仍 failed；S 覆盖 0。
// HEAD 红因：DELETE failed-create-* 204 ⇒ 立即返回 nil、DELETE 1。种子：M12（真键 busy 当成功 ⇒ nil、S withdrawn、覆盖 1）。
func TestD2C_C10_SyntheticForceRealBusy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		c.live = true
		c.mu.Lock()
		c.conn.TimeoutMs = 100
		c.mu.Unlock()
		d2cSeedSynthetic(t, c, e, x, "lost")
		ids := x.ruleIDs()
		if len(ids) != 1 {
			t.Fatalf("device: remote rules=%v want one", ids)
		}
		rk := xdropRuleKey{101, 11, 7, ids[0]}
		release := d2cHold(t, e, rk)
		defer release()
		mark := x.mark()
		done := d2cForceAsync(e, d2cSynthKey)
		err, returned := d2cAwait(done, time.Second) // 远超 S 等锁 100ms + 预检 + 真键 2×100ms
		if !returned {
			t.Errorf("ForceRemove(S) still waiting 1s after start; real-key lock wait must be bounded")
		} else if err == nil || !strings.Contains(err.Error(), "busy") {
			t.Errorf("ForceRemove(S) err=%v; want non-nil containing \"busy\" while real key %s lock is held", err, rk.rule)
		}
		if d := d2bCountKind(x.since(mark), "delete"); d != 0 {
			t.Errorf("DELETE=%d want 0; reqs=%s", d, d2bDescribe(x.since(mark)))
		}
		if st := d2cRow(c, d2cSynthKey); st != "failed" {
			t.Errorf("S status=%s want failed (unchanged)", st)
		}
		if n := c.overrideCount(d2cSynthKey); n != 0 {
			t.Errorf("S overrides=%d want 0", n)
		}
		release() // 释放测试锁并回收 goroutine
		synctest.Wait()
		if !returned {
			<-done
		}
	})
}

// ---------------------------------------------------------------- C09 ListEnabled

// 〔行为〕C09：ListEnabled 返回错误。判据：返回错误含该底层错误、⛔ 含 `not found or disabled`；0 HTTP。
// HEAD 红因：错误被吞 ⇒ `xdrop connector 7 not found or disabled`。种子：M11。
func TestD2C_C09_ListEnabledError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		k := d2cSeedReal(t, c, e, x, false)
		c.listEnabledErr.Store(true)
		mark := x.mark()
		err := d2cForce(e, k)
		if err == nil || !strings.Contains(err.Error(), d2cListEnabledErr) {
			t.Errorf("ForceRemove err=%v; want it to carry %q", err, d2cListEnabledErr)
		}
		if err != nil && strings.Contains(err.Error(), "not found or disabled") {
			t.Errorf("ForceRemove err=%q; a connector DB failure must not read as `not found or disabled`", err)
		}
		if reqs := x.since(mark); len(reqs) != 0 {
			t.Errorf("HTTP=%d want 0; reqs=%s", len(reqs), d2bDescribe(reqs))
		}
	})
}

// ---------------------------------------------------------------- C11–C12 守卫

// 〔守卫〕C11：k 在退避中（xdropRetries 未到期）。判据：仍 DELETE 1、返回 nil。HEAD 绿。种子：M14（读退避并跳过）。
func TestD2C_C11_ForceIgnoresBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		k := d2cSeedReal(t, c, e, x, false)
		e.xdropAttemptFinished(k, false, time.Now())
		if !e.xdropBackoff(k) {
			t.Fatalf("device: key %s not in backoff after recorded failure", k)
		}
		mark := x.mark()
		if err := d2cForce(e, k); err != nil {
			t.Errorf("ForceRemove during backoff err=%v want nil", err)
		}
		if d := d2bCountKind(x.since(mark), "delete"); d != 1 {
			t.Errorf("DELETE during backoff=%d want 1; reqs=%s", d, d2bDescribe(x.since(mark)))
		}
	})
}

// 〔守卫〕C12：DELETE 503。判据：返回 error 文本 = deleteXDropClaim 原错误（逐字）；退避表无 k；新增 xdrop 执行日志 0；行状态不变；覆盖 0。
// HEAD 绿。种子：M13（失败记退避）。
func TestD2C_C12_ForceFailureNoSideEffects(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, e, x := d2cFixture(t)
		k := d2cSeedReal(t, c, e, x, false)
		x.setDelete("503")
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		want := deleteXDropClaim(conn, k)
		if want.Error == nil || x.ourClaims() != 1 {
			t.Fatalf("device: reference DELETE err=%v ourClaims=%d; want 503 error and claim kept", want.Error, x.ourClaims())
		}
		if _, ok := d2cRetryEntry(e, k); ok {
			t.Fatalf("device: backoff entry exists before force remove")
		}
		logsBefore := d2cXDropLogCount(c)
		mark := x.mark()
		err := d2cForce(e, k)
		if err == nil || err.Error() != want.Error.Error() {
			t.Errorf("ForceRemove err=%v; want exactly %q", err, want.Error.Error())
		}
		if d := d2bCountKind(x.since(mark), "delete"); d != 1 {
			t.Errorf("DELETE=%d want 1", d)
		}
		if r, ok := d2cRetryEntry(e, k); ok {
			t.Errorf("backoff entry after failed force remove=%+v; want none", r)
		}
		if n := d2cXDropLogCount(c) - logsBefore; n != 0 {
			t.Errorf("new xdrop execution logs=%d want 0; logs=%s", n, d2bLogTexts(c.d2bStore))
		}
		if st := d2cRow(c, k); st != "active" {
			t.Errorf("row status=%s want active (unchanged)", st)
		}
		if n := c.overrideCount(k); n != 0 {
			t.Errorf("overrides=%d want 0", n)
		}
	})
}

// ---------------------------------------------------------------- v0.2a 新增 C14–C16

// d2cNotSentCreate：连接器 URL 临时带控制字符 ⇒ 真实 NewRequest 失败（NotSent，`create request:`），S failed + 1 份不可恢复证据。
func d2cNotSentCreate(c *d2cStore, e *Engine, x *d2bRemote) {
	c.mu.Lock()
	good := c.conn.APIURL
	c.conn.APIURL = good + "\x7f"
	c.mu.Unlock()
	d2cCreate(c, e, x, "", "on_detected")
	c.mu.Lock()
	c.conn.APIURL = good
	c.mu.Unlock()
}

// 〔行为〕C14_LateFailureAfterForce（N1）：live 攻击；S failed，历史证据只有 NotSent。一次周期创建（lost，phase=updated）已在远端提交本 ref，
// 其失败执行日志在落库前被屏障挡住（d2cStore.preLog，沿用 C31 装置形状）；此时强撤 S（只看得到 NotSent 证据 ⇒ 本地关闭成功），再放行日志提交 ⇒
// xdropAfterCreate 回读 S withdrawn 走补撤。
// 子格 no_real_row：R 无真行、无调度 ⇒ 判据：强撤返回 nil；创建回读完成后本 ref 认领 0、补撤 DELETE /rules/R?claim_ref=a101.x11 = 1、
// S 保持 withdrawn、late_create_leak 增量 0。
// 子格 real_active：R 有 active 真行 ⇒ 判据：强撤返回 nil；DELETE 0（强撤起算）、R 行 active、本 ref 认领仍 1、S withdrawn。
// HEAD 红因：强撤 DELETE failed-create-*、不写 withdrawn ⇒ 回读见 S failed 不补撤（no_real_row 认领 1）；real_active DELETE 1、S failed。
// 种子：M15（迟到回读不识别人工覆盖 ⇒ 自动模式 skipped_live ⇒ no_real_row 认领 1、leak +1）。
func TestD2C_C14_LateFailureAfterForce(t *testing.T) {
	for _, kind := range []string{"no_real_row", "real_active"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, e, x := d2cFixture(t)
				c.live = true
				var rk xdropRuleKey
				if kind == "real_active" {
					rk = d2cSeedReal(t, c, e, x, false)
				}
				d2cNotSentCreate(c, e, x)
				logs := d2bCreateLogs(c.d2bStore)
				if len(logs) != 1 || logs[0].StatusCode != nil || !strings.HasPrefix(logs[0].ErrorMessage, "create request:") || d2cRow(c, d2cSynthKey) != "failed" {
					t.Fatalf("device: want one NotSent create log and failed S; logs=%s S=%s", d2bLogTexts(c.d2bStore), d2cRow(c, d2cSynthKey))
				}
				entered, resume := make(chan struct{}), make(chan struct{})
				var enterOnce, resumeOnce sync.Once
				release := func() { resumeOnce.Do(func() { close(resume) }) }
				defer release()
				c.setPreLogHook(func(l store.ActionExecutionLog) {
					if l.ExternalRuleID == d2bSynthetic && l.Status == "failed" && l.TriggerPhase == "updated" {
						enterOnce.Do(func() { close(entered); <-resume })
					}
				})
				done := make(chan struct{})
				go func() {
					defer close(done)
					d2cCreate(c, e, x, "lost", "updated")
				}()
				select {
				case <-entered:
				case <-time.After(30 * time.Second):
					t.Fatalf("device: late failed create did not reach the log-commit barrier")
				}
				ids := x.ruleIDs()
				if x.ourClaims() != 1 || len(ids) != 1 || kind == "real_active" && ids[0] != rk.rule {
					t.Fatalf("device: remote rules=%v ourClaims=%d; want one rule R holding our ref before force", ids, x.ourClaims())
				}
				real := ids[0]
				leak := d2bReconcileMetric("late_create_leak")
				mark := x.mark()
				if err := d2cForce(e, d2cSynthKey); err != nil {
					t.Errorf("ForceRemove(S) err=%v want nil (only NotSent evidence visible)", err)
				}
				release()
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatalf("late failed create did not finish after its log commit was released")
				}
				reqs := x.since(mark)
				if st := d2cRow(c, d2cSynthKey); st != "withdrawn" {
					t.Errorf("S status=%s want withdrawn", st)
				}
				if kind == "real_active" {
					if d := d2bCountKind(reqs, "delete"); d != 0 {
						t.Errorf("DELETE=%d want 0 (claim owned by active real row); reqs=%s", d, d2bDescribe(reqs))
					}
					if st := d2cRow(c, rk); st != "active" {
						t.Errorf("R status=%s want active", st)
					}
					if n := x.ourClaims(); n != 1 {
						t.Errorf("our remote claims=%d want 1 (left to R)", n)
					}
					return
				}
				if n := x.ourClaims(); n != 0 {
					t.Errorf("our remote claims after late failed create=%d want 0", n)
				}
				n := 0
				for _, r := range reqs {
					if d2bKind(r) == "delete" && strings.HasSuffix(r.Path, "/rules/"+real) && r.Ref == d2bRef {
						n++
					}
				}
				if n != 1 {
					t.Errorf("DELETE /rules/%s?claim_ref=%s = %d want 1; reqs=%s", real, d2bRef, n, d2bDescribe(reqs))
				}
				if d := d2bReconcileMetric("late_create_leak") - leak; d != 0 {
					t.Errorf("late_create_leak delta=%g want 0", d)
				}
			})
		})
	}
}

// 〔行为〕C15_SyntheticForceConnectorDisabledMidway（N2）：live 攻击；S 有合格 Uncertain 证据（lost）、R 无真行。
// 假 XDrop 在预检应答返回之后（x.roundTrip 已完成）把连接器改为停用（d2bStore.getDisabled ⇒ 真键锁内 XDropConnectors().Get 见 Enabled=false；
// 入口 ListEnabled 已在之前通过）。
// 子格 single：判据 validate 1、DELETE 0；返回非 nil；S 仍 failed；S 覆盖 0。种子：M16（manual 下 skipped_connector 当成功）。
// 子格 multi_body（M17 专属）：两份不同身份的 Uncertain body（dst_port 53 / 123 ⇒ R1、R2）；第 1 次预检后停用、第 2 次预检后重新启用
// ⇒ 前份 skipped_connector、后份可释放成功。判据：返回非 nil；S 仍 failed；S 覆盖 0；本 ref 认领 ≥ 1（R1 未释放）。validate / DELETE 次数不钉
// （实现可在首份失败后短路）。种子：M17（多 body 后份成功覆盖前份失败 ⇒ nil、S withdrawn、覆盖 1）。
// HEAD 红因：不预检、DELETE failed-create-* 204 ⇒ 返回 nil。
func TestD2C_C15_SyntheticForceConnectorDisabledMidway(t *testing.T) {
	for _, kind := range []string{"single", "multi_body"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, e, x := d2cFixture(t)
				c.live = true
				var logs []store.ActionExecutionLog
				if kind == "single" {
					logs = d2cSeedSynthetic(t, c, e, x, "lost")
					if len(x.ruleIDs()) != 1 || x.ourClaims() != 1 {
						t.Fatalf("device: remote rules=%v ourClaims=%d; want one R holding our ref", x.ruleIDs(), x.ourClaims())
					}
				} else {
					for _, port := range []int{53, 123} {
						c.actions[0].XDropCustomPayload = json.RawMessage(fmt.Sprintf(`{"dst_ip":"198.51.100.7","dst_port":%d,"action":"drop"}`, port))
						d2cCreate(c, e, x, "lost", "on_detected")
					}
					logs = d2bCreateLogs(c.d2bStore)
					if len(logs) != 2 || len(d2bBodies(logs)) != 2 || len(x.ruleIDs()) != 2 || x.ourClaims() != 2 || d2cRow(c, d2cSynthKey) != "failed" {
						t.Fatalf("device: logs=%d bodies=%d rules=%v ourClaims=%d S=%s; want 2/2/2 rules/2/failed", len(logs), len(d2bBodies(logs)), x.ruleIDs(), x.ourClaims(), d2cRow(c, d2cSynthKey))
					}
				}
				var validates atomic.Int32
				d2HTTP(t, func(r *http.Request) (*http.Response, error) {
					resp, err := x.roundTrip(r)
					if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rules/batch") && r.URL.Query().Get("validate") == "1" {
						switch validates.Add(1) {
						case 1:
							c.getDisabled.Store(true)
						case 2:
							c.getDisabled.Store(false)
						}
					}
					return resp, err
				})
				mark := x.mark()
				err := d2cForce(e, d2cSynthKey)
				reqs := x.since(mark)
				if err == nil {
					t.Errorf("ForceRemove(S) err=nil; want failure when the connector was disabled before the real-key re-read")
				}
				if st := d2cRow(c, d2cSynthKey); st != "failed" {
					t.Errorf("S status=%s want failed (unchanged)", st)
				}
				if n := c.overrideCount(d2cSynthKey); n != 0 {
					t.Errorf("S overrides=%d want 0", n)
				}
				if kind == "single" {
					d2bRecoveryCheck(t, reqs, 1, 0, d2bBodies(logs))
					if n := x.ourClaims(); n != 1 {
						t.Errorf("our remote claims=%d want 1 (not released)", n)
					}
					return
				}
				if n := x.ourClaims(); n < 1 {
					t.Errorf("our remote claims=%d want >=1 (R1 behind the disabled connector not released)", n)
				}
				t.Logf("multi_body validate=%d DELETE=%d err=%v", d2bCountKind(reqs, "validate"), d2bCountKind(reqs, "delete"), err)
			})
		})
	}
}

// C16_ForceStopOrCancelled：两子格。判据：返回非 nil；HTTP 0；行不变（active）；覆盖 0。
// 子格 cancelled：调用方 ctx 已取消（HEAD 在 DELETE 前查 ctx.Err() ⇒ 预期绿 = 守卫）。
// 子格 stopped：引擎已停机（经生产入口 RunXDropReconcile 起停，xdropContext 已取消；HEAD 不看停机 ⇒ 预期红 = 行为）。
// 实测标签见 head-gates.txt。
func TestD2C_C16_ForceStopOrCancelled(t *testing.T) {
	for _, kind := range []string{"cancelled", "stopped"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, e, x := d2cFixture(t)
				c.live = true // 停机子格起停对账一轮时攻击 live ⇒ 对账不碰 R
				k := d2cSeedReal(t, c, e, x, false)
				ctx := context.Background()
				if kind == "cancelled" {
					cctx, cancel := context.WithCancel(ctx)
					cancel()
					ctx = cctx
				} else {
					before := x.mark()
					stop := d2Start(t, e)
					stop()
					synctest.Wait()
					if !e.xdropStopped(context.Background()) || len(x.since(before)) != 0 {
						t.Fatalf("device: engine stopped=%t reconcile HTTP=%d; want stopped and 0 HTTP", e.xdropStopped(context.Background()), len(x.since(before)))
					}
				}
				mark := x.mark()
				err := e.ForceRemove(ctx, k.attack, k.action, k.connector, k.rule)
				if err == nil {
					t.Errorf("%s ForceRemove err=nil; want failure", kind)
				}
				if reqs := x.since(mark); len(reqs) != 0 {
					t.Errorf("%s HTTP=%d want 0; reqs=%s", kind, len(reqs), d2bDescribe(reqs))
				}
				if st := d2cRow(c, k); st != "active" {
					t.Errorf("%s row status=%s want active (unchanged)", kind, st)
				}
				if n := c.overrideCount(k); n != 0 {
					t.Errorf("%s overrides=%d want 0", kind, n)
				}
			})
		})
	}
}
