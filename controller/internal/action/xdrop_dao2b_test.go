package action

// Tests for XDrop creation, recovery, reconciliation, and withdrawal behavior.
// All HTTP uses the in-memory RoundTripper (d2HTTP); the remote calls v3Mock.serve directly, without listeners.
// Behavior is exercised through executeXDrop (create/unblock), HandleEvent, RunXDropReconcile / reconcileXDropRound,
// RecoverScheduledActions, executeRecoveredXDropUnblock, withdrawXDropLocked (C19 only), metrics, and store queries.
// Cases distinguish behavior regressions from guards for existing behavior.
import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	d2bRef       = "a101.x11"
	d2bSynthetic = "failed-create-101-11"
	d2bOtherRef  = "a900.x900"
	// 与 executeXDrop 对 v3Attack(101,"udp","198.51.100.7") 的默认载荷同身份（comment / action 不入身份）。
	d2bOtherBody = `{"dst_ip":"198.51.100.7","protocol":"udp","action":"drop","claim_ref":"` + d2bOtherRef + `"}`
)

// ---------------------------------------------------------------- store 包装

// d2bStore 在 d2Store 上补：执行日志 ListByAttack（v3Logs 缺此方法，补撤读日志必需）、
// 多连接器 / 显式目标、Get 时停用（列目标与锁内重读之间被停用）、认领落败、列表出错。
type d2bStore struct {
	*d2Store
	extra       []store.XDropConnector
	targets     []int
	getDisabled atomic.Bool
	listErr     atomic.Bool
	loseClaim   sync.Map
	liveFrom    int32 // >0：第 liveFrom 次及以后的 LiveIDs 调用报活（模拟对账快照后、锁内重读前攻击重新活跃）
	liveCalls   atomic.Int32
	completeErr atomic.Bool // v0.4 C28：ScheduledActions().Complete 恒失败（模拟真行 withdrawn 后调度 Complete 写失败、调度残留）
	logErr      atomic.Bool // 执行日志 ListByAttack 出错（C20）
	hookMu      sync.Mutex
	onGet       func()             // 一次性：连接器 Get 时触发（C14/cancelled 用来在锁内取消 ctx）
	ruleBarrier chan chan struct{} // 一次性：下一次规则 ListByAttack 送出 release 通道并阻塞（C22）
}

func (s *d2bStore) takeOnGet() func() {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	f := s.onGet
	s.onGet = nil
	return f
}
func (s *d2bStore) takeBarrier() chan chan struct{} {
	s.hookMu.Lock()
	defer s.hookMu.Unlock()
	c := s.ruleBarrier
	s.ruleBarrier = nil
	return c
}

type d2bAttacks struct {
	d2Attacks
	b *d2bStore
}

func (s *d2bStore) Attacks() store.AttackRepo { return d2bAttacks{d2Attacks{d: s.d2Store}, s} }
func (r d2bAttacks) LiveIDs(c context.Context, ids []int) (map[int]bool, error) {
	n := r.b.liveCalls.Add(1)
	m, err := r.d2Attacks.LiveIDs(c, ids)
	if r.b.liveFrom > 0 && n >= r.b.liveFrom {
		for _, id := range ids {
			m[id] = true
		}
	}
	return m, err
}

type d2bRules struct {
	d2Rules
	b *d2bStore
}
type d2bLogs struct {
	v3Logs
	b *d2bStore
}
type d2bConns struct {
	store.XDropConnectorRepo
	b *d2bStore
}
type d2bTargets struct {
	store.XDropTargetRepo
	b *d2bStore
}

func (s *d2bStore) XDropActiveRules() store.XDropActiveRuleRepo {
	return d2bRules{d2Rules{v3Active{s: s.v3Store}, s.d2Store}, s}
}
func (s *d2bStore) ActionExecLog() store.ActionExecLogRepo    { return d2bLogs{v3Logs{s: s.v3Store}, s} }
func (s *d2bStore) XDropConnectors() store.XDropConnectorRepo { return d2bConns{b: s} }
func (s *d2bStore) XDropTargets() store.XDropTargetRepo       { return d2bTargets{b: s} }

type d2bSchedules struct {
	d2Schedules
	b *d2bStore
}

func (s *d2bStore) ScheduledActions() store.ScheduledActionRepo {
	return d2bSchedules{d2Schedules{v3Schedules{s: s.v3Store}}, s}
}
func (r d2bSchedules) Complete(c context.Context, id int) error {
	if r.b.completeErr.Load() {
		return errors.New("injected d2b Complete failure")
	}
	return r.d2Schedules.Complete(c, id)
}

func (r d2bRules) ListByAttack(c context.Context, id int) ([]store.XDropActiveRule, error) {
	if r.b.listErr.Load() {
		return nil, errors.New("injected d2b list failure")
	}
	if entered := r.b.takeBarrier(); entered != nil {
		release := make(chan struct{})
		entered <- release
		<-release
	}
	return r.d2Rules.ListByAttack(c, id)
}
func (r d2bRules) MarkWithdrawing(c context.Context, a, b, d int, id string) (bool, error) {
	if _, lose := r.b.loseClaim.Load(id); lose {
		return false, nil
	}
	return r.d2Rules.MarkWithdrawing(c, a, b, d, id)
}
func (r d2bLogs) ListByAttack(_ context.Context, attackID int) ([]store.ActionExecutionLog, error) {
	if r.b.logErr.Load() {
		return nil, errors.New("injected d2b execution log read failure")
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []store.ActionExecutionLog
	for _, l := range r.s.logs {
		if l.AttackID == attackID {
			out = append(out, l)
		}
	}
	return out, nil
}
func (r d2bConns) Get(_ context.Context, id int) (*store.XDropConnector, error) {
	if f := r.b.takeOnGet(); f != nil {
		f()
	}
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	if id == r.b.conn.ID {
		c := r.b.conn
		if r.b.getDisabled.Load() {
			c.Enabled = false
		}
		return &c, nil
	}
	for _, c := range r.b.extra {
		if c.ID == id {
			cp := c
			return &cp, nil
		}
	}
	return nil, sql.ErrNoRows
}
func (r d2bConns) ListEnabled(context.Context) ([]store.XDropConnector, error) {
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	var out []store.XDropConnector
	for _, c := range append([]store.XDropConnector{r.b.conn}, r.b.extra...) {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out, nil
}
func (r d2bTargets) List(context.Context, int) ([]store.XDropConnector, error) {
	r.b.mu.Lock()
	defer r.b.mu.Unlock()
	if r.b.targets == nil {
		return []store.XDropConnector{r.b.conn}, nil
	}
	var out []store.XDropConnector
	for _, id := range r.b.targets {
		for _, c := range append([]store.XDropConnector{r.b.conn}, r.b.extra...) {
			if c.ID == id {
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- 远端替身

type d2bReq struct {
	Method, Host, Path, Query, Ref string
	Body                           []byte
}

// d2bRemote 把 v3Mock.serve 包成 RoundTripper：可设创建 POST 模式、创建 POST 闸门、validate / DELETE 故障。
// 创建 POST（/rules）模式：""=转发；lost=转发后报传输错（远端已建、回包丢失）；drop=不转发即传输错；
// 400 / 409 / 503=不转发直接回该码；noid=转发后改回 201 无 id；created503=转发后回 503；
// reflect=不转发、传输错正文含 URL 与假 key；reflect503=不转发、503 正文含 URL 与假 key。
// v0.3：`POST /rules/batch?validate=1` 由 d2bRemote.validate 按 rc2 BatchValidate 三态只读应答（不建、不认领、不续期）。
// expiry 旁表模拟 rc2 existingResult 的续期副作用（有限期限遇无 expires_in 的同身份创建 ⇒ 改为永久），供 C26 / M26。
type d2bRemote struct {
	m            *v3Mock
	mu           sync.Mutex
	reqs         []d2bReq
	postMode     string
	deleteMode   string
	validateMode string
	gate         chan struct{}
	waiting      atomic.Int32
	reflectKey   string
	expiry       map[string]string
	deleteFailN  atomic.Int32 // v0.4 C29：接下来 N 次 DELETE 回 503
	// v0.4 C28：预检应答前的假时间延迟。真行 R 的残留调度每轮都是对账候选，其 worker 的 Complete 故障
	// 走 xdropWrite 三次重试（100ms+200ms）期间持 R 锁；延迟 500ms 让 S 的真键 try-lock 落在 R 锁释放之后（确定性）。
	validateDelay atomic.Int64
}

func d2bInstall(t *testing.T) *d2bRemote {
	t.Helper()
	x := &d2bRemote{m: &v3Mock{rules: map[string]*v3Rule{}, epoch: "epoch-test"}, expiry: map[string]string{}}
	d2HTTP(t, x.roundTrip)
	return x
}
func (x *d2bRemote) setValidate(mode string) { x.mu.Lock(); x.validateMode = mode; x.mu.Unlock() }
func (x *d2bRemote) expiryOf(id string) string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.expiry[id]
}

// d2bKind：create = POST /rules；validate = POST /rules/batch?validate=1；batch = 其它 batch；delete = DELETE。
func d2bKind(r d2bReq) string {
	q, _ := url.ParseQuery(r.Query)
	switch {
	case r.Method == http.MethodDelete:
		return "delete"
	case r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/rules/batch") && q.Get("validate") == "1":
		return "validate"
	case r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/rules/batch"):
		return "batch"
	case r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/rules"):
		return "create"
	}
	return r.Method + " " + r.Path
}
func d2bCountKind(reqs []d2bReq, kind string) int {
	n := 0
	for _, r := range reqs {
		if d2bKind(r) == kind {
			n++
		}
	}
	return n
}

// validate 复刻 rc2 api.batch + BatchValidate 的只读三态：items 按 RulePatch 严格解码（含 claim_ref 等未知键 ⇒ 整体 400）；
// 身份存在且 action / rate_limit 相同 ⇒ rule.id + existing=true；身份存在但冲突 ⇒ error{rule_conflict, rule_id}；
// 不存在 ⇒ rule.id="" + existing=false。⛔ 改账本。
func (x *d2bRemote) validate(r *http.Request, body []byte) *http.Response {
	if r.Header.Get("Authorization") != "Bearer "+v3TestKey {
		return d2Reply(401, `{"code":"unauthenticated","message":"test contract rejection"}`)
	}
	if r.URL.Query().Get("validate") != "1" {
		return d2Reply(400, `{"code":"bad_request","message":"batch create not modeled by d2b"}`)
	}
	var in struct {
		ClaimRef string            `json:"claim_ref"`
		Items    []json.RawMessage `json:"items"`
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&in) != nil {
		return d2Reply(400, `{"code":"bad_request","message":"invalid JSON request"}`)
	}
	if len(in.Items) < 1 || len(in.Items) > 500 {
		return d2Reply(400, `{"code":"batch_too_large","message":"items must contain 1..500 rules","field":"items"}`)
	}
	results := []map[string]any{}
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	for i, raw := range in.Items {
		var p v3RulePatch
		di := json.NewDecoder(bytes.NewReader(raw))
		di.DisallowUnknownFields()
		if err := di.Decode(&p); err != nil {
			field := ""
			if strings.HasPrefix(err.Error(), "json: unknown field ") {
				field = strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), "\"")
			}
			out, _ := json.Marshal(map[string]string{"code": "bad_request", "message": "invalid JSON request", "field": field})
			return d2Reply(400, string(out))
		}
		item := map[string]any{"index": i}
		fields, code, field := v3Canonical(p)
		if code != "" {
			item["error"] = map[string]any{"code": code, "message": "test contract rejection", "field": field}
			results = append(results, item)
			continue
		}
		identity := map[string]any{}
		for k, v := range fields {
			if !strings.Contains(" action rate_limit comment enabled expires_in ", " "+k+" ") {
				identity[k] = v
			}
		}
		encoded, _ := json.Marshal(identity)
		var found *v3Rule
		for _, rule := range x.m.rules {
			if rule.identity == string(encoded) {
				found = rule
				break
			}
		}
		switch {
		case found != nil && (found.fields["action"] != fields["action"] || found.fields["rate_limit"] != fields["rate_limit"]):
			item["error"] = map[string]any{"code": "rule_conflict", "message": "rule identity is occupied", "rule_id": found.id}
		case found != nil:
			item["rule"], item["existing"] = x.m.ruleJSON(found), true
		default:
			rule := map[string]any{}
			for k, v := range fields {
				rule[k] = v
			}
			rule["id"] = ""
			item["rule"], item["existing"] = rule, false
		}
		results = append(results, item)
	}
	out, _ := json.Marshal(map[string]any{"epoch": x.m.epoch, "results": results})
	return d2Reply(200, string(out))
}
func (x *d2bRemote) setPost(mode string) { x.mu.Lock(); x.postMode = mode; x.mu.Unlock() }
func (x *d2bRemote) setDelete(mode string) {
	x.mu.Lock()
	x.deleteMode = mode
	x.mu.Unlock()
}
func (x *d2bRemote) setGate(g chan struct{}) { x.mu.Lock(); x.gate = g; x.mu.Unlock() }
func (x *d2bRemote) roundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	ref := r.URL.Query().Get("claim_ref")
	if r.Method == http.MethodPost {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			ref, _ = m["claim_ref"].(string)
		}
	}
	x.mu.Lock()
	x.reqs = append(x.reqs, d2bReq{r.Method, r.URL.Host, r.URL.Path, r.URL.RawQuery, ref, body})
	mode, gate, del, key, vmode := x.postMode, x.gate, x.deleteMode, x.reflectKey, x.validateMode
	x.mu.Unlock()
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rules/batch") {
		if d := x.validateDelay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}
		switch vmode {
		case "503":
			return d2Reply(503, `{"code":"unavailable","message":"retry"}`), nil
		case "transport":
			return nil, errors.New("connection reset during validate")
		case "malformed_empty": // v0.4 R2：非契约形状，results[0] = {}
			return d2Reply(200, `{"epoch":"epoch-test","results":[{}]}`), nil
		case "malformed_norule": // v0.4 R2：非契约形状，缺 rule 对象
			return d2Reply(200, `{"epoch":"epoch-test","results":[{"index":0,"existing":false}]}`), nil
		}
		return x.validate(r, body), nil
	}
	if r.Method == http.MethodPost && gate != nil {
		x.waiting.Add(1)
		<-gate
		x.waiting.Add(-1)
	}
	reflected := "request " + r.URL.String() + " credential " + key + " peer https://user:" + key + "@192.0.2.21/path"
	if r.Method == http.MethodPost {
		switch mode {
		case "lost":
			resp := x.forward(r, body)
			resp.Body.Close()
			return nil, errors.New("connection reset after request was sent")
		case "drop":
			return nil, errors.New("connection refused")
		case "400":
			return d2Reply(400, `{"code":"invalid_rule","message":"test contract rejection","field":"protocol"}`), nil
		case "409":
			return d2Reply(409, `{"code":"rule_conflict","message":"test contract rejection"}`), nil
		case "503":
			return d2Reply(503, `{"code":"unavailable","message":"retry"}`), nil
		case "noid":
			resp := x.forward(r, body)
			resp.Body.Close()
			return d2Reply(201, `{"existing":false}`), nil
		case "created503":
			resp := x.forward(r, body)
			resp.Body.Close()
			return d2Reply(503, `{"code":"unavailable","message":"commit outcome unknown"}`), nil
		case "reflect":
			return nil, errors.New(reflected)
		case "reflect503":
			b, _ := json.Marshal(map[string]string{"code": "upstream_error", "field": "rule", "message": reflected})
			return d2Reply(503, string(b)), nil
		}
	}
	if r.Method == http.MethodDelete && x.deleteFailN.Load() > 0 {
		x.deleteFailN.Add(-1)
		return d2Reply(503, `{"code":"unavailable","message":"retry"}`), nil
	}
	if r.Method == http.MethodDelete && del == "503" {
		return d2Reply(503, `{"code":"unavailable","message":"retry"}`), nil
	}
	return x.forward(r, body), nil
}
func (x *d2bRemote) forward(r *http.Request, body []byte) *http.Response {
	target := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req := httptest.NewRequest(r.Method, target, bytes.NewReader(body))
	req.Header = r.Header.Clone()
	rec := httptest.NewRecorder()
	x.m.serve(rec, req)
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rules") && (rec.Code == 200 || rec.Code == 201) {
		var in struct {
			ExpiresIn string `json:"expires_in"`
		}
		var out struct {
			ID       string `json:"id"`
			Existing bool   `json:"existing"`
		}
		_ = json.Unmarshal(body, &in)
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		x.mu.Lock()
		if old, seen := x.expiry[out.ID]; !out.Existing || !seen {
			x.expiry[out.ID] = in.ExpiresIn
		} else if old != "" && in.ExpiresIn != old {
			x.expiry[out.ID] = in.ExpiresIn // rc2 existingResult：有限期限被延长或改为永久（""）
		}
		x.mu.Unlock()
	}
	return rec.Result()
}
func (x *d2bRemote) mark() int { x.mu.Lock(); defer x.mu.Unlock(); return len(x.reqs) }
func (x *d2bRemote) since(mark int) []d2bReq {
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]d2bReq(nil), x.reqs[mark:]...)
}
func d2bCount(reqs []d2bReq, method string) int {
	n := 0
	for _, r := range reqs {
		if r.Method == method {
			n++
		}
	}
	return n
}
func d2bDescribe(reqs []d2bReq) string {
	var parts []string
	for _, r := range reqs {
		parts = append(parts, fmt.Sprintf("%s %s%s?%s ref=%s", r.Method, r.Host, r.Path, r.Query, r.Ref))
	}
	return "[" + strings.Join(parts, "; ") + "]"
}

// ourClaims 数远端上「本凭证 + 本 ref」的认领条数（跨全部规则）。
func (x *d2bRemote) ourClaims() int {
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	n := 0
	for _, r := range x.m.rules {
		if r.claims["Bearer "+v3TestKey+"|"+d2bRef] {
			n++
		}
	}
	return n
}
func (x *d2bRemote) ruleIDs() []string {
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	var out []string
	for id := range x.m.rules {
		out = append(out, id)
	}
	return out
}
func (x *d2bRemote) seedOther(t *testing.T) string { return x.seedOtherBody(t, d2bOtherBody) }
func (x *d2bRemote) seedOtherBody(t *testing.T, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+v3TestKey)
	rec := httptest.NewRecorder()
	x.m.serve(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	id, _ := out["id"].(string)
	if rec.Code != 201 || id == "" {
		t.Fatalf("device: seed other holder HTTP %d %s", rec.Code, rec.Body.String())
	}
	var in struct {
		ExpiresIn string `json:"expires_in"`
	}
	_ = json.Unmarshal([]byte(body), &in)
	x.mu.Lock()
	x.expiry[id] = in.ExpiresIn
	x.mu.Unlock()
	return id
}

// ---------------------------------------------------------------- 装置与入口

func d2bFixture(t *testing.T) (*d2bStore, *Engine, *d2bRemote) {
	t.Helper()
	d, _, _ := d2Fixture(t, "active")
	d.mu.Lock()
	d.rules = map[string]store.XDropActiveRule{}
	d.history = map[string][]string{}
	d.conn.APIKey = v3TestKey
	d.mu.Unlock()
	d.actions[0].XDropAction = "filter_l4"
	d.actions[0].TriggerPhase = "on_detected"
	b := &d2bStore{d2Store: d}
	x := d2bInstall(t)
	return b, NewEngine(b, "auto"), x
}

// d2bCreate 经真实 executeXDrop 创建段产生执行日志与合成号行（mode 见 d2bRemote）。
func d2bCreate(b *d2bStore, e *Engine, x *d2bRemote, mode, phase string) {
	x.setPost(mode)
	defer x.setPost("")
	a := v3Attack(101, "udp", "198.51.100.7")
	l, _ := executeXDrop(context.Background(), b, b.actions[0], a, "confirmed", a.DstIP, "draft", phase, 101, nil, e)
	if l != nil {
		_, _ = b.ActionExecLog().Create(context.Background(), l)
	}
}

// d2bUnblock = 配对 on_expired 子动作（normal 入口）；返回的日志按引擎口径落库。
func d2bUnblock(b *d2bStore, e *Engine, ctx context.Context) {
	a := v3Attack(101, "udp", "198.51.100.7")
	l, _ := executeXDrop(ctx, b, b.actions[1], a, "expired", a.DstIP, "draft", "on_expired", 101, nil, e)
	if l != nil {
		_, _ = b.ActionExecLog().Create(context.Background(), l)
	}
}

func d2bRow(b *d2bStore, rule string) store.XDropActiveRule {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rules[v3RuleKey(101, 11, b.conn.ID, rule)]
}
func d2bLogsFor(b *d2bStore, action int) []store.ActionExecutionLog {
	var out []store.ActionExecutionLog
	for _, l := range b.logSnapshot() {
		if l.AttackID == 101 && l.ActionID == action {
			out = append(out, l)
		}
	}
	return out
}
func d2bCreateLogs(b *d2bStore) []store.ActionExecutionLog {
	var out []store.ActionExecutionLog
	for _, l := range d2bLogsFor(b, 11) {
		if l.ExternalRuleID == d2bSynthetic && l.Status == "failed" {
			out = append(out, l)
		}
	}
	return out
}
func d2bAnyLog(b *d2bStore, needle string) bool {
	for _, l := range b.logSnapshot() {
		if strings.Contains(l.ErrorMessage, needle) {
			return true
		}
	}
	return false
}
func d2bLogTexts(b *d2bStore) string {
	var parts []string
	for _, l := range b.logSnapshot() {
		parts = append(parts, fmt.Sprintf("{act=%d rule=%s status=%s skip=%s msg=%q}", l.ActionID, l.ExternalRuleID, l.Status, l.SkipReason, l.ErrorMessage))
	}
	return strings.Join(parts, " ")
}

// v0.2 钉死的 WARN 前缀（log 包时间戳之后的正文以它开头）。
const (
	d2bWarnUnrecoverable = "WARN action: xdrop synthetic failed-create unrecoverable"
	d2bWarnLateLeak      = "WARN action: xdrop late create leaked"
)

func d2bWarnCount(text, prefix string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if i := strings.Index(line, "WARN "); i >= 0 && strings.HasPrefix(line[i:], prefix) {
			n++
		}
	}
	return n
}
func d2bReconcileMetric(outcome string) float64 {
	return testutil.ToFloat64(metrics.XDropReconcile.WithLabelValues(outcome))
}
func d2bLiveCount(b *d2bStore, connector int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, r := range b.rules {
		if r.ConnectorID == connector && (r.Status == "active" || r.Status == "delayed" || r.Status == "withdrawing" || r.Status == "failed") {
			n++
		}
	}
	return n
}

// d2bRunReconcile 起真实 RunXDropReconcile（I=1s），跑 rounds 个 tick 后停。
func d2bRunReconcile(t *testing.T, e *Engine, rounds int) {
	t.Helper()
	stop := d2Start(t, e)
	for i := 1; i < rounds; i++ {
		time.Sleep(time.Second)
		synctest.Wait()
	}
	stop()
	synctest.Wait()
}

// d2bRecoveryCheck（v0.3）：创建之后的 HTTP 恰为 validate wantValidate + DELETE wantDelete，且 0 次 POST /rules、0 次非预检 batch；
// 每个 validate：query validate=1、body 顶层只有 items、恰 1 项、该项 = 某份日志 RequestBody 解析后去 claim_ref 键（其余键值相同）；
// 每个 DELETE 认领本 ref。
func d2bRecoveryCheck(t *testing.T, reqs []d2bReq, wantValidate, wantDelete int, bodies map[string]bool) {
	t.Helper()
	v, d := d2bCountKind(reqs, "validate"), d2bCountKind(reqs, "delete")
	if v != wantValidate || d != wantDelete || len(reqs) != v+d {
		t.Errorf("recovery HTTP validate=%d DELETE=%d other=%d; want %d/%d/0 (0 POST /rules); reqs=%s", v, d, len(reqs)-v-d, wantValidate, wantDelete, d2bDescribe(reqs))
	}
	for _, r := range reqs {
		switch d2bKind(r) {
		case "validate":
			if !d2bValidateItemOK(r.Body, bodies) {
				t.Errorf("validate body is not {items:[logged body minus claim_ref]}: %s", r.Body)
			}
		case "delete":
			if r.Ref != d2bRef {
				t.Errorf("recovery DELETE claim_ref=%q want %q", r.Ref, d2bRef)
			}
		}
	}
}

// d2bIdentity 与 v3Mock.serve 的身份算法逐字一致（去 action / rate_limit / comment / enabled / expires_in）。
func d2bIdentity(fields map[string]any) string {
	identity := map[string]any{}
	for k, v := range fields {
		if !strings.Contains(" action rate_limit comment enabled expires_in ", " "+k+" ") {
			identity[k] = v
		}
	}
	encoded, _ := json.Marshal(identity)
	return string(encoded)
}

// uiUpdate 模拟 rc2 Service.Update（UI）：改匹配字段后重算身份，保留 id 与全部认领（v0.4 C30 / r2 N3）。
func (x *d2bRemote) uiUpdate(t *testing.T, id, field string, value any) {
	t.Helper()
	x.m.mu.Lock()
	defer x.m.mu.Unlock()
	r := x.m.rules[id]
	if r == nil {
		t.Fatalf("device: uiUpdate unknown rule %s", id)
	}
	r.fields[field] = value
	r.identity = d2bIdentity(r.fields)
}

// d2bContractNotFound recognizes a contract-compliant not-found response: exactly one result with a rule object,
// existing=false, rule.id=="", and no error. Used only by D01: fixture checks distinguish this shape from malformed responses.
func d2bContractNotFound(resp []byte) bool {
	var out struct {
		Results []map[string]json.RawMessage `json:"results"`
	}
	if json.Unmarshal(resp, &out) != nil || len(out.Results) != 1 {
		return false
	}
	item := out.Results[0]
	if _, bad := item["error"]; bad {
		return false
	}
	var rule map[string]any
	var existing *bool
	if json.Unmarshal(item["rule"], &rule) != nil || rule == nil || json.Unmarshal(item["existing"], &existing) != nil || existing == nil {
		return false
	}
	id, ok := rule["id"].(string)
	return !*existing && ok && id == ""
}

func d2bValidateItemOK(raw []byte, bodies map[string]bool) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || len(top) != 1 {
		return false
	}
	var items []map[string]any
	if json.Unmarshal(top["items"], &items) != nil || len(items) != 1 {
		return false
	}
	for b := range bodies {
		var want map[string]any
		if json.Unmarshal([]byte(b), &want) != nil {
			continue
		}
		delete(want, "claim_ref")
		if reflect.DeepEqual(want, items[0]) {
			return true
		}
	}
	return false
}
func d2bBodies(logs []store.ActionExecutionLog) map[string]bool {
	out := map[string]bool{}
	for _, l := range logs {
		out[l.RequestBody] = true
	}
	return out
}

// ---------------------------------------------------------------- C01–C03 补撤

// 〔行为〕C01：1 份 Uncertain 日志（远端其实已建；body 合法含本 ref）+ 另一持有方共享身份；
// 攻击已结束、对账一轮 ⇒ validate 1（existing 真 id）+ DELETE 1、0 次 POST /rules、本 ref 认领 0、另一持有方仍在、行 withdrawn（v0.3：只读预检）。
// 子格 transport（StatusCode nil：传输错）/ http_503（StatusCode 503：§4-1 的 ≥500 也归 Uncertain）。
// HEAD 红因：对账入口 skipped_synthetic，0 HTTP，行留 failed。种子：M02（transport）；起草方补 http_503 = M02 的「5xx 当 Rejected」变体。
func TestD2B_C01_SyntheticUncertainRecovered(t *testing.T) {
	for _, kind := range []string{"transport", "http_503"} {
		t.Run(kind, func(t *testing.T) { d2bC01(t, kind) })
	}
}
func d2bC01(t *testing.T, kind string) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		other := x.seedOther(t)
		mode := map[string]string{"transport": "lost", "http_503": "created503"}[kind]
		d2bCreate(b, e, x, mode, "on_detected")
		logs := d2bCreateLogs(b)
		codeOK := len(logs) == 1 && (kind == "transport" && logs[0].StatusCode == nil || kind == "http_503" && logs[0].StatusCode != nil && *logs[0].StatusCode == 503)
		if !codeOK || d2bRow(b, d2bSynthetic).Status != "failed" || x.m.claimCount(other) != 2 {
			t.Fatalf("device: logs=%s row=%s claims=%d; want 1 Uncertain(%s) log, failed row, 2 claims", d2bLogTexts(b), d2bRow(b, d2bSynthetic).Status, x.m.claimCount(other), kind)
		}
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		d2bRecoveryCheck(t, x.since(mark), 1, 1, d2bBodies(logs))
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our claims after recovery=%d want 0", n)
		}
		if n := x.m.claimCount(other); n != 1 {
			t.Errorf("shared rule claims=%d want 1 (other holder kept)", n)
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("synthetic row status=%s want withdrawn", st)
		}
	})
}

// 〔行为〕C02：日志为 2xx 缺 id（远端已建、本 ref 持有）⇒ 补撤释放、远端规则删空、行 withdrawn。
// HEAD 红因：同 C01。种子：M03。
func TestD2B_C02_SyntheticCreatedNoIdRecovered(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		d2bCreate(b, e, x, "noid", "on_detected")
		logs := d2bCreateLogs(b)
		if len(logs) != 1 || logs[0].StatusCode == nil || *logs[0].StatusCode != 201 || x.ourClaims() != 1 {
			t.Fatalf("device: logs=%+v ourClaims=%d; want one 201-no-id log and 1 claim", logs, x.ourClaims())
		}
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		d2bRecoveryCheck(t, x.since(mark), 1, 1, d2bBodies(logs))
		if n, rules := x.ourClaims(), x.ruleIDs(); n != 0 || len(rules) != 0 {
			t.Errorf("after recovery ourClaims=%d remote rules=%v; want 0 / none", n, rules)
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("synthetic row status=%s want withdrawn", st)
		}
	})
}

// 〔行为〕C03：同一合成号两份不同 body（载荷被编辑过），均 Uncertain、均已建 ⇒ validate 2（各单项）+ DELETE 2、0 次 POST /rules，两身份本 ref 均释放。
// HEAD 红因：同 C01。种子：M01（只补最后一份）。
func TestD2B_C03_SyntheticMultiBody(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		for _, port := range []int{53, 123} {
			b.actions[0].XDropCustomPayload = json.RawMessage(fmt.Sprintf(`{"dst_ip":"198.51.100.7","dst_port":%d,"action":"drop"}`, port))
			d2bCreate(b, e, x, "lost", "on_detected")
		}
		logs := d2bCreateLogs(b)
		bodies := d2bBodies(logs)
		if len(logs) != 2 || len(bodies) != 2 || len(x.ruleIDs()) != 2 || x.ourClaims() != 2 {
			t.Fatalf("device: logs=%d distinct bodies=%d remote rules=%d ourClaims=%d; want 2/2/2/2", len(logs), len(bodies), len(x.ruleIDs()), x.ourClaims())
		}
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		reqs := x.since(mark)
		d2bRecoveryCheck(t, reqs, 2, 2, bodies)
		validated := map[string]bool{}
		for _, r := range reqs {
			if d2bKind(r) == "validate" {
				validated[string(r.Body)] = true
			}
		}
		if len(validated) != 2 {
			t.Errorf("distinct validate bodies=%d want 2", len(validated))
		}
		if n, rules := x.ourClaims(), x.ruleIDs(); n != 0 || len(rules) != 0 {
			t.Errorf("after recovery ourClaims=%d remote rules=%v; want 0 / none", n, rules)
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("synthetic row status=%s want withdrawn", st)
		}
	})
}

// ---------------------------------------------------------------- C04 / C05 本地关闭

// C04 子格：<kind>/normal〔守卫〕= normal 入口 0 HTTP + withdrawn（HEAD 已如此）；
// <kind>/normal_text〔行为〕= normal 入口执行日志含 `closed locally`（HEAD 文案不同）；
// <kind>/reconcile〔行为〕= 对账入口 0 HTTP + withdrawn + `closed locally`（HEAD skipped_synthetic、行留 failed）。
// kind：not_sent（真实 NewRequest 失败，文案前缀 `create request:`）· http_400 · http_409。种子：M19（not_sent/*）。
func TestD2B_C04_SyntheticNotSentOrRejected(t *testing.T) {
	for _, kind := range []string{"not_sent", "http_400", "http_409"} {
		for _, entry := range []string{"normal", "normal_text", "reconcile"} {
			t.Run(kind+"/"+entry, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					b, e, x := d2bFixture(t)
					switch kind {
					case "not_sent":
						b.mu.Lock()
						good := b.conn.APIURL
						b.conn.APIURL = good + "\x7f"
						b.mu.Unlock()
						d2bCreate(b, e, x, "", "on_detected")
						b.mu.Lock()
						b.conn.APIURL = good
						b.mu.Unlock()
					case "http_400":
						d2bCreate(b, e, x, "400", "on_detected")
					case "http_409":
						d2bCreate(b, e, x, "409", "on_detected")
					}
					logs := d2bCreateLogs(b)
					if len(logs) != 1 || d2bRow(b, d2bSynthetic).Status != "failed" {
						t.Fatalf("device: create logs=%d row=%s; want 1 / failed; logs=%s", len(logs), d2bRow(b, d2bSynthetic).Status, d2bLogTexts(b))
					}
					if kind == "not_sent" && (!strings.HasPrefix(logs[0].ErrorMessage, "create request:") || logs[0].StatusCode != nil) {
						t.Fatalf("device: not_sent log=%q code=%v; want create request: prefix and nil code", logs[0].ErrorMessage, logs[0].StatusCode)
					}
					mark := x.mark()
					if entry == "reconcile" {
						d2bRunReconcile(t, e, 2)
					} else {
						d2bUnblock(b, e, context.Background())
						synctest.Wait()
					}
					reqs := x.since(mark)
					if entry != "normal_text" {
						if len(reqs) != 0 {
							t.Errorf("%s/%s HTTP=%d want 0; reqs=%s", kind, entry, len(reqs), d2bDescribe(reqs))
						}
						if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
							t.Errorf("%s/%s row status=%s want withdrawn", kind, entry, st)
						}
					}
					if entry != "normal" && !d2bAnyLog(b, "closed locally") {
						t.Errorf("%s/%s missing execution log `closed locally`; logs=%s", kind, entry, d2bLogTexts(b))
					}
				})
			})
		}
	}
}

// 〔行为〕C05：截断 body / 0 份日志 / body 的 claim_ref ≠ 本 ref ⇒ 对账一轮：0 HTTP、withdrawn、
// xsight_xdrop_reconcile_total{outcome="synthetic_unrecoverable"} +1、WARN。
// HEAD 红因：skipped_synthetic，行留 failed、无指标。种子：M04（wrong_ref）、M05（truncated）。
func TestD2B_C05_SyntheticTruncatedOrMissing(t *testing.T) {
	for _, kind := range []string{"truncated", "missing", "wrong_ref"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				switch kind {
				case "truncated":
					b.actions[0].XDropCustomPayload = json.RawMessage(`{"dst_ip":"198.51.100.7","action":"drop","comment":"` + strings.Repeat("c", 1500) + `"}`)
					d2bCreate(b, e, x, "lost", "on_detected")
					logs := d2bCreateLogs(b)
					if len(logs) != 1 || json.Valid([]byte(logs[0].RequestBody)) || len(logs[0].RequestBody) != 1024 {
						t.Fatalf("device: want one truncated (1024B, invalid JSON) body; logs=%d", len(logs))
					}
				case "missing":
					if _, err := b.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: d2bSynthetic, Status: "failed", ErrorMessage: "HTTP POST <url>: request timed out"}); err != nil {
						t.Fatal(err)
					}
				case "wrong_ref":
					d2bCreate(b, e, x, "lost", "on_detected")
					b.mu.Lock()
					for i := range b.logs {
						if b.logs[i].ExternalRuleID == d2bSynthetic {
							b.logs[i].RequestBody = strings.Replace(b.logs[i].RequestBody, `"claim_ref":"`+d2bRef+`"`, `"claim_ref":"a102.x11"`, 1)
						}
					}
					b.mu.Unlock()
					logs := d2bCreateLogs(b)
					if len(logs) != 1 || !json.Valid([]byte(logs[0].RequestBody)) || !strings.Contains(logs[0].RequestBody, `"claim_ref":"a102.x11"`) {
						t.Fatalf("device: want one valid body with foreign claim_ref; logs=%+v", logs)
					}
				}
				if st := d2bRow(b, d2bSynthetic).Status; st != "failed" {
					t.Fatalf("device: seeded row status=%s want failed", st)
				}
				captured := d2R4Capture(t)
				before := d2bReconcileMetric("synthetic_unrecoverable")
				mark := x.mark()
				d2bRunReconcile(t, e, 2)
				if reqs := x.since(mark); len(reqs) != 0 {
					t.Errorf("%s HTTP=%d want 0; reqs=%s", kind, len(reqs), d2bDescribe(reqs))
				}
				if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
					t.Errorf("%s row status=%s want withdrawn", kind, st)
				}
				if d := d2bReconcileMetric("synthetic_unrecoverable") - before; d != 1 {
					t.Errorf("%s synthetic_unrecoverable delta=%g want 1", kind, d)
				}
				if n := d2bWarnCount(captured.text(), d2bWarnUnrecoverable); n < 1 {
					t.Errorf("%s WARN lines with prefix %q = %d want >=1; log=%q", kind, d2bWarnUnrecoverable, n, captured.text())
				}
			})
		})
	}
}

// ---------------------------------------------------------------- C06–C09

// 〔行为〕C06（v0.3）：补撤只读预检 validate 回 503 ⇒ 行仍 failed、记共享退避；资格前 normal / 结束事件 / 对账轮 0 增量；
// 到期（I=2min 缺省）后再试成功 ⇒ 恰 validate 1 + DELETE 1、0 次 POST /rules、withdrawn。
// 全程 synthetic_unrecoverable 增量 0、无 unrecoverable WARN（M29：筛选若读回撤销阶段自己写的失败日志，重试时会多出一份不合格份告警）。
// HEAD 红因：normal 入口对合成号 0 HTTP 直接 withdrawn。种子：M06（失败仍 withdrawn）、M07（绕过退避）、M29。
func TestD2B_C06_SyntheticRetryBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		d2bCreate(b, e, x, "lost", "on_detected")
		logs := d2bCreateLogs(b)
		if len(logs) != 1 || x.ourClaims() != 1 {
			t.Fatalf("device: Uncertain create not seeded; logs=%s", d2bLogTexts(b))
		}
		captured := d2R4Capture(t)
		unrecoverable := d2bReconcileMetric("synthetic_unrecoverable")
		x.setValidate("503")
		mark := x.mark()
		d2bUnblock(b, e, context.Background())
		synctest.Wait()
		first := x.since(mark)
		if v, other := d2bCountKind(first, "validate"), len(first)-d2bCountKind(first, "validate"); v != 1 || other != 0 {
			t.Errorf("first attempt validate=%d other=%d want 1/0; reqs=%s", v, other, d2bDescribe(first))
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "failed" {
			t.Errorf("after failed validate row status=%s want failed", st)
		}
		a := v3Attack(101, "udp", "198.51.100.7")
		rid := 1
		a.ResponseID = &rid
		entries := []struct {
			name string
			run  func()
		}{
			{"normal", func() { d2bUnblock(b, e, context.Background()) }},
			{"ended_event", func() { e.HandleEvent(tracker.AttackEvent{Type: "expired", DBID: 101, Attack: a}) }},
			{"reconcile_round", func() { e.reconcileXDropRound(context.Background()) }},
		}
		for _, wait := range []time.Duration{0, d2DefaultI / 2} {
			time.Sleep(wait)
			for _, en := range entries {
				before := x.mark()
				en.run()
				synctest.Wait()
				if reqs := x.since(before); len(reqs) != 0 {
					t.Errorf("%s before eligibility (+%s) bypassed backoff: reqs=%s", en.name, wait, d2bDescribe(reqs))
				}
			}
		}
		x.setValidate("")
		time.Sleep(d2DefaultI/2 + 2*time.Second)
		synctest.Wait()
		mark = x.mark()
		for _, en := range entries {
			en.run()
			synctest.Wait()
		}
		d2bRecoveryCheck(t, x.since(mark), 1, 1, d2bBodies(logs))
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("after eligible retry row status=%s want withdrawn", st)
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our claims=%d want 0", n)
		}
		if d := d2bReconcileMetric("synthetic_unrecoverable") - unrecoverable; d != 0 {
			t.Errorf("synthetic_unrecoverable delta=%g want 0 (withdraw-phase failure logs must not be read back as create evidence)", d)
		}
		if n := d2bWarnCount(captured.text(), d2bWarnUnrecoverable); n != 0 {
			t.Errorf("unrecoverable WARN lines=%d want 0", n)
		}
	})
}

// 〔守卫〕C07：攻击仍活 ⇒ 对账 3 轮 0 HTTP、合成号行仍 failed（远端本 ref 认领保留）。HEAD 绿。种子：M08。
// 子格 live：一直活（被对账轮级 LiveIDs 过滤先拦，不进 withdrawXDropLocked）；
// live_at_lock：轮级快照不活、锁内重读时已活（只有 withdrawXDropLocked 内的活攻击门能拦）——M08 的专属种子。
func TestD2B_C07_SyntheticLiveUntouched(t *testing.T) {
	for _, kind := range []string{"live", "live_at_lock"} {
		t.Run(kind, func(t *testing.T) { d2bC07(t, kind) })
	}
}
func d2bC07(t *testing.T, kind string) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		d2bCreate(b, e, x, "lost", "on_detected")
		if kind == "live" {
			b.live = true
		} else {
			b.liveFrom = 2
		}
		mark := x.mark()
		d2bRunReconcile(t, e, 3)
		if kind == "live_at_lock" && b.liveCalls.Load() < 2 {
			t.Fatalf("device: in-lock LiveIDs not reached, calls=%d", b.liveCalls.Load())
		}
		if reqs := x.since(mark); len(reqs) != 0 {
			t.Errorf("live attack HTTP=%d want 0; reqs=%s", len(reqs), d2bDescribe(reqs))
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "failed" {
			t.Errorf("live synthetic row status=%s want failed", st)
		}
		if n := x.ourClaims(); n != 1 {
			t.Errorf("live remote claims=%d want 1", n)
		}
	})
}

// C08 子格：disabled〔守卫〕连接器停用 ⇒ 对账 2 轮 0 HTTP、行仍 failed（HEAD 绿）；
// reenabled〔行为〕停用 2 轮后启用 ⇒ 下一轮补撤 validate 1 + DELETE 1、0 次 POST /rules、withdrawn（HEAD 红：skipped_synthetic）。种子：M09（disabled）。
func TestD2B_C08_SyntheticDisabledUntouched(t *testing.T) {
	for _, kind := range []string{"disabled", "reenabled"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				d2bCreate(b, e, x, "lost", "on_detected")
				logs := d2bCreateLogs(b)
				b.setEnabled(false)
				mark := x.mark()
				stop := d2Start(t, e)
				defer stop()
				time.Sleep(time.Second)
				synctest.Wait()
				if reqs := x.since(mark); len(reqs) != 0 {
					t.Errorf("disabled connector HTTP=%d want 0; reqs=%s", len(reqs), d2bDescribe(reqs))
				}
				if st := d2bRow(b, d2bSynthetic).Status; st != "failed" {
					t.Errorf("disabled synthetic row status=%s want failed", st)
				}
				if kind == "disabled" {
					return
				}
				b.setEnabled(true)
				mark = x.mark()
				time.Sleep(time.Second)
				synctest.Wait()
				d2bRecoveryCheck(t, x.since(mark), 1, 1, d2bBodies(logs))
				if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
					t.Errorf("re-enabled synthetic row status=%s want withdrawn", st)
				}
				if n := x.ourClaims(); n != 0 {
					t.Errorf("re-enabled our claims=%d want 0", n)
				}
			})
		})
	}
}

// 〔行为〕C09（TD-202）：响应里没有 on_expired 子动作（子动作从未运行），创建被 400 拒 ⇒ 合成号 failed 行；
// 攻击结束事件 + 对账 ⇒ 行被收（withdrawn）、本连接器 live 计数（CountLiveByConnector 口径：
// active/delayed/withdrawing/failed）归 0。HEAD 红因：扫尾跳过合成号、对账 skipped_synthetic ⇒ 永久 failed。
// 「删连接器 200」属 api 包，本格以 live 计数 0 代证（见 drafter-report 拿不准）。
func TestD2B_C09_ReconcileCollectsOrphanSynthetic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		b.actions = b.actions[:1]
		d2bCreate(b, e, x, "400", "on_detected")
		if d2bLiveCount(b, 7) != 1 {
			t.Fatalf("device: live count=%d want 1 after failed create", d2bLiveCount(b, 7))
		}
		a := v3Attack(101, "udp", "198.51.100.7")
		rid := 1
		a.ResponseID = &rid
		e.HandleEvent(tracker.AttackEvent{Type: "expired", DBID: 101, Attack: a})
		synctest.Wait()
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		if reqs := x.since(mark); len(reqs) != 0 {
			t.Errorf("orphan rejected synthetic HTTP=%d want 0; reqs=%s", len(reqs), d2bDescribe(reqs))
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("orphan synthetic row status=%s want withdrawn", st)
		}
		if n := d2bLiveCount(b, 7); n != 0 {
			t.Errorf("connector live count=%d want 0 (connector delete would 409)", n)
		}
	})
}

// ---------------------------------------------------------------- C10–C12 迟到创建（N1）

// d2bLate：首建（闸门开）→ 闸门关、起第二次创建 POST（updated）卡在闸门 → normal 子动作撤行 → 开闸。
// 返回首建真 id。
func d2bLate(t *testing.T, b *d2bStore, e *Engine, x *d2bRemote, afterWithdraw func()) string {
	t.Helper()
	d2bCreate(b, e, x, "", "on_detected")
	var realID string
	b.mu.Lock()
	for _, r := range b.rules {
		if r.Status == "active" {
			realID = r.ExternalRuleID
		}
	}
	b.mu.Unlock()
	if realID == "" {
		t.Fatalf("device: first create produced no active row; logs=%s", d2bLogTexts(b))
	}
	gate := make(chan struct{})
	x.setGate(gate)
	done := make(chan struct{})
	go func() { d2bCreate(b, e, x, "", "updated"); close(done) }()
	synctest.Wait()
	if x.waiting.Load() != 1 {
		close(gate)
		t.Fatalf("device: late POST not parked at gate, waiting=%d", x.waiting.Load())
	}
	x.setGate(nil)
	d2bUnblock(b, e, context.Background())
	synctest.Wait()
	if st := d2bRow(b, realID).Status; st != "withdrawn" {
		close(gate)
		t.Fatalf("device: row %s status=%s after unblock; want withdrawn", realID, st)
	}
	if afterWithdraw != nil {
		afterWithdraw()
	}
	close(gate)
	synctest.Wait()
	select {
	case <-done:
	default:
		t.Error("late create did not return")
	}
	return realID
}

// 〔行为〕C10：共享身份（另一持有方）+ 迟到 POST 把本 ref 认领加回、行已 withdrawn ⇒ 补 DELETE 1、
// 本 ref 认领 0、另一持有方仍在、行仍 withdrawn、执行日志 `late create released`。
// HEAD 红因：Upsert 撞 withdrawn 静默返回，认领永久残留（claimCount=2）。种子：M10。
func TestD2B_C10_LateCreateReleased(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		other := x.seedOther(t)
		mark := x.mark()
		id := d2bLate(t, b, e, x, nil)
		if id != other {
			t.Fatalf("device: create id=%s want shared id %s", id, other)
		}
		reqs := x.since(mark)
		if d := d2bCount(reqs, "DELETE"); d != 2 {
			t.Errorf("DELETE total=%d want 2 (unblock + late-create release); reqs=%s", d, d2bDescribe(reqs))
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our claims=%d want 0", n)
		}
		if n := x.m.claimCount(other); n != 1 {
			t.Errorf("shared rule claims=%d want 1 (other holder only)", n)
		}
		if st := d2bRow(b, id).Status; st != "withdrawn" {
			t.Errorf("row status=%s want withdrawn", st)
		}
		if !d2bAnyLog(b, "late create released") {
			t.Errorf("missing execution log `late create released`; logs=%s", d2bLogTexts(b))
		}
	})
}

// 〔行为〕C11：同 C10，但补 DELETE 回 503 ⇒ WARN `late create leaked` + 指标
// xsight_xdrop_reconcile_total{outcome="late_create_leak"} +1、行仍 withdrawn。HEAD 红因：无补 DELETE、无指标。种子：M11。
func TestD2B_C11_LateCreateLeakVisible(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		x.seedOther(t)
		captured := d2R4Capture(t)
		before := d2bReconcileMetric("late_create_leak")
		id := d2bLate(t, b, e, x, func() { x.setDelete("503") })
		if d := d2bReconcileMetric("late_create_leak") - before; d != 1 {
			t.Errorf("late_create_leak delta=%g want 1", d)
		}
		if n := d2bWarnCount(captured.text(), d2bWarnLateLeak); n < 1 {
			t.Errorf("WARN lines with prefix %q = %d want >=1; log=%q", d2bWarnLateLeak, n, captured.text())
		}
		if st := d2bRow(b, id).Status; st != "withdrawn" {
			t.Errorf("row status=%s want withdrawn (never revived)", st)
		}
	})
}

// Guard C12: with no second holder, withdrawal removes the rule; a late POST creates a new ID and active row, which the next reconciliation withdraws.
func TestD2B_C12_LateCreateNewIdReconciled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		first := d2bLate(t, b, e, x, nil)
		var second string
		b.mu.Lock()
		for _, r := range b.rules {
			if r.ExternalRuleID != first && r.Status == "active" {
				second = r.ExternalRuleID
			}
		}
		b.mu.Unlock()
		if second == "" {
			t.Fatalf("device: late create did not land a new active row; rules=%v", x.ruleIDs())
		}
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		reqs := x.since(mark)
		if d := d2bCount(reqs, "DELETE"); d != 1 {
			t.Errorf("reconcile DELETE=%d want 1; reqs=%s", d, d2bDescribe(reqs))
		}
		if st := d2bRow(b, second).Status; st != "withdrawn" {
			t.Errorf("late new-id row status=%s want withdrawn", st)
		}
		if n, rules := x.ourClaims(), x.ruleIDs(); n != 0 || len(rules) != 0 {
			t.Errorf("our claims=%d remote rules=%v; want 0 / none", n, rules)
		}
	})
}

// ---------------------------------------------------------------- C13 R3

// 〔行为〕C13：无行逾期调度，恢复入口 DELETE 500 ⇒ 调度仍 executing（⛔ failed）、失败执行日志照旧；
// 对账起跑后资格前 0 增量；资格到（缺省 I=2min 退避）对账接手 204 ⇒ completed、success 日志、不造规则行。
// HEAD 红因：Fail(S) ⇒ ListPending/ListExecuting 不再返回，再无入口。种子：M12。
func TestD2B_C13_R3_NoRowFailureRetried(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		b, e, x := d2bFixture(t)
		sa := d2NoRowSchedule(t, b.d2Store, store.ScheduledAction{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: "rule-draft", ActionType: "xdrop_unblock"}, time.Now().Add(-time.Minute), false)
		var calls atomic.Int32
		d2HTTP(t, func(r *http.Request) (*http.Response, error) {
			n := calls.Add(1)
			if r.Method != "DELETE" || !strings.HasSuffix(r.URL.Path, "/rules/rule-draft") || r.URL.Query().Get("claim_ref") != d2bRef {
				t.Errorf("wrong release identity: %s %s", r.Method, r.URL)
			}
			if n == 1 {
				return d2Reply(500, `{"code":"internal","message":"retry"}`), nil
			}
			return d2Reply(204, ""), nil
		})
		_ = x
		if err := e.RecoverScheduledActions(ctx); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("device: first no-row DELETE=%d want 1", calls.Load())
		}
		if st := d2SchedStatus(b.d2Store, sa.ID); st != "executing" {
			t.Errorf("after DELETE 500 schedule status=%s want executing", st)
		}
		if n := d2LogCount(b.d2Store, "failed"); n != 1 {
			t.Errorf("failed execution logs=%d want 1", n)
		}
		stop := d2Start(t, e)
		defer stop()
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Errorf("reconcile retried before backoff eligibility: DELETE=%d want 1", calls.Load())
		}
		time.Sleep(time.Minute + 2*time.Second)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Errorf("reconcile takeover DELETE total=%d want 2", calls.Load())
		}
		if st := d2SchedStatus(b.d2Store, sa.ID); st != "completed" {
			t.Errorf("after takeover schedule status=%s want completed", st)
		}
		if n := d2LogCount(b.d2Store, "success"); n != 1 {
			t.Errorf("success execution logs=%d want 1", n)
		}
		if rows, _ := b.XDropActiveRules().ListByAttack(ctx, 101); len(rows) != 0 {
			t.Errorf("no-row R3 path fabricated rule rows: %+v", rows)
		}
	})
}

// ---------------------------------------------------------------- C14 / C15 unblock 汇总

// 〔行为〕C14（TD-203）：每子格令规则延后 ⇒ 子动作（action 12）汇总日志 status 与 HEAD 同（success），
// error_message 精确等于 `deferred N: backoff=a, connector_disabled=b, busy=c, claimed=d`（固定顺序、只列非零；v0.2：cancelled 计 busy）。
// 子格：backoff / connector_disabled（列目标后、锁内重读时停用）/ busy（行锁被占、ctx 到期）/
// cancelled（已持锁、锁内读连接器时 ctx 被取消 ⇒ 助手回 cancelled）/ claimed（认领落败）/
// mixed（backoff + claimed + 1 条 204 删除）。HEAD 红因：跳过一律 skipped++，success 且无文案。种子：M13。
func TestD2B_C14_UnblockDeferredText(t *testing.T) {
	cases := []struct {
		name, want string
	}{
		{"backoff", "deferred 1: backoff=1"},
		{"connector_disabled", "deferred 1: connector_disabled=1"},
		{"busy", "deferred 1: busy=1"},
		{"cancelled", "deferred 1: busy=1"},
		{"claimed", "deferred 1: claimed=1"},
		{"mixed", "deferred 2: backoff=1, claimed=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, _ := d2bFixture(t)
				var deletes atomic.Int32
				d2HTTP(t, func(r *http.Request) (*http.Response, error) {
					deletes.Add(1)
					if strings.HasSuffix(r.URL.Path, "/rules/rule-c") {
						return d2Reply(204, ""), nil
					}
					return d2Reply(503, `{"code":"unavailable","message":"retry"}`), nil
				})
				seed := func(rule string) store.ScheduledAction {
					if _, err := b.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: rule, Status: "active"}); err != nil {
						t.Fatal(err)
					}
					return store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: rule}
				}
				ctx := context.Background()
				switch tc.name {
				case "backoff":
					sa := seed("rule-a")
					e.executeRecoveredXDropUnblock(ctx, sa) // 503 ⇒ failed + 退避
				case "connector_disabled":
					seed("rule-a")
					b.getDisabled.Store(true)
				case "busy":
					sa := seed("rule-a")
					unlock, ok := e.lockXDrop(ctx, xdropKeyFromSchedule(sa), true)
					if !ok {
						t.Fatal("device: could not hold row lock")
					}
					defer unlock()
					c, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					ctx = c
				case "cancelled":
					seed("rule-a")
					c, cancel := context.WithCancel(ctx)
					defer cancel()
					ctx = c
					b.hookMu.Lock()
					b.onGet = cancel
					b.hookMu.Unlock()
				case "claimed":
					seed("rule-a")
					b.loseClaim.Store("rule-a", true)
				case "mixed":
					sa := seed("rule-a")
					e.executeRecoveredXDropUnblock(ctx, sa)
					seed("rule-b")
					b.loseClaim.Store("rule-b", true)
					seed("rule-c")
				}
				before := deletes.Load()
				d2bUnblock(b, e, ctx)
				synctest.Wait()
				var summary []store.ActionExecutionLog
				for _, l := range d2bLogsFor(b, 12) {
					summary = append(summary, l)
				}
				if len(summary) != 1 {
					t.Fatalf("unblock summary logs=%d want 1; logs=%s", len(summary), d2bLogTexts(b))
				}
				if summary[0].Status != "success" {
					t.Errorf("summary status=%s want success (unchanged from HEAD)", summary[0].Status)
				}
				if summary[0].ErrorMessage != tc.want {
					t.Errorf("summary error_message=%q want %q", summary[0].ErrorMessage, tc.want)
				}
				if tc.name == "cancelled" {
					if st := d2bRow(b, "rule-a").Status; st != "active" || ctx.Err() == nil {
						t.Errorf("device: cancelled case row status=%s ctxErr=%v; want active (stopped before claim) and cancelled ctx", st, ctx.Err())
					}
				}
				wantDeletes := int32(0)
				if tc.name == "mixed" {
					wantDeletes = 1
				}
				if d := deletes.Load() - before; d != wantDeletes {
					t.Errorf("unblock DELETE=%d want %d", d, wantDeletes)
				}
			})
		})
	}
}

// C15 子格：zero_rows〔行为〕攻击无任何规则行 ⇒ 子动作恰 1 条 skipped + no_rules_to_unblock + dao12f 已钉文案、0 条 failed
// （HEAD 红：failed `no external_rule_ids found for unblock`）。种子：M14。
// list_error〔守卫〕列表出错 ⇒ failed、文案 `list xdrop_active_rules: ...`（HEAD 绿）。种子：M15。
func TestD2B_C15_UnblockZeroRowsSkipped(t *testing.T) {
	for _, kind := range []string{"zero_rows", "list_error"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				if kind == "list_error" {
					b.listErr.Store(true)
				}
				d2bUnblock(b, e, context.Background())
				synctest.Wait()
				if n := x.mark(); n != 0 {
					t.Errorf("HTTP=%d want 0", n)
				}
				logs := d2bLogsFor(b, 12)
				if len(logs) != 1 {
					t.Fatalf("unblock logs=%d want 1; logs=%s", len(logs), d2bLogTexts(b))
				}
				l := logs[0]
				if kind == "zero_rows" {
					if l.Status != "skipped" || l.SkipReason != SkipReasonNoRulesToUnblock || l.ErrorMessage != "no active, delayed or failed rules to unblock" {
						t.Errorf("zero rows log status=%s skip=%q msg=%q; want skipped / no_rules_to_unblock / dao12f text", l.Status, l.SkipReason, l.ErrorMessage)
					}
					return
				}
				if l.Status != "failed" || !strings.HasPrefix(l.ErrorMessage, "list xdrop_active_rules: ") {
					t.Errorf("list error log status=%s msg=%q; want failed / `list xdrop_active_rules: ...`", l.Status, l.ErrorMessage)
				}
			})
		})
	}
}

// ---------------------------------------------------------------- C16 ACT-02

// 〔行为〕C16：显式目标停用 ⇒ 该目标 0 POST、写 skipped + connector_disabled（ConnectorName=该连接器名字，不要求 ConnectorID）。
// 子格 mixed：显式目标 = {7 启用, 8 停用} ⇒ 8 上 0 POST、7 照常 POST 1 + success。
// 子格 all_disabled（v0.3 R4）：显式目标 = {8 停用}，全局另有启用的 7 ⇒ 任何连接器 0 POST（⛔ 过滤后落入 ListEnabled 全局兜底）、8 的 skip 日志 1 条。
// HEAD 红因：XDropTargets().List 不滤 enabled，停用目标照 POST。种子：M16（mixed）、「过滤后落入全局兜底」（all_disabled）。
func TestD2B_C16_DisabledExplicitTargetNoPost(t *testing.T) {
	for _, kind := range []string{"mixed", "all_disabled"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				b.extra = []store.XDropConnector{{ID: 8, Name: "xdrop-disabled", APIURL: "http://192.0.2.22/api/v1", APIKey: v3TestKey, TimeoutMs: 1000, Enabled: false}}
				b.targets = []int{7, 8}
				if kind == "all_disabled" {
					b.targets = []int{8}
				}
				d2bCreate(b, e, x, "", "on_detected")
				hosts := map[string]int{}
				for _, r := range x.since(0) {
					if r.Method == "POST" {
						hosts[r.Host]++
					}
				}
				wantEnabled := 1
				if kind == "all_disabled" {
					wantEnabled = 0
				}
				if hosts["192.0.2.22"] != 0 || hosts["192.0.2.20"] != wantEnabled {
					t.Errorf("POST by host=%v; want disabled .22=0, enabled .20=%d", hosts, wantEnabled)
				}
				var skipped, success int
				for _, l := range d2bLogsFor(b, 11) {
					if l.Status == "skipped" && l.SkipReason == SkipReasonConnectorDisabled && l.ConnectorName == "xdrop-disabled" {
						skipped++
					}
					if l.Status == "success" && l.ConnectorID != nil && *l.ConnectorID == 7 {
						success++
					}
				}
				if skipped != 1 || success != wantEnabled {
					t.Errorf("connector_disabled skip logs=%d success logs=%d; want 1/%d; logs=%s", skipped, success, wantEnabled, d2bLogTexts(b))
				}
			})
		})
	}
}

// ---------------------------------------------------------------- C18 脱敏

// C18 子格：transport_error / http_503〔行为〕创建传输错 / 503 正文含 URL 与假 key ⇒ 执行日志、合成号行 error_message、
// 返回错误均不含 key / URL / userinfo；503 仍保留 `HTTP 503` 与 v3 code（HEAD 红：原样回显）。种子：M18。
// not_sent_prefix〔守卫〕NewRequest 失败 ⇒ 执行日志仍以 `create request:` 开头（HEAD 绿；§4-1 NotSent 判据依赖，M19 另由 C04 守）。
// not_sent_redacted〔行为，v0.2 加〕连接器 URL 含 userinfo 假 key 且含控制字符 ⇒ NotSent 文案（执行日志 / 行 / 返回错误）
// 不含 key / URL / userinfo，且仍以 `create request:` 开头（HEAD 红：parse 错误原样回显 URL）。
// v0.3（N6 / R5）：transport_error / http_503 / not_sent_redacted 另断言执行日志 ResponseBody 同样不含禁词（M28），
// 文案不含 `DELETE`；transport_error 文案须含 `POST`。对外 action-log / 攻击详情返回由 tests 包 TestD2B_C18_CreateErrorRedactedAPI 守。
func TestD2B_C18_CreateErrorRedacted(t *testing.T) {
	for _, kind := range []string{"transport_error", "http_503", "not_sent_prefix", "not_sent_redacted"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				const secret = "d2b-obviously-fake-credential-0123456789"
				b.mu.Lock()
				b.conn.APIKey = secret
				good := b.conn.APIURL
				if kind == "not_sent_prefix" {
					b.conn.APIURL = good + "\x7f"
				}
				if kind == "not_sent_redacted" {
					b.conn.APIURL = "http://user:" + secret + "@192.0.2.20/api/v1\x7f"
				}
				b.mu.Unlock()
				x.mu.Lock()
				x.reflectKey = secret
				x.mu.Unlock()
				mode := map[string]string{"transport_error": "reflect", "http_503": "reflect503"}[kind]
				x.setPost(mode)
				a := v3Attack(101, "udp", "198.51.100.7")
				_, err := executeXDrop(context.Background(), b, b.actions[0], a, "confirmed", a.DstIP, "draft", "on_detected", 101, nil, e)
				x.setPost("")
				logs := d2bCreateLogs(b)
				if len(logs) != 1 {
					t.Fatalf("device: create failure logs=%d want 1; logs=%s", len(logs), d2bLogTexts(b))
				}
				if kind == "not_sent_prefix" {
					if !strings.HasPrefix(logs[0].ErrorMessage, "create request:") {
						t.Errorf("NotSent log=%q; want `create request:` prefix", logs[0].ErrorMessage)
					}
					return
				}
				if kind == "not_sent_redacted" && !strings.HasPrefix(logs[0].ErrorMessage, "create request:") {
					t.Errorf("NotSent log=%q; want `create request:` prefix kept", logs[0].ErrorMessage)
				}
				errText := ""
				if err != nil {
					errText = err.Error()
				}
				destinations := map[string]string{"execution": logs[0].ErrorMessage, "row": d2bRow(b, d2bSynthetic).ErrorMessage, "returned": errText, "response_body": logs[0].ResponseBody}
				for name, text := range destinations {
					if text == "" && name != "response_body" {
						t.Errorf("%s detail empty", name)
					}
					if name != "response_body" && strings.Contains(text, "DELETE") {
						t.Errorf("%s labels create error as DELETE: %s", name, text)
					}
					for _, forbidden := range []string{secret, "user:", "http://", "https://"} {
						if strings.Contains(text, forbidden) {
							t.Errorf("%s exposes %q: %s", name, forbidden, text)
						}
					}
				}
				if kind == "transport_error" && !strings.Contains(logs[0].ErrorMessage, "POST") {
					t.Errorf("transport error lost method POST: %s", logs[0].ErrorMessage)
				}
				if kind == "http_503" {
					for _, want := range []string{"HTTP 503", "upstream_error"} {
						if !strings.Contains(logs[0].ErrorMessage, want) {
							t.Errorf("503 lost safe diagnostic %q: %s", want, logs[0].ErrorMessage)
						}
					}
				}
			})
		})
	}
}

// ---------------------------------------------------------------- C19 P3-b

// C19 subcases ended_sweep / startup_cleanup: call withdrawXDropLocked under the row lock with a schedule but no rule row; it must not panic.
// Current callers cannot reach this state (sweeps pass row-derived sa.ID=0), so the helper is called directly; a nil dereference is classified as a behavior case.
func TestD2B_C19_P3bNilRowGuard(t *testing.T) {
	for _, origin := range []string{"ended-sweep", "startup-cleanup"} {
		t.Run(strings.ReplaceAll(origin, "-", "_"), func(t *testing.T) {
			b, e, _ := d2bFixture(t)
			var calls atomic.Int32
			d2HTTP(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return d2Reply(204, ""), nil })
			sa := d2NoRowSchedule(t, b.d2Store, store.ScheduledAction{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: "rule-draft", ActionType: "xdrop_unblock"}, time.Now().Add(-time.Minute), true)
			var outcome string
			panicked := func() (p any) {
				defer func() { p = recover() }()
				unlock, ok := e.lockXDrop(context.Background(), xdropKeyFromSchedule(sa), true)
				if !ok {
					t.Fatal("device: lock unavailable")
				}
				defer unlock()
				outcome = e.withdrawXDropLocked(context.Background(), sa, origin, store.TriggerPhaseOnExpired, time.Time{})
				return nil
			}()
			if panicked != nil {
				t.Errorf("%s no-row withdrawal panicked: %v", origin, panicked)
				return
			}
			t.Logf("%s no-row outcome=%s HTTP=%d", origin, outcome, calls.Load())
		})
	}
}

// ---------------------------------------------------------------- v0.2 新增 C20–C22

func d2bRetry(e *Engine, rule string) xdropRetry {
	e.xdropMu.Lock()
	defer e.xdropMu.Unlock()
	return e.xdropRetries[xdropRuleKey{101, 11, 7, rule}.String()]
}

// 〔行为〕C20（v0.3）：读执行日志失败 ⇒ list_error +1、0 HTTP、行不变，且 ⛔ 记退避、⛔ 改已有退避。
// 子格 immediate_retry：一轮对账读失败；恢复日志后**同一时刻**经 normal 入口重试 ⇒ 当次补撤（validate 1 + DELETE 1、withdrawn）。
//
//	读失败若记了退避（M20b），normal 入口此刻被退避挡住 ⇒ 红。
//
// 子格 prior_backoff：先有一次补撤失败（validate 503 ⇒ 退避 failures=1、next_retry=T）；资格到后读日志失败 ⇒
//
//	0 HTTP、行 failed、list_error +1、退避条目逐字段不变（failures 与 next_retry）；恢复后立即 normal 入口 ⇒ 当次补撤。
//
// HEAD 红因：skipped_synthetic / normal 入口 0 HTTP 本地关闭，不读日志、无 list_error、无退避。种子：M20（读失败当 0 份）、M20b（读失败记退避）。
func TestD2B_C20_SyntheticLogReadFailure(t *testing.T) {
	for _, kind := range []string{"immediate_retry", "prior_backoff"} {
		t.Run(kind, func(t *testing.T) { d2bC20(t, kind) })
	}
}
func d2bC20(t *testing.T, kind string) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		b, e, x := d2bFixture(t)
		d2bCreate(b, e, x, "lost", "on_detected")
		logs := d2bCreateLogs(b)
		if len(logs) != 1 || x.ourClaims() != 1 {
			t.Fatalf("device: Uncertain create not seeded; logs=%s", d2bLogTexts(b))
		}
		var prior xdropRetry
		if kind == "prior_backoff" {
			x.setValidate("503")
			mark := x.mark()
			d2bUnblock(b, e, ctx)
			synctest.Wait()
			x.setValidate("")
			prior = d2bRetry(e, d2bSynthetic)
			if v := d2bCountKind(x.since(mark), "validate"); v != 1 || prior.failures != 1 {
				t.Errorf("first failed attempt validate=%d retry.failures=%d; want 1/1", v, prior.failures)
			}
			time.Sleep(d2DefaultI + time.Second)
		}
		b.logErr.Store(true)
		before := d2bReconcileMetric("list_error")
		mark := x.mark()
		if kind == "immediate_retry" {
			e.reconcileXDropRound(ctx)
		} else {
			d2bUnblock(b, e, ctx)
		}
		synctest.Wait()
		if reqs := x.since(mark); len(reqs) != 0 {
			t.Errorf("log read failure HTTP=%d want 0; reqs=%s", len(reqs), d2bDescribe(reqs))
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "failed" {
			t.Errorf("log read failure row status=%s want failed (unchanged)", st)
		}
		if d := d2bReconcileMetric("list_error") - before; d != 1 {
			t.Errorf("list_error delta=%g want 1", d)
		}
		after := d2bRetry(e, d2bSynthetic)
		if after.failures != prior.failures || !after.nextAttempt.Equal(prior.nextAttempt) {
			t.Errorf("read failure changed backoff: failures %d -> %d, next_retry %s -> %s", prior.failures, after.failures, prior.nextAttempt, after.nextAttempt)
		}
		b.logErr.Store(false)
		mark = x.mark()
		d2bUnblock(b, e, ctx) // 同一时刻立即重试
		synctest.Wait()
		d2bRecoveryCheck(t, x.since(mark), 1, 1, d2bBodies(logs))
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("after log recovery row status=%s want withdrawn", st)
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("after log recovery our claims=%d want 0", n)
		}
	})
}

// Behavior C21: two logs share one synthetic ID: one valid (Uncertain, default body) and one truncated (1500-byte comment, invalid JSON).
// Reconciliation validates the valid body once (without claim_ref), sends one DELETE and no POST /rules, and releases this ref's claim; the truncated body sends no HTTP and increments synthetic_unrecoverable once.
// At least one WARN line is required. Once all valid bodies are released, the row becomes withdrawn; the truncated body's remote claim is reported as a warning.
// Seed M21 detects abandoning the entire row when any body is invalid, resulting in no recovery HTTP requests.
func TestD2B_C21_SyntheticMixedBodies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		d2bCreate(b, e, x, "lost", "on_detected")
		valid := d2bCreateLogs(b)
		b.actions[0].XDropCustomPayload = json.RawMessage(`{"dst_ip":"198.51.100.7","dst_port":53,"action":"drop","comment":"` + strings.Repeat("c", 1500) + `"}`)
		d2bCreate(b, e, x, "lost", "on_detected")
		logs := d2bCreateLogs(b)
		if len(valid) != 1 || len(logs) != 2 || !json.Valid([]byte(valid[0].RequestBody)) || json.Valid([]byte(logs[1].RequestBody)) || x.ourClaims() != 2 {
			t.Fatalf("device: want one valid + one truncated body and 2 remote claims; logs=%d ourClaims=%d", len(logs), x.ourClaims())
		}
		var validRule string
		x.m.mu.Lock()
		for id, r := range x.m.rules {
			if r.fields["dst_port"] == 0 {
				validRule = id
			}
		}
		x.m.mu.Unlock()
		captured := d2R4Capture(t)
		before := d2bReconcileMetric("synthetic_unrecoverable")
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		reqs := x.since(mark)
		d2bRecoveryCheck(t, reqs, 1, 1, d2bBodies(valid))
		for _, r := range reqs {
			if r.Method == "DELETE" && !strings.HasSuffix(r.Path, "/rules/"+validRule) {
				t.Errorf("DELETE path=%s want valid-body rule %s", r.Path, validRule)
			}
		}
		if n := x.m.claimCount(validRule); n != 0 {
			t.Errorf("valid-body rule claims=%d want 0", n)
		}
		if n := x.ourClaims(); n != 1 {
			t.Errorf("our remaining claims=%d want 1 (truncated copy left as alert)", n)
		}
		if d := d2bReconcileMetric("synthetic_unrecoverable") - before; d != 1 {
			t.Errorf("synthetic_unrecoverable delta=%g want 1", d)
		}
		if n := d2bWarnCount(captured.text(), d2bWarnUnrecoverable); n < 1 {
			t.Errorf("WARN lines with prefix %q = %d want >=1; log=%q", d2bWarnUnrecoverable, n, captured.text())
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("row status=%s want withdrawn", st)
		}
	})
}

// 〔行为〕C22：共享身份 + 迟到创建（同 C10），但迟到 POST 落地回读时，同键（真 id）行锁正被对账 worker 持有：
// worker 因该键的 executing 调度成为候选，锁内首次规则读被屏障卡住。开闸放 POST ⇒ 释放屏障 ⇒
// 迟到创建须等锁后回读 withdrawn 并补 DELETE：DELETE 总数 2、本 ref 认领 0、另一持有方仍在、日志 `late create released`。
// HEAD 红因：迟到创建不回读（claimCount=2）。种子：M22（try-lock 忙即放弃 ⇒ 0 补 DELETE）。
func TestD2B_C22_LateCreateWaitsLock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		b, e, x := d2bFixture(t)
		other := x.seedOther(t)
		mark := x.mark()
		d2bCreate(b, e, x, "", "on_detected")
		if d2bRow(b, other).Status != "active" {
			t.Fatalf("device: first create row status=%s want active", d2bRow(b, other).Status)
		}
		gate := make(chan struct{})
		x.setGate(gate)
		lateDone := make(chan struct{})
		go func() { d2bCreate(b, e, x, "", "updated"); close(lateDone) }()
		synctest.Wait()
		if x.waiting.Load() != 1 {
			close(gate)
			t.Fatalf("device: late POST not parked, waiting=%d", x.waiting.Load())
		}
		x.setGate(nil)
		d2bUnblock(b, e, ctx)
		synctest.Wait()
		if st := d2bRow(b, other).Status; st != "withdrawn" {
			close(gate)
			t.Fatalf("device: row status=%s after unblock want withdrawn", st)
		}
		sa := store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: other, ScheduledFor: time.Now().Add(-time.Minute)}
		id, err := b.ScheduledActions().Schedule(ctx, &sa)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ScheduledActions().MarkExecuting(ctx, id); err != nil {
			t.Fatal(err)
		}
		entered := make(chan chan struct{}, 1)
		b.hookMu.Lock()
		b.ruleBarrier = entered
		b.hookMu.Unlock()
		roundDone := make(chan struct{})
		go func() { e.reconcileXDropRound(ctx); close(roundDone) }()
		synctest.Wait()
		var release chan struct{}
		select {
		case release = <-entered:
		default:
			close(gate)
			t.Fatal("device: reconcile worker did not reach in-lock barrier")
		}
		close(gate) // 迟到 POST 落地；此时同键锁由 worker 持有
		synctest.Wait()
		close(release)
		synctest.Wait()
		for name, ch := range map[string]chan struct{}{"late create": lateDone, "reconcile round": roundDone} {
			select {
			case <-ch:
			default:
				t.Errorf("%s did not return", name)
			}
		}
		reqs := x.since(mark)
		if d := d2bCount(reqs, "DELETE"); d != 2 {
			t.Errorf("DELETE total=%d want 2 (unblock + late-create release after waiting lock); reqs=%s", d, d2bDescribe(reqs))
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our claims=%d want 0", n)
		}
		if n := x.m.claimCount(other); n != 1 {
			t.Errorf("shared rule claims=%d want 1 (other holder only)", n)
		}
		if st := d2bRow(b, other).Status; st != "withdrawn" {
			t.Errorf("row status=%s want withdrawn", st)
		}
		if !d2bAnyLog(b, "late create released") {
			t.Errorf("missing execution log `late create released`; logs=%s", d2bLogTexts(b))
		}
	})
}

// ---------------------------------------------------------------- v0.3 新增 C23–C27

// d2bNotSentCreate：连接器 URL 临时带控制字符 ⇒ 真实 NewRequest 失败（NotSent），请求体与正常创建逐字节相同。
func d2bNotSentCreate(b *d2bStore, e *Engine, x *d2bRemote) {
	b.mu.Lock()
	good := b.conn.APIURL
	b.conn.APIURL = good + "\x7f"
	b.mu.Unlock()
	d2bCreate(b, e, x, "", "on_detected")
	b.mu.Lock()
	b.conn.APIURL = good
	b.mu.Unlock()
}

// 〔行为〕C23（N1）：同一 body 两条创建日志，一条 Uncertain（远端已建、回包丢失）+ 一条 NotSent；两种时间顺序各一子格
// （d2bLogs 按写入顺序返回，两子格分别让 Uncertain / NotSent 排前）⇒ 对账：validate 1 + DELETE 1、0 次 POST /rules、本 ref 释放、行 withdrawn。
// HEAD 红因：skipped_synthetic、0 HTTP。种子：M23（先按 body 去重后分类 ⇒ 某一顺序只剩 NotSent ⇒ 本地关闭、认领泄漏）。
func TestD2B_C23_SameBodyMixedEvidence(t *testing.T) {
	for _, order := range []string{"uncertain_first", "notsent_first"} {
		t.Run(order, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				if order == "uncertain_first" {
					d2bCreate(b, e, x, "lost", "on_detected")
					time.Sleep(time.Second)
					d2bNotSentCreate(b, e, x)
				} else {
					d2bNotSentCreate(b, e, x)
					time.Sleep(time.Second)
					d2bCreate(b, e, x, "lost", "on_detected")
				}
				logs := d2bCreateLogs(b)
				bodies := d2bBodies(logs)
				if len(logs) != 2 || len(bodies) != 1 || x.ourClaims() != 1 {
					t.Fatalf("device: logs=%d distinct bodies=%d ourClaims=%d; want 2/1/1; logs=%s", len(logs), len(bodies), x.ourClaims(), d2bLogTexts(b))
				}
				mark := x.mark()
				d2bRunReconcile(t, e, 2)
				d2bRecoveryCheck(t, x.since(mark), 1, 1, bodies)
				if n := x.ourClaims(); n != 0 {
					t.Errorf("our claims=%d want 0", n)
				}
				if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
					t.Errorf("row status=%s want withdrawn", st)
				}
			})
		})
	}
}

// 〔行为〕C24（N2）：真行 R（同 atk/act/conn）与合成号 S 并存，S 有 Uncertain 日志、validate 会得 R。
// 子格 future_schedule：R 为 delayed 且有未来 pending 调度 ⇒ 对账处理 S：validate 1、⛔ DELETE、S withdrawn、
//
//	执行日志 `synthetic claim owned by rule <R>`；R 行仍 delayed、调度仍 pending、本 ref 认领仍在。
//
// Subcase same_round: R is active with no schedule; S and R are candidates from the same snapshot. Barriers coordinate two recovery workers
// so S takes ownership while R is nonterminal, then R withdraws itself: exactly one DELETE and both rows withdrawn.
// Subcase real_done_first: S has obtained R in preflight; a barrier holds the response until R has withdrawn itself and stored withdrawn.
// S reads the terminal state under the lock and still sends a recovery DELETE: two DELETEs total, no claim for this ref, and both rows withdrawn.
// HEAD 红因：S skipped_synthetic 留 failed。种子：M24（不查真键直接 DELETE）= future_schedule 的「DELETE 0」。
func TestD2B_C24_RealKeyOwnsClaim(t *testing.T) {
	for _, kind := range []string{"future_schedule", "same_round"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				b, e, x := d2bFixture(t)
				d2bCreate(b, e, x, "", "on_detected")
				var real string
				b.mu.Lock()
				for _, r := range b.rules {
					if r.Status == "active" {
						real = r.ExternalRuleID
					}
				}
				b.mu.Unlock()
				d2bCreate(b, e, x, "lost", "on_detected")
				if real == "" || d2bRow(b, d2bSynthetic).Status != "failed" || x.ourClaims() != 1 {
					t.Fatalf("device: real=%q S=%s ourClaims=%d; want real row, failed S, 1 claim", real, d2bRow(b, d2bSynthetic).Status, x.ourClaims())
				}
				schedID := 0
				if kind == "future_schedule" {
					if _, err := b.XDropActiveRules().Upsert(ctx, &store.XDropActiveRule{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: real, Status: "delayed"}); err != nil {
						t.Fatal(err)
					}
					sa := store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: real, ScheduledFor: time.Now().Add(10 * time.Minute)}
					id, err := b.ScheduledActions().Schedule(ctx, &sa)
					if err != nil {
						t.Fatal(err)
					}
					schedID = id
					// As in C28, let R's own round worker finish its locked
					// future-schedule check before S tries R. This case tests
					// lifecycle handoff, not incidental busy/retry scheduling.
					x.validateDelay.Store(int64(500 * time.Millisecond))
				}
				mark := x.mark()
				if kind == "same_round" {
					d2bC24Handoff(t, b, e, x, real, mark)
				} else {
					d2bRunReconcile(t, e, 3)
				}
				reqs := x.since(mark)
				if n := d2bCountKind(reqs, "create") + d2bCountKind(reqs, "batch"); n != 0 {
					t.Errorf("POST /rules or non-validate batch=%d want 0; reqs=%s", n, d2bDescribe(reqs))
				}
				if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
					t.Errorf("S status=%s want withdrawn", st)
				}
				realDeletes := 0
				for _, r := range reqs {
					if d2bKind(r) == "delete" && strings.HasSuffix(r.Path, "/rules/"+real) {
						realDeletes++
					}
				}
				if kind == "future_schedule" {
					if v, d := d2bCountKind(reqs, "validate"), d2bCountKind(reqs, "delete"); v != 1 || d != 0 {
						t.Errorf("validate=%d DELETE=%d want 1/0 (claim owned by real key R); reqs=%s", v, d, d2bDescribe(reqs))
					}
					if st := d2bRow(b, real).Status; st != "delayed" {
						t.Errorf("real row status=%s want delayed (unchanged)", st)
					}
					if st := d2SchedStatus(b.d2Store, schedID); st != "pending" {
						t.Errorf("real key schedule status=%s want pending (unchanged)", st)
					}
					if n := x.ourClaims(); n != 1 {
						t.Errorf("our claims=%d want 1 (left to R's own schedule)", n)
					}
					if !d2bAnyLog(b, "synthetic claim owned by rule "+real) {
						t.Errorf("missing execution log `synthetic claim owned by rule %s`; logs=%s", real, d2bLogTexts(b))
					}
					return
				}
				if realDeletes != 1 {
					t.Errorf("DELETE on real rule %s = %d want 1 (only R's own path); reqs=%s", real, realDeletes, d2bDescribe(reqs))
				}
				if st := d2bRow(b, real).Status; st != "withdrawn" {
					t.Errorf("real row status=%s want withdrawn", st)
				}
				if n := x.ourClaims(); n != 0 {
					t.Errorf("our claims=%d want 0", n)
				}
			})
		})
	}
	t.Run("real_done_first", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx := context.Background()
			b, e, x := d2bFixture(t)
			d2bCreate(b, e, x, "", "on_detected")
			ids := x.ruleIDs()
			if len(ids) != 1 {
				t.Fatalf("device: real rules=%v want one", ids)
			}
			real := ids[0]
			d2bCreate(b, e, x, "lost", "on_detected")
			if d2bRow(b, real).Status != "active" || d2bRow(b, d2bSynthetic).Status != "failed" || x.ourClaims() != 1 {
				t.Fatal("device: want active R, failed S and one claim")
			}
			mark := x.mark()
			validated, resumeS := make(chan struct{}), make(chan struct{})
			var release sync.Once
			resume := func() { release.Do(func() { close(resumeS) }) }
			defer resume()
			d2HTTP(t, func(r *http.Request) (*http.Response, error) {
				resp, err := x.roundTrip(r)
				if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rules/batch") {
					// Capture the real pre-withdrawal response, not a fabricated id.
					close(validated)
					<-resumeS
				}
				return resp, err
			})
			sDone := make(chan struct{})
			go func() {
				defer close(sDone)
				e.executeRecoveredXDropUnblock(ctx, xdropScheduleForRule(d2bRow(b, d2bSynthetic)))
			}()
			synctest.Wait()
			select {
			case <-validated:
			default:
				t.Fatal("device: S did not reach the post-validation barrier")
			}
			if n := d2bCountKind(x.since(mark), "delete"); n != 0 {
				t.Errorf("before R runs DELETE=%d want 0", n)
			}
			e.executeRecoveredXDropUnblock(ctx, xdropScheduleForRule(d2bRow(b, real)))
			if st := d2bRow(b, real).Status; st != "withdrawn" {
				t.Errorf("before releasing S, R status=%s want withdrawn", st)
			}
			if n := d2bCountKind(x.since(mark), "delete"); n != 1 {
				t.Errorf("R's own DELETE=%d want 1", n)
			}
			if n := x.ourClaims(); n != 0 {
				t.Errorf("after R withdrawal claims=%d want 0", n)
			}
			resume()
			synctest.Wait()
			select {
			case <-sDone:
			default:
				t.Fatal("S did not finish after the response barrier opened")
			}
			reqs := x.since(mark)
			d2bRecoveryCheck(t, reqs, 1, 2, d2bBodies(d2bCreateLogs(b)))
			for _, r := range reqs {
				if d2bKind(r) == "delete" && !strings.HasSuffix(r.Path, "/rules/"+real) {
					t.Errorf("DELETE targets %s want real rule %s", r.Path, real)
				}
			}
			for _, id := range []string{d2bSynthetic, real} {
				if st := d2bRow(b, id).Status; st != "withdrawn" {
					t.Errorf("rule %s status=%s want withdrawn (never revived)", id, st)
				}
			}
			if n := x.ourClaims(); n != 0 {
				t.Errorf("final claims=%d want 0", n)
			}
		})
	})
}

// Both candidates come from one real store snapshot. R waits before entering
// the shared withdrawal helper: waiting inside its DELETE would hold R's lock
// and prevent S from making the in-lock ownership decision this case exercises.
func d2bC24Handoff(t *testing.T, b *d2bStore, e *Engine, x *d2bRemote, real string, mark int) {
	t.Helper()
	ctx := context.Background()
	rows, err := b.XDropActiveRules().ListActive(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("device: round candidates=%+v err=%v want S and R", rows, err)
	}
	candidates := map[string]store.ScheduledAction{}
	for _, row := range rows {
		candidates[row.ExternalRuleID] = xdropScheduleForRule(row)
	}
	sDone, rDone, startR := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var release sync.Once
	resume := func() { release.Do(func() { close(startR) }) }
	defer resume()
	go func() {
		defer close(rDone)
		<-startR
		e.executeRecoveredXDropUnblock(ctx, candidates[real])
	}()
	go func() {
		defer close(sDone)
		e.executeRecoveredXDropUnblock(ctx, candidates[d2bSynthetic])
	}()
	synctest.Wait()
	select {
	case <-sDone:
	default:
		t.Fatal("S did not finish while R was waiting before withdrawal")
	}
	if n := d2bCountKind(x.since(mark), "delete"); n != 0 {
		t.Errorf("S DELETE before R starts=%d want 0 (owned by nonterminal R)", n)
	}
	if st := d2bRow(b, real).Status; st != "active" {
		t.Errorf("R before its worker starts=%s want active", st)
	}
	if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
		t.Errorf("S after handoff=%s want withdrawn", st)
	}
	if !d2bAnyLog(b, "synthetic claim owned by rule "+real) {
		t.Errorf("missing in-lock handoff log for R=%s; logs=%s", real, d2bLogTexts(b))
	}
	resume()
	synctest.Wait()
	select {
	case <-rDone:
	default:
		t.Fatal("R did not finish after the handoff barrier opened")
	}
}

// 〔行为〕C25（N3）：原创建已建并认领（回包丢失 ⇒ Uncertain），随后规则 action 被改（UI 改为 rate_limit 1000）；
// 补撤 validate 返回 rule_conflict + rule_id ⇒ DELETE(rule_id, 本 ref) 204、本 ref 认领 0、S withdrawn、0 次 POST /rules。
// HEAD 红因：skipped_synthetic、0 HTTP。种子：M25（冲突当 Rejected ⇒ 本地关闭不释放）。
func TestD2B_C25_ConflictAfterActionChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		d2bCreate(b, e, x, "lost", "on_detected")
		logs := d2bCreateLogs(b)
		ids := x.ruleIDs()
		if len(logs) != 1 || len(ids) != 1 || x.ourClaims() != 1 {
			t.Fatalf("device: logs=%d rules=%v ourClaims=%d", len(logs), ids, x.ourClaims())
		}
		x.m.mu.Lock()
		x.m.rules[ids[0]].fields["action"] = "rate_limit"
		x.m.rules[ids[0]].fields["rate_limit"] = int64(1000)
		x.m.mu.Unlock()
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		reqs := x.since(mark)
		d2bRecoveryCheck(t, reqs, 1, 1, d2bBodies(logs))
		for _, r := range reqs {
			if d2bKind(r) == "delete" && !strings.HasSuffix(r.Path, "/rules/"+ids[0]) {
				t.Errorf("DELETE path=%s want conflict rule_id %s", r.Path, ids[0])
			}
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our claims=%d want 0", n)
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("S status=%s want withdrawn", st)
		}
	})
}

// 〔守卫〕C26（N4 契约）：另一 ref 持有同身份规则、expires_in=1h（有限）；xSight 原创建根本没到服务器（drop ⇒ Uncertain）。
// 对账补撤后：该规则 expiry 仍为 1h、enabled 不变、另一持有方认领仍在、0 次 POST /rules。
// 替身 expiry 旁表模拟 rc2 existingResult：无 expires_in 的同身份创建会把有限期限改永久。HEAD 0 HTTP 故绿；
// 实施后与 C01 合看。种子：M26（补撤改回重发 POST ⇒ expiry 变永久 + POST /rules 1）。
func TestD2B_C26_OtherHolderExpiryUnchanged(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		other := x.seedOtherBody(t, `{"dst_ip":"198.51.100.7","protocol":"udp","action":"drop","claim_ref":"`+d2bOtherRef+`","expires_in":"1h"}`)
		x.m.mu.Lock()
		enabled := x.m.rules[other].fields["enabled"]
		x.m.mu.Unlock()
		d2bCreate(b, e, x, "drop", "on_detected")
		if len(d2bCreateLogs(b)) != 1 || x.expiryOf(other) != "1h" || x.m.claimCount(other) != 1 {
			t.Fatalf("device: logs=%s expiry=%q claims=%d", d2bLogTexts(b), x.expiryOf(other), x.m.claimCount(other))
		}
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		reqs := x.since(mark)
		if n := d2bCountKind(reqs, "create") + d2bCountKind(reqs, "batch"); n != 0 {
			t.Errorf("POST /rules or non-validate batch=%d want 0; reqs=%s", n, d2bDescribe(reqs))
		}
		if got := x.expiryOf(other); got != "1h" {
			t.Errorf("other holder expiry=%q want 1h (unchanged)", got)
		}
		x.m.mu.Lock()
		gotEnabled := x.m.rules[other] != nil && x.m.rules[other].fields["enabled"] == enabled
		x.m.mu.Unlock()
		if !gotEnabled {
			t.Errorf("other holder rule missing or enabled changed")
		}
		if n := x.m.claimCount(other); n != 1 {
			t.Errorf("other holder claims=%d want 1", n)
		}
	})
}

// 〔行为〕C27（N5）：先有 NotSent 合成号 S；第二次创建 POST 在途（闸门）；normal 子动作把 S 本地关闭为 withdrawn；
// 放行后该 POST 实际已建（本 ref 认领）但回包丢失 ⇒ 失败分支回读 S 已 withdrawn ⇒ 立即 validate + DELETE。
// 子格 released：validate 1 + DELETE 1、0 次 POST /rules（放行之后）、本 ref 认领 0、S 仍 withdrawn。
// 子格 leak：补 DELETE 503 ⇒ late_create_leak +1、WARN 前缀行 ≥1、S 仍 withdrawn（⛔ 复活）。
// 子格 real_key_busy / lock_timeout（v0.4，r2 N2）见 d2bC27Busy。
// HEAD 红因：失败分支 Upsert 被 withdrawn 守卫挡住后无人处理 ⇒ 认领泄漏。种子：M27（失败分支不回读合成号）、M31（真键 try-lock 忙即放弃）。
func TestD2B_C27_LateFailureOntoWithdrawnSynthetic(t *testing.T) {
	for _, kind := range []string{"released", "leak", "real_key_busy", "lock_timeout"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "real_key_busy" || kind == "lock_timeout" {
				d2bC27Busy(t, kind)
				return
			}
			synctest.Test(t, func(t *testing.T) {
				ctx := context.Background()
				b, e, x := d2bFixture(t)
				d2bNotSentCreate(b, e, x)
				if d2bRow(b, d2bSynthetic).Status != "failed" {
					t.Fatalf("device: NotSent S status=%s want failed", d2bRow(b, d2bSynthetic).Status)
				}
				gate := make(chan struct{})
				x.setGate(gate)
				done := make(chan struct{})
				go func() { d2bCreate(b, e, x, "lost", "updated"); close(done) }()
				synctest.Wait()
				if x.waiting.Load() != 1 {
					close(gate)
					t.Fatalf("device: in-flight POST not parked, waiting=%d", x.waiting.Load())
				}
				x.setGate(nil)
				d2bUnblock(b, e, ctx)
				synctest.Wait()
				if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
					close(gate)
					t.Fatalf("device: S status=%s after unblock want withdrawn", st)
				}
				captured := d2R4Capture(t)
				before := d2bReconcileMetric("late_create_leak")
				if kind == "leak" {
					x.setDelete("503")
				}
				mark := x.mark()
				close(gate)
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Error("late failed create did not return")
				}
				reqs := x.since(mark)
				if v, d, c := d2bCountKind(reqs, "validate"), d2bCountKind(reqs, "delete"), d2bCountKind(reqs, "create"); v != 1 || d != 1 || c != 0 {
					t.Errorf("after late failure validate=%d DELETE=%d POST /rules=%d want 1/1/0; reqs=%s", v, d, c, d2bDescribe(reqs))
				}
				if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
					t.Errorf("S status=%s want withdrawn (never revived)", st)
				}
				if kind == "released" {
					if n, rules := x.ourClaims(), x.ruleIDs(); n != 0 || len(rules) != 0 {
						t.Errorf("our claims=%d remote rules=%v; want 0 / none", n, rules)
					}
					return
				}
				if d := d2bReconcileMetric("late_create_leak") - before; d != 1 {
					t.Errorf("late_create_leak delta=%g want 1", d)
				}
				if n := d2bWarnCount(captured.text(), d2bWarnLateLeak); n < 1 {
					t.Errorf("WARN lines with prefix %q = %d want >=1; log=%q", d2bWarnLateLeak, n, captured.text())
				}
			})
		})
	}
}

// d2bC27Busy（v0.4，r2 N2，移植 C22 屏障）：另一持有方共享身份 R；先正常创建得真行 R，再 NotSent 得合成号 S；
// 第三次创建（lost，在途闸门）；unblock 把 R、S 都撤为 withdrawn（R 的 DELETE 释放本 ref）；开闸前给 R 挂 executing 调度
// 并起一轮对账，worker 因该调度成为 R 的候选、锁内首次规则读被屏障卡住（= 真键锁被 worker 持有）。开闸 ⇒ 迟到 POST
// 实际已建（本 ref 认领加回 R）但回包丢失 ⇒ 失败分支回读 S withdrawn ⇒ 预检得 R ⇒ 对 R 有限等锁（预算 TimeoutMs × 2）。
// real_key_busy：持锁期间 DELETE 0；放屏障后 DELETE(R, ref) 1、validate 1、POST /rules 0、本 ref 认领 0、另一持有方仍在、
//
//	S 与 R 仍 withdrawn、late_create_leak 不增。（R 行 withdrawn ⇒ 残留调度 ⛔ 算接管，§4-1 第 6 步 / N1。）
//
// lock_timeout：连接器 TimeoutMs=100（预算 200ms）；持锁并推进 1s ⇒ 迟到创建返回、late_create_leak +1、WARN 前缀行 ≥1、DELETE 0；
//
//	放屏障后仍 DELETE 0（⛔ 超时后再补）、S 仍 withdrawn、本 ref 认领仍 1。
func d2bC27Busy(t *testing.T, kind string) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		b, e, x := d2bFixture(t)
		if kind == "lock_timeout" {
			b.mu.Lock()
			b.conn.TimeoutMs = 100
			b.mu.Unlock()
		}
		other := x.seedOther(t)
		d2bCreate(b, e, x, "", "on_detected")
		d2bNotSentCreate(b, e, x)
		if d2bRow(b, other).Status != "active" || d2bRow(b, d2bSynthetic).Status != "failed" {
			t.Fatalf("device: R status=%s S status=%s; want active / failed", d2bRow(b, other).Status, d2bRow(b, d2bSynthetic).Status)
		}
		gate := make(chan struct{})
		x.setGate(gate)
		done := make(chan struct{})
		go func() { d2bCreate(b, e, x, "lost", "updated"); close(done) }()
		synctest.Wait()
		if x.waiting.Load() != 1 {
			close(gate)
			t.Fatalf("device: in-flight POST not parked, waiting=%d", x.waiting.Load())
		}
		x.setGate(nil)
		d2bUnblock(b, e, ctx)
		synctest.Wait()
		if r, s, n := d2bRow(b, other).Status, d2bRow(b, d2bSynthetic).Status, x.ourClaims(); r != "withdrawn" || s != "withdrawn" || n != 0 {
			close(gate)
			t.Fatalf("device: after unblock R=%s S=%s ourClaims=%d; want withdrawn / withdrawn / 0", r, s, n)
		}
		sa := store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: other, ScheduledFor: time.Now().Add(-time.Minute)}
		id, err := b.ScheduledActions().Schedule(ctx, &sa)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ScheduledActions().MarkExecuting(ctx, id); err != nil {
			t.Fatal(err)
		}
		entered := make(chan chan struct{}, 1)
		b.hookMu.Lock()
		b.ruleBarrier = entered
		b.hookMu.Unlock()
		roundDone := make(chan struct{})
		go func() { e.reconcileXDropRound(ctx); close(roundDone) }()
		synctest.Wait()
		var release chan struct{}
		select {
		case release = <-entered:
		default:
			close(gate)
			t.Fatal("device: reconcile worker did not reach in-lock barrier on real key")
		}
		captured := d2R4Capture(t)
		before := d2bReconcileMetric("late_create_leak")
		mark := x.mark()
		close(gate) // 迟到 POST 落地（本 ref 认领加回 R）、回包丢失；真键锁由 worker 持有
		synctest.Wait()
		if x.ourClaims() != 1 {
			close(release)
			t.Fatalf("device: late POST did not re-add our claim, ourClaims=%d", x.ourClaims())
		}
		if d := d2bCountKind(x.since(mark), "delete"); d != 0 {
			t.Errorf("DELETE while real key held=%d want 0; reqs=%s", d, d2bDescribe(x.since(mark)))
		}
		if kind == "lock_timeout" {
			time.Sleep(time.Second) // 预算 2 × 100ms 已过，屏障仍未放
			synctest.Wait()
			select {
			case <-done:
			default:
				t.Error("late failed create still waiting after lock budget expired")
			}
			if d := d2bReconcileMetric("late_create_leak") - before; d != 1 {
				t.Errorf("late_create_leak delta=%g want 1 (lock wait timed out)", d)
			}
			if n := d2bWarnCount(captured.text(), d2bWarnLateLeak); n < 1 {
				t.Errorf("WARN lines with prefix %q = %d want >=1; log=%q", d2bWarnLateLeak, n, captured.text())
			}
		}
		close(release)
		synctest.Wait()
		for name, ch := range map[string]chan struct{}{"late failed create": done, "reconcile round": roundDone} {
			select {
			case <-ch:
			default:
				t.Errorf("%s did not return", name)
			}
		}
		reqs := x.since(mark)
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("S status=%s want withdrawn (never revived)", st)
		}
		if st := d2bRow(b, other).Status; st != "withdrawn" {
			t.Errorf("R status=%s want withdrawn (never revived)", st)
		}
		if n := x.m.claimCount(other) - x.ourClaims(); n != 1 {
			t.Errorf("other holder claims=%d want 1", n)
		}
		if kind == "lock_timeout" {
			if d := d2bCountKind(reqs, "delete"); d != 0 {
				t.Errorf("DELETE after lock timeout=%d want 0 (counted as leak, no retry); reqs=%s", d, d2bDescribe(reqs))
			}
			if n := x.ourClaims(); n != 1 {
				t.Errorf("our claims=%d want 1 (leaked)", n)
			}
			return
		}
		if v, d, c := d2bCountKind(reqs, "validate"), d2bCountKind(reqs, "delete"), d2bCountKind(reqs, "create"); v != 1 || d != 1 || c != 0 {
			t.Errorf("after release validate=%d DELETE=%d POST /rules=%d want 1/1/0; reqs=%s", v, d, c, d2bDescribe(reqs))
		}
		for _, r := range reqs {
			if d2bKind(r) == "delete" && (!strings.HasSuffix(r.Path, "/rules/"+other) || r.Ref != d2bRef) {
				t.Errorf("DELETE path=%s ref=%s want /rules/%s ref=%s", r.Path, r.Ref, other, d2bRef)
			}
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our claims=%d want 0", n)
		}
		if d := d2bReconcileMetric("late_create_leak") - before; d != 0 {
			t.Errorf("late_create_leak delta=%g want 0", d)
		}
	})
}

// ---------------------------------------------------------------- v0.4 新增 C28–C30

// 〔行为〕C28（r2 N1）：另一持有方共享身份 R；正常创建得真行 R ⇒ unblock 撤为 withdrawn（本 ref 释放）；
// 再给 R 挂 executing 调度并让 ScheduledActions().Complete 恒失败（残留调度确定留存）；预检应答延迟 500ms 假时间
// （见 d2bRemote.validateDelay：避开 R worker Complete 重试持锁窗口，否则 S 每轮 busy）；随后迟到 lost 创建
// （本 ref 认领加回 R、合成号 S failed + Uncertain）。对账 2 轮处理 S：validate 1 得 R ⇒ R 行 withdrawn ⇒
// 残留调度 ⛔ 算「已交真行」⇒ DELETE(R, ref) 1、0 次 POST /rules、本 ref 认领 0、另一持有方仍在、R 仍 withdrawn、S withdrawn。
// HEAD 红因：skipped_synthetic、0 HTTP。种子：M30（withdrawn 真行的残留调度算接管 ⇒ DELETE 0、本 ref 认领 1）。
func TestD2B_C28_WithdrawnRealRowLeftoverSchedule(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		b, e, x := d2bFixture(t)
		other := x.seedOther(t)
		d2bCreate(b, e, x, "", "on_detected")
		d2bUnblock(b, e, ctx)
		if st, n := d2bRow(b, other).Status, x.ourClaims(); st != "withdrawn" || n != 0 {
			t.Fatalf("device: R status=%s ourClaims=%d after unblock; want withdrawn / 0", st, n)
		}
		sa := store.ScheduledAction{ActionType: "xdrop_unblock", AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: other, ScheduledFor: time.Now().Add(-time.Minute)}
		schedID, err := b.ScheduledActions().Schedule(ctx, &sa)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ScheduledActions().MarkExecuting(ctx, schedID); err != nil {
			t.Fatal(err)
		}
		b.completeErr.Store(true)
		x.validateDelay.Store(int64(500 * time.Millisecond))
		d2bCreate(b, e, x, "lost", "updated")
		logs := d2bCreateLogs(b)
		if len(logs) != 1 || d2bRow(b, d2bSynthetic).Status != "failed" || x.ourClaims() != 1 || x.m.claimCount(other) != 2 {
			t.Fatalf("device: create logs=%d S=%s ourClaims=%d claims(R)=%d; want 1 / failed / 1 / 2", len(logs), d2bRow(b, d2bSynthetic).Status, x.ourClaims(), x.m.claimCount(other))
		}
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		time.Sleep(time.Second) // 排空末轮 R worker 的 Complete 重试（xdropWrite 至多 300ms）
		synctest.Wait()
		reqs := x.since(mark)
		if st := d2SchedStatus(b.d2Store, schedID); st != "executing" {
			t.Errorf("device: leftover schedule status=%s want executing (Complete fault must keep it)", st)
		}
		d2bRecoveryCheck(t, reqs, 1, 1, d2bBodies(logs))
		for _, r := range reqs {
			if d2bKind(r) == "delete" && !strings.HasSuffix(r.Path, "/rules/"+other) {
				t.Errorf("DELETE path=%s want real rule %s", r.Path, other)
			}
		}
		if n := x.ourClaims(); n != 0 {
			t.Errorf("our claims=%d want 0 (withdrawn real row's leftover schedule is not a takeover)", n)
		}
		if n := x.m.claimCount(other); n != 1 {
			t.Errorf("R claims=%d want 1 (other holder only)", n)
		}
		if st := d2bRow(b, other).Status; st != "withdrawn" {
			t.Errorf("R row status=%s want withdrawn (never revived)", st)
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("S status=%s want withdrawn", st)
		}
	})
}

// 〔行为〕C29（r2 N4）：另一持有方持有身份 R；两份仅 comment 不同的 Uncertain body（同身份 ⇒ 同 R、本 ref 认领 1 份）。
// 子格 dedupe：对账 2 轮 ⇒ validate 2、DELETE 1（R, ref）、0 次 POST /rules、本 ref 认领 0、另一持有方仍在、S withdrawn。
// 子格 first_delete_503：首次 DELETE 503 ⇒ 该轮 DELETE 总 1（⛔ 第二份再删同 R）、S failed、退避 failures=1；
//
//	下一资格（退避到期后再跑 1 轮）DELETE 恰 1 ⇒ S withdrawn、本 ref 认领 0。validate 计数不钉（登记）。
//
// HEAD 红因：skipped_synthetic、0 HTTP。种子：M32（同 R 不去重 ⇒ dedupe DELETE 2；first_delete_503 首轮 DELETE 2）。
func TestD2B_C29_SameRealIdTwoBodies(t *testing.T) {
	for _, kind := range []string{"dedupe", "first_delete_503"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				other := x.seedOther(t) // 创建侧把 protocol 钉成 udp，身份与 d2bOtherBody 相同
				for _, c := range []string{"c1", "c2"} {
					b.actions[0].XDropCustomPayload = json.RawMessage(`{"dst_ip":"198.51.100.7","action":"drop","comment":"` + c + `"}`)
					d2bCreate(b, e, x, "lost", "on_detected")
				}
				logs := d2bCreateLogs(b)
				bodies := d2bBodies(logs)
				if len(logs) != 2 || len(bodies) != 2 || len(x.ruleIDs()) != 1 || x.ourClaims() != 1 || x.m.claimCount(other) != 2 {
					t.Fatalf("device: logs=%d bodies=%d rules=%v ourClaims=%d claims(R)=%d; want 2/2/[R]/1/2", len(logs), len(bodies), x.ruleIDs(), x.ourClaims(), x.m.claimCount(other))
				}
				mark := x.mark()
				if kind == "dedupe" {
					d2bRunReconcile(t, e, 2)
					reqs := x.since(mark)
					d2bRecoveryCheck(t, reqs, 2, 1, bodies)
				} else {
					x.deleteFailN.Store(1)
					d2bRunReconcile(t, e, 1)
					reqs := x.since(mark)
					if d, c := d2bCountKind(reqs, "delete"), d2bCountKind(reqs, "create")+d2bCountKind(reqs, "batch"); d != 1 || c != 0 {
						t.Errorf("first round DELETE=%d POST /rules+batch=%d want 1/0 (same R not retried in the same attempt); reqs=%s", d, c, d2bDescribe(reqs))
					}
					if st := d2bRow(b, d2bSynthetic).Status; st != "failed" {
						t.Errorf("after first round S status=%s want failed", st)
					}
					r := d2bRetry(e, d2bSynthetic)
					if r.failures != 1 {
						t.Errorf("S backoff failures=%d want 1", r.failures)
					}
					if wait := time.Until(r.nextAttempt); wait > 0 {
						time.Sleep(wait + time.Second)
					}
					mark2 := x.mark()
					d2bRunReconcile(t, e, 1)
					reqs2 := x.since(mark2)
					if d, c := d2bCountKind(reqs2, "delete"), d2bCountKind(reqs2, "create")+d2bCountKind(reqs2, "batch"); d != 1 || c != 0 {
						t.Errorf("next eligibility DELETE=%d POST /rules+batch=%d want 1/0; reqs=%s", d, c, d2bDescribe(reqs2))
					}
				}
				for _, r := range x.since(mark) {
					if d2bKind(r) == "delete" && (!strings.HasSuffix(r.Path, "/rules/"+other) || r.Ref != d2bRef) {
						t.Errorf("DELETE path=%s ref=%s want /rules/%s ref=%s", r.Path, r.Ref, other, d2bRef)
					}
				}
				if n := x.ourClaims(); n != 0 {
					t.Errorf("our claims=%d want 0", n)
				}
				if n := x.m.claimCount(other); n != 1 {
					t.Errorf("R claims=%d want 1 (other holder only)", n)
				}
				if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
					t.Errorf("S status=%s want withdrawn", st)
				}
			})
		})
	}
}

// 〔行为〕C30（r2 N3 契约 · 能力边界）：lost 创建 ⇒ 本 ref 认领 R、S failed + Uncertain；随后替身模拟 XDrop UI Update
// 改匹配字段 dst_ip（id 与认领保留）⇒ 预检旧体得契约「不存在」（rule 对象在、existing=false、rule.id 空、无 error）。
// 对账 2 轮 ⇒ validate 1、DELETE 0、0 次 POST /rules；S withdrawn；synthetic_identity_not_found +1；执行日志含
// `claim cannot be proven absent`；对账期间新增的执行日志 ⛔ 含 `released`；R 上本 ref 认领仍 1（登记能力边界，非期望修复）。
// HEAD 红因：skipped_synthetic、0 HTTP、无该指标。种子：M33（「不存在」写成 released / 不计数）。
func TestD2B_C30_IdentityEditedNotFound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, e, x := d2bFixture(t)
		d2bCreate(b, e, x, "lost", "on_detected")
		logs := d2bCreateLogs(b)
		ids := x.ruleIDs()
		if len(logs) != 1 || len(ids) != 1 || x.ourClaims() != 1 {
			t.Fatalf("device: logs=%d rules=%v ourClaims=%d; want 1/[R]/1", len(logs), ids, x.ourClaims())
		}
		x.uiUpdate(t, ids[0], "dst_ip", "198.51.100.8")
		before := d2bReconcileMetric("synthetic_identity_not_found")
		nLogs := len(b.logSnapshot())
		mark := x.mark()
		d2bRunReconcile(t, e, 2)
		reqs := x.since(mark)
		if v, d, c := d2bCountKind(reqs, "validate"), d2bCountKind(reqs, "delete"), d2bCountKind(reqs, "create")+d2bCountKind(reqs, "batch"); v != 1 || d != 0 || c != 0 {
			t.Errorf("validate=%d DELETE=%d POST /rules+batch=%d want 1/0/0; reqs=%s", v, d, c, d2bDescribe(reqs))
		}
		for _, r := range reqs {
			if d2bKind(r) == "validate" && !d2bValidateItemOK(r.Body, d2bBodies(logs)) {
				t.Errorf("validate body %s is not the logged body minus claim_ref", r.Body)
			}
		}
		if st := d2bRow(b, d2bSynthetic).Status; st != "withdrawn" {
			t.Errorf("S status=%s want withdrawn", st)
		}
		if d := d2bReconcileMetric("synthetic_identity_not_found") - before; d != 1 {
			t.Errorf("synthetic_identity_not_found delta=%g want 1", d)
		}
		if !d2bAnyLog(b, "claim cannot be proven absent") {
			t.Errorf("missing execution log `claim cannot be proven absent`; logs=%s", d2bLogTexts(b))
		}
		for _, l := range b.logSnapshot()[nLogs:] {
			if strings.Contains(l.ErrorMessage, "released") {
				t.Errorf("new execution log claims release: rule=%s status=%s msg=%q", l.ExternalRuleID, l.Status, l.ErrorMessage)
			}
		}
		if n, got := x.ourClaims(), x.ruleIDs(); n != 1 || len(got) != 1 || got[0] != ids[0] {
			t.Errorf("our claims=%d rules=%v; want 1 on %s (capability boundary: claim stays)", n, got, ids[0])
		}
	})
}

// Behavior C30b: malformed preflight responses in malformed_empty (`results:[{}]`) and
// malformed_norule (a result without a rule object) count as protocol errors and fail that body.
// A lost create leaves S failed with an Uncertain log and this ref claiming R. One reconciliation round sends one validate, no DELETE, and no POST /rules or batch.
// S stays failed with backoff failures=1; synthetic_identity_not_found does not increase, and this ref still holds one claim.
// The test requires preflight validation and backoff accounting instead of skipping the synthetic row.
// Seed M33b detects treating malformed responses as not-found, which would withdraw S, increment the metric, and leave failures=0.
func TestD2B_C30b_MalformedValidateIsFailure(t *testing.T) {
	for _, mode := range []string{"malformed_empty", "malformed_norule"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				d2bCreate(b, e, x, "lost", "on_detected")
				logs := d2bCreateLogs(b)
				if len(logs) != 1 || d2bRow(b, d2bSynthetic).Status != "failed" || x.ourClaims() != 1 {
					t.Fatalf("device: logs=%d S=%s ourClaims=%d; want 1 / failed / 1", len(logs), d2bRow(b, d2bSynthetic).Status, x.ourClaims())
				}
				x.setValidate(mode)
				before := d2bReconcileMetric("synthetic_identity_not_found")
				mark := x.mark()
				d2bRunReconcile(t, e, 1)
				reqs := x.since(mark)
				if v, d, c := d2bCountKind(reqs, "validate"), d2bCountKind(reqs, "delete"), d2bCountKind(reqs, "create")+d2bCountKind(reqs, "batch"); v != 1 || d != 0 || c != 0 {
					t.Errorf("validate=%d DELETE=%d POST /rules+batch=%d want 1/0/0; reqs=%s", v, d, c, d2bDescribe(reqs))
				}
				if st := d2bRow(b, d2bSynthetic).Status; st != "failed" {
					t.Errorf("S status=%s want failed (non-contract shape is a failed share, not not-found)", st)
				}
				if r := d2bRetry(e, d2bSynthetic); r.failures != 1 {
					t.Errorf("S backoff failures=%d want 1", r.failures)
				}
				if d := d2bReconcileMetric("synthetic_identity_not_found") - before; d != 0 {
					t.Errorf("synthetic_identity_not_found delta=%g want 0", d)
				}
				if n := x.ourClaims(); n != 1 {
					t.Errorf("our claims=%d want 1", n)
				}
			})
		})
	}
}

// ---------------------------------------------------------------- 装置自检

// 〔装置〕D01：d2bRemote 的 rc2 预检替身与续期旁表自检（HEAD 应绿；它红 ⇒ 下游 v0.3 格读数作废）。
// 三态：existing（返回真 id、existing=true）/ rule_conflict（error.rule_id=真 id）/ 不存在（rule.id 空、existing=false）；
// item 含 claim_ref ⇒ 整体 400；预检前后规则集、认领、expiry 均不变；无 expires_in 的同身份创建把 1h 改为永久（rc2 existingResult）。
func TestD2B_D01_ValidateFakeSelfCheck(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		x := d2bInstall(t)
		other := x.seedOtherBody(t, `{"dst_ip":"198.51.100.7","protocol":"udp","action":"drop","claim_ref":"`+d2bOtherRef+`","expires_in":"1h"}`)
		call := func(body string) (int, map[string]any) {
			req, _ := http.NewRequest(http.MethodPost, "http://192.0.2.20/api/v1/rules/batch?validate=1", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+v3TestKey)
			resp, err := http.DefaultTransport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var out map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&out)
			return resp.StatusCode, out
		}
		item := func(out map[string]any) map[string]any {
			rs, _ := out["results"].([]any)
			if len(rs) != 1 {
				t.Fatalf("results=%v", out)
			}
			return rs[0].(map[string]any)
		}
		code, out := call(`{"items":[{"dst_ip":"198.51.100.7","protocol":"udp","action":"drop","comment":"x"}]}`)
		r := item(out)
		if rule, _ := r["rule"].(map[string]any); code != 200 || out["epoch"] != "epoch-test" || r["existing"] != true || rule["id"] != other {
			t.Errorf("existing: HTTP %d %v", code, out)
		}
		code, out = call(`{"items":[{"dst_ip":"198.51.100.7","protocol":"udp","action":"rate_limit","rate_limit":5}]}`)
		if e, _ := item(out)["error"].(map[string]any); code != 200 || e["code"] != "rule_conflict" || e["rule_id"] != other {
			t.Errorf("conflict: HTTP %d %v", code, out)
		}
		code, out = call(`{"items":[{"dst_ip":"198.51.100.8","protocol":"udp","action":"drop"}]}`)
		r = item(out)
		if rule, _ := r["rule"].(map[string]any); code != 200 || r["existing"] != false || rule["id"] != "" {
			t.Errorf("absent: HTTP %d %v", code, out)
		}
		if code, out = call(`{"items":[{"dst_ip":"198.51.100.7","protocol":"udp","action":"drop","claim_ref":"a101.x11"}]}`); code != 400 || out["field"] != "claim_ref" {
			t.Errorf("item with claim_ref: HTTP %d %v want 400 field=claim_ref", code, out)
		}
		if n := len(x.ruleIDs()); n != 1 || x.m.claimCount(other) != 1 || x.expiryOf(other) != "1h" {
			t.Errorf("validate mutated ledger: rules=%d claims=%d expiry=%q", n, x.m.claimCount(other), x.expiryOf(other))
		}
		req, _ := http.NewRequest(http.MethodPost, "http://192.0.2.20/api/v1/rules", strings.NewReader(`{"dst_ip":"198.51.100.7","protocol":"udp","action":"drop","claim_ref":"a101.x11"}`))
		req.Header.Set("Authorization", "Bearer "+v3TestKey)
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 || x.expiryOf(other) != "" || x.m.claimCount(other) != 2 {
			t.Errorf("existing create side effect: HTTP %d expiry=%q claims=%d; want 200 / permanent / 2", resp.StatusCode, x.expiryOf(other), x.m.claimCount(other))
		}
		logged := map[string]bool{`{"action":"drop","claim_ref":"a101.x11","comment":"c","dst_ip":"198.51.100.7","protocol":"udp"}`: true}
		for body, want := range map[string]bool{
			`{"items":[{"protocol":"udp","dst_ip":"198.51.100.7","comment":"c","action":"drop"}]}`:                        true,
			`{"items":[{"protocol":"udp","dst_ip":"198.51.100.7","comment":"c","action":"drop","claim_ref":"a101.x11"}]}`: false,
			`{"items":[{"protocol":"udp","dst_ip":"198.51.100.7","action":"drop"}]}`:                                      false,
			`{"claim_ref":"a101.x11","items":[{"protocol":"udp","dst_ip":"198.51.100.7","comment":"c","action":"drop"}]}`: false,
		} {
			if got := d2bValidateItemOK([]byte(body), logged); got != want {
				t.Errorf("d2bValidateItemOK(%s)=%t want %t", body, got, want)
			}
		}
		// v0.4 R2：契约「不存在」判别。真形状为 true；{} / 缺 rule 字段的非契约形状为 false（不得当「不存在」）。
		raw := func(body string) []byte {
			req, _ := http.NewRequest(http.MethodPost, "http://192.0.2.20/api/v1/rules/batch?validate=1", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+v3TestKey)
			resp, err := http.DefaultTransport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return b
		}
		absentBody := `{"items":[{"dst_ip":"198.51.100.8","protocol":"udp","action":"drop"}]}`
		if b := raw(absentBody); !d2bContractNotFound(b) {
			t.Errorf("contract not-found shape rejected: %s", b)
		}
		for _, mode := range []string{"malformed_empty", "malformed_norule"} {
			x.setValidate(mode)
			if b := raw(absentBody); d2bContractNotFound(b) {
				t.Errorf("%s shape accepted as not-found: %s", mode, b)
			}
		}
		x.setValidate("")
		for _, body := range []string{`{"epoch":"e","results":[{"index":0,"rule":{"id":"rule_x"},"existing":false}]}`, `{"epoch":"e","results":[{"index":0,"rule":{"id":""},"existing":true}]}`, `{"epoch":"e","results":[{"index":0,"rule":{},"existing":false}]}`, `{"epoch":"e","results":[]}`} {
			if d2bContractNotFound([]byte(body)) {
				t.Errorf("non-contract shape accepted as not-found: %s", body)
			}
		}
		// v0.4 C30 装置：uiUpdate 改匹配字段后旧身份查不到、id 与认领保留。
		x.uiUpdate(t, other, "dst_ip", "198.51.100.9")
		if b := raw(`{"items":[{"dst_ip":"198.51.100.7","protocol":"udp","action":"drop"}]}`); !d2bContractNotFound(b) || x.m.claimCount(other) != 2 || len(x.ruleIDs()) != 1 {
			t.Errorf("uiUpdate: old identity validate=%s claims=%d rules=%d; want not-found / 2 / 1", b, x.m.claimCount(other), len(x.ruleIDs()))
		}
		if v, c := d2bCountKind(x.since(0), "validate"), d2bCountKind(x.since(0), "create"); v != 8 || c != 1 {
			t.Errorf("request kinds validate=%d create=%d want 4/1", v, c)
		}
	})
}

// ---------------------------------------------------------------- r2 C31 创建证据提交窗口（行为）

// C31: pause the actual creation-log commit after the active-rule upsert.
// The channel barrier fixes the interleaving without replacing production methods.
type d2bC31LogBarrierStore struct {
	*d2bStore
	entered chan struct{}
	release chan struct{}
}

type d2bC31LogBarrierRepo struct {
	store.ActionExecLogRepo
	s *d2bC31LogBarrierStore
}

func (s *d2bC31LogBarrierStore) ActionExecLog() store.ActionExecLogRepo {
	return d2bC31LogBarrierRepo{s.d2bStore.ActionExecLog(), s}
}

func (r d2bC31LogBarrierRepo) Create(ctx context.Context, l *store.ActionExecutionLog) (int, error) {
	if l.ExternalRuleID == d2bSynthetic && l.Status == "failed" && l.TriggerPhase == "updated" {
		close(r.s.entered)
		<-r.s.release
	}
	return r.ActionExecLogRepo.Create(ctx, l)
}

// 〔行为〕C31: committed creation evidence must be visible before the final readback.
func TestD2B_C31_CreateReadbackAfterLogCommit(t *testing.T) {
	for _, mode := range []string{"lost", "created503", "noid"} {
		for _, prior := range []bool{false, true} {
			name := mode + "/empty_history"
			if prior {
				name = mode + "/prior_rejected"
			}
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					b, _, x := d2bFixture(t)
					if prior {
						d2bCreate(b, NewEngine(b, "auto"), x, "400", "on_detected")
					}
					s := &d2bC31LogBarrierStore{b, make(chan struct{}), make(chan struct{})}
					e := NewEngine(s, "auto")
					x.setPost(mode)
					done := make(chan struct{})
					go func() {
						a := v3Attack(101, "udp", "198.51.100.7")
						_, _ = executeXDrop(context.Background(), s, b.actions[0], a, "confirmed", a.DstIP, "review", "updated", 101, nil, e)
						close(done)
					}()
					<-s.entered
					if got := d2bRow(b, d2bSynthetic).Status; got != "failed" || x.ourClaims() != 1 {
						close(s.release)
						t.Fatalf("setup row=%s claims=%d", got, x.ourClaims())
					}
					mark := x.mark()
					e.reconcileXDropRound(context.Background())
					synctest.Wait()
					t.Logf("before log commit: S=%s claims=%d", d2bRow(b, d2bSynthetic).Status, x.ourClaims())
					close(s.release)
					<-done
					for n := 0; n < 3; n++ {
						e.reconcileXDropRound(context.Background())
						synctest.Wait()
					}
					if got := d2bRow(b, d2bSynthetic).Status; got != "withdrawn" {
						t.Errorf("after log commit and 3 reconcile rounds: S=%s; want withdrawn", got)
					}
					reqs := x.since(mark)
					if x.ourClaims() != 0 {
						t.Errorf("after log commit and 3 reconcile rounds: S=%s claims=%d validate=%d DELETE=%d; want claims=0", d2bRow(b, d2bSynthetic).Status, x.ourClaims(), d2bCountKind(reqs, "validate"), d2bCountKind(reqs, "delete"))
					}
				})
			})
		}
	}
}

// 〔守卫〕C32: a validate redirect must never become a non-validate batch POST.
func TestD2B_C32_ValidateNoRedirect(t *testing.T) {
	for _, code := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, e, x := d2bFixture(t)
				d2bCreate(b, e, x, "lost", "on_detected")
				var calls, validates, followPosts, deletes atomic.Int32
				d2HTTP(t, func(r *http.Request) (*http.Response, error) {
					calls.Add(1)
					if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/rules/batch") && r.URL.Query().Get("validate") == "1" {
						validates.Add(1)
						resp := d2Reply(code, "")
						resp.Header.Set("Location", "/api/v1/rules/batch")
						return resp, nil
					}
					if r.Method == http.MethodPost {
						followPosts.Add(1)
					}
					if r.Method == http.MethodDelete {
						deletes.Add(1)
					}
					return d2Reply(http.StatusCreated, `{"id":"unexpected-create"}`), nil
				})
				e.reconcileXDropRound(context.Background())
				synctest.Wait()
				if calls.Load() != 1 || validates.Load() != 1 || followPosts.Load() != 0 || deletes.Load() != 0 {
					t.Errorf("redirect %d: HTTP=%d validate=%d subsequent POST=%d DELETE=%d; want 1/1/0/0", code, calls.Load(), validates.Load(), followPosts.Load(), deletes.Load())
				}
				if got := d2bRow(b, d2bSynthetic).Status; got != "failed" {
					t.Errorf("redirect %d: S=%s; want failed", code, got)
				}
				if retry := d2bRetry(e, d2bSynthetic); retry.failures != 1 || !retry.nextAttempt.After(time.Now()) {
					t.Errorf("redirect %d: retry=%+v; want one failure with future retry", code, retry)
				}
				if got := x.ourClaims(); got != 1 {
					t.Errorf("redirect %d: claims=%d; want untouched claim", code, got)
				}
			})
		})
	}
}
