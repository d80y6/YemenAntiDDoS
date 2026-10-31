package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/littlewolf9527/xsight/controller/internal/action"
	"github.com/littlewolf9527/xsight/controller/internal/api"
	"github.com/littlewolf9527/xsight/controller/internal/ingestion"
	"github.com/littlewolf9527/xsight/controller/internal/store"
)

const dao13eForbidden = "This response is referenced by outbound (sends) rules — cannot add xDrop/BGP action"
const dao13eOutbound = "outbound_block_forbidden"

// Threshold reads and writes copy rows, so assertions observe persisted state
// rather than a pointer mutated by the handler before Update.
type dao13eThresholds struct {
	store.ThresholdRepo
	rows []store.Threshold
	err  error
}

func (r *dao13eThresholds) List(context.Context) ([]store.Threshold, error) {
	return dao12aCopy(r.rows), r.err
}
func (r *dao13eThresholds) Get(_ context.Context, id int) (*store.Threshold, error) {
	for _, row := range r.rows {
		if row.ID == id {
			copy := dao12aCopy(row)
			return &copy, nil
		}
	}
	return nil, errors.New("threshold not found")
}
func (r *dao13eThresholds) Update(_ context.Context, row *store.Threshold) error {
	for i := range r.rows {
		if r.rows[i].ID == row.ID {
			r.rows[i] = dao12aCopy(*row)
			return nil
		}
	}
	return errors.New("threshold not found")
}

type dao13eStore struct {
	*dao12aStore
	thresholds *dao13eThresholds
}

type dao13ePrefixes struct {
	store.PrefixRepo
	rows []store.WatchPrefix
}
type dao13ePrefixStore struct {
	store.Store
	prefixes *dao13ePrefixes
}

func (s dao13ePrefixStore) Prefixes() store.PrefixRepo { return s.prefixes }
func (r *dao13ePrefixes) List(context.Context) ([]store.WatchPrefix, error) {
	return dao12aCopy(r.rows), nil
}
func (r *dao13ePrefixes) Get(_ context.Context, id int) (*store.WatchPrefix, error) {
	for _, row := range r.rows {
		if row.ID == id {
			copy := dao12aCopy(row)
			return &copy, nil
		}
	}
	return nil, errors.New("prefix not found")
}
func (r *dao13ePrefixes) Update(_ context.Context, row *store.WatchPrefix) error {
	for i := range r.rows {
		if r.rows[i].ID == row.ID {
			r.rows[i] = dao12aCopy(*row)
			return nil
		}
	}
	return errors.New("prefix not found")
}

func (s *dao13eStore) Thresholds() store.ThresholdRepo { return s.thresholds }
func dao13eFixture(t *testing.T, kind string) *dao13eStore {
	t.Helper()
	s := dao12aFixture(t, kind, false)
	return &dao13eStore{s, &dao13eThresholds{ThresholdRepo: s.Thresholds(), rows: []store.Threshold{{
		ID: 9, PrefixID: intPtr(8), ResponseID: intPtr(1), Direction: "sends",
		Domain: "internal_ip", Decoder: "udp", Unit: "pps", Comparison: "over", Value: 100, Enabled: true,
	}}}}
}

func dao13eRequest(t *testing.T, s store.Store, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	setupRouter(s).ServeHTTP(w, req)
	return w
}
func dao13eStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
	}
}
func dao13eError(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"error": want}) {
		t.Errorf("body=%v want only error=%q", got, want)
	}
}

func TestDao13e_A1(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		for _, edit := range []string{"POST", "PUTPriority", "PUTDisabled"} {
			t.Run(edit+"/"+kind, func(t *testing.T) {
				s := dao13eFixture(t, kind)
				method, path, body := "POST", "/api/responses/1/actions", dao12aBody(kind)
				if edit != "POST" {
					method, path, body = "PUT", "/api/actions/10", map[string]any{"priority": 2}
					if edit == "PUTDisabled" {
						body = map[string]any{"enabled": false}
					}
				}
				w := dao13eRequest(t, s, method, path, body)
				dao13eStatus(t, w, 400)
				dao13eError(t, w, dao13eForbidden)
				dao12aCheck(t, "ZeroWrites", dao12aWrites(s.dao12aStore), "")
			})
		}
	}
	t.Run("LaterSendsReference", func(t *testing.T) {
		for _, first := range []string{"Receives", "OtherResponse", "NilResponse"} {
			for _, kind := range []string{"xdrop", "bgp"} {
				for _, method := range []string{"POST", "PUT"} {
					t.Run(first+"/"+kind+"/"+method, func(t *testing.T) {
						s := dao13eFixture(t, kind)
						target := s.thresholds.rows[0]
						unrelated := dao12aCopy(target)
						unrelated.ID = 8
						switch first {
						case "Receives":
							unrelated.Direction = "receives"
						case "OtherResponse":
							unrelated.ResponseID = intPtr(2)
						case "NilResponse":
							unrelated.ResponseID = nil
						}
						s.thresholds.rows = []store.Threshold{unrelated, target}
						path, body := "/api/responses/1/actions", dao12aBody(kind)
						if method == "PUT" {
							path, body = "/api/actions/10", map[string]any{"priority": 2}
						}
						w := dao13eRequest(t, s, method, path, body)
						dao12aCheck(t, "Status", w.Code, 400)
						t.Run("Error", func(t *testing.T) {
							dao13eError(t, w, dao13eForbidden)
						})
						dao12aCheck(t, "ZeroWrites", dao12aWrites(s.dao12aStore), "")
					})
				}
			}
		}
	})
	for _, name := range []string{"UnboundTemplate", "DisabledRule", "ListError"} {
		t.Run(name, func(t *testing.T) {
			s := dao13eFixture(t, "webhook")
			status, message := 400, dao13eForbidden
			switch name {
			case "UnboundTemplate":
				s.thresholds.rows[0].PrefixID, s.thresholds.rows[0].TemplateID = nil, intPtr(5)
			case "DisabledRule":
				s.thresholds.rows[0].Enabled = false
			case "ListError":
				s.thresholds.err = errors.New("outbound lookup failed")
				status, message = 500, "failed to check outbound rule references: database error"
			}
			w := dao13eRequest(t, s, "POST", "/api/responses/1/actions", dao12aBody("xdrop"))
			dao13eStatus(t, w, status)
			dao13eError(t, w, message)
			dao12aCheck(t, "ZeroWrites", dao12aWrites(s.dao12aStore), "")
		})
	}
}

func TestDao13e_A2(t *testing.T) {
	for _, kind := range []string{"webhook", "shell"} {
		t.Run(kind, func(t *testing.T) {
			s := dao13eFixture(t, "webhook")
			dao13eStatus(t, dao13eRequest(t, s, "POST", "/api/responses/1/actions", dao12aBody(kind)), 201)
		})
	}
	for _, name := range []string{"Receives", "EmptyDirection", "OtherResponse"} {
		t.Run(name, func(t *testing.T) {
			s := dao13eFixture(t, "webhook")
			switch name {
			case "Receives":
				s.thresholds.rows[0].Direction = "receives"
			case "EmptyDirection":
				s.thresholds.rows[0].Direction = ""
			case "OtherResponse":
				s.thresholds.rows[0].ResponseID = intPtr(2)
			}
			dao13eStatus(t, dao13eRequest(t, s, "POST", "/api/responses/1/actions", dao12aBody("xdrop")), 201)
		})
	}
	t.Run("GlobalFirst", func(t *testing.T) {
		s := dao13eFixture(t, "webhook")
		s.global = "referenced"
		w := dao13eRequest(t, s, "POST", "/api/responses/1/actions", dao12aBody("xdrop"))
		dao13eStatus(t, w, 400)
		dao13eError(t, w, "This response is referenced by global prefix (0.0.0.0/0) rules — cannot add xDrop/BGP action")
		dao12aCheck(t, "ZeroWrites", dao12aWrites(s.dao12aStore), "")
	})
	for _, name := range []string{"Unbind", "ChangeDirection"} {
		t.Run(name, func(t *testing.T) {
			s := dao13eFixture(t, "xdrop")
			body := map[string]any{"response_id": nil}
			if name == "ChangeDirection" {
				body = map[string]any{"direction": "receives"}
			}
			dao13eStatus(t, dao13eRequest(t, s, "PUT", "/api/thresholds/9", body), 200)
			dao13eStatus(t, dao13eRequest(t, s, "POST", "/api/responses/1/actions", dao12aBody("xdrop")), 201)
		})
	}
	t.Run("Delete", func(t *testing.T) {
		s := dao13eFixture(t, "xdrop")
		dao13eStatus(t, dao13eRequest(t, s, "DELETE", "/api/actions/10", nil), 200)
		if _, err := s.Responses().GetAction(context.Background(), 10); err == nil {
			t.Fatal("deleted action still exists")
		}
	})
	for _, path := range []string{"/api/thresholds", "/api/threshold-templates/5/rules", "/api/thresholds/9"} {
		t.Run("ForwardValidation"+path, func(t *testing.T) {
			s := dao13eFixture(t, "xdrop")
			body := dao12aCopy(s.thresholds.rows[0])
			method := "POST"
			if strings.HasSuffix(path, "/9") {
				method = "PUT"
				s.thresholds.rows[0].Direction = "receives"
			}
			w := dao13eRequest(t, s, method, path, body)
			dao13eStatus(t, w, 400)
			dao13eError(t, w, "outbound (sends) rules cannot use responses containing xDrop/BGP actions")
		})
	}
}

func TestDao13e_C1(t *testing.T) {
	for _, route := range []string{"thresholds", "threshold-rules"} {
		for _, name := range []string{"Omitted", "Null", "ID"} {
			t.Run(route+"/"+name, func(t *testing.T) {
				s := dao13eFixture(t, "webhook")
				s.thresholds.rows[0].ResponseID, s.thresholds.rows[0].Direction = intPtr(7), "receives"
				body, want := map[string]any{"value": 500}, intPtr(7)
				switch name {
				case "Null":
					body["response_id"], want = nil, nil
				case "ID":
					body, want = map[string]any{"response_id": 9}, intPtr(9)
				}
				dao13eStatus(t, dao13eRequest(t, s, "PUT", "/api/"+route+"/9", body), 200)
				row, err := s.Thresholds().Get(context.Background(), 9)
				if err != nil {
					t.Fatal(err)
				}
				dao12aCheck(t, "StoredResponse", row.ResponseID, want)
				if name != "ID" {
					dao12aCheck(t, "StoredValue", row.Value, int64(500))
				}
			})
		}
	}
	for _, field := range []string{"parent_id", "threshold_template_id", "omitted"} {
		t.Run("Prefix/"+field, func(t *testing.T) {
			base := NewMockStore()
			ctx := context.Background()
			parent, id := 1, 2
			s := dao13ePrefixStore{base, &dao13ePrefixes{PrefixRepo: base.Prefixes(), rows: []store.WatchPrefix{
				{ID: parent, Prefix: "192.0.2.0/24", Enabled: true},
				{ID: id, Prefix: "192.0.2.0/25", ParentID: &parent, ThresholdTemplateID: intPtr(7), Enabled: true},
			}}}
			body := map[string]any{"name": "renamed"}
			wantParent, wantTemplate := &parent, intPtr(7)
			if field != "omitted" {
				body[field] = nil
				if field == "parent_id" {
					wantParent = nil
				} else {
					wantTemplate = nil
				}
			}
			dao13eStatus(t, dao13eRequest(t, s, "PUT", fmt.Sprintf("/api/prefixes/%d", id), body), 200)
			row, err := s.Prefixes().Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			dao12aCheck(t, "Parent", row.ParentID, wantParent)
			dao12aCheck(t, "Template", row.ThresholdTemplateID, wantTemplate)
		})
	}
}

func TestDao13e_C2(t *testing.T) {
	for _, name := range []string{"EmptyClears", "NullKeeps"} {
		t.Run(name, func(t *testing.T) {
			s := dao12aFixture(t, "shell", false)
			s.responses.actions[0].ShellExtraArgs = "--old"
			var value any = ""
			want := ""
			if name == "NullKeeps" {
				value, want = nil, "--old"
			}
			dao13eStatus(t, dao13eRequest(t, s, "PUT", "/api/actions/10", map[string]any{"shell_extra_args": value}), 200)
			dao12aCheck(t, "StoredArgs", dao12aState(s, 10).ShellExtraArgs, want)
		})
	}
}

var dao13eBadConditions = []struct {
	attr, op, value string
	operatorError   bool
}{
	{"pps", "gt", "1M", false},
	{"decoder", "eq", "tcp_synn", false},
	{"decoder", "neq", "tcp_synn", false},
	{"pps", "not_in", "abc", false},
	{"node", "neq", "x", true},
	{"decoder", "gt", "udp", true},
	{"severity", "eq", "urgent", false},
	{"pps", "in", "1,,2", false},
	{"cidr", "gt", "x", false},
	{"unique_src_ips", "in", "1,x", false},
	{"domain", "eq", "internal", false},
	{"domain", "eq", " subnet", false},
	{"severity", "in", "low,,high", false},
	{"node", "not_in", "a", true},
	{"node", "eq", "a,,b", false},
	{"attack_type", "gt", "x", true},
}

func dao13eCondition(t *testing.T, attr, op, value, message string) {
	t.Helper()
	ctx := context.Background()
	s := NewMockStore()
	seed := []store.ActionPrecondition{{Attribute: "pps", Operator: "gt", Value: "123"}}
	if err := s.Preconditions().ReplaceAll(ctx, 9, seed); err != nil {
		t.Fatal(err)
	}
	before, err := s.Preconditions().List(ctx, 9)
	if err != nil {
		t.Fatal(err)
	}
	p := store.ActionPrecondition{Attribute: attr, Operator: op, Value: value}
	w := dao13eRequest(t, s, "PUT", "/api/actions/9/preconditions", map[string]any{"preconditions": []store.ActionPrecondition{p}})
	after, err := s.Preconditions().List(ctx, 9)
	if err != nil {
		t.Fatal(err)
	}
	if message != "" {
		dao13eStatus(t, w, 400)
		dao13eError(t, w, message)
		dao12aCheck(t, "SeedUnchanged", after, before)
		return
	}
	dao13eStatus(t, w, 200)
	if len(after) != 1 {
		t.Fatalf("stored rows=%+v", after)
	}
	dao12aCheck(t, "ExactAttribute", after[0].Attribute, attr)
	dao12aCheck(t, "ExactOperator", after[0].Operator, op)
	dao12aCheck(t, "ExactValueBytes", []byte(after[0].Value), []byte(value))
}
func TestDao13e_D1(t *testing.T) {
	for _, p := range dao13eBadConditions {
		t.Run(p.attr+"/"+p.op+"/"+p.value, func(t *testing.T) {
			message := fmt.Sprintf("invalid precondition value for %s: %q", p.attr, p.value)
			if p.operatorError {
				message = fmt.Sprintf("precondition operator %s is not supported for attribute %s", p.op, p.attr)
			}
			dao13eCondition(t, p.attr, p.op, p.value, message)
		})
	}
}
func TestDao13e_D2(t *testing.T) {
	for _, p := range [][3]string{
		{"pps", "gt", " 1000 "}, {"pps", "in", "1, 2"}, {"cidr", "lte", "24"},
		{"decoder", "eq", "ip"}, {"decoder", "in", "udp, tcp_syn"}, {"decoder", "not_in", "ip"},
		{"severity", "eq", "critical"}, {"domain", "eq", "internal_ip"}, {"node", "eq", "node-a"},
		{"node", "eq", "a, b"}, {"node", "in", "a, b"}, {"attack_type", "eq", "anything"},
		{"dominant_dst_port_pct", "gte", "40"},
	} {
		t.Run(strings.Join(p[:], "/"), func(t *testing.T) {
			dao13eCondition(t, p[0], p[1], p[2], "")
		})
	}
}

type dao13eSummaryStore struct {
	store.Store
	fault      string
	partial    bool
	active     int
	nodes      []store.Node
	prefixes   int
	thresholds int
}
type dao13eSummaryAttacks struct {
	store.AttackRepo
	s *dao13eSummaryStore
}
type dao13eSummaryNodes struct {
	store.NodeRepo
	s *dao13eSummaryStore
}
type dao13eSummaryPrefixes struct {
	store.PrefixRepo
	s *dao13eSummaryStore
}
type dao13eSummaryThresholds struct {
	store.ThresholdRepo
	s *dao13eSummaryStore
}

func (s *dao13eSummaryStore) failure(which string) error {
	if s.fault == which {
		return errors.New("injected failure")
	}
	return nil
}
func (s *dao13eSummaryStore) Attacks() store.AttackRepo {
	return dao13eSummaryAttacks{s.Store.Attacks(), s}
}
func (s *dao13eSummaryStore) Nodes() store.NodeRepo {
	return dao13eSummaryNodes{s.Store.Nodes(), s}
}
func (s *dao13eSummaryStore) Prefixes() store.PrefixRepo {
	return dao13eSummaryPrefixes{s.Store.Prefixes(), s}
}
func (s *dao13eSummaryStore) Thresholds() store.ThresholdRepo {
	return dao13eSummaryThresholds{s.Store.Thresholds(), s}
}
func (r dao13eSummaryAttacks) CountActive(context.Context) (int, error) {
	return r.s.active, r.s.failure("attacks")
}
func (r dao13eSummaryNodes) List(context.Context) ([]store.Node, error) {
	if err := r.s.failure("nodes"); err != nil && !r.s.partial {
		return nil, err
	}
	return r.s.nodes, r.s.failure("nodes")
}
func (r dao13eSummaryPrefixes) Count(context.Context) (int, error) {
	return r.s.prefixes, r.s.failure("prefixes")
}
func (r dao13eSummaryThresholds) Count(context.Context) (int, error) {
	return r.s.thresholds, r.s.failure("thresholds")
}
func dao13eSummary(t *testing.T, s *dao13eSummaryStore, nonzero bool) *httptest.ResponseRecorder {
	t.Helper()
	tr := dao4Tracker(s, nil)
	if nonzero {
		tr.CreatedTotal.Store(3)
		tr.SuppressedTotal.Store(4)
		tr.EvictedTotal.Store(5)
	}
	r := api.NewRouter(api.Dependencies{Store: s, JWTSecret: testJWTSecret, APIKey: "test-api-key", Tracker: tr, NodeState: ingestion.NewNodeState()})
	req := httptest.NewRequest("GET", "/api/stats/summary", nil)
	req.Header.Set("Authorization", "Bearer "+makeTestToken(t))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
func TestDao13e_F1(t *testing.T) {
	for _, which := range []string{"attacks", "nodes", "prefixes", "thresholds", "partial-nodes"} {
		t.Run(which, func(t *testing.T) {
			s := &dao13eSummaryStore{Store: NewMockStore(), fault: which}
			if which == "partial-nodes" {
				s.fault, s.partial, s.nodes = "nodes", true, []store.Node{{ID: "node-a"}}
			}
			w := dao13eSummary(t, s, false)
			dao13eStatus(t, w, 500)
			dao13eError(t, w, "stats summary: "+s.fault+": database error")
		})
	}
	for _, nonzero := range []bool{false, true} {
		t.Run(fmt.Sprintf("Success/nonzero=%t", nonzero), func(t *testing.T) {
			s := &dao13eSummaryStore{Store: NewMockStore()}
			want := map[string]int{"active_attacks": 0, "total_nodes": 0, "online_nodes": 0, "total_prefixes": 0, "total_thresholds": 0, "tracker_count": 0, "attacks_created": 0, "attacks_suppressed": 0, "attacks_evicted": 0}
			if nonzero {
				s.active, s.prefixes, s.thresholds, s.nodes = 2, 6, 7, []store.Node{{ID: "node-a"}}
				want["active_attacks"], want["total_nodes"], want["total_prefixes"], want["total_thresholds"] = 2, 1, 6, 7
				want["attacks_created"], want["attacks_suppressed"], want["attacks_evicted"] = 3, 4, 5
			}
			w := dao13eSummary(t, s, nonzero)
			dao13eStatus(t, w, 200)
			var got map[string]int
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			dao12aCheck(t, "Counters", got, want)
		})
	}
}

// Every negative dispatch assertion has a receives twin using the same fixture.
// The positive twin must create a rule/announcement, not merely reach a handler.
func dao13eDispatch(t *testing.T, kind, direction, event, variant string) {
	t.Helper()
	var report func(*testing.T)
	synctest.Test(t, func(t *testing.T) {
		ms, rules, e, ev := dao4XDrop()
		d := dao4HTTP(t)
		record := ""
		if kind == "bgp" {
			ms, _, ev = dao4Fixture("bgp", "once", "on_detected")
			script, path := dao4Vtysh(t)
			record = path
			ms.responses.actions[0].BGPConnectorID, ms.responses.actions[0].BGPRouteMap = intPtr(7), "RTBH"
			ms.bgpConnectors.connectors = []store.BGPConnector{{ID: 7, Enabled: true, VtyshPath: script, BGPASN: 64512}}
			e = action.NewEngine(ms, "auto")
		}
		ctx := context.Background()
		before, err := ms.BGPAnnouncements().FindByBusinessKey(ctx, "192.0.2.10/32", "RTBH", 7)
		if err != nil || before != nil {
			t.Fatalf("initial announcement=%+v err=%v", before, err)
		}
		attachments, err := ms.BGPAnnouncements().ListAttachmentsForAttack(ctx, 20)
		if err != nil || len(attachments) != 0 {
			t.Fatalf("initial attachments=%+v err=%v", attachments, err)
		}
		wantSkips := 1
		switch variant {
		case "double":
			second := ms.responses.actions[0]
			second.ID = 12
			ms.responses.actions = append(ms.responses.actions, second)
			wantSkips = 2
		case "webhook":
			ms.responses.actions = append(ms.responses.actions, store.ResponseAction{
				ID: 12, ResponseID: 1, ActionType: "webhook", TriggerPhase: "on_detected", RunMode: "once",
				Enabled: true, Config: []byte(`{"url":"http://hook.invalid/webhook"}`),
			})
		case "legacy":
			ms.responses.actions[0].TriggerPhase, ms.responses.actions[0].ExecutionPolicy = "", "once_on_enter"
		case "observe":
			e = action.NewEngine(dao4RuleStore{ms, rules}, "observe")
		case "manual":
			ms.responses.actions[0].Execution = "manual"
		}
		if event == "updated" {
			ms.responses.actions[0].RunMode = "periodic"
		}
		ev.Type, ev.Attack.Direction = event, direction
		metric := dao11iMetric(t)
		metricBefore, _ := metric(dao13eOutbound)
		e.HandleEvent(ev)
		synctest.Wait()
		logs := ms.actionExecLog.snapshotLogs()
		rows, err := ms.XDropActiveRules().ListByAttack(ctx, 20)
		if err != nil {
			t.Fatal(err)
		}
		ann, err := ms.BGPAnnouncements().FindByBusinessKey(ctx, "192.0.2.10/32", "RTBH", 7)
		if err != nil {
			t.Fatal(err)
		}
		attachments, err = ms.BGPAnnouncements().ListAttachmentsForAttack(ctx, 20)
		if err != nil {
			t.Fatal(err)
		}
		posts, hooks := 0, 0
		for _, req := range d.requests {
			if req.Method == "POST" && req.URL.Host == "dao4.invalid" {
				posts++
			}
			if req.URL.Host == "hook.invalid" {
				hooks++
			}
		}
		command := ""
		if record != "" {
			command = dao4Read(t, record)
		}
		metricAfter, _ := metric(dao13eOutbound)
		report = func(t *testing.T) {
			blocked := direction == "sends" || variant == "observe" || variant == "manual"
			if blocked {
				t.Run("NoSideEffect", func(t *testing.T) {
					if posts != 0 || len(rows) != 0 || ann != nil || len(attachments) != 0 {
						t.Errorf("POST=%d rules=%+v announcement=%+v attachments=%+v", posts, rows, ann, attachments)
					}
					if command != "" {
						t.Errorf("unexpected vtysh commands: %q", command)
					}
				})
				t.Run("SkipRows", func(t *testing.T) {
					if variant == "manual" {
						if len(logs) != 0 {
							t.Errorf("manual action logged %+v", logs)
						}
						return
					}
					reason := dao13eOutbound
					if variant == "observe" {
						reason = "mode_observe"
					}
					count := 0
					for _, l := range logs {
						if l.ActionType == "webhook" {
							continue
						}
						count++
						phase := "on_detected"
						if variant == "legacy" {
							phase = ""
						}
						if l.Status != "skipped" || l.SkipReason != reason || (l.ActionID != 10 && !(variant == "double" && l.ActionID == 12)) || l.TriggerPhase != phase {
							t.Errorf("unexpected skip row %+v", l)
						}
					}
					if count != wantSkips {
						t.Errorf("skip count=%d want=%d logs=%+v", count, wantSkips, logs)
					}
				})
				t.Run("Metric", func(t *testing.T) {
					want := float64(wantSkips)
					if variant == "observe" || variant == "manual" {
						want = 0
					}
					if metricAfter-metricBefore != want {
						t.Errorf("outbound metric delta=%v want=%v", metricAfter-metricBefore, want)
					}
				})
			} else {
				t.Run("PositiveSideEffect", func(t *testing.T) {
					if kind == "xdrop" && (posts < 1 || len(rows) == 0) {
						t.Errorf("invalid positive control: POST=%d rules=%+v", posts, rows)
					}
					if kind == "bgp" {
						cmd := command
						if ann == nil || len(attachments) == 0 || !strings.Contains(cmd, "network 192.0.2.10/32 route-map RTBH") || strings.Contains(cmd, "no network") {
							t.Errorf("invalid positive control: cmd=%q announcement=%+v attachments=%+v", cmd, ann, attachments)
						}
					}
					for _, l := range logs {
						if l.SkipReason == "no_connector" || l.SkipReason == dao13eOutbound {
							t.Errorf("invalid positive control: %+v", l)
						}
					}
				})
			}
			if variant == "webhook" && hooks != 1 {
				t.Errorf("webhook HTTP calls=%d want=1", hooks)
			}
		}
	})
	if report != nil {
		report(t)
	}
}

func TestDao13e_P0(t *testing.T) {
	for _, kind := range []string{"xdrop", "bgp"} {
		t.Run(kind, func(t *testing.T) { dao13eDispatch(t, kind, "receives", "confirmed", "") })
	}
}
func TestDao13e_B1(t *testing.T) {
	for _, row := range []struct{ kind, event, variant string }{
		{"xdrop", "confirmed", ""}, {"bgp", "confirmed", ""},
		{"xdrop", "confirmed", "double"}, {"xdrop", "confirmed", "webhook"},
		{"xdrop", "confirmed", "legacy"}, {"xdrop", "updated", ""}, {"bgp", "updated", ""},
		{"xdrop", "type_upgrade", ""}, {"bgp", "type_upgrade", ""},
	} {
		t.Run(row.kind+"/"+row.event+"/"+row.variant, func(t *testing.T) {
			for _, direction := range []string{"receives", "sends"} {
				t.Run(direction, func(t *testing.T) {
					dao13eDispatch(t, row.kind, direction, row.event, row.variant)
				})
			}
		})
	}
}
func TestDao13e_B2Mode(t *testing.T) {
	for _, variant := range []string{"observe", "manual"} {
		t.Run(variant, func(t *testing.T) { dao13eDispatch(t, "xdrop", "sends", "confirmed", variant) })
	}
}

// BEGIN HISTORY CONTRACT: also replayed on the baseline with private R0 names.
func dao13eHistory(t *testing.T, variant, direction string) map[string]int {
	t.Helper()
	result := map[string]int{}
	checks := map[string][]string{"NoOutboundSkip": nil}
	synctest.Test(t, func(t *testing.T) {
		if variant == "NoHistoryRow" || variant == "WithdrawnHistoryRow" {
			ms, _, e, ev := dao4XDrop()
			d := dao4HTTP(t)
			if variant == "WithdrawnHistoryRow" {
				dao4SeedRule(t, ms, "withdrawn", "rule-1", false)
			}
			ev.Type, ev.Attack.Direction = "expired", direction
			e.HandleEvent(ev)
			synctest.Wait()
			checks["HistoryResult"], checks["NoDeleteHTTP"] = nil, nil
			n := 0
			for _, row := range ms.actionExecLog.snapshotLogs() {
				matches := row.ActionID == 11 && row.Status == "skipped" &&
					row.SkipReason == "no_rules_to_unblock" && row.ErrorMessage == "no active, delayed or failed rules to unblock"
				if variant == "WithdrawnHistoryRow" {
					matches = row.ActionID == 11 && row.Status == "skipped" && row.SkipReason == "no_rules_to_unblock"
				}
				if matches {
					n++
				}
				if row.SkipReason == "outbound_block_forbidden" {
					checks["NoOutboundSkip"] = append(checks["NoOutboundSkip"], fmt.Sprintf("ended action was forbidden: %+v", row))
				}
				result[fmt.Sprintf("%d/%s/%s/%s", row.ActionID, row.Status, row.SkipReason, row.TriggerPhase)]++
			}
			if n != 1 {
				checks["HistoryResult"] = append(checks["HistoryResult"], fmt.Sprintf("%s matching rows=%d want=1; logs=%+v", variant, n, ms.actionExecLog.snapshotLogs()))
			}
			for _, req := range d.requests {
				if req.Method == "DELETE" {
					checks["NoDeleteHTTP"] = append(checks["NoDeleteHTTP"], "unexpected DELETE "+req.URL.String())
				}
			}
			result["HTTP"] = d.count()
			return
		}
		delay := 0
		if variant == "HistoricDelayed" {
			delay = 1
		}
		f := td104New(t, delay)
		f.event.Attack.Direction = direction
		if variant == "HistoricEvicted" {
			f.event.Type = "evicted"
		}
		if variant == "ManualOverride" {
			act := f.s.responses.actions[1]
			if _, err := f.s.ManualOverrides().Create(context.Background(), &store.ActionManualOverride{
				AttackID: 20, ActionID: act.ID, ConnectorID: 7, ExternalRuleID: "192.0.2.10/32|RTBH",
			}); err != nil {
				t.Fatal(err)
			}
		}
		if variant == "LegacyOnceOnExit" {
			f.onlyXDrop()
			f.s.responses.actions = f.s.responses.actions[:1]
			f.s.responses.actions[0].TriggerPhase = ""
			f.s.responses.actions[0].ExecutionPolicy = "once_on_exit"
			f.s.responses.actions[0].XDropAction = "drop"
		}
		logs := dao5CaptureLog(t)
		f.run()
		rows := f.s.actionExecLog.snapshotLogs()
		for _, row := range rows {
			if row.SkipReason == "outbound_block_forbidden" {
				checks["NoOutboundSkip"] = append(checks["NoOutboundSkip"], fmt.Sprintf("ended action was forbidden: %+v", row))
			}
		}
		if variant == "HistoricRelease" || variant == "HistoricEvicted" {
			checks["NormalChildExecuted"], checks["NoSweepNoRecovery"] = nil, nil
			byAction := map[int]int{}
			for _, row := range rows {
				byAction[row.ActionID]++
				if variant == "HistoricRelease" && (row.Status != "success" || row.SkipReason != "") {
					checks["NormalChildExecuted"] = append(checks["NormalChildExecuted"], fmt.Sprintf("normal child did not succeed: %+v", row))
				}
			}
			if !reflect.DeepEqual(byAction, map[int]int{11: 1, 30: 1, 31: 1}) {
				checks["NormalChildExecuted"] = append(checks["NormalChildExecuted"], fmt.Sprintf("execution log counts=%v", byAction))
			}
			ann, err := f.s.MockStore.BGPAnnouncements().Get(context.Background(), f.ann)
			if err != nil {
				t.Fatal(err)
			}
			rules, err := f.s.MockStore.XDropActiveRules().ListByAttack(context.Background(), 20)
			if err != nil {
				t.Fatal(err)
			}
			// Same state oracle as td104Fixture.state, captured before cleanup.
			if ann.Status != "withdrawn" || len(rules) != 1 || rules[0].Status != "withdrawn" ||
				strings.Count(dao4Read(t, f.path), "no network") != 1 || f.d.count() != 1 {
				checks["NormalChildExecuted"] = append(checks["NormalChildExecuted"], fmt.Sprintf("state: announcement=%+v rules=%+v HTTP=%d", ann, rules, f.d.count()))
			}
			for key, value := range f.values(t) {
				if value != f.before[key] {
					checks["NoSweepNoRecovery"] = append(checks["NoSweepNoRecovery"], fmt.Sprintf("sweep metric %s delta=%v", key, value-f.before[key]))
				}
			}
			if strings.Count(logs.text(), "ended sweep") != 0 || strings.Count(logs.text(), "recovered xdrop") != 0 {
				checks["NoSweepNoRecovery"] = append(checks["NoSweepNoRecovery"], "unexpected recovery:\n"+logs.text())
			}
		}
		if variant == "HistoricDelayed" {
			f.state(t, "delayed", "delayed", 0, 0)
			f.cancel()
		}
		if variant == "ManualOverride" {
			want, id := "manual_override", 11
			n := 0
			for _, row := range rows {
				if row.SkipReason == want && row.ActionID == id {
					n++
				}
			}
			if n != 1 {
				t.Errorf("expected one %s action=%d row, got %+v", want, id, rows)
			}
		}
		result["HTTP"] = f.d.count()
		for _, row := range rows {
			result[fmt.Sprintf("%d/%s/%s/%s", row.ActionID, row.Status, row.SkipReason, row.TriggerPhase)]++
		}
	})
	for _, name := range []string{"NoOutboundSkip", "NormalChildExecuted", "NoSweepNoRecovery", "HistoryResult", "NoDeleteHTTP"} {
		if failures, ok := checks[name]; ok {
			t.Run(name, func(t *testing.T) {
				for _, failure := range failures {
					t.Error(failure)
				}
			})
		}
	}
	return result
}

func TestDao13e_B2(t *testing.T) {
	for _, variant := range []string{"HistoricRelease", "HistoricEvicted", "HistoricDelayed", "ManualOverride", "LegacyOnceOnExit", "NoHistoryRow", "WithdrawnHistoryRow"} {
		t.Run(variant, func(t *testing.T) {
			var receives, sends map[string]int
			t.Run("receives", func(t *testing.T) { receives = dao13eHistory(t, variant, "receives") })
			t.Run("sends", func(t *testing.T) { sends = dao13eHistory(t, variant, "sends") })
			if !reflect.DeepEqual(sends, receives) {
				t.Errorf("sends=%v receives=%v", sends, receives)
			}
		})
	}
}

// END HISTORY CONTRACT

func TestDao13e_R0(t *testing.T) {
	t.Run("Fixed", func(t *testing.T) {
		t.Run("a", func(t *testing.T) {
			for _, kind := range []string{"xdrop", "bgp"} {
				s := dao13eFixture(t, "webhook")
				w := dao13eRequest(t, s, "POST", "/api/responses/1/actions", dao12aBody(kind))
				dao13eStatus(t, w, 400)
				dao13eError(t, w, dao13eForbidden)
			}
			s := dao13eFixture(t, "xdrop")
			dao13eStatus(t, dao13eRequest(t, s, "PUT", "/api/actions/10", map[string]any{"priority": 2}), 400)
		})
		t.Run("b", func(t *testing.T) {
			for _, kind := range []string{"xdrop", "bgp"} {
				t.Run(kind, func(t *testing.T) { dao13eDispatch(t, kind, "sends", "confirmed", "") })
			}
		})
		t.Run("d", TestDao13e_D1)
		t.Run("e", func(t *testing.T) {
			w := dao13eSummary(t, &dao13eSummaryStore{Store: NewMockStore(), fault: "attacks"}, false)
			dao13eStatus(t, w, 500)
			dao13eError(t, w, "stats summary: attacks: database error")
		})
	})
}
