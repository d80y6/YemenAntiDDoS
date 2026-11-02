package action

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/metrics"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
	"github.com/d80y6/YemenDDoS/controller/internal/tracker"
	dto "github.com/prometheus/client_model/go"
)

var v3Decoders = []string{"tcp", "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin", "udp", "icmp", "gre", "esp", "igmp", "fragment", "bad_fragment", "invalid"}

const v3WebPayload = `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","dst_port":"{dominant_dst_port}","src_port":"{dominant_src_port}","protocol":"{decoder}","source":"xsight","action":"drop"}`

func v3Attack(id int, decoder, dst string) *store.Attack {
	return &store.Attack{ID: id, DecoderFamily: decoder, DstIP: dst, AttackType: decoder + "_flood", Direction: "receives"}
}
func v3Action(id int, payload string) store.ResponseAction {
	return store.ResponseAction{ID: id, ResponseID: 1, ActionType: "xdrop", XDropAction: "filter_l4", TriggerPhase: "on_detected", RunMode: "once", Enabled: true, XDropCustomPayload: json.RawMessage(payload)}
}
func v3Execute(t *testing.T, m *v3Mock, s *v3Store, a *store.Attack, act store.ResponseAction, fa *FlowAnalysis) (store.ActionExecutionLog, map[string]any) {
	t.Helper()
	before := len(s.logSnapshot())
	l, _ := executeXDrop(context.Background(), s, act, a, "confirmed", a.DstIP, "v3-test", act.TriggerPhase, a.ID, fa, nil)
	if l != nil {
		_, _ = s.ActionExecLog().Create(context.Background(), l)
	}
	logs := s.logSnapshot()
	if len(logs) <= before {
		t.Fatal("no execution log")
	}
	last := logs[len(logs)-1]
	var body map[string]any
	for _, req := range m.snapshot() {
		if req.Method == "POST" {
			if err := json.Unmarshal(req.Body, &body); err != nil {
				t.Fatal(err)
			}
		}
	}
	return last, body
}
func v3Success(t *testing.T, l store.ActionExecutionLog) {
	t.Helper()
	if l.Status != "success" || l.StatusCode == nil || (*l.StatusCode != 200 && *l.StatusCode != 201) || !strings.HasPrefix(l.ExternalRuleID, "rule_") {
		t.Fatalf("create failed: %+v", l)
	}
}
func v3NoKeys(t *testing.T, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; ok {
			t.Errorf("unexpected %s=%v", k, m[k])
		}
	}
}

func TestC1_DefaultDecoderMatrix(t *testing.T) {
	for _, dec := range v3Decoders {
		for _, dst := range []string{"198.51.100.7", "198.51.100.0/24", "2001:db8::7/128"} {
			if dec == "bad_fragment" && strings.Contains(dst, ":") {
				continue
			}
			t.Run(dec+"/"+dst, func(t *testing.T) {
				m := newV3Mock(t)
				s := newV3Store(m.server.URL)
				l, body := v3Execute(t, m, s, v3Attack(101, dec, dst), v3Action(11, ""), nil)
				v3Success(t, l)
				v3NoKeys(t, body, "source", "decoder", "expires_in")
				if body["claim_ref"] != "a101.x11" {
					t.Fatal(body)
				}
				if s.state(101, 11, l.ExternalRuleID) != "active" {
					t.Fatal("missing active state")
				}
			})
		}
	}
}
func TestC2_WebNoFlows(t *testing.T) {
	m := newV3Mock(t)
	s := newV3Store(m.server.URL)
	l, body := v3Execute(t, m, s, v3Attack(101, "udp", "198.51.100.7"), v3Action(11, v3WebPayload), nil)
	v3Success(t, l)
	v3NoKeys(t, body, "source")
	for key, value := range body {
		if value == "" {
			t.Errorf("empty %s", key)
		}
	}
	// fa=nil means insufficient samples and selects fallback; with no threshold for this attack, retain drop and the unavailable hint.
	if body["action"] != "drop" {
		t.Fatalf("action=%v want drop", body["action"])
	}
	v3NoKeys(t, body, "rate_limit", "dst_port", "src_port", "src_ip", "src_cidr")
	for _, want := range []string{"shape: samples 0 < 1000", "fallback rate unavailable: "} {
		if !strings.Contains(l.ErrorMessage, want) {
			t.Fatalf("missing %q: %s", want, l.ErrorMessage)
		}
	}
}
func TestC2b_EmptyInjection(t *testing.T) {
	for _, tc := range []struct{ dec, key, want string }{{"tcp_syn", "tcp_flags", "SYN,!ACK"}, {"fragment", "fragment", "frag"}} {
		t.Run(tc.dec, func(t *testing.T) {
			m := newV3Mock(t)
			s := newV3Store(m.server.URL)
			l, body := v3Execute(t, m, s, v3Attack(101, tc.dec, "198.51.100.7"), v3Action(11, fmt.Sprintf(`{"dst_ip":"{dst_ip}","%s":"","action":"drop"}`, tc.key)), nil)
			v3Success(t, l)
			if body[tc.key] != tc.want {
				t.Fatalf("%s=%v", tc.key, body[tc.key])
			}
		})
	}
}
func TestC3_AddressPairs(t *testing.T) {
	for _, tc := range []struct{ name, dst, payload, src, wantDst, wantSrc, code string }{
		{"01_no_flows", "198.51.100.0/24", v3WebPayload, "", "198.51.100.0/24", "", ""},
		{"02_source_v4", "198.51.100.0/24", v3WebPayload, "192.0.2.10", "198.51.100.0/24", "192.0.2.10/32", ""},
		{"03_source_v6", "2001:db8::/64", v3WebPayload, "2001:db8:1::1", "2001:db8::/64", "2001:db8:1::1/128", ""},
		{"04_zero_v4", "198.51.100.0/24", `{"dst_ip":"{dst_ip}","src_ip":"0.0.0.0"}`, "", "198.51.100.0/24", "", ""},
		{"04_mapped_zero", "198.51.100.0/24", `{"dst_ip":"{dst_ip}","src_ip":"::ffff:0.0.0.0"}`, "", "198.51.100.0/24", "", ""},
		{"04_zero_v6", "2001:db8::/64", `{"dst_ip":"{dst_ip}","src_ip":"::"}`, "", "2001:db8::/64", "", ""},
		{"04_expanded_zero", "2001:db8::/64", `{"dst_ip":"{dst_ip}","src_ip":"0:0:0:0:0:0:0:0"}`, "", "2001:db8::/64", "", ""},
		{"04_explicit_cidr", "198.51.100.0/24", `{"dst_ip":"{dst_ip}","src_cidr":"0.0.0.0/32"}`, "", "198.51.100.0/24", "0.0.0.0/32", ""},
		{"05_source_cidr", "198.51.100.7", `{"dst_ip":"{dst_ip}","src_cidr":"192.0.2.0/24"}`, "", "198.51.100.7/32", "192.0.2.0/24", ""},
		{"06_family_mismatch", "198.51.100.0/24", `{"dst_ip":"{dst_ip}","src_ip":"2001:db8::1"}`, "", "198.51.100.0/24", "2001:db8::1/128", "address_family_mismatch"},
		{"07_dst_cidr_priority", "198.51.100.7", `{"dst_cidr":"198.51.100.0/24","dst_ip":"198.51.100.7/32"}`, "", "198.51.100.0/24", "", ""},
		{"07_src_cidr_priority", "198.51.100.7", `{"dst_ip":"198.51.100.7","src_cidr":"192.0.2.0/24","src_ip":"192.0.2.10/32"}`, "", "198.51.100.7/32", "192.0.2.0/24", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newV3Mock(t)
			s := newV3Store(m.server.URL)
			var fa *FlowAnalysis
			if tc.src != "" {
				fa = &FlowAnalysis{TopSrcIPs: []string{tc.src}, TopSrcIPPct: 100, SamplePackets: 1000}
			}
			l, body := v3Execute(t, m, s, v3Attack(101, "udp", tc.dst), v3Action(11, tc.payload), fa)
			if tc.code == "" {
				v3Success(t, l)
			} else if l.Status != "failed" || !strings.Contains(l.ErrorMessage, tc.code) {
				t.Fatal(l)
			}
			v3NoKeys(t, body, "dst_ip", "src_ip")
			if body["dst_cidr"] != tc.wantDst {
				t.Fatal(body)
			}
			if tc.wantSrc == "" {
				v3NoKeys(t, body, "src_cidr")
			} else if body["src_cidr"] != tc.wantSrc {
				t.Fatal(body)
			}
			switch tc.name {
			case "01_no_flows": // Fallback without a threshold retains drop and the unavailable hint.
				if body["action"] != "drop" || !strings.Contains(l.ErrorMessage, "fallback rate unavailable: ") {
					t.Fatalf("action=%v hints=%q", body["action"], l.ErrorMessage)
				}
				v3NoKeys(t, body, "rate_limit")
			case "02_source_v4", "03_source_v6": // The source IP meets the threshold and is retained, so fallback is not used.
				if body["action"] != "drop" || !strings.Contains(l.ErrorMessage, "shape: kept src_ip=100%") || strings.Contains(l.ErrorMessage, "fallback") {
					t.Fatalf("action=%v hints=%q", body["action"], l.ErrorMessage)
				}
				v3NoKeys(t, body, "rate_limit")
			}
		})
	}
}
func v3Unblock(t *testing.T, s *v3Store, a *store.Attack, e *Engine) {
	t.Helper()
	act := v3Action(99, "")
	act.XDropAction = "unblock"
	act.TriggerPhase = "on_expired"
	l, err := executeXDrop(context.Background(), s, act, a, "expired", a.DstIP, "v3-test", "on_expired", a.ID, nil, e)
	if err != nil || l != nil {
		t.Fatalf("unblock: %v %+v", err, l)
	}
}
func v3Deletes(t *testing.T, m *v3Mock, want ...string) {
	t.Helper()
	got := map[string]int{}
	for _, r := range m.snapshot() {
		if r.Method != "DELETE" {
			continue
		}
		if r.Auth != "Bearer "+v3TestKey {
			t.Errorf("DELETE auth=%q", r.Auth)
		}
		q, err := url.ParseQuery(r.Query)
		if err != nil {
			t.Fatal(err)
		}
		got[q.Get("claim_ref")]++
	}
	expected := map[string]int{}
	for _, ref := range want {
		expected[ref]++
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("DELETE refs=%v want=%v", got, expected)
	}
}
func TestC4_SharedRules(t *testing.T) {
	t.Run("01_two_attacks", func(t *testing.T) {
		m := newV3Mock(t)
		s := newV3Store(m.server.URL)
		act := v3Action(11, "")
		s.actions = []store.ResponseAction{act}
		a, b := v3Attack(101, "udp", "198.51.100.7"), v3Attack(102, "udp", "198.51.100.7")
		la, _ := v3Execute(t, m, s, a, act, nil)
		lb, _ := v3Execute(t, m, s, b, act, nil)
		v3Success(t, la)
		v3Success(t, lb)
		if la.ExternalRuleID != lb.ExternalRuleID || m.claimCount(la.ExternalRuleID) != 2 {
			t.Fatal("not shared")
		}
		v3Unblock(t, s, a, nil)
		if m.count() != 1 || m.claimCount(la.ExternalRuleID) != 1 {
			t.Fatal("A release affected B")
		}
		v3Unblock(t, s, b, nil)
		if m.count() != 0 {
			t.Fatal("B claim leaked")
		}
		v3Deletes(t, m, "a101.x11", "a102.x11")
	})
	t.Run("02_two_actions", func(t *testing.T) {
		m := newV3Mock(t)
		s := newV3Store(m.server.URL)
		a := v3Attack(101, "udp", "198.51.100.7")
		x, y := v3Action(11, ""), v3Action(12, "")
		s.actions = []store.ResponseAction{x, y}
		lx, _ := v3Execute(t, m, s, a, x, nil)
		ly, _ := v3Execute(t, m, s, a, y, nil)
		v3Success(t, lx)
		v3Success(t, ly)
		if lx.ExternalRuleID != ly.ExternalRuleID || m.claimCount(lx.ExternalRuleID) != 2 {
			t.Fatal("not shared")
		}
		v3Unblock(t, s, a, nil)
		if m.count() != 0 {
			t.Fatal("claim leaked")
		}
		v3Deletes(t, m, "a101.x11", "a101.x12")
		for _, id := range []int{11, 12} {
			if s.state(101, id, lx.ExternalRuleID) != "withdrawn" {
				t.Errorf("action %d not withdrawn", id)
			}
			found := 0
			for _, l := range s.logSnapshot() {
				if l.TriggerPhase == "on_expired" && l.ActionID == id && l.ExternalRuleID == lx.ExternalRuleID && l.Status == "success" {
					found++
				}
			}
			if found != 1 {
				t.Errorf("action %d log count %d", id, found)
			}
		}
	})
}

// Seed the valid rule independently of production authentication so M1 reaches
// the DELETE exit under test instead of failing at the preceding POST.
func v3SeedOwned(t *testing.T, m *v3Mock, s *v3Store, a *store.Attack, act store.ResponseAction) store.ActionExecutionLog {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"protocol": "udp", "dst_ip": a.DstIP, "claim_ref": fmt.Sprintf("a%d.x%d", a.ID, act.ID)})
	status, response := v3Raw(t, m, "POST", "/rules", string(body))
	id, _ := response["id"].(string)
	if (status != 200 && status != 201) || id == "" {
		t.Fatal("invalid independent rule seed")
	}
	conn := s.conn.ID
	l := store.ActionExecutionLog{AttackID: a.ID, ActionID: act.ID, ActionType: "xdrop", TriggerPhase: "on_detected", ConnectorID: &conn, ExternalRuleID: id, Status: "success", StatusCode: &status}
	_, _ = s.ActionExecLog().Create(context.Background(), &l)
	_, _ = s.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: a.ID, ActionID: act.ID, ConnectorID: conn, ExternalRuleID: id, Status: "active"})
	return l
}

func TestC5_Exits(t *testing.T) {
	for _, exit := range []string{"immediate", "recovery", "manual"} {
		t.Run(exit, func(t *testing.T) {
			m := newV3Mock(t)
			s := newV3Store(m.server.URL)
			a := v3Attack(101, "udp", "198.51.100.7")
			act := v3Action(11, "")
			s.actions = []store.ResponseAction{act}
			l := v3SeedOwned(t, m, s, a, act)
			v3Success(t, l)
			e := NewEngine(s, "auto")
			switch exit {
			case "immediate":
				v3Unblock(t, s, a, e)
			case "recovery":
				sa := store.ScheduledAction{AttackID: 101, ActionID: 11, ConnectorID: 7, ExternalRuleID: l.ExternalRuleID, ActionType: "xdrop_unblock"}
				id, err := s.ScheduledActions().Schedule(context.Background(), &sa)
				if err != nil {
					t.Fatal(err)
				}
				sa.ID = id
				e.executeRecoveredXDropUnblock(context.Background(), sa)
			case "manual":
				if err := e.ForceRemove(context.Background(), 101, 11, 7, l.ExternalRuleID); err != nil {
					t.Fatal(err)
				}
			}
			v3Deletes(t, m, "a101.x11")
			if m.count() != 0 {
				t.Fatal("claim leaked")
			}
		})
	}
}
func TestC5_Delayed(t *testing.T) {
	m := newV3Mock(t)
	s := newV3Store(m.server.URL)
	a := v3Attack(101, "udp", "198.51.100.7")
	x, y := v3Action(11, ""), v3Action(12, "")
	y.UnblockDelayMinutes = 1
	s.actions = []store.ResponseAction{x, y}
	lx := v3SeedOwned(t, m, s, a, x)
	ly := v3SeedOwned(t, m, s, a, y)
	v3Success(t, lx)
	v3Success(t, ly)
	if lx.ExternalRuleID != ly.ExternalRuleID {
		t.Fatal("not shared")
	}
	e := NewEngine(s, "auto")
	start := time.Now()
	v3Unblock(t, s, a, e)
	v3Deletes(t, m, "a101.x11")
	if m.claimCount(lx.ExternalRuleID) != 1 || s.state(101, 12, lx.ExternalRuleID) != "delayed" {
		t.Fatal("Y not delayed")
	}
	s.mu.Lock()
	scheduled := append([]store.ScheduledAction(nil), s.schedules...)
	s.mu.Unlock()
	if len(scheduled) != 1 || scheduled[0].ActionID != 12 {
		t.Fatalf("schedule=%+v", scheduled)
	}
	if !v3Eventually(75*time.Second, func() bool { return s.state(101, 12, lx.ExternalRuleID) == "withdrawn" }) {
		t.Fatal("Y not withdrawn by deadline")
	}
	if elapsed := time.Since(start); elapsed < time.Minute || elapsed > 75*time.Second {
		t.Fatalf("delay=%s", elapsed)
	}
	v3Deletes(t, m, "a101.x11", "a101.x12")
	if m.count() != 0 {
		t.Fatal("Y claim leaked")
	}
	s.mu.Lock()
	history := append([]string(nil), s.history[v3RuleKey(101, 12, 7, lx.ExternalRuleID)]...)
	s.mu.Unlock()
	if !reflect.DeepEqual(history, []string{"active", "delayed", "withdrawing", "withdrawn"}) {
		t.Fatal(history)
	}
	for _, id := range []int{11, 12} {
		count := 0
		for _, l := range s.logSnapshot() {
			if l.TriggerPhase == "on_expired" && l.ActionID == id && l.ExternalRuleID == lx.ExternalRuleID && l.Status == "success" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("action %d withdrawal logs=%d", id, count)
		}
	}
}
func TestC6_ResponseSize(t *testing.T) {
	for _, size := range []int{0, 70000} {
		name := "C6_1104"
		if size > 0 {
			name = "C6b_70000_comment"
		}
		t.Run(name, func(t *testing.T) {
			m := newV3Mock(t)
			s := newV3Store(m.server.URL)
			payload, _ := json.Marshal(map[string]any{"dst_ip": "{dst_ip}", "comment": strings.Repeat("c", size)})
			l, _ := v3Execute(t, m, s, v3Attack(101, "udp", "198.51.100.7"), v3Action(11, string(payload)), nil)
			v3Success(t, l)
			m.mu.Lock()
			response := append([]byte(nil), m.responses[0]...)
			m.mu.Unlock()
			if size == 0 && len(response) != 1104 {
				t.Fatalf("response length=%d want 1104", len(response))
			}
			if size > 0 && len(response) <= 65536 {
				t.Fatal("response not over 64 KiB")
			}
			var echoed struct{ Comment string }
			if err := json.Unmarshal(response, &echoed); err != nil || len(echoed.Comment) != size {
				t.Fatal("comment not echoed intact")
			}
			var decoded map[string]any
			if err := json.Unmarshal(response[:1024], &decoded); err == nil {
				t.Fatal("1024 bytes unexpectedly complete")
			}
			if s.state(101, 11, l.ExternalRuleID) != "active" {
				t.Fatal("state not active")
			}
			if len(l.ResponseBody) != 1024 {
				t.Fatal("logged response not truncated")
			}
		})
	}
}
func TestC7_InvalidCreateResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{{"missing", `{}`, 200}, {"empty", `{"id":""}`, 200}, {"null", `{"id":null}`, 200}, {"number", `{"id":42}`, 200}, {"202", `{"id":"rule_00000000000000000000000000000001"}`, 202}} {
		t.Run(tc.name, func(t *testing.T) {
			m := newV3Mock(t)
			m.postStatus, m.postBody = tc.status, []byte(tc.body)
			s := newV3Store(m.server.URL)
			l, _ := v3Execute(t, m, s, v3Attack(101, "udp", "198.51.100.7"), v3Action(11, ""), nil)
			if l.Status != "failed" || l.ErrorMessage != "v3 created but id missing" || l.ExternalRuleID != "failed-create-101-11" || s.state(101, 11, l.ExternalRuleID) != "failed" {
				t.Fatalf("%+v", l)
			}
		})
	}
}
func v3SkipCounter() float64 {
	var m dto.Metric
	_ = metrics.ActionSkip.WithLabelValues(SkipReasonXDropAnomalyRequiresDrop).Write(&m)
	return m.GetCounter().GetValue()
}
func TestC8_AnomalyRateLimit(t *testing.T) {
	for i, dec := range []string{"bad_fragment", "invalid"} {
		t.Run(dec, func(t *testing.T) {
			m := newV3Mock(t)
			s := newV3Store(m.server.URL)
			a := v3Attack(101, dec, "198.51.100.7")
			responseID := 1
			a.ResponseID = &responseID
			act := v3Action(11, `{"dst_ip":"{dst_ip}","action":"rate_limit","rate_limit":5000}`)
			act.XDropAction = "rate_limit"
			s.actions = []store.ResponseAction{act}
			before := v3SkipCounter()
			NewEngine(s, "auto").HandleEvent(tracker.AttackEvent{Type: "confirmed", Attack: a, DBID: 101})
			if !v3Eventually(2*time.Second, func() bool { return len(s.logSnapshot()) > 0 }) {
				t.Fatal("no dispatch log")
			}
			logs := s.logSnapshot()
			v3Success(t, logs[len(logs)-1])
			if v3SkipCounter() != before {
				t.Fatal("skip counter grew")
			}
			requests := m.snapshot()
			if len(requests) != 1 || requests[0].Method != "POST" {
				t.Fatal(requests)
			}
			var body map[string]any
			_ = json.Unmarshal(requests[0].Body, &body)
			if body["match_anomaly"] != float64(i+1) || body["action"] != "rate_limit" {
				t.Fatal(body)
			}
		})
	}
}
func TestC9_ProtocolFamilies(t *testing.T) {
	for _, path := range []string{"default", "custom"} {
		for _, tc := range []struct{ dec, dst, proto, fragment string }{{"fragment", "198.51.100.7", "all", "frag"}, {"fragment", "2001:db8::7/128", "all", ""}, {"icmp", "198.51.100.7", "icmp", ""}, {"icmp", "2001:db8::7/128", "icmpv6", ""}} {
			t.Run(path+"/"+tc.dec+"/"+tc.dst, func(t *testing.T) {
				m := newV3Mock(t)
				s := newV3Store(m.server.URL)
				payload := ""
				if path == "custom" {
					payload = `{"dst_ip":"{dst_ip}","protocol":"{decoder}"}`
				}
				l, body := v3Execute(t, m, s, v3Attack(101, tc.dec, tc.dst), v3Action(11, payload), nil)
				v3Success(t, l)
				if body["protocol"] != tc.proto {
					t.Fatal(body)
				}
				if tc.fragment == "" {
					v3NoKeys(t, body, "fragment")
				} else if body["fragment"] != tc.fragment {
					t.Fatal(body)
				}
			})
		}
	}
}
func TestC10_ErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{{"conflict", `{"code":"rule_conflict","message":"conflict"}`, "HTTP 409 rule_conflict: conflict", 409}, {"field", `{"code":"invalid_rule","field":"tcp_flags","message":"flags require tcp"}`, "HTTP 400 invalid_rule field=tcp_flags: flags require tcp", 400}, {"non_json", "broken", "HTTP 500: broken", 500}} {
		t.Run(tc.name, func(t *testing.T) {
			m := newV3Mock(t)
			m.postStatus, m.postBody = tc.status, []byte(tc.body)
			s := newV3Store(m.server.URL)
			l, _ := v3Execute(t, m, s, v3Attack(101, "udp", "198.51.100.7"), v3Action(11, ""), nil)
			if l.Status != "failed" || l.ErrorMessage != tc.want {
				t.Fatal(l)
			}
		})
	}
	t.Run("anomaly_no_anchor", func(t *testing.T) {
		m := newV3Mock(t)
		s := newV3Store(m.server.URL)
		l, _ := v3Execute(t, m, s, v3Attack(101, "invalid", "198.51.100.7"), v3Action(11, `{"protocol":"{decoder}"}`), nil)
		if l.Status != "failed" || !strings.Contains(l.ErrorMessage, "invalid_rule") {
			t.Fatal(l)
		}
	})
	t.Run("bad_fragment_ipv6", func(t *testing.T) {
		m := newV3Mock(t)
		s := newV3Store(m.server.URL)
		l, _ := v3Execute(t, m, s, v3Attack(101, "bad_fragment", "2001:db8::7/128"), v3Action(11, ""), nil)
		if l.Status != "failed" || !strings.Contains(l.ErrorMessage, "invalid_rule") {
			t.Fatal(l)
		}
	})
}
func TestC12_Delivery(t *testing.T) {
	for _, tc := range []struct {
		name                string
		conflicts, requests int
		missing, fail       bool
	}{{"normal", 0, 2, false, false}, {"retry", 1, 4, false, false}, {"retry_limit", 2, 4, false, true}, {"missing", 1, 4, true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			m := newV3Mock(t)
			s := newV3Store(m.server.URL)
			l, _ := v3Execute(t, m, s, v3Attack(101, "udp", "198.51.100.7"), v3Action(11, ""), nil)
			v3Success(t, l)
			m.mu.Lock()
			m.requests = nil
			m.deliveryConflicts = tc.conflicts
			m.mu.Unlock()
			id := l.ExternalRuleID
			if tc.missing {
				id = "rule_ffffffffffffffffffffffffffffffff"
			}
			result, err := QueryXDropDelivery(context.Background(), s.conn, id)
			if tc.fail {
				if err == nil || !strings.Contains(err.Error(), "gen_epoch_mismatch") {
					t.Fatalf("%+v %v", result, err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if tc.missing {
				if result != nil {
					t.Fatal(result)
				}
			} else {
				if result == nil || result.RuleID != id || result.TargetGen != 1 || result.Epoch != "epoch-test" || len(result.Nodes) != 2 || result.Nodes[0].State != "confirmed" || result.Nodes[1].Code != "invalid_rule" || result.Nodes[1].Error != "test rejection" {
					t.Fatalf("%+v", result)
				}
			}
			requests := m.snapshot()
			if len(requests) != tc.requests {
				t.Fatalf("requests=%d", len(requests))
			}
			for i, r := range requests {
				if r.Auth != "Bearer "+v3TestKey || r.Method != "GET" {
					t.Fatal(r)
				}
				if i%2 == 0 && r.Path != "/nodes" || i%2 == 1 && !strings.HasSuffix(r.Path, "/delivery") {
					t.Fatal(requests)
				}
				if i%2 == 1 && !strings.Contains(r.Query, "gen=0") {
					t.Fatal(r)
				}
			}
		})
	}
}
func TestC13_LegacyAnomalyUnion(t *testing.T) {
	m := newV3Mock(t)
	s := newV3Store(m.server.URL)
	l, body := v3Execute(t, m, s, v3Attack(101, "invalid", "198.51.100.7"), v3Action(11, `{"dst_ip":"{dst_ip}","decoder":"bad_fragment","match_anomaly":2}`), nil)
	v3Success(t, l)
	v3NoKeys(t, body, "decoder", "protocol")
	if body["match_anomaly"] != float64(3) {
		t.Fatal(body)
	}
}

func TestC13_FailureHints(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"upstream", `{"code":"rule_conflict","message":"conflict"}`, "rule_conflict", 409},
		{"invalid_id", `{}`, "v3 created but id missing", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newV3Mock(t)
			m.postStatus, m.postBody = tc.status, []byte(tc.body)
			s := newV3Store(m.server.URL)
			l, _ := v3Execute(t, m, s, v3Attack(101, "udp", "198.51.100.7"), v3Action(11, `{"dst_ip":"{dst_ip}","protocol":"tcp","source":"xsight"}`), nil)
			if l.Status != "failed" {
				t.Fatal(l)
			}
			for _, want := range []string{tc.want, "protocol pinned: tcp→udp", "dropped: source"} {
				if !strings.Contains(l.ErrorMessage, want) {
					t.Fatalf("missing %q: %s", want, l.ErrorMessage)
				}
			}
		})
	}
}

func TestC13_DroppedFields(t *testing.T) {
	m := newV3Mock(t)
	s := newV3Store(m.server.URL)
	l, body := v3Execute(t, m, s, v3Attack(101, "udp", "198.51.100.7"), v3Action(11, `{"dst_ip":"{dst_ip}","source":"xsight","expires_in":"1h","unknown_test_key":true}`), nil)
	v3Success(t, l)
	v3NoKeys(t, body, "source", "expires_in", "unknown_test_key")
	for _, part := range []string{"dropped:", "source", "expires_in", "unknown_test_key"} {
		if !strings.Contains(l.ErrorMessage, part) {
			t.Errorf("missing %s: %s", part, l.ErrorMessage)
		}
	}
}
func v3Expected(dec, dst string) string {
	switch dec {
	case "tcp", "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin":
		return "tcp"
	case "icmp":
		if strings.Contains(dst, ":") {
			return "icmpv6"
		}
		return "icmp"
	case "fragment":
		return "all"
	case "bad_fragment", "invalid":
		return ""
	}
	return dec
}
func TestC14_ProtocolPinned(t *testing.T) {
	for _, dec := range v3Decoders {
		for _, mode := range []string{"absent", "empty", "wrong", "default", "correct"} {
			t.Run(dec+"/"+mode, func(t *testing.T) {
				m := newV3Mock(t)
				s := newV3Store(m.server.URL)
				want := v3Expected(dec, "198.51.100.7")
				payload := ""
				if mode != "default" {
					body := map[string]any{"dst_ip": "{dst_ip}"}
					switch mode {
					case "empty":
						body["protocol"] = ""
					case "wrong":
						body["protocol"] = "tcp"
						if want == "tcp" {
							body["protocol"] = "udp"
						}
					case "correct":
						if want != "" {
							body["protocol"] = want
						}
					}
					raw, _ := json.Marshal(body)
					payload = string(raw)
				}
				l, body := v3Execute(t, m, s, v3Attack(101, dec, "198.51.100.7"), v3Action(11, payload), nil)
				v3Success(t, l)
				if want == "" {
					v3NoKeys(t, body, "protocol")
				} else if body["protocol"] != want {
					t.Fatal(body)
				}
				hint := strings.Contains(l.ErrorMessage, "protocol pinned:")
				if mode == "wrong" && want != "" && !hint {
					t.Fatal("missing protocol pinned hint")
				}
				if (mode == "correct" || mode == "default") && hint {
					t.Fatal("unchanged protocol logged as pinned")
				}
			})
		}
	}
}
func TestC15_FlowFilter(t *testing.T) {
	for _, bypass := range []bool{false, true} {
		for _, tc := range []struct {
			name, dec, dst                 string
			proto, flags, dirtyFlags, want int
		}{{"01_udp", "udp", "198.51.100.7", 17, 0, 0, 53}, {"02_syn", "tcp_syn", "198.51.100.7", 6, 2, 18, 80}, {"03_ack", "tcp_ack", "198.51.100.7", 6, 16, 18, 81}, {"04_icmpv6", "icmp", "2001:db8::7", 58, 0, 0, 0}} {
			t.Run(fmt.Sprintf("%s/bypass_%t", tc.name, bypass), func(t *testing.T) {
				s := newV3Store("")
				s.bypassFilter = bypass
				dirtyProto := 6
				if tc.dec == "icmp" {
					dirtyProto = 1
				}
				s.flows = []store.FlowLog{{SrcIP: "192.0.2.1", DstPort: tc.want, Protocol: tc.proto, TCPFlags: tc.flags, Packets: 60}, {SrcIP: "192.0.2.2", DstPort: tc.want, Protocol: tc.proto, TCPFlags: tc.flags, Packets: 40}, {SrcIP: "192.0.2.3", DstPort: 443, Protocol: dirtyProto, TCPFlags: tc.dirtyFlags, Packets: 10000}}
				fa := analyzeFlows(context.Background(), s, v3Attack(101, tc.dec, tc.dst))
				if fa == nil || fa.DominantDstPort != tc.want {
					t.Fatalf("%+v", fa)
				}
				if !reflect.DeepEqual(s.filter.Protocols, []int{tc.proto}) {
					t.Fatal(s.filter)
				}
				if tc.dec == "tcp_syn" && (s.filter.TCPFlagsAll != 2 || s.filter.TCPFlagsNone != 16) {
					t.Fatal(s.filter)
				}
				if tc.dec == "tcp_ack" && (s.filter.TCPFlagsAll != 16 || s.filter.TCPFlagsNone != 2) {
					t.Fatal(s.filter)
				}
				if got := expandParams("{dominant_dst_port}", v3Attack(101, tc.dec, tc.dst), "confirmed", tc.dst, fa); got != fmt.Sprint(tc.want) && tc.want != 0 {
					t.Fatalf("webhook variable=%s", got)
				}
			})
		}
	}
	for _, bypass := range []bool{false, true} {
		for _, tc := range []struct {
			name, decoder string
			flags         int
		}{{"06_rst", "tcp_rst", 4}, {"07_fin", "tcp_fin", 1}} {
			t.Run(fmt.Sprintf("%s/bypass_%t", tc.name, bypass), func(t *testing.T) {
				s := newV3Store("")
				s.bypassFilter = bypass
				s.flows = []store.FlowLog{
					{SrcIP: "192.0.2.1", DstPort: 80, Protocol: 6, TCPFlags: tc.flags, Packets: 100},
					{SrcIP: "192.0.2.2", DstPort: 443, Protocol: 6, TCPFlags: 16, Packets: 10000},
				}
				fa := analyzeFlows(context.Background(), s, v3Attack(101, tc.decoder, "198.51.100.7"))
				if fa == nil || fa.DominantDstPort != 80 {
					t.Errorf("want dominant port 80: analysis=%+v filter=%+v", fa, s.filter)
				}
				if !reflect.DeepEqual(s.filter.Protocols, []int{6}) || s.filter.TCPFlagsAll != uint8(tc.flags) || s.filter.TCPFlagsNone != 0 {
					t.Errorf("want protocol 6 all=%d none=0: %+v", tc.flags, s.filter)
				}
			})
		}
	}
	t.Run("05_all_filtered", func(t *testing.T) {
		s := newV3Store("")
		s.bypassFilter = true
		s.flows = []store.FlowLog{{Protocol: 6, DstPort: 443, Packets: 10}}
		if analyzeFlows(context.Background(), s, v3Attack(101, "udp", "198.51.100.7")) != nil {
			t.Fatal("expected no flow data")
		}
	})
}
func TestC15_WebhookVariable(t *testing.T) {
	s := newV3Store("")
	s.bypassFilter = true
	s.flows = []store.FlowLog{{Protocol: 17, DstPort: 53, Packets: 100}, {Protocol: 6, DstPort: 443, Packets: 10000}}
	a := v3Attack(101, "udp", "198.51.100.7")
	fa := analyzeFlows(context.Background(), s, a)
	if got := expandParams("{dominant_dst_port}", a, "confirmed", a.DstIP, fa); got != "53" {
		t.Fatalf("webhook variable=%s", got)
	}
}

func TestC17_DecoderTable(t *testing.T) {
	count := 0
	for dec, enabled := range xDropCompatibleDecoders {
		if !enabled {
			continue
		}
		count++
		if _, exists := xdropDecoderSpec[dec]; !exists {
			t.Errorf("missing %s", dec)
		}
	}
	if count != len(xdropDecoderSpec) {
		t.Errorf("table sizes %d %d", count, len(xdropDecoderSpec))
	}
	for dec, spec := range xdropDecoderSpec {
		if !xDropCompatibleDecoders[dec] {
			t.Errorf("extra %s", dec)
		}
		if dec == "fragment" || dec == "bad_fragment" || dec == "invalid" {
			if spec.ProtocolV4 != 0 || spec.ProtocolV6 != 0 || spec.TCPFlagsAll != 0 || spec.TCPFlagsNone != 0 {
				t.Errorf("unexpected sample filter for %s", dec)
			}
		}
	}
}
