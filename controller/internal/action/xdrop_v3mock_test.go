package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

const v3TestKey = "xdk_0000000000000000_test"

// v3RulePatch is the independent 20-field DTO from tag v3.0.0-rc1,
// controller/core/rules/input.go. ClaimRef belongs to the create wrapper.
type v3RulePatch struct {
	SrcIP        *string `json:"src_ip"`
	DstIP        *string `json:"dst_ip"`
	SrcCIDR      *string `json:"src_cidr"`
	DstCIDR      *string `json:"dst_cidr"`
	SrcPort      *int    `json:"src_port"`
	DstPort      *int    `json:"dst_port"`
	Protocol     *string `json:"protocol"`
	TTL          *string `json:"ttl"`
	DSCP         *string `json:"dscp"`
	ICMPType     *string `json:"icmp_type"`
	ICMPCode     *string `json:"icmp_code"`
	Fragment     *string `json:"fragment"`
	PktLen       *string `json:"pkt_len"`
	TCPFlags     *string `json:"tcp_flags"`
	MatchAnomaly *int    `json:"match_anomaly"`
	Action       *string `json:"action"`
	RateLimit    *int64  `json:"rate_limit"`
	Enabled      *bool   `json:"enabled"`
	Comment      *string `json:"comment"`
	ExpiresIn    *string `json:"expires_in"`
}
type v3Create struct {
	v3RulePatch
	ClaimRef string `json:"claim_ref"`
}
type v3Request struct {
	Method, Path, Query, Auth string
	Body                      []byte
}
type v3Rule struct {
	id       string
	logical  int
	fields   map[string]any
	identity string
	claims   map[string]bool
}
type v3Mock struct {
	server            *httptest.Server
	mu                sync.Mutex
	requests          []v3Request
	rules             map[string]*v3Rule
	sequence          int
	epoch             string
	userNext          bool
	deliveryConflicts int
	postStatus        int
	postBody          []byte
	responses         [][]byte
}

func newV3Mock(t *testing.T) *v3Mock {
	t.Helper()
	m := &v3Mock{rules: map[string]*v3Rule{}, epoch: "epoch-test"}
	m.server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.server.Close)
	return m
}
func (m *v3Mock) snapshot() []v3Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]v3Request(nil), m.requests...)
}
func (m *v3Mock) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.rules) }
func (m *v3Mock) claimCount(id string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.rules[id]; r != nil {
		return len(r.claims)
	}
	return 0
}
func v3Write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func v3Error(w http.ResponseWriter, status int, code, field string) {
	v3Write(w, status, map[string]any{"code": code, "message": "test contract rejection", "field": field})
}

// v3Canonical follows Canonicalize's address-family / raw exact-CIDR /
// canonicalIP order, then normalizes identity before comparing it.
func v3Canonical(p v3RulePatch) (map[string]any, string, string) {
	m := map[string]any{}
	v := reflect.ValueOf(p)
	typ := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := typ.Field(i).Tag.Get("json")
		ptr := v.Field(i)
		if ptr.IsNil() {
			m[field] = reflect.Zero(ptr.Type().Elem()).Interface()
			continue
		}
		value := ptr.Elem().Interface()
		if value == "" && field != "comment" {
			return nil, "empty_value", field
		}
		m[field] = value
	}
	str := func(k string) string { s, _ := m[k].(string); return s }
	if p.Enabled == nil {
		m["enabled"] = true
	}
	for _, key := range []string{"src_port", "dst_port"} {
		n := m[key].(int)
		if n < 0 || n > 65535 {
			return nil, "invalid_rule", key
		}
	}
	if str("action") == "" {
		m["action"] = "drop"
	}
	rate := m["rate_limit"].(int64)
	if rate < 0 || rate > 4294967295 {
		return nil, "invalid_rule", "rate_limit"
	}
	if str("action") == "drop" {
		m["rate_limit"] = int64(0)
	} else if str("action") != "rate_limit" || rate == 0 {
		return nil, "invalid_rule", "action"
	}
	isCIDR := str("src_cidr") != "" || str("dst_cidr") != ""
	addrKeys := []string{"src_ip", "dst_ip"}
	if isCIDR {
		addrKeys = []string{"src_cidr", "dst_cidr"}
	}
	family := 0
	for _, key := range addrKeys {
		raw := str(key)
		if raw == "" || !isCIDR && (raw == "0.0.0.0" || raw == "::") {
			continue
		}
		ip := net.ParseIP(raw)
		if isCIDR {
			ip, _, _ = net.ParseCIDR(raw)
		}
		if ip == nil {
			continue
		}
		if strings.Contains(strings.Split(raw, "/")[0], ":") && ip.To4() != nil {
			return nil, "mapped_ipv6", key
		}
		next := 6
		if ip.To4() != nil {
			next = 4
		}
		if family != 0 && family != next {
			return nil, "address_family_mismatch", ""
		}
		family = next
	}
	if isCIDR && (str("src_ip") != "" || str("dst_ip") != "") {
		return nil, "invalid_rule", "ip"
	}
	bounded, v4, v6 := false, false, false
	for _, key := range []string{"src_ip", "dst_ip"} {
		if str(key) == "" {
			continue
		}
		ip := net.ParseIP(str(key))
		if ip == nil {
			return nil, "invalid_rule", "ip"
		}
		value := ip.String()
		if value == "0.0.0.0" || value == "::" {
			value = ""
		}
		m[key] = value
		if value != "" {
			bounded = true
			v4 = v4 || ip.To4() != nil
			v6 = v6 || ip.To4() == nil
		}
	}
	for _, key := range []string{"src_cidr", "dst_cidr"} {
		if str(key) == "" {
			continue
		}
		ip, n, err := net.ParseCIDR(str(key))
		if err != nil {
			return nil, "invalid_rule", "cidr"
		}
		m[key] = n.String()
		ones, _ := n.Mask.Size()
		bounded = bounded || ones > 0
		v4 = v4 || ip.To4() != nil
		v6 = v6 || ip.To4() == nil
	}
	if str("protocol") == "" {
		m["protocol"] = "all"
	}
	switch str("protocol") {
	case "all", "tcp", "udp":
	case "icmp", "icmpv6", "gre", "esp", "igmp":
		if m["src_port"].(int) != 0 || m["dst_port"].(int) != 0 {
			return nil, "invalid_rule", "protocol"
		}
	default:
		return nil, "invalid_rule", "protocol"
	}
	if !isCIDR && str("src_ip") == "" && str("dst_ip") == "" && m["src_port"].(int) == 0 && m["dst_port"].(int) == 0 && str("protocol") == "all" {
		return nil, "invalid_rule", "tuple"
	}
	bits := m["match_anomaly"].(int)
	if bits < 0 || bits & ^15 != 0 || bits != 0 && (!bounded || v6 && bits&9 != 0) {
		return nil, "invalid_rule", "match_anomaly"
	}
	names := []string{"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
	mask, value := 0, 0
	for _, part := range strings.Split(str("tcp_flags"), ",") {
		part = strings.ToUpper(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		neg := strings.HasPrefix(part, "!")
		name := strings.TrimPrefix(part, "!")
		bit := 0
		for i, n := range names {
			if name == n {
				bit = 1 << i
			}
		}
		if bit == 0 || mask&bit != 0 && (value&bit != 0) == neg {
			return nil, "invalid_rule", "tcp_flags"
		}
		mask |= bit
		if !neg {
			value |= bit
		}
	}
	if mask != 0 && str("protocol") != "tcp" {
		return nil, "invalid_rule", "tcp_flags"
	}
	var flags []string
	for i := len(names) - 1; i >= 0; i-- {
		bit := 1 << i
		if mask&bit == 0 {
			continue
		}
		name := names[i]
		if value&bit == 0 {
			name = "!" + name
		}
		flags = append(flags, name)
	}
	m["tcp_flags"] = strings.Join(flags, ",")
	if str("fragment") != "" && (!v4 || v6) {
		return nil, "invalid_rule", "conditions"
	}
	for key, max := range map[string]int{"ttl": 255, "dscp": 63, "icmp_type": 255, "icmp_code": 255, "pkt_len": 65535, "fragment": 7} {
		if str(key) == "" {
			continue
		}
		if (key == "icmp_type" || key == "icmp_code") && str("protocol") != "icmp" && str("protocol") != "icmpv6" {
			return nil, "invalid_rule", "conditions"
		}
		canonical, ok := v3Expression(key, str(key), max)
		if !ok {
			return nil, "invalid_rule", "conditions"
		}
		m[key] = canonical
	}
	return m, "", ""
}
func v3Expression(key, raw string, max int) (string, bool) {
	for _, r := range raw {
		if r == '\n' || r == '\r' || r > 127 {
			return "", false
		}
	}
	raw = strings.Trim(raw, " \t")
	neg := strings.HasPrefix(raw, "!")
	raw = strings.Trim(strings.TrimPrefix(raw, "!"), " \t")
	set := make([]bool, max+1)
	atoms := map[string][]int{"nofrag": {0, 4}, "first": {2, 6}, "middle": {3, 7}, "last": {1, 5}, "frag": {1, 2, 3, 5, 6, 7}, "nonfirst": {1, 3, 5, 7}}
	for _, part := range strings.Split(raw, ",") {
		part = strings.Trim(part, " \t")
		if key == "fragment" {
			values, ok := atoms[strings.ToLower(part)]
			if !ok {
				return "", false
			}
			for _, n := range values {
				set[n] = true
			}
			continue
		}
		ends := strings.Split(part, "-")
		if len(ends) > 2 {
			return "", false
		}
		nums := []int{}
		for _, end := range ends {
			end = strings.Trim(end, " \t")
			if end == "" || len(end) > 1 && end[0] == '0' {
				return "", false
			}
			for _, c := range end {
				if c < '0' || c > '9' {
					return "", false
				}
			}
			n, err := strconv.Atoi(end)
			if err != nil || n > max {
				return "", false
			}
			nums = append(nums, n)
		}
		lo, hi := nums[0], nums[len(nums)-1]
		if hi < lo {
			return "", false
		}
		for n := lo; n <= hi; n++ {
			set[n] = true
		}
	}
	count := 0
	for i := range set {
		if neg {
			set[i] = !set[i]
		}
		if set[i] {
			count++
		}
	}
	if count == 0 || count == len(set) {
		return "", false
	}
	var parts []string
	if key == "fragment" {
		for _, name := range []string{"nofrag", "first", "middle", "last"} {
			if set[atoms[name][0]] {
				parts = append(parts, name)
			}
		}
	} else {
		for i := 0; i < len(set); i++ {
			if !set[i] {
				continue
			}
			start := i
			for i+1 < len(set) && set[i+1] {
				i++
			}
			p := strconv.Itoa(start)
			if i > start {
				p += "-" + strconv.Itoa(i)
			}
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ","), true
}
func (m *v3Mock) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, v3Request{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), body})
	if r.Header.Get("Authorization") != "Bearer "+v3TestKey {
		v3Error(w, 401, "unauthenticated", "")
		return
	}
	path := r.URL.Path
	if path == "/auth/me" {
		kind := "machine"
		if m.userNext {
			kind = "user"
			m.userNext = false
		}
		v3Write(w, 200, map[string]string{"kind": kind, "name": "xsight-test"})
		return
	}
	if path == "/nodes" {
		v3Write(w, 200, map[string]any{"epoch": m.epoch, "nodes": []any{}})
		return
	}
	if path == "/rules" && r.Method == "POST" {
		var input v3Create
		d := json.NewDecoder(bytes.NewReader(body))
		d.DisallowUnknownFields()
		err := d.Decode(&input)
		var extra any
		if err != nil || d.Decode(&extra) != io.EOF {
			field := ""
			if err != nil && strings.HasPrefix(err.Error(), "json: unknown field ") {
				field = strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), "\"")
			}
			v3Error(w, 400, "bad_request", field)
			return
		}
		fields, code, field := v3Canonical(input.v3RulePatch)
		if code != "" {
			v3Error(w, 400, code, field)
			return
		}
		identity := map[string]any{}
		for k, v := range fields {
			if !strings.Contains(" action rate_limit comment enabled expires_in ", " "+k+" ") {
				identity[k] = v
			}
		}
		encoded, _ := json.Marshal(identity)
		var found *v3Rule
		status := 201
		for _, rule := range m.rules {
			if rule.identity == string(encoded) {
				found = rule
				status = 200
				break
			}
		}
		if found != nil && (found.fields["action"] != fields["action"] || found.fields["rate_limit"] != fields["rate_limit"]) {
			v3Error(w, 409, "rule_conflict", "")
			return
		}
		if found == nil {
			m.sequence++
			id := fmt.Sprintf("rule_%032x", m.sequence)
			found = &v3Rule{id: id, logical: m.sequence, fields: fields, identity: string(encoded), claims: map[string]bool{}}
			m.rules[id] = found
		}
		found.claims[r.Header.Get("Authorization")+"|"+input.ClaimRef] = true
		out := m.ruleJSON(found)
		out["existing"] = status == 200
		out["gen"] = m.sequence
		out["epoch"] = m.epoch
		out["nodes"] = []any{map[string]any{"name": "node-a", "online": true, "incompatible": false, "rules_state": "synced"}, map[string]any{"name": "node-b", "online": true, "incompatible": false, "rules_state": "pending"}, map[string]any{"name": "node-c", "online": false, "incompatible": false, "rules_state": "offline"}}
		response, _ := json.Marshal(out)
		if len(response) < 1104 {
			response = append(append(response[:len(response)-1], bytes.Repeat([]byte(" "), 1104-len(response))...), '}')
		}
		if m.postStatus != 0 {
			status = m.postStatus
			response = append([]byte(nil), m.postBody...)
			m.postStatus = 0
		}
		m.responses = append(m.responses, response)
		w.WriteHeader(status)
		_, _ = w.Write(response)
		return
	}
	if path == "/rules" && r.Method == "GET" {
		m.list(w, r)
		return
	}
	id := strings.TrimPrefix(path, "/rules/")
	if strings.HasSuffix(id, "/delivery") {
		id = strings.TrimSuffix(id, "/delivery")
		if m.deliveryConflicts > 0 {
			m.deliveryConflicts--
			v3Error(w, 409, "gen_epoch_mismatch", "")
			return
		}
		if r.URL.Query().Get("epoch") != m.epoch {
			v3Error(w, 409, "gen_epoch_mismatch", "")
			return
		}
		if m.rules[id] == nil {
			v3Error(w, 404, "not_found", "")
			return
		}
		v3Write(w, 200, map[string]any{"rule_id": id, "gen": m.sequence, "target_gen": m.sequence, "epoch": m.epoch, "nodes": []any{map[string]string{"name": "node-a", "state": "confirmed"}, map[string]string{"name": "node-b", "state": "rejected", "code": "invalid_rule", "error": "test rejection"}}})
		return
	}
	if r.Method == "DELETE" {
		if rule := m.rules[id]; rule != nil {
			delete(rule.claims, r.Header.Get("Authorization")+"|"+r.URL.Query().Get("claim_ref"))
			if len(rule.claims) == 0 {
				delete(m.rules, id)
			}
		}
		w.WriteHeader(204)
		return
	}
	if rule := m.rules[id]; rule != nil && r.Method == "GET" {
		v3Write(w, 200, m.ruleJSON(rule))
		return
	}
	v3Error(w, 404, "not_found", "")
}
func (m *v3Mock) ruleJSON(r *v3Rule) map[string]any {
	out := map[string]any{}
	for k, v := range r.fields {
		if k != "expires_in" {
			out[k] = v
		}
	}
	out["id"] = r.id
	out["logical_id"] = r.logical
	out["kind"] = "exact"
	if r.fields["src_cidr"] != "" || r.fields["dst_cidr"] != "" {
		out["kind"] = "cidr"
	}
	out["group_key"] = r.identity
	out["cond_key"] = "[]"
	out["created_at"] = "2026-10-19T00:00:00Z"
	out["updated_at"] = out["created_at"]
	out["created_by"] = "machine:test"
	out["updated_by"] = "machine:test"
	out["expires_at"] = nil
	return out
}
func (m *v3Mock) list(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	isID := regexp.MustCompile(`^rule_[0-9a-f]{32}$`).MatchString(q)
	ip := net.ParseIP(q)
	_, network, _ := net.ParseCIDR(q)
	if q != "" && !isID && ip == nil && network == nil {
		v3Error(w, 400, "bad_request", "q")
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000 {
			v3Error(w, 400, "bad_request", "limit")
			return
		}
		limit = n
	}
	after := int64(0)
	if raw := r.URL.Query().Get("after"); r.URL.Query().Has("after") {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			v3Error(w, 400, "bad_request", "after")
			return
		}
		after = n
	}
	var matches []*v3Rule
	for _, rule := range m.rules {
		if int64(rule.logical) <= after {
			continue
		}
		match := q == "" || q == rule.id
		for _, key := range []string{"src_ip", "dst_ip", "src_cidr", "dst_cidr"} {
			raw, _ := rule.fields[key].(string)
			candidate := net.ParseIP(raw)
			_, prefix, _ := net.ParseCIDR(raw)
			if network != nil {
				match = match || candidate != nil && network.Contains(candidate) || prefix != nil && (network.Contains(prefix.IP) || prefix.Contains(network.IP))
			} else if ip != nil {
				match = match || candidate != nil && ip.Equal(candidate) || prefix != nil && prefix.Contains(ip)
			}
		}
		if match {
			matches = append(matches, rule)
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].logical < matches[j].logical })
	var next any
	if len(matches) > limit {
		matches = matches[:limit]
		next = matches[limit-1].logical
	}
	items := []any{}
	for _, rule := range matches {
		items = append(items, m.ruleJSON(rule))
	}
	v3Write(w, 200, map[string]any{"items": items, "next_after": next})
}
func v3Raw(t *testing.T, m *v3Mock, method, path, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, m.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+v3TestKey)
	resp, err := m.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
func v3Seed(t *testing.T, m *v3Mock, extra string) (int, map[string]any) {
	return v3Raw(t, m, "POST", "/rules", `{"protocol":"udp",`+extra+`}`)
}

func TestV3MockSelfCheck(t *testing.T) {
	for _, tc := range []struct{ name, extra, code string }{
		{"01_exact_cidr", `"dst_cidr":"198.51.100.0/24","src_ip":"192.0.2.10"`, "invalid_rule"},
		{"01_wildcard_exact_cidr", `"dst_cidr":"198.51.100.0/24","src_ip":"0.0.0.0"`, "invalid_rule"},
		{"01_positive", `"dst_cidr":"198.51.100.0/24","src_cidr":"192.0.2.10/32"`, ""},
		{"04_family", `"dst_cidr":"198.51.100.0/24","src_cidr":"2001:db8::1/128"`, "address_family_mismatch"},
		{"04_exact_order", `"dst_cidr":"198.51.100.0/24","src_ip":"2001:db8::1"`, "invalid_rule"},
		{"04_positive", `"dst_cidr":"198.51.100.0/24","src_cidr":"192.0.2.10/32"`, ""},
		{"06_fragment_v6", `"dst_ip":"2001:db8::1","fragment":"frag"`, "invalid_rule"},
		{"06_positive", `"dst_cidr":"198.51.100.0/24","fragment":"frag"`, ""},
		{"07_anomaly_unbounded", `"dst_cidr":"0.0.0.0/0","match_anomaly":2`, "invalid_rule"},
		{"07_positive", `"dst_cidr":"198.51.100.0/24","match_anomaly":2`, ""},
		{"08_flags_udp", `"dst_ip":"198.51.100.7","tcp_flags":"SYN"`, "invalid_rule"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newV3Mock(t)
			status, out := v3Seed(t, m, tc.extra)
			want := 201
			if tc.code != "" {
				want = 400
			}
			if status != want || tc.code != "" && out["code"] != tc.code {
				t.Fatalf("%d %v", status, out)
			}
		})
	}
	t.Run("08_positive", func(t *testing.T) {
		m := newV3Mock(t)
		status, _ := v3Raw(t, m, "POST", "/rules", `{"protocol":"tcp","dst_ip":"198.51.100.7","tcp_flags":"SYN,!ACK"}`)
		if status != 201 {
			t.Fatal(status)
		}
	})
	for _, tc := range []struct {
		name, first, second string
		idempotent          bool
	}{
		{"02_distinct_refs", `"claim_ref":"a1.x1"`, `"claim_ref":"a2.x1"`, false},
		{"02_idempotent_ref", `"claim_ref":"a1.x1"`, `"claim_ref":"a1.x1"`, true},
		{"03_drop_rate_zero", `"action":"drop","rate_limit":42`, `"action":"drop"`, false},
		{"05_wildcard_identity", `"src_ip":"0.0.0.0"`, `"comment":""`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newV3Mock(t)
			s, a := v3Seed(t, m, `"dst_ip":"198.51.100.7",`+tc.first)
			s2, b := v3Seed(t, m, `"dst_ip":"198.51.100.7",`+tc.second)
			if s != 201 || s2 != 200 || a["id"] != b["id"] || b["existing"] != true {
				t.Fatalf("%d %d %v %v", s, s2, a, b)
			}
			if tc.idempotent {
				status, _ := v3Raw(t, m, "DELETE", "/rules/"+a["id"].(string)+"?claim_ref=a1.x1", "")
				if status != 204 || m.count() != 0 {
					t.Fatal("same ref was not idempotent")
				}
			} else if tc.name == "02_distinct_refs" && m.claimCount(a["id"].(string)) != 2 {
				t.Fatal("missing claim")
			}
		})
	}
	for _, q := range []string{"198.51.100.", "198.51.100.0/24", "", "rule_00000000000000000000000000000001"} {
		t.Run("09_query_"+q, func(t *testing.T) {
			m := newV3Mock(t)
			s, _ := v3Raw(t, m, "GET", "/rules?q="+url.QueryEscape(q), "")
			want := 200
			if q == "198.51.100." {
				want = 400
			}
			if s != want {
				t.Fatal(s)
			}
		})
	}
	t.Run("09_pagination", func(t *testing.T) {
		t.Run("after_empty", func(t *testing.T) {
			m := newV3Mock(t)
			status, out := v3Raw(t, m, "GET", "/rules?q=&limit=1&after=", "")
			if status != 400 || out["code"] != "bad_request" || out["field"] != "after" {
				t.Fatalf("explicit empty after: HTTP %d %v", status, out)
			}
		})
		t.Run("after_zero", func(t *testing.T) {
			m := newV3Mock(t)
			status, out := v3Raw(t, m, "GET", "/rules?q=&limit=1&after=0", "")
			if status != 200 {
				t.Fatalf("explicit zero after: HTTP %d %v", status, out)
			}
		})
		m := newV3Mock(t)
		for i := 1; i <= 3; i++ {
			status, _ := v3Seed(t, m, fmt.Sprintf(`"dst_ip":"198.51.100.%d"`, i))
			if status != 201 {
				t.Fatal(status)
			}
		}
		seen := map[string]bool{}
		after := ""
		for page := 0; page < 4; page++ {
			path := "/rules?q=&limit=1"
			if after != "" {
				path += "&after=" + url.QueryEscape(after)
			}
			status, out := v3Raw(t, m, "GET", path, "")
			if status != 200 {
				t.Fatal(status)
			}
			items := out["items"].([]any)
			if len(items) != 1 {
				t.Fatal(items)
			}
			id := items[0].(map[string]any)["id"].(string)
			if seen[id] {
				t.Fatal("duplicate page")
			}
			seen[id] = true
			if out["next_after"] == nil {
				break
			}
			after = fmt.Sprint(out["next_after"])
		}
		if len(seen) != 3 {
			t.Fatal(seen)
		}
	})
}

func TestV3StoreSelfCheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		logs []store.ActionExecutionLog
		want int
	}{
		{"summary_without_rule", []store.ActionExecutionLog{{AttackID: 1, ActionID: 9, ActionType: "xdrop", Status: "success"}}, 0},
		{"distinct_triple", []store.ActionExecutionLog{{AttackID: 1, ActionID: 9, ActionType: "xdrop", Status: "success", ExternalRuleID: "rule_test"}, {AttackID: 1, ActionID: 9, ActionType: "xdrop", Status: "success", ExternalRuleID: "rule_test"}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newV3Store("")
			for _, l := range tc.logs {
				if l.ExternalRuleID != "" {
					if _, err := s.XDropActiveRules().Upsert(context.Background(), &store.XDropActiveRule{AttackID: l.AttackID, ActionID: l.ActionID, ExternalRuleID: l.ExternalRuleID, Status: "active"}); err != nil {
						t.Fatal(err)
					}
				}
			}
			rows, err := s.XDropActiveRules().ListByAttack(context.Background(), 1)
			if err != nil || len(rows) != tc.want {
				t.Fatalf("%v %v", rows, err)
			}
		})
	}
}
