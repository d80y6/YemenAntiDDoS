//go:build xdroplab

package action

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

// Only the main session runs this gate. Credentials are read from the process
// environment and are never printed or written to disk.
func TestXDropV3Lab(t *testing.T) {
	logger := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(logger) })
	baseURL, key := strings.TrimRight(os.Getenv("XDROP_V3_BASE_URL"), "/"), os.Getenv("XDROP_V3_API_KEY")
	if baseURL == "" || key == "" {
		t.Fatal("lab environment required")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	request := func(method, path string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(context.Background(), method, baseURL+path, nil)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid lab request")
		}
		SetXDropAuth(req, key)
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, fmt.Errorf("lab transport failed")
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return resp.StatusCode, body, err
	}
	page := func(limit int) (int, error) {
		count := 0
		after := ""
		seen := map[string]bool{}
		for {
			path := "/rules?q=" + url.QueryEscape("198.51.100.192/26") + "&limit=" + fmt.Sprint(limit)
			if after != "" {
				path += "&after=" + url.QueryEscape(after)
			}
			status, body, err := request("GET", path)
			if err != nil || status != 200 {
				return 0, fmt.Errorf("lab rule query failed: HTTP %d", status)
			}
			var result struct {
				Items     []json.RawMessage `json:"items"`
				NextAfter *json.Number      `json:"next_after"`
			}
			if json.Unmarshal(body, &result) != nil {
				return 0, fmt.Errorf("invalid lab rule page")
			}
			count += len(result.Items)
			if result.NextAfter == nil {
				return count, nil
			}
			after = result.NextAfter.String()
			if seen[after] {
				return 0, fmt.Errorf("lab pagination did not advance")
			}
			seen[after] = true
		}
	}
	if count, err := page(1000); err != nil {
		t.Fatal(err)
	} else if count != 0 {
		t.Fatal("环境冲突，需人工确认")
	}
	base := 900000000 + int(time.Now().Unix()%10000000)*10
	type claim struct {
		id             string
		attack, action int
	}
	var claims []claim
	t.Cleanup(func() {
		for _, c := range claims {
			status, _, err := request("DELETE", "/rules/"+url.PathEscape(c.id)+"?claim_ref="+url.QueryEscape(xdropClaimRef(c.attack, c.action)))
			if err != nil || status != 204 {
				t.Errorf("lab claim cleanup failed: HTTP %d", status)
			}
		}
		if count, err := page(1000); err != nil {
			t.Error(err)
		} else if count != 0 {
			t.Errorf("lab residual rules: %d", count)
		}
	})
	newStore := func() *v3Store { s := newV3Store(baseURL); s.conn.APIKey = key; s.conn.TimeoutMs = 10000; return s }
	create := func(t *testing.T, s *v3Store, a *store.Attack, act store.ResponseAction, fa *FlowAnalysis) string {
		t.Helper()
		s.actions = append(s.actions, act)
		before := len(s.logSnapshot())
		log, err := executeXDrop(context.Background(), s, act, a, "confirmed", a.DstIP, "v3-lab", "on_detected", a.ID, fa, nil)
		if log != nil {
			_, _ = s.ActionExecLog().Create(context.Background(), log)
		}
		logs := s.logSnapshot()
		if len(logs) <= before {
			t.Fatal("lab create missing log")
		}
		last := logs[len(logs)-1]
		if err != nil || last.Status != "success" || last.ExternalRuleID == "" {
			t.Fatal("lab create failed")
		}
		claims = append(claims, claim{last.ExternalRuleID, a.ID, act.ID})
		return last.ExternalRuleID
	}
	exists := func(t *testing.T, id string, want bool) {
		t.Helper()
		status, _, err := request("GET", "/rules/"+url.PathEscape(id))
		expected := 404
		if want {
			expected = 200
		}
		if err != nil || status != expected {
			t.Fatalf("lab rule presence: HTTP %d want %d", status, expected)
		}
	}
	manual := func(t *testing.T, s *v3Store, attack, action int, id string) {
		t.Helper()
		if NewEngine(s, "auto").ForceRemove(context.Background(), attack, action, s.conn.ID, id) != nil {
			t.Fatal("lab manual release failed")
		}
	}
	unblock := func(t *testing.T, s *v3Store, a *store.Attack) {
		t.Helper()
		act := v3Action(99, "")
		act.XDropAction, act.TriggerPhase = "unblock", "on_expired"
		l, err := executeXDrop(context.Background(), s, act, a, "expired", a.DstIP, "v3-lab", "on_expired", a.ID, nil, nil)
		if err != nil || l != nil {
			t.Fatal("lab immediate release failed")
		}
	}
	t.Run("pagination_device", func(t *testing.T) {
		s := newStore()
		one := create(t, s, v3Attack(base, "udp", "198.51.100.253"), v3Action(9001, ""), nil)
		two := create(t, s, v3Attack(base, "udp", "198.51.100.254"), v3Action(9002, ""), nil)
		if count, err := page(1); err != nil || count != 2 {
			t.Fatalf("lab pagination count=%d error=%v", count, err)
		}
		manual(t, s, base, 9001, one)
		manual(t, s, base, 9002, two)
		if count, err := page(1); err != nil || count != 0 {
			t.Fatalf("lab pagination cleanup count=%d error=%v", count, err)
		}
	})
	for i, dec := range []string{"tcp_syn", "udp", "gre", "bad_fragment", "fragment"} {
		t.Run("C1/"+dec, func(t *testing.T) {
			s := newStore()
			act := v3Action(11+i, "")
			if dec == "bad_fragment" {
				act.XDropAction = "rate_limit"
				act.XDropCustomPayload = json.RawMessage(`{"dst_ip":"{dst_ip}","action":"rate_limit","rate_limit":5000}`)
			}
			a := v3Attack(base+1, dec, fmt.Sprintf("198.51.100.%d", 193+i))
			id := create(t, s, a, act, nil)
			exists(t, id, true)
			manual(t, s, a.ID, act.ID, id)
		})
	}
	t.Run("C3_source_host", func(t *testing.T) {
		s := newStore()
		a := v3Attack(base+2, "udp", "198.51.100.192/26")
		act := v3Action(21, v3WebPayload)
		id := create(t, s, a, act, &FlowAnalysis{TopSrcIPs: []string{"192.0.2.10"}, TopSrcIPPct: 100, SamplePackets: 1000})
		status, body, err := request("GET", "/rules/"+url.PathEscape(id))
		if err != nil || status != 200 {
			t.Fatal("lab C3 get failed")
		}
		var rule map[string]any
		if json.Unmarshal(body, &rule) != nil || rule["dst_cidr"] != "198.51.100.192/26" || rule["src_cidr"] != "192.0.2.10/32" {
			t.Fatal("lab C3 address constraints differ")
		}
		manual(t, s, a.ID, act.ID, id)
	})
	t.Run("C4_two_attacks", func(t *testing.T) {
		s := newStore()
		act := v3Action(31, "")
		a, b := v3Attack(base+3, "udp", "198.51.100.199"), v3Attack(base+4, "udp", "198.51.100.199")
		one, two := create(t, s, a, act, nil), create(t, s, b, act, nil)
		if one != two {
			t.Fatal("lab identity not shared")
		}
		unblock(t, s, a)
		exists(t, one, true)
		unblock(t, s, b)
		exists(t, one, false)
	})
	t.Run("C4_two_actions", func(t *testing.T) {
		s := newStore()
		a := v3Attack(base+5, "udp", "198.51.100.200")
		one := create(t, s, a, v3Action(41, ""), nil)
		two := create(t, s, a, v3Action(42, ""), nil)
		if one != two {
			t.Fatal("lab identity not shared")
		}
		unblock(t, s, a)
		exists(t, one, false)
		for _, action := range []int{41, 42} {
			if s.state(a.ID, action, one) != "withdrawn" {
				t.Fatal("lab source action not withdrawn")
			}
		}
	})
	t.Run("C5_immediate", func(t *testing.T) {
		s := newStore()
		a := v3Attack(base+6, "udp", "198.51.100.201")
		id := create(t, s, a, v3Action(51, ""), nil)
		unblock(t, s, a)
		exists(t, id, false)
	})
	t.Run("C5_manual", func(t *testing.T) {
		s := newStore()
		a := v3Attack(base+7, "udp", "198.51.100.202")
		id := create(t, s, a, v3Action(61, ""), nil)
		manual(t, s, a.ID, 61, id)
		exists(t, id, false)
	})
	t.Run("C12_delivery", func(t *testing.T) {
		s := newStore()
		a := v3Attack(base+8, "udp", "198.51.100.203")
		id := create(t, s, a, v3Action(71, ""), nil)
		result, err := QueryXDropDelivery(context.Background(), s.conn, id)
		if err != nil || result == nil || result.RuleID != id || result.Epoch == "" {
			t.Fatal("lab delivery failed")
		}
		manual(t, s, a.ID, 71, id)
		result, err = QueryXDropDelivery(context.Background(), s.conn, id)
		if err != nil || result != nil {
			t.Fatal("lab absent delivery failed")
		}
	})
}
