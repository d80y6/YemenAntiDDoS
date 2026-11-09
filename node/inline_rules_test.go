//go:build linux

package main

import (
	"net"
	"testing"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
	"github.com/d80y6/YemenDDoS/node/internal/pb"
)

func testRulesApplier(t *testing.T) (*inlineRulesApplier, *bpf.Manager) {
	t.Helper()
	mgr := testInlineManager(t)
	if err := mgr.SetCookieSecret(1, 2); err != nil {
		t.Fatalf("install cookie secret: %v", err)
	}
	return &inlineRulesApplier{sink: mgr}, mgr
}

func TestInlineRulesApplier_TriStateCookieSwitch(t *testing.T) {
	a, mgr := testRulesApplier(t)
	if err := mgr.SetSynCookieEnabled(true); err != nil {
		t.Fatal(err)
	}

	// A rules-only push has no cookie intent (plain bool false + no targets)
	// and must not disable a switch the node already enabled.
	if err := a.apply(&pb.InlineRuleSet{Version: 1, DefaultAction: "pass"}); err != nil {
		t.Fatal(err)
	}
	if v, err := mgr.ConfigValue(bpf.CfgSynCookieEnable); err != nil || v != 1 {
		t.Fatalf("rules-only push changed CFG_SYN_COOKIE_ENABLE to %d (err=%v), want 1", v, err)
	}

	// Naming protected targets carries intent and turns the switch back on.
	if err := mgr.SetSynCookieEnabled(false); err != nil {
		t.Fatal(err)
	}
	if err := a.apply(&pb.InlineRuleSet{
		Version:       2,
		CookieTargets: []string{"203.0.113.0/24"},
	}); err != nil {
		t.Fatal(err)
	}
	if v, err := mgr.ConfigValue(bpf.CfgSynCookieEnable); err != nil || v != 1 {
		t.Fatalf("cookie_targets did not enable the switch (got %d, err=%v)", v, err)
	}

	// An explicit enable flag also carries intent.
	if err := mgr.SetSynCookieEnabled(false); err != nil {
		t.Fatal(err)
	}
	if err := a.apply(&pb.InlineRuleSet{Version: 3, SynCookieEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if v, err := mgr.ConfigValue(bpf.CfgSynCookieEnable); err != nil || v != 1 {
		t.Fatalf("syn_cookie_enabled=true did not enable the switch (got %d, err=%v)", v, err)
	}
}

func TestInlineRulesApplier_RejectsStaleVersion(t *testing.T) {
	a, mgr := testRulesApplier(t)
	rule := &pb.InlineRule{
		Id: 7, DstIp: net.IPv4(192, 0, 2, 1).To4(),
		Protocol: 6, DstPort: 443, Action: "drop", Priority: 10,
	}
	if err := a.apply(&pb.InlineRuleSet{
		Version: 5, Rules: []*pb.InlineRule{rule}, DefaultAction: "pass",
	}); err != nil {
		t.Fatal(err)
	}
	before := mgr.InlineCounters().ActiveFilterRules
	if before != 1 {
		t.Fatalf("ActiveFilterRules = %d after v5, want 1", before)
	}

	// v4 is older than the applied v5: reject without touching the tables.
	if err := a.apply(&pb.InlineRuleSet{Version: 4, DefaultAction: "pass"}); err == nil {
		t.Fatal("stale v4 rule set was accepted after v5")
	}
	if after := mgr.InlineCounters().ActiveFilterRules; after != before {
		t.Fatalf("stale push mutated rules: %d -> %d", before, after)
	}

	// Re-applying the current version is idempotent and must succeed.
	if err := a.apply(&pb.InlineRuleSet{
		Version: 5, Rules: []*pb.InlineRule{rule}, DefaultAction: "pass",
	}); err != nil {
		t.Fatalf("equal version re-apply: %v", err)
	}
}

func TestInlineRulesApplier_AcceptsFreshControllerEpoch(t *testing.T) {
	a, mgr := testRulesApplier(t)
	rule := &pb.InlineRule{
		Id: 3, DstIp: net.IPv4(192, 0, 2, 3).To4(),
		Protocol: 6, DstPort: 443, Action: "drop", Priority: 10,
	}
	if err := a.apply(&pb.InlineRuleSet{Version: 5, Rules: []*pb.InlineRule{rule}}); err != nil {
		t.Fatal(err)
	}
	// A restarted controller numbers its first push v1 again; the node must
	// adopt the new epoch instead of rejecting every push until v5.
	if err := a.apply(&pb.InlineRuleSet{Version: 1}); err != nil {
		t.Fatalf("fresh controller epoch v1 rejected: %v", err)
	}
	if got := mgr.InlineCounters().ActiveFilterRules; got != 0 {
		t.Fatalf("ActiveFilterRules = %d after epoch reset, want 0", got)
	}
}

func TestInlineRulesApplier_PlumbsDefaultActionAndCookieTargets(t *testing.T) {
	a, mgr := testRulesApplier(t)
	rule := &pb.InlineRule{
		Id: 9, DstIp: net.IPv4(192, 0, 2, 2).To4(),
		Protocol: 6, DstPort: 443, Action: "drop", Priority: 10,
	}
	if err := a.apply(&pb.InlineRuleSet{
		Version:       1,
		Rules:         []*pb.InlineRule{rule},
		DefaultAction: "drop",
		CookieTargets: []string{"203.0.113.0/24"},
	}); err != nil {
		t.Fatal(err)
	}

	var key bpf.FilterRuleKey
	var val bpf.FilterRule
	if err := mgr.Objs.ActiveFilterRules.Lookup(&key, &val); err != nil {
		t.Fatalf("default_action=drop did not install the catch-all: %v", err)
	}
	if val.Action != bpf.FilterActionDrop {
		t.Fatalf("catch-all action = %d, want FILTER_ACTION_DROP (%d)", val.Action, bpf.FilterActionDrop)
	}

	// LPM lookups probe with a full-length key, as the data plane does.
	var sk bpf.LPMKey
	sk.Prefixlen = 32
	copy(sk.Addr[:4], net.IPv4(203, 0, 113, 7).To4())
	var sv bpf.FilterRule
	if err := mgr.Objs.ActiveFilterSubnetsDst.Lookup(&sk, &sv); err != nil {
		t.Fatalf("cookie target rule missing from subnet table: %v", err)
	}
	if sv.Action != bpf.FilterActionSynCookie {
		t.Fatalf("cookie target action = %d, want FILTER_ACTION_SYN_COOKIE (%d)",
			sv.Action, bpf.FilterActionSynCookie)
	}
	var miss bpf.LPMKey
	miss.Prefixlen = 32
	copy(miss.Addr[:4], net.IPv4(203, 0, 114, 7).To4())
	var mv bpf.FilterRule
	if err := mgr.Objs.ActiveFilterSubnetsDst.Lookup(&miss, &mv); err == nil {
		t.Fatal("cookie target rule matched outside 203.0.113.0/24")
	}
}

func TestCookieTargetSpecsDedupesExistingRules(t *testing.T) {
	existing := []bpf.InlineRuleSpec{{
		ID: 1, DstIP: "203.0.113.0", DstPrefixLen: 24, Protocol: 6, Action: "syn_cookie",
	}}
	if got := cookieTargetSpecs([]string{"203.0.113.0/24"}, existing); len(got) != 0 {
		t.Fatalf("duplicate cookie target produced %d extra rules, want 0", len(got))
	}
	got := cookieTargetSpecs([]string{"203.0.113.0/24", "bad-cidr"}, nil)
	if len(got) != 1 {
		t.Fatalf("cookieTargetSpecs = %d rules, want 1 (bad CIDR skipped)", len(got))
	}
	if got[0].Action != "syn_cookie" || got[0].Protocol != 6 || got[0].DstPrefixLen != 24 {
		t.Fatalf("cookie target spec = %+v", got[0])
	}
}

type recordingRuleSink struct {
	defaultActions []string
	cookieCalls    []bool
}

func (r *recordingRuleSink) ApplyInlineRules(_ []bpf.InlineRuleSpec, defaultAction string) error {
	r.defaultActions = append(r.defaultActions, defaultAction)
	return nil
}

func (r *recordingRuleSink) SetSynCookieEnabled(on bool) error {
	r.cookieCalls = append(r.cookieCalls, on)
	return nil
}

func TestInlineRulesApplier_PreservesDefaultActionWhenEmpty(t *testing.T) {
	r := &recordingRuleSink{}
	a := &inlineRulesApplier{sink: r}
	if err := a.apply(&pb.InlineRuleSet{Version: 1, DefaultAction: "drop"}); err != nil {
		t.Fatal(err)
	}
	// proto3 cannot distinguish an empty default_action from "unset", so a
	// partial push must not silently reset the drop policy to pass.
	if err := a.apply(&pb.InlineRuleSet{Version: 2}); err != nil {
		t.Fatal(err)
	}
	if len(r.defaultActions) != 2 ||
		r.defaultActions[0] != "drop" || r.defaultActions[1] != "drop" {
		t.Fatalf("default actions = %v, want [drop drop]", r.defaultActions)
	}
}
