//go:build linux

package main

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
	"github.com/d80y6/YemenDDoS/node/internal/config"
)

func testInlineManager(t *testing.T) *bpf.Manager {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("inline setup gates require root; run under sudo")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	mgr, err := bpf.Load("", 0)
	if err != nil {
		t.Fatalf("load BPF: %v", err)
	}
	t.Cleanup(mgr.Close)
	return mgr
}

func TestSetupInlineEngineEnablesAlerts(t *testing.T) {
	mgr := testInlineManager(t)
	cfg := &config.Config{}
	cfg.Inline.Enabled = true
	if _, err := setupInlineEngine(cfg, mgr, "lo"); err != nil {
		t.Fatalf("setupInlineEngine: %v", err)
	}
	v, err := mgr.ConfigValue(bpf.CfgAlertsEnable)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Fatalf("CFG_ALERTS_ENABLE = %d, want 1 after inline setup", v)
	}
}

func TestSetupInlineEngineInstallsCookieSecret(t *testing.T) {
	mgr := testInlineManager(t)
	cfg := &config.Config{}
	cfg.Inline.Enabled = true
	cfg.Inline.SynCookie = true
	if _, err := setupInlineEngine(cfg, mgr, "lo"); err != nil {
		t.Fatalf("setupInlineEngine: %v", err)
	}
	lo, hi, err := mgr.CookieSecret()
	if err != nil {
		t.Fatal(err)
	}
	if lo == 0 && hi == 0 {
		t.Fatal("inline setup enabled cookies with an unset secret")
	}
	v, err := mgr.ConfigValue(bpf.CfgSynCookieEnable)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Fatalf("CFG_SYN_COOKIE_ENABLE = %d, want 1", v)
	}
}

func TestInlinePostureSnapshotBurstAlerts(t *testing.T) {
	mgr := testInlineManager(t)
	p := &inlinePosture{mgr: mgr, mode: "driver", enabled: true}
	p.burstAlerts.Store(7)
	got := p.snapshot()
	if got.GetBurstAlerts() != 7 {
		t.Fatalf("BurstAlerts = %d, want 7", got.GetBurstAlerts())
	}
	if got.GetXdpMode() != "driver" || !got.GetInlineEnabled() {
		t.Fatalf("posture metadata = %+v", got)
	}
}
