package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func dao6Grep(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/grep", args...).CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
			t.Fatalf("grep %v: %v %s", args, err, out)
		}
	}
	return string(out)
}
func dao6MainSource() string {
	if path := os.Getenv("DAO6_STATIC_MAIN"); path != "" {
		return path
	}
	return "main.go"
}
func TestDao6_S2g_QueueWiring(t *testing.T) {
	p := dao6MainSource()
	for _, pattern := range []string{`tracker.New(.*actionEngine.Enqueue)`, `SetRebreachCallback(actionEngine.EnqueueRebreach)`, `tracker.New(`} {
		if got := strings.TrimSpace(dao6Grep(t, "-c", pattern, p)); got != "1" {
			t.Errorf("grep %q count=%s want 1", pattern, got)
		}
	}
	if got := dao6Grep(t, "-E", `(tracker.New\(.*HandleEvent|SetRebreachCallback\(.*CancelDelaysForAttack)`, p); got != "" {
		t.Errorf("legacy callback wiring: %s", got)
	}
}
func dao6ProductionFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (path == "console" || strings.HasPrefix(d.Name(), ".")) && path != "." {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
func TestDao6_S1g_TrackerCallerFiles(t *testing.T) {
	// Full method-name set captured from the anchored HEAD; authorization #1
	// corrects the PLAN's GetActive typo to ActiveTimers.
	pattern := `\.(SetRebreachCallback|Feed|ForceExpire|NotifyExpired|ActiveTimers|UpgradeType|RecoverFromDB|ActiveDstIPs|ActiveCount|tick|transitionToActive|transitionToExpired|countActive|findLowestActive|lowestActivePPS|evictAttack)\(`
	args := append([]string{"-l", "-E", pattern}, dao6ProductionFiles(t)...)
	got := strings.Fields(dao6Grep(t, args...))
	// v4.0 adds internal/tracker/fastpath.go as a deliberate tracker mutation
	// caller: the CriticalEventStream sub-second escalation path invokes
	// transitionToActive directly, bypassing the 1s confirmation window.
	want := []string{"internal/api/attacks.go", "internal/metrics/metrics.go", "internal/tracker/fastpath.go", "internal/tracker/tracker.go", "main.go"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tracker caller files=%v want HEAD set=%v", got, want)
	}
}
func TestDao6_S3g_BoundedShutdownNoProductionStop(t *testing.T) {
	p := dao6MainSource()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	tail := strings.SplitN(string(data), "grpcSrv.GracefulStop()", 2)
	if len(tail) != 2 || strings.Count(tail[1], "actionEngine.Drain(") != 1 {
		t.Error("want one Drain after GracefulStop")
	}
	args := append([]string{"-n", "-E", `\.stop\(`}, dao6ProductionFiles(t)...)
	if got := dao6Grep(t, args...); got != "" {
		t.Errorf("production stop call: %s", got)
	}
}

// G11: new callbacks with the same B13 DeepEqual oracle.
func TestDao4_B13_RecoveryCompletesBeforeReconciliation(t *testing.T) {
	var marks []string
	recoverOnStartup(context.Background(),
		func(context.Context) { marks = append(marks, "RecoverBGPRoutes enter", "RecoverBGPRoutes exit") },
		func(context.Context) { marks = append(marks, "PrepareStartupCleanup enter") },
		func(context.Context) { marks = append(marks, "ReconcileOnStartup enter") },
		func(context.Context) { marks = append(marks, "CleanupEndedAttachments enter") },
		func(context.Context) error { marks = append(marks, "RecoverFromDB enter"); return nil },
		func(context.Context) { marks = append(marks, "BootstrapBGPOrphans enter") })
	want := []string{"RecoverBGPRoutes enter", "RecoverBGPRoutes exit", "PrepareStartupCleanup enter", "ReconcileOnStartup enter", "CleanupEndedAttachments enter", "RecoverFromDB enter", "BootstrapBGPOrphans enter"}
	if !reflect.DeepEqual(marks, want) {
		t.Fatalf("startup marks=%v; want %v", marks, want)
	}
}
