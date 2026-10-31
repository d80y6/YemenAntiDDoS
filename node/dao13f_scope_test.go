package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func dao13fAllowed(path string) bool {
	// The lab copies this exact generated header before make generate.
	if path == "node/bpf/vmlinux.h" {
		return true
	}
	switch path {
	case "node/main.go", "node/config.example.yaml",
		"node/internal/config/config.go", "node/internal/collector/collector.go",
		"node/internal/reporter/reporter.go", "node/internal/sampler/packet.go",
		"node/internal/sampler/worker_pool.go",
		"node/README.md", "node/README.zh.md", "node/API.md", "node/API.zh.md",
		"docs/architecture.md", "docs/architecture.zh.md", "docs/user-guide.md", "docs/user-guide.zh.md":
		return true
	}
	name := filepath.Base(path)
	switch filepath.Dir(path) {
	case "node", "node/internal/config", "node/internal/collector", "node/internal/reporter", "node/internal/sampler":
		return strings.HasPrefix(name, "dao13f_") && strings.HasSuffix(name, "_test.go")
	}
	return false
}

func TestDao13f_S3(t *testing.T) {
	t.Run("GeneratedHeaderExceptionIsExact", func(t *testing.T) {
		for _, path := range []string{
			"node/bpf/vmlinux.h",
			"node/bpf/other.h",
			"node/bpf/vmlinux.h.tmp",
			"node/bpf/nested/vmlinux.h",
			"vmlinux.h",
			"unexpected.txt",
		} {
			want := path == "node/bpf/vmlinux.h"
			if got := dao13fAllowed(path); got != want {
				t.Errorf("scope allowance for %q=%v, want %v", path, got, want)
			}
		}
	})
	t.Run("ChangedFilesWhitelist", func(t *testing.T) {
		var data []byte
		var err error
		if manifest := os.Getenv("DAO13F_CHANGED_FILES"); manifest != "" {
			// An archive has no Git metadata. Its manifest is produced by
			// comparing actual files with the independently exported baseline.
			data, err = os.ReadFile(manifest)
		} else {
			// The whitelist describes this change set against its implementation
			// base. Once later commits land on top, the diff is no longer this
			// change set alone, so the check only applies on the base itself.
			head := exec.Command("git", "rev-parse", "HEAD")
			head.Dir = dao13fRoot(t)
			out, headErr := head.Output()
			if headErr != nil {
				t.Skipf("no git metadata (%v); whitelist applies only on implementation base cb4cefa", headErr)
			}
			if strings.TrimSpace(string(out)) != "cb4cefa402585b82387f4086f53c3a677fd6da43" {
				t.Skipf("HEAD %s is not the implementation base; scope whitelist applies to the delivery tree only", strings.TrimSpace(string(out)))
			}
			cmd := exec.Command("git", "diff", "--name-only", "cb4cefa402585b82387f4086f53c3a677fd6da43")
			cmd.Dir = dao13fRoot(t)
			data, err = cmd.Output()
			if err == nil {
				cmd = exec.Command("git", "ls-files", "--others", "--exclude-standard")
				cmd.Dir = dao13fRoot(t)
				var untracked []byte
				untracked, err = cmd.Output()
				data = append(data, untracked...)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range strings.Fields(string(data)) {
			if !dao13fAllowed(path) {
				t.Errorf("changed file outside the allowed file set: %s", path)
			}
		}
	})
}
