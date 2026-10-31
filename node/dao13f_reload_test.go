package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDao13f_R2(t *testing.T) {
	t.Run("FailureDiagnostics", func(t *testing.T) {
		for _, applyFails := range []bool{false, true} {
			name := "Validation"
			if applyFails {
				name = "Apply"
			}
			t.Run(name, func(t *testing.T) {
				configText := "node_id: dao13f\nparse_workers: 1\ncontroller:\n  address: localhost:50051\nauth:\n  node_api_key: test-key\n"
				if applyFails {
					configText += "interfaces:\n  - name: test0\n    mode: mirror\n    sample_bytes: 256\n"
				} else {
					configText += "mode: flow\n"
				}
				path := filepath.Join(t.TempDir(), "reload.yaml")
				if err := os.WriteFile(path, []byte(configText), 0600); err != nil {
					t.Fatal(err)
				}
				applied, rate := false, uint32(7)
				cause := errors.New("injected slot 2 failure")
				err := reloadConfig(path, "mirror", func(string, uint32, uint32) error {
					applied = true
					return cause
				}, func(v uint32) { rate = v })
				if err == nil || applied != applyFails || rate != 7 {
					t.Fatalf("error=%v applied=%v rate=%d", err, applied, rate)
				}
				if errors.Is(err, errReloadApply) != applyFails || errors.Is(err, cause) != applyFails {
					t.Fatalf("reload error lost its stage or original cause: %v", err)
				}
				var output bytes.Buffer
				oldWriter := log.Writer()
				log.SetOutput(&output)
				t.Cleanup(func() { log.SetOutput(oldWriter) })
				logConfigReloadError(err)
				text := output.String()
				t.Log(strings.TrimSpace(text))
				if !strings.Contains(text, "Config reload failed:") {
					t.Fatalf("missing reload failure diagnostic: %s", text)
				}
				if applyFails {
					if strings.Contains(text, "keeping running config") ||
						!strings.Contains(text, "BPF may be partially updated; upstream rate unchanged") {
						t.Fatalf("apply failure diagnostic claims rollback: %s", text)
					}
				} else if !strings.Contains(text, "keeping running config") {
					t.Fatalf("validation rejection must retain running config: %s", text)
				}
			})
		}
	})
	for _, name := range []string{"RateAppliedAfterBPF", "ApplyFailKeepsRate", "FlowModeRejectedNoPanic", "HeteroRejected", "BadYAMLRejected", "ModeChangeRejected", "SameModeOtherFieldsApplied"} {
		t.Run(name, func(t *testing.T) {
			configText := "node_id: dao13f\nparse_workers: 1\ncontroller:\n  address: localhost:50051\nauth:\n  node_api_key: test-key\n"
			ifaces := "interfaces:\n  - name: test0\n    mode: mirror\n    sample_bytes: 256\n    upstream_sample_rate: 10\n"
			wantErr := ""
			switch name {
			case "FlowModeRejectedNoPanic":
				ifaces = "mode: flow\n"
				wantErr = "requires restart"
			case "HeteroRejected":
				ifaces += "  - name: test1\n    mode: erspan\n    sample_bytes: 256\n    upstream_sample_rate: 10\n"
				wantErr = "differs from interfaces[0]"
			case "BadYAMLRejected":
				ifaces = "interfaces: [\n"
				wantErr = "parse config"
			case "ModeChangeRejected":
				ifaces = strings.Replace(ifaces, "mode: mirror", "mode: erspan", 1)
				wantErr = "mode change requires restart"
			case "ApplyFailKeepsRate":
				wantErr = "injected apply failure"
			}
			path := filepath.Join(t.TempDir(), "reload.yaml")
			if err := os.WriteFile(path, []byte(configText+ifaces), 0600); err != nil {
				t.Fatal(err)
			}
			var calls []string
			rate := uint32(1)
			apply := func(mode string, sampleBytes, upstreamRate uint32) error {
				calls = append(calls, fmt.Sprintf("apply:%s:%d:%d", mode, sampleBytes, upstreamRate))
				if name == "ApplyFailKeepsRate" {
					return errors.New("injected apply failure")
				}
				return nil
			}
			set := func(v uint32) {
				calls = append(calls, fmt.Sprintf("set:%d", v))
				rate = v
			}
			err := reloadConfig(path, "mirror", apply, set)
			if wantErr == "" {
				if err != nil || rate != 10 || !reflect.DeepEqual(calls, []string{"apply:mirror:256:10", "set:10"}) {
					t.Fatalf("error=%v rate=%d calls=%v", err, rate, calls)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), wantErr) || rate != 1 {
					t.Fatalf("error=%v rate=%d, want error containing %q and unchanged rate", err, rate, wantErr)
				}
				var want []string
				if name == "ApplyFailKeepsRate" {
					want = []string{"apply:mirror:256:10"}
				}
				if !reflect.DeepEqual(calls, want) {
					t.Fatalf("calls=%v, want %v", calls, want)
				}
			}
		})
	}
}
