package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDao13b_C(t *testing.T) {
	for _, tc := range []struct {
		name, password string
		valid          bool
	}{
		{"DefaultRejected", "admin", false},
		{"SevenRejected", "1234567", false},
		{"Absent", "", true},
		{"LegalAccepted", " initial-pass ", true},
		{"LengthBounds/Eight", strings.Repeat("a", 8), true},
		{"LengthBounds/SeventyTwo", strings.Repeat("a", 72), true},
		{"LengthBounds/SeventyThree", strings.Repeat("a", 73), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := baseYAML
			if tc.password != "" {
				yaml += fmt.Sprintf("  initial_admin_password: %q\n", tc.password)
			}
			path := filepath.Join(t.TempDir(), "dao13b.yaml")
			if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if (err == nil) != tc.valid {
				t.Fatalf("Load error=%v; want accepted=%v", err, tc.valid)
			}
			if tc.valid && cfg.Auth.InitialAdminPassword != tc.password {
				t.Fatalf("password changed during Load: got %q want %q", cfg.Auth.InitialAdminPassword, tc.password)
			}
		})
	}
}
