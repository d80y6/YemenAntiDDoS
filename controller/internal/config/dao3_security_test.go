package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dao3Config(key string) *Config {
	c := &Config{}
	c.Database.DSN = "test"
	c.Database.Driver = "postgres"
	c.Action.Mode = "auto"
	c.Detection.ExpiryFunction = "static"
	c.Auth.APIKey = key
	c.Ring.MaxPointsPerIP = 120
	c.Ring.MaxIPsPerPrefix = 1000
	c.Ring.MaxGlobalKeys = 1000
	return c
}
func TestDao3_T3a_DefaultKeyRejected(t *testing.T) {
	for _, key := range []string{"", "CHANGE_ME"} {
		t.Run(map[bool]string{true: "empty", false: "CHANGE_ME"}[key == ""], func(t *testing.T) {
			err := dao3Config(key).validate()
			if err == nil || !strings.Contains(err.Error(), "CHANGE_ME") {
				t.Fatalf("validate error=%v; want default-key rejection mentioning CHANGE_ME", err)
			}
		})
	}
	for _, tc := range []struct{ name, key string }{
		{"space", " "}, {"control_whitespace", "\t\r\n"}, {"unicode_space", "\u2003"}, {"padded_default", " CHANGE_ME "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dao3LoadConfig(t, tc.key)
			if err == nil || !strings.Contains(err.Error(), "CHANGE_ME") {
				t.Fatalf("Load error=%v; want default-key rejection mentioning CHANGE_ME", err)
			}
		})
	}
}
func TestDao3_T3b_UniqueKeyAllowed(t *testing.T) {
	if err := dao3Config("unique-test-key").validate(); err != nil {
		t.Fatalf("unique key rejected: %v", err)
	}
	t.Run("internal_space_original_preserved", func(t *testing.T) {
		key := "  unique test key  "
		cfg, err := dao3LoadConfig(t, key)
		if err != nil {
			t.Fatalf("valid key rejected: %v", err)
		}
		if cfg.Auth.APIKey != key {
			t.Fatalf("Load rewrote key: got %q want %q", cfg.Auth.APIKey, key)
		}
	})
}

func dao3LoadConfig(t *testing.T, key string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dao3-load-input.yml")
	body := fmt.Sprintf("database:\n  dsn: unused\nauth:\n  api_key: %q\n", key)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}
