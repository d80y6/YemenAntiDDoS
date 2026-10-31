package config

import (
	"strings"
	"testing"
)

func TestDao14b2_C4(t *testing.T) {
	for _, tc := range []struct {
		name, yaml    string
		want          int
		explicit, bad bool
	}{
		{"DefaultFollowsExpiry", "detection: {expiry_interval_seconds: 120}", 120, false, false},
		{"DefaultNoDetection", "", 300, false, false},
		{"ExplicitZero", "detection: {manual_expire_hold_seconds: 0}", 0, true, false},
		{"Explicit86400", "detection: {manual_expire_hold_seconds: 86400}", 86400, true, false},
		{"Negative", "detection: {manual_expire_hold_seconds: -1}", 0, true, true},
		{"TooLarge", "detection: {manual_expire_hold_seconds: 86401}", 0, true, true},
		{"NonPositiveExpiryStillLoads", "detection: {expiry_interval_seconds: -5}", 0, false, false},
		{"DefaultCapped", "detection: {expiry_interval_seconds: 100000}", 86400, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, baseYAML+"\n"+tc.yaml+"\n"))
			if tc.bad {
				if err == nil || !strings.Contains(err.Error(), "detection.manual_expire_hold_seconds must be between 0 and 86400") {
					t.Fatalf("Load error=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Detection.ResolvedManualExpireHoldSeconds(); got != tc.want {
				t.Errorf("resolved=%d; want %d", got, tc.want)
			}
			if (cfg.Detection.ManualExpireHoldSeconds != nil) != tc.explicit {
				t.Errorf("configured pointer=%v; explicit=%v", cfg.Detection.ManualExpireHoldSeconds, tc.explicit)
			}
		})
	}
}
