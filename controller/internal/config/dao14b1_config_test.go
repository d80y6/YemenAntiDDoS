package config

import (
	"strings"
	"testing"
)

func TestDao14b1V04_C1(t *testing.T) {
	for _, tc := range []struct {
		name, y string
		reject  bool
	}{
		{"hard12_pts10", baseYAML + "detection:\n  hard_threshold_confirm_seconds: 12\nring:\n  max_points_per_ip: 10\n", true},
		{"dyn11_pts10", baseYAML + "detection:\n  dynamic_threshold_confirm_seconds: 11\nring:\n  max_points_per_ip: 10\n", true},
		{"both10_pts10", baseYAML + "detection:\n  hard_threshold_confirm_seconds: 10\n  dynamic_threshold_confirm_seconds: 10\nring:\n  max_points_per_ip: 10\n", false},
		{"negative", baseYAML + "detection:\n  hard_threshold_confirm_seconds: -3\n  dynamic_threshold_confirm_seconds: 0\nring:\n  max_points_per_ip: 10\n", false},
		{"default", baseYAML, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.y))
			if tc.reject != (err != nil) || (err != nil && !strings.Contains(err.Error(), "max_points_per_ip")) {
				t.Errorf("err=%v reject=%v", err, tc.reject)
			}
		})
	}
}
