package config

import "testing"

func TestDao7yi_R1_DefaultRingEstimate(t *testing.T) {
	cfg, err := Load(writeConfig(t, baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	if got := RingEstimateBytes(cfg); got != 100000*120*480 {
		t.Errorf("default estimate=%d want=%d", got, int64(100000*120*480))
	}
}
func TestDao7yi_R2_NewEstimateDoesNotReject(t *testing.T) {
	cfg := &Config{Database: DatabaseConfig{Driver: "postgres", DSN: "test-only"}, Auth: AuthConfig{APIKey: "dao7-test-key"}, Action: ActionConfig{Mode: "observe"}, Detection: DetectionConfig{ExpiryFunction: "static"}, Ring: RingConfig{MaxGlobalKeys: 200000, MaxPointsPerIP: 120, MaxIPsPerPrefix: 10000}}
	if RingEstimateBytes(cfg) <= 8*1024*1024*1024 {
		t.Fatal("new estimate must exceed 8 GiB")
	}
	if old := int64(cfg.Ring.MaxGlobalKeys) * int64(cfg.Ring.MaxPointsPerIP) * 80; old > 8*1024*1024*1024 {
		t.Fatal("old estimate must fit")
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("warning-only config rejected: %v", err)
	}
}
func TestDao7yi_R3_LegacyRejectionUnchanged(t *testing.T) {
	TestRingEstimatedMemoryExceeds8GB(t)
}
