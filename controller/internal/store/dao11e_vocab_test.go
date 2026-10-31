package store

import "testing"

func TestDao11e_VocabularyPinned(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{"ActionTypeXDrop", ActionTypeXDrop, "xdrop"},
		{"ActionTypeBGP", ActionTypeBGP, "bgp"},
		{"ActionTypeWebhook", ActionTypeWebhook, "webhook"},
		{"ActionTypeShell", ActionTypeShell, "shell"},
		{"ActionTypeXDropAPI", ActionTypeXDropAPI, "xdrop_api"},
		{"TriggerPhaseOnDetected", TriggerPhaseOnDetected, "on_detected"},
		{"TriggerPhaseOnExpired", TriggerPhaseOnExpired, "on_expired"},
		{"RunModeOnce", RunModeOnce, "once"},
		{"RunModePeriodic", RunModePeriodic, "periodic"},
		{"RunModeRetryUntilSuccess", RunModeRetryUntilSuccess, "retry_until_success"},
		{"ExecutionAutomatic", ExecutionAutomatic, "automatic"},
		{"ExecutionManual", ExecutionManual, "manual"},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q: these values are stored in response_actions; changing one changes the meaning of persisted rows", tc.name, tc.got, tc.want)
		}
	}
}
