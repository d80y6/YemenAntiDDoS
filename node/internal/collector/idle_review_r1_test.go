package collector

import "testing"

// Read the shipping default without passing through the fixture that sets it to 3.
func TestDao7jia_R2_DefaultIdleThreshold(t *testing.T) {
	if ipIdleTicks != 300 {
		t.Fatalf("shipping idle threshold=%d, want 300 successful ticks", ipIdleTicks)
	}
}
