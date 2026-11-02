package action

import "testing"

func TestEffectiveMinSamples(t *testing.T) {
	defer func() {
		SetXDropAdaptiveSamples(false)
		SetXDropShapeConfig(80, 1000)
	}()

	SetXDropShapeConfig(80, 1000)
	SetXDropAdaptiveSamples(false)
	if got := effectiveMinSamples(99); got != 1000 {
		t.Fatalf("disabled: got %d, want 1000", got)
	}

	SetXDropAdaptiveSamples(true)
	if got := effectiveMinSamples(89); got != 1000 {
		t.Fatalf("89%%: got %d, want 1000", got)
	}
	if got := effectiveMinSamples(90); got != 100 {
		t.Fatalf("90%%: got %d, want 100", got)
	}
	if got := effectiveMinSamples(95); got != 50 {
		t.Fatalf("95%%: got %d, want 50", got)
	}

	SetXDropShapeConfig(80, 0)
	if got := effectiveMinSamples(99); got != 0 {
		t.Fatalf("base 0 must disable the floor: got %d", got)
	}

	SetXDropShapeConfig(80, 10)
	if got := effectiveMinSamples(95); got != 10 {
		t.Fatalf("adaptive must never tighten: got %d, want 10", got)
	}
}
