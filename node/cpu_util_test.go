//go:build linux

package main

import (
	"math"
	"testing"
)

const procStatSample = `cpu  100 0 100 800 0 0 0 0 0 0
cpu0 50 0 50 400 0 0 0 0 0 0
cpu1 50 0 50 400 0 0 0 0 0 0
intr 12345 0 0
`

func TestParseCPUTimesSkipsAggregate(t *testing.T) {
	got := parseCPUTimes(procStatSample)
	if len(got) != 2 {
		t.Fatalf("parseCPUTimes = %d cores, want 2 (aggregate line skipped)", len(got))
	}
	// cpu0: total=50+50+400=500, idle=400.
	if got[0].total != 500 || got[0].idle != 400 {
		t.Fatalf("cpu0 = %+v, want total=500 idle=400", got[0])
	}
}

func TestCPUUtilPercent(t *testing.T) {
	prev := parseCPUTimes(procStatSample)
	cur := parseCPUTimes(`cpu  200 0 100 1000 0 0 0 0 0 0
cpu0 100 0 50 450 0 0 0 0 0 0
cpu1 100 0 50 450 0 0 0 0 0 0
intr 1 0 0
`)
	got := cpuUtilPercent(prev, cur)
	if len(got) != 2 {
		t.Fatalf("cpuUtilPercent returned %d cores, want 2", len(got))
	}
	// cpu0 delta: total=100, idle=50 -> 50% busy.
	if math.Abs(got[0]-50) > 0.001 {
		t.Fatalf("cpu0 util = %v, want 50", got[0])
	}
	// A zero delta must not divide by zero.
	flat := cpuUtilPercent(prev, prev)
	if len(flat) != 2 || flat[0] != 0 {
		t.Fatalf("flat util = %v, want zeroes", flat)
	}
}
