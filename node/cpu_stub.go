//go:build !linux

package main

// applyCPUPins is a no-op off Linux; xsight-node requires Linux for XDP.
func applyCPUPins(cores []int) error { return nil }

// cpuTimes is one core's cumulative jiffies.
type cpuTimes struct {
	total uint64
	idle  uint64
}

// readCPUTimes is unavailable off Linux.
func readCPUTimes() ([]cpuTimes, error) { return nil, nil }

// cpuUtilPercent returns per-core busy percentages between two samples.
func cpuUtilPercent(prev, cur []cpuTimes) []float64 { return nil }
