//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// applyCPUPins pins the whole node process (all goroutines) to the given
// cores. Hot-path threads are short-lived, so process-wide affinity is the
// practical knob for keeping XDP/AF_XDP work off management cores.
func applyCPUPins(cores []int) error {
	if len(cores) == 0 {
		return nil
	}
	var set unix.CPUSet
	set.Zero()
	for _, c := range cores {
		if c < 0 {
			continue
		}
		set.Set(c)
	}
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		return fmt.Errorf("sched_setaffinity %v: %w", cores, err)
	}
	log.Printf("perf: process pinned to cores %v", cores)
	return nil
}

// cpuTimes is one core's cumulative /proc/stat jiffies.
type cpuTimes struct {
	total uint64
	idle  uint64
}

// readCPUTimes samples per-core cumulative jiffies from /proc/stat.
func readCPUTimes() ([]cpuTimes, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil, err
	}
	return parseCPUTimes(string(data)), nil
}

// parseCPUTimes extracts per-core totals from /proc/stat content. The
// aggregate "cpu" line is skipped; guest time is excluded because the kernel
// already accounts it in user time.
func parseCPUTimes(s string) []cpuTimes {
	var out []cpuTimes
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
			continue
		}
		vals := make([]uint64, 0, len(f)-1)
		for _, x := range f[1:] {
			v, err := strconv.ParseUint(x, 10, 64)
			if err != nil {
				break
			}
			vals = append(vals, v)
		}
		if len(vals) < 4 {
			continue
		}
		var total uint64
		for i, v := range vals {
			if i >= 8 {
				break
			}
			total += v
		}
		idle := vals[3]
		if len(vals) > 4 {
			idle += vals[4] // iowait counts as idle
		}
		out = append(out, cpuTimes{total: total, idle: idle})
	}
	return out
}

// cpuUtilPercent returns per-core busy percentages between two samples.
func cpuUtilPercent(prev, cur []cpuTimes) []float64 {
	n := len(cur)
	if len(prev) < n {
		n = len(prev)
	}
	out := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		dt := cur[i].total - prev[i].total
		if dt == 0 {
			out = append(out, 0)
			continue
		}
		di := cur[i].idle - prev[i].idle
		if di > dt {
			di = dt
		}
		out = append(out, float64(dt-di)*100/float64(dt))
	}
	return out
}
