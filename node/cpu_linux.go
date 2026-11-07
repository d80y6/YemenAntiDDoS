//go:build linux

package main

import (
	"fmt"
	"log"

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
