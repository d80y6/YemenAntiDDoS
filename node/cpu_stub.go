//go:build !linux

package main

// applyCPUPins is a no-op off Linux; xsight-node requires Linux for XDP.
func applyCPUPins(cores []int) error { return nil }
