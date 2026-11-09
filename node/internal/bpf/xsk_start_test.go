//go:build linux

package bpf

import (
	"testing"

	"golang.org/x/sys/unix"
)

// StartXSK must publish the manager before OpenXSK registers the socket in the
// XSKMAP; otherwise registerIntoXSKMap sees globalXSKManager == nil.
func TestStartXSKInstallsManagerBeforeOpen(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer unix.Close(fds[1])

	old := openXSKFn
	defer func() { openXSKFn = old }()

	var seen *XSKManager
	openXSKFn = func(string, uint32, uint32, uint32, bool) (*XSK, error) {
		seen = globalXSKManager
		return &XSK{fd: fds[0]}, nil
	}

	mgr, err := StartXSK(nil, "test0", 7, 0, 0, false, nil)
	if err != nil {
		t.Fatalf("StartXSK: %v", err)
	}
	if seen == nil {
		t.Fatal("globalXSKManager was nil during OpenXSK; socket cannot register in XSKMAP")
	}
	if seen != mgr {
		t.Fatalf("manager installed during OpenXSK = %p, want %p", seen, mgr)
	}
	if globalXSKManager != mgr {
		globalXSKMu.Lock()
		got := globalXSKManager
		globalXSKMu.Unlock()
		t.Fatalf("globalXSKManager after start = %p, want %p", got, mgr)
	}

	mgr.Close()
	globalXSKMu.Lock()
	got := globalXSKManager
	globalXSKMu.Unlock()
	if got != nil {
		t.Fatalf("globalXSKManager after Close = %p, want nil", got)
	}
}
