//go:build linux

package main

import (
	"net"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
)

func TestBurstAlertEventCarriesKernelTimestamp(t *testing.T) {
	now := time.Unix(1_700_000_000, 500_000_000)
	const nowMono = uint64(5_000_000_000)

	var a bpf.BurstAlert
	a.TimestampNS = nowMono - 2_000_000_000 // captured 2s ago in the kernel
	a.IsV4 = 1
	copy(a.DstAddr[:4], net.IPv4(192, 0, 2, 1).To4())
	a.WindowPPS = 12345
	a.Proto = 6
	a.TCPFlags = 0x02

	ev := burstAlertEvent("node-1", "eth0", a, now, nowMono)

	wantNS := now.Add(-2 * time.Second).UnixNano()
	if ev.GetTimestampNs() != wantNS {
		t.Fatalf("TimestampNs = %d, want %d (kernel capture time)", ev.GetTimestampNs(), wantNS)
	}
	if ev.GetTimestamp() != wantNS/int64(time.Second) {
		t.Fatalf("Timestamp = %d, want %d", ev.GetTimestamp(), wantNS/int64(time.Second))
	}
	if got := net.IP(ev.GetTargetIp()).String(); got != "192.0.2.1" {
		t.Fatalf("TargetIp = %s, want 192.0.2.1", got)
	}
	if ev.GetCurrentPps() != 12345 || ev.GetDecoder() != "tcp_syn" || ev.GetAttackType() != "syn_flood" {
		t.Fatalf("event metadata = %+v", ev)
	}
	if !ev.GetLocalMitigated() {
		t.Fatal("LocalMitigated = false, want true")
	}
	if ev.Counters["window_pps"] != 12345 || ev.Counters["emergency"] != 1 {
		t.Fatalf("counters = %v", ev.Counters)
	}
}

func TestAlertEventTimeFallbacks(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, ts := range []uint64{0, 5_000_000_001} {
		if got := alertEventTime(ts, now, 5_000_000_000); !got.Equal(now) {
			t.Fatalf("alertEventTime(%d) = %v, want now", ts, got)
		}
	}
}
