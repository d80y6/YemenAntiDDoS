//go:build linux

package bpf

import (
	"log"
	"strings"
	"testing"
)

// Observe the synchronous log at the end of the real HotSwap body, before its
// deferred unlock. No sleeps, goroutine timing, pins, or production hooks.
type dao7jiaR1LogProbe struct{ visit func() }

func (w dao7jiaR1LogProbe) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "hotswap: slot ") {
		w.visit()
	}
	return len(p), nil
}

func TestDao7jia_R1_HotSwapHoldsDeletionMutex(t *testing.T) {
	dao7jiaBoth(t, func(t *testing.T, src bool) {
		m, prefixes := dao7jiaLoad(t)
		dao8Positive(t, m, prefixes[0], "192.0.2.1", false, src)
		slot, seen, key := dao7jiaSeen(t, m, src)
		var called, skipped bool
		var deleted []LPMKey
		var probeErr error
		oldWriter := log.Writer()
		log.SetOutput(dao7jiaR1LogProbe{visit: func() {
			called = true
			deleted, skipped, probeErr = m.DeleteIdleStats(src, slot^1, []LPMKey{key}, seen)
		}})
		t.Cleanup(func() { log.SetOutput(oldWriter) })
		swapErr := m.HotSwap(prefixes)
		log.SetOutput(oldWriter)
		if swapErr != nil {
			t.Fatal(swapErr)
		}
		if !called {
			t.Fatal("HotSwap did not reach the synchronous completion probe")
		}
		if probeErr != nil || !skipped || len(deleted) != 0 {
			t.Fatalf("HotSwap did not exclude deletion: deleted=%v skipped=%t err=%v", deleted, skipped, probeErr)
		}
		var got DstIPStats
		if err := dao8IPMap(t, m, src).Lookup(&key, &got); err != nil || got != seen[key] {
			t.Fatalf("HotSwap/deletion probe lost the migrated key: got=%+v err=%v", got, err)
		}
	})
}
