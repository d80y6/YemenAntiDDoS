package threshold

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/engine"
	"github.com/d80y6/YemenDDoS/controller/internal/store/ring"
)

func TestDao12e_G2_R1(t *testing.T) { dao12eTickRace(t, "subnet", "receives") }
func TestDao12e_G2_R2(t *testing.T) { dao12eTickRace(t, "subnet", "sends") }
func TestDao12e_G2_R3(t *testing.T) { dao12eTickRace(t, "internal_ip", "receives") }
func TestDao12e_G2_R4(t *testing.T) { dao12eTickRace(t, "internal_ip", "sends") }

func dao12eTickRace(t *testing.T, domain, direction string) {
	t.Helper()
	const node, prefix = "dao12e", "192.0.2.0/24"
	rings := ring.New(ring.DefaultLimits())
	rules := []engine.ResolvedThreshold{{
		Decoder: "ip", Unit: "pps", Comparison: "over", Value: 1,
		Domain: domain, Direction: direction,
	}}
	var split splitResult
	push := func() {
		dp := ring.DataPoint{Time: time.Now(), PPS: 100}
		if domain == "subnet" {
			if direction == "receives" {
				rings.PushPrefix(node, prefix, dp)
			} else {
				rings.PushSrcPrefix(node, prefix, dp)
			}
		} else if direction == "receives" {
			rings.PushIP(node, prefix, net.ParseIP("192.0.2.1"), dp)
		} else {
			rings.PushSrcIP(node, prefix, net.ParseIP("192.0.2.1"), dp)
		}
	}
	if domain == "subnet" {
		if direction == "receives" {
			split.subnetRecv = rules
		} else {
			split.subnetSend = rules
		}
	} else if direction == "receives" {
		split.ipRecv = rules
	} else {
		split.ipSend = rules
	}
	tree := NewTree()
	tree.byPrefix = map[string][]engine.ResolvedThreshold{prefix: rules}
	tree.bySplit = map[string]splitResult{prefix: split}
	tree.allPrefixes = []string{prefix}
	detector := NewDetector(tree, rings)
	push()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Delay the write without creating a happens-before edge from the read.
		time.Sleep(50 * time.Millisecond)
		push()
	}()
	got := detector.Tick([]string{node})
	wg.Wait()
	t.Run("Hit", func(t *testing.T) {
		if len(got) != 1 {
			t.Fatalf("got %d breaches, want 1", len(got))
		}
		if got[0].Domain != domain || got[0].Direction != direction || got[0].Actual != 100 {
			t.Fatalf("breach = %+v, want domain=%s direction=%s actual=100", got[0], domain, direction)
		}
	})
}
