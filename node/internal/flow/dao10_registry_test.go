package flow

import (
	"reflect"
	"testing"

	"github.com/d80y6/YemenDDoS/shared/decoder"
)

func TestDao10_K7_ExhaustiveDecoderCoverage(t *testing.T) {
	seen := map[string]bool{}
	maxHits := 0
	for protocol := 0; protocol < 256; protocol++ {
		for flags := 0; flags < 256; flags++ {
			indices, n := ProtocolToDecoders(uint8(protocol), uint8(flags))
			if n < 1 || n > MaxDecoderHits {
				t.Fatalf("protocol=%d flags=%d hits=%d", protocol, flags, n)
			}
			if n > maxHits {
				maxHits = n
			}
			hits := map[int]bool{}
			for _, i := range indices[:n] {
				if i < 0 || i >= len(decoder.Names) || decoder.Names[i] == "" || hits[i] {
					t.Fatalf("protocol=%d flags=%d invalid/duplicate index=%d", protocol, flags, i)
				}
				hits[i] = true
				seen[decoder.Names[i]] = true
			}
			for index, want := range map[int]bool{
				decoder.TCPSyn: protocol == 6 && flags&2 != 0 && flags&16 == 0,
				decoder.TCPAck: protocol == 6 && flags&16 != 0 && flags&2 == 0,
				decoder.TCPRst: protocol == 6 && flags&4 != 0,
				decoder.TCPFin: protocol == 6 && flags&1 != 0,
			} {
				if hits[index] != want {
					t.Errorf("protocol=%d flags=%d decoder=%s present=%v want=%v", protocol, flags, decoder.Names[index], hits[index], want)
				}
			}
		}
	}
	// Flow records lack IP-header flags and anomaly bits (K7).
	excluded := map[string]bool{"fragment": true, "bad_fragment": true, "invalid": true}
	want := map[string]bool{}
	for _, name := range decoder.Names {
		if name != "" && !excluded[name] {
			want[name] = true
		}
	}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("flow coverage=%v, registry minus exclusions=%v", seen, want)
	}
	if maxHits != MaxDecoderHits {
		t.Errorf("maximum observed hits=%d, MaxDecoderHits=%d", maxHits, MaxDecoderHits)
	}
}
