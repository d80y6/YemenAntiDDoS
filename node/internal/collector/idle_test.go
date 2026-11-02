package collector

import (
	"math"
	"testing"

	"github.com/d80y6/YemenDDoS/node/internal/bpf"
)

func TestDao7jia_A6_UnsignedWrapUnchanged(t *testing.T) {
	prev := bpf.DstIPStats{
		PktCount: math.MaxUint64 - 1, ByteCount: math.MaxUint64 - 1,
		SmallPkt: math.MaxUint32 - 1, MediumPkt: math.MaxUint32 - 1, LargePkt: math.MaxUint32 - 1,
	}
	cur := bpf.DstIPStats{PktCount: 8, ByteCount: 8, SmallPkt: 8, MediumPkt: 8, LargePkt: 8}
	want := bpf.DstIPStats{PktCount: 10, ByteCount: 10, SmallPkt: 10, MediumPkt: 10, LargePkt: 10}
	for i := range prev.DecoderCounts {
		prev.DecoderCounts[i], cur.DecoderCounts[i], want.DecoderCounts[i] = math.MaxUint32-1, 8, 10
		prev.DecoderByteCounts[i], cur.DecoderByteCounts[i], want.DecoderByteCounts[i] = math.MaxUint64-1, 8, 10
	}
	if got := subtractIPStats(cur, prev); got != want {
		t.Fatalf("wrap delta=%+v, want every counter 10 (%+v)", got, want)
	}
}
