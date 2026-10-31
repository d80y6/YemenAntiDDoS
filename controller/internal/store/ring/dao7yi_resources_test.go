package ring

import (
	"testing"
	"unsafe"

	"github.com/littlewolf9527/xsight/controller/internal/config"
)

func TestDao7yi_R1_DataPointSizeMatchesEstimate(t *testing.T) {
	size := int64(unsafe.Sizeof(DataPoint{}))
	if size != 240 {
		t.Fatalf("DataPoint size=%d want=240", size)
	}
	c := &config.Config{Ring: config.RingConfig{MaxGlobalKeys: 100000, MaxPointsPerIP: 120}}
	want := size * 2 * int64(c.Ring.MaxGlobalKeys) * int64(c.Ring.MaxPointsPerIP)
	if got := config.RingEstimateBytes(c); got != want {
		t.Errorf("estimate=%d actual two-direction DataPoints=%d", got, want)
	}
}
