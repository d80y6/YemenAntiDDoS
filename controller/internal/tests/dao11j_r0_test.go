package tests

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

// This reproduction intentionally uses only baseline symbols.
func TestDao11j_R0_StuckWithoutRuntimeReconcile(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s, e, ev, _, id := dao5BGPFixture(t, 0)
		s.anns.inject(3, 0, nil)
		e.HandleEvent(ev)
		synctest.Wait()
		<-time.After(10 * time.Minute)
		synctest.Wait()
		a := dao5bRow(t, s.anns, id)
		if a.Status != "withdrawing" || a.Gen != 0 {
			t.Errorf("ASSERT R0.Status FAIL row=%+v; want withdrawing generation 0 after ten minutes", a)
		} else {
			t.Log("ASSERT R0.Status PASS withdrawing generation 0 after ten minutes")
		}
		_, err := s.anns.Attach(context.Background(), store.BGPAttachParams{Prefix: "192.0.2.10/32", RouteMap: "RTBH", ConnectorID: 7, AttackID: 21, ActionID: intPtr(10)})
		if err == nil || !strings.Contains(err.Error(), "status withdrawing") {
			t.Errorf("ASSERT R0.Attach FAIL error=%v; want withdrawing rejection", err)
		} else {
			t.Logf("ASSERT R0.Attach PASS error=%v", err)
		}
	})
}
