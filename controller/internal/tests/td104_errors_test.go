package tests

import (
	"strings"
	"testing"
	"testing/synctest"
)

func TestTD104_E10b_DeletedConnectors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.disable(t)
		f.s.bgpConnectors.connectors = nil
		f.s.xdropConnectors.connectors = nil
		f.run()
		f.state(t, "active", "active", 0, 0)
		f.delta(t, map[string]float64{"bgp/skipped_connector": 1, "xdrop/skipped_connector": 1})
	})
}
func TestTD104_E10c_ConnectorQueryFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.disable(t)
		f.s.fail("bgp_connector")
		f.s.fail("xdrop_connector")
		log := dao5CaptureLog(t)
		f.run()
		f.state(t, "active", "active", 0, 0)
		f.delta(t, map[string]float64{"bgp/failed": 1, "xdrop/failed": 1})
		fzEqual(t, "WARN scan lines", strings.Count(log.text(), "WARN action: ended sweep"), 2)
	})
}
func TestTD104_ClaimFailureNeverDeletes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := td104New(t, 0)
		f.onlyXDrop()
		f.disable(t)
		f.s.fail("claim_active")
		log := dao5CaptureLog(t)
		f.run()
		fzEqual(t, "DELETE", f.d.count(), 0)
		f.delta(t, map[string]float64{"xdrop/failed": 1})
		r, err := f.s.MockStore.XDropActiveRules().ListByAttack(fzCtx, 20)
		fzCheck(t, err)
		fzEqual(t, "unclaimed rule", r[0].Status, "active")
		fzEqual(t, "WARN scan lines", strings.Count(log.text(), "WARN action: ended sweep"), 1)
	})
}
