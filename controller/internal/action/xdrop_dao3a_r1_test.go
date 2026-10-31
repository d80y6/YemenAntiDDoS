package action

import (
	"fmt"
	"strings"
	"testing"
)

// TestD3A_S03_OperatorEnumOnlyE2E locks the executeXDrop caller's operator
// rate_limit flag: only the action enum asks for rate_limit, so a caller that
// drops the flag would let the fallback overwrite the operator's rate.
func TestD3A_S03_OperatorEnumOnlyE2E(t *testing.T) {
	for _, actionField := range []string{"", `,"action":"drop"`} {
		t.Run(fmt.Sprintf("body=%q", actionField), func(t *testing.T) {
			m := d3aMock(t)
			s := d3aNewStore("pps", 1000)
			a := d3aAttack("udp", "198.51.100.7", true)
			act := v3Action(74, `{"dst_ip":"{dst_ip}","src_ip":"{src_ip}","protocol":"udp","rate_limit":5000`+actionField+`}`)
			act.XDropAction = "rate_limit"
			r := d3aExecute(t, m, s, a, act, d3aFAOf(53, 95, 123, 95, 95, 100))
			if r.body["rate_limit"] != float64(5000) || r.calls != 0 || strings.Contains(r.log.ErrorMessage, "fallback") {
				t.Fatalf("operator enum protection lost: body=%v calls=%d hints=%q", r.body, r.calls, r.log.ErrorMessage)
			}
			if actionField == "" {
				if d3aHas(r.body, "action") {
					t.Fatalf("absent body action changed: %v", r.body)
				}
			} else if r.body["action"] != "drop" {
				t.Fatalf("operator body action changed: %v", r.body)
			}
		})
	}
}
