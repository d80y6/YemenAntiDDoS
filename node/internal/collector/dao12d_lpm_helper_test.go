package collector

import (
	"net"
	"testing"
)

func TestDao12d_G4a(t *testing.T) {
	for _, tc := range []struct{ name, parent, child string }{
		{"V4", "192.0.2.0/24", "192.0.2.128/25"},
		{"V6", "2001:db8::/32", "2001:db8:1::/48"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ps []prefixNet
			for _, cidr := range []string{tc.parent, tc.child} {
				_, n, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatal(err)
				}
				ps = append(ps, prefixNet{net: *n})
			}
			sortLongestFirst(ps)
			if ps[0].net.String() != tc.child || ps[1].net.String() != tc.parent {
				t.Errorf("order=%s,%s, want %s,%s", ps[0].net.String(), ps[1].net.String(), tc.child, tc.parent)
			}
		})
	}
}
