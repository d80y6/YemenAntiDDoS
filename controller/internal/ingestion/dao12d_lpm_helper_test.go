package ingestion

import (
	"net"
	"reflect"
	"testing"
)

func TestDao12d_G3a(t *testing.T) {
	prefix := func(cidr string) parsedPrefix {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		return parsedPrefix{cidr, n}
	}
	parent, child := prefix("192.0.2.0/24"), prefix("192.0.2.128/25")
	peer, v6 := prefix("198.51.100.0/24"), prefix("2001:db8:1::/48")
	for _, tc := range []struct {
		name string
		in   []parsedPrefix
		want []string
	}{
		{"Order", []parsedPrefix{parent, peer, child, v6}, []string{"2001:db8:1::/48", "192.0.2.128/25", "192.0.2.0/24", "198.51.100.0/24"}},
		{"NoNil", []parsedPrefix{{}}, nil},
		{"CopyUnchanged", []parsedPrefix{parent, {}, child}, []string{"192.0.2.128/25", "192.0.2.0/24"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]parsedPrefix(nil), tc.in...)
			got := sortedForMatch(tc.in)
			for i := range before {
				if tc.in[i] != before[i] {
					t.Errorf("input element %d changed: got %+v, want %+v", i, tc.in[i], before[i])
				}
			}
			var cidrs []string
			for _, p := range got {
				cidrs = append(cidrs, p.cidr)
			}
			if !reflect.DeepEqual(cidrs, tc.want) {
				t.Errorf("matches=%v, want %v", cidrs, tc.want)
			}
		})
	}
}
