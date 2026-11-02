package dedup

import (
	"reflect"
	"testing"

	"github.com/d80y6/YemenDDoS/shared/decoder"
)

func TestDao10_K3_SuppressionRegistry(t *testing.T) {
	// Q1=A: missing map entries deliberately mean no suppression.
	want := map[string][]string{
		"ip": {"tcp", "tcp_syn", "udp", "icmp", "fragment"}, "tcp": {"tcp_syn"},
		"tcp_syn": {}, "udp": {}, "icmp": {}, "fragment": {},
		"tcp_ack": {}, "tcp_rst": {}, "tcp_fin": {}, "gre": {}, "esp": {},
		"igmp": {}, "ip_other": {}, "bad_fragment": {}, "invalid": {},
	}
	registered := map[string]bool{"ip": true}
	for _, name := range decoder.Names {
		if name != "" {
			registered[name] = true
		}
	}
	keys := map[string]bool{}
	set := func(names []string) map[string]bool {
		out := map[string]bool{}
		for _, name := range names {
			out[name] = true
		}
		return out
	}
	for name, expected := range want {
		keys[name] = true
		if !reflect.DeepEqual(set(suppressedBy[name]), set(expected)) {
			t.Errorf("suppressedBy[%q]=%v, want %v", name, suppressedBy[name], expected)
		}
	}
	if !reflect.DeepEqual(keys, registered) {
		t.Errorf("explicit suppression decisions=%v, registry=%v", keys, registered)
	}
}
