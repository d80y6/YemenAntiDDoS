package action

import (
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/action/flowspec"
	"github.com/d80y6/YemenDDoS/controller/internal/store"
)

func TestFlowspecRuleNameIsStableAndSafe(t *testing.T) {
	cases := map[string]string{
		"198.51.100.7/32": "xsight-198-51-100-7-32",
		"2001:db8::1/128": "xsight-2001-db8--1-128",
		"203.0.113.9":     "xsight-203-0-113-9",
	}
	for in, want := range cases {
		if got := flowspecRuleName(in); got != want {
			t.Errorf("flowspecRuleName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProtocolForDecoder(t *testing.T) {
	cases := []struct {
		family string
		want   uint8
		any    bool
	}{
		{"tcp_syn", 6, true},
		{"http_flood", 6, true},
		{"slowloris", 6, true},
		{"udp_flood", 17, true},
		{"dns_query", 17, true},
		{"icmp_flood", 1, true},
		{"unknown_family", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got := protocolForDecoder(c.family)
		if c.any {
			if got == nil || *got != c.want {
				t.Errorf("protocolForDecoder(%q) = %v, want %d", c.family, got, c.want)
			}
			continue
		}
		if got != nil {
			t.Errorf("protocolForDecoder(%q) = %d, want nil", c.family, *got)
		}
	}
}

func TestConnectorVendorDefaultsToFRRAndFailsClosed(t *testing.T) {
	for _, in := range []string{"", "frr", "FRR"} {
		got, err := connectorVendor(&store.BGPConnector{Vendor: in})
		if err != nil || got != flowspec.VendorFRR {
			t.Errorf("connectorVendor(%q) = %q, %v; want frr", in, got, err)
		}
	}
	if got, err := connectorVendor(&store.BGPConnector{Vendor: "cisco_xr"}); err != nil || got != flowspec.VendorCisco {
		t.Errorf("connectorVendor(cisco_xr) = %q, %v; want cisco_xr", got, err)
	}
	if got, err := connectorVendor(&store.BGPConnector{ID: 7, Vendor: "bogus"}); err == nil || got != "" {
		t.Errorf("connectorVendor(bogus) = %q, %v; want empty vendor and error", got, err)
	}
}

func TestFlowspecRuleForNarrowsMatch(t *testing.T) {
	rule := flowspecRuleFor("198.51.100.7/32", &store.Attack{DecoderFamily: "tcp_syn"})
	if rule.Name != "xsight-198-51-100-7-32" || rule.Prefix != "198.51.100.7/32" {
		t.Fatalf("unexpected rule identity: %+v", rule)
	}
	if rule.Protocol == nil || *rule.Protocol != 6 {
		t.Fatalf("protocol not derived from decoder: %+v", rule.Protocol)
	}
	if rule.Action != flowspec.ActionDrop {
		t.Fatalf("action = %q, want drop", rule.Action)
	}
	if err := rule.Validate(); err != nil {
		t.Fatalf("generated rule must validate: %v", err)
	}
}
