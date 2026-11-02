package flowspec

import (
	"strings"
	"testing"
)

func u8(v uint8) *uint8    { return &v }
func u16(v uint16) *uint16 { return &v }

func TestRenderFRR_RateLimit(t *testing.T) {
	r := Rule{
		Name:      "xsight-1",
		Prefix:    "198.51.100.7/32",
		Protocol:  u8(6),
		DstPort:   u16(443),
		Action:    ActionRateLimit,
		RateLimit: 1_000_000,
	}
	lines, err := Render(VendorFRR, r)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"configure terminal",
		"flowspec",
		"flow spec ipv4 xsight-1 permit",
		" match destination 198.51.100.7/32",
		" match protocol tcp",
		" match destination-port 443",
		" then actions rate-limit 1000000",
		"exit",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestRenderFRR_DropNoOptionalMatches(t *testing.T) {
	lines, err := Render(VendorFRR, Rule{Name: "r", Prefix: "203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, " then actions drop") {
		t.Fatalf("missing drop action:\n%s", joined)
	}
	if strings.Contains(joined, "match protocol") || strings.Contains(joined, "port") {
		t.Fatalf("optional matches must be omitted:\n%s", joined)
	}
}

func TestRenderWithdrawFRR(t *testing.T) {
	lines, err := RenderWithdraw(VendorFRR, Rule{Name: "r", Prefix: "203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "no flow spec ipv4 r") {
		t.Fatalf("withdraw missing no-flow line: %v", lines)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		ok   bool
	}{
		{"missing name", Rule{Prefix: "1.2.3.4/32"}, false},
		{"missing prefix", Rule{Name: "r"}, false},
		{"default action drop", Rule{Name: "r", Prefix: "1.2.3.4/32"}, true},
		{"rate without value", Rule{Name: "r", Prefix: "1.2.3.4/32", Action: ActionRateLimit}, false},
		{"rate with value", Rule{Name: "r", Prefix: "1.2.3.4/32", Action: ActionRateLimit, RateLimit: 5}, true},
		{"bad action", Rule{Name: "r", Prefix: "1.2.3.4/32", Action: "redirect"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rule.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("Validate() err=%v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestRenderVendorTemplatesSubstitute(t *testing.T) {
	r := Rule{
		Name:      "xsight-9",
		Prefix:    "198.51.100.0/24",
		Protocol:  u8(17),
		DstPort:   u16(53),
		Action:    ActionRateLimit,
		RateLimit: 5000,
	}
	for _, v := range []Vendor{VendorCisco, VendorJuniper, VendorArista} {
		lines, err := Render(v, r)
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		joined := strings.Join(lines, "\n")
		if strings.Contains(joined, "{") {
			t.Fatalf("%s: unsubstituted placeholder:\n%s", v, joined)
		}
		if !strings.Contains(joined, "xsight-9") || !strings.Contains(joined, "198.51.100.0/24") {
			t.Fatalf("%s: missing name/prefix:\n%s", v, joined)
		}
		if !strings.Contains(joined, "udp") && !strings.Contains(joined, "rate-limit 5000") {
			t.Fatalf("%s: missing protocol or rate:\n%s", v, joined)
		}
	}
}

func TestUnknownVendor(t *testing.T) {
	if _, err := Render(Vendor("nope"), Rule{Name: "r", Prefix: "1.2.3.4/32"}); err == nil {
		t.Fatal("expected error for unknown vendor")
	}
}
