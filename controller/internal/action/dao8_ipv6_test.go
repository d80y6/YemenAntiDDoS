package action

import (
	"testing"

	"github.com/littlewolf9527/xsight/controller/internal/store"
)

func dao8CIDR(t *testing.T, dst, want string) {
	t.Helper()
	p := store.ActionPrecondition{Attribute: "cidr", Operator: "eq", Value: want}
	if !evaluateStructuredPrecondition(p, &store.Attack{DstIP: dst}, "", nil) {
		t.Errorf("cidr eq %s for %q = false, want true", want, dst)
	}
}

func TestDao8_C1_BareIPv6(t *testing.T)   { dao8CIDR(t, "2001:db8::1", "128") }
func TestDao8_C2_MaskedIPv6(t *testing.T) { dao8CIDR(t, "2001:db8::1/128", "128") }
func TestDao8_C3_IPv4(t *testing.T) {
	for _, dst := range []string{"192.0.2.1", "192.0.2.1/32"} {
		t.Run(dst, func(t *testing.T) { dao8CIDR(t, dst, "32") })
	}
}
func TestDao8_C4_PrefixLengthHelpers(t *testing.T) {
	for _, tc := range []struct{ dst, want string }{
		{"2001:db8::1", "128"}, {"2001:db8::1/128", "128"},
		{"192.0.2.1", "32"}, {"192.0.2.1/32", "32"}, {"invalid", "32"},
	} {
		t.Run(tc.dst, func(t *testing.T) {
			if got := extractPrefixLen(tc.dst); got != tc.want {
				t.Errorf("extractPrefixLen(%q) = %q, want %q", tc.dst, got, tc.want)
			}
			if !comparePrefixLen(">="+tc.want, tc.dst) || !comparePrefixLen("<="+tc.want, tc.dst) {
				t.Errorf("comparePrefixLen bounds for %s and %q do not establish equality", tc.want, tc.dst)
			}
			dao8CIDR(t, tc.dst, tc.want)
		})
	}
}
