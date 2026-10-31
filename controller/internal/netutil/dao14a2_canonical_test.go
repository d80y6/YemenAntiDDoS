package netutil

import (
	"bytes"
	"net"
	"testing"
)

func TestDao14a2_G1n(t *testing.T) {
	v6 := func(s string) []byte { return net.ParseIP(s).To16() }
	good := []struct {
		name string
		raw  []byte
		plen uint32
		want string
	}{
		{"V4Net", []byte{192, 0, 2, 0}, 24, "192.0.2.0/24"}, {"V4Host", []byte{192, 0, 2, 10}, 32, "192.0.2.10/32"}, {"V4Zero", []byte{0, 0, 0, 0}, 0, "0.0.0.0/0"},
		{"V6Net", v6("2001:db8::"), 32, "2001:db8::/32"}, {"V6Host", v6("2001:db8::1"), 128, "2001:db8::1/128"}, {"V6Zero", v6("::"), 0, "::/0"},
		{"Mapped24", v6("192.0.2.0"), 24, "192.0.2.0/24"},
	}
	for _, c := range good {
		t.Run("Good/"+c.name, func(t *testing.T) {
			s, n, ok := CanonicalPrefix(c.raw, c.plen)
			if !ok || s != c.want || s != FormatPrefix(c.raw, c.plen) || n.String() != s {
				t.Errorf("%v/%d => %q %v %v want %q", c.raw, c.plen, s, n, ok, c.want)
			}
		})
	}
	bad := map[string]struct {
		raw  []byte
		plen uint32
	}{
		"Len3": {[]byte{192, 0, 2}, 24}, "Len33": {[]byte{192, 0, 2, 0}, 33}, "Mapped120": {v6("192.0.2.0"), 120},
		"Empty": {[]byte{}, 0}, "Nil": {nil, 0}, "Len5": {[]byte{192, 0, 2, 0, 0}, 24},
		"Host24": {[]byte{192, 0, 2, 5}, 24}, "Host6": {v6("2001:db8::5"), 32}, "Host31": {[]byte{192, 0, 2, 1}, 31}, "HostMapped": {v6("192.0.2.5"), 24},
	}
	for name, c := range bad {
		t.Run("Bad/"+name, func(t *testing.T) {
			if s, _, ok := CanonicalPrefix(c.raw, c.plen); ok {
				t.Errorf("%v/%d accepted as %q", c.raw, c.plen, s)
			}
		})
	}
	t.Run("InputUnchanged", func(t *testing.T) {
		for _, raw := range [][]byte{{192, 0, 2, 5}, v6("192.0.2.5"), v6("2001:db8::5")} {
			before := append([]byte(nil), raw...)
			CanonicalPrefix(raw, 24)
			if !bytes.Equal(raw, before) {
				t.Errorf("raw mutated %v -> %v", before, raw)
			}
		}
	})
	for _, c := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"IPV4", []byte{192, 0, 2, 1}, "192.0.2.1"}, {"IPV6", v6("2001:db8::1"), "2001:db8::1"}, {"IPMapped", v6("192.0.2.1"), "192.0.2.1"}, {"IPV6Zero", v6("::"), "::"}, {"IPV4Zero", []byte{0, 0, 0, 0}, "0.0.0.0"},
	} {
		t.Run("Good/"+c.name, func(t *testing.T) {
			if s, ok := CanonicalIP(c.raw); !ok || s != c.want || s != net.IP(c.raw).String() {
				t.Errorf("IP=%q ok=%v want %q", s, ok, c.want)
			}
		})
	}
	for name, r := range map[string][]byte{"IPEmpty": {}, "IPNil": nil, "IPLen3": {192, 0, 2}, "IPLen5": {1, 2, 3, 4, 5}} {
		t.Run("Bad/"+name, func(t *testing.T) {
			if s, ok := CanonicalIP(r); ok {
				t.Errorf("%v accepted as %q", r, s)
			}
		})
	}
}
