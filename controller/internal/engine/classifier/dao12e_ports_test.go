package classifier

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestDao12e_G3(t *testing.T) {
	t.Run("Table", func(t *testing.T) {
		for _, row := range []struct {
			port         uint32
			name, attack string
			reason       string
		}{
			{53, "53_dns", "dns_reflection", "src_port_53_dns_dominant"},
			{123, "123_ntp", "ntp_reflection", "src_port_123_ntp_dominant"},
			{11211, "11211_memcached", "memcached_reflection", "src_port_11211_memcached_dominant"},
			{1900, "1900_ssdp", "ssdp_reflection", "src_port_1900_ssdp_dominant"},
			{389, "389_cldap", "cldap_reflection", "src_port_389_cldap_dominant"},
			{161, "161_snmp", "snmp_reflection", "src_port_161_snmp_dominant"},
			{19, "19_chargen", "chargen_reflection", "src_port_19_chargen_dominant"},
		} {
			t.Run(row.name, func(t *testing.T) {
				dst := net.ParseIP("192.0.2.1")
				ports := make([]uint32, 20)
				for i := range ports {
					ports[i] = row.port
				}
				c := New()
				c.Ingest(sampleBatch(dst, ports))
				got := c.Classify(dst)
				if got == nil {
					t.Fatal("classification is nil")
				}
				want := []string{"src_port_dominant", row.reason}
				if got.AttackType != row.attack || !reflect.DeepEqual(got.Reasons, want) {
					t.Fatalf("classification=%+v, want attack=%s reasons=%v", got, row.attack, want)
				}
			})
		}
	})
	t.Run("Unknown", func(t *testing.T) {
		if got := portName(9999); got != "unknown" {
			t.Fatalf("portName(9999)=%q, want unknown", got)
		}
	})
	t.Run("Count", func(t *testing.T) {
		if got := len(reflectionPorts); got != 7 {
			t.Fatalf("reflection port count=%d, want 7", got)
		}
	})
	t.Run("NoSwitch", func(t *testing.T) {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("cannot locate source file")
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(filepath.Dir(file), "classifier.go"), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "portName" {
				found = true
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if _, ok := n.(*ast.SwitchStmt); ok {
						t.Error("portName contains a switch")
					}
					return true
				})
			}
		}
		if !found {
			t.Fatal("portName not found")
		}
	})
}
