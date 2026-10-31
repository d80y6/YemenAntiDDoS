package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dao13fConfig(ifaces ...Interface) *Config {
	return &Config{
		NodeID: "dao13f", Interfaces: ifaces, ParseWorkers: 1,
		Controller: CtrlConfig{Address: "localhost:50051"},
		Auth:       AuthConfig{NodeAPIKey: "test-key"},
	}
}

func dao13fIface(name string) Interface {
	return Interface{Name: name, Mode: "mirror", SampleBytes: 128, UpstreamSampleRate: 1}
}

func dao13fExample(t *testing.T) *Config {
	t.Helper()
	data, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "example.yaml")
	if err := os.WriteFile(path, append(data, []byte("\nparse_workers: 1\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDao13f_N1(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		change      func(*Interface)
	}{
		{"ModeDiffers", "mode", func(i *Interface) { i.Mode = "erspan" }},
		{"SampleBytesDiffers", "sample_bytes", func(i *Interface) { i.SampleBytes = 256 }},
		{"UpstreamDiffers", "upstream_sample_rate", func(i *Interface) { i.UpstreamSampleRate = 10 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, count := range []int{2, 3} {
				ifaces := []Interface{dao13fIface("test0"), dao13fIface("test1")}
				if count == 3 {
					ifaces = append(ifaces, dao13fIface("test2"))
				}
				tc.change(&ifaces[count-1])
				err := dao13fConfig(ifaces...).validate()
				index := "interfaces[1]"
				if count == 3 {
					index = "interfaces[2]"
				}
				if err == nil || !strings.Contains(err.Error(), index+"."+tc.field) ||
					!strings.Contains(err.Error(), "differs from interfaces[0]") {
					t.Fatalf("heterogeneous config: error=%v, want %s.%s", err, index, tc.field)
				}
			}
		})
	}
}

func TestDao13f_N2(t *testing.T) {
	for _, name := range []string{"IdenticalPair", "OmittedRateFirst", "OmittedRateSecond", "SingleInterface", "FlowNoInterfaces"} {
		t.Run(name, func(t *testing.T) {
			c := dao13fConfig(dao13fIface("test0"), dao13fIface("test1"))
			switch name {
			case "OmittedRateFirst":
				c.Interfaces[0].UpstreamSampleRate = 0
			case "OmittedRateSecond":
				c.Interfaces[1].UpstreamSampleRate = 0
			case "SingleInterface":
				c.Interfaces = c.Interfaces[:1]
			case "FlowNoInterfaces":
				c.Mode, c.Interfaces = "flow", nil
			}
			if err := c.validate(); err != nil {
				t.Fatal(err)
			}
			for _, iface := range c.Interfaces {
				if iface.UpstreamSampleRate != 1 {
					t.Fatalf("defaulted rate=%d, want 1", iface.UpstreamSampleRate)
				}
			}
		})
	}
}

func TestDao13f_N3(t *testing.T) {
	t.Run("ExampleConfigHomogeneous", func(t *testing.T) {
		c := dao13fExample(t)
		if len(c.Interfaces) != 1 {
			t.Fatalf("example has %d interfaces, want one", len(c.Interfaces))
		}
	})
}

func TestDao13f_N4(t *testing.T) {
	for _, name := range []string{"OmittedSampleBytesDefaults256", "OmittedVsExplicit256First", "OmittedVsExplicit256Second", "ExplicitOutOfRangeStillRejected"} {
		t.Run(name, func(t *testing.T) {
			a, b := dao13fIface("test0"), dao13fIface("test1")
			a.SampleBytes, b.SampleBytes = 0, 256
			c := dao13fConfig(a)
			switch name {
			case "OmittedVsExplicit256First":
				c.Interfaces = []Interface{a, b}
			case "OmittedVsExplicit256Second":
				a.SampleBytes, b.SampleBytes = 256, 0
				c.Interfaces = []Interface{a, b}
			case "ExplicitOutOfRangeStillRejected":
				for _, value := range []uint32{1, 127, 513} {
					c.Interfaces[0].SampleBytes = value
					if err := c.validate(); err == nil || !strings.Contains(err.Error(), "sample_bytes must be 128-512") {
						t.Fatalf("value %d: error=%v", value, err)
					}
				}
				return
			}
			if err := c.validate(); err != nil {
				t.Fatal(err)
			}
			for _, iface := range c.Interfaces {
				if iface.SampleBytes != 256 {
					t.Fatalf("sample_bytes=%d, want 256", iface.SampleBytes)
				}
			}
		})
	}
}

func TestDao13f_R0FixedN(t *testing.T) {
	t.Run("HeteroRejected", func(t *testing.T) {
		a, b := dao13fIface("test0"), dao13fIface("test1")
		b.Mode = "erspan"
		if err := dao13fConfig(a, b).validate(); err == nil {
			t.Fatal("heterogeneous interfaces accepted")
		}
	})
	t.Run("ExampleIsHomogeneous", func(t *testing.T) {
		if c := dao13fExample(t); len(c.Interfaces) != 1 {
			t.Fatalf("example interfaces=%d", len(c.Interfaces))
		}
	})
	t.Run("OmittedSampleBytesAccepted", func(t *testing.T) {
		a := dao13fIface("test0")
		a.SampleBytes = 0
		c := dao13fConfig(a)
		if err := c.validate(); err != nil || c.Interfaces[0].SampleBytes != 256 {
			t.Fatalf("default sample bytes: config=%+v error=%v", c, err)
		}
	})
}
