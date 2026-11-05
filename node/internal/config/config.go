// Package config defines the Node configuration structure.
package config

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"

	"github.com/d80y6/YemenDDoS/shared/tlsconf"
	"gopkg.in/yaml.v3"
)

// Config is the top-level Node configuration.
type Config struct {
	Mode         string      `yaml:"mode"` // "xdp" (default) | "xdp_inline" | "flow" — v4.0
	NodeID       string      `yaml:"node_id"`
	Interfaces   []Interface `yaml:"interfaces"`
	BPF          BPFConfig   `yaml:"bpf"`
	Controller   CtrlConfig  `yaml:"controller"`
	TLS          TLSConfig   `yaml:"tls"`
	L7           L7Config    `yaml:"l7"`
	Auth         AuthConfig  `yaml:"auth"`
	ParseWorkers int         `yaml:"parse_workers"` // parallel parse workers, default = NumCPU/2, min 1, max 16
	Pprof        bool        `yaml:"pprof"`         // enable pprof debug server on 127.0.0.1:6061 (default false)

	// v4.0: inline scrubbing engine (xdp_inline mode)
	Inline InlineConfig `yaml:"inline"`
	// v4.0: hardware acceleration / OS tuning
	Perf  PerfConfig  `yaml:"perf"`
	AFXDP AFXDPConfig `yaml:"af_xdp"`
}

// InlineConfig controls the XDP inline scrubbing engine.
type InlineConfig struct {
	Enabled        bool   `yaml:"enabled"`          // master switch (xdp_inline mode implies true)
	BurstPPS       uint64 `yaml:"burst_pps"`        // per-dst burst threshold → 2s emergency drop (0 = kernel default)
	SynCookie      bool   `yaml:"syn_cookie"`       // kernel stateless SYN-cookie engine
	DNSProtect     bool   `yaml:"dns_protect"`      // UDP/DNS reflection defense
	SampleRate     uint32 `yaml:"sample_rate"`      // 1-in-N L7 sampling of protected traffic (0 = disabled)
	CleanPipe      string `yaml:"cleanpipe_egress"` // egress ifname for clean-pipe redirect ("" = same-iface TX only)
	CleanPipeEncap string `yaml:"cleanpipe_encap"`  // "" | "gre" | "geneve"
}

// PerfConfig holds CPU/OS tuning for line-rate operation.
type PerfConfig struct {
	CPUPins []int  `yaml:"cpu_pins"` // cores pinned by the node's hot goroutines
	XDPMode string `yaml:"xdp_mode"` // "driver" (default) | "generic" | "offload"
}

// AFXDPConfig controls AF_XDP zero-copy L7 inspection sockets.
type AFXDPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Queue     uint32 `yaml:"queue"`      // NIC RX queue steered into the XSK map
	Frames    uint32 `yaml:"frames"`     // UMEM frame count (power of two, default 4096)
	FrameSize uint32 `yaml:"frame_size"` // default 4096
	ZeroCopy  bool   `yaml:"zero_copy"`  // request XDP_ZEROCOPY binding
}

// TLSConfig configures mutual TLS for the Node's gRPC client.
//
// When enabled, the Node dials the Controller over TLS and presents its own
// client certificate. The server certificate is verified against ca_file.
// If server_name is empty, the gRPC authority (controller.address host) is
// used as the expected peer name.
type TLSConfig struct {
	Enabled bool `yaml:"enabled"` // when true, use mutual TLS; false keeps plaintext
	// CAFile verifies the Controller's certificate. Same file as the
	// Controller's ca_file in single-tier deployments.
	CAFile string `yaml:"ca_file"`
	// CertFile / KeyFile are the Node's identity certificate and key.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ServerName is the expected name in the Controller certificate.
	// Empty means "use controller.address host".
	ServerName       string `yaml:"server_name"`
	AllowLegacyTLS12 bool   `yaml:"allow_legacy_tls12"`
}

// L7Config controls application-layer inspection on captured payloads.
//
// L7 parsing needs the first ~512 bytes of each TCP payload. With the default
// sample_bytes of 256 a TLS ClientHello may be truncated, so enable L7 with
// sample_bytes: 512 on every XDP interface.
type L7Config struct {
	Enabled          bool   `yaml:"enabled"`
	WindowSeconds    int    `yaml:"window_seconds"` // aggregation window, default 1
	HTTPRPS          uint64 `yaml:"http_rps"`       // HTTP requests/s per destination
	TLSHSPS          uint64 `yaml:"tls_hsps"`       // ClientHellos/s per destination
	SlowlorisConns   uint64 `yaml:"slowloris_conns"`
	MaxTracked       int    `yaml:"max_tracked_destinations"`
	MaxFlows         int    `yaml:"max_tracked_flows"`
	MaxOpenFragments int    `yaml:"max_open_fragments"`
}

// Interface defines a single mirror/ERSPAN interface to monitor.
type Interface struct {
	Name               string `yaml:"name"`
	Mode               string `yaml:"mode"`                 // "mirror" | "erspan"
	UpstreamSampleRate uint32 `yaml:"upstream_sample_rate"` // 1=passthrough, 300=upstream 1:300
	SampleBytes        uint32 `yaml:"sample_bytes"`         // 128-512, default 256
}

// BPFConfig holds BPF-related settings.
type BPFConfig struct {
	Path       string `yaml:"path"`        // path to BPF ELF (only used with manual load)
	MaxEntries uint32 `yaml:"max_entries"` // ip_stats map size, default 1000000
}

// CtrlConfig holds Controller connection settings.
type CtrlConfig struct {
	Address string `yaml:"address"` // "controller:50051"
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	NodeAPIKey string `yaml:"node_api_key"` // API key for gRPC handshake
}

// Load reads and parses a config.yaml file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.NodeID == "" {
		return fmt.Errorf("node_id is required")
	}

	// Default mode to xdp for backward compatibility
	if c.Mode == "" {
		c.Mode = "xdp"
	}
	if c.Mode != "xdp" && c.Mode != "xdp_inline" && c.Mode != "flow" {
		return fmt.Errorf("mode must be 'xdp', 'xdp_inline' or 'flow', got %q", c.Mode)
	}

	// Mode-specific validation
	if c.Mode == "xdp" {
		if len(c.Interfaces) == 0 {
			return fmt.Errorf("at least one interface is required in xdp mode")
		}
		for i, iface := range c.Interfaces {
			if iface.Name == "" {
				return fmt.Errorf("interfaces[%d].name is required", i)
			}
			if iface.Mode != "mirror" && iface.Mode != "erspan" {
				return fmt.Errorf("interfaces[%d].mode must be 'mirror' or 'erspan', got %q", i, iface.Mode)
			}
			if iface.UpstreamSampleRate == 0 {
				c.Interfaces[i].UpstreamSampleRate = 1
			}
			if iface.SampleBytes == 0 {
				c.Interfaces[i].SampleBytes = 256
			}
			if c.Interfaces[i].SampleBytes < 128 || c.Interfaces[i].SampleBytes > 512 {
				return fmt.Errorf("interfaces[%d].sample_bytes must be 128-512, got %d", i, c.Interfaces[i].SampleBytes)
			}
		}
		for i := 1; i < len(c.Interfaces); i++ {
			first, iface := c.Interfaces[0], c.Interfaces[i]
			for _, field := range []struct {
				name       string
				got, first any
			}{
				{"mode", iface.Mode, first.Mode},
				{"sample_bytes", iface.SampleBytes, first.SampleBytes},
				{"upstream_sample_rate", iface.UpstreamSampleRate, first.UpstreamSampleRate},
			} {
				if field.got != field.first {
					return fmt.Errorf("interfaces[%d].%s=%v differs from interfaces[0] (%v): all XDP interfaces share one BPF config and one upstream rate; run separate nodes for different settings", i, field.name, field.got, field.first)
				}
			}
		}
		if c.BPF.MaxEntries == 0 {
			c.BPF.MaxEntries = 1000000
		}
		if c.ParseWorkers == 0 {
			c.ParseWorkers = runtime.NumCPU() / 2
			if c.ParseWorkers < 1 {
				c.ParseWorkers = 1
			}
		}
		if c.ParseWorkers < 1 || c.ParseWorkers > 16 {
			return fmt.Errorf("parse_workers must be 1-16, got %d", c.ParseWorkers)
		}
		// Warn if a configured mirror/ERSPAN interface shares a subnet with
		// a management IP (SSH/gRPC traffic would be XDP_DROP'd).
		warnManagementConflict(c.Interfaces)
	}
	// flow mode: interfaces/BPF/parse_workers not required (config comes from Controller)

	if c.L7.Enabled {
		if c.L7.WindowSeconds <= 0 {
			c.L7.WindowSeconds = 1
		}
		if c.L7.WindowSeconds > 60 {
			return fmt.Errorf("l7.window_seconds must be 1-60, got %d", c.L7.WindowSeconds)
		}
		if c.L7.HTTPRPS == 0 {
			c.L7.HTTPRPS = 2000
		}
		if c.L7.TLSHSPS == 0 {
			c.L7.TLSHSPS = 1000
		}
		if c.L7.SlowlorisConns == 0 {
			c.L7.SlowlorisConns = 50
		}
		if c.L7.MaxTracked == 0 {
			c.L7.MaxTracked = 4096
		}
		if c.L7.MaxFlows == 0 {
			c.L7.MaxFlows = 65536
		}
		if c.L7.MaxOpenFragments == 0 {
			c.L7.MaxOpenFragments = 20
		}
		if c.Mode == "xdp" && len(c.Interfaces) > 0 && c.Interfaces[0].SampleBytes < 512 {
			log.Printf("WARN l7: sample_bytes=%d may truncate TLS ClientHello; set sample_bytes: 512 for full L7 visibility",
				c.Interfaces[0].SampleBytes)
		}
	}

	if c.Controller.Address == "" {
		return fmt.Errorf("controller.address is required")
	}
	if c.Auth.NodeAPIKey == "" {
		return fmt.Errorf("auth.node_api_key is required")
	}
	if c.TLS.Enabled {
		if _, err := tlsconf.ClientConfig(tlsconf.FileConfig{
			CAFile:           c.TLS.CAFile,
			CertFile:         c.TLS.CertFile,
			KeyFile:          c.TLS.KeyFile,
			ServerName:       c.TLS.ServerName,
			AllowLegacyTLS12: c.TLS.AllowLegacyTLS12,
		}); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}

	return nil
}

// IsFlowMode returns true if this node is configured for flow collection mode.
func (c *Config) IsFlowMode() bool {
	return c.Mode == "flow"
}

// IsInlineMode returns true when the XDP inline scrubbing engine should
// attach instead of the mirror-capture program.
func (c *Config) IsInlineMode() bool {
	return c.Mode == "xdp_inline" || (c.Mode == "xdp" && c.Inline.Enabled)
}

// InlineEnabled reports the effective inline-engine switch.
func (c *Config) InlineEnabled() bool {
	return c.IsInlineMode()
}

// XDPModeOrDefault returns the configured attach mode ("driver" default).
func (c *Config) XDPModeOrDefault() string {
	switch c.Perf.XDPMode {
	case "generic", "offload":
		return c.Perf.XDPMode
	default:
		return "driver"
	}
}

// warnManagementConflict checks if any configured mirror interface has an IP
// in the same subnet as another interface on the machine (likely management).
func warnManagementConflict(ifaces []Interface) {
	// Collect all local IPs with their subnets
	type localAddr struct {
		iface string
		net   *net.IPNet
	}
	var mgmtAddrs []localAddr

	netIfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ni := range netIfaces {
		if ni.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ni.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				// Skip IPv6 link-local (fe80::/10) — all interfaces share this
				// prefix, generating false positive warnings.
				if ipnet.IP.IsLinkLocalUnicast() {
					continue
				}
				mgmtAddrs = append(mgmtAddrs, localAddr{iface: ni.Name, net: ipnet})
			}
		}
	}

	// For each configured mirror interface, check if it has an IP that
	// overlaps with another interface's subnet
	for _, mi := range ifaces {
		for _, ma := range mgmtAddrs {
			if ma.iface == mi.Name {
				continue // same interface, skip
			}
			// Check if the mirror interface has an IP in the mgmt subnet
			mirrorIface, err := net.InterfaceByName(mi.Name)
			if err != nil {
				continue
			}
			mirrorAddrs, _ := mirrorIface.Addrs()
			for _, a := range mirrorAddrs {
				if ipnet, ok := a.(*net.IPNet); ok {
					if ma.net.Contains(ipnet.IP) || ipnet.Contains(ma.net.IP) {
						log.Printf("WARNING: mirror interface %s (%s) shares subnet with management interface %s (%s) — XDP will DROP management traffic on %s!",
							mi.Name, ipnet.IP, ma.iface, ma.net.IP, mi.Name)
					}
				}
			}
		}
	}
}
