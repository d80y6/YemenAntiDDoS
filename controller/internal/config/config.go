// Package config loads and validates the Controller's YAML configuration.
package config

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/d80y6/YemenDDoS/shared/tlsconf"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    ListenConfig    `yaml:"listen"`
	Database  DatabaseConfig  `yaml:"database"`
	Log       LogConfig       `yaml:"log"`
	Auth      AuthConfig      `yaml:"auth"`
	TLS       TLSConfig       `yaml:"tls"`
	Action    ActionConfig    `yaml:"action_engine"`
	Detection DetectionConfig `yaml:"detection"`
	Retention RetentionConfig `yaml:"retention"`
	Ring      RingConfig      `yaml:"ring"`
}

// TLSConfig configures mutual TLS on the Node gRPC listener.
//
// Security posture: mTLS is ON by default. The plaintext path exists only so
// an existing deployment can be brought up before its nodes hold certificates;
// it must be treated as a temporary migration window, never as a steady state.
// See docs/MTLS.md for the rollout sequence.
type TLSConfig struct {
	// Enabled turns on mutual TLS for the gRPC listener.
	Enabled bool `yaml:"enabled"`
	// CAFile is the PEM bundle trusted for NODE client certificates. For a
	// single-tier deployment this is the same file as the listener trust
	// store; keeping the key distinct makes the two-tier layout obvious.
	CAFile string `yaml:"ca_file"`
	// CertFile / KeyFile are the Controller's own leaf certificate and key,
	// presented to nodes so they can verify the server.
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// ServerName is the expected name in our own certificate, used for
	// node-side pinning and rejected if the leaf does not carry it. Optional.
	ServerName string `yaml:"server_name"`
	// AllowLegacyTLS12 relaxes the TLS 1.3 floor to 1.2. Kept because some
	// appliances middlebox-inspect TLS and drop 1.3 handshakes; log loudly.
	AllowLegacyTLS12 bool `yaml:"allow_legacy_tls12"`
}

// RingConfig controls the in-memory ring buffer limits.
// Ring is for realtime detection only; long-history analytics use ts_stats.
type RingConfig struct {
	MaxPointsPerIP  int `yaml:"max_points_per_ip"`  // per-IP history depth (default 120 = 2min)
	MaxIPsPerPrefix int `yaml:"max_ips_per_prefix"` // max tracked IPs per prefix (default 10000)
	MaxGlobalKeys   int `yaml:"max_global_keys"`    // total tracked IPs across all prefixes (default 100000)
}

// RetentionConfig controls automatic cleanup of historical data.
type RetentionConfig struct {
	TSStatsDays          int `yaml:"ts_stats_days"`           // delete ts_stats older than N days (0 = keep forever)
	TSStatsCompressDays  int `yaml:"ts_stats_compress_days"`  // compress ts_stats older than N days (default 1); 0 = no compression policy
	TSStatsCaggDays      int `yaml:"ts_stats_cagg_days"`      // delete cagg (ts_stats_5min) older than N days (default 90); chunk size auto N/7 days, min 1
	TSStatsChunkDays     int `yaml:"ts_stats_chunk_days"`     // ts_stats chunk size in days (0 = auto: retention/7, floored to 1; clamped to <= retention)
	FlowLogsDays         int `yaml:"flow_logs_days"`          // delete flow_logs older than N days (default 7); 0 = keep forever
	FlowLogsCompressDays int `yaml:"flow_logs_compress_days"` // compress flow_logs older than N days (default 1); 0 = no compression policy
	FlowLogsChunkDays    int `yaml:"flow_logs_chunk_days"`    // flow_logs chunk size in days (0 = auto: retention/7, floored to 1; clamped to <= retention)
	AttacksDays          int `yaml:"attacks_days"`            // delete ended attacks older than N days (0 = keep forever)
	AuditLogDays         int `yaml:"audit_log_days"`          // delete audit logs older than N days (0 = keep forever)
	IntervalHours        int `yaml:"interval_hours"`          // how often to run cleanup (default 24 = once/day)
}

type ListenConfig struct {
	GRPC string `yaml:"grpc"`
	HTTP string `yaml:"http"`
}

type DatabaseConfig struct {
	Driver string `yaml:"driver"` // postgres | sqlite
	DSN    string `yaml:"dsn"`
}

type LogConfig struct {
	Level string `yaml:"level"` // debug | info | warn | error
}

type AuthConfig struct {
	APIKey               string `yaml:"api_key"`
	InitialAdminPassword string `yaml:"initial_admin_password"`
}

type ActionConfig struct {
	Mode                  string `yaml:"mode"` // observe | auto
	XDropAPI              string `yaml:"xdrop_api"`
	XDropAPIKey           string `yaml:"xdrop_api_key"`
	XDropNarrowPct        int    `yaml:"xdrop_narrow_pct"`
	XDropMinSamplePackets uint64 `yaml:"xdrop_min_sample_packets"`
	XDropTopKPct          int    `yaml:"xdrop_topk_pct"`
	XDropTopKMax          int    `yaml:"xdrop_topk_max"`
	// XDropAdaptiveSamples lowers the sample requirement when the observed
	// dominant field is unambiguous (>=90/95%). Without it, short hit-and-run
	// attacks never reach xdrop_min_sample_packets and the rule stays broad.
	XDropAdaptiveSamples bool `yaml:"xdrop_adaptive_samples"`
	// FastPathMultiplier confirms an attack on the first tick when the
	// measured rate is at least this multiple of the threshold. 0 disables
	// the shortcut. This is what makes autonomous mitigation react within one
	// detection tick instead of waiting for the confirm window.
	FastPathMultiplier float64 `yaml:"fast_path_multiplier"`
}

type DetectionConfig struct {
	HardThresholdConfirmSeconds    int `yaml:"hard_threshold_confirm_seconds"`
	DynamicThresholdConfirmSeconds int `yaml:"dynamic_threshold_confirm_seconds"`
	ExpiryIntervalSeconds          int `yaml:"expiry_interval_seconds"`
	// ManualExpireHoldSeconds limits re-confirmation after manual expiry; 0 disables holding.
	// Nil follows expiry_interval_seconds, capped at 86400, using the base in dynamic mode.
	ManualExpireHoldSeconds *int    `yaml:"manual_expire_hold_seconds"`
	ExpiryFunction          string  `yaml:"expiry_function"`           // "static" | "dynamic", default "static"
	ExpiryScaleBaseSeconds  int     `yaml:"expiry_scale_base_seconds"` // attack duration for 1x scale (default 300)
	ExpiryMaxScale          float64 `yaml:"expiry_max_scale"`          // max multiplier (default 4.0)
	MaxActiveAttacks        int     `yaml:"max_active_attacks"`        // 0 = no limit, default 10000
	DryRun                  bool    `yaml:"dry_run"`                   // true = detect but don't create attacks
}

// ResolvedManualExpireHoldSeconds resolves the manual hold without changing the configured value.
func (d DetectionConfig) ResolvedManualExpireHoldSeconds() int {
	if d.ManualExpireHoldSeconds != nil {
		return *d.ManualExpireHoldSeconds
	}
	if d.ExpiryIntervalSeconds > 0 {
		return min(d.ExpiryIntervalSeconds, 86400)
	}
	return 0
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := &Config{
		Listen: ListenConfig{
			GRPC: ":50051",
			HTTP: ":8080",
		},
		Database: DatabaseConfig{
			Driver: "postgres",
		},
		Log: LogConfig{
			Level: "info",
		},
		Action: ActionConfig{
			Mode:                  "observe",
			XDropNarrowPct:        80,
			XDropMinSamplePackets: 1000,
			XDropTopKPct:          80,
			XDropTopKMax:          8,
			XDropAdaptiveSamples:  false,
			FastPathMultiplier:    5.0,
		},
		Detection: DetectionConfig{
			HardThresholdConfirmSeconds:    3,
			DynamicThresholdConfirmSeconds: 5,
			ExpiryIntervalSeconds:          300,
			ExpiryFunction:                 "static",
			ExpiryScaleBaseSeconds:         300,
			ExpiryMaxScale:                 4.0,
			MaxActiveAttacks:               10000,
		},
		Retention: RetentionConfig{
			TSStatsDays:          7,   // 7 days of time-series data (default)
			TSStatsCompressDays:  1,   // compress after 1 day (default)
			TSStatsCaggDays:      90,  // 90 days of aggregated data (default)
			FlowLogsDays:         7,   // 7 days of flow logs (compressed)
			FlowLogsCompressDays: 1,   // compress after 1 day
			AttacksDays:          90,  // 90 days of attack history
			AuditLogDays:         180, // 180 days of audit trail
			IntervalHours:        24,  // run cleanup once per day
		},
		Ring: RingConfig{
			MaxPointsPerIP:  120, // 2min — realtime detection only
			MaxIPsPerPrefix: 10_000,
			MaxGlobalKeys:   100_000,
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Action.XDropNarrowPct < 1 || cfg.Action.XDropNarrowPct > 100 {
		return nil, fmt.Errorf("action_engine.xdrop_narrow_pct must be between 1 and 100")
	}
	if cfg.Action.XDropTopKPct < 1 || cfg.Action.XDropTopKPct > 100 {
		return nil, fmt.Errorf("action_engine.xdrop_topk_pct must be between 1 and 100")
	}
	if cfg.Action.XDropTopKMax < 1 || cfg.Action.XDropTopKMax > 8 {
		return nil, fmt.Errorf("action_engine.xdrop_topk_max must be between 1 and 8")
	}
	if cfg.Action.FastPathMultiplier < 0 || (cfg.Action.FastPathMultiplier > 0 && cfg.Action.FastPathMultiplier < 1) {
		return nil, fmt.Errorf("action_engine.fast_path_multiplier must be 0 (disabled) or >= 1, got %v", cfg.Action.FastPathMultiplier)
	}
	// TLS: fail fast at startup rather than at the first node handshake. A
	// controller that boots with enabled=true but a missing/unreadable CA
	// would otherwise accept TCP and reject every node afterwards, which is
	// indistinguishable from a node-side misconfiguration in the field.
	if cfg.TLS.Enabled {
		if _, err := tlsconf.ServerConfig(tlsconf.FileConfig{
			CAFile:           cfg.TLS.CAFile,
			CertFile:         cfg.TLS.CertFile,
			KeyFile:          cfg.TLS.KeyFile,
			ServerName:       cfg.TLS.ServerName,
			AllowLegacyTLS12: cfg.TLS.AllowLegacyTLS12,
		}); err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		if cfg.TLS.AllowLegacyTLS12 {
			log.Printf("WARN tls: allow_legacy_tls12=true — TLS 1.3 floor relaxed; harden once the middlebox is removed")
		}
	}

	return cfg, nil
}

// RingEstimateBytes accounts for 240-byte DataPoints in both ring directions.
func RingEstimateBytes(c *Config) int64 {
	return int64(c.Ring.MaxGlobalKeys) * int64(c.Ring.MaxPointsPerIP) * 240 * 2
}

func (c *Config) validate() error {
	if c.Database.DSN == "" {
		return fmt.Errorf("database.dsn is required")
	}
	switch c.Database.Driver {
	case "postgres", "sqlite":
	default:
		return fmt.Errorf("database.driver must be 'postgres' or 'sqlite', got %q", c.Database.Driver)
	}
	switch c.Action.Mode {
	case "observe", "auto":
	default:
		return fmt.Errorf("action_engine.mode must be 'observe' or 'auto', got %q", c.Action.Mode)
	}
	if key := strings.TrimSpace(c.Auth.APIKey); key == "" || key == "CHANGE_ME" {
		return fmt.Errorf(`auth.api_key is empty or still the default "CHANGE_ME"; set a unique value before starting`)
	}
	if password := c.Auth.InitialAdminPassword; password != "" {
		if password == "admin" || len(password) < 8 || len(password) > 72 {
			return fmt.Errorf(`auth.initial_admin_password must be 8 to 72 bytes and must not be "admin"`)
		}
	}
	// Retention validation
	if c.Retention.TSStatsDays < 0 {
		return fmt.Errorf("retention.ts_stats_days must be >= 0, got %d", c.Retention.TSStatsDays)
	}
	if c.Retention.TSStatsCompressDays < 0 {
		return fmt.Errorf("retention.ts_stats_compress_days must be >= 0, got %d", c.Retention.TSStatsCompressDays)
	}
	if c.Retention.TSStatsCaggDays < 0 {
		return fmt.Errorf("retention.ts_stats_cagg_days must be >= 0, got %d", c.Retention.TSStatsCaggDays)
	}
	if c.Retention.FlowLogsDays < 0 {
		return fmt.Errorf("retention.flow_logs_days must be >= 0, got %d", c.Retention.FlowLogsDays)
	}
	if c.Retention.FlowLogsCompressDays < 0 {
		return fmt.Errorf("retention.flow_logs_compress_days must be >= 0, got %d", c.Retention.FlowLogsCompressDays)
	}
	if c.Retention.TSStatsChunkDays < 0 {
		return fmt.Errorf("retention.ts_stats_chunk_days must be >= 0, got %d", c.Retention.TSStatsChunkDays)
	}
	if c.Retention.FlowLogsChunkDays < 0 {
		return fmt.Errorf("retention.flow_logs_chunk_days must be >= 0, got %d", c.Retention.FlowLogsChunkDays)
	}
	if c.Retention.AttacksDays < 0 {
		return fmt.Errorf("retention.attacks_days must be >= 0, got %d", c.Retention.AttacksDays)
	}
	if c.Retention.AuditLogDays < 0 {
		return fmt.Errorf("retention.audit_log_days must be >= 0, got %d", c.Retention.AuditLogDays)
	}
	// Expiry function validation
	switch c.Detection.ExpiryFunction {
	case "static", "dynamic":
	default:
		return fmt.Errorf("detection.expiry_function must be 'static' or 'dynamic', got %q", c.Detection.ExpiryFunction)
	}
	if c.Detection.ExpiryFunction == "dynamic" {
		if c.Detection.ExpiryScaleBaseSeconds < 60 {
			return fmt.Errorf("detection.expiry_scale_base_seconds must be >= 60, got %d", c.Detection.ExpiryScaleBaseSeconds)
		}
		if c.Detection.ExpiryMaxScale < 1.0 || c.Detection.ExpiryMaxScale > 10.0 {
			return fmt.Errorf("detection.expiry_max_scale must be between 1.0 and 10.0, got %.1f", c.Detection.ExpiryMaxScale)
		}
	}
	if v := c.Detection.ManualExpireHoldSeconds; v != nil && (*v < 0 || *v > 86400) {
		return fmt.Errorf("detection.manual_expire_hold_seconds must be between 0 and 86400, got %d", *v)
	}
	// Ring config validation — prevent accidental memory explosion
	if c.Ring.MaxPointsPerIP < 10 {
		return fmt.Errorf("ring.max_points_per_ip must be >= 10, got %d", c.Ring.MaxPointsPerIP)
	}
	if c.Ring.MaxPointsPerIP > 600 {
		return fmt.Errorf("ring.max_points_per_ip must be <= 600 (10min max), got %d — ring is for realtime only, use ts_stats for long history", c.Ring.MaxPointsPerIP)
	}
	if c.Ring.MaxIPsPerPrefix < 100 {
		return fmt.Errorf("ring.max_ips_per_prefix must be >= 100, got %d", c.Ring.MaxIPsPerPrefix)
	}
	if c.Ring.MaxIPsPerPrefix > 50000 {
		return fmt.Errorf("ring.max_ips_per_prefix must be <= 50000, got %d", c.Ring.MaxIPsPerPrefix)
	}
	if c.Ring.MaxGlobalKeys < 1000 {
		return fmt.Errorf("ring.max_global_keys must be >= 1000, got %d", c.Ring.MaxGlobalKeys)
	}
	if c.Ring.MaxGlobalKeys > 500000 {
		return fmt.Errorf("ring.max_global_keys must be <= 500000, got %d", c.Ring.MaxGlobalKeys)
	}
	// Confirmation needs at least this many retained data points.
	if n := max(1, c.Detection.HardThresholdConfirmSeconds, c.Detection.DynamicThresholdConfirmSeconds); n > c.Ring.MaxPointsPerIP {
		return fmt.Errorf("detection confirm seconds (hard %d / dynamic %d) must be <= ring.max_points_per_ip %d — confirmation needs that many points of history", c.Detection.HardThresholdConfirmSeconds, c.Detection.DynamicThresholdConfirmSeconds, c.Ring.MaxPointsPerIP)
	}
	// Memory estimate: MaxGlobalKeys × MaxPointsPerIP × ~80 bytes
	estMB := int64(c.Ring.MaxGlobalKeys) * int64(c.Ring.MaxPointsPerIP) * 80 / (1024 * 1024)
	if estMB > 8192 {
		return fmt.Errorf("ring: estimated memory %dMB exceeds 8GB limit (reduce max_global_keys or max_points_per_ip)", estMB)
	}
	return nil
}
