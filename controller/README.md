# xSight Controller

Management plane for xSight -- the XDP/eBPF-based DDoS detection and response system.

The Controller provides a REST API, gRPC ingestion endpoint, real-time detection engine, automated response system, and an embedded Vue 3 Web UI. It receives per-IP and per-prefix traffic statistics from one or more xSight Nodes (XDP or flow mode), performs threshold and dynamic baseline detection, tracks attack lifecycles, and triggers automated responses via xDrop, BGP blackhole, webhooks, or shell scripts.

## Architecture

```
                  +-----------+
  xSight Node --- | gRPC :50051 | --- StatsWriter ---> Ring Buffer (in-memory)
  (XDP/Flow)      +-----------+                              |
                                                  +----------+-----------+
                                                  |                      |
                                              DBWriter               Detector (1s tick)
                                                  |                      |
                                              ts_stats              ThresholdExceeded
                                          (PostgreSQL +                  |
                                           TimescaleDB)          AttackTracker (state machine)
                                                                         |
                                                                  ActionEngine
                                                              (xDrop / BGP / Webhook / Shell)
```

### Core Components

| Package | Description |
|---------|-------------|
| `ingestion` | gRPC server, StatsWriter (ring buffer feeder), DBWriter (ts_stats persistence), NodeState (connection tracking), SampleWorkerPool, FlowWriter |
| `store/ring` | Ring buffers for per-IP and per-prefix traffic guarded by a single RWMutex; readers copy the latest point under the lock. Serves real-time threshold detection at 1-second granularity |
| `store/postgres` | PostgreSQL + TimescaleDB store. Hypertables for ts_stats and flow_logs with automatic compression and retention |
| `engine/threshold` | Threshold Tree (template inheritance) + Detector (hard threshold evaluation per tick). Supports PPS, BPS, and percentage-of-total units |
| `engine/baseline` | EWMA dynamic baseline calculator. ProfileEngine learns hourly traffic profiles (168 weekly slots) and detects anomalies using progressive deviation |
| `engine/classifier` | Attack type classifier using sampled packet data (SYN flood, UDP amplification, etc.) |
| `engine/dedup` | Alert deduplication to prevent duplicate attack records for the same target |
| `tracker` | Attack lifecycle state machine -- confirmation window, active tracking, dynamic expiry, crash recovery from DB |
| `action` | Response execution engine. Supports four action types (xDrop filter/rate-limit, BGP blackhole via FRR/vtysh, webhook HTTP calls, shell scripts) with preconditions, trigger phases, run modes, and execution logging. v1.2 adds the Action State Layer (bgp_announcements + xdrop_active_rules + scheduled_actions) as single source of truth; v1.2.1 adds xDrop decoder compatibility gate |
| `api` | Gin-based REST API with JWT + API key authentication. Full CRUD for all configuration entities, plus the unauthenticated `/metrics` endpoint |
| `metrics` | Prometheus instrumentation (v1.2.1). Inline counters for vtysh ops / action dispatches / skips / recovery outcomes; custom collectors for BGP / xDrop / scheduled-action state gauges; attack tracker wrapper. Installed once as a `store.Store` decorator so metrics are a side effect of the DB write |
| `configpub` | Config Publisher -- configuration changes except users/nodes, plus force-remove and orphan operations, use the publication path to increment enabled-node versions and re-push, with drift detection |
| `retention` | Automatic data cleanup. TimescaleDB policies remove ts_stats / flow_logs chunks; plain tables are cleaned by row. Expired ended attacks are deleted with execution logs and state rows, while unfinished state retains the attack; old audit entries are also removed |
| `watchdog` | Readiness needs `Type=notify`; heartbeats also need `WatchdogSec=`. Shipped units use `Type=simple` |

## Web UI

The web console uses Vue 3 + TypeScript + Vite, custom controls, SVG charts and vue-i18n. It is embedded into the Go binary at compile time.

Appearance has three modes: **Auto / Light / Dark**. Fonts are **IBM Plex Sans / Mono**.

The UI supports English and Chinese. Development details are in the [console README (Chinese)](console/README.md).

## Build

### Prerequisites

- Go 1.25+
- Node.js 22.12+ to build; 22.22.2+ or 24.15+ to run the console tests; npm

### Steps

```bash
# Build frontend
cd console
npm ci
npm run build
cd ..

# Build controller binary (embeds console/dist)
go build -o bin/xsight-controller .
```

Outside a git checkout, set `XSIGHT_VERSION` before `npm run build`; `./scripts/build-controller.sh` builds the console first, then Go with `-buildvcs=false -trimpath`, and falls back to `unknown` when a Git version is unavailable.

Or use the Makefile:

```bash
make build    # Go binary only (assumes console/dist already built)
make proto    # Regenerate protobuf (requires protoc + Go gRPC plugins)
make migrate  # Run database migrations and exit
```

`make migrate` requires `console/dist` and `controller/config.yaml` first; `make proto` uses GNU `sed -i` and is not compatible with macOS/BSD sed.

### Database Setup

PostgreSQL 15+ with TimescaleDB 2.x is required for automatic chunk compression and retention policies.

```bash
sudo -u postgres psql -c "CREATE USER xsight WITH PASSWORD 'YOUR_DB_PASSWORD';"
sudo -u postgres createdb -O xsight xsight
sudo -u postgres psql -d xsight -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
```

BGP announcement/attachment backfills run only when bgp_announcements is first created, in the same transaction; xDrop and override backfills still run every startup as state-write failure fallbacks. Legacy webhooks copy only when webhook_connectors is first created, also in the table-creation transaction. Before upgrading, a previous version containing these gate tables and backfills must have successfully completed migration after any relevant failure; an earlier database migrations complete log alone is insufficient.

Upgrading the v7 `ts_stats_5min` aggregate to v8 adds `avg_tcp_syn_bps` by rebuilding it: 5-minute aggregates older than 7 days are deleted, and startup synchronously backfills only the last 7 days from available raw data (a fixed window, independent of `ts_stats_days`). Shorter raw retention can leave less history to rebuild. Pre-upgrade raw rows have `tcp_syn_bps = 0`. See [CHANGELOG](../CHANGELOG.md) for all upgrade notes.

Migrations run automatically on startup. Use `-migrate` flag to run migrations only:

```bash
./bin/xsight-controller -config config.yaml -migrate
```

## Configuration

Before the first normal startup, set `auth.initial_admin_password` to a unique 8–72 byte password other than `admin`. An empty user table requires it to create the enabled `admin` account. `-migrate` alone does not require it. Sign in with that configured password, then remove the field after successful initialization.

For an existing database, configure it before upgrading if any admin-role account still uses the legacy default password. Startup rotates only those passwords, including renamed and disabled admins, and preserves their other fields. Without this setting, such accounts prevent startup. Previously changed passwords are never overwritten. Existing users must sign in again after this upgrade.

Copy `config.example.yaml` and edit:

```yaml
listen:
  grpc: ":50051"           # Node gRPC ingestion
  http: ":8080"            # Web UI + REST API

database:
  driver: "postgres"
  dsn: "postgres://xsight:PASSWORD@localhost:5432/xsight?sslmode=disable"

auth:
  api_key: "CHANGE_ME"    # REST API key (X-API-Key header). Generate: openssl rand -hex 32
                           # Also derives the JWT signing key: changing it signs out all sessions.
  initial_admin_password: ""   # first admin password, see above

action_engine:
  mode: "observe"          # "observe" (default, safe) skips xDrop dispatch with
                           # skip_reason=mode_observe. Set to "auto" to enable
                           # automated xDrop blocking. BGP/webhook/shell are
                           # NOT gated by this setting.
  xdrop_narrow_pct: 80             # keep a {dominant_*}/{src_ip} field at this sample share
  xdrop_min_sample_packets: 1000   # minimum sampled packets before narrowing (0 = no check)
  xdrop_topk_pct: 80               # top-K port rules: cumulative share to cover
  xdrop_topk_max: 8                # max rules per action (1-8; 1 = no top-K)

detection:
  hard_threshold_confirm_seconds: 3      # consecutive breach seconds before attack declared
  dynamic_threshold_confirm_seconds: 5
  expiry_interval_seconds: 300           # seconds of no breach before attack expires
  expiry_function: "static"              # "static" | "dynamic" (scales by attack duration)
  expiry_scale_base_seconds: 300         # dynamic expiry scale base
  expiry_max_scale: 4.0                  # maximum scale multiplier
  # manual_expire_hold_seconds: 300     # hold after a manual expire (0 = none, max 86400); omitted = expiry_interval_seconds clamped to 0–86400
  max_active_attacks: 10000
  dry_run: false                         # detect but don't create attack records

ring:
  max_points_per_ip: 120      # per-IP history depth (default 120 = 2 min at 1s)
  max_ips_per_prefix: 10000   # max tracked IPs per prefix
  max_global_keys: 100000     # total tracked IPs globally

retention:
  ts_stats_days: 7             # raw 5s stats
  ts_stats_compress_days: 1    # compress chunks older than N days (TimescaleDB)
  ts_stats_cagg_days: 90       # 5min aggregation (chunk size auto: N/7 days rounded down, min 1 day; 0 = chunk size unchanged)
  ts_stats_chunk_days: 0       # 0 = auto chunk size
  flow_logs_days: 7            # flow_logs (compressed)
  flow_logs_compress_days: 1
  flow_logs_chunk_days: 0
  attacks_days: 90             # ended attack records
  audit_log_days: 180          # config change audit trail
  interval_hours: 24           # cleanup frequency
```

For ts_stats_days, flow_logs_days and ts_stats_cagg_days, 0 removes the table retention policy and keeps data indefinitely; each *_compress_days = 0 independently removes its compression policy. Removal failures log WARNING and startup continues. Removing retention cannot restore deleted data, and removing compression does not decompress existing chunks.

See `config.example.yaml` for the full reference with inline comments. Unknown or misspelled keys are silently ignored, and `database.driver` supports only `postgres`.

## Running

```bash
./bin/xsight-controller -config config.yaml
```

The controller will:
1. Connect to PostgreSQL and run migrations
2. Start the gRPC server on `:50051` for node connections
3. Start the HTTP server on `:8080` for the Web UI and REST API
4. Begin the 1-second detection tick loop
5. Start the retention cleaner on the configured schedule
6. Signal systemd readiness with `Type=notify`; heartbeats also require `WatchdogSec=`, while shipped units use `Type=simple`

A pprof debug endpoint runs on `127.0.0.1:6060` (localhost only).

**Prometheus metrics** are exposed at `GET /metrics` on the HTTP listener (unauthenticated — rely on network-level isolation). See [User Guide § 5.1 Metrics](../docs/user-guide.md#51-metrics) for the metric catalogue.

## Directory Structure

```
controller/
  main.go                  # Entry point, wiring
  embed_console.go         # go:embed for console/dist
  config.example.yaml
  Makefile
  console/                 # Vue 3 + TypeScript web console source
    src/
    dist/                  # Built frontend (embedded)
  internal/
    config/                # YAML config loader
    pb/                    # Generated protobuf (gRPC service)
    ingestion/             # gRPC handler, StatsWriter, DBWriter, NodeState, FlowWriter
    store/                 # Store interfaces
      postgres/            # PostgreSQL implementation (migrations, queries)
      ring/                # In-memory ring buffer (per-IP, per-prefix)
    engine/
      threshold/           # Threshold tree + detector
      baseline/            # EWMA calculator + ProfileEngine (168-slot weekly)
      classifier/          # Attack type classification
      dedup/               # Alert deduplication
    tracker/               # Attack lifecycle state machine
    action/                # Response execution (xDrop, BGP, webhook, shell) + v1.2 Action State Layer
    metrics/               # Prometheus instrumentation (v1.2.1)
    api/                   # REST API handlers + router + /metrics endpoint
    configpub/             # Config push to nodes via gRPC
    retention/             # Data retention cleaner
    netutil/               # IP/prefix formatting utilities
    watchdog/              # systemd sd_notify integration
```
