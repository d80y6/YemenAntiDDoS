# xSight Getting Started

This guide takes a first-time operator from source code to a running controller and node that sees traffic. It is the only installation guide; the [User Guide](docs/user-guide.md) explains detection and response in depth, and the [Architecture Guide](docs/architecture.md) explains how the pieces work inside.

xSight has two programs:

- **Controller** — central server: Web UI, REST API, gRPC ingestion from nodes, detection, attack tracking and response actions. Stores data in PostgreSQL with TimescaleDB.
- **Node** — agent at each observation point, in one of two modes:
  - **XDP mode** — an eBPF/XDP program counts packets on a mirror (SPAN) or ERSPAN interface.
  - **Flow mode** — receives sFlow / NetFlow v5 / NetFlow v9 / IPFIX from routers and switches.

The steps, in order: prerequisites → build → database → controller first start → register the node → node configuration and start → verify → let xDrop actions execute (`auto`).

Examples use documentation addresses: the controller is `192.0.2.10`, watched networks are `198.51.100.0/24` and `2001:db8::/32`.

---

## 1. Prerequisites

| Item | Requirement |
|---|---|
| CPU architecture (node, XDP mode) | x86_64 only: the BPF bindings are generated with `bpf2go -target amd64` |
| Linux kernel (node, XDP mode) | 5.18 or later, with BTF (`/sys/kernel/btf/vmlinux` present). The XDP program uses the `bpf_xdp_load_bytes` helper. Verified on Debian 13 with kernel 6.12. |
| Go | 1.25 or later (the controller module requires 1.25; the node module requires 1.24) |
| Node.js | 22.12+ to build; 22.22.2+ or 24.15+ to run the console tests |
| BPF build tools (node) | `clang`, `llvm`, libbpf headers and `bpftool` (Debian packages: `clang llvm libbpf-dev bpftool`) |
| Database | PostgreSQL 15+ with the TimescaleDB 2.x extension. SQLite is **not** supported: `driver: sqlite` passes config validation but the controller exits with `SQLite driver not yet implemented`. |
| Privileges (node) | root. XDP attach needs `CAP_NET_ADMIN` and `CAP_BPF`; `scripts/node.sh` refuses to start without root in either mode. |
| Optional | FRR with `bgpd` for BGP actions; XDrop v3 for xDrop actions |

The node is a Linux program in both modes. Flow mode does not attach XDP, but the node still imports the BPF package, so a Linux build of the node needs the generated BPF bindings even for Flow mode (see §2.2).

---

## 2. Build

### 2.1 Controller

The Web UI is embedded into the controller binary (`//go:embed all:console/dist`), so build the frontend first; `go build` fails without `controller/console/dist`.

```bash
cd controller/console
npm ci
npm run build
cd ..
go build -o bin/xsight-controller .
cd ..
```

Outside a git checkout, set `XSIGHT_VERSION` before `npm run build`; `./scripts/build-controller.sh` builds the console first, then Go with `-buildvcs=false -trimpath`, and falls back to `unknown` when a Git version is unavailable.

### 2.2 Node

The BPF program includes `vmlinux.h`, which is tracked in the repository (generated for Debian 13 / kernel 6.12). Regenerate it only when building on a different kernel with BTF, then generate the Go bindings and build:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > node/bpf/vmlinux.h

cd node
go generate ./internal/bpf/    # bpf2go: compiles bpf/xsight.c, writes internal/bpf/xsight_x86_bpfel.*
go build -o bin/xsight-node .
cd ..
```

`make build` in `node/` runs `go generate` and then `go build`. `./scripts/build-node.sh` does the same and checks that you are on Linux with clang installed.

Run these steps on Linux for **both** modes. Without the generated files a Linux build fails, because `internal/bpf/loader.go` (Linux only) refers to them. Only a non-Linux build (for example on macOS for development) uses the stub and skips BPF.

---

## 3. Database

Install PostgreSQL and TimescaleDB with your distribution's or Timescale's packages, then create the database, the extension and a user:

```bash
sudo -u postgres psql -c "CREATE USER xsight WITH PASSWORD 'YOUR_DB_PASSWORD';"
sudo -u postgres createdb -O xsight xsight
sudo -u postgres psql -d xsight -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
```

Create the extension as the `postgres` superuser as shown. The controller also runs `CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE` at startup; if that fails it logs `WARNING: TimescaleDB not available` and continues with plain tables, which is not a supported setup.

Tables, hypertables, compression and retention policies are created automatically on the controller's first start. `xsight-controller -config <file> -migrate` runs only the migrations and exits.

**Optional PostgreSQL tuning.** xSight writes time-series rows continuously. For a dedicated database host, these `postgresql.conf` settings reduce write load (size the memory values to your host):

```ini
synchronous_commit = off      # a crash can lose the last moment of statistics
shared_buffers = 4GB          # about 25% of RAM
effective_cache_size = 12GB   # about 75% of RAM
wal_buffers = 64MB
max_wal_size = 4GB
min_wal_size = 1GB
wal_compression = on
wal_level = minimal           # only if you do not replicate this database
max_wal_senders = 0           # required together with wal_level = minimal
```

Restart PostgreSQL after editing.

---

## 4. Controller: configure and first start

```bash
cp controller/config.example.yaml controller/config.yaml
```

Edit at least these keys:

```yaml
database:
  driver: "postgres"
  dsn: "postgres://xsight:YOUR_DB_PASSWORD@localhost:5432/xsight?sslmode=disable"

auth:
  api_key: "REPLACE_WITH_RANDOM_SECRET"        # e.g. openssl rand -hex 32
  initial_admin_password: "REPLACE_WITH_STRONG_PASSWORD"

action_engine:
  mode: "observe"        # default: xDrop actions are only logged as skipped; see §8
```

| Key | Required | Rule |
|---|---|---|
| `database.dsn` | yes | must not be empty |
| `auth.api_key` | yes | must not be empty or `CHANGE_ME`. It is the REST API key (header `X-API-Key`, full admin rights) and also the base of the session-signing secret, so changing it signs every user out. |
| `auth.initial_admin_password` | on first start | 8–72 bytes and not `admin`. If the user table is empty and this is not set, the controller refuses to start (`no users exist; set auth.initial_admin_password to create the first admin`). With it set, the controller creates the user **`admin`** with this password. Remove the key after the first successful start. |
| `listen.http` / `listen.grpc` | no | defaults `:8080` (Web UI + REST API + `/metrics`) and `:50051` (node gRPC) |

Upgrading an older database: if any admin-role account still has the old default password, startup refuses to run until `auth.initial_admin_password` is set; the controller then replaces that password. After such an upgrade every user signs in again.

Unknown or misspelled keys are ignored without a warning, so check spelling carefully. The full key list is in `controller/config.example.yaml`.

Start the controller:

```bash
./controller/bin/xsight-controller -config controller/config.yaml
```

A successful start logs `xsight-controller running (mode=observe)`. Open `http://192.0.2.10:8080` and sign in as `admin` with the configured password.

---

## 5. Register the node in the Web UI

The controller accepts a node only if it was registered first. In the Web UI open **Nodes → Add Node** and enter:

- **Node ID** — a unique name, for example `node-a`.
- **API Key** — a secret for this node only (for example `openssl rand -hex 32`). It is **not** the controller's `auth.api_key`.
- **Mode** — XDP or Flow (the node reports its actual mode when it connects).

---

## 6. Node: configure and start

```bash
cp node/config.example.yaml node/config.yaml
```

XDP mode:

```yaml
node_id: "node-a"                 # exactly the Node ID registered in §5
interfaces:
  - name: "eth1"                  # mirror / ERSPAN interface
    mode: "mirror"                # mirror | erspan
controller:
  address: "192.0.2.10:50051"
auth:
  node_api_key: "THE_KEY_REGISTERED_FOR_node-a"
```

Flow mode:

```yaml
node_id: "node-b"
mode: "flow"                      # omitted = xdp
controller:
  address: "192.0.2.10:50051"
auth:
  node_api_key: "THE_KEY_REGISTERED_FOR_node-b"
```

`auth.node_api_key` must equal the API key registered for this `node_id`. Otherwise the controller rejects the handshake with `node not found` or `invalid api_key`, and the node logs `reporter: handshake rejected: ...` and keeps retrying.

Start the node as root:

```bash
sudo ./node/bin/xsight-node -config node/config.yaml
# or: sudo ./scripts/node.sh start
```

A Flow node receives nothing until you add a Flow Listener and Flow Sources for it in the Web UI (**Flow**); see the User Guide.

---

## 7. Verify

1. Node log shows `reporter: handshake accepted`.
2. **Nodes** shows the node as **Online** (a report arrived in the last 10 seconds).
3. Add a watch prefix (**Watch Prefixes → Add Prefix**, e.g. `198.51.100.0/24`). The controller pushes it to the node; **Nodes** shows the config status as Synced.
4. **Traffic Overview** and **Dashboard** show traffic for the prefix within a few seconds.
5. Optional API check: `curl -H "X-API-Key: YOUR_API_KEY" http://192.0.2.10:8080/api/stats/summary` returns JSON.
6. Optional metrics check: `curl -s http://192.0.2.10:8080/metrics | grep ^xsight_`. `/metrics` has no authentication; restrict port 8080 at the network level.

To detect attacks you still need a threshold template bound to the prefix; the User Guide's quick tour walks through it.

---

## 8. Let xDrop actions execute (`observe` → `auto`)

`action_engine.mode` defaults to `observe`, and it gates **only xDrop actions**. In `observe`, BGP, webhook and shell actions **already execute** as configured, while every xDrop action is skipped and logged with `skip_reason=mode_observe`, so no XDrop rule is created. Keep `observe` while you check detection against real traffic (and bind BGP actions only when you want them to run). To let xDrop actions create rules, set:

```yaml
action_engine:
  mode: "auto"
```

and restart the controller. Operator Force Remove from the Web UI works in both modes.

---

## 9. Run as services (systemd)

Unit templates are in `deploy/`. They expect the layout `/opt/xsight/controller/` and `/opt/xsight/node/` (binary in `bin/`, `config.yaml` next to it); edit `ExecStart` and `WorkingDirectory` if yours differs.

```bash
# The controller unit runs as user "xsight", with only /opt/xsight/controller writable.
sudo useradd --system --home /opt/xsight --shell /usr/sbin/nologin xsight
sudo cp deploy/xsight-controller.service deploy/xsight-node.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now xsight-controller
sudo systemctl enable --now xsight-node      # runs as root, LimitMEMLOCK=infinity
```

Logs go to the journal: `journalctl -u xsight-controller -f`, `journalctl -u xsight-node -f`.

If you use BGP actions, the controller's user must be able to run `vtysh` (path set per BGP connector, default `/usr/bin/vtysh`).

---

## 10. Network and security notes

| Port | Who connects | Notes |
|---|---|---|
| TCP 8080 | browsers, API clients, Prometheus | Web UI, REST API, unauthenticated `/metrics` |
| TCP 50051 | nodes | Node gRPC. Plaintext by default — enable mutual TLS (`tls.enabled: true` on both sides) to upgrade to TLS 1.3 with certificate-pinned node identity (see [docs/MTLS.md](docs/MTLS.md)). Without TLS, run it only on a trusted network or inside a VPN / tunnel. |
| 127.0.0.1:6060 | local only | controller pprof, always on |
| 127.0.0.1:6061 | local only | node pprof, only with `pprof: true` |

---

## 11. Quick troubleshooting

| Symptom | Likely cause |
|---|---|
| `go build` of the controller: `pattern all:console/dist: no matching files found` | Build the Web UI first (§2.1) |
| `go generate`: `vmlinux.h` not found | Generate it with `bpftool` (§2.2) |
| `go generate`: `bpf/bpf_helpers.h` not found | Install the libbpf headers (`libbpf-dev`) |
| Node build on Linux: undefined `xsightObjects` / `loadXsight` | `go generate ./internal/bpf/` was not run (needed in Flow mode too) |
| Controller exits: `auth.api_key is empty or still the default "CHANGE_ME"` | Set a unique `auth.api_key` |
| Controller exits: `initial admin: no users exist; ...` | Set `auth.initial_admin_password` (§4) |
| Controller exits: `SQLite driver not yet implemented` | Use PostgreSQL |
| Node: `Failed to load BPF` / `Failed to attach XDP to <iface>` | Not root, kernel older than 5.18, or wrong interface name |
| Node: `handshake rejected: node not found` / `invalid api_key` / `node disabled` | Register the node; use the per-node key; enable the node (§5, §6) |
| Node cannot reach the controller | Check `controller.address` and that TCP 50051 is open |

More symptoms are covered in the User Guide's troubleshooting chapter.
