# xSight Node

Data plane agent for the xSight DDoS detection system. The Node captures network traffic -- either via XDP/eBPF packet capture from mirror/ERSPAN ports, or by receiving flow data (sFlow/NetFlow/IPFIX) -- and reports aggregated statistics to the Controller over gRPC.

## Dual Mode Architecture

### XDP Mode (default)

Attaches an XDP/eBPF program to mirror or ERSPAN interfaces to capture packets at line rate in the kernel. The BPF program parses each packet, classifies it by decoder type, updates per-IP and per-prefix statistics maps, and samples selected packets to a userspace ring buffer.

**XDP Pipeline:**

```
Packet in (mirror/ERSPAN)
  -> Parse Ethernet/IP/Transport headers
  -> Extract 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
  -> Classify decoder (TCP / TCP_SYN / UDP / ICMP / FRAG / ...)
  -> LPM trie lookup (watch_trie_a/b): match dst_ip (inbound) / src_ip (outbound)
  -> Update ip_stats_a/b or src_stats_a/b (per-IP counters)
  -> Update prefix_stats_map / src_prefix_stats_map (per-prefix counters)
  -> Update global_stats (total counters)
  -> Probabilistic sample -> ring buffer (samples)
  -> XDP_DROP (mirror port, no forwarding; ARP/NDP exception below)
```

ARP and IPv6 NDP (ICMPv6 133–137, including a single VLAN tag) use `XDP_PASS`.

**BPF Maps:**

| Map | Type | Description |
|-----|------|-------------|
| `global_stats` | Array | Total counters: total_pkts, total_bytes, matched_pkts, matched_bytes, per-decoder breakdown (inbound and outbound) |
| `watch_trie_a` / `watch_trie_b` | LPM Trie | Prefix list pushed from the Controller. An A/B pair: a new list is written to the inactive side and then switched in. Used for the dst_ip / src_ip match in the fast path |
| `prefix_stats_map` | Hash | Per-prefix inbound counters: pkt_count, byte_count, decoder counts, active_ips, overflow_count |
| `ip_stats_a` / `ip_stats_b` | Hash | Per-destination-IP inbound counters (size set by `bpf.max_entries`). An A/B pair that switches together with the watch trie |
| `src_stats_a` / `src_stats_b` | Hash | Per-source-IP outbound counters, A/B pair like `ip_stats_*` |
| `src_prefix_stats_map` | Hash | Per-prefix outbound counters |
| `active_slot` | Array | Which A/B set (trie and IP maps) is active |
| `xsight_config` | Array | Runtime settings written by userspace (e.g. sample rate) |
| `samples` | Ring buffer (`BPF_MAP_TYPE_RINGBUF`) | Sampled packet headers sent to userspace |

### Flow Mode

Receives sFlow, NetFlow v5/v9, or IPFIX flow records via UDP using [goflow2](https://github.com/netsampler/goflow2). The Node decodes flow protocol messages, extracts 5-tuple + TCP flags, classifies each record by decoder type, and aggregates per-IP statistics before reporting to the Controller.

**Flow Pipeline:**

```
Flow record in (sFlow/NetFlow/IPFIX over UDP)
  -> goflow2 auto-detect protocol + decode
  -> Extract 5-tuple + TCP flags from FlowMessage
  -> Classify decoder (TCP / TCP_SYN / UDP / ICMP / FRAG / ...)
  -> Prefix trie lookup: match dst_ip (inbound) / src_ip (outbound) against watch_prefixes
  -> Aggregate into per-IP + per-prefix stats (RecordTable)
  -> Every 1s: flush stats -> gRPC StatsReport
```

Configure flow listeners and sources as an admin on the Controller Web UI’s **Flow** page (DETECTION → Flow; title: Flow configuration), using Add Listener and Add source, rather than in the local config file.

## gRPC Streams

The Node is a **gRPC client** that connects to the Controller. It exposes no REST API; besides optional pprof, Flow mode binds UDP flow-listener ports configured by the controller. Three streams are used; `CriticalEventStream` is reserved in the protocol but not opened:

| Stream | Direction | Interval | Purpose |
|--------|-----------|----------|---------|
| `StatsStream` | Node -> Controller | 1s | Aggregated per-IP/prefix stats, health metrics, top flows |
| `SampleStream` | Node -> Controller | Batched | Raw packet header samples from BPF ring buffer (XDP mode only) |
| `CriticalEventStream` | Node -> Controller | — | Reserved, not used. The Node never opens it |
| `ControlStream` | Bidirectional | On change | Controller pushes WatchConfig (prefixes, flow listeners; hard thresholds are stored but unused); Node ACKs with delivery_version |

See [API.md](API.md) for full gRPC message type documentation.

**Security:** the gRPC link is plaintext and the Controller accepts statistics by the `node_id` in each message after that node's first successful handshake, so run Nodes and the Controller only on a trusted network or inside an encrypted tunnel. See [API.md — Security Considerations](API.md#security-considerations).

## Build

The Node is built for **Linux x86_64** in both modes (bpf2go runs with `-target amd64`). Requirements:

- Linux 5.18+ to run XDP mode (the XDP program uses `bpf_xdp_load_bytes`); verified on Debian 13 / kernel 6.12
- Go 1.24+, `clang`, `llvm-strip`, `bpftool` and libbpf headers (e.g. `libbpf-dev`)
- `bpf/vmlinux.h`, which is not in the repository. Generate it on a host with BTF:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

Then:

```bash
# Generate BPF Go bindings (bpf2go)
go generate ./internal/bpf/

# Build the binary
go build -o bin/xsight-node .
```

Or use the Makefile:

```bash
make all        # generate + build
make generate   # bpf2go only
make build      # generate + go build
make clean      # remove artifacts
```

### Flow Mode

Flow mode uses the same binary, and a Linux build always compiles the BPF loader, so building a Linux binary for flow mode also needs `go generate` and the toolchain above, including when cross-compiling from macOS. Only a native non-Linux build (for example on macOS for development) uses the stub `internal/bpf/stub_notlinux.go` and skips BPF generation.

## Configuration

All XDP interfaces in one node must have identical `mode`, `sample_bytes`, and
`upstream_sample_rate` after defaults are applied. Heterogeneous settings are
rejected at startup and reload; use separate nodes for different settings.
`sample_bytes` may be omitted and defaults to 256.

In XDP mode, SIGHUP reloads `sample_bytes` and `upstream_sample_rate`. The new
upstream rate is bound to subsequent collection ticks; queued reports keep their
own rate. Sample batches follow the latest Stats report processed by the reporter.
Changing interface mode, the interface set or names, collection mode (`xdp`/`flow`),
`node_id`, the controller address, `parse_workers`, `bpf.max_entries`,
`auth.node_api_key`, or `pprof` requires a restart. SIGHUP mode changes are
rejected. Interface set/name changes are not applied: appending a homogeneous
interface can report reload success without attaching XDP to that interface.

Flow-mode nodes terminate immediately on SIGHUP; they do not support this reload
path. The supplied systemd unit uses `Restart=on-failure`, which does not restart
the node after SIGHUP termination. Use an explicit service restart for flow-mode
configuration changes.

For ERSPAN Type II samples in `erspan` mode, attribution follows the first IP
layer after decapsulation, including inner IPv6 under outer IPv4. Type I and
Type III sample attribution is unverified. Collection mode remains fixed for the
process lifetime.

Before the first start, register the node on the Controller (Web UI **Nodes → Add Node** or `POST /api/nodes`; select Mode = Flow for Flow nodes) with its `node_id` and an API key. `auth.node_api_key` must be that same key; it is not the Controller's REST `auth.api_key`. Unregistered nodes are rejected with `node not found`, a wrong key with `invalid api_key`.

In XDP mode, hosts with more than 32 CPU cores must explicitly set `parse_workers` (1–16).

Copy `config.example.yaml` and edit:

```yaml
# XDP mode (default)
mode: xdp
node_id: "my-node-01"

interfaces:
  - name: "eth1"
    mode: "mirror"              # mirror | erspan
    upstream_sample_rate: 1     # 1 = no upstream sampling
    sample_bytes: 128           # capture length (128-512)

bpf:
  max_entries: 1000000          # ip_stats map size

controller:
  address: "controller:50051"

auth:
  node_api_key: "CHANGE_ME"    # the key registered for this node_id on the Controller

# Optional tuning (xdp mode only)
# parse_workers: 4             # default = NumCPU/2, range 1-16
# pprof: false                 # pprof on 127.0.0.1:6061
```

```yaml
# Flow mode
mode: flow
node_id: "my-flow-node-01"

controller:
  address: "controller:50051"

auth:
  node_api_key: "CHANGE_ME"
```

In flow mode, `interfaces` and `bpf` sections are not needed. Admins manage flow listeners and sources on the Flow page (DETECTION → Flow), and `ControlStream` pushes them to the Node.

## Permissions

- **XDP mode** requires root or `CAP_BPF` + `CAP_NET_ADMIN` capabilities. The BPF program is attached to the network interface.
- **Flow mode** needs permission to bind UDP ports (typically no special capabilities unless binding to privileged ports < 1024). Note that `scripts/node.sh` refuses to start without root in either mode; run the binary directly to avoid that.

## Directory Structure

```
node/
  main.go                     # XDP mode entrypoint
  flow_main.go                # Flow mode entrypoint
  config.example.yaml
  Makefile
  bpf/
    xsight.c                  # XDP/eBPF C program
    xsight.h                  # BPF struct definitions
  internal/
    bpf/                      # BPF loader, Go type mirrors, bpf2go generated code
      gen.go                  # go:generate directive for bpf2go
      loader.go               # Load + attach XDP program, map operations
      types.go                # Go structs mirroring BPF C structs
      stub_notlinux.go        # Build stub for non-Linux platforms
    config/                   # YAML config loader + validation
      config.go               # Config struct, Load(), validate()
      snapshot.go             # WatchConfig snapshot persistence (survive restarts)
    collector/                # Periodic BPF map reader (XDP mode)
      collector.go            # Reads the active stats maps and global_stats every 1s
    sampler/                  # Packet sample pipeline (XDP mode)
      sampler.go              # BPF ring buffer reader
      batcher.go              # Batch samples for gRPC SampleStream
      packet.go               # Packet header parser (5-tuple extraction)
      flowtable.go            # Top-N flow tracking per tick
      worker_pool.go          # Parallel packet parse workers
    flow/                     # Flow receiver pipeline (Flow mode)
      listener.go             # UDP listener using goflow2
      decoder.go              # FlowMessage -> 5-tuple + decoder classification
      aggregator.go           # Per-IP/prefix stats aggregation + 1s flush
      record.go               # Flow record types
      recordtable.go          # Per-IP record table for aggregation
      prefixtrie.go           # In-memory prefix trie for watch_prefixes matching
    reporter/                 # gRPC client: handshake + streams
      reporter.go             # Stream lifecycle, reconnect, backoff
      convert.go              # Collector Report -> protobuf StatsReport conversion
    watchdog/                 # Health monitoring
      watchdog.go             # Detects degraded state (ring overflow, map full)
    pb/                       # Generated protobuf + gRPC stubs
      xsight.pb.go
      xsight_grpc.pb.go
```
