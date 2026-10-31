# xSight Node gRPC Interface

The Node does **not** expose a REST API. It is a gRPC **client** that connects to the Controller's gRPC server (default port 50051). All communication flows through a single `XSightService` defined in `xsight.proto`.

## Service: `xsight.XSightService`

### RPCs

| RPC | Type | Direction | Description |
|-----|------|-----------|-------------|
| `Handshake` | Unary | Node -> Controller | Initial authentication and config exchange |
| `StatsStream` | Client streaming | Node -> Controller | Periodic aggregated traffic statistics |
| `SampleStream` | Client streaming | Node -> Controller | Packet header samples from BPF ring buffer |
| `CriticalEventStream` | Client streaming | Node -> Controller | Reserved; the current Node does not open it (see §4) |
| `ControlStream` | Bidirectional streaming | Node <-> Controller | Config push / ACK channel |

---

## 1. Handshake (Unary)

First call after TCP connection. The Node authenticates and reports its identity. The Controller responds with acceptance status and the current `WatchConfig`.

**Request: `NodeHandshake`**

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | string | Unique node identifier (from config.yaml) |
| `api_key` | string | Authentication key (from config.yaml `auth.node_api_key`) |
| `interfaces` | string[] | List of interface names being monitored |
| `agent_version` | string | Mode-specific constant: `0.7.0` for XDP, `3.0.0` for Flow; not a release version, and unused by the controller |
| `delivery_version_applied` | uint64 | Last applied config version from local snapshot (0 = none) |
| `mode` | string | `"xdp"` or `"flow"` |

**Response: `HandshakeResponse`**

| Field | Type | Description |
|-------|------|-------------|
| `accepted` | bool | Whether the Controller accepted this node |
| `reject_reason` | string | Reason for rejection (empty if accepted) |
| `watch_config` | WatchConfig | Initial configuration to apply |
| `delivery_version_current` | uint64 | Current config version on the Controller |

On acceptance the Controller always returns the full current `watch_config`, whatever `delivery_version_applied` says. The global prefixes (the IPv4 and IPv6 default routes) are never sent to Nodes. If the node's `delivery_version_current` on the Controller is still 0, it is first raised to the highest version among all nodes.

Reject reasons (`accepted=false`): `node not found` (the `node_id` is not registered), `invalid api_key` (the key differs from the one registered for this node), `node disabled`, `invalid mode: ...`, `internal error: ...`.

---

## 2. StatsStream (Client Streaming)

The Node sends a `StatsReport` message nominally every 1 second; a report covering a longer collection tick carries per-second averages. In flow mode, while connected, if nothing has been sent for at least 1 s and no report is waiting, the Node sends a heartbeat `StatsReport` with only identity, `health` and `sampling_metrics` (no `global_stats`, no IP or prefix entries); none are sent while disconnected. The Controller uses this data for DDoS detection (baseline comparison, threshold evaluation, anomaly detection).

**Message: `StatsReport`**

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | string | Node identifier |
| `interface_name` | string | Source interface name |
| `upstream_sample_rate` | uint32 | Upstream rate effective when this tick was collected (1 = no sampling) |
| `local_sample_rate` | uint32 | BPF-level sample rate the Node last wrote to the BPF map successfully (normally the rate in effect; if the startup reset to 1 fails on a reused BPF map, it can differ from the rate in effect) |
| `timestamp` | int64 | Unix epoch seconds |
| `ip_stats` | IPStats[] | Per-destination-IP inbound statistics |
| `prefix_stats` | PrefixStatsMsg[] | Per-prefix inbound aggregated statistics |
| `global_stats` | GlobalStatsMsg | Global inbound traffic counters |
| `health` | NodeHealth | Agent health status |
| `sampling_metrics` | SamplingMetrics | Ring buffer and sampling health |
| `gap_seconds` | uint32 | Data gap duration after reconnect |
| `ip_stats_truncated` | bool | True if ip_stats was truncated (too many IPs) |
| `total_active_ips` | uint32 | Total active destination IPs (before truncation) |
| `top_flows` | FlowSample[] | Top-N flows this tick (by packet count) |
| `src_ip_stats` | IPStats[] | Per-source-IP outbound statistics |
| `src_prefix_stats` | PrefixStatsMsg[] | Per-prefix outbound aggregated statistics |
| `src_ip_stats_truncated` | bool | True if src_ip_stats was truncated |
| `total_active_src_ips` | uint32 | Total active source IPs (before truncation) |

The stream returns `google.protobuf.Empty` on close.

---

## 3. SampleStream (Client Streaming)

The Node sends `SampleBatch` messages containing raw packet header samples read from the BPF ring buffer. Used by the Controller for flow fingerprinting and deep inspection. XDP mode only.

**Message: `SampleBatch`**

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | string | Node identifier |
| `interface_name` | string | Source interface name |
| `upstream_sample_rate` | uint32 | Upstream rate from the latest processed Stats collection tick; startup rate before the first Stats report |
| `local_sample_rate` | uint32 | BPF-level sample rate |
| `timestamp` | int64 | Unix epoch seconds |
| `samples` | PacketSample[] | Array of sampled packet headers |

The stream returns `google.protobuf.Empty` on close.

---

## 4. CriticalEventStream (Client Streaming)

Reserved in the protocol for urgent events; **not in use**. The current Node never opens this stream and never builds a `CriticalEvent`. A Controller that receives one only writes it to its log. The message is listed for completeness.

**Message: `CriticalEvent`**

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | string | Node identifier |
| `interface_name` | string | Source interface name |
| `timestamp` | int64 | Unix epoch seconds |
| `dst_ip` | bytes | Destination IP involved (4 or 16 bytes), if applicable |
| `event_type` | string | Event category (e.g., `"hard_threshold_exceeded"`, `"map_full"`, `"interface_down"`) |
| `counters` | map<string, uint64> | Counter snapshot at trigger time (key-value pairs) |

The stream returns `google.protobuf.Empty` on close.

---

## 5. ControlStream (Bidirectional Streaming)

Bidirectional stream for runtime configuration updates. The Controller sends `ConfigPush` messages when the watch configuration changes (prefix list, thresholds, flow listener config). The Node applies the config and responds with a `ConfigAck`.

**Message: `ControlMessage`**

Uses a `oneof payload` field:

| Variant | Type | Sender | Description |
|---------|------|--------|-------------|
| `config_push` | ConfigPush | Controller | New configuration to apply |
| `config_ack` | ConfigAck | Node | Acknowledgement of applied config |

---

## Shared Message Types

### IPStats

Per-IP traffic counters reported in `StatsReport.ip_stats` and `StatsReport.src_ip_stats`.

| Field | Type | Description |
|-------|------|-------------|
| `dst_ip` | bytes | IP address (4 bytes IPv4, 16 bytes IPv6) |
| `pkt_count` | uint64 | Total packets |
| `byte_count` | uint64 | Total bytes |
| `decoder_counts` | uint32[] | Packet counts indexed by decoder ID. Slots 0-4: TCP / TCP_SYN / UDP / ICMP / FRAGMENT. Slots 5-13: TCP_ACK / TCP_RST / TCP_FIN / GRE / ESP / IGMP / IP_OTHER / BAD_FRAGMENT / INVALID. See [`shared/decoder/decoder.go`](../shared/decoder/decoder.go) for the canonical registry. |
| `decoder_byte_counts` | uint64[] | Byte counts indexed by decoder ID |
| `small_pkt` | uint32 | Packets < 128 bytes |
| `medium_pkt` | uint32 | Packets 128-512 bytes |
| `large_pkt` | uint32 | Packets > 512 bytes |

### PrefixStatsMsg

Per-prefix traffic counters reported in `StatsReport.prefix_stats` and `StatsReport.src_prefix_stats`.

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | bytes | Network address (4 or 16 bytes) |
| `prefix_len` | uint32 | CIDR prefix length |
| `pkt_count` | uint64 | Total packets |
| `byte_count` | uint64 | Total bytes |
| `active_ips` | uint32 | Number of unique IPs within this prefix |
| `overflow_count` | uint32 | Number of IPs that exceeded per-IP map capacity |
| `decoder_counts` | uint32[] | Packet counts indexed by decoder ID |
| `decoder_byte_counts` | uint64[] | Byte counts indexed by decoder ID |

### GlobalStatsMsg

Global traffic counters reported in `StatsReport.global_stats`.

| Field | Type | Description |
|-------|------|-------------|
| `total_pkts` | uint64 | Total packets seen on the interface |
| `total_bytes` | uint64 | Total bytes seen on the interface |
| `matched_pkts` | uint64 | Packets matching watch_prefixes (inbound) |
| `matched_bytes` | uint64 | Bytes matching watch_prefixes (inbound) |
| `decoder_counts` | uint32[] | Per-decoder PPS breakdown (inbound matched only) |
| `decoder_byte_counts` | uint64[] | Per-decoder BPS breakdown (inbound matched only) |
| `src_matched_pkts` | uint64 | Outbound packets matching watch_prefixes |
| `src_matched_bytes` | uint64 | Outbound bytes matching watch_prefixes |
| `src_decoder_counts` | uint32[] | Per-decoder PPS breakdown (outbound) |
| `src_decoder_byte_counts` | uint64[] | Per-decoder BPS breakdown (outbound) |

### FlowSample

A single aggregated flow (5-tuple) from one tick, reported in `StatsReport.top_flows`.

| Field | Type | Description |
|-------|------|-------------|
| `src_ip` | bytes | Source IP (4 or 16 bytes) |
| `dst_ip` | bytes | Destination IP (4 or 16 bytes) |
| `src_port` | uint32 | Source port |
| `dst_port` | uint32 | Destination port |
| `protocol` | uint32 | IP protocol number (6=TCP, 17=UDP, 1=ICMP) |
| `tcp_flags` | uint32 | Cumulative OR of all TCP flags in this flow |
| `packets` | uint64 | Packet count |
| `bytes_total` | uint64 | Byte count |

### PacketSample

A single sampled packet header, reported in `SampleBatch.samples`.

| Field | Type | Description |
|-------|------|-------------|
| `raw_header` | bytes | Raw captured packet header bytes |
| `src_ip` | bytes | Parsed source IP |
| `dst_ip` | bytes | Parsed destination IP |
| `ip_protocol` | uint32 | IP protocol number |
| `src_port` | uint32 | Source port (TCP/UDP) |
| `dst_port` | uint32 | Destination port (TCP/UDP) |
| `packet_length` | uint32 | Original packet length on wire |
| `tcp_flags` | uint32 | TCP flags (if TCP) |
| `ip_ttl` | uint32 | IP TTL value |
| `fragment_offset` | uint32 | IP fragment offset |
| `icmp_type` | uint32 | ICMP type (if ICMP) |
| `icmp_code` | uint32 | ICMP code (if ICMP) |

### NodeHealth

Agent health status reported in `StatsReport.health`.

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | `"healthy"`, `"degraded"`, or `"unhealthy"` |
| `message` | string | Human-readable status description |

### SamplingMetrics

Ring buffer and sampling health reported in `StatsReport.sampling_metrics`.

| Field | Type | Description |
|-------|------|-------------|
| `ring_fill_ratio` | float | Current ring buffer fill ratio (0.0 - 1.0) |
| `dropped_kernel` | uint64 | Kernel-side ring buffer drops |
| `dropped_user` | uint64 | Userspace-side drops |
| `decode_error` | uint64 | Packet decode errors |
| `batch_send_latency_ms` | float | P50 latency of batch gRPC sends |
| `effective_sample_rate` | float | Sample rate after adaptive adjustment, as last written to the BPF map successfully (same startup exception as `local_sample_rate`) |

### WatchConfig

Configuration pushed from Controller to Node (via Handshake response or ControlStream ConfigPush).

| Field | Type | Description |
|-------|------|-------------|
| `prefixes` | WatchPrefix[] | List of IP prefixes to monitor |
| `hard_thresholds` | HardThresholds | Per-IP hard thresholds (stored by the Node, currently unused) |
| `flow_listeners` | FlowListenerConfig[] | Flow listener config (flow mode only, ignored by XDP nodes) |

### WatchPrefix

A single IP prefix in the watch list.

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | bytes | Network address (4 or 16 bytes) |
| `prefix_len` | uint32 | CIDR prefix length |
| `name` | string | Human-readable label |

### HardThresholds

The Controller sends the lowest value among all enabled `over` rules with domain `internal_ip`, separately for `pps` and `bps` (1,000,000 pps / 10,000,000,000 bps when there is none). The current Node only keeps them in its local snapshot and does not act on them.

| Field | Type | Description |
|-------|------|-------------|
| `pps` | uint64 | Per-IP packets/sec threshold |
| `bps` | uint64 | Per-IP bits/sec threshold |

### ConfigPush

Sent by Controller to Node via ControlStream.

| Field | Type | Description |
|-------|------|-------------|
| `watch_config` | WatchConfig | New configuration to apply |
| `delivery_version_current` | uint64 | Config version number |

### ConfigAck

Sent by Node to Controller via ControlStream after applying a ConfigPush.

| Field | Type | Description |
|-------|------|-------------|
| `delivery_version_applied` | uint64 | Version number that was applied |
| `success` | bool | Whether the config was applied successfully |
| `error_message` | string | Error details if success=false |

### FlowListenerConfig

Flow listener configuration pushed to flow-mode Nodes.

| Field | Type | Description |
|-------|------|-------------|
| `listen_address` | string | UDP bind address (e.g., `":6343"`, `":2055"`) |
| `protocol_mode` | string | `"auto"`, `"sflow"`, `"netflow"`, or `"ipfix"` |
| `sources` | FlowSourceConfig[] | Registered exporter devices |
| `enabled` | bool | Whether this listener is active |

### FlowSourceConfig

A single flow exporter device on a listener.

| Field | Type | Description |
|-------|------|-------------|
| `device_ip` | string | Exporter IP address (matched against UDP source) |
| `sample_mode` | string | `"auto"` (use record's rate), `"force"` (override), or `"none"` (rate=1) |
| `sample_rate` | int32 | Override sample rate (used when sample_mode=`"force"`) |
| `name` | string | Human-readable display name |
| `enabled` | bool | Whether this source is active |

---

## Connection Lifecycle

```
Node starts
  -> Load config.yaml
  -> Load WatchConfig snapshot (if exists)
  -> Dial Controller gRPC (with reconnect backoff)
  -> Handshake (send node_id, api_key, delivery_version_applied)
  -> If accepted:
       -> Apply WatchConfig from HandshakeResponse (when nonempty)
       -> Open StatsStream (sends every 1s)
       -> Open SampleStream (XDP mode, sends batches)
       -> (CriticalEventStream is reserved and not opened)
       -> Open ControlStream (receives ConfigPush, sends ConfigAck)
  -> On disconnect: backoff + reconnect + re-Handshake
```
After a connection attempt lasts at least 30 seconds, the reconnect backoff resets to 1 second.

## Authentication

The Node sends `api_key` in the `Handshake` message. The Controller looks up `node_id` among the registered nodes and compares the key with the `api_key` registered for that node (`POST /api/nodes`). This is not the Controller's REST `auth.api_key`. A node must therefore be registered on the Controller before it can connect.

The streaming RPCs carry no credentials of their own:

- `StatsStream`, `SampleStream` and `CriticalEventStream` check each message's self-reported `node_id`: it is accepted if that node has completed a Handshake with this Controller process at any time since the process started. The check is not tied to the TCP connection, and the entry is not removed when the node disconnects or is later disabled. Otherwise the stream fails with `Unauthenticated` `handshake required`.
- `ControlStream` is mapped to a node by the remote address recorded at Handshake time. A stream from an unknown address is accepted but receives no config pushes.

### Security Considerations

- **Plaintext transport.** The Node dials with insecure credentials and the Controller's gRPC server has no TLS. `api_key`, statistics and samples cross the network unencrypted, and the key is compared as a plain string.
- **Identity is self-reported.** After any successful Handshake for a `node_id`, any client that can reach the gRPC port can send statistics or samples under that `node_id`.
- **Deploy only on a trusted network.** Run the Controller-Node link inside a trusted management network or an encrypted tunnel (for example WireGuard or IPsec), and restrict the gRPC port (default 50051) to the Nodes' addresses with a firewall. Do not expose it to the Internet.
