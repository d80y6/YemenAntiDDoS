# xSight Architecture Guide

> How xSight works inside: components, data flow, state machines, storage and the security model. It is written for contributors and operators who need to reason about behaviour. Installation is in [Getting Started](../GETTING_STARTED.md); configuration and daily operation are in the [User Guide](user-guide.md).

---

## Contents

1. [Components and Data Flow](#1-components-and-data-flow)
2. [Node](#2-node)
3. [Controller Detection Pipeline](#3-controller-detection-pipeline)
4. [Action Engine](#4-action-engine)
5. [State and Storage](#5-state-and-storage)
6. [Security Model](#6-security-model)
7. [Known Limitations](#7-known-limitations)

---

## 1. Components and Data Flow

### Overview

```
  Node (XDP)  ──┐                    Controller
                │ gRPC   ┌──────────────────────────────────────────────────────────┐
  Node (Flow) ──┼──────▶ │ ingestion ─▶ ring buffers ─▶ detection ─▶ tracker         │
                │        │     │                       (static +      │            │
                │        │     ▼                        dynamic)      ▼            │
                │        │ ts_stats / flow_logs                  action engine     │
                │ ◀───── │ config publisher                  BGP · xDrop · webhook │
                │  push  │ REST API + Web UI + /metrics            · shell       │
                │        └──────────────────────────────────────────────────────────┘
```

1. A **node** counts traffic per destination IP, per source IP and per watched prefix (XDP mode), or aggregates flow records (Flow mode), and sends one statistics report per second over gRPC.
2. The controller's **ingestion** layer writes each report into in-memory **ring buffers** (real-time detection) and batches it into the `ts_stats` table (charts, baselines). Flow summaries go to `flow_logs`.
3. Every second, **detection** compares ring data with static threshold rules and, when enabled, with dynamic baseline profiles.
4. Breaches pass alert de-duplication and feed the **attack tracker**, which confirms, keeps alive and ends attacks.
5. Tracker events are queued to the **action engine**, which resolves the response, applies the dispatch gates and runs BGP (FRR `vtysh`), xDrop (XDrop v3 REST API), webhook and shell actions.
6. When prefixes, thresholds or flow listeners change, the **config publisher** pushes a new watch configuration to the nodes.

### Node ↔ Controller Protocol

Nodes connect to the controller's gRPC port (default `:50051`). The service has five RPCs:

| RPC | Type | Use |
|---|---|---|
| `Handshake` | unary | Node ID + per-node API key check; returns the full watch configuration |
| `StatsStream` | client stream | one statistics report per second (the detection input) |
| `SampleStream` | client stream | packet samples from XDP mode, used for attack classification and flow summaries |
| `CriticalEventStream` | client stream | defined in the protocol but **not used**: the node never sends on it; the controller only logs what it receives |
| `ControlStream` | bidirectional | configuration push (controller → node) and acknowledgement (node → controller) |

The full message reference is in [node/API.md](../node/API.md).

### Code Map

| Area | Controller (`controller/internal/`) | Node (`node/internal/`) |
|---|---|---|
| Transport | `ingestion` (gRPC server, report queues) | `reporter` (gRPC client, reconnect with back-off) |
| Data | `store/ring`, `store/postgres`, `retention` | `collector` (BPF map reads), `sampler`, `flow` |
| Logic | `engine/threshold`, `engine/baseline`, `engine/classifier`, `engine/dedup`, `tracker`, `action` | `bpf` (generated bindings + loader) |
| Interface | `api` (REST + embedded Web UI), `configpub`, `metrics` | `config` (YAML + last-config snapshot) |

Decoder names and indexes are shared by both programs through `shared/decoder/decoder.go`.

---

## 2. Node

### XDP Mode

The XDP program (`node/bpf/xsight.c`) is attached to every configured interface. All interfaces of one node share one BPF configuration, so `mode`, `sample_bytes` and `upstream_sample_rate` must be identical across them. In `erspan` mode the program decapsulates GRE/ERSPAN and counts the inner packet.

For each packet the program:

1. Parses Ethernet (with one VLAN tag), IPv4/IPv6 and the L4 header.
2. Looks up the destination (inbound) and source (outbound) address in an LPM trie of watched prefixes. Packets outside every watched prefix only update global counters.
3. Updates per-IP, per-source-IP and per-prefix counters: packets, bytes and a fixed array of 16 decoder counters (the slots of `shared/decoder/decoder.go`).
4. Copies up to `sample_bytes` of a sampled packet into a ring buffer for the user-space sampler.

BPF maps (from `node/bpf/xsight.h`): `global_stats` (array), `watch_trie_a/b` (LPM tries), `ip_stats_a/b` and `src_stats_a/b` (hash), `prefix_stats_map` and `src_prefix_stats_map` (hash), `active_slot` and `xsight_config` (array) and `samples` (ring buffer). The `_a/_b` pairs are double buffers for configuration changes: a new watch-prefix set is written into the idle trie and maps, then `active_slot` switches over, so packets never see a half-written prefix set. Every second the collector reads the cumulative counters and reports the differences.

Stopping the node leaves the XDP program and its pinned maps in place under `/sys/fs/bpf/xsight/`, so a restart resumes counting. `xsight-node -config <file> -unload` detaches XDP and removes the pins. `SIGHUP` reloads `sample_bytes` and `upstream_sample_rate`; changing the mode or the interfaces needs a restart.

### Flow Mode

The node listens for sFlow v5, NetFlow v5/v9 and IPFIX on UDP listeners that are configured in the controller (Web UI **Flow**), not in the node's file. Listeners and sources arrive with the watch configuration. Only records from registered, enabled sources are used; others are counted as unknown exporters. Each source has a sample mode: `auto` (use the rate in the record), `force` (use the configured rate) or `none` (rate 1). Flow mode produces the same per-second statistics, but no packet samples, so the sample-based attack classifier does not run. An idle Flow node sends a heartbeat report every second and stays online.

### Reporting

Every second the node sends a `StatsReport` with per-destination-IP, per-source-IP and per-prefix statistics, global counters, top flows and health/sampling metrics. The node keeps the last applied watch configuration in `/var/lib/xsight/<node_id>/last_config.json` and loads it at startup, so it counts traffic before the controller is reachable.

---

## 3. Controller Detection Pipeline

### Ingestion

The gRPC handler accepts reports only from a node ID that has completed a handshake (see §6). Reports wait in a small per-stream queue; when it is full, the oldest report is dropped. The ring writer stores one data point per second per key; invalid prefixes or addresses are dropped with a rate-limited warning. The database writer flushes `ts_stats` every 5 seconds; flow summaries go to `flow_logs`. A node counts as online while its last report is less than 10 seconds old.

### Static Thresholds

A threshold tree maps each watched prefix to its effective rules (template rules plus inherited parent rules). Each tick, `subnet` rules are compared with the prefix aggregate and `internal_ip` rules with each IP of the prefix, per node and per direction (`receives` = destination, `sends` = source). Breaches pass de-duplication: an active attack on a more specific decoder suppresses a new broader attack for the same IP and direction (for example, an active `tcp` attack suppresses a new `ip` attack).

### Dynamic Detection

Dynamic detection is prefix-level, inbound only, and off by default (`dynamic_detection_config.enabled`).

- **Profile.** For each (node, prefix) there are 168 weekly slots (hour of the week, UTC). Once per hour, the 95th percentile PPS and BPS of the hour that just ended are folded into that slot by EWMA (`ewma_alpha`); each slot takes at most one sample per ISO week.
- **Threshold.** `expected × (100 + deviation) / 100`, where `deviation` (a percentage) shrinks linearly from `deviation_max` to `deviation_min` as the slot's sample count goes from 0 to `stable_weeks`. A slot is used after its first sample.
- **Floor.** Traffic is ignored only when **both** PPS < `min_pps` and BPS < `min_bps`. Above the floor, exceeding either the PPS or the BPS threshold is a breach.
- **Confirmation.** A dynamic breach becomes an `ip`/`subnet`/`receives` event and needs `dynamic_threshold_confirm_seconds` consecutive points.

Separately, a baseline calculator computes P95 × 3 over the last hour for each prefix. That value is only shown as a **recommended static threshold** (`GET /api/baseline`); it is not used for detection.

### Attack Tracker

```
 (no attack) ──breach──▶ Confirming ──N consecutive points──▶ Active ◀──re-breach──┐
      ▲                       │ point missing: discard              │               │
      │                                                   no breach │               │
      │                                                             ▼               │
      └──────────────────────── Expired ◀──expiry timer ends── Expiring ────────────┘
```

| State | Meaning |
|---|---|
| Confirming | Breach seen. N = `hard_threshold_confirm_seconds` (static) or `dynamic_threshold_confirm_seconds` (dynamic) consecutive breaching per-second points confirm it; one missing second is tolerated. |
| Active | Confirmed. Stored in `attacks`; `on_detected` actions run. Every 5 minutes an `updated` event is sent (used by periodic actions). |
| Expiring | Traffic below threshold. Timer = `expiry_interval_seconds`, or with `expiry_function: dynamic`, that value × clamp(attack duration / `expiry_scale_base_seconds`, 1, `expiry_max_scale`). A re-breach returns to Active and cancels pending BGP withdraw delays. |
| Expired | Ended; `ended_at` is set and `on_expired` actions run. |

Severity is assigned at confirmation from peak values: critical (> 1 Mpps or > 10 Gbps), high (> 100 kpps or > 1 Gbps), medium (> 10 kpps or > 100 Mbps), otherwise low.

When `max_active_attacks` is reached, a new attack replaces the lowest-priority Active or Expiring attack only if it strictly outranks it (severity first; at equal severity an Expiring attack ranks lower; then peak PPS); the replaced attack is **evicted** and, if it was Expiring, runs its `on_expired` actions early. Otherwise the new attack stays Confirming and is counted as suppressed. Ring capacity (`max_ips_per_prefix`, `max_global_keys`) protects keys of Active and Confirming attacks when it has to drop keys.

A manual expiry (`POST /api/attacks/:id/expire`) may leave an in-memory hold for the same target, decoder and direction (`manual_expire_hold_seconds`); a controller restart clears it.

In XDP mode, a classifier refines the type of inbound UDP attacks from packet samples (for example `dns_reflection` when source port 53 dominates).

### Configuration Delivery

1. Responses, actions, preconditions, templates, prefixes, thresholds, connectors, Flow configuration and force-remove/orphan operations use the publication path to increment enabled nodes’ **delivery version** and re-push; users and nodes use direct audit instead.
2. The controller builds a `WatchConfig` (prefixes, per-IP hard thresholds, flow listeners for Flow nodes) and pushes it on each node's `ControlStream`. The global prefix is never sent to nodes; it is evaluated from global counters.
3. The node applies it and returns a `ConfigAck`.
4. Each node has a `config_status` of `synced`, `pending` or `failed` and a **drift** (current version − applied version). `failed` means the node reported that applying the current version failed; a push that could not be sent leaves the node `pending`.

---

## 4. Action Engine

### Response Resolution

Tracker events enter a FIFO queue; one dispatcher handles them in order.

- **Inbound (`receives`)**: the triggering rule's `response_id`, otherwise the prefix template's default response.
- **Outbound (`sends`)**: only the rule's own `response_id`; there is no fallback to the template default, which usually contains blocking actions meant for inbound traffic.
- No response, or a disabled response: only global webhooks are notified. Global webhooks are also notified after every dispatch.

### Dispatch Gates

Actions are sorted by `(trigger_phase, priority)` and pass these gates in order. Gates that write an execution-log row use `status=skipped` and a `skip_reason`.

1. **Enabled and phase.** `on_detected` matches `confirmed`, `type_upgrade` and `updated` events (run mode `once` ignores `updated`); `on_expired` matches `expired` and `evicted`.
2. **Run mode.** `once` runs once per attack and phase; `retry_until_success` runs again on later events until one attempt has succeeded; both log `already_executed` when skipped. `periodic` also runs on each `updated` event (about every 5 minutes).
3. **Preconditions.** All must match (`precondition_not_matched`).
4. **Mode.** With `action_engine.mode: observe` every xDrop action is skipped (`mode_observe`). BGP, webhook and shell are not gated and execute in both modes.
5. **Execution = manual.** Skipped silently (no log row); there is no trigger for manual actions yet.
6. **Outbound guard.** For non-ended outbound attacks, xDrop and BGP are skipped (`outbound_block_forbidden`).
7. **First match.** For xDrop, BGP and shell, only the first action of each type that reaches this point runs (`first_match_suppressed`); all webhooks run.
8. **xDrop decoder gate.** `ip` and `ip_other` attacks are skipped for xDrop (`decoder_not_xdrop_compatible`).

### Auto-Paired Actions

Creating an xDrop or BGP action with `trigger_phase: on_detected` also creates a matching `on_expired` child (xDrop unblock / BGP withdraw). The parent stores `paired_with = child.id`; the child has `auto_generated = true` and cannot be edited directly. Updates, enable/disable and delete of the parent propagate to the child, with application-level compensation if the child operation fails.

### BGP Execution

A BGP route is a shared, reference-counted resource keyed on `(prefix, route_map, connector_id)` in `bgp_announcements`, with one row per attached attack in `bgp_announcement_attacks`.

- **Attach** (`on_detected`): under a row lock, the first attack inserts the announcement (`announcing`) and runs `vtysh`: `configure terminal` → `router bgp <ASN>` → `address-family ipv4|ipv6 unicast` (chosen from the prefix) → `network <prefix> route-map <name>`; success makes it `active`. Later attacks only increase `refcount` and do not call `vtysh`. Host attacks are announced as /32 or /128; subnet attacks as their prefix.
- **Detach** (`on_expired`): decreases `refcount`. At 0 the announcement becomes `delayed` (if the delay is > 0) or `withdrawing`, then `no network …` makes it `withdrawn`. The delay is the **maximum** `bgp_withdraw_delay_minutes` of all attacks attached in the current announce cycle.
- **Business key** in logs: `external_rule_id = <prefix>|<route_map>`.
- **Orphans**: at startup the controller lists the BGP tables of enabled connectors; routes without a matching announcement are stored as `orphan`, and the operator withdraws or dismisses them from the Web UI.
- **Reconciliation**: `announcing` rows are checked against FRR with read-only commands after two minutes; stuck `withdrawing` and failed rows with no remaining attachments are retried under an announcement lock. Each `vtysh` call has a 60-second deadline.

### xDrop Execution

- **Authentication and ownership:** xDrop v3 uses a Bearer machine credential (one per xSight instance). Each create carries `claim_ref = a<attack>.x<action>`; holders sharing the same rule identity share its rule ID. xSight does not send `expires_in`; it releases only its own hold, and xDrop deletes the rule after its last holder releases it.
- **Create** (`on_detected`, `filter_l4` / `rate_limit`): success needs HTTP 200/201 and a non-empty `id`, stored as `external_rule_id` in `action_execution_log` and `xdrop_active_rules`. Any other result is recorded as failed with a synthetic `failed-create-<attack>-<action>` ID, which is not a remote rule ID.
- **Payload normalization:** only v3 rule fields are sent; empty values and unknown fields are dropped. The protocol follows the attack's decoder (see the table below). Anomaly rules use `match_anomaly` and carry no protocol. When no TCP flags are given, TCP-flag decoders add their canonical flags.
- **Narrowing and fallback:** the template fields `{src_ip}`, `{dominant_dst_port}` and `{dominant_src_port}` (the Src IP / Dst Port / Src Port checkboxes) only **permit** narrowing. Flow samples are first filtered by the attack's protocol and TCP flags. A field is kept only if there are at least `xdrop_min_sample_packets` samples and its top value has at least `xdrop_narrow_pct` % of them; if both ports qualify, only the source port is kept. If nothing narrows the rule, no literal condition is left, the action is `drop` and the decoder is not `fragment` or an anomaly, the rule is turned into `rate_limit` at the triggering rule's PPS value; when there is no such PPS rule (for example a BPS rule or a dynamic-detection attack), the drop is sent without narrowing.
- **Top-K rules:** when a permitted port's top value is below `xdrop_narrow_pct` but the top 2..K ports (K ≤ `xdrop_topk_max`) together reach `xdrop_topk_pct` % of the samples, one dispatch creates K rules, one per port, all with the same `claim_ref`. The source port is tried first and wins when it needs fewer rules. `xdrop_topk_max: 1` disables this.
- **Shaping notes:** decisions are written to the execution log's `error_message` on success without changing the status, e.g. `shape: kept src_port=92%`, `shape: samples 120 < 1000`, `shape: fallback rate_limit=500000`, `shape: topk dst_port=3 84%`, `shape: item 1/3 dst_port=443`, as well as `dropped:` and `protocol pinned:` notes from normalization.
- **Release** (`on_expired`, unblock): each local hold is released separately. Only HTTP 204 counts as a successful remote release; 404, 200 and 3xx are failures. Releases of the same local hold (attack + action + connector + rule ID) are serialized.
- **Failed creates and late results:** after the attack ends, recoverable failed-create evidence is checked with a read-only `POST /rules/batch?validate=1` (no second create); a matching remote rule is released. Unrecoverable evidence may close the local record without a remote release. A successful create that arrives after the local withdrawal is followed by a release attempt; failure is counted as `late_create_leak`.
- **Reconciliation:** right after startup recovery and then every 2 minutes, records in `active` / `delayed` / `withdrawing` / `failed` and due `xdrop_unblock` schedules are re-checked. Live attacks, future schedules, manual overrides and disabled connectors are skipped. Failed releases back off for 2 / 4 / 8 / 16 minutes. Outcomes are counted in `xsight_xdrop_reconcile_total`.
- **Accepted versus delivered:** `active` means the XDrop controller accepted the rule. Per-node delivery is looked up on demand and describes the configured rule generation, not measured packet hits.

### xDrop Decoder Mapping

| Decoder | xDrop | Rule match |
|---|---|---|
| `tcp` | yes | `protocol=tcp` |
| `tcp_syn` | yes | `protocol=tcp` + `tcp_flags=SYN,!ACK` |
| `tcp_ack` | yes | `protocol=tcp` + `tcp_flags=ACK,!SYN` |
| `tcp_rst` | yes | `protocol=tcp` + `tcp_flags=RST` |
| `tcp_fin` | yes | `protocol=tcp` + `tcp_flags=FIN` |
| `udp` | yes | `protocol=udp` |
| `icmp` | yes | IPv4 `protocol=icmp`; IPv6 `protocol=icmpv6` |
| `fragment` | yes | `protocol=all`; IPv4 adds `fragment=frag` when no fragment condition is supplied |
| `gre` | yes | `protocol=gre` |
| `esp` | yes | `protocol=esp` |
| `igmp` | yes | `protocol=igmp` |
| `bad_fragment` | yes | `match_anomaly`; drop or rate_limit; xDrop rejects IPv6 |
| `invalid` | yes | `match_anomaly`; drop or rate_limit |
| `ip` | no | L3 aggregate — use BGP |
| `ip_other` | no | L3 catch-all — use BGP |

For decoders without ports, ports and TCP flags are removed before sending; anomaly rules also carry no protocol.

### Delayed Execution

Delayed BGP withdrawals and xDrop releases are persisted in `scheduled_actions`, so they survive restarts.

1. When the `on_expired` action has a delay > 0, a `pending` row is written with `scheduled_for = now + delay` and the business key `(attack_id, action_id, connector_id, external_rule_id)`; BGP rows also carry `announcement_id`.
2. When the timer fires, the row becomes `executing`, runs the removal and normally ends `completed` or `failed`. An xDrop legacy schedule with no rule row whose release did not succeed remains `executing` for runtime reconciliation; with a rule row, a failed release normally ends the schedule as `failed`.
3. For BGP, a re-breach during the delay cancels the pending rows (`cancel_reason=rebreach`). xDrop releases are scheduled only after the attack has ended; a later breach creates a new attack and does not cancel that delayed release.
4. A force removal cancels only that artifact's row (`cancel_reason=force_remove`).
5. At startup, pending rows are re-armed (future) or run at once (overdue), and rows left in `executing` are retried; outcomes are counted in `xsight_scheduled_actions_recovered_total`.

### Manual Override (Force Remove)

1. For BGP, Force Remove first commits detachment of all attached attacks, then writes their manual overrides and audit logs, and finally runs vtysh withdrawal. Every attached attack loses the shared route's protection; a failed withdrawal does not undo the recorded overrides.
2. For xDrop, Force Unblock releases the hold of this attack and action; xDrop deletes the rule after its last holder releases it. It may first wait up to one connector timeout for an automatic release in progress. A failed-create record is checked read-only first and then released or closed locally; a successful local closure does not prove that a release reached xDrop.
3. Later automatic `on_expired` processing checks `action_manual_overrides` per artifact and skips only the overridden artifact.

**Disabled BGP connectors:** routes of attacks that end while the connector is disabled are left in place. Enabling the connector again, or editing an enabled connector, sweeps its active announcements once in the background and withdraws those whose attached attacks have all ended.

**Disabled xDrop connectors:** automatic releases wait while the connector is disabled and are reconsidered by the next reconciliation round after it is enabled. New creates skip disabled targets with `connector_disabled`; if every explicitly selected target is disabled, there is no fallback to global connectors. Force Unblock is rejected while the connector is disabled.

---

## 5. State and Storage

### State Machines

Each external artifact has one state table, which is the source of truth for the Web UI and API. `action_execution_log` is an append-only audit trail and is not used to derive state.

| Table | Statuses |
|---|---|
| `bgp_announcements` | `announcing` → `active` → `delayed` / `withdrawing` → `withdrawn`; also `failed`, `orphan`, `dismissed`, `dismissed_on_upgrade` |
| `xdrop_active_rules` | `active` → `delayed` / `withdrawing` → `withdrawn`; also `failed` |
| `scheduled_actions` | `pending` → `executing` → `completed` / `cancelled` / `failed` |

Related tables: `bgp_announcement_attacks` (attachments, with each attack's delay), `bgp_announcement_events` (BGP timeline), `action_manual_overrides` (force removals).

### UI Status Derivation

The Active Mitigations page reads the state tables directly:

- **BGP section**: rows of `bgp_announcements` in `active`, `delayed` or `failed`; `orphan` rows appear in a separate banner (the query also returns `announcing` and `withdrawing`, which the API hides as transient).
- **xDrop section**: `xdrop_active_rules WHERE status IN ('active', 'delayed', 'failed')`.
- **Detail timeline**: `bgp_announcement_events` for BGP; execution-log entries plus `action_manual_overrides` for xDrop.

For BGP rows in an attack's action log, the API adds `bgp_role`: `triggered` (this attack caused the `vtysh` announce) or `attached_shared` (it joined an existing announcement).

### Startup Recovery

On start, before accepting work, the controller runs in this order:

1. Re-apply `active` / `delayed` BGP announcements to FRR.
2. Take a snapshot of scheduled work, finish interrupted BGP announce / withdraw and xDrop release work, and recover `scheduled_actions` (re-arm, run overdue, retry `executing`).
3. Release BGP attachments and xDrop holds of attacks that ended while the controller was down (`xsight_startup_cleanup_total`).
4. Restore active attacks from the database into the tracker.
5. Scan FRR for orphan routes.

Then the xDrop, BGP withdrawing and BGP announcing reconcilers start. After every ended attack, a sweep re-checks that attack's artifacts (`xsight_ended_sweep_total`).

### Storage and Retention

| Data | Table | Default retention |
|---|---|---|
| 5-second statistics | `ts_stats` (hypertable, compressed after `ts_stats_compress_days`) | `ts_stats_days`: 7 |
| 5-minute aggregates (6H / 24H charts) | `ts_stats_5min` (continuous aggregate) | `ts_stats_cagg_days`: 90 |
| Flow summaries | `flow_logs` (hypertable) | `flow_logs_days`: 7 |
| Ended attacks | `attacks` | `attacks_days`: 90 (active attacks are never deleted) |
| Configuration audit | `config_audit_log` | `audit_log_days`: 180 |

`0` keeps data forever. TimescaleDB retention and compression policies handle the hypertables; a built-in cleaner runs every `interval_hours` (default 24) for the other tables. Configuration tables (prefixes, templates, thresholds, responses, actions, preconditions, connectors, nodes, users, flow listeners/sources, dynamic detection config and profiles) are not subject to retention.

Upgrading the v7 `ts_stats_5min` aggregate to v8 adds `avg_tcp_syn_bps` by rebuilding it: 5-minute aggregates older than 7 days are deleted, and startup synchronously backfills only the last 7 days from available raw data (a fixed window, independent of `ts_stats_days`). Shorter raw retention can leave less history to rebuild. Pre-upgrade raw rows have `tcp_syn_bps = 0`. See [CHANGELOG](../CHANGELOG.md).

Deleting expired ended attacks also deletes their execution logs and related state rows; attacks with unfinished state are retained.

### Observability

`GET /metrics` exposes 23 `xsight_*` metrics plus the Go runtime and process metrics. The full catalogue, with labels and alert ideas, is in the [User Guide](user-guide.md#51-metrics); it includes `xsight_xdrop_reconcile_total` for xDrop releases and reconciliation. Metrics read from state tables are collected at scrape time with a 5-second timeout; on a query error that metric is left out of the scrape.

---

## 6. Security Model

- **REST authentication.** Every `/api` route except `POST /api/login` needs `X-API-Key: <auth.api_key>` or `Authorization: Bearer <JWT>`. The API key acts as an administrator.
- **Admin-only writes.** GET requests are allowed for any signed-in user. Every other method requires role `admin`; `viewer` and the legacy `operator` role are read-only (403).
- **Last admin.** The last enabled admin cannot be deleted, demoted or disabled (409).
- **Per-request re-check.** Each JWT request reloads the user and compares its last-modified time with the token. Deleted, disabled or modified users get 401 at once. Tokens live at most 24 hours. The signing secret is derived from `auth.api_key`, so changing the key invalidates all tokens.
- **Login rate limit.** In-memory, per 15-minute window: 5 attempts per username + source address, 20 per source address, at most 10,000 tracked keys; excess requests get 429 with `Retry-After`. The source is the TCP peer address; proxy headers are not trusted, so clients behind one NAT or reverse proxy share a limit.
- **Audit.** Configuration changes and force-remove/orphan operations write `config_audit_log` on a best-effort basis; publication skips the row if building the watch config or listing nodes fails, and audit-write errors are only logged. Manual attack expiry is not audited. Webhook header values are masked in API output and audit diffs; xDrop keys appear as `***` plus the last four characters (just `***` for keys of at most four characters). Passwords, password hashes and node API keys are not recorded.
- **`/metrics` is unauthenticated**, like other Prometheus exporters. Restrict the HTTP port at the network level.
- **gRPC is plaintext.** The node connects without TLS, and the API key is sent in the clear. A handshake checks node ID + key; after that, statistics, sample and event streams are accepted for any message that carries a node ID which has completed a handshake since the controller started, independent of the connection. `ControlStream` identifies the node by the peer address recorded at handshake. Therefore the gRPC port must be reachable only from a trusted network or through a VPN / tunnel.
- **Local debug ports.** Controller pprof is always on at `127.0.0.1:6060`; node pprof at `127.0.0.1:6061` only with `pprof: true`.

---

## 7. Known Limitations

- **Manual execution never runs.** Actions with Execution = Manual are skipped silently; there is no manual trigger in the UI or API.
- **Configuration keys are not validated strictly.** Unknown or misspelled YAML keys are ignored without a warning. `log.level`, `action_engine.xdrop_api`, `action_engine.xdrop_api_key` and `bpf.path` are read but have no effect.
- **`CriticalEventStream` is not implemented** on the node. Per-IP hard thresholds sent to nodes are stored but not used there; all detection happens in the controller.
- **gRPC has no TLS** and the report streams trust the node ID in each message (see §6).
- **SQLite is not implemented**, even though `database.driver: sqlite` passes validation.
- **XDP mode is x86_64 only** and needs Linux 5.18 or later.
- **xDrop expiry.** xSight never sets an expiry on xDrop rules. Until xDrop provides per-holder expiry, sharing a rule with another system can invalidate the expiry that system set.
- **No xDrop orphan scan.** xSight does not scan xDrop for rules it lost track of; remove those in the xDrop interface.

---

## 8. Carrier-Grade Inline Mitigation

For an in-depth specification and implementation roadmap covering wire-speed inline scrubbing (`xdp_filter`), stateless SYN cookies, sub-second burst triggers via `CriticalEventStream`, and SmartNIC offload, see [docs/INLINE-CARRIER-GRADE-AR.md](INLINE-CARRIER-GRADE-AR.md).
