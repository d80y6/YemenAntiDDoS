# Changelog

## v1.4.0 — 2026-10-31

### Upgrade notes (read first)

- Upgrading the `ts_stats_5min` aggregate from v7 to v8 deletes the existing aggregate, including all 5-minute history older than 7 days, then synchronously rebuilds a fixed 7-day window from surviving raw data at startup regardless of `ts_stats_days`; old raw rows have `tcp_syn_bps=0`, and data already removed from the raw table cannot be restored.
- Build with Node.js 22.12+ (console tests require 22.22.2+ or 24.15+), run `npm ci && npm run build` in `controller/console` before building Go, and set `XSIGHT_VERSION` for source archives without Git metadata; the legacy `controller/web` UI has been removed and the new console is embedded by default, and `scripts/build-controller.sh` supplies a Git-derived version or `unknown`.
- Set a unique `auth.api_key` before normal startup or `-migrate`: empty, whitespace-only and placeholder values are rejected.
- The seeded default administrator is removed, so first normal startup on an empty user table requires `auth.initial_admin_password` (8–72 bytes, different from the legacy default), while `-migrate` alone does not require it.
- Existing admin-role accounts still using the legacy default password, including renamed or disabled accounts, require `auth.initial_admin_password` to rotate those passwords at startup; other passwords are preserved, and the setting should be removed after initialization.
- Both confirmation settings, `detection.hard_threshold_confirm_seconds` and `dynamic_threshold_confirm_seconds`, must fit within `ring.max_points_per_ip` or startup fails; confirmation now also requires consecutive breaching data points.
- New `action_engine` settings are `xdrop_narrow_pct=80` and `xdrop_topk_pct=80` (each 1–100), `xdrop_topk_max=8` (1–8; 1 disables top-K), and `xdrop_min_sample_packets=1000` (0 disables the minimum-sample check); out-of-range percentage or top-K limits prevent startup.
- New `detection.manual_expire_hold_seconds` accepts 0–86400 (0 disables holding), defaults to `max(0, min(expiry_interval_seconds, 86400))` when omitted, and prevents startup if outside that range.
- xDrop integration requires XDrop v3 and a dedicated machine credential per xSight instance in the connector’s `api_key`; requests use Bearer authentication and are incompatible with v2.
- Known migration limitation: let all active xDrop rules withdraw before upgrading, either by waiting for attacks to end or using **Force Unblock**, because release of v2-era rules without `claim_ref` is not established.
- On XDP nodes, every interface must use the same `mode`, `sample_bytes` and `upstream_sample_rate` at startup and reload, so split different settings into separate nodes; changing capture mode requires a restart.
- Omitted node `sample_bytes` now correctly uses 256, while the BPF capture length treats 0 as 256 and caps the length at 512 bytes.
- The controller↔node protocol is unchanged and older nodes already handshake before streaming, so a controller upgrade does not require simultaneous node replacement; node-side heartbeat, sampling, GRE/ERSPAN, IPv6, per-IP aging, reload, failed-configuration ACK and reconnect fixes require upgrading the nodes too.
- The first upgraded XDP node start cold-rebuilds BPF pins because the key encoding and ELF changed, resetting pinned counters; subsequent starts can reuse matching pins.
- Automatic migrations fix empty-database installation, add `idx_action_exec_log_attack`, add `bgp_announcements.gen` with existing rows initialized to 0, and widen `bgp_connectors.bgp_asn` from INT to BIGINT.
- Before upgrading, ensure the previous version completed migrations successfully after any earlier failure: BGP state bootstrap and legacy webhook copying now run transactionally only when their destination tables are first created, and existing BGP tables are no longer rebuilt from execution logs on every restart.
- The one-time legacy webhook copy includes headers, but legacy rows added after the connector table was created and never copied must be recreated on **Connectors**; authenticated admin/API-key writes to `/api/webhooks` now return 410, while GET remains available and non-admin writes return 403 first.
- xDrop and manual-override backfills still run at each startup, with creation phases expanded to confirmed/type_upgrade/updated and ending phases to expired/evicted, while successful manual overrides exclude the corresponding rules from active-state reconstruction.
- Startup cleans up ended attacks’ residual routes and rules (waiting up to 30 seconds for BGP withdrawal), restores every active attack, ends duplicate canonical keys through the normal expiry path while keeping the newest start, and merges host-length CIDR/per-IP identities for the same direction and decoder.
- The first retention run may delete more rows because eligible ended attacks now lose all associated log/state rows in batches of up to 10000 attacks, zero retention/compression settings remove existing policies, and cagg chunk sizing follows its retention period for new chunks only, subject to the v8 aggregate rebuild above.
- P95 recommendations and dynamic baselines now use inbound traffic only, and startup warns when the revised two-direction ring-memory estimate exceeds 8 GiB without changing the existing memory rejection threshold.
- Non-admin roles, including viewer and legacy operator, are read-only and receive 403 for writes, REST API keys retain admin access, and JWT verification accepts only HS256.
- Existing login sessions are invalidated by the upgrade: tokens issued by earlier versions are rejected, so all users must sign in again.
- Review automation for stricter writes: legacy `xdrop_api`, empty `trigger_phase`, invalid action/run modes, threshold fields, webhook methods/headers, ASN or withdrawal-delay bounds, IPv4-mapped prefixes and xDrop/BGP actions attached to outbound rules are rejected, with stored invalid values checked when next edited.
- Adjust scripts that relied on shell placeholders becoming multiple arguments (each now remains one argument, including an empty result), and account for webhook timeouts capped at 10 seconds with configured POST/PUT/PATCH methods now honored.
- Only HTTP 204 confirms an xDrop withdrawal; other responses, including 404, leave a failed withdrawal for reconciliation retries with backoff.
- Changing an xDrop connector URL requires re-entering its key, and changing a webhook URL requires resubmitting header values.

### Highlights

- The default embedded console now has grouped navigation, Chinese/English text, **Auto** / **Light** / **Dark** appearance, SVG traffic charts with keyboard readout and zoom, and a saved adjustable dashboard layout.
- xDrop v3 integration adds claim-based rule release, concentration-aware custom rules and top-K port rules.
- TCP SYN bps is now stored and returned in time-series data and can be selected in console charts.

### New

- Nine legacy console routes redirect to their replacements, and saved classic/amber appearance choices migrate to **Light** / **Dark**.
- **Add Node** can generate an API key and a node configuration snippet.
- Runtime reconciliation retries xDrop and BGP withdrawals and checks FRR to repair BGP announcing states.
- Manual attack expiry accepts a configurable hold interval through `hold_seconds` to delay reconfirmation.

### Changed

- Console attack lists use 50-row pages with active attacks ordered by peak pps, and traffic filters are saved in the URL.
- The dashboard's ended-attack table and the attack bands on dashboard / traffic charts load at most the latest 2000 attacks and show a notice when capped.
- Twelve new `xsight_*` metrics cover the action queue, state-write failures, startup cleanup, gRPC identity rejections, ring memory estimate, ended-attack sweeps, stale BGP writes, precondition lookup errors, BGP/xDrop reconciliation and config-publish failures; `max_active_attacks` now counts active and expiring attacks; response webhooks include `end_reason` on expired/evicted events.
- Actions execute through a single FIFO dispatcher outside the tracker lock with a bounded 4096-entry queue that blocks producers when full.
- Disabled parent prefixes retain inheritance, per-IP traffic belongs to the most specific prefix, and non-ending outbound attack events skip xDrop/BGP actions.
- Editing xDrop, shell and webhook connectors preserves omitted fields, while action edits preserve legacy preconditions and attempt reverse-order rollback after partial failure.

### API

- New read endpoints are `GET /api/attacks/mitigation-brief?ids=` (at most 50 IDs) and `GET /api/active-actions/xdrop/delivery`.
- Attack queries add `dst_ip`, `ended_after` and `sort=started_at|peak_pps`, time-series queries add restricted `dst_ip` filtering, total time series supports node/prefix filters, and audit queries add time ranges with a 200-row limit cap.
- Read responses add current attack rates and timer thresholds, summary action mode, per-node overview rates, last stats timestamps, node interfaces/capture data and xDrop port/rate-limit fields.
- Updating or deleting the last enabled admin in a way that would leave none now returns 409 `at least one enabled admin is required` without changing the user.
- Configuration audit diffs now include response enablement, template response bindings, action snapshots and xDrop targets, original precondition lists, and actual Flow object IDs.

### Security

- Authentication and authorization fixes cover default credentials, login abuse and enumeration, token revocation, JWT verification and API-key comparison.
- Security fixes cover command injection, credential disclosure in connector responses/logs/audits, and database error disclosure in API responses.
- Additional fixes cover node identity checks, slow HTTP headers and configuration paths that could omit required restrictions.

### Fixes

- Ended-attack cleanup now runs even when its response or actions were disabled/deleted or the engine is observing.
- Fixes address uncertain xDrop creates and concurrent removal, plus late BGP state writes that could strand announcements.
- In-flight once actions are deduplicated, execution logs survive action timeouts, and failed attack-end persistence remains queued for retry.
- Ingestion retries failed batches per node, superseded streams no longer clear newer streams, failed configuration ACKs are recorded, and configuration-publish failures are logged and counted.
- Node fixes cover applied-rate reporting and random sampling, idle Flow heartbeats, GRE offsets and inner IPv6, disjoint IPv4/IPv6 prefix keys, idle per-IP aging, live upstream-rate reload and reconnect backoff reset.
- Attack pagination is stable for equal start times and reports count-query errors, while a failed COALESCE-marker probe no longer prevents the required-column check from running.

Earlier releases: see the git history (v1.3.10 = commit `10803e2`).
