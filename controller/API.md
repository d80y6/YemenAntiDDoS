# xSight Controller API Reference

Base URL: `http://<host>:8080/api`

## Authentication

All `/api/*` endpoints (except `/api/login`) require one of:

- **API Key**: `X-API-Key: <key>` header (configured in `config.yaml` under `auth.api_key`)
- **JWT Bearer**: `Authorization: Bearer <token>` header (obtained from `/api/login`)

The REST API key is an administrator machine identity. For JWT users, only `admin` may send non-GET requests; `viewer`, legacy `operator`, and any other role are read-only. Denied writes return 403 `{"error":"admin role required"}` before the business handler runs.

A nonempty `X-API-Key` takes precedence over JWT; an invalid key returns 401 `invalid API key` even with a valid JWT. Without either authentication header, the response is 401 `missing authentication`.

JWT lifetime is at most 24 hours. Every authenticated JWT request reads the user from the database and uses the current username and role. Updating a user (including password, role, enabled state, or username), disabling or deleting the user invalidates existing tokens immediately. Database lookup failures return 503 `authentication backend unavailable`; missing, disabled, or stale users return 401 `invalid token`.

### `GET /metrics` — Prometheus scrape (unauthenticated)

Exposes Prometheus metrics for all v1.2 / v1.2.1 instrumentation (vtysh ops, action executions, action skips, scheduled-action recovery outcomes, current BGP announcements / xDrop rules / scheduled actions by status, and attack-tracker counters), plus the default Go runtime and process metrics.

**Unauthenticated by convention** (matching kube-apiserver / etcd / Prometheus itself). Rely on network-level isolation. See [User Guide § 5.1 Metrics](../docs/user-guide.md#51-metrics) for the full metric catalogue.

---

## Login

### POST /api/login

Authenticate a user and receive a JWT token.

Invalid JSON or missing required login fields returns 400 `username and password required`; token generation failure returns 500 `token generation failed`.

Unknown users, disabled accounts, wrong passwords, and login database errors all return the same 401 `{"error":"invalid credentials"}`. Login attempts use two fixed 15-minute windows: 5 per (username, source address) and 20 per source address. Only the connection's remote address is used; proxy headers are ignored. A rejected attempt returns 429 `{"error":"too many login attempts"}` with `Retry-After` in seconds. Successful login clears the username/address bucket and returns its address quota. Limits are local to one controller instance; NAT and reverse-proxy clients share the address bucket.

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | **Required.** |
| `password` | string | **Required.** |

**Response:**

```json
{
  "token": "eyJhbG...",
  "user": { "id": 1, "username": "admin", "role": "admin" }
}
```

---

## Users

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/users` | List all users |
| POST | `/api/users` | Create a user |
| PUT | `/api/users/:id` | Update a user |
| DELETE | `/api/users/:id` | Delete a user |

PUT that demotes or disables the last enabled `admin`, or DELETE of that account, returns 409 `at least one enabled admin is required`. The rejected request writes nothing, adds no audit entry, and leaves existing tokens valid. Create does not perform this check.

### Create User -- POST /api/users

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | **Required.** |
| `password` | string | **Required.** |
| `role` | string | `admin` or `viewer` (default: `viewer`). The value is not validated: any other string is stored, and every role except `admin` is read-only. |

`enabled` is not accepted on create; new users are always enabled.

### Update User -- PUT /api/users/:id

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | New username |
| `password` | string | New password. Changing it invalidates the user's existing tokens; the audit entry records `password_changed`. |
| `role` | string | `admin` or `viewer` (not validated, as on create) |
| `enabled` | bool | Enable/disable account |

Empty or omitted `username`, `role`, and `password` keep the stored values; passwords are trimmed before hashing. Every successful PUT, including `{}`, updates `updated_at` and invalidates existing tokens.

---

## Nodes

<!-- fe-q0:B9 -->
`GET /api/nodes` adds `last_stats_at` (RFC3339 timestamp) when a stats report has been seen; unknown timestamps are omitted.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/nodes` | List all nodes (enriched with `online` status) |
| POST | `/api/nodes` | Register a node |
| GET | `/api/nodes/:id` | Get node details |
| PUT | `/api/nodes/:id` | Update node |
| DELETE | `/api/nodes/:id` | Delete node (cascades to flow listeners/sources) |
| GET | `/api/nodes/:id/status` | Detailed node status (online, config drift, flow metrics) |

### Create Node -- POST /api/nodes

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | **Required.** Node identifier (e.g. `hk-mirror-01`) |
| `api_key` | string | **Required.** Shared secret for gRPC authentication |
| `description` | string | Human-readable label |
| `mode` | string | `xdp` (default) or `flow` |

New nodes are always enabled; create ignores `enabled`.

### Update Node -- PUT /api/nodes/:id

| Field | Type | Description |
|-------|------|-------------|
| `description` | string | Empty or omitted keeps the stored value; an empty string cannot clear it. |
| `mode` | string | `xdp` or `flow` |
| `enabled` | bool | |

### Node Status -- GET /api/nodes/:id/status

<!-- fe-q0:B7 -->
Optional `interfaces` lists interface names from the latest accepted handshake. Optional `capture: [{interface, upstream_sample_rate}]` lists each named interface's latest reported sampling rate, sorted by interface. The integer `upstream_sample_rate` is the rate reported by the node. Empty names are ignored. A newly accepted handshake replaces interfaces and clears capture; disconnects retain these values until the next handshake. Empty collections are omitted.

**Response** includes: `id`, `mode`, `online`, `config_status`, `delivery_version_current`, `delivery_version_applied`, `drift`, `last_ack_at`, `last_stats_at`, `stats_age_seconds`, `connected_at`, `uptime_seconds`, `flow_metrics`, `source_statuses`, `listener_statuses`.

`online` is true while the node's last stats report arrived within the last 10 seconds. An idle flow node sends a heartbeat report every second, so it stays online without traffic. In `source_statuses`, a flow source is inactive after 60 seconds without records. `config_status` is `failed` only when the node reported that applying the current, not yet applied version failed; a push that could not be sent stays `pending`. `last_ack_at` is the last successful apply.

---

## Prefixes

Watched IP prefixes (subnets) for traffic monitoring and threshold detection.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/prefixes` | List all prefixes (tree structure with parent/child) |
| POST | `/api/prefixes` | Create a watched prefix |
| GET | `/api/prefixes/:id` | Get prefix details |
| PUT | `/api/prefixes/:id` | Update prefix |
| DELETE | `/api/prefixes/:id` | Delete prefix |

### Create Prefix -- POST /api/prefixes

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | string | **Required.** CIDR notation (e.g. `198.51.100.0/24`). Use `0.0.0.0/0` for global. `::/0` is not allowed. |
| `parent_id` | int | Parent prefix ID for hierarchy |
| `threshold_template_id` | int | Assign a threshold template |
| `name` | string | Display name |
| `ip_group` | string | IP group label |

The IPv6 default route is rejected with a 400 that points to the global IPv4 prefix, and an IPv4-mapped IPv6 prefix returns **400** `Use IPv4 notation for IPv4-mapped prefixes`; both checks also apply on update.

### Update Prefix -- PUT /api/prefixes/:id

All fields optional. Supports `prefix`, `name`, `ip_group`, `parent_id`, `threshold_template_id`, `enabled`. Set `parent_id` or `threshold_template_id` to `null` to clear.

On create and update, a `0.0.0.0/0` prefix bound to a template whose default response or any rule response contains xDrop or BGP actions returns **400**. An update is checked against the prefix as it would be after the change: if it is still `0.0.0.0/0` and still bound to such a template, the update is rejected, even if it only renames the prefix. To fix an existing global prefix with such a binding, unbind the template (`threshold_template_id`: `null`) or change the template's responses.

For both create and update, a non-null `parent_id` that creates a cycle or reaches an existing cycle returns **400** with `parent_id would create a cycle`. Create and update also reject a missing parent with **400** and `parent_id not found`. Rejected requests do not write, publish configuration, or create an audit entry. Omitted or null `parent_id` does not trigger a parent-chain preflight.

---

## Threshold Templates

Reusable threshold rule sets that can be assigned to multiple prefixes.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/threshold-templates` | List all templates |
| POST | `/api/threshold-templates` | Create a template |
| GET | `/api/threshold-templates/:id` | Get template with rules and assigned prefixes: `{template, rules, prefixes_using}` |
| PUT | `/api/threshold-templates/:id` | Update template |
| DELETE | `/api/threshold-templates/:id` | Delete template (fails if in use by prefixes) |
| POST | `/api/threshold-templates/:id/duplicate` | Duplicate template with all rules |
| GET | `/api/threshold-templates/:id/rules` | List rules in this template |
| POST | `/api/threshold-templates/:id/rules` | Create a rule in this template |

### Create Template -- POST /api/threshold-templates

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `description` | string | |
| `response_id` | int | Optional default response for this template |

### Update Template -- PUT /api/threshold-templates/:id

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | |
| `description` | string | |
| `response_id` | int/null | Default response for this template. Set `null` to clear. Cannot be xDrop/BGP if assigned to global prefix. |

Omitted fields keep their stored values. A body that is not valid JSON returns **400**.

If the template has `sends` rules, assigning a default response containing xDrop/BGP actions returns 400 `Template has outbound (sends) rules — cannot use responses containing xDrop/BGP actions as default`. PUT does not reject an empty `name`.

### Duplicate Template -- POST /api/threshold-templates/:id/duplicate

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Name for the copy (default: original name + " (Copy)") |

The copy preserves the default response and every rule's response override, direction, thresholds, and enabled state in one transaction. It does not copy prefix bindings or duplicate response objects. Returns HTTP 201 `{id, name}`.

### Create Template Rule -- POST /api/threshold-templates/:id/rules

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | `internal_ip` or `subnet` (default: `internal_ip`) |
| `direction` | string | `receives` or `sends` (default: `receives`) |
| `decoder` | string | Protocol filter. Available: `ip` (L3 aggregate), `tcp`, `tcp_syn`, `udp`, `icmp`, `fragment`, `tcp_ack`, `tcp_rst`, `tcp_fin`, `gre`, `esp`, `igmp`, `ip_other`, `bad_fragment`, `invalid`. Default: `""` (all traffic). See the user guide for semantics. |
| `unit` | string | `pps` (default), `bps`, or `pct` (percentage of total). `pct` requires a specific decoder. |
| `comparison` | string | `over` or `under` (default: `over`) |
| `value` | int | For `pps`/`bps`: >= 0. For `pct`: 1-100. A template rule with `comparison=over` and `value=0` means over 0; it does not cancel inheritance. Only per-prefix overrides use 0 to cancel inheritance. A fractional value is truncated here (1.5 is stored as 1), while `POST /api/thresholds` rejects it with 400. |
| `inheritable` | bool | Whether child prefixes inherit this rule (default: `true`) |
| `response_id` | int | Optional response override for this rule |

`enabled` is not accepted on create; new rules are always enabled.

---

## Thresholds (Per-Prefix Overrides)

Per-prefix threshold rules that override or supplement template rules.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/thresholds` | List all thresholds. Filter: `?prefix_id=N` |
| POST | `/api/thresholds` | Create a per-prefix threshold |
| GET | `/api/thresholds/:id` | Get threshold details |
| PUT | `/api/thresholds/:id` | Update threshold |
| DELETE | `/api/thresholds/:id` | Delete threshold |
| PUT | `/api/threshold-rules/:id` | Update a template rule (same handler) |
| DELETE | `/api/threshold-rules/:id` | Delete a template rule (same handler) |

### Create Threshold -- POST /api/thresholds

Uses the template-rule fields, but `POST /api/thresholds` requires `unit`, `comparison`, and `domain`; these fields have no defaults here. Two other defaults also differ from template rules: omitted `inheritable` is `false`, and an omitted `direction` is stored as an empty string rather than `receives`, so send `direction` explicitly. Additional fields:

| Field | Type | Description |
|-------|------|-------------|
| `prefix_id` | int | Target prefix. Exactly one of `prefix_id` and `template_id` must be set (database constraint); for a per-prefix rule send `prefix_id`. |
| `response_id` | int/null | Override response for this rule |

All validation from template rules applies (enums, value range, direction, decoder/unit combos, global prefix constraints). Both threshold PUT routes merge supplied fields with the stored row; omitted fields keep their values. Validation applies to the merged row, including existing invalid values. A rule's owner (`template_id` / `prefix_id`) cannot be changed: values sent in a PUT are ignored and the stored owner is kept.

For both `PUT /api/thresholds/:id` and `PUT /api/threshold-rules/:id`, omitting `response_id` keeps the existing binding, explicit `null` clears it, and an integer ID replaces it.

---

## Responses

Response policies that define what actions to execute when an attack is detected or expires.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/responses` | List all responses |
| POST | `/api/responses` | Create a response |
| GET | `/api/responses/:id` | Get response with enriched actions: `{response, actions}`; each action also carries `connector_name`, `connector_id`, `target_node_ids`, `xdrop_fields`, `xdrop_rate_limit` |
| PUT | `/api/responses/:id` | Update response |
| DELETE | `/api/responses/:id` | Delete response (fails if referenced by templates or thresholds) |

### Create Response -- POST /api/responses

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `description` | string | |
| `enabled` | bool | Default: `true` |

### Update Response -- PUT /api/responses/:id

Merge update: omitted fields and `null` keep their stored values. An empty `name` returns **400** `name is required`; an empty `description` clears it.

---

## Response Actions

Actions within a response policy. Each action has a type, trigger phase, and run mode.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/responses/:id/actions` | List actions for a response |
| POST | `/api/responses/:id/actions` | Create an action |
| PUT | `/api/actions/:id` | Update an action |
| DELETE | `/api/actions/:id` | Delete an action |

### Create/Update Action

Creating or editing an xDrop/BGP action returns HTTP 400 if any `sends` rule explicitly references its response, including disabled rules and template rules not bound to a prefix. Disabling an action through PUT is subject to the same check. Global-prefix validation takes precedence. Webhook and shell actions are unaffected. To repair a historical combination, clear the rule's `response_id` or change its direction to `receives` first.

| Field | Type | Description |
|-------|------|-------------|
| `action_type` | string | **Required.** `xdrop`, `bgp`, `webhook`, or `shell`; deprecated `xdrop_api` is rejected. |
| `trigger_phase` | string | **Required.** `on_detected` or `on_expired` (otherwise 400 `trigger_phase must be on_detected or on_expired`). `on_expired` accepts only `run_mode=once` or an empty run mode. |
| `run_mode` | string | Optional: `once`, `periodic`, `retry_until_success`, or `""`. Omitted on create is stored as `""`; for `on_detected` this runs on each confirmed/type_upgrade/updated event without once-style deduplication (like periodic), while `on_expired` treats it like once. PUT omissions keep the stored value. |
| `period_seconds` | int | Interval for `periodic` run mode |
| `execution` | string | `automatic` or `manual`. Actions set to `manual` are never executed (there is no manual trigger yet); any other value, including omitted, runs automatically. |
| `priority` | int | Lower = higher priority |
| `enabled` | bool | Default: `true` |
| `connector_id` | int | **Required for webhook/shell/bgp.** Connector to use |
| `target_node_ids` | []int | xDrop connector IDs to target (xDrop type only) |
| `xdrop_action` | string | **Required for xDrop:** `filter_l4`, `rate_limit`, or `unblock` |
| `xdrop_custom_payload` | object | xDrop only: v3 rule fields, including match fields and `rate_limit`. `filter_l4` / `rate_limit` need at least one match field (`dst_ip`, `src_ip`, `dst_port`, `src_port` or `protocol`); `rate_limit` also needs a positive `rate_limit`. `{variable}` placeholders must be supported template variables; unknown names are rejected. xSight writes `claim_ref`; `source`, `expires_in`, unknown fields and empty values are dropped. Protocol follows the attack type. Normalization notes (`dropped:` / `protocol pinned:` / `shape:`) appear in successful execution logs under `error_message` without changing the status. |
| `shell_extra_args` | string | Shell only: additional arguments passed to the command. `{variable}` placeholders are validated like `xdrop_custom_payload`. |
| `unblock_delay_minutes` | int | xDrop filter_l4/rate_limit only: auto-unblock after N minutes (0-1440) |
| `bgp_route_map` | string | BGP only: **Required for on_detected.** Route-map name for blackhole injection |
| `bgp_withdraw_delay_minutes` | int | BGP only: delay before withdrawing route after attack expires (0-1440). Effective delay across multiple sharing attacks is MAX per announce cycle — see [architecture.md § BGP Execution](../docs/architecture.md#bgp-execution) |

PUT cannot change `action_type`: it returns 400 `cannot change action_type via PUT — delete this action and create a new one instead`. `bgp_route_map` accepts only letters, digits, `_`, `-`, and `.`. Deleting an auto-generated child directly returns 400; deleting its parent also deletes the paired child.

> **xDrop decoder compatibility:** xDrop actions are dispatched for attacks whose decoder is one of `tcp`, `tcp_syn`, `tcp_ack`, `tcp_rst`, `tcp_fin`, `udp`, `icmp`, `fragment`, `gre`, `esp`, `igmp`, `bad_fragment`, `invalid`. Attacks with decoder `ip` or `ip_other` are skipped with `skip_reason=decoder_not_xdrop_compatible` — use a BGP action for L3-aggregate attacks. Anomaly decoders (`bad_fragment` / `invalid`) use xDrop v3 anomaly-bit matching and support both `drop` and `rate_limit`; xDrop rejects IPv6 `bad_fragment`.

> **Auto-paired actions:** Creating any xDrop `on_detected` action (every `xdrop_action`, including `unblock`) or a BGP `on_detected` action automatically creates a matching `on_expired` child action (`unblock` / withdraw). The child cannot be edited directly; edit the parent. Creating an `xdrop` or `bgp` action with `trigger_phase=on_expired` is rejected with HTTP 400.

> **xDrop rule shaping and top-K rules:** The placeholders `{dominant_dst_port}`, `{dominant_src_port}` and `{src_ip}` allow narrowing; they do not guarantee a rule condition. A placeholder field is kept only when the attack sample has at least `action_engine.xdrop_min_sample_packets` packets (default 1000) and the dominant value covers at least `xdrop_narrow_pct` percent of it (default 80); if both ports qualify, only the source port is kept. When no single port qualifies, one action can instead expand into several rules: the top ports of one port field are taken, 2 up to `action_engine.xdrop_topk_max` of them (default 8, range 1–8; 1 disables expansion), until they cover `xdrop_topk_pct` percent of the sample (default 80), and one xDrop rule is created per port. Each of these rules has its own `external_rule_id` and its own row in `GET /api/active-actions/xdrop` and in `mitigation-summary` `xdrop_rules`; all of them belong to the same attack and action. If nothing narrows a `drop` rule and no literal match field remains, the rule falls back to `rate_limit` at the attack's pps threshold (only when that threshold rule uses `pps`). Each decision is logged as a `shape:` note, e.g. `shape: topk dst_port=3 85%`, `shape: item 1/3 dst_port=53`, `shape: dropped src_ip=12%`, `shape: fallback rate_limit=50000`.

### xDrop Targets

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/actions/:id/xdrop-targets` | Get xDrop connector IDs for an action |
| PUT | `/api/actions/:id/xdrop-targets` | Set xDrop connector IDs |

**PUT body:** `{ "connector_ids": [1, 2, 3] }`

### Preconditions

Conditional execution rules for actions.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/actions/:id/preconditions` | List preconditions |
| PUT | `/api/actions/:id/preconditions` | Replace all preconditions |

**PUT body:**

```json
{
  "preconditions": [
    { "attribute": "pps", "operator": "gt", "value": "100000" },
    { "attribute": "decoder", "operator": "eq", "value": "udp" }
  ]
}
```

Supported attributes: `cidr`, `decoder`, `attack_type`, `severity`, `pps`, `bps`, `peak_pps`, `peak_bps`, `node`, `domain`, `carpet_bomb`, `dominant_src_port`, `dominant_src_port_pct`, `dominant_dst_port`, `dominant_dst_port_pct`, `unique_src_ips`.

`carpet_bomb eq true` is a readability alias for `domain eq subnet` — matches attacks whose `DstIP` is a subnet (aggregate-at-destination pattern). Accepts `true` / `false` / `1` / `0` / `yes` / `no` (case-insensitive). Operators: `eq`, `neq`.

Supported operators: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`.

The API validates operators and values before replacing any stored conditions:

| Attribute class | Operators | Value format |
|---|---|---|
| Numeric: `cidr`, `pps`, `bps`, `peak_pps`, `peak_bps`, all `dominant_*` attributes, `unique_src_ips` | All eight | Signed base-10 int64 after trimming whitespace; `in` / `not_in` require a comma-separated list of valid, nonempty integers. |
| `decoder`, `severity`, `domain` | `eq`, `neq`, `in`, `not_in` | `eq` / `neq` require an exact allowed value without trimming. List items are trimmed and must be nonempty allowed values. Decoder uses the threshold decoder registry including `ip`; severity is `low`, `medium`, `high`, `critical`; domain is `internal_ip`, `subnet`. |
| `attack_type` | `eq`, `neq`, `in`, `not_in` | Nonempty text; no enumeration check. |
| `node` | `eq`, `in` | Both operators accept comma-separated lists; each trimmed item must be nonempty. |
| `carpet_bomb` | `eq`, `neq` | `true`, `false`, `1`, `0`, `yes`, `no`, ignoring surrounding whitespace and case. |

Invalid or empty numeric/enumerated list items are rejected with HTTP 400. Validation preserves the original stored text; it does not check numeric ranges or enumerate `attack_type`, so it does not reject every condition that may always match.

---

## Webhooks (Legacy)

Simple webhook notifications (pre-Response System v2).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/webhooks` | List all webhooks (read-only) |
| POST | `/api/webhooks` | 410 Gone |
| PUT | `/api/webhooks/:id` | 410 Gone |
| DELETE | `/api/webhooks/:id` | 410 Gone |

POST / PUT / DELETE return 410 without writes, audit entries or publication; manage global webhooks via /api/settings/webhook-connectors. Source rows accepted with 201 before upgrade but never copied by a startup will not be copied after upgrade when the connector table already exists: review GET results and recreate them manually on the connectors page.

Non-admin JWT users are rejected first with 403 `admin role required`; only admin/API-key requests reach the 410 response. Header values are masked as `******` in GET `/api/webhooks`, `/api/responses/:id`, `/api/responses/:id/actions`, and audit diffs for `webhook_connector`, `webhook`, and `response_action`.

---

## Settings -- Connectors

### Webhook Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings/webhook-connectors` | List all (header values masked as `******`) |
| POST | `/api/settings/webhook-connectors` | Create |
| GET | `/api/settings/webhook-connectors/:id` | Get (header values masked as `******`) |
| PUT | `/api/settings/webhook-connectors/:id` | Merge update: omitted fields and scalar `null` keep their values. Merged name and URL must be nonempty. A header value sent back as `******` keeps the stored value; if the URL changed, that returns 400 `url changed: header values must be re-entered`. |
| DELETE | `/api/settings/webhook-connectors/:id` | Delete (fails if in use by actions) |
| POST | `/api/settings/webhook-connectors/:id/test` | Send test payload. HTTP 200 `{success, status_code}` (`success` = upstream 2xx) or `{success:false, error}` with a sanitized error. |

**Create/Update fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `url` | string | **Required.** Webhook URL |
| `method` | string | `POST`, `PUT`, or `PATCH`; surrounding whitespace is trimmed and case normalized before storage. Empty/whitespace means `POST`. Omitted on create defaults to `POST`; omitted on update keeps the old method (an empty old method becomes `POST`). The test endpoint uses the execution-side normalization. |
| `headers` | object/null | JSON object with string values, e.g. `{"Key": "Value"}`. Omitted on create and `null` are accepted; explicit `null` on PUT clears headers. PUT omission keeps existing headers and validates their shape. When changing URL, headers must be re-entered unless the old headers are absent, `null`, or `{}`. |
| `timeout_ms` | int | >= 0, with no API upper bound. Create omission/0 stores 10000; PUT omission keeps the old value and explicit 0 is stored as 0. Execution falls back to 10 seconds for 0 or values above 10000. |
| `global` | bool | Set on create/PUT; default `false`. Only `true` receives global webhook events. |
| `enabled` | bool | Ignored on create, which always enables the connector; use PUT to enable/disable. |

The test endpoint returns 404 `webhook connector not found` for a missing connector and 400 with a sanitized message if request construction fails.

### xDrop Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings/xdrop-connectors` | List all (API key masked) |
| POST | `/api/settings/xdrop-connectors` | Create; `enabled` is not accepted and the new connector is always enabled. Enable/disable with PUT. |
| GET | `/api/settings/xdrop-connectors/:id` | Get (API key masked) |
| PUT | `/api/settings/xdrop-connectors/:id` | Merge update: omitted fields and scalar `null` keep their values; explicit 0/false are stored. Empty/omitted `api_key` keeps the key. Explicit empty name or URL is rejected; a changed URL (after trimming trailing slashes) requires a new key. |
| DELETE | `/api/settings/xdrop-connectors/:id` | Delete. HTTP 409 `xDrop connector in use by N action(s)` when referenced by actions; HTTP 409 `xDrop connector still has active rules` when it has active / delayed / withdrawing / failed rows, including failed creates. A rule-usage check error returns HTTP 500 `failed to check xDrop connector usage`. |
| POST | `/api/settings/xdrop-connectors/:id/test` | Test the connector credential with xDrop `GET /auth/me`. Missing connector: 404; request construction failure: 400; request send failure (including a missing scheme that passes construction): HTTP 200 `{success:false, error}`. An upstream response produces HTTP 200 `{success, status_code, kind, name}`, plus `error` on failure. `success` requires upstream HTTP 200, no body read error, valid JSON and `kind=machine`. |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `api_url` | string | **Required.** xDrop API base URL (e.g. `https://xdrop.example.com:8000/api/v1`) |
| `api_key` | string | **Required.** Key of an xDrop v3 machine credential, sent as Bearer authentication. Each xSight instance uses a dedicated credential. |
| `timeout_ms` | int | Wait limit per xDrop request: create, withdraw, force unblock (initial lock wait), delivery lookup and connector test. Omitted or 0 on create stores 10000; 0 uses 10 s. The API sets no upper limit; the UI range is 1–30000 ms. |

The xDrop `api_key` read value is `***` plus the last four characters, or just `***` for keys of at most four characters. Every nonempty `api_key` sent to PUT is stored as a new key, including a masked read value; omit the field when keeping the key instead of sending a GET result back unchanged.

### Shell Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings/shell-connectors` | List all |
| POST | `/api/settings/shell-connectors` | Create |
| GET | `/api/settings/shell-connectors/:id` | Get |
| PUT | `/api/settings/shell-connectors/:id` | Merge update: omitted fields and scalar `null` keep their values; explicit 0/false are stored. Merged name and command must be nonempty. |
| DELETE | `/api/settings/shell-connectors/:id` | Delete (fails if in use by actions) |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `command` | string | **Required.** Absolute path to script/binary (must start with `/`) |
| `default_args` | string | Default arguments. `{variable}` placeholders must be supported action template variables (e.g. `{ip}`); unknown names are rejected. Shell expressions such as `${HOME}` are left unchanged by this validation. |
| `timeout_ms` | int | Execution timeout in ms (default: 30000) |
| `pass_stdin` | bool | Pass the attack context to the command as JSON on standard input (default: `false`) |

`enabled` is forced to `true` on create; enable/disable with PUT.

### BGP Connectors

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/settings/bgp-connectors` | List all |
| POST | `/api/settings/bgp-connectors` | Create |
| GET | `/api/settings/bgp-connectors/:id` | Get |
| PUT | `/api/settings/bgp-connectors/:id` | Update |
| DELETE | `/api/settings/bgp-connectors/:id` | Delete (409 if referenced by actions or announcements in announcing/active/delayed/withdrawing/failed/orphan; 500 if the precheck fails) |
| POST | `/api/settings/bgp-connectors/:id/test` | Test FRR connectivity (`show bgp summary`); vtysh deadline 25 s, timeout returns 502 (`timed out`) |
| GET | `/api/settings/bgp-connectors/:id/routes` | Show BGP RIB; query both address families concurrently within one 25 s vtysh deadline; return 502 only if both fail |


BGP test success returns `{ok:true, output}`; any vtysh failure returns 502 `vtysh failed: …`. Routes success returns `{output}`; if both address families fail, it returns 502 `vtysh failed: ipv4=… ipv6=…`.

Deletion only performs a precheck; concurrent Attach/Delete is not atomic. Withdrawn, dismissed, and dismissed_on_upgrade announcements do not block deletion; dismissed routes have been handed over to operators and may still exist in FRR.

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | **Required.** |
| `bgp_asn` | int | **Required on create.** Local BGP AS number, 1-4294967295. PUT omission/null keeps the old ASN; the merged ASN must be in range. |
| `vtysh_path` | string | Path to vtysh binary (default: `/usr/bin/vtysh`) |
| `address_family` | string | Kept for compatibility; not used. Defaults to `auto` and the value is not validated. The address family is derived from each prefix at execution time, and `/routes` always queries both families. |
| `description` | string | On PUT, omitted or `null` keeps the stored value and `""` clears it. (`name`, `vtysh_path` and `address_family` sent as `""` keep their stored values.) |
| `enabled` | bool | Default: `true` |

---

## Stats

### GET /api/stats/summary

<!-- fe-q0:B6 -->
Optional response field `action_mode` is the engine's configured `observe` or `auto` mode. Omitted when the action engine is unavailable.

Dashboard summary counters.

If any active-attack count, node list, prefix count, or threshold count query fails, the endpoint returns HTTP 500 with only `{"error":"stats summary: <which>: database error"}` (the underlying error is written only to the controller log); it does not return partial counters.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `active_attacks` | int | Currently active attacks |
| `total_nodes` | int | Registered nodes |
| `online_nodes` | int | Connected nodes |
| `total_prefixes` | int | Watched prefixes |
| `total_thresholds` | int | Threshold rules |
| `tracker_count` | int | Attacks tracked in memory |
| `attacks_created` | int | Total attacks created since startup |
| `attacks_suppressed` | int | Confirmations held back by the `max_active_attacks` cap: counted once on every tick where a new attack is ready to confirm but does not strictly outrank the lowest-priority Active or Expiring attack (a tie also counts); the new attack stays Confirming and is retried on later ticks. Dedup suppression is not counted here |
| `attacks_evicted` | int | Attacks evicted to make room under `max_active_attacks` (an evicted Expiring attack runs its on_expired actions early) |

### GET /api/stats/timeseries

<!-- fe-q0:B1 -->
Optional `dst_ip` selects a single IPv4/IPv6 target; host CIDRs `/32` and `/128` are normalized to bare addresses. Other CIDRs or invalid addresses return 400 `invalid dst_ip`. It is mutually exclusive with `prefix` (400 `dst_ip and prefix are mutually exclusive`). Target queries use raw samples only, accept only `resolution=5s|5min` and `direction=receives|sends` (default receives), and reject `both`. The maximum `to - from` is 6 hours; omitted `to` means now, and a longer range returns 400 `dst_ip queries are limited to 6h`. In the sends direction the target identifies the local source address.

Per-prefix or per-node time-series traffic data.

| Param | Type | Description |
|-------|------|-------------|
| `prefix` | string | CIDR; sums this prefix and every watched prefix inside it. Omitted or empty = all prefixes. Invalid CIDR or host bits set returns **400** `invalid input`. |
| `node_id` | string | Filter by node |
| `direction` | string | `receives` (default), `sends`, or `both`; other nonempty values return 400 `direction must be 'receives', 'sends', or 'both'` |
| `resolution` | string | `5s`, `5min` (default), or `1h` |
| `from` | string | RFC3339 start time (default: 1 hour ago) |
| `to` | string | RFC3339 end time |
| `include_extras` | bool | `true` adds `extra_decoder_pps` / `extra_decoder_bps` (per-decoder maps for the decoders beyond the fixed columns) |

### GET /api/stats/overview

<!-- fe-q0:B8 -->
Response field `nodes: [{id, pps, bps}]` gives per-node totals, sorted by id. It uses the same direction, `node_id` filter, virtual global-prefix exclusion and 10-second freshness window as the overview totals. Nodes without fresh data are absent; an unready ring returns `nodes: []`. `total_pps` equals the sum of node pps.

Real-time traffic overview from ring buffer. Returns total PPS/BPS and top prefixes.

| Param | Type | Description |
|-------|------|-------------|
| `direction` | string | `receives` (default), `sends`, or `both`; other values (including an explicit empty string) return 400 `direction must be 'receives', 'sends', or 'both'` |
| `node_id` | string | Filter by node |
| `limit` | int | Max prefixes returned (default: 20, max: 200) |

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `total_pps` | int | Aggregate packets per second |
| `total_bps` | int | Aggregate bits per second |
| `node_count` | int | Nodes contributing data |
| `active_prefixes` | int | Prefixes with recent traffic |
| `top_prefixes` | array | Top prefixes by PPS (with per-protocol breakdown: tcp/udp/icmp PPS and BPS, plus `nodes: [{id, mode}]`). The global prefix is not included. If live traffic data is unavailable, every counter is 0. |

### GET /api/stats/total-timeseries

<!-- fe-q0:B1-total -->
Accepts the same `dst_ip` parameter and all target-query constraints documented for `/api/stats/timeseries`, including the `prefix` exclusion, raw-table selection, 6-hour limit and direction semantics.

Aggregate time-series data: all prefixes and nodes, or only those selected by `node_id` / `prefix`.

| Param | Type | Description |
|-------|------|-------------|
| `node_id` | string | Only this node's data (matches `GET /api/nodes` `id`; history of deleted nodes still matches). Omitted or empty = all nodes. |
| `prefix` | string | CIDR; sums this prefix and every watched prefix inside it. Omitted or empty = all prefixes. An unparsable CIDR or one with host bits set returns **400** `invalid input`. |
| `direction` | string | `receives` (default), `sends`, or `both`; other nonempty values return 400 `direction must be 'receives', 'sends', or 'both'` |
| `resolution` | string | `5s`, `5min` (default), or `1h` |
| `from` | string | RFC3339 start time (default: 1 hour ago) |
| `to` | string | RFC3339 end time |
| `include_extras` | bool | Same as for `/api/stats/timeseries` |

Both time-series endpoints return an array of points: `time`, `pps`, `bps`, `tcp_pps`, `tcp_syn_pps`, `udp_pps`, `icmp_pps`, `frag_pps`, `tcp_bps`, `udp_bps`, `icmp_bps`, `frag_bps`, `tcp_syn_bps` (plus the `extra_decoder_*` maps with `include_extras=true`). An unparsable `from` / `to` is ignored. Each resolution has a row cap, and longer ranges are truncated: `5s` 7200 points, `5min` 2000, `1h` 1000. If nothing matches in the window, the response body is `null`. For `5min` / `1h` over a range starting more than 90 minutes ago, both time-series endpoints read the 5-minute aggregate: under normal operation a bucket appears about 1–6 minutes after it closes (not a hard bound), the bucket in progress is not returned, a `from` that is not on a 5-minute boundary drops its partial first bucket, and a historical `to` includes its whole last bucket.

`tcp_syn_bps` is always returned in each time-series point; pre-upgrade raw rows have a value of 0. Upgrading the `ts_stats_5min` aggregate to v8 (v1.4.0) deletes 5-minute aggregates older than 7 days, so `5min` and `1h` resolution queries for those periods return no data. Dashboard and Traffic Overview default to `tcp` and `udp`; SYN can be selected under Decoders.

---

## Baseline

### GET /api/baseline

Reference P95 baselines and suggested manual thresholds for every enabled prefix, recomputed every minute from the last hour of stored statistics. Only inbound (`receives`) traffic is counted. For each prefix the node with the most data points is used.

This endpoint is for reference only. Runtime dynamic detection uses the weekly profiles described under [Dynamic Detection](#dynamic-detection) and does not read any value returned here.

**Response:** a JSON array with one element per enabled prefix (`null` when no prefix is enabled). Returns 503 `baseline calculator not available` if the calculator is not running.

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | string | Prefix CIDR |
| `p95_pps` | int | P95 packets per second over the last hour |
| `p95_bps` | int | P95 bits per second over the last hour |
| `recommend_pps` | int | Suggested manual threshold (P95 × 2) |
| `recommend_bps` | int | Suggested manual threshold (P95 × 2) |
| `detect_thresh_pps` | int | Display value only (P95 × 3); dynamic detection does not use it |
| `detect_thresh_bps` | int | Display value only (P95 × 3); dynamic detection does not use it |
| `data_points` | int | Number of data points in the window |
| `active` | bool | `false` while the window has fewer than 60 data points (cold start); the P95-based fields are then 0 |
| `source` | string | Always `best_node` |

---

## Attacks

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/attacks` | List attacks (paginated, filterable) |
| GET | `/api/attacks/active` | List currently active attacks |
| GET | `/api/attacks/mitigation-brief` | Batch mitigation summaries (up to 50 IDs) |
| GET | `/api/attacks/:id` | Get attack details: `{attack, actions_log, timer?, current?}` (`timer` only while the attack is tracked live). `actions_log` holds execution log rows, without the `bgp_role` fields of `/action-log`. A non-numeric ID returns 404. |
| POST | `/api/attacks/:id/expire` | Force-expire an active attack |
| GET | `/api/attacks/:id/action-log` | Get action execution log for an attack (v1.2: includes `bgp_role`) |
| GET | `/api/attacks/:id/sensor-logs` | Get flow-level sensor logs for an attack |
| GET | `/api/attacks/:id/mitigation-summary` | Aggregated mitigation view for an attack (v1.2) |

In `/api/attacks/:id`, `/action-log`, and mitigation-summary `executions`, nonempty webhook `error_message` values are reduced to `HTTP <code>` or `webhook error (details redacted)`. Non-numeric attack IDs return 400 `invalid attack id` for `/action-log`, `/sensor-logs`, `/mitigation-summary`, and `/expire` (unlike 404 for the attack-detail endpoint).

### List Attacks -- GET /api/attacks

By default, attacks are sorted by start time descending, with equal start times sorted by id descending.

<!-- fe-q0:B11 -->
Optional `ended_after` must be RFC3339 (invalid input: 400 `invalid ended_after`). It includes unfinished attacks or attacks ending at/after this time. Combine `ended_after=T0&to=T1` to select attacks overlapping [T0, T1]. Existing `from`/`to` still filter start time.
Optional `sort` accepts `started_at` (default order) or `peak_pps` (peak PPS descending, then start time descending, then id descending); other values return 400 `sort must be 'started_at' or 'peak_pps'`.
Optional `dst_ip` accepts an IP or CIDR (invalid input: 400 `invalid dst_ip`). It matches attack targets contained within the searched address/network; searching a host does not match an enclosing subnet attack. Both the list and `total` use this filter.

| Param | Type | Description |
|-------|------|-------------|
| `status` | string | `active` (not yet ended) or `expired` (ended). Other values are ignored. |
| `direction` | string | `receives` or `sends`; other nonempty values return 400 `direction must be 'receives' or 'sends'` |
| `prefix_id` | int | Filter by prefix |
| `from` | string | RFC3339; attacks that started at or after this time. An unparsable value is ignored. |
| `to` | string | RFC3339; attacks that started at or before this time. An unparsable value is ignored. |
| `limit` | int | Page size (omitted: 50; nonnumeric or ≤0: 100; max: 200) |
| `offset` | int | Pagination offset |

**Response:** `{ "attacks": [...], "total": N }`

### Active Attacks -- GET /api/attacks/active

<!-- fe-q0:B12 -->
Each live `timer` / `timers` entry optionally includes `threshold_value` and `threshold_unit`, the triggering rule snapshot. Both are present only when the unit is known; a known threshold value of 0 is included. Recovered entries with an unknown unit omit both fields.
Optional `current: {<attack_id>: {pps, bps}}` contains fresh current totals for tracked attacks in this page. `GET /api/attacks/:id` similarly adds `current: {pps, bps}`. Data is summed over nodes with a point no older than 10 seconds, using inbound or outbound rings for the attack direction; subnet targets use prefix totals. Missing data, missing ownership for a single-IP target, ended attacks and untracked attacks omit the key, rather than returning an unknown value as zero.

| Param | Type | Description |
|-------|------|-------------|
| `limit` | int | Max results (default, non-numeric or ≤0: 100; max: 1000); ordered by `peak_pps DESC` |

**Response:** `{ "attacks": [...], "active_count": N, "returned": N, "tracker_count": N, "timers": {...} }`; `timers` maps attack ID to its live detection timer, for the returned attacks only.

### Force Expire -- POST /api/attacks/:id/expire

Manually expires an active attack. Triggers on_expired actions (e.g., xDrop unblock, BGP route withdrawal).

| Param | Type | Description |
|-------|------|-------------|
| `hold_seconds` | int | Optional, 0–86400. After the manual expiry, new alerts for the same target, decoder and direction are held back for up to this many seconds. `0` = no hold. Omitted = `detection.manual_expire_hold_seconds` (default: `expiry_interval_seconds`, clamped to 0–86400). |

Any other value, including an empty `hold_seconds=`, returns **400** `hold_seconds must be an integer between 0 and 86400`. The hold ends early once detection no longer sees the traffic, and a controller restart clears it. `"method": "db"` means the attack was not in live detection (for example after a restart): it is ended without a hold. An attack that has already ended returns **409** `attack already expired`.

**Response:** `{ "ok": true, "method": "tracker" }` or `{ "ok": true, "method": "db" }`

### Sensor Logs -- GET /api/attacks/:id/sensor-logs

Returns per-flow records from the `flow_logs` table for the attack's target IP and time window. For active attacks, the query window is capped to the last 1 hour.

| Param | Type | Description |
|-------|------|-------------|
| `limit` | int | Max flow records (default: 1000, max: 10000) |

**Response:** `{ "flows": [...], "total": N, "expired": bool, "window": "full"|"last_1h" }`

Global attacks (`0.0.0.0/0`) return `{flows:[], total:0, expired:false}` without `window`.

### Action Log -- GET /api/attacks/:id/action-log

Returns every `action_execution_log` row for this attack. BGP `on_detected` entries are enriched with v1.2 announcement-level fields so the UI can distinguish which attack actually triggered vtysh from attacks that joined an existing shared announcement.

**Response (array element shape):**

| Field | Type | Description |
|-------|------|-------------|
| `id`, `attack_id`, `action_id`, `response_name`, `action_type`, `connector_name`, `trigger_phase`, `status`, `status_code`, `error_message`, `request_body`, `response_body`, `external_rule_id`, `connector_id`, `duration_ms`, `executed_at`, `scheduled_for`, `detail`, `skip_reason` | — | Base fields from `action_execution_log`; `scheduled_for`, `detail`, and `skip_reason` may be omitted. |
| `bgp_role` | string | BGP `on_detected` only. `"triggered"` = this attack was first to attach in the current cycle (the vtysh announce fired for this attack). `"attached_shared"` = this attack joined an existing active announcement (no vtysh side effect). Empty otherwise. |
| `announcement_id` | int | BGP `on_detected` only. ID of the `bgp_announcements` row this log entry is attached to. |
| `announcement_refcount` | int | BGP `on_detected` only. Current refcount on the announcement at query time. |

### Mitigation Brief -- GET /api/attacks/mitigation-brief

<!-- fe-q0:B3 -->
Required `ids=1,2,3`: 1–50 unique positive integers, each at most 2147483647. Empty, non-positive, invalid, duplicate or over-limit IDs return 400. Any repository failure fails the whole response with a database error. Unknown IDs return two empty arrays.

```json
{"1":{"xdrop_rules":[{"external_rule_id":"r1","status":"delayed","scheduled_for":"2026-10-27T12:05:00Z"}],"bgp":[{"prefix":"192.0.2.0/24","route_map":"RTBH","status":"active","attached_at":"2026-10-27T12:00:00Z","delay_minutes":5}]},"2":{"xdrop_rules":[],"bgp":[]}}
```

`scheduled_for` is present only for delayed XDrop rules with a start time and positive delay: start + delay minutes. BGP `detached_at` is present only after detachment; `delay_minutes` is the attachment's delay.

### Mitigation Summary -- GET /api/attacks/:id/mitigation-summary (v1.2)

Aggregated view of every mitigation outcome the attack produced, backed by the v1.2 Action State Layer. Used by the attack-detail page to render the BGP Role column, per-attack Force remove buttons, and per-attack mitigation counters without forcing the UI to re-stitch state from raw logs.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `attack` | object | The attack row |
| `summary` | object | Counters: `total_evaluated` (all action logs for this attack), `success`, `failed`, `skipped`, `timeout` (logs with that `status`), and `skip_reasons` (map of `skip_reason` → count for skipped logs) |
| `executions` | array | Same shape as the `/action-log` response (including `bgp_role`, `announcement_id`, `announcement_refcount`) |
| `xdrop_rules` | array | Rows from `xdrop_active_rules` for this attack: `id`, `attack_id`, `action_id`, `connector_id`, `external_rule_id`, `status`, `delay_started_at`, `delay_minutes`, `withdrawn_at`, `created_at`, `error_message`. An `external_rule_id` starting with `failed-create-` marks a failed create with an unknown result; it is not an xDrop rule ID. A withdrawn row has an empty `error_message`. An action expanded into top-K rules has one row per rule. |
| `bgp_announcements` | array | Per-announcement attachments: `announcement` (full `bgp_announcements` row), `attached_at`, `detached_at`, `attack_delay_minutes`, `attack_action_id` |

---

## Active Mitigations (v1.2)

<!-- fe-q0:B10 -->
XDrop list elements additionally expose nonzero integer `src_port`, `dst_port` and `rate_limit` parsed from historical request bodies. JSON numbers and digit-only strings are accepted; other shapes are ignored. If `dst_ip` is absent, `dst_cidr` supplies its value.

Real-time view of BGP routes and xDrop rules that xSight is currently maintaining, plus operator actions to force-remove or resolve orphan announcements.

### Lists

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/active-actions/bgp` | List BGP announcements that xSight still maintains. Returned `status` is `active`, `delayed`, `failed` or `orphan` (orphans also carry `is_orphan: true`). Announcements that are still announcing or already withdrawing are hidden, as are withdrawn, dismissed and dismissed_on_upgrade ones. |
| GET | `/api/active-actions/xdrop` | List xDrop rules in `active`, `delayed`, `failed`, including failed-create records; withdrawing and withdrawn rows are hidden. |
| GET | `/api/active-actions/xdrop/delivery` | Look up current per-node delivery for a rule on demand. |
| GET | `/api/active-actions/timeline` | Get the Execution Timeline for a single artifact (detail drawer) |

**List elements:** both lists return an array (`null` when empty). Each element has `attack_id`, `attack_dst_ip`, `action_id`, `action_type`, `connector_id`, `connector_name`, `external_rule_id`, `created_at`, `status`, and `scheduled_for` for delayed rows. BGP elements add `prefix`, `route_map`, `announcement_id` and `attached_attacks` (currently attached attacks plus at most 30 detached ones); their `external_rule_id` is `<prefix>|<route_map>`. xDrop elements add `dst_ip`, `protocol`, `tcp_flags` and `action` from the request body. Each xDrop row is the hold of one attack and action on one rule: when several attacks hold the same XDrop rule, the same `external_rule_id` appears in several rows, and an action expanded into top-K rules has one row per rule. A row does not show which other attacks or systems also hold the rule. `connector_name` is empty when the original execution log is not found.

**Delivery query:** `connector_id` (positive integer) and `rule_id` (non-empty) are required. Invalid parameters return 400; a missing or disabled connector returns 404 `xdrop connector not found`; upstream errors return 502. HTTP 200 is `{found:false}` for an absent rule, or `{rule_id,target_gen,epoch,nodes:[{name,state,code?,error?}]}`. Node states are `confirmed`, `pending`, `disabled`, `offline`, `incompatible`, `overloaded`, `rejected`; they reflect the configured rule generation, not measured packet hits. A `gen_epoch_mismatch` response is retried once. This endpoint is intended for on-demand lookup.

**Timeline query params:**

| Param | Type | Description |
|-------|------|-------------|
| `attack_id` | int | **Required.** Attack ID. |
| `external_rule_id` | string | **Required.** External rule ID. |
| `connector_id` | int | Optional connector filter. |

**Timeline response:** `{attack, logs}`. `logs` are this attack's execution log rows with a matching `external_rule_id`, oldest first (`null` when none match). With `connector_id`, rows that have no connector are still included. An attack ID is required, so orphan BGP announcements have no timeline here.

### Force remove (per-attack / per-artifact)

```
POST /api/active-actions/force-remove
```

Force-removes a specific mitigation artifact. For BGP this detaches all attacks from the shared announcement and withdraws the entire route via vtysh, removing protection for every attached attack. For a normal xDrop rule, force unblock releases the hold of this attack and action; xDrop deletes the rule after its last holder releases it. An in-progress automatic withdrawal may cause an initial wait of up to one connector timeout. Both paths write a `manual_override` audit row so natural on_expired cleanup skips this artifact.

For a failed-create record, recoverable create evidence is first checked against xDrop using a read-only lookup, then the operation releases the hold or closes the local record. Without recoverable evidence, it may close the local record directly. The whole operation may exceed one connector timeout; successful local closure does not prove that a release was sent to xDrop. Both normal and failed-create operations reject disabled connectors.

Success returns HTTP 200 `{ok:true, message:"force removed <id> (attack #N)", warning?}`; if the removal succeeded but its execution log could not be written, it returns HTTP 200 `{ok:true, warning}` without `message`. An execution failure returns HTTP 500 `force remove failed`; details appear in the `manual_override` execution log under `error_message`.

**Body:**

| Field | Type | Description |
|-------|------|-------------|
| `artifact_type` | string | Optional; ignored if supplied. |
| `attack_id` | int | **Required.** |
| `action_id` | int | **Required.** |
| `connector_id` | int | **Required.** |
| `external_rule_id` | string | **Required.** |

### Orphan BGP Announcements

Orphan announcements are FRR routes that `BootstrapBGPOrphans` found on controller startup with no backing active attack. First-boot v1.2 upgrade routes are recorded as `dismissed_on_upgrade`; subsequently-observed orphans are `orphan` and require operator resolution.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/active-actions/bgp/orphan-force-withdraw` | Withdraw an orphan announcement via vtysh. Body: `{ "announcement_id": N }`. Rejects non-orphan rows with 400 — use `/force-remove` instead. |
| POST | `/api/active-actions/bgp/orphan-dismiss` | Mark an orphan as operator-acknowledged without withdrawing. Body: `{ "announcement_id": N }` |
| GET | `/api/active-actions/bgp/dismissed-orphans` | List announcements in `dismissed` / `dismissed_on_upgrade` status |
| POST | `/api/active-actions/bgp/orphan-undismiss` | Re-surface a dismissed orphan. Body: `{ "announcement_id": N }` |

Orphan force-withdraw returns 404 `announcement not found` for a missing announcement. Success returns 200 `{ok:true, announcement_id}`; vtysh failure still returns 200 `{ok:true, warning:"vtysh error: … (row marked failed)"}`. Dismiss of a non-orphan and undismiss of a row outside `dismissed` / `dismissed_on_upgrade` return 400.

---

## Audit Log

### GET /api/audit-log

Audit diffs include response `enabled`; template create/copy `response_id` (and copy `description`); action snapshots including `paired_with` and known xDrop `target_node_ids` old/new values; the previous precondition list (`[]` when absent); and actual IDs on Flow creation.

Configuration change history with old/new diffs.

Successful user and node create/update/delete requests add `user` / `node` audit entries. These are best-effort records of successful requests, have no delivery version, and do not publish configuration. User diffs omit passwords and hashes; updates include `password_changed`. Node diffs omit API keys. API-key requests have no user ID; self-deletion also records a null user ID.

| Param | Type | Description |
|-------|------|-------------|
| `entity_type` | string | Filter by entity type (e.g. `watch_prefix`, `threshold`, `response`, `user`, `node`) |
| `user_id` | int | Filter by user |
| `from` | string | RFC3339 start time, inclusive. An unparsable value is ignored. Encode `+` in a UTC offset as `%2B`, or use the `Z` form. |
| `to` | string | RFC3339 end time, inclusive. An unparsable value is ignored. |
| `limit` | int | Page size (omitted: 50; nonnumeric or ≤0: 100; max: 200; larger values are capped) |
| `offset` | int | Pagination offset |

**Response:** a JSON array, newest first (`null` when nothing matches). No total count is returned; request one extra row to tell whether a next page exists.

---

## Dynamic Detection

Dynamic detection compares live inbound traffic with a learned weekly profile per node and prefix. A profile has 168 hourly slots in UTC (slot 0 = Monday 00:00 UTC, slot 167 = Sunday 23:00 UTC). When an hour ends, its P95 pps / bps is folded into that slot's expected value with an EWMA (`ewma_alpha`; the first sample is taken as is), at most once per week, and the slot's `sample_weeks` grows by one.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dynamic-detection/config` | Get the configuration (same fields as the PUT body) |
| PUT | `/api/dynamic-detection/config` | Replace the whole configuration |
| GET | `/api/dynamic-detection/status` | Get current profile status per prefix |

### Detection Rule

For each node and prefix, using the current slot:

1. Detection is disabled, the slot has no profile, or its `sample_weeks` is 0 (learning): no breach. One sampled week is enough to activate a slot.
2. Current pps is below `min_pps` **and** current bps is below `min_bps`: no breach. Reaching either floor is enough for the traffic to be evaluated.
3. The deviation narrows linearly from `deviation_max` to `deviation_min` as the slot collects weeks: deviation = `deviation_max` − min(`sample_weeks`, `stable_weeks`) / `stable_weeks` × (`deviation_max` − `deviation_min`).
4. Threshold = expected × (100 + deviation) / 100, separately for pps and bps. Exceeding either threshold is a breach.

A breach is then confirmed like a hard-threshold breach, using `detection.dynamic_threshold_confirm_seconds`. The resulting attack has direction `receives`, decoder `ip` and domain `subnet`.

Example: with the defaults `deviation_max` 200, `deviation_min` 100 and `stable_weeks` 4, a slot with one sampled week alerts above 2.75 × expected, and from week 4 on above 2 × expected.

### Update Config -- PUT /api/dynamic-detection/config

**Whole replacement, not a merge:** the body replaces every field. Send the complete object (start from the GET response). An omitted `stable_weeks` or `ewma_alpha` returns 400; an omitted `enabled` turns detection off; omitted `deviation_*` or `min_*` fields are stored as 0. The response echoes the stored configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable/disable dynamic detection |
| `deviation_min` | int | 100 | Deviation in **percent** once the slot is stable (100 = alert above 2 × expected). Must be an integer >= 0; a fraction such as 1.5 returns 400. |
| `deviation_max` | int | 200 | Deviation in percent for a slot with one sampled week (200 = 3 × expected). Integer, must be >= `deviation_min`. |
| `stable_weeks` | int | 4 | Number of sampled weeks over which the deviation narrows from `deviation_max` to `deviation_min` (>= 1). It does not delay activation. |
| `ewma_alpha` | float | 0.3 | EWMA weight of the newest week (0 < alpha < 1) |
| `min_pps` | int | 100000 | Traffic floor in packets/s (>= 0); see rule 2 above |
| `min_bps` | int | 1000000000 | Traffic floor in bits/s (>= 0); see rule 2 above |

Validation errors: `deviation values must be non-negative`, `deviation_min must be <= deviation_max`, `stable_weeks must be >= 1`, `ewma_alpha must be between 0 and 1 (exclusive)`, `min_pps must be >= 0`, `min_bps must be >= 0`.

### Detection Status -- GET /api/dynamic-detection/status

Returns 503 `profile engine not available` when the profile engine is not running.

**Response:**

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | bool | Whether dynamic detection is enabled |
| `current_slot` | int | Current hourly slot (0-167) |
| `current_slot_label` | string | Label such as `Monday 14:00 UTC`. If the current slot has no profile data, the newest earlier slot with data is shown and the label ends in ` (latest)`; `current_slot` still names the current slot. |
| `total_prefixes` | int | Prefixes with profile data in the shown slot |
| `activated_count` | int | Prefixes past the learning phase |
| `learning_count` | int | Prefixes still learning |
| `prefixes` | array | Per-prefix detail (`null` when there is no data): `prefix`, `node_count`, `expected_pps`, `expected_bps`, `current_pps`, `current_bps`, `thresh_pps`, `thresh_bps`, `sample_weeks`, `status` (`learning`/`normal`/`exceeded`) |

With several nodes, a prefix row takes the largest expected and threshold values, the sum of current traffic across nodes, and the smallest `sample_weeks`. `status` compares current traffic with the thresholds only; it ignores `min_pps` / `min_bps` and the confirmation window, so it can differ from what actually raises an attack.

---

## Flow Configuration

Manage NetFlow/sFlow/IPFIX listeners and sources for flow-mode nodes.

### Flow Listeners

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/flow-listeners?node_id=X` | List listeners for a node (**node_id required**) |
| POST | `/api/flow-listeners` | Create a flow listener |
| GET | `/api/flow-listeners/:id` | Get listener with its sources: `{listener, sources}` |
| PUT | `/api/flow-listeners/:id` | Update listener (node_id immutable) |
| DELETE | `/api/flow-listeners/:id` | Delete listener (cascades to sources) |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | string | **Required.** Must be a flow-mode node |
| `listen_address` | string | **Required.** `:port` or `host:port` (1-65535) |
| `protocol_mode` | string | `auto` (default), `sflow`, `netflow`, or `ipfix` |
| `description` | string | Free-text label |

Create always stores `enabled=true` for listeners and sources; a PUT that omits `enabled` keeps the stored value.

Listener and source PUT are full replacements, except for omitted `enabled` and the immutable owner ID (`node_id` / `listener_id`). Send every field: omitted `description` is cleared, and omitted source `sample_rate` becomes 0 in `auto` / `none` mode but returns 400 in `force` mode, which requires a positive rate. Update does not apply create defaults: listeners require `listen_address` / `protocol_mode`, and sources require `name` / `device_ip` / `sample_mode`, or return 400.

### Flow Sources

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/flow-sources?listener_id=N` | List sources for a listener (**listener_id required**) |
| POST | `/api/flow-sources` | Create a flow source |
| GET | `/api/flow-sources/:id` | Get source |
| PUT | `/api/flow-sources/:id` | Update source (listener_id immutable) |
| DELETE | `/api/flow-sources/:id` | Delete source |

**Create fields:**

| Field | Type | Description |
|-------|------|-------------|
| `listener_id` | int | **Required.** Parent listener |
| `name` | string | **Required.** Display name |
| `device_ip` | string | **Required.** Exporter IP address (must be a valid IP) |
| `sample_mode` | string | `auto` (default), `force`, or `none` |
| `sample_rate` | int | Required when `sample_mode=force` (must be > 0) |
| `description` | string | Free-text label |

---

## Common Response Patterns

### Success

```json
{ "ok": true }
```

### Created

HTTP 201 with:

```json
{ "id": 42 }
```

### Error

```json
{ "error": "description of the problem" }
```

Most database failures reported as HTTP 500 carry a fixed message that ends in `database error` (some endpoints add a short prefix, e.g. `failed to check template responses: database error`). A few operations use their own fixed message instead: Force remove returns `force remove failed`, and an action update whose rollback is incomplete appends the steps that could not be rolled back. In all of these cases the underlying error is written only to the controller log. A database failure while loading the object named in the URL is reported by many endpoints as **404** `<object> not found`, without a log entry, so a 404 alone does not prove that the object is missing. When the database rejects a request because of its input, most endpoints return a fixed message instead: a duplicate value returns **409** `already exists`; a reference to a missing object returns **400** `referenced object not found` (**409** `in use` on DELETE); a constraint or required-value violation returns **400** `invalid value`; malformed input such as an unparsable CIDR, or a negative `offset`, returns **400** `invalid input`. Turning a database error into one of these fixed input-error responses does not write an additional error log. `GET /api/stats/summary` always returns 500 on a query failure (see above).

Except for `/api/login`, a request body that fails JSON binding returns **400** with the validator's original message. An unknown `/api/*` path, or a known path with an unsupported method, returns **404** `{"error":"not found"}` (there is no 405).

### Conflict (in-use guard)

HTTP 409 when trying to delete an entity that is referenced by other entities:

```json
{ "error": "template in use by 3 prefixes: [198.51.100.0/24 203.0.113.0/24 192.0.2.0/24]" }
```
