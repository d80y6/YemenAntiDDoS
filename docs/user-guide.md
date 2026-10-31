# xSight User Guide

> How to configure detection and response and how to run xSight day to day. Installation is in [Getting Started](../GETTING_STARTED.md); internals are in the [Architecture Guide](architecture.md); the REST API is in [controller/API.md](../controller/API.md).

---

## Contents

1. [Concepts](#1-concepts)
2. [Detection](#2-detection)
3. [Response](#3-response)
4. [Web UI by Feature](#4-web-ui-by-feature)
5. [Operations](#5-operations)
6. [Troubleshooting](#6-troubleshooting)
7. [Scenarios](#7-scenarios)
8. [Known Limitations](#8-known-limitations)

---

## 1. Concepts

### 1.1 Components and Requirements

| Component | Role | Requirement |
|---|---|---|
| Controller | Web UI, REST API, detection, attack tracking, response actions | PostgreSQL with TimescaleDB 2.x |
| Node (XDP mode) | Counts packets on a mirror / ERSPAN interface | Linux 5.18+, x86_64, root |
| Node (Flow mode) | Receives sFlow / NetFlow v5 / NetFlow v9 / IPFIX | Linux, root (service script) |
| FRR (optional) | Announces and withdraws BGP routes for BGP actions | `bgpd` enabled, `vtysh` usable by the controller's user |
| XDrop (optional) | Filters or rate-limits traffic for xDrop actions | XDrop v3; a dedicated machine credential created in XDrop for each xSight instance |

### 1.2 Configuration Objects

| Object | What it is |
|---|---|
| Node | A registered observation point: Node ID, its own API key, mode (XDP / Flow) |
| Watch prefix | An IPv4 or IPv6 CIDR that xSight monitors; may have a parent prefix and a threshold template |
| Threshold template | A named set of detection rules plus a default response |
| Rule | One condition: domain, direction, decoder, unit, comparison, value; may override the response |
| Response | A named set of actions, split into "When Attack Detected" and "When Attack Expired" |
| Action | One step: webhook, shell, BGP or xDrop, with run mode, priority and preconditions |
| Connector | Where an action is sent: a webhook URL, a shell command, a BGP (FRR) instance or an XDrop controller |

Binding chain: prefix → template → rules; attack → rule's response (or the template's default response) → actions → connectors.

### 1.3 Attack Lifecycle

| State | Meaning |
|---|---|
| Confirming | A rule is breached; waiting for N consecutive breaching seconds (default 3; dynamic detection 5). One missing second is tolerated. |
| Active | Confirmed. The attack is stored and "when detected" actions run. |
| Expiring | Traffic is below the threshold; a countdown runs (default 300 s). A re-breach returns the attack to Active. |
| Expired | Ended. "When expired" actions run (including the automatic BGP withdraw / xDrop release). |

### 1.4 Quick Tour

After [Getting Started](../GETTING_STARTED.md) (controller and node online):

1. **Watch Prefixes → Add Prefix**: `198.51.100.0/24`.
2. **Thresholds → Create**: a template, then **Add Rule**: domain `subnet`, direction Receives, decoder `ip`, unit `pps`, comparison Over, value `100000`, inheritable on.
3. **Watch Prefixes**: edit the prefix and select the template.
4. Traffic above 100,000 pps for 3 seconds now creates an attack on **Attacks**.
5. For mitigation: add a connector under **Connectors**, create a response with actions under **Responses**, select it as the template's default response, and set `action_engine.mode: auto` if you use xDrop.

---

## 2. Detection

### 2.1 Watch Prefixes

A watch prefix is the unit of monitoring. Nodes count traffic only for addresses inside a watched prefix (other traffic only updates global counters). A prefix can have a parent: rules marked **Inheritable** in the parent's template also apply to the child. Disabling a parent stops monitoring of that parent prefix only; its template rules and per-prefix overrides are still inherited by its children.

Fields: Prefix (CIDR), Name, IP Group, Parent Prefix, Threshold Template and Status. Examples: `198.51.100.0/24` and `2001:db8::/32`. New prefixes are always enabled; Status is available only when editing. The console cannot change an existing CIDR. Deleting a prefix deletes its individual rules and makes its children top-level prefixes. IPv4-mapped IPv6 prefixes are rejected; use IPv4 notation.

**Global prefix.** A special prefix covers the total traffic seen by each node. It is evaluated from the nodes' global counters and is never pushed to the BPF prefix table.

- Use `0.0.0.0/0` for the global prefix — it covers both IPv4 and IPv6 traffic. `::/0` is not supported and will be rejected by the API.
- Only `subnet` rules are allowed for it.
- Cannot bind a Response containing xDrop or BGP actions (prevents accidental global blackhole). This includes binding a template whose default response or any rule response contains them. Edits to a global prefix that already has such a binding are rejected, even a rename, as long as it stays the global prefix and stays bound to that template; unbind the template or change those responses to fix it.

### 2.2 Threshold Templates and Rules

A template holds rules and a **Default Response**. Each rule can select its own response, which overrides the default for attacks triggered by that rule.

| Field | Values | Meaning |
|---|---|---|
| Domain | `subnet` / `internal_ip` | `subnet`: the prefix's total. `internal_ip`: each IP separately (the attack target is a /32 or /128). |
| Direction | `receives` / `sends` | `receives`: traffic to the prefix (inbound attacks). `sends`: traffic from the prefix (compromised hosts, outbound attacks). |
| Decoder | see §2.3 | Which traffic is counted. Select `ip` for all IP traffic; the dropdown has no empty option. |
| Unit | `pps` / `bps` / `pct` | Packets/s, bits/s, or this decoder's share of all traffic (1–100; not allowed with `ip`). |
| Comparison | `over` / `under` | Breach when the value is above / below the threshold. |
| Value | number | The threshold. |
| Inheritable | on / off | Whether child prefixes inherit the rule. |
| Response | optional | Overrides the template's default response. |

Outbound (`sends`) attacks use only the rule's own response; they never fall back to the template's default response, and xDrop / BGP actions are skipped for them while they are active (`outbound_block_forbidden`). Give outbound rules a webhook-only response.

Thresholds has Templates and All Rules views. Set a rule’s Response in the template detail table, not the Add Rule drawer; “-- (use default)” uses the template’s Default Response, whose “None” option clears the binding. Templates support Copy and cannot be deleted while used by prefixes. All Rules creates inbound per-prefix rules with `pps` or `bps`; these rules can only be deleted in the console.

### 2.3 Decoders

The decoder list comes from `shared/decoder/decoder.go`; `ip` is an aggregate and has no counter slot of its own.

| Decoder | Counts | xDrop |
|---|---|---|
| `ip` | all IP traffic | no |
| `tcp` | all TCP | yes |
| `tcp_syn` | TCP with SYN set and ACK clear | yes |
| `tcp_ack` | TCP with ACK set and SYN clear (most established-connection traffic) | yes |
| `tcp_rst` | TCP with RST set | yes |
| `tcp_fin` | TCP with FIN set | yes |
| `udp` | all UDP | yes |
| `icmp` | ICMP and ICMPv6 | yes |
| `fragment` | any IP fragment | yes |
| `gre` | IP protocol 47 | yes |
| `esp` | IP protocol 50 | yes |
| `igmp` | IP protocol 2 | yes |
| `ip_other` | IP protocols not listed above | no |
| `bad_fragment` | Ping-of-death style fragments (offset × 8 + payload > 65535) and first fragments too small for the L4 header | yes |
| `invalid` | IPv4 IHL < 5, IP total length < header length, TCP data offset < 5 | yes |

Notes: a SYN+ACK packet counts only toward `tcp`. A bad fragment counts toward its protocol, `fragment` and `bad_fragment`. TCP flag anomalies (NULL, XMAS, SYN+FIN) are not decoders; match them with XDrop rules. Reflection attacks (DNS, NTP, memcached and others) are also not decoders: use `udp` plus a "dominant source port" precondition (§3.3). When the same IP has an active attack on a more specific decoder, a new attack on a broader one (for example `ip`) is suppressed.

### 2.4 Confirmation, Expiry and Severity

| Setting (`detection.` in the controller config) | Default | Meaning |
|---|---|---|
| `hard_threshold_confirm_seconds` | 3 | consecutive breaching seconds to confirm a static-rule attack |
| `dynamic_threshold_confirm_seconds` | 5 | the same for dynamic detection |
| `expiry_interval_seconds` | 300 | countdown after traffic drops |
| `expiry_function` | `static` | `dynamic`: countdown × (attack duration / `expiry_scale_base_seconds`), between 1 and `expiry_max_scale` (default 4) |
| `manual_expire_hold_seconds` | follows `expiry_interval_seconds`, at most 86400 | after a manual expire, how long new alerts for the same target, decoder and direction are held back (0 = none) |
| `max_active_attacks` | 10000 | cap on Active + Expiring attacks (0 = no cap) |
| `dry_run` | false | log detections (`DRY-RUN: would trigger ...`) without creating attacks |

Severity is set when the attack is confirmed, from its peak values:

| Severity | Condition |
|---|---|
| critical | > 1,000,000 pps or > 10 Gbps |
| high | > 100,000 pps or > 1 Gbps |
| medium | > 10,000 pps or > 100 Mbps |
| low | otherwise |

When `max_active_attacks` is reached, a new attack replaces the lowest-priority one only if it ranks strictly higher; the replaced attack is counted as evicted (and runs its "when expired" actions early if it was Expiring). Otherwise the new attack waits and is counted as suppressed.

### 2.5 Dynamic Detection

Dynamic detection learns a weekly traffic profile per node and prefix and alerts on deviation from it. It is off by default; turn it on in **Dynamic Detection**. It applies to inbound prefix totals (it creates `ip` / `subnet` / `receives` attacks).

- **Profile:** 168 slots, one per hour of the week (UTC). After each hour, that hour's 95th-percentile PPS and BPS are blended into the slot with EWMA (`ewma_alpha`, default 0.3). Each slot learns at most once per week.
- **Threshold:** expected value × (100 + deviation) / 100. The deviation is a percentage that starts at `deviation_max` (default 200, i.e. 3 × expected) and narrows linearly to `deviation_min` (default 100, i.e. 2 × expected) over `stable_weeks` (default 4) weeks of samples.
- **Activation:** a slot is used once it has learned one sample, so after one full week every slot is active. Until then it is shown as learning.
- **Floor:** traffic is ignored only when PPS < `min_pps` **and** BPS < `min_bps` (defaults 100,000 pps and 1 Gbps). Above the floor, exceeding either the PPS or the BPS threshold counts.

The status view shows each prefix's current slot, expected values, thresholds and learning progress. Its "exceeded" mark compares current traffic with the threshold only; it does not apply the floor or the confirmation time.

The profile table shows PPS only, refreshes every 30 seconds, and has **↻ Refresh**. Console ranges: **Deviation Max (%)** 50–500, **Deviation Min (%)** 10–500, **Stable Weeks** 1–12, and **EWMA Alpha** 0.01–0.99.

### 2.6 Recommended Thresholds

Separately from dynamic detection, the controller recommends thresholds for enabled prefixes using the last hour’s P95 × 2 (`GET /api/baseline`). At least 60 data points are required. Watch Prefixes shows these recommendations; the template detail page shows them only for inbound `ip` rules (also legacy empty decoders), as a range when several prefixes have usable baselines. Recommendations are a starting point for static rules and are not used for detection.

### 2.7 Capacity Limits

| Setting (`ring.`) | Default | Range | Meaning |
|---|---|---|---|
| `max_points_per_ip` | 120 | 10–600 | seconds of history per key; must be ≥ both confirm settings |
| `max_ips_per_prefix` | 10000 | 100–50000 | tracked IPs per prefix |
| `max_global_keys` | 100000 | 1000–500000 | tracked IPs in total |

When a limit is reached, a new IP first replaces a key idle for 5 seconds, otherwise the lightest key if the new IP is heavier; keys of Active and Confirming attacks are protected. The estimated memory is exported as `xsight_ring_estimated_memory_bytes`.

---

## 3. Response

### 3.1 Responses and Actions

A response has two sections: **When Attack Detected** (`on_detected`) and **When Attack Expired** (`on_expired`). For an inbound attack the controller uses the triggering rule's response, otherwise the template's default response; for an outbound attack only the rule's own response. With no response, or a disabled one, only global webhooks are notified.

| Action field | Values | Notes |
|---|---|---|
| Action Type | Webhook / Shell / BGP / xDrop | BGP and xDrop are offered only under "When Attack Detected"; their "When Attack Expired" counterpart is created automatically (§3.2) |
| Connector | per type | xDrop uses Target Nodes instead (§3.6) |
| Priority | 1–10 | lower runs first; decides first match |
| Run Mode | Once / Periodic / Retry Until Success | "When Attack Expired" actions offer only Once |
| Execution | Automatic / Manual | **Manual actions never run** (§8) |
| Enabled | on / off | |
| Preconditions | see §3.3 | all must match |

Automatically generated release/withdraw actions are hidden in When Attack Expired. An action’s type cannot be changed after creation; delete and recreate it. Non-webhook actions carry the **first-match** badge.

### 3.2 When Actions Run

- **When Attack Detected** actions run when the attack is confirmed and when its type is upgraded. **Periodic** actions also run with each attack update, about every 5 minutes. **Retry Until Success** runs again on later events until one attempt succeeds. **Once** runs once per attack.
- **When Attack Expired** actions run when the attack ends, or when it is evicted by the capacity limit.
- **First match:** for xDrop, BGP and Shell, only the first action of each type (by priority) that passes all checks runs; later ones are logged as `first_match_suppressed`. All webhook actions run. Example: priority 1 xDrop with precondition decoder = `tcp_syn`, priority 2 xDrop without precondition; a SYN flood uses priority 1, a UDP flood falls through to priority 2.
- **observe / auto:** with `action_engine.mode: observe` (the default) every xDrop action is skipped with `skip_reason=mode_observe`. BGP, webhook and shell actions are not gated by this switch: they execute in both modes. Set `auto` and restart to let xDrop actions create rules.
- **Auto-pairing:** creating a BGP or xDrop action under "When Attack Detected" creates a matching BGP withdraw / xDrop unblock under "When Attack Expired". It copies the connector, delay and targets, follows later edits, is deleted with its parent and cannot be edited directly.
- Every skipped action is written to the attack's action log with a `skip_reason`, so the attack-detail page shows why an action did not run.

### 3.3 Preconditions

| Attribute | Compares | Example |
|---|---|---|
| `decoder` | attack decoder | `eq udp` |
| `attack_type` | attack type (e.g. `syn_flood`, `udp_flood`, `dns_reflection`) | `eq syn_flood` |
| `severity` | `critical` / `high` / `medium` / `low` | `in critical,high` |
| `pps` / `bps` | peak values | `gt 100000` |
| `domain` | `internal_ip` (single host) or `subnet` | `eq internal_ip` |
| `cidr` | prefix length of the attack target | `eq 32` |
| `node` | reporting node IDs | `in node-a,node-b` |
| `dominant_src_port` / `dominant_dst_port` | most frequent port in the flow samples | `eq 53` |
| `dominant_src_port_pct` / `dominant_dst_port_pct` | that port's share in % | `gte 80` |
| `unique_src_ips` | distinct source IPs in the samples | `gt 1000` |

Operators: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`. The flow-based attributes need flow samples; without them the condition fails. Unknown attributes fail closed.

The table uses API attribute/operator names. The console displays labels such as **Dominant Source Port** and operators `=`, `≠`, `>`, `≥`, `<`, `≤`, `in`, `not in`. `carpet_bomb`, `peak_pps` and `peak_bps` are API-only; `carpet_bomb` is true for subnet attacks and accepts only `eq` / `neq`.

### 3.4 Webhook and Shell

**Webhook connectors:** Name, URL, Method, Headers (JSON object), Timeout (ms) (1–10000 ms; a call never waits longer than 10 s), Global, Enabled. A **global** webhook receives every attack event without being part of a response. Header values are masked when read back; to keep them, leave the mask unchanged when editing. **Test** sends a test request.

**Shell connectors:** Name, Command (absolute path starting with `/`), Default arguments, Timeout (ms) (1–30000; each action is capped at about 30 s), Enabled. Extra Arguments on the action are appended to the defaults; supported placeholders include `{ip}`, `{prefix}`, `{decoder}`, `{severity}`, `{peak_pps}`, `{attack_id}` and `{dominant_src_port}`. Unknown placeholders are rejected on save. `pass_stdin` (when true, the event is written as JSON to the script’s standard input) is API-only: console-created connectors use `false`, and console edits preserve the stored value. Shell has no Test button.

Webhook Method is POST / PUT / PATCH. Changing URL requires re-entering every header value; clearing the entire Headers field deletes all headers. New Webhook, XDrop and Shell connectors are always enabled; only BGP offers an Enabled switch on create. Connectors also includes **Legacy Webhooks (read only)**.

### 3.5 BGP (FRR)

**BGP connectors:** Name, BGP ASN, vtysh path (default `/usr/bin/vtysh`), Description, Enabled. One connector serves IPv4 and IPv6: the address family is chosen from each prefix. **Test** checks FRR access; **Routes** shows the current BGP table. Configure the ASN and route-maps in FRR before use.

**BGP action:** Route Map (e.g. `RTBH`) and Withdraw Delay (min) (0–1440 minutes).

- The controller runs `network <target> route-map <name>` under `router bgp <ASN>` in the right address family. A host attack is announced as /32 or /128, a subnet attack as its prefix.
- Attacks that resolve to the same prefix, route-map and connector **share one route**. The route is withdrawn only when the last attached attack has ended, after the longest withdraw delay among the attacks attached during that announcement.
- If an attack re-breaches during the delay, the delay is cancelled and the route stays.
- Orphan BGP routes identified by the startup scan appear in a separate banner on Active Mitigations; admins can use Force Withdraw or Dismiss.
- Global prefix attacks never trigger BGP (no concrete target).

### 3.6 xDrop

**xDrop connectors:** Name, API URL (the final base URL including the API path, e.g. `https://xdrop.example.com:8000/api/v1`; requests do not follow redirects), API key (the key of the XDrop v3 machine credential dedicated to this xSight instance), Timeout (ms), Enabled.

- Timeout: Wait limit per XDrop request, 1–30000 ms (default 10000). Used by create, withdraw, force unblock and delivery lookup; larger values make force unblock and lookup slower.
- **Test** verifies the machine credential and shows its name on success.
- A connector still used by actions, or with active / delayed / withdrawing / failed rule records, cannot be deleted.
- Connector disabled: withdraw waits until it is enabled; force unblock is rejected.

Changing API URL requires a new API key; leave the key blank to keep it when the URL is unchanged. The system appends `/rules` to the base URL.

**xDrop action fields:**

| Field | Meaning |
|---|---|
| xDrop Action | `Filter L4` (drop) / `Rate Limit` / `Unblock` |
| Filter Fields | Checked fields that apply to the attack type become rule conditions; empty values are not sent. |
| Protocol | Protocol follows the attack type, checked or not; anomaly rules carry no protocol. |
| Rate Limit (PPS) | for Rate Limit only |
| Target Nodes | XDrop connectors to use (empty = all enabled connectors). Disabled connectors are skipped; if every selected connector is disabled, nothing is sent and there is no fallback to all connectors. |
| Unblock Delay (min) | How long this xSight keeps holding the rule after the attack ends. 0 = release immediately. XDrop deletes the rule after its last holder releases it. |

**What gets sent.** Destination IP is the attack target. The protocol and, for TCP-flag decoders, the TCP flags come from the attack's decoder (for example `tcp_syn` → `protocol=tcp`, `tcp_flags=SYN,!ACK`; IPv6 ICMP → `icmpv6`); `bad_fragment` and `invalid` use XDrop anomaly matching. `ip` and `ip_other` attacks are skipped (`decoder_not_xdrop_compatible`) — use BGP for them.

**Source IP / Destination Port / Source Port only allow narrowing.** Checking them lets xSight add the attack's top source IP, top destination port or top source port, taken from flow samples filtered to the attack's protocol and flags. A field is added only when:

- there are at least `xdrop_min_sample_packets` samples (default 1000; 0 turns this check off), and
- its top value has at least `xdrop_narrow_pct` % of the samples (default 80).

If both ports qualify, only the source port is used. If none of the checked fields can be used, the rule is not narrowed. In that case a **Filter L4 (drop)** action becomes a **rate_limit at the triggering rule's PPS threshold**, so a broad rule throttles instead of dropping everything to the target. If the triggering rule is not a PPS rule (for example a BPS rule or a dynamic-detection attack), the broad drop is sent. This fallback does not apply to Rate Limit actions, `fragment` or anomaly attacks.

**Several rules for spread ports (top-K).** If a checked port has no single dominant value but its top 2..K values together reach `xdrop_topk_pct` % of the samples (default 80; K at most `xdrop_topk_max`, default 8), xSight creates one rule per port — up to K rules for one action. `xdrop_topk_max: 1` turns this off. Each decision is written as a `shape: ...` note on the execution-log entry, for example `shape: dropped dst_port=35%` or `shape: topk dst_port=3 84%`.

**Holds and holders.** XDrop may hold one rule on behalf of several holders. Each xSight attack + action that created or joined a rule is one holder. xSight never sets an expiry on the rule; when the attack ends (after the unblock delay) xSight releases its own hold, and XDrop deletes the rule after its last holder releases it.

**Create failures.** If XDrop does not confirm a create, the record is kept with a synthetic rule ID (`failed-create-…`) and shown as **Create failed**. After the attack ends, xSight checks XDrop read-only for a matching rule, releases it if found, and closes the record.

An admin can also select Force Unblock on a failed-create row and confirm **Close out**. This only guarantees that the xSight record is closed; a matching rule may remain on XDrop.

**Retries and reconciliation.** Right after startup and every 2 minutes, xSight retries unfinished releases, backing off for 2 / 4 / 8 / 16 minutes after failures. Live attacks, future delays, manual overrides and disabled connectors are skipped. Results are counted in `xsight_xdrop_reconcile_total`.

### 3.7 Delays and Force remove

- **Withdraw Delay (min)** (BGP) and **Unblock Delay (min)** (xDrop) keep the mitigation for N minutes after the attack ends, because attacks often resume when protection is lifted. Delays survive controller restarts.
- During the delay, Active Mitigations shows **Delayed withdrawal** with a countdown. For BGP, a re-breach cancels the delay. For xDrop, the release is scheduled after the attack has ended; a later breach creates a new attack and does not cancel the old delayed release.
- **Force Withdraw** (BGP) detaches all attached attacks and withdraws the entire shared route. In attack-detail, **Force remove** appears only for admins on successful `on_detected` BGP/xDrop log rows with an external rule and connector ID, while the attack has not ended: BGP removes the whole shared route, while xDrop releases this attack/action’s hold (confirmation: **Release**).
- **Force Unblock** (xDrop) releases the hold of this attack and action; the rule stays while other holders (in this xSight or in other systems) still hold it. To delete a rule for all holders, use the XDrop interface. It may first wait up to one connector timeout for an automatic release in progress.
- After a successful force removal, automatic cleanup for that artifact is skipped.

---

## 4. Web UI by Feature

The console offers Auto / Light / Dark appearance and English / Chinese language options. Non-admin users see read-only pages with write controls hidden or disabled and no connector Test action; BGP Routes remains available.

The sidebar can collapse, shows Actions: Auto / Observe with help text, and refreshes active-attack and offline-node badges every 30 seconds. About shows the version, project link and third-party licenses.

| Page | What it is for |
|---|---|
| Dashboard | Inbound traffic, active attacks, online / total nodes; BGP / XDrop counters include active and delayed mitigations; Attacks · last 24 h includes ended attacks, alongside charts, top prefixes and nodes |
| Traffic Overview | Curves by node, prefix, direction and range; 6h / 24h use 5-minute aggregates that appear a few minutes after each bucket closes |
| Attacks | Ongoing and historical attacks; End in the list and End attack in details are available only to admins for attacks that have not ended |
| attack-detail | Summary, action logs, Force remove and Traffic samples; click a log row to open its details for skip reasons and notes |
| Active Mitigations | BGP and XDrop sections with status, countdowns, details, Execution Timeline and XDrop Delivery; refreshes every 5 seconds |
| Nodes | Add/delete nodes and view online/configuration status; refreshes every 5 seconds; description, mode and enabled state cannot be edited in the console |
| Flow | Configure listeners and sources per Flow node, with health and online status; status refreshes every 10 seconds |
| Watch Prefixes | Prefixes, parents and Threshold Template bindings |
| Thresholds | Templates, All Rules and Default Response |
| Responses | Responses, actions, preconditions and xDrop / BGP settings |
| Dynamic Detection | Dynamic-detection parameters and Profile Status |
| Connectors | Webhook / XDrop / Shell / BGP, with Test where available |
| Users | Accounts and roles; updates, disabling or deletion invalidate existing tokens, and changing or deleting your own account signs you out |
| Audit Log | Configuration changes, force removal and orphan withdraw/dismiss/un-dismiss; End attack is not audited; 50 rows per page |

**Dashboard layout.** Select 15m / 1h / 6h / 24h, drag panels to reorder them, resize with the separator, or use Restore default layout.

**Traffic controls.** Select Inbound / Outbound / Both, 1h / 6h / 24h, and PPS / BPS. Prefix filtering affects curves only, not cards or the Top table. The Top table supports 10 / 20 / 50 / 100 rows and sorting; clicking a row filters by that prefix. Filters are stored in the URL. Only this page supports drag-to-zoom, half-window panning and Reset zoom.

**Chart keyboard controls.** After focusing a chart with Tab, the screen-reader hint for standard charts reads: “Use Left / Right to read each point, Home / End for the first / last point, and Esc to clear the readout.” The Traffic Overview screen-reader hint reads: “Use Left / Right to read each point, Home / End for the first / last point; press Enter to start a selection and Enter again to zoom. Esc cancels the selection or clears the readout.”

**Attack list.** Pages contain 50 rows and refresh every 5 seconds. Ongoing / Ended / All include counts, with direction and target IP or containing-network filters; Ended offers 24h / 7d / 30d. The default is Ongoing, falling back to All when none are ongoing. Ongoing sorts by peak PPS descending; the other views sort by start time descending. Hold seconds accepts an integer from 0–86400, or empty for the configured default; 0 means no hold. The hold ends early when detection no longer sees the attack, and a controller restart clears it.

**Node controls.** Add Node takes Node ID, Mode, Description and API Key; IDs cannot contain `/` or equal `.` or `..`. Generate and Copy are available for the key. The drawer provides a `config.yaml` snippet; the key is not shown after saving. Details show XDP capture interfaces and sampling rates, plus the last 15 minutes of traffic. Deletion also removes the node’s Flow listeners and sources while retaining stored traffic. Configuration states are Synced / Failed / Pending · {n} behind.

**Flow controls.** Listener addresses use `:port` or `host:port`, with protocol `auto` / `sflow` / `netflow` / `ipfix`. Source device IPs cannot contain CIDR suffixes; sampling modes are `auto` / `force` / `none`. A source with no records for 60 seconds is Offline. Health counters are Decode errors / Unknown exporters / Template misses; Sources {count} opens the source drawer. Admins can use inline enable switches; deleting a listener also deletes its sources.

**Users and audit.** Existing usernames cannot be changed in the console; new users are enabled with role viewer by default. The last enabled admin cannot be deleted, demoted or disabled: the backend returns 409 `at least one enabled admin is required`, and the console also guards these operations. Audit Log filters by entity type, user and local start/end time (e.g. `2026-10-27 08:00`); click a row for details. Requests use 51 rows and offset steps of 50 to detect the next page.

**Active Mitigations status:**

| Status | Meaning |
|---|---|
| Active | BGP is announced; XDrop has accepted the rule, with per-node state available under Delivery |
| Delayed withdrawal | The attack ended; waiting for the route/rule hold period |
| Failed | BGP removal failed or XDrop release is unfinished and will retry; Create failed records close automatically after the attack ends, or an admin can Close out manually |

Orphans are separate from the status table, in the “{count} orphan BGP route(s) detected” banner with Force Withdraw and Dismiss. Expand “View dismissed orphans ({count})” to Un-dismiss. For non-synthetic XDrop records, Delivery is queried once when the drawer opens and has Refresh; Force Unblock is disabled when the connector is disabled.

In XDrop Rules, Shared means this xSight holds the rule for several attacks/actions. Force Unblock confirmation reads:

- Shared rule: “Release the hold of this attack and action? This xSight has {n} other holder(s); the rule stays.”
- Other rule: “Release the hold of this attack and action? Other systems may still hold the rule.”

---

## 5. Operations

### 5.1 Metrics

`GET /metrics` on the HTTP port (no authentication; restrict it at the network level). Example Prometheus job:

```yaml
scrape_configs:
  - job_name: xsight-controller
    static_configs:
      - targets: ["192.0.2.10:8080"]
```

All 23 xSight metrics (`controller/internal/metrics/metrics.go`):

| Metric | Type | Labels | Meaning / alert idea |
|---|---|---|---|
| `xsight_attacks_active` | gauge | — | attacks currently tracked |
| `xsight_attacks_created_total` | counter | — | attacks created |
| `xsight_attacks_suppressed_total` | counter | — | new attacks held back at `max_active_attacks`; non-zero → raise the cap |
| `xsight_attacks_evicted_total` | counter | — | attacks evicted at `max_active_attacks`; non-zero → raise the cap |
| `xsight_action_executions_total` | counter | `action_type`, `status` | action results (`success`, `failed`, `timeout`, `skipped`, `scheduled`); alert on `failed` |
| `xsight_action_skip_total` | counter | `skip_reason` | skipped actions; `mode_observe` means xDrop is off, `decoder_not_xdrop_compatible` means xDrop is aimed at `ip` attacks |
| `xsight_action_precondition_lookup_errors_total` | counter | — | precondition lookups that failed; should stay 0 |
| `xsight_action_queue_total` | counter | `outcome` | `full` (event queue back-pressure) or `drain_timeout` |
| `xsight_scheduled_actions_recovered_total` | counter | `outcome` | delayed tasks recovered at startup; `executing_retried` > 0 means a task was interrupted |
| `xsight_scheduled_actions` | gauge | `status` | delayed tasks by status |
| `xsight_vtysh_ops_total` | counter | `operation`, `result` | FRR announce / withdraw results; alert on `failed` |
| `xsight_bgp_announcements` | gauge | `status` | BGP routes by status; `orphan` > 0 needs review |
| `xsight_bgp_withdrawing_reconcile_total` | counter | `outcome` | retries of stuck BGP withdrawals; alert on `list_error` |
| `xsight_bgp_announcing_reconcile_total` | counter | `outcome` | FRR checks of pending announcements; alert on `absent`, `probe_error`, `state_write_error` |
| `xsight_bgp_stale_writes_total` | counter | `op` | BGP state writes not applied because the announcement had a newer generation or was already final |
| `xsight_xdrop_rules` | gauge | `status` | xDrop rule records by status |
| `xsight_xdrop_reconcile_total` | counter | `outcome` | xDrop release retries; alert on rising `failed`, `list_error`, `state_write_error` and on any `synthetic_unrecoverable`, `synthetic_identity_not_found`, `late_create_leak` (possible rule left on XDrop) |
| `xsight_state_write_failures_total` | counter | `op` | state writes that failed after retries; should stay 0 |
| `xsight_startup_cleanup_total` | counter | `kind`, `outcome` | cleanup of attacks that ended while the controller was down; alert on `failed` |
| `xsight_ended_sweep_total` | counter | `kind`, `outcome` | follow-up check after each attack ends; alert on `failed` |
| `xsight_config_publish_failures_total` | counter | `stage` | config saved but rebuild or push to nodes failed |
| `xsight_grpc_identity_rejects_total` | counter | `stream` | node reports refused because the node had not completed a handshake |
| `xsight_ring_estimated_memory_bytes` | gauge | — | estimated ring buffer memory |

Gauges read from the database are collected at scrape time with a 5-second timeout; when the database is slow they are missing from that scrape.

### 5.2 Logs

Both programs log to standard output (the journal under systemd). There is no log level setting. Useful lines:

| Log line | Meaning |
|---|---|
| `xsight-controller running (mode=...)` | controller started; shows observe / auto |
| `reporter: handshake accepted` / `handshake rejected: <reason>` | node registration and key check |
| `reporter: received ConfigPush version=...` | node got a new watch configuration |
| `tracker: attack ... expiring` / `back to active` | attack state changes |
| `DRY-RUN: would trigger ...` | detection with `dry_run: true` |
| `WARNING: TimescaleDB not available` | the database lacks TimescaleDB |

### 5.3 Data Retention

| Key (`retention.`) | Code default | Data |
|---|---|---|
| `ts_stats_days` | 7 | per-second statistics |
| `ts_stats_compress_days` | 1 | compress statistics older than this |
| `ts_stats_cagg_days` | 90 | 5-minute aggregates (6H / 24H charts) |
| `flow_logs_days` | 7 | flow samples (**Traffic samples**, flow-based preconditions) |
| `flow_logs_compress_days` | 1 | compress flow samples older than this |
| `attacks_days` | 90 | ended attacks |
| `audit_log_days` | 180 | audit log |
| `interval_hours` | 24 | how often the built-in cleaner runs |

`0` keeps data forever. `ts_stats` is the largest table; shorter retention reduces disk use. Chunk sizes (`ts_stats_chunk_days`, `flow_logs_chunk_days`, 0 = automatic) limit how precisely old data is dropped.

### 5.4 Restarts and Upgrades

- Restarting the controller keeps attacks, delays and mitigations: delayed tasks are re-armed, interrupted work is finished, attacks that ended meanwhile are cleaned up, and active attacks are restored.
- Upgrade the controller and nodes together.
- If an upgrade starts with an admin account still on the old default password, startup stops until `auth.initial_admin_password` is set; then all users sign in again.
- Changing `auth.api_key` signs out every user.
- `xsight-controller -config <file> -migrate` applies database migrations and exits.
- Stopping the node leaves XDP attached and the BPF maps pinned so a restart resumes; `xsight-node -config <file> -unload` detaches it. `SIGHUP` reloads `sample_bytes` and `upstream_sample_rate`; other node changes need a restart.

### 5.5 Users and Audit

Roles: `admin` can change everything; `viewer` and `operator` are read-only. Login failures all return the same error; repeated failures are rate-limited (5 per user and source, 20 per source, per 15 minutes) and return 429. The audit log records configuration changes, force removal and orphan withdraw/dismiss/un-dismiss with user and time; manual attack expiry is not audited. Passwords and node API keys are not recorded. The last enabled admin cannot be deleted, demoted or disabled (409).

---

## 6. Troubleshooting

### 6.1 Node

| Symptom | Cause | Check |
|---|---|---|
| `handshake rejected: node not found` | Node ID not registered | **Nodes**: add the node with exactly this ID |
| `handshake rejected: invalid api_key` | `auth.node_api_key` ≠ the key registered for this node | Use the per-node key, not the controller's `auth.api_key` |
| `handshake rejected: node disabled` | node disabled | re-enable with `PUT /api/nodes/<id>` and `{"enabled":true}`; no console control |
| Node offline | no report in the last 10 s | node service running, TCP 50051 reachable, node log |
| Config status Pending · {n} behind / drift grows | pushes do not reach the node | network to 50051, node log for `apply ConfigPush failed` |
| Online but no traffic (XDP) | no watched prefix, or mirror not delivering | add a prefix; check the interface receives the mirror |
| Online but no traffic (Flow) | no listener or source, or exporter address differs from the registered device IP | **Flow**; unregistered exporters are ignored |

### 6.2 Detection

| Symptom | Cause | Check |
|---|---|---|
| No attacks | no template bound, threshold too high, wrong direction or decoder | prefix → template binding; rule values; Traffic Overview |
| No attacks while traffic breaches | `dry_run: true`, or `max_active_attacks` reached | controller log, `xsight_attacks_suppressed_total` |
| Expected `ip` attack missing | a more specific decoder already has an active attack on the IP | Attacks page |
| Dynamic detection never fires | disabled, slot still learning, or below both `min_pps` and `min_bps` | Dynamic Detection status |

### 6.3 Actions

| Symptom | Cause | Check |
|---|---|---|
| Nothing in the action log | no response bound, response disabled, or Execution = Manual | template default response / rule response; action Execution |
| `mode_observe` | `action_engine.mode` is `observe` | set `auto`, restart |
| `precondition_not_matched` | a precondition failed (the note names it) | preconditions; flow-based ones need samples |
| `first_match_suppressed` | an earlier action of the same type ran | priorities |
| `outbound_block_forbidden` | xDrop / BGP on an outbound attack | use webhook / shell for outbound rules |
| `decoder_not_xdrop_compatible` | xDrop on an `ip` / `ip_other` attack | use BGP, or rules with specific decoders |
| `connector_disabled` / `no_connector` | connector disabled or not set | Connectors |

### 6.4 BGP

| Symptom | Cause | Check |
|---|---|---|
| Announce failed | FRR not running, `bgpd` off, route-map missing, vtysh not permitted | `vtysh -c "show route-map"`; execution log text; `xsight_vtysh_ops_total` |
| Route stays after the attack | another attack still attached, delay running, or connector disabled | Active Mitigations drawer; enable the connector |
| Orphan routes | untracked routes found in FRR, possibly legacy state or managed by another system | withdraw or dismiss on Active Mitigations |

### 6.5 xDrop

| Symptom | Cause | Check |
|---|---|---|
| No rule created | observe mode, decoder gate, all targets disabled, wrong URL or key | action log; connector **Test**; API URL must include the API path |
| Rule broader than expected / rate_limit instead of drop | not enough samples or no dominant value | `shape:` notes in the action log; §3.6 |
| Several rules for one action | top-K split | `shape: topk` note; `xdrop_topk_max` |
| Rule not removed | delay running, other holders, connector disabled, release failing | **Shared** mark, connector state, `deferred N: …` note, `xsight_xdrop_reconcile_total` |
| Create failed | create result unknown | closes automatically after the attack ends; admins can Close out manually, but a rule may remain on XDrop |

### 6.6 Controller and Metrics

| Symptom | Cause | Check |
|---|---|---|
| Controller exits at start | invalid config value, `CHANGE_ME` API key, no admin password on an empty database, SQLite, database unreachable | the last log line names the key |
| A setting has no effect | misspelled key (ignored silently) or one of the unused keys | compare with `controller/config.example.yaml` |
| `/metrics` gauges missing | database query timed out at scrape | PostgreSQL load |

---

## 7. Scenarios

### 7.1 UDP Reflection

Rule: `subnet`, receives, `udp`, `pps`, e.g. 1,000,000. Response: BGP action (route-map `DIVERT`, **Withdraw Delay (min)** 5) plus an xDrop Filter L4 action with Destination IP and Source Port checked and precondition `domain eq internal_ip`. To target one reflector type, add `dominant_src_port eq 53` (DNS), `123` (NTP), `11211` (memcached), `1900` (SSDP), `389` (CLDAP) or `19` (chargen). If you run such a service yourself, prefer Rate Limit over Filter L4.

### 7.2 SYN Flood

Rule: `tcp_syn`, `pps`, sized to your servers. xDrop rules get `tcp_flags=SYN,!ACK` automatically. A first xDrop Rate Limit action limits the flood; a BGP RTBH action with a higher priority number can be added under a precondition such as `severity eq critical`. Keep `net.ipv4.tcp_syncookies=1` on the servers.

### 7.3 Carpet Bombing

A `subnet` rule catches attacks spread over many addresses. Give the BGP action no precondition (it announces the prefix) and the xDrop action `domain eq internal_ip`, so xDrop acts only on single-host attacks; the console’s Domain = subnet (API: `domain eq subnet`) selects the subnet case explicitly.

### 7.4 Outbound Attacks

Rule: direction `sends`, decoder `ip`, `bps`, with its own webhook-only response. xDrop and BGP are never applied to active outbound attacks.

### 7.5 False Positive

Open **Active Mitigations**, select the entry and use **Force Withdraw** (BGP) or **Force Unblock** (xDrop). Then raise the rule's threshold or add a precondition.

---

## 8. Known Limitations

- **Manual execution does not run.** When Execution = Manual is selected, the editor warns: “Manual actions do not run (manual triggering is not available yet).”
- **Unknown configuration keys are ignored.** Misspelled keys in either YAML file are accepted without a warning. `log.level`, `action_engine.xdrop_api`, `action_engine.xdrop_api_key` and `bpf.path` are read but have no effect.
- **No TLS between nodes and controller.** gRPC is plaintext and reports are accepted by node ID after a handshake; keep port 50051 on a trusted network or a tunnel.
- **`CriticalEventStream` is not implemented** on the node.
- **SQLite is not implemented.**
- **XDP mode needs x86_64 and Linux 5.18+.**
- **xDrop expiry.** Until xDrop provides per-holder expiry, sharing a rule with another system can invalidate the expiry that system set.
- **No xDrop orphan scan.** Rules whose local records were lost must be removed in the XDrop interface.
