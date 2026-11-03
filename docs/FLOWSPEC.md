# BGP Flowspec Management

> العربية: [docs/FLOWSPEC.ar.md](FLOWSPEC.ar.md)


## Overview

YemenAntiDDoS can announce BGP Flowspec rules (multi-vendor) instead of falling back to
global RTBH blackholing. Rules are stored in the `bgp_announcements` table with `kind='flowspec'`
and a JSON `rule_spec`, and are executed via FRR (`vtysh`) for the local connector; Cisco,
Juniper and Arista connectors are export-only (commands are generated for manual application).

## Flow

1. An attack triggers an action whose BGP connector has `flowspec_enabled=true`.
2. `executeBGPFlowspec` builds a `flowspec.Rule` via `flowspecRuleFor(dstIP, attack)` and attaches
   a `BGPAnnouncement` with `RouteMap = xsight-<prefix>` and `Kind="flowspec"`.
3. For FRR connectors the rule is rendered with `flowspec.Render` and applied via `vtysh`.
4. For non-FRR connectors the announcement is marked announced with the rendered commands for export.

## Console

The **Mitigations → Flowspec** tab lists announcements, opens a drawer with the rule and
install/withdraw commands (copyable), shows attached attacks, and supports force-withdraw.
The **Preview** panel renders a rule for any vendor/prefix/protocol/port/action/rate without
creating an announcement.

## Force withdraw

`POST /api/flowspec/announcements/:id/withdraw` renders the vendor-specific `no …` command,
executes it via FRR when applicable, and marks the announcement withdrawn.

## Vendor normalization

`normalizeVendor` accepts `frr`, `cisco`, `juniper`, `arista` (case-insensitive) and defaults
to `frr` when empty. Unknown values return an error.

## Connector settings

BGP connectors are configured from the Console (**Settings → BGP Connectors**), not from
YAML. Fields per connector:

| Field | Values |
|---|---|
| `vendor` | `frr` (default) \| `cisco_xr` \| `juniper` \| `arista` |
| `flowspec_enabled` | `true` = announce Flowspec rules, `false` = RTBH only |
| `bgp_asn` | local autonomous system number (required) |
| `vtysh_path` | path to the FRR `vtysh` binary (`frr` vendor only) |
| `address_family` | `ipv4` \| `ipv6` |

Rules are applied locally for `frr` connectors through `vtysh`; Cisco XR, Juniper and
Arista connectors stay export-only — the console renders the vendor-specific commands in
the **Mitigations → Flowspec** drawer for manual application.
