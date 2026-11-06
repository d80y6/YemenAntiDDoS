# Inline Scrubbing & DDoS Defense (v4.0)

This document covers the inline data plane: how a Node stops being a passive
sensor and becomes an in-path scrubber, what the Controller pushes to it, and
how to verify the result without dropping production traffic.

For L7 detection details see [L7.md](L7.md); for BGP Flowspec see
[FLOWSPEC.md](FLOWSPEC.md); for mTLS see [MTLS.md](MTLS.md).

---

## 1. Modes

| `mode` | Data path | Behaviour |
|--------|-----------|-----------|
| `xdp` (default) | mirror / ERSPAN port | `xsight_main` counts packets and drops them (mirror semantics are unchanged) |
| `xdp_inline` | in-line (bridge or routed) | `xdp_inline` passes benign traffic and applies `active_filter_rules` |
| `flow` | sFlow / NetFlow / IPFIX | no XDP program |

Enable inline scrubbing either with `mode: xdp_inline` or with `mode: xdp` plus
`inline.enabled: true`. Both forms are equivalent; `xdp_inline` is clearer in
deployments where the interface is genuinely in the path.

The default action is `XDP_PASS`. If the Controller is unreachable the Node
keeps forwarding traffic; existing rules age out by TTL.

> **Before you flip the switch:** attach the Node in line in a lab first. A
> wrong rule set drops real traffic. Keep an out-of-band console session and be
> ready to `systemctl stop xsight-node` (removing the XDP program restores
> normal forwarding).

---

## 2. Node configuration

```yaml
mode: xdp_inline

inline:
  enabled: true                  # implied by mode: xdp_inline
  burst_pps: 200000              # per-destination burst threshold; 0 = default
  syn_cookie: true               # stateless SYN-cookie validation (TCP floods)
  dns_protect: true              # UDP/DNS reflection defense
  sample_rate: 0                 # 1-in-N L7 sampling of protected traffic (0 = off)
  cleanpipe_egress: ""           # egress ifname for clean-pipe redirect ("" = XDP_TX on the ingress iface)
  cleanpipe_encap: ""            # "" | "gre" | "geneve"

perf:
  cpu_pins: [2, 3]               # pin XDP/AF_XDP hot goroutines
  xdp_mode: driver               # driver | generic | offload

af_xdp:
  enabled: true                  # zero-copy L7 inspection
  queue: 0                       # RX queue steered into the XSK map
  frames: 4096                   # UMEM frames (power of two)
  frame_size: 4096
  zero_copy: true                # fall back to copy mode when unsupported
```

### Attach modes

- `driver` (default) — native XDP in the NIC driver. Required for `XDP_REDIRECT`
  and usable with AF_XDP zero-copy.
- `generic` — `SKB` mode; works on any interface but is much slower. Useful for
  functional tests on veth/bridges.
- `offload` — SmartNIC XDP offload. The alert ringbuf and other
  verifier-unfriendly helpers are gated off under offload
  (`CFG_ALERTS_ENABLE`), so sub-second burst alerts require `driver` mode; the
  Node falls back to driver mode when offload binding fails.

### Clean-pipe

With `cleanpipe_egress` set, scrubbed traffic is sent to that interface with
`XDP_TX` (or encapsulated with GRE when `cleanpipe_encap` is set) instead
of being forwarded on the ingress interface. This is the building block for a
clean-pipe return path from a scrubbing center.

A redirect rule with `egress_ifindex == 0` falls back to `cleanpipe_egress`.
For GRE (`encap: "gre"`), the rule's `encap_daddr` is the outer IPv4
destination; the outer source is the egress interface's IPv4 address (written
at startup, 0 with a warning when the interface has no IPv4). The GRE payload
protocol is transparent Ethernet bridging (`0x6558`) because the encapsulated
frame still begins with its Ethernet header. Clean-pipe egress is treated as
an L2 adjacency: `bpf_redirect()` transmits without neighbour resolution and
the original destination MAC is reused, so the clean-pipe link must be
point-to-point at L2. GENEVE is declared on the wire but not implemented; the
node rejects `encap: "geneve"` at install time.

The controller's `default_action` is enforced by installing a lowest-priority
all-zero catch-all rule when it is `"drop"`; the rule is removed by the next
snapshot with `"pass"` (including an empty withdraw push). Specific rules,
including `pass`, override the catch-all.

---

## 3. Controller configuration

```yaml
action_engine:
  inline_enabled: true
  inline_broad_rate_pps: 20000    # phase-1 cap per target
  inline_narrow_delay_ms: 750     # phase-2 delay (target 500–1000 ms)
```

The Controller keeps the authoritative rule snapshot per attack and pushes the
**whole snapshot** on every change. Pushes are idempotent, so a Node that
reconnects (new ControlStream) receives the complete current state and rebuilds
its BPF maps from scratch.

### Rule lifecycle (narrow-then-rebreadth)

1. **Broad (immediate).** A per-target `rate_limit` rule caps the destination at
   `inline_broad_rate_pps`. For TCP attacks a `syn_cookie` rule is added so
   spoofed handshakes are answered statelessly.
2. **Narrow (~750 ms).** Flow evidence narrows the rule set: dominant
   destination ports (at least 25 % share, at most 4) become `drop` rules with a
   residual `rate_limit` for the rest of the traffic. Optionally the top source
   /24 subnets are dropped too.
3. **Rebreadth.** If the flood continues after narrowing (new ports, rotating
   sources), the mitigator re-applies the broad cap. Every re-broadening is
   counted in the mitigation's `Rebreadths`.

When the attack ends, the Controller pushes an empty rule set (withdraw) and the
Node's filter maps return to pass-all.

---

## 4. Data plane

Key BPF maps (`node/bpf/xsight.h`):

| Map | Purpose |
|-----|---------|
| `active_filter_rules` | exact DIP / protocol / port / action rules, priority ordered |
| `active_filter_subnets` | CIDR (LPM trie) rules for source-subnet and /24 blocks |
| `validated_clients` | LRU of clients that solved the cookie handshake, bypassing emergency drops for `VALIDATED_CLIENT_TTL_NS` |
| `burst_windows` | per-destination 100 ms counters and emergency state |
| `alerts` | ringbuf: urgent burst events read by `CriticalEventStream` |
| `dns_outstanding` | reflection heuristic for UDP/53 |
| `inline_stats` | per-CPU counters surfaced as node posture |
| `xsight_xsk` | AF_XDP socket map |

Actions map to `XDP_PASS`, `XDP_DROP`, `XDP_TX` (SYN-ACK / clean-pipe on the
same interface) and `XDP_REDIRECT` (clean-pipe egress). Rules carry an expiry
(`ExpiresUnix`) so a lost Controller connection does not leave permanent drops.

### SYN cookies

```
cookie = siphash-2-4(key = secret_lo|secret_hi,
                     msg = LE64(sip[0:8]) | LE64(sip[8:16]) |
                           LE64(dip[0:8]) | LE64(dip[8:16]) |
                           LE64(sport | dport<<32))
ISN    = uint32(cookie)
valid  = client_ack_seq == ISN+1 and client_isn == ISN
```

The BPF program rewrites the SYN into a SYN-ACK and returns it with `XDP_TX`;
the final ACK validates the cookie and records the client in
`validated_clients`. `shared/cookie` implements the same formula in Go
(including the 40-byte SipHash length block); the test suite pins both a known
answer and the standard SipHash-2-4 vectors, so any drift between the C and Go
sides fails CI.

---

## 5. Detection timing

| Stage | Budget | Where |
|-------|--------|-------|
| Burst counter tick | 100 ms | BPF (`burst_windows`) |
| Emergency micro-drop | 2 s | BPF (`in_emergency`) |
| Urgent ringbuf alert | < 500 ms from burst start | BPF → `CriticalEventStream` (bypasses 1 s batching) |
| Controller attack confirmation | < 200 ms from alert | `tracker.FastTrackConfirm` |
| Broad rule installed | < 500 ms from alert | `action.InlineMitigator.OnCritical` |
| Narrow rules | ~750 ms after broad | `NarrowDelay` |

The tracker reuses the normal confirmation path, so deduplication, event
emission, expiry and the DB record are identical to the threshold detector.

---

## 6. HTTP API and console

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/inline/mitigations` | active mitigations, phase, rules, nodes, push counters |
| `GET` | `/api/nodes/posture` | data-plane posture for every reporting Node |
| `GET` | `/api/nodes/:id/posture` | posture for one Node |
| `POST` | `/api/inline/reconcile` | admin only: re-push the snapshot to all connected Nodes |

The console adds an **Inline Scrubbing** page under Monitoring with KPI cards,
the mitigation table (attack, target, phase, rules, nodes) and the per-Node
posture table (XDP mode, filter rules, validated clients, SYN-cookie
replied/validated/dropped, emergency drops, burst alerts, AF_XDP health, CPU
pins). The L7 page now also lists top JA3 / JA4 fingerprints and User-Agents.

---

## 7. Verification

```bash
# 1. Compile the BPF object and the Node
make bpf && make -C node

# 2. Unit suites
(cd controller && GOTOOLCHAIN=go1.25.0 go test ./...)
(cd node && go test ./...)
(cd shared && go test ./...)

# 3. Console
(cd controller/console && npm ci && npm run build)

# 4. Lab: print the 10 Gbps / 14.88 Mpps plan (never sends traffic unless RUN=1)
IFACE=eth1 GBPS=10 ./scripts/stress-10g.sh
```

Pass criteria during a synthetic flood are printed by the harness: broad rule
in under 500 ms, narrowed rules after ~750 ms, SYN-cookie replies and validated
clients rising, benign handshakes completing, and clean-pipe output keeping
packet integrity.

Some `node/internal/bpf` and `node/internal/collector` gates load real BPF maps
and therefore require root; they are expected to be run in CI as root (the
tests fail closed rather than skipping).

---

## 8. Limitations

- Offload mode cannot raise sub-second burst alerts (ringbuf/prandom helpers are
  not offloadable); use `driver` mode for the full feature set.
- Clean-pipe GRE/Geneve requires the remote end to decapsulate; the Node only
  encapsulates and redirects.
- A Node that restarts loses its BPF map contents; it recovers state when the
  ControlStream reconnects and the Controller reconciles.
- Inline mode is not meaningful on a mirror port — traffic there is a copy, so
  dropping it does not protect anything.
