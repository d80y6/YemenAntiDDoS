# Inline Scrubbing & Mitigation — Hardening Design

Date: 2026-11-06
Status: Approved (pending written-spec review)
Scope: corrective hardening of the uncommitted "v4.0 inline" implementation across all five mission pillars. No new product surface; the goal is to make the already-shipped feature actually function, remain backward compatible, and be verifiable.

## 1. Context

`github.com/d80y6/YemenDDoS` gained an in-tree, uncommitted implementation of the
"autonomous inline scrubbing" mission: BPF inline program, SYN cookies, DNS
reflection defense, burst detection, `CriticalEventStream`, controller
narrow-then-rebreadth mitigation, L7/JA3 collection, AF_XDP, and a console Inline
page. `go test ./...` is green (controller and shared fully; node except
root-gated kernel tests), and `docs/INLINE.md` claims the feature works.

An independent audit (5 parallel reviewers + author verification) found the
happy path is largely non-functional. Tests pass because none exercise the real
fast paths: there is no `xdp_inline` prog-run test, no ringbuf round-trip test,
no AF_XDP test, and the L7 store tests use counter keys the collector never
emits. This document defines the correct behavior and the chosen fix for each
confirmed defect.

## 2. Confirmed defect inventory

Severity: **H** = data path wrong/non-functional or unsafe; **M** = incorrect in
an edge case or degrades at scale; **L** = hygiene.

### Pillar 1 — Inline & clean-pipe (XDP)
- H `xsight.c:798` `filter_consider` guard `if (!out->hit || ...) return;` makes
  every filter rule dead (`hit` starts false).
- H `xsight.c:1433-1434` `xdp_inline` hardcodes trie `active=0`; `HotSwap` sets
  slot 1, so watched destinations stop matching after the first config push.
- H `xsight.c:789` rule expiry compares ktime-seconds (since boot) against a
  Unix-epoch `expires_unix`, so rules never expire.
- H Exact-rule wildcard lookup only covers 7 of the needed permutations
  (source-only/proto-only/global/dst+src+proto missing) `xsight.c:833-876`.
- H `active_filter_subnets` is keyed only by address and queried for both src
  and dst, so subnet rules ignore proto/port and match the wrong direction
  `xsight.c:885-891,1481-1486`.
- H Go rule routing sends mixed exact-dst + src-prefix rules to the hash map
  with `src_prefix_len=0` `node/internal/bpf/inline.go:333-337`.
- H Clean-pipe GRE: outer `daddr=0`, `saddr=0` `xsight.c:926`, payload protocol
  `ETH_P_IP` instead of TEB `0x6558` `:933`, `encap_daddr` never plumbed
  end-to-end (proto field exists, Go/node/BPF drop it), redirect reuses the
  original DMAC (no FIB/neigh rewrite) `:935`.
- M `default_action` from the controller is ignored `node/inline.go:267`.
- M `cookie_targets` ignored by the node.
- M IPv4 fragments bypass the entire rule engine `xsight.c:1471`.
- M `rate_limit_pps < 10` computes a zero budget and drops everything
  `xsight.c:1294`.
- M `CFG_EGRESS_IFINDEX` is written but never read; `cleanpipe_encap` config
  never applied.
- L GENEVE encap declared but silently falls through to plain redirect.

### Pillar 2 — SYN cookies / DNS / burst
- H Cookie ACK validation `xsight.c:1077` requires `cookie == client_isn`; a
  real ACK has `ack=cookie+1`, unrelated `seq`, so no client is ever validated.
  `shared/cookie/cookie.go:137` mirrors it; `docs/INLINE.md:139` codifies it.
- H SYN-ACK `tot_len=40` `xsight.c:1010` but TCP header is 24 bytes → 44;
  pseudo-header checksum adds protocol/length in the wrong byte order `:1045`.
- H Burst-alert record is 40 bytes `xsight.h:236` but reader requires 48
  `node/internal/bpf/inline.go:537`; every alert dropped.
- H `CFG_ALERTS_ENABLE` never written by userspace and `cfg_read` defaults are
  ineffective for array maps → alerts permanently off `xsight.c:1112`.
- H Cookie zone answers every IPv4 SYN to any watched dest regardless of a
  rule, and returns before burst accounting `xsight.c:1554`.
- H Validated clients bypass all rules, not just emergency drop
  `xsight.c:1460`.
- M `burst_windows` shared by burst and rate-limit paths under different keys
  (dst vs src) → collision `xsight.c:1142,1287`.
- M Emergency never resets `count`; re-arms from stale counts; `sustained`
  never cleared `xsight.c:1150`.
- M L4 offset ignores IPv4 IHL and VLAN for options-bearing packets
  `xsight.c:1442`, and cookie reply rejects VLAN-tagged SYNs `:989`.
- M DNS: ANY/TXT dropped even when solicited; no per-client/qtype volume
  window `xsight.c:1265`.
- M Cookie secret only initialized when `inline.syn_cookie` is true at startup;
  later controller enable uses an all-zero key `node/main.go:358`.
- L Mission formula includes `isn`; C/Go hash only tuple. Reconcile to the
  tuple form (documented) or add `isn`.

### Pillar 3 — Proto / node userspace
- H `packNative` passes the 16-byte interface header, so `XDP_UMEM_REG` is
  garbage `xsk.go:298`; ring mmap uses `ro.Desc*pagesize` instead of the kernel
  magic offsets `xsk.go:334`; fill/comp descriptor stride uses 16 not 8;
  `registerIntoXSKMap` runs before `globalXSKManager` is assigned `xsk.go:276`.
- H Reporter `sendWithTimeout` leaks a goroutine and permits concurrent
  `stream.Send` `reporter.go:356`.
- H `mapCount` passes `*interface{}` to the iterator so posture rule/client
  counts are always 0 `inline.go:487`.
- M `applyInlineRules` resets the SYN-cookie switch to false on any rules-only
  push; no version ordering (stale snapshot can overwrite newer).
- M `applyPostureConfig` is a no-op for xdp_mode/AF_XDP; AF_XDP can't be enabled
  at runtime.
- M `default_action` / `cookie_targets` not plumbed.
- M CriticalEvent `current_bps`/`top_flows` never populated; event time uses
  wall clock instead of BPF timestamp.
- M Non-linux build tags incomplete; graceful shutdown `os.Exit` skips defers.
- L Ring mappings never munmapped; `XSK.Close` not idempotent; `SendRawFrame`
  never wakes TX; `refillAll` can publish offsets beyond UMEM.

### Pillar 4 — Controller detection / action
- H `ActionConfig.InlineEnabled` (`ActionConfig` holds inline settings) has no
  default and `config.yaml` omits it →
  inline mitigation disabled in the live config `config.go:162`.
- H Per-node ControlStream `Send` unsynchronized across narrowing/rebreath/
  withdraw/reconcile goroutines `grpc_handler.go:598`.
- H Network I/O under the tracker lock (`endAttack`→withdraw→Send) and blocking
  action-engine enqueue under the same lock → detection tick can freeze
  `tracker.go:582,410`.
- H Evicted attacks never call the ended hook → inline rules leak
  `tracker.go:1055`.
- H Controller restart does not rebuild inline mitigations from DB; reconcile
  pushes an empty set and clears node BPF maps `inline.go:154, main.go:246`.
- H Source-subnet/ASN narrowing never emits rules; `SetNarrowingSource` has no
  production caller so rebreath can never re-narrow `inline.go:460,184`.
- M Narrow phase hardcodes TCP (UDP/ICMP port floods get wrong rules).
- M No periodic snapshot refresh; rules expire after TTL with no re-push.
- M Newly-attached node for an existing attack isn't pushed the current rules.
- M Data race on `mit.Nodes` in `push`.
- M `syn_cookie` installed for any decoder containing "tcp" (ACK/RST too).
- M Retry doubles the narrowing delay past the 500ms–1s target.
- M CriticalEventStream has no backpressure queue (unlike StatsStream).

### Pillar 5 — L7 / hardware / console
- H Collector emits an event for essentially any TLS/UA-bearing destination
  regardless of thresholds `collector.go:374-413`.
- H L7 counter key mismatch between collector and store → MissingSNI/
  Connections/UniqueSources always 0 `collector.go` vs `l7store/store.go:179`.
- H JA4 is non-canonical: decimal, unsorted, no sigalgs, `r` instead of `i`.
- H PoW JS hashes `token+nonceHex` while Go hashes `token||hexDecode(nonce)` →
  no solution ever validates; challenge page also drops the token.
- H Challenge path orphaned: no production `Mint`/`Validate`/`RenderChallenge307`
  /`SendRawFrame` caller; controller never emits a challenge rule.
- M Slowloris only detected on complete request lines (byte-drip invisible),
  and flagged once per connection.
- M Non-L7 critical events pollute the L7 store.
- M `burst_alerts` and redirect egress rate and desktop CPU utilization missing
  from posture/UI despite being claimed.
- M Console `L7.vue` `chartWidth` never measured; `XPill` used without import.
- L Various docs drift (L7.md event types/defaults, INLINE.md alert claim).

## 3. Design decisions

### 3.1 Filter engine model (Pillar 1)
The rules are installed by the controller as whole snapshots and must be
evaluated cheapest-first. Decision:

- `filter_consider` becomes a proper "best match" reducer: skip dead rules
  (`!rule_live`), then replace the current hit when there is no hit yet, or the
  candidate has a strictly lower `priority` value, or equal priority with a
  more specific cookie request. This fixes the guard and defines a deterministic
  tie-break.
- Expiry uses a single clock domain. The controller already owns wall-clock;
  the node's `applyConfig`/`applyInlineRules` will convert the controller's
  absolute `ExpiresUnix` into a node-local ktime deadline once, at install time,
  and the BPF struct carries `expires_ns` (ktime domain). BPF compares against
  `bpf_ktime_get_ns()`. This avoids a per-packet division and keeps the wire
  contract unchanged.
- Wildcard matching is completed to cover every meaningful prefix of
  `(dst, src, proto, dport, sport)`: full, dst+proto+dport, dst+proto, dst,
  src-only, proto-only, and global. The exact-rule path remains a bounded
  sequence of hash lookups. Subnet rules move to two separate LPM tries
  (`dst` and `src`) whose values carry proto + port constraints, so a subnet
  rule is evaluated only in the correct direction and only for its protocol.
- Go routing classifies a rule as LPM when it carries any prefix length; LPM
  values include the port/proto scope. Mixed exact-dst + src-prefix goes to the
  source LPM trie.
- `default_action` is encoded as a lowest-priority catch-all rule (drop) rather
  than a new config path, so it naturally loses to any specific rule and is
  withdrawn with the snapshot.
- `active_slot` is read exactly as `xsight_main` does in every
  `PROCESS_DIRECTION` call in `xdp_inline`.

### 3.2 Clean-pipe (Pillar 1)
- `encap_daddr` is plumbed proto → `InlineRuleSpec` → `filter_rule` and used as
  the outer GRE/Geneve destination. Outer `saddr` is taken from the config
  egress interface address resolved at install time (stored in a BPF config
  slot), because XDP cannot autoselect.
- GRE payload protocol is corrected to transparent Ethernet bridging `0x6558`,
  or the inner L2 is stripped; decision: keep the inner Ethernet header and set
  `0x6558` (transparent Ethernet bridging), matching how the frame is built.
- `XDP_REDIRECT` to an egress interface uses `bpf_redirect_neigh` where the
  kernel supports it so the L2 header is rewritten for a routed next hop;
  otherwise the rule must be a direct L2 clean-pipe link and we document that.
- `SetEgressIfindex` is read as the default egress when a rule does not set one;
  `cleanpipe_encap` sets the default encapsulation for redirect rules. GENEVE
  is either implemented or rejected with a clear error at install (decision:
  reject-with-error now; tunnel support is a documented follow-up).

### 3.3 SYN cookies & emergency (Pillar 2)
- Cookie validation checks only `ack_num == cookie+1` (the cookie is the
  server ISN). `client_isn` is removed from the check. The Go `ValidAck` and its
  test and `docs/INLINE.md` are updated together.
- SYN-ACK is built with `tot_len=44` and a correct pseudo-header checksum
  (`(IPPROTO_TCP<<8)` and `bpf_htons(24)`). L4 offsets derive from `iph->ihl*4`;
  VLAN-tagged SYNs are supported by resolving the L3 offset in the caller.
- The burst-alert reader accepts 40 bytes; `CFG_ALERTS_ENABLE` is written at
  engine setup; `emit_burst_alert` treats a zero value as "disabled" explicitly.
- Cookie replies are gated on a rule requesting the cookie action; burst
  accounting runs before the cookie verdict. Validated clients bypass only the
  emergency drop, not rule evaluation.
- Emergency entry clears the window count/`sustained`; the rate limiter uses a
  dedicated key space separate from burst windows.
- DNS drops apply to unsolicited/over-volume responses only; a per-client/qtype
  window drives the "high volume" decision, ANY/TXT are charged an
  amplification score.
- The cookie secret is generated whenever inline is active (not only at
  startup) and written atomically as a single value; enabling cookies without a
  secret is refused.

### 3.4 Node userspace (Pillar 3)
- AF_XDP: `packNative` is replaced with a typed, size-correct encoder; rings are
  mmapped at the `XDP_PGOFF_*` constants; fill/comp use 8-byte descriptors;
  `StartXSK` sets the manager before `registerIntoXSKMap` (or passes the manager
  in); ring mappings are retained and unmapped on `Close`; `Close` is
  idempotent; `refillAll` is bounded by `numFrms`.
- The reporter sends synchronously with the stream's context; the orphaned
  goroutine and concurrent-Send hazard are removed.
- `mapCount` uses concrete typed key/value; posture exposes burst alerts,
  redirect/egress counters, and per-core CPU utilization.
- `applyInlineRules` treats the SYN-cookie switch as tri-state (only change it
  when the rule set explicitly says so), rejects stale versions, and plumbs
  `default_action`/`cookie_targets`.
- `CriticalEvent` carries the BPF timestamp; `current_bps`/`top_flows` are
  populated from the alert/flow context.
- Build tags are completed so non-linux builds compile; shutdown runs defers.

### 3.5 Controller (Pillar 4)
- `InlineEnabled` defaults to true (feature is opt-out consistent with the
  mission) and is documented in `config.yaml`.
- Each node has a serialized send path (mutex or single writer) for
  ControlStream pushes.
- Withdrawal and action-engine notify are dispatched off the tracker lock;
  the action queue enqueue becomes non-blocking with a drop metric.
- `evictAttack` invokes the ended hook so inline rules are withdrawn.
- On controller restart, inline mitigations are rebuilt from recovered active
  attacks before the server serves/reconciles.
- `SetNarrowingSource` is wired to a per-attack top-flows store; narrowing emits
  source subnet rules when `TopSrcSubnets` is configured; rebreadth re-narrows
  from live evidence.
- Narrowing carries the attack's dominant protocol (not a hardcoded 6); a
  periodic ticker re-pushes snapshots before `RuleTTL`; attaching a node to an
  existing attack pushes immediately.
- `CriticalEventStream` gets a bounded worker queue like `StatsStream`.
- `syn_cookie` only for SYN handshake floods.
- Config validation clamps `inline_narrow_delay_ms` to the 500–1000ms target.

### 3.6 L7 / console (Pillar 5)
- The collector only emits an event on a real threshold branch; fingerprints and
  UAs are attached to that event. Counter keys are aligned with the store
  (single shared constant set).
- JA4 becomes canonical: 4-char lowercase hex for ciphers (sorted) and
  extensions (sorted) plus `_` + sigalgs in order; no-SNI marker `i`; version
  from supported_versions. Add FoxIO known-answer vectors.
- PoW hashes the same byte representation on both sides; the challenge page
  carries the token; `Mint`/`Validate`/`RenderChallenge307`/`SendRawFrame` are
  wired, and the controller emits challenge rules.
- Slowloris accumulates raw bytes per 5-tuple and re-flags across windows.
- Non-L7 critical events are excluded from the L7 store.
- Console: `chartWidth` measured via ResizeObserver; `XPill` imported; posture
  UI shows burst alerts, redirect egress rate, and CPU utilization.

## 4. Testing & verification strategy

- **Phase 0 harness first.** `make bpf` must pass (make `llvm-strip` optional,
  fall back to no-op when absent, or install it in CI); regenerate bindings so
  tests run current C.
- **BPF prog-run tests** (root; available via `sudo`): load `xdp_inline`, assert
  a matched DROP rule drops, a RATE_LIMIT rule limits, a SYN to a watched dest
  produces a SYN-ACK with correct `tot_len`/checksum, a valid ACK populates
  `validated_clients`, a DNS flood drops, and a burst sets emergency state.
- **Ringbuf round-trip test** for `readBurstAlert` at the real 40-byte size.
- **Go unit tests** for reporter send serialization (`-race`), `mapCount`,
  AF_XDP encoders (pure functions), cookie `ValidAck`, JA4 vectors, PoW
  agreement, collector threshold gating, and counter-key alignment.
- **Controller tests** for send serialization (`-race`), restart reconciliation,
  source narrowing, eviction withdraw, async dispatch, and config default.
- **Full gates:** `go test ./...` (node via `sudo` for kernel gates, controller
  with `GOTOOLCHAIN=go1.25.0`, shared), `-race` on concurrency-critical
  packages, console `npm run build` + tests, and `make bpf`.
- Each fix is landed with the test that fails before and passes after (TDD
  where a test is feasible; prog-run tests for the C paths).

## 5. Backward compatibility

- The proto contract is already additive; no field numbers change. Existing
  `xdp`/`flow` modes and mirror semantics are untouched.
- The cookie formula's wire behavior is corrected (a bug fix); nodes and
  controller are upgraded together, which mTLS already assumes.
- `default_action` is opt-in via the existing controller field; default remains
  pass.
- Config gains defaults, not removals.

## 6. Risks

- Offload mode cannot run ringbuf/prandom helpers; alerts stay driver-mode only
  (already documented). Offload-safe compilation as a separate object is out of
  scope here and tracked as a follow-up.
- Prog-run tests require a kernel with BTF and root; CI must run them as root.
- AF_XDP correctness can only be fully proven on a NIC that supports it; pure
  unit tests cover encoding/mapping math, and a veth loopback smoke test covers
  the rest where possible.

## 7. Out of scope

- New features beyond the five pillars; ASN enrichment beyond what flow samples
  already carry; GENEVE tunnel implementation; IPv6 SYN cookies; offload-safe
  ELF split; a full traffic generator (the stress script stays a planner).
