# Inline Scrubbing & Mitigation Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing uncommitted "v4.0 inline scrubbing" implementation actually function correctly across the XDP data plane, node, controller, and console, with tests that exercise the real fast paths.

**Architecture:** Corrective hardening, in dependency order. Phase 0 installs the verification harness (BPF prog-run + ringbuf tests) that makes every later fix provable. Phases 1–2 fix the kernel data plane (filter engine, SYN cookies, DNS, burst). Phases 3–4 fix node userspace and controller. Phase 5 fixes L7/console. Every task lands with a failing-then-passing test and a commit.

**Tech Stack:** C eBPF/XDP (clang, bpf2go, cilium/ebpf), Go 1.24/1.25 (gRPC, protobuf), Vue 3 + TypeScript (Vite).

**Reference spec:** `docs/superpowers/specs/2026-11-06-inline-scrubbing-hardening-design.md`

**Conventions:** run node tests as root for kernel gates (`sudo go test ./...`); controller needs `GOTOOLCHAIN=go1.25.0`. Commit after each task. Do not reformat unrelated code.

---

## File structure

- `node/Makefile` — BPF build; make strip optional; add `generate` drift target.
- `node/bpf/xsight.h` — map/struct definitions, config slots, inline constants.
- `node/bpf/xsight.c` — XDP programs; filter engine, cookie, DNS, burst.
- `node/internal/bpf/inline.go` — Go↔BPF bridge: rule encode, alerts, posture.
- `node/internal/bpf/xsk.go` — AF_XDP socket setup/TX.
- `node/internal/bpf/types.go` — Go-side struct mirrors (if present).
- `node/internal/bpf/inline_prog_linux_test.go` (new) — `xdp_inline` prog-run tests.
- `node/internal/bpf/inline_ringbuf_test.go` (new) — alert round-trip tests.
- `node/internal/bpf/xsk_encode_test.go` (new) — pure AF_XDP encoder tests.
- `node/internal/reporter/reporter.go` — gRPC stream send path.
- `node/inline.go` — node inline orchestration, posture, pinning.
- `node/main.go` — wiring, secret lifecycle, shutdown.
- `shared/cookie/cookie.go` + `cookie_test.go` — cookie formula + ACK validation.
- `shared/l7/ja3.go` + `ja3_fingerprint_test.go` — JA3/JA4.
- `node/internal/l7collector/collector.go`, `challenge.go` + tests.
- `controller/internal/config/config.go` — ActionConfig defaults/validation.
- `controller/internal/action/inline.go` — mitigator, narrowing, push.
- `controller/internal/ingestion/grpc_handler.go` — ControlStream serialization, critical stream.
- `controller/internal/ingestion/node_state.go` — node liveness/mode.
- `controller/internal/tracker/tracker.go`, `fastpath.go` — hooks, eviction, recovery.
- `controller/main.go` — config wiring, reconcile, tickers.
- `controller/console/src/views/inline/Inline.vue`, `views/l7/L7.vue` — UI.
- `docs/INLINE.md`, `docs/L7.md` — correct the documented behavior.

---

## Phase 0 — Verification harness (unblocks all other phases)

### Task 0.1: Make `make bpf` pass when `llvm-strip` is absent

**Files:**
- Modify: `node/Makefile:22-27`

- [ ] **Step 1: Reproduce**

Run: `cd node && make -B bpf`
Expected: FAIL with `llvm-strip: No such file or directory` (exit 2), though `bpf/xsight.elf` is produced.

- [ ] **Step 2: Make strip best-effort**

```make
STRIP ?= $(shell command -v llvm-strip 2>/dev/null || command -v strip 2>/dev/null)
...
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@if [ -n "$(STRIP)" ]; then $(STRIP) -g $(BPF_OBJ); else echo "note: no llvm-strip; leaving debug info"; fi
```

- [ ] **Step 3: Verify**

Run: `cd node && make -B bpf && test -s bpf/xsight.elf && echo OK`
Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add node/Makefile && git commit -m "build(bpf): make llvm-strip optional in node Makefile"
```

### Task 0.2: Generate fresh BPF bindings and fail on drift

**Files:**
- Modify: `node/Makefile` (add `generate-check`)
- Modify (generated): `node/internal/bpf/xsight_bpf*.go`, `*.o`

- [ ] **Step 1: Regenerate**

Run: `cd node && make generate`
Expected: bindings regenerated from current `xsight.c` (the current `.o` predates the C edits).

- [ ] **Step 2: Add a drift check target**

```make
## generate-check — fail if committed bindings differ from a fresh generate
generate-check:
	$(GO) generate ./internal/bpf/
	git diff --exit-code -- internal/bpf/xsight_bpf*.go
```

- [ ] **Step 3: Verify boot**

Run: `cd node && sudo go test ./internal/bpf/ -run TestXsightMainLoads -count=1`
Expected: PASS (or the existing load smoke test).

- [ ] **Step 4: Commit**

```bash
git add node/Makefile node/internal/bpf && git commit -m "build(bpf): regenerate bindings and add drift check"
```

### Task 0.3: Ringbuf burst-alert round-trip test

**Files:**
- Create: `node/internal/bpf/inline_ringbuf_test.go`
- Test target: `readBurstAlert` in `node/internal/bpf/inline.go:535`

- [ ] **Step 1: Write the failing test**

```go
//go:build linux

package bpf

import (
	"encoding/binary"
	"testing"
)

func TestReadBurstAlert_KernelLayout40(t *testing.T) {
	raw := make([]byte, 40)
	binary.LittleEndian.PutUint64(raw[0:8], 12345)
	copy(raw[8:24], []byte{192, 0, 2, 1})
	binary.LittleEndian.PutUint32(raw[24:28], 1)
	binary.LittleEndian.PutUint32(raw[28:32], 9000)
	binary.LittleEndian.PutUint32(raw[32:36], 6)
	binary.LittleEndian.PutUint32(raw[36:40], 2)
	a, err := readBurstAlert(raw)
	if err != nil {
		t.Fatalf("40-byte kernel record rejected: %v", err)
	}
	if a.WindowPPS != 9000 || a.Proto != 6 || a.IsV4 != 1 {
		t.Fatalf("decode mismatch: %+v", a)
	}
}
```

- [ ] **Step 2: Run to confirm failure**

Run: `cd node && go test ./internal/bpf/ -run TestReadBurstAlert_KernelLayout40 -count=1`
Expected: FAIL `short alert record 40`.

- [ ] **Step 3: Fix the length guard**

In `node/internal/bpf/inline.go:537`, change `if len(raw) < 48` to `if len(raw) < 40`.

- [ ] **Step 4: Verify pass**

Run same command. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add node/internal/bpf/inline.go node/internal/bpf/inline_ringbuf_test.go && git commit -m "fix(bpf): accept 40-byte kernel burst-alert records"
```

### Task 0.4: `xdp_inline` prog-run test harness

**Files:**
- Create: `node/internal/bpf/inline_prog_linux_test.go`
- Reference: existing `node/internal/bpf/prog_run_linux_test.go` for the loader pattern

- [ ] **Step 1: Write the harness (root-gated, fail-closed)**

```go
//go:build linux

package bpf

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatalf("BPF prog-run gates require root; run under sudo")
	}
}

// runInlineProgram builds a minimal IPv4+TCPUDP/SYN frame and runs XdpInline.
func runInlineProgram(t *testing.T, frame []byte) uint32 {
	t.Helper()
	objs := loadInlineForTest(t) // loads XsightMain-type object exposing XdpInline
	...
}
```

(Use `ebpf.Program.Test` with `bpf.RunOptions{Data: frame}`; assert the returned
`RunRetval`/`Retval` in `{XDP_PASS,XDP_DROP,XDP_TX,XDP_REDIRECT}`. Prefer the
generated `XsightObjects.XdpInline` handle.)

- [ ] **Step 2: Add a smoke assertion**

Assert an ARP frame yields `XDP_PASS` and a benign IPv4/UDP frame yields
`XDP_PASS` with no rules installed.

- [ ] **Step 3: Verify (root)**

Run: `cd node && sudo go test ./internal/bpf/ -run TestInlineProgram_Smoke -count=1`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add node/internal/bpf/inline_prog_linux_test.go && git commit -m "test(bpf): add xdp_inline prog-run harness"
```

---

## Phase 1 — Inline filter engine & clean-pipe

### Task 1.1: Fix `filter_consider` best-match reducer

**Files:** Modify `node/bpf/xsight.c:794-806`; Test `node/internal/bpf/inline_prog_linux_test.go`.

- [ ] **Step 1: Write failing prog-run test**

Install one `drop` rule for `203.0.113.7/dport 443` in `active_filter_rules`,
run a matching SYN frame, assert `XDP_DROP`.

- [ ] **Step 2: Verify it fails**

Run: `cd node && sudo go test ./internal/bpf/ -run TestInlineProgram_DropRule -count=1`
Expected: FAIL (returns `XDP_PASS` — rule ignored).

- [ ] **Step 3: Fix the reducer**

```c
static __always_inline void filter_consider(struct filter_hit *out,
                                            const struct filter_rule *r,
                                            bool cookie_action, __u64 now_ns)
{
    if (!rule_live(r, now_ns))
        return;
    if (!out->hit ||
        r->priority < out->rule.priority ||
        (r->priority == out->rule.priority && !out->is_cookie && cookie_action)) {
        out->rule = *r;
        out->is_cookie = cookie_action;
        out->hit = true;
    }
}
```

- [ ] **Step 4: Verify pass**, run the same command. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add node/bpf/xsight.c node/internal/bpf/inline_prog_linux_test.go && git commit -m "fix(bpf): filter_consider records the best matching rule"
```

### Task 1.2: Use `active_slot` in `xdp_inline`

**Files:** Modify `node/bpf/xsight.c:1431-1510`; Test prog-run.

- [ ] **Step 1: Write failing test**

Call `HotSwap`/`applyConfig` (active slot becomes 1), then install a watched
prefix; run a matching frame; assert the filter rule is evaluated.

- [ ] **Step 2: Verify fail.** Run `sudo go test ./internal/bpf/ -run TestInlineProgram_AfterConfigPush -count=1`. Expected: FAIL.

- [ ] **Step 3: Read the active slot like `xsight_main`**

At `xsight.c:1431`:

```c
__u32 slot_key = 0;
__u32 *slot = bpf_map_lookup_elem(&active_slot, &slot_key);
__u32 active = slot ? *slot : 0;
struct lpm_key dst_trie_key = {};
struct lpm_key src_trie_key = {};
__s64 dst_prefixlen = lookup_prefix(&dst_key, &dst_trie_key, active);
__s64 src_prefixlen = lookup_prefix(&src_key, &src_trie_key, active);
```

Replace every hardcoded `0` passed as `active_slot` to `PROCESS_DIRECTION` in
`xdp_inline` with `active`.

- [ ] **Step 4: Verify pass.** Expected: PASS.

- [ ] **Step 5: Commit** `fix(bpf): honor active_slot in xdp_inline`.

### Task 1.3: Unify rule-expiry clock domain

**Files:** Modify `node/bpf/xsight.h` (`filter_rule.expires_unix` → `expires_ns`), `node/bpf/xsight.c:787-791`, `node/internal/bpf/inline.go` (encode `expires_ns = now_ktime + ttl`).

- [ ] **Step 1: Failing test** — install a rule with a 1 ns TTL, sleep 5 ms, run a matching frame, assert `XDP_PASS` (rule expired).
- [ ] **Step 2: Verify fail.** Expected: FAIL (rule still drops).
- [ ] **Step 3: Implement**
  - Rename field to `expires_ns` (ktime domain) in `struct filter_rule`.
  - `rule_live` compares `r->expires_ns != 0 && r->expires_ns < bpf_ktime_get_ns()`.
  - Go encode: `expires_ns = uint64(time.Now().UnixNano())` is NOT ktime; instead
    send a relative TTL and let the node compute `boot_ktime + ttl`. Simpler and
    correct: node computes `expires_ns = ktimeNow() + rule.TTLns` where
    `ktimeNow()` reads `/proc/uptime` (or `CLOCK_MONOTONIC`) at install. Keep the
    wire field name; document that it is ktime.
- [ ] **Step 4: Verify pass + regenerate bindings** (`make generate`). Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): rule expiry uses monotonic ktime domain`.

### Task 1.4: Complete exact-rule wildcard permutations

**Files:** Modify `node/bpf/xsight.c:811-878`; Test prog-run for each form.

- [ ] **Step 1: Failing tests** — one per form: src-only, proto-only, dst+src+proto, global/default. Install each and assert the action fires; assert others do NOT match.
- [ ] **Step 2: Verify fail.** Expected: FAIL for the missing forms.
- [ ] **Step 3: Implement all permutations**

Enumerate lookups in cheapest-first order with the key fields zeroed
appropriately: full; any-sport; any-dport; any-port; dst+proto+dport;
dst+proto; dst; dst+src+proto; src+proto+dport; src+proto; src; proto; global.
Keep the function `__noinline` with its 64-byte key on its own frame; do not
exceed the 512-byte stack limit.

- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): full wildcard coverage for exact filter rules`.

### Task 1.5: Separate src/dst subnet tries with proto/port scope

**Files:** Modify `node/bpf/xsight.h` (`active_filter_subnets_dst`, `active_filter_subnets_src`), `node/bpf/xsight.c` (lookup + callers), `node/internal/bpf/inline.go` (populate both).

- [ ] **Step 1: Failing test** — install a src-subnet drop for `198.51.100.0/24`; assert inbound traffic *to* that subnet still passes and traffic *from* it drops.
- [ ] **Step 2: Verify fail.** Expected: FAIL (current trie matches both).
- [ ] **Step 3: Implement**
  - Two LPM tries. Value = `filter_rule` (carries proto + port + priority + action).
  - Query `_dst` with `dst16` and `_src` with `src16`; in the value match, reject
    when proto/ports do not match.
  - Go: upsert into `_dst` when `DstPrefixLen>0`, `_src` when `SrcPrefixLen>0`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): direction-scoped subnet tries with proto/port match`.

### Task 1.6: Correct Go rule routing for mixed prefixes

**Files:** Modify `node/internal/bpf/inline.go:200-340`; Test `inline_encoding_test.go`.

- [ ] **Step 1: Failing test** — a rule with exact `DstIP` + `SrcPrefixLen=24` must route to the source LPM trie (not the hash with a zeroed prefix).
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** `isSubnet := DstPrefixLen > 0 || SrcPrefixLen > 0`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(node): route mixed exact/LPM rules to the subnet tries`.

### Task 1.7: Enforce `default_action`

**Files:** Modify `node/inline.go:238-270`, `node/bpf/xsight.h` (config slot), `node/bpf/xsight.c` (fallback).

- [ ] **Step 1: Failing test** — push a snapshot with `default_action=drop`; a frame matching no rule is `XDP_DROP`; with `default_action=pass` it is `XDP_PASS`.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** a lowest-priority catch-all keyed rule installed/withdrawn with the snapshot (or a `CFG_DEFAULT_ACTION` config slot read only when `!hit`).
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(bpf): enforce inline default_action`.

### Task 1.8: Clean-pipe correctness

**Files:** Modify `node/bpf/xsight.h` (`filter_rule.encap_daddr`), `node/bpf/xsight.c:898-941,1318-1348`, `proto/xsight.proto` (already has field 17), `node/internal/bpf/inline.go`, `node/inline.go`.

- [ ] **Step 1: Failing test** — encode a rule with `encap_daddr`; assert the Go `InlineRuleSpec` carries it and the BPF value stores it; GRE build test asserts outer daddr set and payload proto `0x6558`.
- [ ] **Step 2: Verify fail.** Expected: FAIL (field dropped).
- [ ] **Step 3: Implement**
  - Plumb `encap_daddr` proto → spec → `filter_rule`.
  - `gre_encap_redirect`: set `gre[1] = bpf_htons(0x6558)`; set `iph->daddr = rule.encap_daddr`; source from `CFG_EGRESS_SADDR` config slot written at install.
  - Use `bpf_redirect_neigh` when available, else `bpf_redirect` (document L2 requirement).
  - Egress fallback: if rule `egress_ifindex==0`, use `CFG_EGRESS_IFINDEX` (now actually read).
  - `cleanpipe_encap=geneve`: return an install-time error ("geneve not supported; use gre").
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): correct GRE clean-pipe encap and encap_daddr plumbing`.

### Task 1.9: Clamp `rate_limit_pps`

**Files:** Modify `node/bpf/xsight.c:1290-1298`.

- [ ] **Step 1: Failing test** — a `rate_limit` rule with `RateLimitPPS=5` must not drop all traffic (budget ≥ 1 per 100 ms window).
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** `per_window = rate/10; if (per_window == 0) per_window = 1;`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): clamp rate-limit budget to at least one per window`.

---

## Phase 2 — SYN cookies, DNS, burst detection

### Task 2.1: Fix cookie ACK validation (C + Go + docs)

**Files:** Modify `node/bpf/xsight.c:1067-1087` and caller `:1509-1573`; `shared/cookie/cookie.go:130-145`; `shared/cookie/cookie_test.go`; `docs/INLINE.md:131-147`.

- [ ] **Step 1: Failing test (Go)** — `ValidAck(cookie, clientISN, ack=cookie+1)` must be true for arbitrary `clientISN`; false when `ack != cookie+1`.
- [ ] **Step 2: Verify fail.** Run `cd shared && go test ./cookie/ -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement**
  - C: `if (ack_num != (__u32)cookie + 1) { ...drop... }` and remove the `client_isn` comparison; drop the parameter (update caller).
  - Go: `ValidAck` signature `(cookie uint32, ackNum uint32) bool` returning `ackNum == cookie+1`.
  - Update `docs/INLINE.md` to `valid = client_ack == ISN+1`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(cookie): validate ACK by ack_seq == cookie+1`.

### Task 2.2: Correct SYN-ACK length and checksum

**Files:** Modify `node/bpf/xsight.c:1010,1038-1054`.

- [ ] **Step 1: Failing test (prog-run)** — feed a SYN; capture the `XDP_TX` frame (or assert the rewritten buffer via `bpf_prog_test_run` output); assert `iph->tot_len == htons(44)` and `tcp->check` verifies.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement**
  - `iph->tot_len = bpf_htons(44);`
  - `sum += (__u16)(IPPROTO_TCP << 8); sum += bpf_htons(24);`
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): correct SYN-ACK total length and TCP checksum`.

### Task 2.3: Derive L4 offset from IHL; support VLAN SYNs

**Files:** Modify `node/bpf/xsight.c:992-1030,1442`; caller of `syn_cookie_reply`.

- [ ] **Step 1: Failing test** — a SYN with IPv4 options (IHL=6) and a VLAN-tagged SYN both produce correct cookie replies.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** parse `ihl = iph->ihl*4`; pass the resolved L3/L4 offset into `syn_cookie_reply`; accept VLAN by resolving EtherType in the caller.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): IHL/VLAN-aware SYN-cookie parsing`.

### Task 2.4: Enable burst alerts

**Files:** Modify `node/internal/bpf/inline.go` (`setupInlineEngine`), `node/bpf/xsight.c:1112`.

- [ ] **Step 1: Failing test** — after setup, `CFG_ALERTS_ENABLE == 1`; a synthetic burst emits a ringbuf record that `readBurstAlert` parses.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** write `CFG_ALERTS_ENABLE=1` from Go at engine setup; make `emit_burst_alert` treat a missing/zero slot as disabled explicitly.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): enable burst alerts from userspace`.

### Task 2.5: Cookie gating, accounting order, validated scope

**Files:** Modify `node/bpf/xsight.c:1455-1608`.

- [ ] **Step 1: Failing tests** — (a) a SYN to a watched dest with no cookie rule is NOT answered; (b) SYN packets increment `burst_windows`; (c) a validated client still has filter rules applied.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** gate the cookie reply on `hit.is_cookie`; move `burst_track` before any early cookie return; move `client_validated` to the emergency branch only.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): gate cookies on rules and run burst accounting`.

### Task 2.6: Emergency reset and rate-limit key separation

**Files:** Modify `node/bpf/xsight.h` (new `rate_limit_windows`), `node/bpf/xsight.c:1139-1162,1287-1298`.

- [ ] **Step 1: Failing test** — a burst that ends does not immediately re-arm; burst and rate-limit counters on the same address do not collide.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** clear `count`/`sustained` on emergency entry and after expiry; key the rate limiter on a dedicated map.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): reset emergency state and separate rate-limit keys`.

### Task 2.7: DNS solicited/volume-aware drops

**Files:** Modify `node/bpf/xsight.c:1177-1276`, `node/bpf/xsight.h`.

- [ ] **Step 1: Failing test** — a solicited ANY/TXT response below the volume threshold passes; an unsolicited/over-volume high-amplification response drops.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** per-client/qtype count window; charge ANY/TXT an amplification score; drop only unsolicited or over-volume.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(bpf): volume-aware DNS amplification defense`.

### Task 2.8: Cookie secret lifecycle

**Files:** Modify `node/main.go:358-361`, `node/inline.go` (rotation), `node/internal/bpf/inline.go:430-435`.

- [ ] **Step 1: Failing test** — inline active with cookies enabled by a later controller push always has a non-zero secret; rotation writes are atomic.
- [ ] **Step 2: Verify fail.** Expected: FAIL (zero secret possible).
- [ ] **Step 3: Implement** start rotation whenever inline is active; store secret pair as one map value (or add a generation flag); refuse cookie enable without a secret.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(node): guarantee cookie secret and atomic rotation`.

---

## Phase 3 — Node userspace

### Task 3.1: Correct AF_XDP UMEM registration encoder

**Files:** Modify `node/internal/bpf/xsk.go:292-303`; Test `xsk_encode_test.go` (new).

- [ ] **Step 1: Failing test** — `packNative(xdpUmemReg{...})` returns `unsafe.Sizeof(xdpUmemReg{})` bytes with the struct's field values.
- [ ] **Step 2: Verify fail.** Expected: FAIL (16 bytes of interface header).
- [ ] **Step 3: Implement**

```go
func structBytes(v any) []byte {
	rv := reflect.ValueOf(v)
	sz := int(rv.Type().Size())
	buf := make([]byte, sz)
	reflect.NewAt(rv.Type(), unsafe.Pointer(&buf[0])).Elem().Set(rv)
	return buf
}
```

- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(xsk): correct zero-copy struct encoder`.

### Task 3.2: Correct ring mmap offsets and descriptor strides

**Files:** Modify `node/internal/bpf/xsk.go:320-362` and the descriptor-size constants.

- [ ] **Step 1: Failing test** — `mapRing` uses the `XDP_PGOFF_*` constant for RX/TX/FILL/COMP; fill/comp use 8-byte descriptors.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement**

```go
const (
	xdpPgoffRXRing = 0
	xdpPgoffTXRing = 0x80000000
	xdpPgoffFillRing = 0x100000000
	xdpPgoffCompRing = 0x180000000
)
```

`unix.Mmap(fd, int64(pgoff), size, ...)`; use `xskRingDescSize=16` for
rx/tx and `xskUmemDescSize=8` for fill/comp.

- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(xsk): correct ring mmap offsets and UMEM ring stride`.

### Task 3.3: XSKMAP registration ordering

**Files:** Modify `node/internal/bpf/xsk.go:276-290,583-600`.

- [ ] **Step 1: Failing test** — after `StartXSK`, the socket FD is present in `XsightXsk` for its queue.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** assign `globalXSKManager` before `OpenXSK` registration, or pass the manager into `OpenXSK`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(xsk): register socket after manager is available`.

### Task 3.4: XSK resource lifecycle

**Files:** Modify `node/internal/bpf/xsk.go:365-374,453-500,613-622`.

- [ ] **Step 1: Failing test** — double `Close` does not panic; `refillAll` never publishes offsets ≥ UMEM; TX frames return to the fill ring after `sendto` (kick TX).
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** retain and munmap the four ring mappings; make `Close` idempotent (`sync.Once`); bound `refillAll` by `numFrms`; add the `sendto`/poll TX kick.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(xsk): lifecycle, bounds, and TX kick`.

### Task 3.5: Synchronous, serialized reporter sends

**Files:** Modify `node/internal/reporter/reporter.go:356-369,432-569`; Test with `-race`.

- [ ] **Step 1: Failing race test** — concurrent stream sends and a canceled context produce no goroutine leak and no concurrent `Send`.
- [ ] **Step 2: Verify fail.** Run `cd node && go test -race ./internal/reporter/ -count=1`. Expected: FAIL/race.
- [ ] **Step 3: Implement** send synchronously under a per-stream mutex using the stream context; remove the timeout goroutine.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(reporter): serialize gRPC stream sends`.

### Task 3.6: Typed `mapCount`

**Files:** Modify `node/internal/bpf/inline.go:487-498`; Test.

- [ ] **Step 1: Failing test** — after installing N rules, `mapCount` returns N.
- [ ] **Step 2: Verify fail.** Expected: FAIL (0).
- [ ] **Step 3: Implement** iterate with concrete `var k filterRuleKey; var v filterRule`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(node): typed map iteration for posture counts`.

### Task 3.7: Rule-set semantics (tri-state cookies, versions, default_action, cookie_targets)

**Files:** Modify `node/inline.go:238-296`, `node/internal/bpf/inline.go`.

- [ ] **Step 1: Failing tests** — rules-only push preserves cookie enable; stale version rejected; `default_action`/`cookie_targets` applied.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** tri-state switch; monotonic version guard (`s.lastApplied`); plumb both fields.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(node): rule-set version/tri-state/default_action semantics`.

### Task 3.8: CriticalEvent fidelity, build tags, shutdown

**Files:** Modify `node/inline.go:166-203`, `node/main.go`, add `stub_notlinux.go` methods.

- [ ] **Step 1: Failing test** — CriticalEvent carries the BPF timestamp; a non-linux build compiles (`GOOS=darwin go build ./...`).
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** use `a.TimestampNS`; populate `current_bps`/`top_flows` where available; complete stubs; run defers on shutdown instead of `os.Exit`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(node): critical-event fidelity, stubs, graceful shutdown`.

### Task 3.9: Posture completeness (burst alerts, redirect, CPU)

**Files:** Modify `node/inline.go:133-161`; `node/internal/bpf/inline.go`.

- [ ] **Step 1: Failing test** — posture exposes drained alert count, redirect counters, and per-core utilization.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** count drained alerts into an atomic; read `inline_stats` redirect counters; sample CPU utilization.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(node): complete inline posture metrics`.

---

## Phase 4 — Controller

### Task 4.1: Default inline mitigation on + config docs

**Files:** Modify `controller/internal/config/config.go:162-170`, `controller/config.example.yaml`.

- [ ] **Step 1: Failing test** — `Load` with no `inline_enabled` yields `true`.
- [ ] **Step 2: Verify fail.** Run `cd controller && GOTOOLCHAIN=go1.25.0 go test ./internal/config/ -count=1`. Expected: FAIL.
- [ ] **Step 3: Implement** `InlineEnabled: true` in the `ActionConfig` default; document in the example YAML.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(config): enable inline mitigation by default`.

### Task 4.2: Serialize per-node ControlStream sends

**Files:** Modify `controller/internal/ingestion/grpc_handler.go:598-622`.

- [ ] **Step 1: Failing `-race` test** — concurrent `SendInlineRulePush` to one node is serialized.
- [ ] **Step 2: Verify fail.** Expected: race/failure.
- [ ] **Step 3: Implement** a per-node send mutex or a single writer goroutine + channel.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(controller): serialize ControlStream pushes per node`.

### Task 4.3: Off-lock withdrawal and non-blocking action enqueue

**Files:** Modify `controller/internal/tracker/tracker.go:410,582`, `controller/internal/engine/engine.go:239`.

- [ ] **Step 1: Failing test** — a stalled action dispatcher does not block the detection tick.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** dispatch `onEndedHook`/`notifyAction` asynchronously; non-blocking enqueue with a drop metric.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(tracker): dispatch actions off the detection lock`.

### Task 4.4: Withdraw inline rules on eviction

**Files:** Modify `controller/internal/tracker/tracker.go:1055-1098`.

- [ ] **Step 1: Failing test** — an evicted attack triggers `Withdraw`.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** call the ended hook in `evictAttack`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(tracker): withdraw inline rules on attack eviction`.

### Task 4.5: Rebuild inline mitigations on controller restart

**Files:** Modify `controller/main.go:246-252`, `controller/internal/tracker/tracker.go:791-861`.

- [ ] **Step 1: Failing test** — after `RecoverFromDB` with an active attack, `Reconcile` pushes non-empty rules.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** rebuild mitigations from recovered active attacks before serving.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(controller): rebuild inline state after restart`.

### Task 4.6: Source-subnet narrowing + wire narrowing source + re-narrow

**Files:** Modify `controller/internal/action/inline.go:184,460-464,239-317`; `controller/main.go` (wire `SetNarrowingSource`).

- [ ] **Step 1: Failing test** — with top source subnets present, narrow emits src-subnet drop rules; a rebreath re-narrows.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** emit `SrcIP/SrcPrefixLen` rules from `subnetCount` when `TopSrcSubnets` configured; supply a real `narrowFn`; re-narrow on rebreath.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(controller): source-subnet narrowing and re-narrow`.

### Task 4.7: Protocol-aware narrowing

**Files:** Modify `controller/internal/action/inline.go:481`.

- [ ] **Step 1: Failing test** — a UDP port flood produces UDP (proto 17) narrow rules.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** carry the dominant protocol into narrow rules.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(controller): protocol-aware narrowing`.

### Task 4.8: Periodic snapshot refresh + push on node attach

**Files:** Modify `controller/main.go` (ticker), `controller/internal/action/inline.go:199-236`.

- [ ] **Step 1: Failing test** — a ticker re-pushes before `RuleTTL`; attaching a node to an existing attack pushes immediately.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** `ReconcileAll` ticker < `RuleTTL`; push merged snapshot on node-set change.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(controller): refresh inline snapshots and push on attach`.

### Task 4.9: CriticalEventStream backpressure queue

**Files:** Modify `controller/internal/ingestion/grpc_handler.go:497-518`.

- [ ] **Step 1: Failing test** — a stalled handler does not block stream receipt (bounded queue + drop metric).
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** bounded worker queue mirroring `StatsStream`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(ingestion): bound CriticalEventStream backlog`.

### Task 4.10: Remaining controller correctness

**Files:** Modify `controller/internal/action/inline.go:648-651,534-536,113-124`, `controller/internal/config/config.go` (clamp).

- [ ] **Step 1: Failing tests** — `syn_cookie` only for SYN floods; no race on `mit.Nodes`; `inline_narrow_delay_ms` clamped to 500–1000.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** tighten `isHandshakeFlood`; snapshot nodes under lock; clamp config.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(controller): handshake detection, node race, delay clamp`.

---

## Phase 5 — L7 & console

### Task 5.1: Emit L7 events only above threshold

**Files:** Modify `node/internal/l7collector/collector.go:360-413`; Test.

- [ ] **Step 1: Failing test** — a single benign TLS ClientHello produces no event; a flood produces one with fingerprints attached.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** emit only on the threshold branch; attach JA3/JA4/UA to that event.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(l7): gate collector events on thresholds`.

### Task 5.2: Align L7 counter keys with the store

**Files:** Modify `node/internal/l7collector/collector.go`, `controller/internal/l7store/store.go:179-183`; shared constants.

- [ ] **Step 1: Failing test** — MissingSNI/Connections/UniqueSources are non-zero after a synthesized attack.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** a shared key constant set used by both sides; update `store_test.go`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(l7): align collector and store counter keys`.

### Task 5.3: Canonical JA4 + vectors

**Files:** Modify `shared/l7/ja3.go:80-140`; Test `ja3_fingerprint_test.go`.

- [ ] **Step 1: Failing test** — FoxIO known-answer vectors (4-char lowercase hex, sorted ciphers/extensions, `_` + sigalgs, marker `i`).
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** canonical encoding; version from supported_versions.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(l7): canonical JA4 encoding`.

### Task 5.4: PoW agreement + challenge wiring

**Files:** Modify `node/internal/l7collector/challenge.go:140-250`, `node/inline.go:344-355`; Test.

- [ ] **Step 1: Failing test** — the JS computation and Go `Validate` agree on a vector; the challenge page carries the token; the data plane calls the responder.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** identical byte representation; include the token in the page; wire `Mint`/`Validate`/`RenderChallenge307`/`SendRawFrame`, and emit challenge rules from the controller.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(l7): PoW agreement and challenge wiring`.

### Task 5.5: Slowloris raw-byte accumulation

**Files:** Modify `node/internal/l7collector/collector.go:251-308`; Test.

- [ ] **Step 1: Failing test** — byte-drip fragmented headers are detected; a sustained attack re-flags across windows.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** accumulate raw bytes per 5-tuple; allow re-flagging.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(l7): raw-byte slowloris detection`.

### Task 5.6: Keep L3 critical events out of the L7 store

**Files:** Modify `controller/main.go:362-365`, `controller/internal/l7store/store.go:145-157`.

- [ ] **Step 1: Failing test** — a `burst_emergency` event is not stored as an L7 record.
- [ ] **Step 2: Verify fail.** Expected: FAIL.
- [ ] **Step 3: Implement** filter by known L7 kinds in `onCritical`.
- [ ] **Step 4: Verify pass.** Expected: PASS.
- [ ] **Step 5: Commit** `fix(l7): exclude non-L7 critical events from the store`.

### Task 5.7: Console fixes

**Files:** Modify `controller/console/src/views/l7/L7.vue:7-9,125-175`, `views/inline/Inline.vue:227`, tests.

- [ ] **Step 1: Failing test** — `chartWidth` measured via ResizeObserver; `XPill` imported; posture renders burst alerts/redirect rate/CPU.
- [ ] **Step 2: Verify fail.** Run `cd controller/console && npm run build`. Expected: FAIL/warnings.
- [ ] **Step 3: Implement** the fixes above; extend the parity/mock fixtures as needed.
- [ ] **Step 4: Verify pass.** Expected: build + tests pass.
- [ ] **Step 5: Commit** `fix(console): chart width, XPill import, posture fields`.

---

## Final verification (after all tasks)

- [ ] `cd node && sudo go test ./... -count=1` → PASS.
- [ ] `cd node && grep -q OK <(make -B bpf && echo OK)` → ELF builds.
- [ ] `cd node && make generate-check` → no diff.
- [ ] `cd controller && GOTOOLCHAIN=go1.25.0 go test ./... -count=1` → PASS.
- [ ] `cd shared && go test ./... -count=1` → PASS.
- [ ] `cd controller && GOTOOLCHAIN=go1.25.0 go test -race ./internal/action/... ./internal/tracker/... ./internal/ingestion/...` → PASS.
- [ ] `cd node && go test -race ./internal/reporter/... -count=1` → PASS.
- [ ] `cd controller/console && npm ci && npm run build && npm test` → PASS.
- [ ] Update `docs/INLINE.md` and `docs/L7.md` to match corrected behavior.
- [ ] Commit final docs.

## Self-review notes

- Spec coverage: every "Confirmed defect inventory" item maps to a task above (Pillar 1 → 1.1–1.9; Pillar 2 → 2.1–2.8; Pillar 3 → 3.1–3.9; Pillar 4 → 4.1–4.10; Pillar 5 → 5.1–5.7; harness → 0.1–0.4).
- Out-of-scope items (GENEVE tunnel, IPv6 SYN cookies, offload-safe ELF split, traffic generator) are explicitly excluded, matching the spec.
- Type/name consistency: `filter_rule.expires_ns`, `active_filter_subnets_dst/_src`, `filter_hit`, `readBurstAlert`, `ValidAck(cookie, ackNum)` are used consistently across tasks.

## Execution status (final)

All phases complete and merged to `main` (fast-forward d6573ec → 1a5bd7e):

- Phases 0–5 implemented; every verification box above executed and green
  (node sudo full suite + `make -B bpf` stack 344 B ≤ 480; controller full
  suite; shared; action/tracker/ingestion `-race`; console build; docs
  updated in `be1ecf0`).
- Phase 5 post-review fixes in `3ac75c8`: TCP seq-continuity for the
  challenge funnel, XSS hardening (JSON-escaped page + hex/relative-path
  validation), challenge rules gated to AF_XDP-active nodes and IPv4
  targets, PoW 12→16 bits, deterministic token eviction with 32/IP quota,
  UMEM frame clamping, reply-before-consume, `make proto` grpc pin.
- Follow-up in `1a5bd7e`: eviction tie-break by mint sequence; the
  rebreath test withdraws its mitigation (fixed a real test-leak data race
  the `-race` gate caught).
- Console suite carries 788 pre-existing failures verified identical at
  the HEAD baseline (worktree comparison); tracked separately.
- Deferred from the review (intentional, documented in INLINE.md/L7.md):
  separate validated_clients scope for challenge admissions vs cookie
  validations, and reducer fall-through past a waived CHALLENGE hit.
