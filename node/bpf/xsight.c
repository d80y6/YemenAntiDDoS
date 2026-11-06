// SPDX-License-Identifier: GPL-2.0
// xSight Node — XDP program (pure counting + sampling, all XDP_DROP)
//            docs/node-development-plan.md P1/P2
//
// P0: Minimal skeleton ✓
// P1: L2/L3 parsing → trie lookup → per-IP/prefix counting ✓
// P2: ERSPAN decap (Type I/II/III) + ring buffer sampling

#include "xsight.h"

// ---------------------------------------------------------------------------
// DECODER_SWITCH — single source of truth for protocol → decoder index mapping.
// To add a new decoder: add one case here + one constant in xsight.h + one in
// shared/decoder/decoder.go + one case in node/internal/flow/decoder.go (flow mode mirror).
// All 4 call sites (ip_stats, prefix_stats, global inbound, global outbound) use this macro.
//
// TCP flag bits (RFC 793): FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10.
// For DDoS detection we subdivide TCP into:
//   - TCP_SYN: SYN set, ACK not set (client-initiated handshake — SYN flood signature)
//   - TCP_ACK: ACK set, SYN not set (stateless ACK flood signature, excludes SYN-ACK)
//   - TCP_RST: RST set (RST flood / abort signal spam)
//   - TCP_FIN: FIN set (FIN scan / FIN flood)
// Packets may increment multiple sub-counters (e.g., FIN+ACK → FIN + ACK).
// ---------------------------------------------------------------------------
#define DECODER_SWITCH(counts, byte_counts, pkt_len, l4_proto, tcp_flags, is_frag, is_bad_fragment, is_invalid) \
do {                                                                               \
    switch (l4_proto) {                                                            \
    case IPPROTO_TCP:                                                              \
        __sync_fetch_and_add(&(counts)[DECODER_TCP], 1);                           \
        __sync_fetch_and_add(&(byte_counts)[DECODER_TCP], pkt_len);                \
        if (((tcp_flags) & 0x02) && !((tcp_flags) & 0x10)) {                       \
            __sync_fetch_and_add(&(counts)[DECODER_TCP_SYN], 1);                   \
            __sync_fetch_and_add(&(byte_counts)[DECODER_TCP_SYN], pkt_len);        \
        }                                                                          \
        if (((tcp_flags) & 0x10) && !((tcp_flags) & 0x02)) {                       \
            __sync_fetch_and_add(&(counts)[DECODER_TCP_ACK], 1);                   \
            __sync_fetch_and_add(&(byte_counts)[DECODER_TCP_ACK], pkt_len);        \
        }                                                                          \
        if ((tcp_flags) & 0x04) {                                                  \
            __sync_fetch_and_add(&(counts)[DECODER_TCP_RST], 1);                   \
            __sync_fetch_and_add(&(byte_counts)[DECODER_TCP_RST], pkt_len);        \
        }                                                                          \
        if ((tcp_flags) & 0x01) {                                                  \
            __sync_fetch_and_add(&(counts)[DECODER_TCP_FIN], 1);                   \
            __sync_fetch_and_add(&(byte_counts)[DECODER_TCP_FIN], pkt_len);        \
        }                                                                          \
        break;                                                                     \
    case IPPROTO_UDP:                                                              \
        __sync_fetch_and_add(&(counts)[DECODER_UDP], 1);                           \
        __sync_fetch_and_add(&(byte_counts)[DECODER_UDP], pkt_len);                \
        break;                                                                     \
    case IPPROTO_ICMP:                                                             \
    case IPPROTO_ICMPV6:                                                           \
        __sync_fetch_and_add(&(counts)[DECODER_ICMP], 1);                          \
        __sync_fetch_and_add(&(byte_counts)[DECODER_ICMP], pkt_len);               \
        break;                                                                     \
    case IPPROTO_GRE:                                                              \
        __sync_fetch_and_add(&(counts)[DECODER_GRE], 1);                           \
        __sync_fetch_and_add(&(byte_counts)[DECODER_GRE], pkt_len);                \
        break;                                                                     \
    case IPPROTO_ESP:                                                              \
        __sync_fetch_and_add(&(counts)[DECODER_ESP], 1);                           \
        __sync_fetch_and_add(&(byte_counts)[DECODER_ESP], pkt_len);                \
        break;                                                                     \
    case IPPROTO_IGMP:                                                             \
        __sync_fetch_and_add(&(counts)[DECODER_IGMP], 1);                          \
        __sync_fetch_and_add(&(byte_counts)[DECODER_IGMP], pkt_len);               \
        break;                                                                     \
    default:                                                                       \
        /* Catch-all for IP protocols not explicitly tracked. */                   \
        __sync_fetch_and_add(&(counts)[DECODER_IP_OTHER], 1);                      \
        __sync_fetch_and_add(&(byte_counts)[DECODER_IP_OTHER], pkt_len);           \
        break;                                                                     \
    }                                                                              \
    if (is_frag) {                                                                 \
        __sync_fetch_and_add(&(counts)[DECODER_FRAG], 1);                          \
        __sync_fetch_and_add(&(byte_counts)[DECODER_FRAG], pkt_len);               \
    }                                                                              \
    /* v1.3 Phase 1b (追加): anomaly decoders are additive to protocol counters. \
     * A single bad fragment packet increments both its protocol (e.g., UDP) AND  \
     * DECODER_FRAG AND DECODER_BAD_FRAGMENT — gives operators a baseline-vs-attack \
     * ratio on the same chart. */                                                 \
    if (is_bad_fragment) {                                                         \
        __sync_fetch_and_add(&(counts)[DECODER_BAD_FRAGMENT], 1);                  \
        __sync_fetch_and_add(&(byte_counts)[DECODER_BAD_FRAGMENT], pkt_len);       \
    }                                                                              \
    if (is_invalid) {                                                              \
        __sync_fetch_and_add(&(counts)[DECODER_INVALID], 1);                       \
        __sync_fetch_and_add(&(byte_counts)[DECODER_INVALID], pkt_len);            \
    }                                                                              \
} while (0)

// Helper: update per-IP stats (protocol distribution + packet size)
// v1.3 Phase 1b: tcp_flags threaded through to DECODER_SWITCH for ACK/RST/FIN detection.
// v1.3 Phase 1b (追加): is_bad_fragment + is_invalid also threaded for anomaly counters.
// ---------------------------------------------------------------------------
static __always_inline void update_ip_stats(
    struct dst_ip_stats *st,
    __u32 pkt_len,
    __u8  l4_proto,
    __u8  tcp_flags,
    bool  is_frag,
    bool  is_bad_fragment,
    bool  is_invalid)
{
    __sync_fetch_and_add(&st->pkt_count, 1);
    __sync_fetch_and_add(&st->byte_count, pkt_len);

    DECODER_SWITCH(st->decoder_counts, st->decoder_byte_counts,
                   pkt_len, l4_proto, tcp_flags, is_frag, is_bad_fragment, is_invalid);

    if (pkt_len < PKT_SMALL_THRESHOLD)
        __sync_fetch_and_add(&st->small_pkt, 1);
    else if (pkt_len > PKT_LARGE_THRESHOLD)
        __sync_fetch_and_add(&st->large_pkt, 1);
    else
        __sync_fetch_and_add(&st->medium_pkt, 1);
}

// ---------------------------------------------------------------------------
// Helper: update per-decoder counters on prefix_stats (shared by inbound + outbound)
// ---------------------------------------------------------------------------
static __always_inline void update_prefix_decoders(
    struct prefix_stats *ps,
    __u32 pkt_len,
    __u8  l4_proto,
    __u8  tcp_flags,
    bool  is_frag,
    bool  is_bad_fragment,
    bool  is_invalid)
{
    DECODER_SWITCH(ps->decoder_counts, ps->decoder_byte_counts,
                   pkt_len, l4_proto, tcp_flags, is_frag, is_bad_fragment, is_invalid);
}

// MACRO: build prefix_key, mask host bits, lookup in map.
// Must be a macro because BPF map references must be compile-time constants.
// Result is stored in variable named _ps_##suffix.
#define LOOKUP_PREFIX_STATS(result_var, map, ip_key, matched_prefixlen)       \
do {                                                                          \
    struct prefix_key _lpk = {};                                              \
    __builtin_memcpy(_lpk.addr, (ip_key)->addr, 16);                         \
    _lpk.prefixlen = (matched_prefixlen);                                     \
    __u32 _fb = (matched_prefixlen) / 8;                                      \
    __u32 _rm = (matched_prefixlen) % 8;                                      \
    if (_fb < 16) {                                                           \
        if (_rm)                                                              \
            _lpk.addr[_fb] &= (0xFF << (8 - _rm));                           \
        _Pragma("unroll")                                                     \
        for (int _i = 0; _i < 16; _i++) {                                    \
            if (_i > _fb || (_i == _fb && _rm == 0))                          \
                _lpk.addr[_i] = 0;                                            \
        }                                                                     \
    }                                                                         \
    (result_var) = bpf_map_lookup_elem(&(map), &_lpk);                        \
} while (0)

// ---------------------------------------------------------------------------
// MACRO: process one direction — prefix_stats + ip_stats update
// Must be a macro (not function) because BPF map references must be
// compile-time constants — cannot pass maps through void* parameters.
// ---------------------------------------------------------------------------
#define PROCESS_DIRECTION(prefix_map, ip_map_a, ip_map_b, active_slot,       \
                          ip_key, trie_key, matched_prefixlen, pkt_len,       \
                          l4_proto, tcp_flags, is_frag,                       \
                          is_bad_fragment, is_invalid)                        \
do {                                                                          \
    struct prefix_stats *_ps;                                                 \
    LOOKUP_PREFIX_STATS(_ps, prefix_map, trie_key, matched_prefixlen);        \
    if (_ps) {                                                                \
        __sync_fetch_and_add(&_ps->pkt_count, 1);                             \
        __sync_fetch_and_add(&_ps->byte_count, pkt_len);                      \
        update_prefix_decoders(_ps, pkt_len, l4_proto, tcp_flags, is_frag,    \
                               is_bad_fragment, is_invalid);                  \
    }                                                                         \
    struct dst_ip_stats *_ist;                                                \
    if (active_slot == 0)                                                     \
        _ist = bpf_map_lookup_elem(&ip_map_a, ip_key);                        \
    else                                                                      \
        _ist = bpf_map_lookup_elem(&ip_map_b, ip_key);                        \
    if (_ist) {                                                               \
        update_ip_stats(_ist, pkt_len, l4_proto, tcp_flags, is_frag,          \
                        is_bad_fragment, is_invalid);                         \
    } else {                                                                  \
        /* The 224-byte dst_ip_stats value is too large for the verifier's    \
         * shared 512-byte call stack; build it in per-CPU scratch instead    \
         * and insert the fully-initialized entry atomically (same value as   \
         * the former stack local). */                                        \
        __u32 _scratch_key = 0;                                               \
        struct dst_ip_stats *_scr =                                           \
            bpf_map_lookup_elem(&ip_stats_scratch, &_scratch_key);            \
        if (_scr) {                                                           \
            __builtin_memset(_scr, 0, sizeof(*_scr));                         \
            update_ip_stats(_scr, pkt_len, l4_proto, tcp_flags, is_frag,      \
                            is_bad_fragment, is_invalid);                     \
            int _ret;                                                         \
            if (active_slot == 0)                                             \
                _ret = bpf_map_update_elem(&ip_map_a, ip_key, _scr,           \
                                           BPF_NOEXIST);                      \
            else                                                              \
                _ret = bpf_map_update_elem(&ip_map_b, ip_key, _scr,           \
                                           BPF_NOEXIST);                      \
            if (_ret != 0 && _ps)                                             \
                __sync_fetch_and_add(&_ps->overflow_count, 1);                \
        }                                                                     \
    }                                                                         \
} while (0)

#define IS_V4_MAPPED(key)                                                     \
    (((key)->addr[0] | (key)->addr[1] | (key)->addr[2] | (key)->addr[3] |       \
      (key)->addr[4] | (key)->addr[5] | (key)->addr[6] | (key)->addr[7] |       \
      (key)->addr[8] | (key)->addr[9] |                                      \
      ((key)->addr[10] ^ 0xff) | ((key)->addr[11] ^ 0xff)) == 0)

// Global linkage lets the verifier check this function independently of callers.
// Return a length in [0, 128] or -1; the caller must also bound the scalar result.
// Fully write trie_key without changing the original per-IP HASH key.
__noinline __s64 lookup_prefix(const struct lpm_key *ip_key,
                              struct lpm_key *trie_key, __u32 active)
{
    if (!ip_key)
        return -1;
    if (!trie_key)
        return -1;
    __builtin_memset(trie_key, 0, sizeof(*trie_key));
    if (ip_key->prefixlen == 32) {
        trie_key->prefixlen = 128;
        trie_key->addr[10] = trie_key->addr[11] = 0xff;
        __builtin_memcpy(trie_key->addr + 12, ip_key->addr, 4);
    } else {
        *trie_key = *ip_key;
        if (IS_V4_MAPPED(trie_key))
            return -1;
    }

    __u32 *prefixlen;
    if (active == 0)
        prefixlen = bpf_map_lookup_elem(&watch_trie_a, trie_key);
    else
        prefixlen = bpf_map_lookup_elem(&watch_trie_b, trie_key);
    if (!prefixlen)
        return -1;
    __u32 matched = *prefixlen;
    if (matched > 128)
        return -1;
    // Broad IPv6 prefixes may cover the mapped namespace: reject before counting.
    if (ip_key->prefixlen == 32 && matched < 96)
        return -1;
    return matched;
}

// UPDATE_GLOBAL_DECODERS — thin wrapper around DECODER_SWITCH for global_stats arrays.
// Kept as a named macro for readability at call sites.
#define UPDATE_GLOBAL_DECODERS(dec_counts, dec_byte_counts,                   \
                               pkt_len, l4_proto, tcp_flags, is_frag,         \
                               is_bad_fragment, is_invalid)                   \
    DECODER_SWITCH(dec_counts, dec_byte_counts, pkt_len, l4_proto, tcp_flags, \
                   is_frag, is_bad_fragment, is_invalid)

// ---------------------------------------------------------------------------
// Helper: read __u64 from config map with default
// ---------------------------------------------------------------------------
static __always_inline __u64 cfg_read(__u32 index, __u64 def)
{
    __u64 *val = bpf_map_lookup_elem(&xsight_config, &index);
    return val ? *val : def;
}

// ---------------------------------------------------------------------------
// Helper: emit sample to ring buffer
// Sends raw packet bytes (from data to data_end), capped at sample_bytes.
// Matched packets are sampled 1-in-N at random.
// ---------------------------------------------------------------------------
static __always_inline void emit_sample(struct xdp_md *ctx, struct global_stats *gs)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len  = (__u32)(data_end - data);

    // Reserve fixed-size slot: sample_hdr(8B) + MAX_SAMPLE_BYTES(512B) = 520B
    // Verifier needs constant size for bpf_ringbuf_reserve.
    void *buf = bpf_ringbuf_reserve(&samples, sizeof(struct sample_hdr) + MAX_SAMPLE_BYTES, 0);
    if (!buf) {
        // Ring buffer full — count the drop for backpressure signaling
        if (gs)
            __sync_fetch_and_add(&gs->sample_drops, 1);
        return;
    }

    __u64 sample_bytes = cfg_read(CFG_SAMPLE_BYTES, DEFAULT_SAMPLE_BYTES);

    if (sample_bytes == 0)
        sample_bytes = DEFAULT_SAMPLE_BYTES;
    if (sample_bytes > MAX_SAMPLE_BYTES)
        sample_bytes = MAX_SAMPLE_BYTES;
    __u64 cap_len = sample_bytes;

    // Don't read past packet end
    if (cap_len > pkt_len)
        cap_len = pkt_len;

    // Keep the checked scalar 64-bit so the verifier carries both bounds to
    // the helper argument without a separate 32-bit normalization.
    asm volatile("" : "+r"(cap_len));
    if (cap_len == 0 || cap_len > MAX_SAMPLE_BYTES) {
        bpf_ringbuf_discard(buf, 0);
        return;
    }

    // Write sample header (first 8 bytes of reserved slot)
    struct sample_hdr *hdr = buf;
    hdr->cap_len = cap_len;
    hdr->pkt_len = pkt_len;

    // Packet data follows header; the bound includes all 512 reserved bytes.
    if (bpf_xdp_load_bytes(ctx, 0, (void *)hdr + sizeof(struct sample_hdr), cap_len) < 0) {
        bpf_ringbuf_discard(buf, 0);
        return;
    }

    bpf_ringbuf_submit(buf, 0);
}

// ---------------------------------------------------------------------------
// Helper: parse inner IP header, extract dst_ip + l4 info
// Returns 0 on success, -1 if packet is too short / not IP.
// All results written to out-params (scalars only, no pkt_end passing).
// ---------------------------------------------------------------------------
// parse_ip extracts dst_ip key + L4 protocol info from IP header.
// src_key is extracted separately in xsight_main to avoid verifier pointer issues.
// v1.3 Phase 1b: replaced `is_syn bool` output with full `tcp_flags` byte so
// downstream DECODER_SWITCH can subdivide TCP into SYN/ACK/RST/FIN decoders.
// Output `tcp_flags` is the full RFC 793 flags byte (FIN=0x01, SYN=0x02, RST=0x04,
// PSH=0x08, ACK=0x10, URG=0x20); 0 for non-TCP packets.
//
// v1.3 Phase 1b (追加): added stateless anomaly detection.
//   *is_bad_fragment set when:
//     - fragment_end (offset*8 + payload) > 65535  (Ping of Death pattern)
//     - first fragment (MF=1, offset=0) with payload too small to contain L4 header
//       (tiny fragment: < 20B for TCP, < 8B for UDP) — indicates fragment-based IDS evasion
//   *is_invalid set when:
//     - IPv4 IHL < 5 (header shorter than minimum 20 bytes)
//     - IP total_length < IHL*4 (header says length less than header size)
//     - TCP doff < 5 (TCP header shorter than minimum 20 bytes)
//   IPv6 anomaly detection is intentionally limited in v1.3 (no IHL, fragment
//   extension headers require option walking). Only `is_invalid` is set for
//   IPv6 based on L4 header checks; IPv6 fragmentation anomalies defer to v1.4.
static __always_inline int parse_ip(
    void *l3_hdr, void *data_end,
    struct lpm_key *key, __u8 *l4_proto,
    bool *is_frag, __u8 *tcp_flags,
    bool *is_bad_fragment, bool *is_invalid,
    __u16 eth_type)
{
    if (eth_type == ETH_P_IP) {
        struct iphdr *iph = l3_hdr;
        if ((void *)(iph + 1) > data_end)
            return -1;

        key->prefixlen = 32;
        __builtin_memcpy(key->addr, &iph->daddr, 4);

        *l4_proto = iph->protocol;

        // v1.3 INVALID: IHL must be ≥ 5 (20 bytes minimum).
        // Bounded to ihl ≥ 5 below so downstream ihl*4 arithmetic is safe.
        __u8 ihl = iph->ihl;
        if (ihl < 5) {
            *is_invalid = true;
            return 0;  // Can't trust header → return early (l4_hdr offset undefined)
        }

        // v1.3 INVALID: total_length must be ≥ header size.
        __u16 tot_len = bpf_ntohs(iph->tot_len);
        __u16 hdr_bytes = (__u16)ihl * 4;
        if (tot_len < hdr_bytes) {
            *is_invalid = true;
        }

        __u16 frag_off = bpf_ntohs(iph->frag_off);
        __u16 mf       = frag_off & 0x2000;   // More Fragments flag
        __u16 offset13 = frag_off & 0x1FFF;   // Fragment offset in 8-byte units
        *is_frag = mf || offset13;

        if (*is_frag) {
            // v1.3 BAD_FRAGMENT — Ping of Death pattern: offset*8 + payload > 65535.
            // Clamp payload to avoid unsigned underflow if tot_len < hdr_bytes.
            __u16 payload = (tot_len > hdr_bytes) ? (tot_len - hdr_bytes) : 0;
            __u32 frag_end = ((__u32)offset13 * 8) + (__u32)payload;
            if (frag_end > 65535) {
                *is_bad_fragment = true;
            }
            // v1.3 BAD_FRAGMENT — Tiny fragment: first fragment (MF=1, offset=0)
            // must be big enough to contain L4 header to not hide flags/ports.
            if (mf && offset13 == 0) {
                if (*l4_proto == IPPROTO_TCP && payload < 20) {
                    *is_bad_fragment = true;
                }
                if (*l4_proto == IPPROTO_UDP && payload < 8) {
                    *is_bad_fragment = true;
                }
            }
        }

        if (*l4_proto == IPPROTO_TCP && !(*is_frag)) {
            void *l4_hdr = l3_hdr + hdr_bytes;
            if (l4_hdr + 14 <= data_end) {
                *tcp_flags = *((__u8 *)l4_hdr + 13);
                // v1.3 INVALID — TCP doff must be ≥ 5 (20 bytes minimum).
                // byte 12 upper 4 bits = data offset.
                __u8 doff = (*((__u8 *)l4_hdr + 12)) >> 4;
                if (doff < 5) {
                    *is_invalid = true;
                }
            }
        }
        return 0;

    } else if (eth_type == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = l3_hdr;
        if ((void *)(ip6h + 1) > data_end)
            return -1;

        key->prefixlen = 128;
        __builtin_memcpy(key->addr, &ip6h->daddr, 16);

        *l4_proto = ip6h->nexthdr;

        if (*l4_proto == IPPROTO_TCP) {
            void *l4_hdr = (void *)(ip6h + 1);
            if (l4_hdr + 14 <= data_end) {
                *tcp_flags = *((__u8 *)l4_hdr + 13);
                // v1.3 INVALID — TCP doff check (same as IPv4)
                __u8 doff = (*((__u8 *)l4_hdr + 12)) >> 4;
                if (doff < 5) {
                    *is_invalid = true;
                }
            }
        }
        return 0;
    }

    return -1;  // Not IP
}

// extract_src_key extracts source IP into an LPM key for outbound trie lookup.
// Separate function to avoid verifier pointer arithmetic issues with multi-output parse_ip.
static __always_inline void extract_src_key(
    void *l3_hdr, void *data_end,
    struct lpm_key *src_key, __u16 eth_type)
{
    if (eth_type == ETH_P_IP) {
        struct iphdr *iph = l3_hdr;
        if ((void *)(iph + 1) > data_end)
            return;
        src_key->prefixlen = 32;
        __builtin_memcpy(src_key->addr, &iph->saddr, 4);
    } else if (eth_type == ETH_P_IPV6) {
        struct ipv6hdr *ip6h = l3_hdr;
        if ((void *)(ip6h + 1) > data_end)
            return;
        src_key->prefixlen = 128;
        __builtin_memcpy(src_key->addr, &ip6h->saddr, 16);
    }
}

SEC("xdp")
int xsight_main(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len  = (__u32)(ctx->data_end - ctx->data);

    // ① global_stats — every packet, unconditionally
    __u32 gs_key = 0;
    struct global_stats *gs = bpf_map_lookup_elem(&global_stats, &gs_key);
    if (gs) {
        __sync_fetch_and_add(&gs->total_pkts, 1);
        __sync_fetch_and_add(&gs->total_bytes, pkt_len);
    }

    // ② Parse outer L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 eth_type = bpf_ntohs(eth->h_proto);
    void *l3_hdr = (void *)(eth + 1);

    // Handle 802.1Q VLAN (single tag) FIRST so ARP/NDP pass-through below
    // covers both untagged and single-VLAN-tagged mirror setups. Codex
    // v1.3.4 audit P1: placing the pass-through before the VLAN decap left
    // tagged ARP/NDP stranded, so any Juniper mirror on a tagged subint
    // would silently stop forwarding after neighbor-cache TTL.
    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr *vhdr = l3_hdr;
        if ((void *)(vhdr + 1) > data_end)
            return XDP_DROP;
        eth_type = bpf_ntohs(vhdr->h_vlan_encapsulated_proto);
        l3_hdr   = (void *)(vhdr + 1);
    }

    // ARP pass-through — upstream router (e.g., Juniper port-mirroring with
    // `next-hop`) needs to resolve node interface MAC via ARP to rewrite DMAC
    // on mirrored frames. Without this, mirror traffic stops after ARP cache
    // TTL expiry (~20min on Juniper). See node-development-plan.md §链路层保活例外.
    if (eth_type == ETH_P_ARP)
        return XDP_PASS;

    // IPv6 NDP pass-through — symmetric with ARP above, for IPv6 mirror
    // setups. Upstream uses ICMPv6 NS/NA (RFC 4861) instead of ARP to resolve
    // node MAC when mirror next-hop is an IPv6 address. Without this, any
    // Juniper `family inet6` mirror config would see zero traffic after
    // initial NDP cache expiry. Passes RS(133)/RA(134)/NS(135)/NA(136)/
    // Redirect(137). Missed when v1.3 added IPv6 parse support; moved
    // below the VLAN decap in v1.3.4 so tagged mirrors work too.
    if (eth_type == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = l3_hdr;
        if ((void *)(ip6 + 1) <= data_end &&
            ip6->nexthdr == IPPROTO_ICMPV6) {
            void *icmp6 = (void *)(ip6 + 1);
            if (icmp6 + 1 <= data_end) {
                __u8 icmp6_type = *(__u8 *)icmp6;
                if (icmp6_type >= 133 && icmp6_type <= 137)
                    return XDP_PASS;
            }
        }
    }

    // ② ERSPAN mode: detect GRE encapsulation → decap to inner frame
    // Read mode from config map: 0=mirror (default), 1=erspan
    __u64 mode = cfg_read(CFG_MODE, 0);

    if (mode == 1) {
        // ERSPAN path: outer must be IPv4 with protocol=GRE
        // (IPv6 GRE tunnels are theoretically possible but extremely rare)
        if (eth_type != ETH_P_IP)
            return XDP_DROP;

        struct iphdr *outer_iph = l3_hdr;
        if ((void *)(outer_iph + 1) > data_end)
            return XDP_DROP;

        if (outer_iph->protocol != IPPROTO_GRE)
            return XDP_DROP;

        // GRE header: flags(2B) + protocol(2B) = 4 bytes minimum
        void *gre_hdr = l3_hdr + (outer_iph->ihl * 4);
        if (gre_hdr + 4 > data_end)
            return XDP_DROP;

        __u16 gre_flags = bpf_ntohs(*(__u16 *)gre_hdr);
        __u16 gre_proto = bpf_ntohs(*((__u16 *)gre_hdr + 1));

        if (gre_flags & (GRE_FLAG_ROUTING | GRE_VERSION_MASK))
            return XDP_DROP;
        __u32 gre_len = 4;
        if (gre_flags & GRE_FLAG_CSUM)
            gre_len += 4;
        if (gre_flags & GRE_FLAG_KEY)
            gre_len += 4;
        if (gre_flags & GRE_FLAG_SEQ)
            gre_len += 4;

        // Determine inner frame offset based on ERSPAN type
        // Reference: brainstorm-node.md "ERSPAN auto-detection"
        void *inner_eth;

        if (gre_proto == GRE_PROTO_ERSPAN_III) {
            // Type III: GRE and its options, then the 12-byte ERSPAN header.
            inner_eth = gre_hdr + gre_len + 12;
            // Note: optional 8B subheader not handled (PoC — record if needed)

        } else if (gre_proto == GRE_PROTO_ERSPAN_II) {
            // Without S, preserve Type I semantics (no ERSPAN header).
            inner_eth = (gre_flags & GRE_FLAG_SEQ) ? gre_hdr + gre_len + 8 : gre_hdr + gre_len;

        } else {
            // Unknown GRE protocol — drop
            return XDP_DROP;
        }

        // Parse inner Ethernet
        struct ethhdr *inner_eth_hdr = inner_eth;
        if ((void *)(inner_eth_hdr + 1) > data_end)
            return XDP_DROP;

        eth_type = bpf_ntohs(inner_eth_hdr->h_proto);
        l3_hdr   = (void *)(inner_eth_hdr + 1);

        // Handle inner VLAN
        if (eth_type == ETH_P_8021Q) {
            struct vlan_hdr *ivhdr = l3_hdr;
            if ((void *)(ivhdr + 1) > data_end)
                return XDP_DROP;
            eth_type = bpf_ntohs(ivhdr->h_vlan_encapsulated_proto);
            l3_hdr   = (void *)(ivhdr + 1);
        }
    }

    // ③ Parse IP — dst_key via parse_ip, src_key via separate extract (avoids verifier pointer issues)
    struct lpm_key dst_key = {};
    struct lpm_key src_key = {};
    __u8  l4_proto        = 0;
    bool  is_frag         = false;
    __u8  tcp_flags       = 0;  // v1.3 Phase 1b: full TCP flags byte for SYN/ACK/RST/FIN dispatch
    bool  is_bad_fragment = false;  // v1.3 Phase 1b (追加)
    bool  is_invalid      = false;  // v1.3 Phase 1b (追加)

    if (parse_ip(l3_hdr, data_end, &dst_key, &l4_proto, &is_frag, &tcp_flags,
                 &is_bad_fragment, &is_invalid, eth_type) != 0)
        return XDP_DROP;

    // Extract src_ip for outbound detection (separate call to avoid verifier issues)
    extract_src_key(l3_hdr, data_end, &src_key, eth_type);

    struct lpm_key dst_trie_key = {};
    struct lpm_key src_trie_key = {};

    // ④ Read active_slot → choose trie + maps
    __u32 slot_key = 0;
    __u32 *slot = bpf_map_lookup_elem(&active_slot, &slot_key);
    __u32 active = slot ? *slot : 0;

    // ⑤ / ⑤b LPM trie lookup — inbound / outbound, with identical family guards.
    __s64 dst_prefixlen = lookup_prefix(&dst_key, &dst_trie_key, active);
    __s64 src_prefixlen = lookup_prefix(&src_key, &src_trie_key, active);
    // Keep caller bounds even if clang infers the callee's return range.
    asm volatile("" : "+r"(dst_prefixlen), "+r"(src_prefixlen));

    // Both miss → done.
    // Global-call results are unknown scalars here; bound both before masking.
    // Unsigned comparison also rejects the -1 miss sentinel. Keep the barrier.
    if ((__u64)dst_prefixlen > 128) {
        asm volatile("" ::: "memory");
        if ((__u64)src_prefixlen > 128)
            return XDP_DROP;
    }

    // ====== INBOUND (dst_ip matched) ======
    if ((__u64)dst_prefixlen <= 128) {
        if (gs) {
            __sync_fetch_and_add(&gs->matched_pkts, 1);
            __sync_fetch_and_add(&gs->matched_bytes, pkt_len);
            UPDATE_GLOBAL_DECODERS(gs->decoder_counts, gs->decoder_byte_counts,
                                   pkt_len, l4_proto, tcp_flags, is_frag,
                                   is_bad_fragment, is_invalid);
        }
        PROCESS_DIRECTION(prefix_stats_map, ip_stats_a, ip_stats_b,
                          active, &dst_key, &dst_trie_key, (__u32)dst_prefixlen,
                          pkt_len, l4_proto, tcp_flags, is_frag,
                          is_bad_fragment, is_invalid);
    }

    // ====== OUTBOUND (src_ip matched) — same macro, different maps ======
    if ((__u64)src_prefixlen <= 128) {
        if (gs) {
            __sync_fetch_and_add(&gs->src_matched_pkts, 1);
            __sync_fetch_and_add(&gs->src_matched_bytes, pkt_len);
            UPDATE_GLOBAL_DECODERS(gs->src_decoder_counts, gs->src_decoder_byte_counts,
                                   pkt_len, l4_proto, tcp_flags, is_frag,
                                   is_bad_fragment, is_invalid);
        }
        PROCESS_DIRECTION(src_prefix_stats_map, src_stats_a, src_stats_b,
                          active, &src_key, &src_trie_key, (__u32)src_prefixlen,
                          pkt_len, l4_proto, tcp_flags, is_frag,
                          is_bad_fragment, is_invalid);
    }

    // ⑧ Ring buffer sampling — after trie match (either direction)
    __u64 sample_rate = cfg_read(CFG_SAMPLE_RATE, DEFAULT_SAMPLE_RATE);
    if (sample_rate == 0)
        sample_rate = 1;

    if (sample_rate <= 1 || ((__u64)bpf_get_prandom_u32() % sample_rate) == 0)
        emit_sample(ctx, gs);

    // ⑨ Drop — mirror/ERSPAN packets are copies
    return XDP_DROP;
}

// ===========================================================================
// v4.0 INLINE SCRUBBING ENGINE (xdp_inline program)
//
// Sits in the packet path (XDP_PASS for benign traffic) and implements:
//   1. Bidirectional active filter rules (hash exact + LPM subnet tables)
//      with PASS/DROP/TX/REDIRECT actions incl. GRE clean-pipe encapsulation.
//   2. Stateless kernel TCP SYN cookies (siphash-2-4) answered in-place via
//      XDP_TX; client ACKs validate the cookie and enter validated_clients.
//   3. UDP/DNS reflection defense via an outstanding-query LRU map.
//   4. Sub-second burst detection (100ms sliding windows) driving a 2s
//      emergency micro-drop state with urgent ringbuf alerts.
//
// Hardware offload note: the program avoids unbounded loops, spin locks and
// dynamic pointer arithmetic. Ringbuf emission and prandom sampling are the
// two helpers SmartNICs (ConnectX-6 / Netronome / E810) typically reject in
// offload mode — both are config-gated, and the node agent falls back to
// driver-mode attach when offload verification fails (see node posture).
// ===========================================================================

#define rotl64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// ---------------------------------------------------------------------------
// siphash-2-4 over a fixed 40-byte message (5 LE u64 words + length block).
// The Go mirror lives in shared/cookie/cookie.go — keep both in lockstep.
// Message layout: sip[0..8], sip[8..16], dip[0..8], dip[8..16],
//                 (u64)sport | ((u64)dport << 32)
// ---------------------------------------------------------------------------
static __always_inline __u64 xsight_siphash24(__u64 k0, __u64 k1,
                                              const __u8 *msg /* 40 bytes */)
{
    __u64 m[5];
    __builtin_memcpy(&m[0], msg + 0, 8);
    __builtin_memcpy(&m[1], msg + 8, 8);
    __builtin_memcpy(&m[2], msg + 16, 8);
    __builtin_memcpy(&m[3], msg + 24, 8);
    __builtin_memcpy(&m[4], msg + 32, 8);

    __u64 v0 = 0x736f6d6570736575ULL ^ k0;
    __u64 v1 = 0x646f72616e646f6dULL ^ k1;
    __u64 v2 = 0x6c7967656e657261ULL ^ k0;
    __u64 v3 = 0x7465646279746573ULL ^ k1;
    __u64 b = 40ULL << 56;

#pragma unroll
    for (int i = 0; i < 5; i++) {
        v3 ^= m[i];
        /* SipHash-2-4: 2 compression rounds per word (keep in lockstep with
         * shared/cookie siphash24 — one round here would make the Go mirror
         * and any external validator disagree with kernel cookies). */
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
        v0 ^= m[i];
    }

    v3 ^= b;
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    v0 ^= b;

    v2 ^= 0xff;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
        v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    }
    return v0 ^ v1 ^ v2 ^ v3;
}

static __always_inline void stat_add(__u32 idx, __u64 n)
{
    __u64 *v = bpf_map_lookup_elem(&inline_stats, &idx);
    if (v)
        __sync_fetch_and_add(v, n);
}

// ipv4_csum computes the IPv4 header checksum over hdr_bytes (20..60). The
// pointer bound is checked per word so the verifier can see every access.
static __always_inline __u16 ipv4_csum(struct iphdr *iph, void *data_end, __u32 hdr_bytes)
{
    __u32 sum = 0;
    __u16 *w = (__u16 *)iph;
    if (hdr_bytes < 20)
        hdr_bytes = 20;
    if (hdr_bytes > 60)
        hdr_bytes = 60;
    iph->check = 0;
#pragma unroll
    for (int i = 0; i < 30; i++) {
        if ((__u32)(i * 2) < hdr_bytes && (void *)(w + i + 1) <= data_end)
            sum += w[i];
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (__u16)~sum;
}

// ---------------------------------------------------------------------------
// Filter rule evaluation — exact hash table (wildcard variants, most-specific
// first) then subnet LPM tables. Returns the highest-priority live rule or
// NULL. `dst16`/`src16` are 16-byte arrays (IPv4 in the first 4 bytes).
// ---------------------------------------------------------------------------
struct filter_hit {
    struct filter_rule rule;
    bool is_cookie;   // rule requested the SYN-cookie engine
    bool hit;
};

static __always_inline bool rule_live(const struct filter_rule *r, __u64 now_ns)
{
    if (r->expires_ns != 0 && r->expires_ns < now_ns)
        return false;
    return true;
}

// Subnet trie values only carry an address prefix; proto/ports narrow the
// rule scope (0 = wildcard). Ports are network byte order in both places.
static __always_inline bool filter_rule_matches(const struct filter_rule *r,
                                                __u8 proto, __u16 dport, __u16 sport)
{
    if (r->proto != 0 && r->proto != proto)
        return false;
    if (r->dst_port != 0 && r->dst_port != dport)
        return false;
    if (r->src_port != 0 && r->src_port != sport)
        return false;
    return true;
}

static __always_inline void filter_consider(struct filter_hit *out,
                                            const struct filter_rule *r,
                                            bool cookie_action, __u64 now_ns)
{
    if (!rule_live(r, now_ns))
        return;
    if (!out->hit || r->priority < out->rule.priority ||
        (r->priority == out->rule.priority && !out->is_cookie && cookie_action)) {
        out->rule = *r;
        out->is_cookie = cookie_action;
        out->hit = true;
    }
}

// Global (noinline): the 64-byte key lives on this function's own frame.
// ports packs dport in the high half and sport in the low half.
// Returns 0: BPF global (noinline) functions must return a scalar.
__noinline int filter_exact_lookup(struct filter_hit *out,
                                                const struct addr16 *dst16,
                                                const struct addr16 *src16,
                                                __u8 proto, __u32 ports)
{
    // Global functions are first verified against the prototype with pointer
    // args typed mem_or_null, so each needs an explicit null guard on entry.
    if (!out || !dst16 || !src16)
        return 0;
    __u64 now_ns = bpf_ktime_get_ns();
    __u16 dport = (__u16)(ports >> 16);
    __u16 sport = (__u16)(ports & 0xFFFF);
    struct filter_rule_key k = {};
    __builtin_memcpy(k.dst_addr, dst16, 16);
    __builtin_memcpy(k.src_addr, src16, 16);
    k.proto = proto;
    k.dst_port = dport;
    k.src_port = sport;

    struct filter_rule *r;

    // Prefix lens are unused by the hash table; the controller zeroes them too.
    k.dst_prefix_len = 0;
    k.src_prefix_len = 0;

    // 1) full 5-tuple
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 2) any destination port (sport retained)
    k.dst_port = 0;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 3) any source port (dport retained). Without this permutation a rule
    //    that pins dst_port but wildcards src_port never matches.
    k.dst_port = dport;
    k.src_port = 0;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 4) any source + destination port
    k.dst_port = 0;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 5) dst + proto + dport, any source + sport
    __builtin_memset(k.src_addr, 0, 16);
    k.dst_port = dport;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 6) dst + proto, any source + ports
    k.dst_port = 0;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 7) dst only, any proto/source/ports
    k.proto = 0;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 8) src + proto + dport, any destination + sport (egress ACL)
    __builtin_memcpy(k.src_addr, src16, 16);
    k.proto = proto;
    __builtin_memset(k.dst_addr, 0, 16);
    k.dst_port = dport;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 9) src + proto, any destination + ports
    k.dst_port = 0;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 10) src only, any destination/proto/ports
    k.proto = 0;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 11) proto only, any address/ports
    __builtin_memset(k.src_addr, 0, 16);
    k.proto = proto;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);

    // 12) global default rule
    k.proto = 0;
    r = bpf_map_lookup_elem(&active_filter_rules, &k);
    if (r)
        filter_consider(out, r, r->action == FILTER_ACTION_SYN_COOKIE, now_ns);
    return 0;
}

// LPM subnet lookups: match the address (v4 → /32 prefix on 4 bytes, v6 →
// /128). Kept static/always_inline (not global noinline fns) so the map-value
// pointer may be the return value — global functions must return a scalar to
// the verifier. Each body is a 20-byte lpm_key plus one lookup, so inlining
// costs one frame slot in the caller.
static __always_inline struct filter_rule *filter_subnet_lookup_dst(const __u8 *addr16, bool is_v4)
{
    struct lpm_key k = {};
    __builtin_memcpy(k.addr, addr16, 16);
    k.prefixlen = is_v4 ? 32 : 128;
    return bpf_map_lookup_elem(&active_filter_subnets_dst, &k);
}

static __always_inline struct filter_rule *filter_subnet_lookup_src(const __u8 *addr16, bool is_v4)
{
    struct lpm_key k = {};
    __builtin_memcpy(k.addr, addr16, 16);
    k.prefixlen = is_v4 ? 32 : 128;
    return bpf_map_lookup_elem(&active_filter_subnets_src, &k);
}

// ---------------------------------------------------------------------------
// GRE clean-pipe encapsulation: wraps the frame in IPv4+GRE (4-byte header,
// no options) and redirects to the egress interface. The new outer frame
// reuses the original Ethernet header. Clean-pipe egress is treated as an L2
// adjacency: the original DMAC is reused and bpf_redirect() transmits without
// neighbour resolution (no bpf_redirect_neigh).
// ---------------------------------------------------------------------------
__noinline int gre_encap_redirect(struct xdp_md *ctx, __u32 egress_if,
                                  __u32 remote_daddr, __u32 local_saddr)
{
    const __u32 GRE_OVERHEAD = 14 + 20 + 4;
    if (bpf_xdp_adjust_head(ctx, -(int)GRE_OVERHEAD))
        return -1;

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + GRE_OVERHEAD + 14 > data_end)
        return -1;

    // Rebuild outer Ethernet: copy the original header (sits at data+38),
    // then relabel the protocol as IPv4.
    __builtin_memcpy(data, data + GRE_OVERHEAD, 14);
    struct ethhdr *eth = data;
    eth->h_proto = bpf_htons(ETH_P_IP);

    struct iphdr *iph = data + 14;
    if ((void *)(iph + 1) > data_end)
        return -1;
    __builtin_memset(iph, 0, sizeof(*iph));
    iph->version = 4;
    iph->ihl = 5;
    iph->tot_len = bpf_htons((__u16)(data_end - (data + 14)));
    iph->ttl = 64;
    iph->protocol = IPPROTO_GRE;
    iph->saddr = local_saddr; // CFG_EGRESS_SADDR (0 when the egress has no IPv4)
    iph->daddr = remote_daddr;
    iph->check = ipv4_csum(iph, data_end, 20);

    __u16 *gre = data + 34;
    if ((void *)gre + 1 > data_end)
        return -1;
    gre[0] = 0;                            // flags + version = 0
    gre[1] = bpf_htons(GRE_PROTO_TEB);     // payload is an Ethernet frame

    if (bpf_redirect(egress_if, 0) != 0) {
        stat_add(INLINE_STAT_REDIRECT_ERR, 1);
        return -1;
    }
    stat_add(INLINE_STAT_REDIRECT_OK, 1);
    return 0;
}

// ---------------------------------------------------------------------------
// Stateless SYN-cookie engine.
// ---------------------------------------------------------------------------
// Global (noinline) so its 40-byte message buffer gets its own verifier
// stack frame instead of inflating xdp_inline's 512-byte budget.
__noinline __u64 syn_cookie_compute(const struct addr16 *sip16,
                                    const struct addr16 *dip16,
                                    __u16 sport, __u16 dport)
{
    // Global fn: pointer args are mem_or_null on entry — guard before deref.
    if (!sip16 || !dip16)
        return 0;
    __u64 secret_lo = cfg_read(CFG_COOKIE_SECRET_LO, 0);
    __u64 secret_hi = cfg_read(CFG_COOKIE_SECRET_HI, 0);

    __u8 msg[40];
    // sip16/dip16 are struct addr16*, so byte offsets come from ->b: plain
    // pointer arithmetic would advance by whole 16-byte structs.
    __builtin_memcpy(msg + 0, sip16->b + 0, 8);
    __builtin_memcpy(msg + 8, sip16->b + 8, 8);
    __builtin_memcpy(msg + 16, dip16->b + 0, 8);
    __builtin_memcpy(msg + 24, dip16->b + 8, 8);
    __u64 ports = (__u64)sport | ((__u64)dport << 32);
    __builtin_memcpy(msg + 32, &ports, 8);
    return xsight_siphash24(secret_lo, secret_hi, msg);
}

// syn_cookie_emit rewrites the validated SYN into a SYN-ACK in place and
// transmits it via XDP_TX. IPv4 only; the packet is truncated to
// l3_off + iph->ihl*4 + 24 (eth 14/18 + ip 20..60 + tcp 24 with MSS option).
// cookie_and_seq packs client_seq in the high 32 bits and the cookie in the
// low 32 bits so the function stays within the 5-argument BPF call limit.
__noinline int syn_cookie_emit(struct xdp_md *ctx, __u32 ports, __u64 cookie_and_seq)
{
    __u16 sport = (__u16)(ports & 0xFFFF);
    __u16 dport = (__u16)(ports >> 16);
    __u32 cookie = (__u32)cookie_and_seq;
    __u32 client_seq = (__u32)(cookie_and_seq >> 32);
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    __u32 l3_off = 14;
    __u16 eth_type = bpf_ntohs(eth->h_proto);
    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr *vhdr = (void *)(eth + 1);
        if ((void *)(vhdr + 1) > data_end)
            return -1;
        eth_type = bpf_ntohs(vhdr->h_vlan_encapsulated_proto);
        l3_off = 18;
    }
    if (eth_type != ETH_P_IP)
        return -1; // cookie path is IPv4-only (documented); IPv6 falls to filters

    struct iphdr *iph = (void *)((char *)data + l3_off);
    if ((void *)(iph + 1) > data_end)
        return -1;
    __u32 hdr_bytes = (__u32)iph->ihl * 4;
    if (hdr_bytes < 20 || hdr_bytes > 60)
        return -1;
    if ((void *)((char *)iph + hdr_bytes) > data_end)
        return -1;

    __u32 l4_off = l3_off + hdr_bytes;
    struct tcphdr *tcp = (void *)((char *)data + l4_off);
    if ((void *)((char *)tcp + 24) > data_end)
        return -1; // SYN must carry the full 24-byte TCP header we emit

    // L2: swap MACs (reflection is out the same interface). The VLAN tag, if
    // present, stays in place between the Ethernet and IPv4 headers.
    __u8 tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    __u32 new_saddr = iph->daddr;
    __u32 new_daddr = iph->saddr;
    iph->saddr = new_saddr;
    iph->daddr = new_daddr;
    iph->tot_len = bpf_htons((__u16)(hdr_bytes + 24));
    iph->ttl = 64;
    iph->check = ipv4_csum(iph, data_end, hdr_bytes);

    __u16 new_sport = dport;
    __u16 new_dport = sport;
    tcp->source = new_sport;
    tcp->dest = new_dport;
    tcp->seq = bpf_htonl((__u32)cookie);
    tcp->ack_seq = bpf_htonl(client_seq + 1);
    tcp->doff = 6;                       // 24-byte header (MSS option)
    *((__u8 *)tcp + 13) = 0x12;          // SYN|ACK
    tcp->window = bpf_htons(0xFFFF);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    // MSS option (kind=2, len=4, mss=1460) fills the last 4 TCP header bytes.
    __u8 *opt = (__u8 *)tcp + 20;
    if ((void *)opt + 4 > data_end)
        return -1;
    opt[0] = 2;
    opt[1] = 4;
    opt[2] = 0x05; // 1460 >> 8
    opt[3] = 0xB4; // 1460 & 0xFF

    // TCP checksum: pseudo-header + 24 header bytes (no payload). The header
    // words are read as native __u16 (network-order bytes), so the protocol
    // and length words use the same byte order as the segment sum.
    {
        __u32 sum = 0;
        sum += (new_saddr >> 16) & 0xFFFF;
        sum += new_saddr & 0xFFFF;
        sum += (new_daddr >> 16) & 0xFFFF;
        sum += new_daddr & 0xFFFF;
        sum += (IPPROTO_TCP << 8);
        sum += bpf_htons(24);
        __u16 *w = (__u16 *)tcp;
#pragma unroll
        for (int i = 0; i < 12; i++)
            sum += w[i];
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        tcp->check = (__u16)~sum;
    }

    // Truncate to exactly l3_off + IP header + TCP header (58 without a VLAN
    // tag or IP options; 62 with either).
    __u32 want_len = l4_off + 24;
    if (bpf_xdp_adjust_tail(ctx, (int)(want_len - (__u32)(data_end - data))))
        return -1;

    stat_add(INLINE_STAT_COOKIE_REPLY, 1);
    return 0;
}

// syn_cookie_reply computes the stateless cookie and delegates the in-place
// SYN-ACK rewrite. Keeping the emit path in its own global subprogram bounds
// the verifier's deepest call chain (xdp_inline → reply → emit/csum).
__noinline int syn_cookie_reply(struct xdp_md *ctx,
                                const struct addr16 *sip16,
                                const struct addr16 *dip16,
                                __u32 ports, __u32 client_seq)
{
    if (!sip16 || !dip16)
        return -1;
    __u16 sport = (__u16)(ports & 0xFFFF);
    __u16 dport = (__u16)(ports >> 16);
    __u64 cookie = syn_cookie_compute(sip16, dip16, sport, dport);
    __u64 packed = ((__u64)client_seq << 32) | (__u32)cookie;
    return syn_cookie_emit(ctx, ports, packed);
}

// validate_cookie_ack checks the client's final ACK against the expected
// cookie. A real client acknowledges the SYN-ACK with ack_seq == cookie+1; its
// own sequence number is unrelated. On success the client is admitted into
// validated_clients.
// ports packs dport high, sport low (BPF global fns take max 5 args).
__noinline int validate_cookie_ack(const struct addr16 *sip16,
                                   const struct addr16 *dip16,
                                   __u32 ports, __u32 ack_num)
{
    if (!sip16 || !dip16)
        return -1;
    __u16 sport = (__u16)(ports & 0xFFFF);
    __u16 dport = (__u16)(ports >> 16);
    __u64 now = bpf_ktime_get_ns();
    __u64 cookie = syn_cookie_compute(sip16, dip16, sport, dport);
    if (ack_num != (__u32)cookie + 1) {
        stat_add(INLINE_STAT_COOKIE_DROPPED, 1);
        return -1;
    }
    __u64 expiry = now + VALIDATED_CLIENT_TTL_NS;
    __u8 key[16];
    __builtin_memcpy(key, sip16, 16);
    bpf_map_update_elem(&validated_clients, key, &expiry, BPF_ANY);
    stat_add(INLINE_STAT_COOKIE_VALIDATED, 1);
    return 0;
}

static __always_inline bool client_validated(const __u8 *addr16)
{
    __u64 *expiry = bpf_map_lookup_elem(&validated_clients, addr16);
    if (!expiry)
        return false;
    if (*expiry < bpf_ktime_get_ns())
        return false;
    return true;
}

// ---------------------------------------------------------------------------
// Burst detection — per-destination 100ms sliding window. On the second
// consecutive breached window the destination enters a 2s emergency
// micro-drop state and an urgent alert is pushed to the ringbuf.
// ---------------------------------------------------------------------------
// dst16 rides as a pointer (burst windows' key buffer); time is re-read here.
// Returns 0 on success: BPF global (noinline) functions must return a scalar
// — a void return is rejected by the verifier ("doesn't return scalar").
__noinline int emit_burst_alert(const struct addr16 *dst16, bool is_v4,
                                __u32 window_pps, __u32 proto, __u8 tcp_flags)
{
    if (!dst16)
        return 0;
    if (!cfg_read(CFG_ALERTS_ENABLE, 0))
        return 0; // zero slot = explicitly disabled (array maps default to 0)
    struct burst_alert *a = bpf_ringbuf_reserve(&alerts, sizeof(*a), 0);
    if (!a)
        return 0;
    a->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memcpy(a->dst_addr, dst16, 16);
    a->is_v4 = is_v4 ? 1 : 0;
    a->window_pps = window_pps;
    a->proto = proto;
    a->tcp_flags = tcp_flags;
    bpf_ringbuf_submit(a, 0);
    return 0;
}

static __always_inline struct burst_window *burst_window_get(const __u8 *addr16, __u64 now)
{
    struct burst_window *w = bpf_map_lookup_elem(&burst_windows, addr16);
    if (w)
        return w;
    struct burst_window init = {};
    init.window_start_ns = now;
    if (bpf_map_update_elem(&burst_windows, addr16, &init, BPF_NOEXIST) != 0)
        return bpf_map_lookup_elem(&burst_windows, addr16);
    return bpf_map_lookup_elem(&burst_windows, addr16);
}

static __always_inline struct burst_window *rate_window_get(const __u8 *addr16, __u64 now)
{
    struct burst_window *w = bpf_map_lookup_elem(&rate_limit_windows, addr16);
    if (w)
        return w;
    struct burst_window init = {};
    init.window_start_ns = now;
    if (bpf_map_update_elem(&rate_limit_windows, addr16, &init, BPF_NOEXIST) != 0)
        return bpf_map_lookup_elem(&rate_limit_windows, addr16);
    return bpf_map_lookup_elem(&rate_limit_windows, addr16);
}

static __always_inline void burst_track(const __u8 *dst16, bool is_v4, __u32 proto, __u8 tcp_flags)
{
    __u64 now = bpf_ktime_get_ns();
    struct burst_window *w = burst_window_get(dst16, now);
    if (!w)
        return;
    // Emergency exit: discard the stale window count/sustained state so the
    // next packet cannot immediately re-arm another 2s drop window.
    if (w->emergency_until_ns != 0 && now >= w->emergency_until_ns) {
        w->count = 0;
        w->sustained = 0;
        w->window_start_ns = now;
        w->emergency_until_ns = 0;
    }
    if (now - w->window_start_ns >= BURST_WINDOW_NS) {
        __u32 pps = w->count * 10;
        w->count = 0;
        w->window_start_ns = now;
        __u64 threshold = cfg_read(CFG_BURST_PPS, 0);
        if (threshold && pps >= threshold) {
            w->sustained++;
            if (w->sustained >= BURST_SUSTAINED_TRIGGER &&
                now > w->emergency_until_ns) {
                // Emergency entry: start a clean window in addition to arming
                // the drop state, so the high pre-entry count cannot carry over.
                w->count = 0;
                w->sustained = 0;
                w->window_start_ns = now;
                w->emergency_until_ns = now + BURST_EMERGENCY_NS;
                (void)emit_burst_alert((const struct addr16 *)dst16, is_v4, pps, proto, tcp_flags);
            }
        } else if (pps < threshold / 2) {
            w->sustained = 0;
        }
    }
    w->count++;
}

static __always_inline bool in_emergency(const __u8 *dst16)
{
    struct burst_window *w = bpf_map_lookup_elem(&burst_windows, dst16);
    if (!w)
        return false;
    return w->emergency_until_ns > bpf_ktime_get_ns();
}

// ---------------------------------------------------------------------------
// DNS reflection defense.
// ---------------------------------------------------------------------------
// dns_parse_qtype walks the question name (bounded) and returns the qtype in
// network byte order, or 0 when parsing fails.
static __always_inline __u16 dns_parse_qtype(__u8 *dns, __u8 *dns_end)
{
    __u8 *p = dns;
    __u8 *end = dns_end;
    if (p + 12 > end)
        return 0; // need header (id 2 + flags 2 + counts 8)
    p += 12;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (p + 1 > end)
            return 0;
        __u8 len = *p;
        if (len == 0) {
            p += 1;
            break;
        }
        if (len & 0xC0) { // compression pointer — qtype follows 1 byte later
            p += 2;
            if (p + 2 > end)
                return 0;
            __u16 qt;
            __builtin_memcpy(&qt, p, 2);
            return qt;
        }
        p += 1 + len;
    }
    if (p + 2 > end)
        return 0;
    __u16 qt;
    __builtin_memcpy(&qt, p, 2);
    return qt;
}

#define DNS_QTYPE_ANY 0x00FF
#define DNS_QTYPE_TXT 0x0010

// dns_protect tracks outbound queries and drops unsolicited/amplified
// responses toward protected clients. Returns an XDP verdict.
static __always_inline int dns_protect(const __u8 *src16, const __u8 *dst16,
                                       bool src_watched, bool dst_watched,
                                       void *udph, void *data_end)
{
    struct udphdr *u = udph;
    if ((void *)(u + 1) > data_end)
        return 0; // let parser decide elsewhere

    __u16 sport = bpf_ntohs(u->source);
    __u16 dport = bpf_ntohs(u->dest);
    if (sport != 53 && dport != 53)
        return 0;

    void *dns = (void *)(u + 1);

    if (dport == 53 && src_watched) {
        // Outbound client query — record (client, id, qtype) for 2s.
        __u16 qid = 0, qtype = 0;
        if (dns + 2 <= data_end) {
            __builtin_memcpy(&qid, dns, 2);
            qtype = dns_parse_qtype(dns, data_end);
        }
        struct dns_query_key k = {};
        __builtin_memcpy(k.client_addr, src16, 16);
        k.query_id = qid;
        k.qtype = qtype;
        __u64 expiry = bpf_ktime_get_ns() + DNS_QUERY_TTL_NS;
        bpf_map_update_elem(&dns_outstanding, &k, &expiry, BPF_ANY);
        return 0;
    }

    if (sport == 53 && dst_watched) {
        // Inbound response toward a protected client — must be solicited.
        __u16 qid = 0, qtype = 0;
        if (dns + 2 <= data_end) {
            __builtin_memcpy(&qid, dns, 2);
            qtype = dns_parse_qtype(dns, data_end);
        }
        struct dns_query_key k = {};
        __builtin_memcpy(k.client_addr, dst16, 16);
        k.query_id = qid;
        k.qtype = qtype;
        __u64 *expiry = bpf_map_lookup_elem(&dns_outstanding, &k);
        bool solicited = expiry && *expiry > bpf_ktime_get_ns();
        if (!solicited) {
            stat_add(INLINE_STAT_DNS_DROPS, 1);
            return XDP_DROP;
        }
        // Amplification vectors: ANY responses and large TXT payloads are
        // dropped even when solicited (anomaly threshold by size).
        if (qtype == bpf_htons(DNS_QTYPE_ANY)) {
            stat_add(INLINE_STAT_DNS_DROPS, 1);
            return XDP_DROP;
        }
        __u16 dgram_len = bpf_ntohs(u->len);
        if (qtype == bpf_htons(DNS_QTYPE_TXT) && dgram_len > 256) {
            stat_add(INLINE_STAT_DNS_DROPS, 1);
            return XDP_DROP;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Rate-limit action: fixed 100ms window on the source address; exceeding
// rate_limit_pps drops for the remainder of the window.
// ---------------------------------------------------------------------------
static __always_inline bool rate_limited(const struct filter_rule *r, const __u8 *src16)
{
    if (r->action != FILTER_ACTION_RATE_LIMIT || r->rate_limit_pps == 0)
        return false;
    __u64 now = bpf_ktime_get_ns();
    struct burst_window *w = rate_window_get(src16, now);
    if (!w)
        return false;
    if (now - w->window_start_ns >= BURST_WINDOW_NS) {
        w->count = 0;
        w->window_start_ns = now;
    }
    __u64 per_window = r->rate_limit_pps / 10;
    if (per_window == 0)
        per_window = 1;
    if (w->count >= per_window)
        return true;
    w->count++;
    return false;
}

// apply_filter verdicts for the actions the inline program enforces itself.
// Returns 1 when a verdict was reached (stored in *verdict), 0 to continue.
static __always_inline int apply_filter(struct xdp_md *ctx, const struct filter_rule *r,
                                        __u32 rx_queue, int *verdict)
{
    switch (r->action) {
    case FILTER_ACTION_PASS:
        stat_add(INLINE_STAT_FILTER_PASS, 1);
        *verdict = XDP_PASS;
        return 1;
    case FILTER_ACTION_DROP:
        stat_add(INLINE_STAT_FILTER_DROPS, 1);
        *verdict = XDP_DROP;
        return 1;
    case FILTER_ACTION_TX:
        *verdict = XDP_TX;
        return 1;
    case FILTER_ACTION_REDIRECT: {
        // A rule with no egress ifindex falls back to the clean-pipe egress
        // configured by the node (CFG_EGRESS_IFINDEX).
        __u32 egress = r->egress_ifindex;
        if (egress == 0)
            egress = (__u32)cfg_read(CFG_EGRESS_IFINDEX, 0);

        if (r->encap == ENCAP_GRE) {
            __u32 saddr = (__u32)cfg_read(CFG_EGRESS_SADDR, 0);
            if (gre_encap_redirect(ctx, egress, r->encap_daddr, saddr) == 0) {
                *verdict = XDP_REDIRECT;
                return 1;
            }
            *verdict = XDP_DROP;
            return 1;
        }
        // GENEVE is rejected at install time; drop defensively if a stale
        // rule ever reaches the data plane with an unsupported encap.
        if (r->encap != ENCAP_NONE) {
            stat_add(INLINE_STAT_REDIRECT_ERR, 1);
            *verdict = XDP_DROP;
            return 1;
        }
        if (bpf_redirect(egress, 0) == 0) {
            stat_add(INLINE_STAT_REDIRECT_OK, 1);
            *verdict = XDP_REDIRECT;
        } else {
            stat_add(INLINE_STAT_REDIRECT_ERR, 1);
            *verdict = XDP_DROP;
        }
        return 1;
    }
    case FILTER_ACTION_CHALLENGE:
        // Steer into the AF_XDP socket for L7 inspection / JS-PoW challenge.
        // Fall through to normal handling when no socket is bound to the queue.
        if (bpf_map_lookup_elem(&xsight_xsk, &rx_queue)) {
            stat_add(INLINE_STAT_XSK_STEER, 1);
            *verdict = bpf_redirect_map(&xsight_xsk, rx_queue, 0);
            return 1;
        }
        return 0;
    case FILTER_ACTION_RATE_LIMIT:
        *verdict = XDP_PASS; // enforcement happens at the call site (needs src16)
        return 1;
    default:
        return 0;
    }
}

// ---------------------------------------------------------------------------
// INLINE PROGRAM ENTRY — bidirectional inline scrubbing.
// Verdict default is XDP_PASS: clean traffic flows unmodified; only policy
// hits (rules / emergencies / cookies / DNS defense) divert packets.
// ---------------------------------------------------------------------------
SEC("xdp")
int xdp_inline(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 pkt_len  = (__u32)(data_end - data);
    __u32 rx_queue = ctx->rx_queue_index;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u16 eth_type = bpf_ntohs(eth->h_proto);
    void *l3_hdr = (void *)(eth + 1);

    if (eth_type == ETH_P_8021Q) {
        struct vlan_hdr *vhdr = l3_hdr;
        if ((void *)(vhdr + 1) > data_end)
            return XDP_DROP;
        eth_type = bpf_ntohs(vhdr->h_vlan_encapsulated_proto);
        l3_hdr   = (void *)(vhdr + 1);
    }

    // Control-plane keepalives always pass (same rationale as mirror mode).
    if (eth_type == ETH_P_ARP)
        return XDP_PASS;
    if (eth_type == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = l3_hdr;
        if ((void *)(ip6 + 1) <= data_end && ip6->nexthdr == IPPROTO_ICMPV6) {
            void *icmp6 = (void *)(ip6 + 1);
            if (icmp6 + 1 <= data_end) {
                __u8 t = *(__u8 *)icmp6;
                if (t >= 133 && t <= 137)
                    return XDP_PASS;
            }
        }
    }

    struct lpm_key dst_key = {};
    struct lpm_key src_key = {};
    __u8  l4_proto  = 0;
    bool  is_frag   = false;
    __u8  tcp_flags = 0;
    bool  is_bad_fragment = false;
    bool  is_invalid      = false;

    if (parse_ip(l3_hdr, data_end, &dst_key, &l4_proto, &is_frag, &tcp_flags,
                 &is_bad_fragment, &is_invalid, eth_type) != 0)
        return XDP_PASS; // non-IP: pass in inline mode

    extract_src_key(l3_hdr, data_end, &src_key, eth_type);

    bool is_v4 = (eth_type == ETH_P_IP);
    // dst_key.addr/src_key.addr already hold the zero-padded address: the keys
    // are zero-initialized and parse_ip/extract_src_key only overwrite IPv4's
    // first 4 bytes, so alias them as the 16-byte addr16 buffers rather than
    // spending 32 bytes of stack on copies.
    const __u8 *dst16 = dst_key.addr;
    const __u8 *src16 = src_key.addr;

    // Watch-trie membership determines "protected destination" semantics.
    struct lpm_key dst_trie_key = {};
    struct lpm_key src_trie_key = {};
    __u32 slot_key = 0;
    __u32 *slot = bpf_map_lookup_elem(&active_slot, &slot_key);
    __u32 active = slot ? *slot : 0;
    __s64 dst_prefixlen = lookup_prefix(&dst_key, &dst_trie_key, active);
    __s64 src_prefixlen = lookup_prefix(&src_key, &src_trie_key, active);
    asm volatile("" : "+r"(dst_prefixlen), "+r"(src_prefixlen));
    bool dst_watched = (__u64)dst_prefixlen <= 128;
    bool src_watched = (__u64)src_prefixlen <= 128;

    // UDP/TCP ports for policy and DNS defense (parsed before L4-frag guard).
    __u16 sport = 0;
    __u16 dport = 0;
    void *l4;
    if (is_v4) {
        struct iphdr *iph4 = l3_hdr;
        // parse_ip() above proved the fixed IPv4 header is in bounds.
        __u8 ihl = iph4->ihl;
        if (ihl < 5)
            ihl = 5;
        l4 = l3_hdr + (__u32)ihl * 4;
    } else {
        l4 = l3_hdr + 40;
    }
    if (l4_proto == IPPROTO_TCP && !is_frag) {
        if (l4 + 4 <= data_end) {
            __builtin_memcpy(&sport, l4, 2);
            __builtin_memcpy(&dport, ((char *)l4) + 2, 2);
        }
    } else if (l4_proto == IPPROTO_UDP && !is_frag) {
        if (l4 + 4 <= data_end) {
            __builtin_memcpy(&sport, l4, 2);
            __builtin_memcpy(&dport, ((char *)l4) + 2, 2);
        }
    }

    // Burst accounting runs before any policy/cookie early return so a SYN
    // flood is counted and alerted even when a cookie rule answers it.
    if (dst_watched)
        burst_track(dst16, is_v4, l4_proto, tcp_flags);

    // ---- Inline engine gate -------------------------------------------------
    bool cookie_requested = false;
    if (cfg_read(CFG_INLINE_ENABLE, 0)) {
        // ① Active filter rules — bidirectional (inbound dst + outbound src).
        if (!is_frag) {
            __u64 now_ns = bpf_ktime_get_ns();
            struct filter_hit hit = {};
            (void)filter_exact_lookup(&hit, (const struct addr16 *)dst16,
                                        (const struct addr16 *)src16,
                                        l4_proto, ((__u32)dport << 16) | sport);
            struct filter_rule *sub = filter_subnet_lookup_dst(dst16, is_v4);
            if (sub && filter_rule_matches(sub, l4_proto, dport, sport))
                filter_consider(&hit, sub, sub->action == FILTER_ACTION_SYN_COOKIE, now_ns);
            struct filter_rule *ssub = filter_subnet_lookup_src(src16, is_v4);
            if (ssub && filter_rule_matches(ssub, l4_proto, dport, sport))
                filter_consider(&hit, ssub, ssub->action == FILTER_ACTION_SYN_COOKIE, now_ns);

            cookie_requested = hit.hit && hit.is_cookie;

            if (hit.hit) {
                int verdict = 0;
                if (hit.rule.action == FILTER_ACTION_SYN_COOKIE) {
                    // Handled by the cookie path below.
                } else if (apply_filter(ctx, &hit.rule, rx_queue, &verdict)) {
                    if (hit.rule.action == FILTER_ACTION_RATE_LIMIT) {
                        if (rate_limited(&hit.rule, src16)) {
                            stat_add(INLINE_STAT_FILTER_DROPS, 1);
                            return XDP_DROP;
                        }
                    }
                    if (verdict == XDP_PASS && dst_watched) {
                        PROCESS_DIRECTION(prefix_stats_map, ip_stats_a, ip_stats_b,
                                          active, &dst_key, &dst_trie_key, (__u32)dst_prefixlen,
                                          pkt_len, l4_proto, tcp_flags, is_frag,
                                          is_bad_fragment, is_invalid);
                    }
                    return verdict;
                }
            }
        }

        // ② Emergency micro-drop state (2s) — validated clients bypass only this drop.
        if (dst_watched && !client_validated(src16) && in_emergency(dst16)) {
            if (l4_proto == IPPROTO_TCP) {
                if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
                    // SYN inside a SYN flood — answer with a stateless cookie.
                    if (cookie_requested && cfg_read(CFG_SYN_COOKIE_ENABLE, 1) && is_v4) {
                        __u32 client_seq = 0;
                        if (l4 + 8 <= data_end) {
                            __builtin_memcpy(&client_seq, ((char *)l4) + 4, 4);
                            client_seq = bpf_ntohl(client_seq);
                        }
                        if (syn_cookie_reply(ctx, (const struct addr16 *)src16,
                                (const struct addr16 *)dst16,
                                ((__u32)dport << 16) | sport, client_seq) == 0)
                            return XDP_TX;
                    }
                    stat_add(INLINE_STAT_EMERGENCY_DROPS, 1);
                    return XDP_DROP;
                }
                if ((tcp_flags & 0x10) && !(tcp_flags & 0x02)) {
                    // Final ACK — validate the cookie before admitting.
                    if (cfg_read(CFG_SYN_COOKIE_ENABLE, 1) && is_v4 && !is_frag) {
                        __u32 ack_num = 0;
                        if (l4 + 12 <= data_end) {
                            __builtin_memcpy(&ack_num, ((char *)l4) + 8, 4);
                            ack_num = bpf_ntohl(ack_num);
                        }
                        if (validate_cookie_ack((const struct addr16 *)src16,
                                                (const struct addr16 *)dst16,
                                                ((__u32)dport << 16) | sport,
                                                ack_num) == 0)
                            return XDP_PASS;
                    }
                    stat_add(INLINE_STAT_EMERGENCY_DROPS, 1);
                    return XDP_DROP;
                }
            }
            stat_add(INLINE_STAT_EMERGENCY_DROPS, 1);
            return XDP_DROP;
        }

        // ③ Explicit SYN-cookie zone (rule-driven, no emergency needed).
        if (cookie_requested && l4_proto == IPPROTO_TCP &&
            (tcp_flags & 0x02) && !(tcp_flags & 0x10) &&
            cfg_read(CFG_SYN_COOKIE_ENABLE, 1) && is_v4 && !is_frag && dst_watched) {
            __u32 client_seq = 0;
            if (l4 + 8 <= data_end) {
                __builtin_memcpy(&client_seq, ((char *)l4) + 4, 4);
                client_seq = bpf_ntohl(client_seq);
            }
            if (syn_cookie_reply(ctx, (const struct addr16 *)src16,
                                (const struct addr16 *)dst16,
                                ((__u32)dport << 16) | sport, client_seq) == 0)
                return XDP_TX;
        }

        // ④ DNS reflection defense.
        if (cfg_read(CFG_DNS_PROTECT, 1) && l4_proto == IPPROTO_UDP && !is_frag) {
            int v = dns_protect(src16, dst16, src_watched, dst_watched, l4, data_end);
            if (v)
                return v;
        }
    }

    // ---- Accounting (shared with mirror mode) -------------------------------
    __u32 gs_key = 0;
    struct global_stats *gs = bpf_map_lookup_elem(&global_stats, &gs_key);
    if (gs) {
        __sync_fetch_and_add(&gs->total_pkts, 1);
        __sync_fetch_and_add(&gs->total_bytes, pkt_len);
    }

    if (dst_watched) {
        if (gs) {
            __sync_fetch_and_add(&gs->matched_pkts, 1);
            __sync_fetch_and_add(&gs->matched_bytes, pkt_len);
            UPDATE_GLOBAL_DECODERS(gs->decoder_counts, gs->decoder_byte_counts,
                                   pkt_len, l4_proto, tcp_flags, is_frag,
                                   is_bad_fragment, is_invalid);
        }
        PROCESS_DIRECTION(prefix_stats_map, ip_stats_a, ip_stats_b,
                          active, &dst_key, &dst_trie_key, (__u32)dst_prefixlen,
                          pkt_len, l4_proto, tcp_flags, is_frag,
                          is_bad_fragment, is_invalid);
    }
    if (src_watched) {
        if (gs) {
            __sync_fetch_and_add(&gs->src_matched_pkts, 1);
            __sync_fetch_and_add(&gs->src_matched_bytes, pkt_len);
        }
        PROCESS_DIRECTION(src_prefix_stats_map, src_stats_a, src_stats_b,
                          active, &src_key, &src_trie_key, (__u32)src_prefixlen,
                          pkt_len, l4_proto, tcp_flags, is_frag,
                          is_bad_fragment, is_invalid);
    }

    // L7 sampling (optional): feed the existing sampler pipeline with a
    // bounded 1-in-N slice of protected TCP traffic for HTTP/TLS inspection.
    if (dst_watched && l4_proto == IPPROTO_TCP) {
        __u64 rate = cfg_read(CFG_INLINE_SAMPLE, 0);
        if (rate && rate <= 1)
            emit_sample(ctx, gs);
        else if (rate && ((__u64)bpf_get_prandom_u32() % rate) == 0)
            emit_sample(ctx, gs);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
