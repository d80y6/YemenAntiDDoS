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
        struct dst_ip_stats _new = {};                                        \
        update_ip_stats(&_new, pkt_len, l4_proto, tcp_flags, is_frag,         \
                        is_bad_fragment, is_invalid);                         \
        int _ret;                                                             \
        if (active_slot == 0)                                                 \
            _ret = bpf_map_update_elem(&ip_map_a, ip_key, &_new,              \
                                       BPF_NOEXIST);                          \
        else                                                                  \
            _ret = bpf_map_update_elem(&ip_map_b, ip_key, &_new,              \
                                       BPF_NOEXIST);                          \
        if (_ret != 0 && _ps)                                                 \
            __sync_fetch_and_add(&_ps->overflow_count, 1);                    \
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

char _license[] SEC("license") = "GPL";
