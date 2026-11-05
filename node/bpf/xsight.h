// SPDX-License-Identifier: GPL-2.0
// xSight Node — BPF shared definitions

#ifndef __XSIGHT_H__
#define __XSIGHT_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Config map indices
#define CFG_SAMPLE_RATE      0  // dynamic sample rate (written by Agent)
#define CFG_SAMPLE_BYTES     1  // per-packet capture length (128-512)
#define CFG_MODE             2  // 0=mirror, 1=erspan
#define CFG_UPSTREAM_RATE    3  // upstream_sample_rate (from config.yaml)
// v4.0 inline scrubbing config (xsight_config grows 8 → 16 entries)
#define CFG_INLINE_ENABLE    4  // inline filter engine master switch (xdp_inline program)
#define CFG_SYN_COOKIE_ENABLE 5 // kernel SYN-cookie engine master switch
#define CFG_COOKIE_SECRET_LO 6  // siphash secret, low 64 bits (rotated by Agent)
#define CFG_COOKIE_SECRET_HI 7  // siphash secret, high 64 bits
#define CFG_EGRESS_IFINDEX   8  // clean-pipe egress interface for XDP_REDIRECT
#define CFG_BURST_PPS        9  // per-dst burst threshold (PPS) → 2s emergency drop
#define CFG_ALERTS_ENABLE    10 // burst alert ringbuf emissions (0 = offload-safe builds)
#define CFG_DNS_PROTECT      11 // UDP/DNS reflection defense master switch
#define CFG_INLINE_SAMPLE    12 // inline-mode L7 sampling 1-in-N (0 = disabled)
#define CFG_MAX              16 // xsight_config array size

// Inline filter actions (mirrors proto InlineRule.action strings)
#define FILTER_ACTION_PASS       0
#define FILTER_ACTION_DROP       1
#define FILTER_ACTION_TX         2
#define FILTER_ACTION_REDIRECT   3
#define FILTER_ACTION_RATE_LIMIT 4  // enforced as drop beyond limit (see filter apply)
#define FILTER_ACTION_SYN_COOKIE 5
#define FILTER_ACTION_CHALLENGE  6  // steer into AF_XDP socket map for L7 challenge

// Clean-pipe encapsulation kinds (proto InlineRule.encap)
#define ENCAP_NONE   0
#define ENCAP_GRE    1
#define ENCAP_GENEVE 2

// SYN-cookie validated-client lifetime (ns) and DNS outstanding-query TTL
#define VALIDATED_CLIENT_TTL_NS (60ULL * 1000000000ULL)
#define DNS_QUERY_TTL_NS        (2ULL * 1000000000ULL)

// Burst sliding window: 100ms granularity, 2s emergency drop window
#define BURST_WINDOW_NS     (100ULL * 1000000ULL)
#define BURST_EMERGENCY_NS  (2ULL * 1000000000ULL)
// Emergency engages after 2 consecutive breached windows (≈200ms reaction)
#define BURST_SUSTAINED_TRIGGER 2

// Default values
#define DEFAULT_SAMPLE_RATE  1
#define DEFAULT_SAMPLE_BYTES 256
#define MAX_SAMPLE_BYTES     512

// Protocol numbers (not always in vmlinux.h)
#define IPPROTO_ICMPV6       58
#define IPPROTO_GRE          47

// GRE protocol IDs for ERSPAN
#define GRE_PROTO_ERSPAN_II  0x88BE
#define GRE_PROTO_ERSPAN_III 0x22EB

// GRE header flags
#define GRE_FLAG_SEQ         0x1000  // Sequence number present
#define GRE_FLAG_CSUM        0x8000  // Checksum and reserved word present
#define GRE_FLAG_ROUTING     0x4000  // Routing is unsupported
#define GRE_FLAG_KEY         0x2000  // Key present
#define GRE_VERSION_MASK    0x0007  // Only GRE version zero is supported

// Ethernet types
#define ETH_P_ARP            0x0806
#define ETH_P_IP             0x0800
#define ETH_P_IPV6           0x86DD
#define ETH_P_8021Q          0x8100

// Packet size thresholds
#define PKT_SMALL_THRESHOLD  128
#define PKT_LARGE_THRESHOLD  512

// ---------------------------------------------------------------------------
// Decoder Index — append-only, never reorder.
// IMPORTANT: keep in sync with shared/decoder/decoder.go
// ---------------------------------------------------------------------------
#define DECODER_TCP       0
#define DECODER_TCP_SYN   1
#define DECODER_UDP       2
#define DECODER_ICMP      3
#define DECODER_FRAG      4
// v1.3 Phase 1b — TCP flag subdivisions
#define DECODER_TCP_ACK   5
#define DECODER_TCP_RST   6
#define DECODER_TCP_FIN   7
// v1.3 Phase 1b — Non-TCP/UDP/ICMP protocols
#define DECODER_GRE       8
#define DECODER_ESP       9
#define DECODER_IGMP      10
#define DECODER_IP_OTHER  11
// v1.3 Phase 1b (追加) — Packet-level anomalies (stateless detection)
#define DECODER_BAD_FRAGMENT 12  // Ping of Death / tiny fragment
#define DECODER_INVALID      13  // IP IHL<5, TCP doff<5, header length anomalies
// Slots 14-15 reserved for future decoders (explicit additions only).
#define MAX_DECODERS      16

// IP protocol numbers used by v1.3 Phase 1b dispatch (not all present in vmlinux.h)
#ifndef IPPROTO_ESP
#define IPPROTO_ESP       50
#endif
#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP      2
#endif
// IPPROTO_GRE already defined above (line 28)

// ---------------------------------------------------------------------------
// Data Structures — must match Go-side definitions exactly
// ---------------------------------------------------------------------------

// Per-destination-IP statistics
// Reference: brainstorm-node.md "per dst_ip aggregated stats structure"
struct dst_ip_stats {
    __u64 pkt_count;
    __u64 byte_count;

    // Protocol distribution (array indexed by DECODER_* constants)
    __u32 decoder_counts[MAX_DECODERS];
    // Per-decoder byte counts (for per-decoder BPS thresholds)
    __u64 decoder_byte_counts[MAX_DECODERS];

    // Packet size distribution
    __u32 small_pkt;       // <128B (small-packet flood indicator)
    __u32 medium_pkt;      // 128-512B
    __u32 large_pkt;       // >512B (bandwidth attack indicator)
};

// LPM trie key for watch_prefix matching (IPv4 + IPv6 unified)
// 16-byte address container for BPF *global* (noinline) function arguments.
// A raw __u8* argument is typed mem(sz=1) by the verifier, so any 16-byte read
// inside the callee fails with "invalid access to memory, mem_size=1"; a struct
// gives the callee mem(sz=16) and keeps the address copy legal.
struct addr16 {
    __u8 b[16];
};

struct lpm_key {
    __u32 prefixlen;
    __u8  addr[16];        // IPv4 uses first 4 bytes, IPv6 uses all 16
};

// Prefix stats key — matches watch_prefix entry
struct prefix_key {
    __u8  addr[16];
    __u32 prefixlen;
};

// Per-prefix aggregated statistics (for carpet bombing detection + chart decoder breakdown)
struct prefix_stats {
    __u64 pkt_count;
    __u64 byte_count;
    __u32 overflow_count;  // ip_stats map full → this prefix's IPs couldn't be tracked
    __u32 _pad;            // alignment padding (keeps struct size stable)
    __u32 decoder_counts[MAX_DECODERS];  // indexed by DECODER_* constants
    __u64 decoder_byte_counts[MAX_DECODERS];  // per-decoder byte counts for BPS thresholds
};

// Sample header — prefixed to each ring buffer record
// Enables userspace to distinguish valid data from zero-padded tail.
struct sample_hdr {
    __u32 cap_len;   // actual captured bytes (≤ MAX_SAMPLE_BYTES)
    __u32 pkt_len;   // original packet length on wire
};

// Global stats — single entry, every packet increments unconditionally
// v2.11: added matched_bytes + per-decoder breakdown for 0.0.0.0/0 global threshold detection
struct global_stats {
    __u64 total_pkts;
    __u64 total_bytes;
    __u64 matched_pkts;    // packets matching watch_prefix
    __u64 matched_bytes;   // bytes matching watch_prefix (authoritative source for global ip+bps)
    __u64 sample_drops;    // ring buffer reserve failures (backpressure signal)

    // Per-decoder breakdown (inbound, matched traffic only)
    __u32 decoder_counts[MAX_DECODERS];
    __u64 decoder_byte_counts[MAX_DECODERS];

    // v2.11 Phase 2: outbound global counters (src_ip matched traffic)
    __u64 src_matched_pkts;
    __u64 src_matched_bytes;
    __u32 src_decoder_counts[MAX_DECODERS];
    __u64 src_decoder_byte_counts[MAX_DECODERS];
};

// ---------------------------------------------------------------------------
// v4.0 Inline scrubbing data structures
// ---------------------------------------------------------------------------

// Inline filter hash key — exact 5-tuple with wildcard semantics.
// Wildcards: proto=0 matches any protocol; dst_port/src_port=0 match any port;
// src_addr all-zero with src_prefix_len=0 matches any source.
struct filter_rule_key {
    __u32 dst_prefix_len;   // host bits masked by userspace (32 or 128)
    __u32 src_prefix_len;
    __u8  dst_addr[16];     // IPv4 in first 4 bytes (v4-mapped not used here)
    __u8  src_addr[16];
    __u8  proto;
    __u8  _pad[3];
    __u16 dst_port;         // network byte order
    __u16 src_port;         // network byte order
};

// Inline filter rule value.
struct filter_rule {
    __u8  action;           // FILTER_ACTION_*
    __u8  encap;            // ENCAP_* for REDIRECT clean-pipe return
    __u16 _pad;
    __u32 egress_ifindex;   // TX/REDIRECT/CHALLENGE egress
    __u32 rate_limit_pps;   // RATE_LIMIT cap (best-effort burst cap)
    __u32 priority;         // lower wins when an exact key and a subnet rule overlap
    __u64 rule_id;          // controller-assigned id (reconciliation)
    __u64 expires_unix;     // 0 = until withdrawn; expired rules are ignored in-kernel
};

// Per-destination burst sliding window (100ms buckets, 2s emergency drop).
struct burst_window {
    __u32 count;              // packets in current 100ms window
    __u32 sustained;          // consecutive breached windows
    __u64 window_start_ns;
    __u64 emergency_until_ns; // 0 = not in emergency
};

// Urgent alert pushed to userspace ringbuf → CriticalEventStream (<500ms path)
struct burst_alert {
    __u64 timestamp_ns;
    __u8  dst_addr[16];
    __u32 is_v4;              // 1 = dst_addr[0..3] is IPv4
    __u32 window_pps;         // measured PPS in the breached window
    __u32 proto;              // triggering L4 protocol
    __u32 tcp_flags;          // triggering TCP flags (0 for non-TCP)
};

// DNS outstanding-query key: client that issued the query + DNS identifiers
struct dns_query_key {
    __u8  client_addr[16];    // IPv4 in first 4 bytes
    __u16 query_id;           // network byte order
    __u16 qtype;              // network byte order
    __u32 _pad;
};

// Inline engine counters (inline_stats array indices)
#define INLINE_STAT_COOKIE_REPLY     0
#define INLINE_STAT_COOKIE_VALIDATED 1
#define INLINE_STAT_COOKIE_DROPPED   2
#define INLINE_STAT_EMERGENCY_DROPS  3
#define INLINE_STAT_FILTER_DROPS     4
#define INLINE_STAT_DNS_DROPS        5
#define INLINE_STAT_REDIRECT_OK      6
#define INLINE_STAT_REDIRECT_ERR     7
#define INLINE_STAT_XSK_STEER        8
#define INLINE_STAT_FILTER_PASS      9
#define INLINE_STAT_MAX              16

// Cookie engine input block (48 bytes = 6 u64 siphash words)
struct cookie_input {
    __u8  sip[16];
    __u8  dip[16];
    __u32 sport;
    __u32 dport;
    __u64 secret_lo;
    __u64 secret_hi;
};

// ---------------------------------------------------------------------------
// BPF Maps — SEC(".maps") style for bpf2go compatibility
// Reference: brainstorm-node.md "BPF Maps inventory"
// ---------------------------------------------------------------------------

// Global packet counter — health check (Array, 1 entry)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats);
} global_stats SEC(".maps");

// Watch prefix trie A — active side (LPM Trie, 50K)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 50000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32);  // prefix index
} watch_trie_a SEC(".maps");

// Watch prefix trie B — shadow side (LPM Trie, 50K)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 50000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u32);
} watch_trie_b SEC(".maps");

// Per-prefix aggregated stats (Hash, 50K)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, struct prefix_key);
    __type(value, struct prefix_stats);
} prefix_stats_map SEC(".maps");

// Per-destination-IP stats A — active side (Hash, configurable max_entries)
// Note: max_entries set via bpf2go or runtime rewrite; 1M default, prealloc
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct lpm_key);  // full IP as /32 or /128
    __type(value, struct dst_ip_stats);
} ip_stats_a SEC(".maps");

// Per-destination-IP stats B — shadow side (Hash, same as A)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct lpm_key);
    __type(value, struct dst_ip_stats);
} ip_stats_b SEC(".maps");

// Per-CPU scratch used to materialize a fresh per-IP stats entry. The 224-byte
// struct dst_ip_stats cannot live on the verifier's shared 512-byte call stack,
// so the zeroed entry is built in per-CPU map memory and inserted atomically.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dst_ip_stats);
} ip_stats_scratch SEC(".maps");

// v2.11 Phase 2: Per-source-IP stats (outbound tracking, reuses dst_ip_stats struct)
// max_entries intentionally smaller — outbound cardinality typically lower than inbound
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000);
    __type(key, struct lpm_key);
    __type(value, struct dst_ip_stats);
} src_stats_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000);
    __type(key, struct lpm_key);
    __type(value, struct dst_ip_stats);
} src_stats_b SEC(".maps");

// v2.11 Phase 2: Per-prefix outbound aggregated stats
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 50000);
    __type(key, struct prefix_key);
    __type(value, struct prefix_stats);
} src_prefix_stats_map SEC(".maps");

// Double-buffer slot selector (Array, 1 entry: 0=A active, 1=B active)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} active_slot SEC(".maps");

// Runtime config (Array, 16 entries)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CFG_MAX);
    __type(key, __u32);
    __type(value, __u64);
} xsight_config SEC(".maps");

// ---------------------------------------------------------------------------
// v4.0 Inline scrubbing maps
// ---------------------------------------------------------------------------

// Dynamic packet filter table — exact 5-tuple rules with wildcards.
// Controller pushes via ControlStream; hash of (DIP, SIP, Proto, DPort, SPort).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct filter_rule_key);
    __type(value, struct filter_rule);
} active_filter_rules SEC(".maps");

// Subnet-scope filter rules (LPM trie). Source-subnet ACLs and broad
// destination protections; exact hash rules win on equal priority.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, struct filter_rule);
} active_filter_subnets SEC(".maps");

// SYN-cookie validated clients — short-lived LRU. On a successful cookie ACK
// the client IP is admitted here and bypasses the emergency drop state.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, __u8[16]);
    __type(value, __u64);   // expiry (ktime ns)
} validated_clients SEC(".maps");

// Per-destination 100ms sliding windows for sub-second burst detection.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u8[16]);
    __type(value, struct burst_window);
} burst_windows SEC(".maps");

// Urgent alerts → userspace → CriticalEventStream. NOTE: ringbuf is not
// supported by SmartNIC offload; deployments in offload mode must keep
// CFG_ALERTS_ENABLE=0 and accept userspace-only detection there.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} alerts SEC(".maps");

// Outbound DNS queries (src_ip, query_id, qtype) for reflection defense.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct dns_query_key);
    __type(value, __u64);   // expiry (ktime ns)
} dns_outstanding SEC(".maps");

// Inline engine counters (userspace reads for posture + console)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, INLINE_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} inline_stats SEC(".maps");

// AF_XDP steer map — packets flagged for L7 challenge/inspection are
// redirected into the userspace zero-copy socket bound to a NIC queue.
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsight_xsk SEC(".maps");

// Sampling ring buffer — raw packet headers to userspace (16MB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} samples SEC(".maps");

#endif // __XSIGHT_H__
