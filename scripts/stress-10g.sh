#!/usr/bin/env bash
# stress-10g.sh — 10Gbps / 64-byte PPS validation harness for xSight nodes.
#
# It never sends traffic unless RUN=1 is set, so it is safe to run on a
# production controller: by default it only prints the exact commands and the
# theoretical numbers for the requested link speed.
#
# Usage:
#   IFACE=eth1 GBPS=10 ./scripts/stress-10g.sh            # dry run (default)
#   IFACE=eth1 GBPS=10 RUN=1 DURATION=600 ./scripts/stress-10g.sh
#
# Environment:
#   IFACE      target NIC on the traffic generator (required for RUN=1)
#   GBPS       link rate to model (default 10)
#   DURATION   seconds (default 600)
#   SRC        spoofed source pool, e.g. 203.0.113.0/24
#   DST        victim, e.g. 198.51.100.7
#   PORT       destination port (default 443)
#   RUN        1 = actually generate traffic
#   METHOD     trex | pktgen | tcpreplay (default trex)
set -euo pipefail

GBPS="${GBPS:-10}"
DURATION="${DURATION:-600}"
SRC="${SRC:-203.0.113.0/24}"
DST="${DST:-198.51.100.7}"
PORT="${PORT:-443}"
RUN="${RUN:-0}"
METHOD="${METHOD:-trex}"

# 64-byte Ethernet frame on the wire = 64 payload + 20 preamble/IFG + 4 FCS = 84 bytes.
# 1 Gbps / (84 * 8) = 1,488,095 pps for a saturated 64-byte stream.
pps=$(( GBPS * 1000000000 / (84 * 8) ))
mbps_pps=$(awk -v p="$pps" 'BEGIN { printf "%.2f", p/1000000 }')

cat <<EOF
xSight 10Gbps / 64-byte baseline
  link rate        : ${GBPS} Gbps
  frame on wire    : 84 bytes (64 + 20 preamble/IFG + 4 FCS)
  theoretical PPS  : ${pps} (${mbps_pps} Mpps)
  duration         : ${DURATION}s
  victim           : ${DST}:${PORT}
  source pool      : ${SRC}
  method           : ${METHOD}

Detection expectations (Controller defaults):
  - threshold detector ticks once per second
  - hard confirm window: 3s  |  dynamic confirm: 5s
  - with action_engine.fast_path_multiplier=5 an attack >=5x threshold
    must reach state=active within ONE tick (~1s)

Inline scrubbing (mode: xdp_inline) acceptance:
  - per-destination burst counters tick every 100ms
  - burst_emergency alert on the ringbuf within <500ms of the burst
  - Controller confirms the attack (tracker fast path) in <200ms after the alert
  - broad (rate_limit) rule visible in active_filter_rules in <500ms
  - narrow (drop on dominant port + residual cap) after inline_narrow_delay_ms (default 750ms)
  - SYN flood: syn_cookie replies rise, validated_clients populates, benign
    handshakes still complete; cookie-accepting clients bypass emergency drops
  - clean-pipe: redirect/GRE (or XDP_TX on cleanpipe_egress) counters rise and
    the scrubbed stream keeps byte/packet integrity (no reordering at the sink)

Pass criteria:
  - XDP: xdp_redirect/drop counters rise, no xdp_exception, node CPU < 80%
  - node -> controller sample stream stays within 10% of injected PPS
  - attack state reaches active; xDrop rule appears (mode=auto)
  - time from first breaching second to xDrop rule < 2s (fast path)
  - AF_XDP (when enabled): af_xdp_active=1, no UMEM drops at the target PPS

SYN-flood variant:
  - TRex: set L3 src = random over ${SRC} and L4 = TCP SYN with a random
    source port (flags=0x02); or pktgen with a spoofed 203.0.113.0/24 pool.
  - Expect the SYN-cookie path (no half-open state) instead of per-source drops.

EOF

case "$METHOD" in
  trex)
    cat <<EOF
# --- TRex stateless, 64-byte UDP flood -------------------------------
# trex_cfg.yaml:  port 0 -> ${IFACE:-<iface>}, /24 source pool
sudo ./t-rex-64 -f /etc/trex_cfg.yaml -c -d ${DURATION} --limit \\
  -m ${mbps_pps}mpps -p 0 --streams 1
# Stream profile (stl/udp_64b.py):
#   base_pkt / Ethernet()/IP(src=rand ${SRC},dst=${DST})/UDP(dport=${PORT})/Raw(b'\\x00'*18)
#   vm = STLScVmRaw([STLVmFlowVar(name='src', min_value=..., max_value=..., size=4, op='random')])
EOF
    ;;
  pktgen)
    cat <<EOF
# --- kernel pktgen ---------------------------------------------------
for cpu in \$(seq 0 \$(( \$(nproc) - 1 ))); do
  echo "rem_device_all" > /proc/net/pktgen/kpktgend_\${cpu} 2>/dev/null || true
  echo "add_device ${IFACE:-<iface>}@\${cpu}" > /proc/net/pktgen/kpktgend_\${cpu}
  echo "count 0"        > /proc/net/pktgen/${IFACE:-<iface>}@\${cpu}
  echo "clone_skb 100000" > /proc/net/pktgen/${IFACE:-<iface>}@\${cpu}
  echo "pkt_size 64"    > /proc/net/pktgen/${IFACE:-<iface>}@\${cpu}
  echo "delay 0"        > /proc/net/pktgen/${IFACE:-<iface>}@\${cpu}
  echo "dst ${DST}"     > /proc/net/pktgen/${IFACE:-<iface>}@\${cpu}
  echo "dst_mac \$(cat /sys/class/net/${IFACE:-eth0}/address)" > /proc/net/pktgen/${IFACE:-<iface>}@\${cpu}
done
echo "start" > /proc/net/pktgen/pgctrl
sleep ${DURATION}; echo "stop" > /proc/net/pktgen/pgctrl
EOF
    ;;
  tcpreplay)
    cat <<EOF
# --- tcpreplay replay of a captured 64-byte pcap --------------------
sudo tcpreplay -i ${IFACE:-<iface>} --pps ${pps} --loop 0 \\
  --duration ${DURATION} /tmp/flood-64b.pcap
EOF
    ;;
  *)
    echo "unknown METHOD=$METHOD (use trex|pktgen|tcpreplay)" >&2
    exit 2
    ;;
esac

cat <<EOF

# --- observe while the flood runs -----------------------------------
watch -n1 'bpftool prog show | grep -i xdp'
watch -n1 'ethtool -S ${IFACE:-<iface>} | grep -E "xdp|drop|pps"'
mpstat -P ALL 1 10
# node counters (if metrics are enabled)
curl -s localhost:9090/metrics | grep -E "xsight_(samples|packets|drops)_total"

# --- run gate -------------------------------------------------------
if [ "${RUN}" != "1" ]; then
  echo "DRY RUN: set RUN=1 (and IFACE=<nic>) to execute."
fi
EOF

if [ "${RUN}" = "1" ]; then
  if [ -z "${IFACE:-}" ]; then
    echo "RUN=1 requires IFACE=<nic>" >&2
    exit 2
  fi
  echo "RUN=1 accepted; execute the ${METHOD} block above on the generator host."
fi
