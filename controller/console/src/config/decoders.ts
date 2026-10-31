export interface Decoder {
  key: string
  group: string
  ppsField: string
  bpsField: string
  extraKey: string
}

// Deliberately literal: the Go guard consumes every entry and field, failing closed on unfamiliar syntax.
export const DECODERS: Decoder[] = [
  { key: 'total', group: 'summary', ppsField: 'pps', bpsField: 'bps', extraKey: '' },
  { key: 'tcp', group: 'l4', ppsField: 'tcp_pps', bpsField: 'tcp_bps', extraKey: '' },
  { key: 'udp', group: 'l4', ppsField: 'udp_pps', bpsField: 'udp_bps', extraKey: '' },
  { key: 'icmp', group: 'l4', ppsField: 'icmp_pps', bpsField: 'icmp_bps', extraKey: '' },
  { key: 'tcp_syn', group: 'flags', ppsField: 'tcp_syn_pps', bpsField: 'tcp_syn_bps', extraKey: '' },
  { key: 'tcp_ack', group: 'flags', ppsField: 'extra_decoder_pps', bpsField: 'extra_decoder_bps', extraKey: 'tcp_ack' },
  { key: 'tcp_rst', group: 'flags', ppsField: 'extra_decoder_pps', bpsField: 'extra_decoder_bps', extraKey: 'tcp_rst' },
  { key: 'tcp_fin', group: 'flags', ppsField: 'extra_decoder_pps', bpsField: 'extra_decoder_bps', extraKey: 'tcp_fin' },
  { key: 'gre', group: 'ip', ppsField: 'extra_decoder_pps', bpsField: 'extra_decoder_bps', extraKey: 'gre' },
  { key: 'esp', group: 'ip', ppsField: 'extra_decoder_pps', bpsField: 'extra_decoder_bps', extraKey: 'esp' },
  { key: 'igmp', group: 'ip', ppsField: 'extra_decoder_pps', bpsField: 'extra_decoder_bps', extraKey: 'igmp' },
  { key: 'ip_other', group: 'ip', ppsField: 'extra_decoder_pps', bpsField: 'extra_decoder_bps', extraKey: 'ip_other' },
  { key: 'fragment', group: 'anomaly', ppsField: 'frag_pps', bpsField: 'frag_bps', extraKey: '' },
  { key: 'bad_fragment', group: 'anomaly',
    ppsField: 'extra_decoder_pps',
    bpsField: 'extra_decoder_bps', extraKey: 'bad_fragment' },
  { key: 'invalid', group: 'anomaly',
    ppsField: 'extra_decoder_pps',
    bpsField: 'extra_decoder_bps', extraKey: 'invalid' },
]
