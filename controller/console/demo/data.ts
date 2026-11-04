// A page-load snapshot, independent of the development fixtures and application state.
export type Row = Record<string, any>
export const session = { token: 'demo-session', user: { id: 1, username: 'demo', role: 'viewer' } }
export const day = 86400000
export function random(seed = 9527) {
  let state = seed >>> 0
  return () => { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state / 4294967296 }
}
export function createData(now = Date.now()) {
  const iso = (offset = 0) => new Date(now + offset).toISOString()
  const created_at = iso(-28 * day), updated_at = iso(-day)
  const nodes: Row[] = [
    ['probe-a', 'Site A', 'xdp', 3], ['probe-b', 'Site B', 'xdp', 12], ['flow-c', 'Flow collector', 'flow', 5],
  ].map(([id, description, mode, age]) => ({ id, description, mode, enabled: true, online: true,
    delivery_version_current: 24, delivery_version_applied: 24, config_status: 'synced',
    last_ack_at: iso(-3000), last_stats_at: iso(-Number(age) * 1000), created_at, updated_at }))
  const prefixes: Row[] = [
    [1, '203.0.113.0/24', 'Web', null, 1], [2, '203.0.113.0/26', 'Web A', 1, 1],
    [3, '198.51.100.0/24', 'DNS', null, 2], [4, '2001:db8:100::/48', 'IPv6 services', null, 3],
  ].map(([id, prefix, name, parent_id, threshold_template_id]) => ({ id, prefix, name, parent_id,
    threshold_template_id, ip_group: '', enabled: true, created_at }))
  const templates: Row[] = ['Web thresholds', 'DNS thresholds', 'IPv6 thresholds'].map((name, i) => ({
    id: i + 1, name, description: 'Inbound service traffic', response_id: i === 1 ? 2 : 1,
    rule_count: 2, prefix_count: i ? 1 : 2, created_at, updated_at,
  }))
  const rules: Row[] = templates.flatMap(t => ['udp', 'tcp_syn'].map((decoder, j) => ({
    id: t.id * 10 + j, template_id: t.id, prefix_id: null, domain: 'internal_ip', direction: 'receives',
    decoder: t.id === 3 && j === 0 ? 'icmp' : decoder,
    unit: 'pps', comparison: 'over', value: j ? 600000 : 1200000,
    inheritable: true, response_id: t.response_id, enabled: true, created_at,
  })))
  rules.push({ ...rules[0], id: 40, template_id: null, prefix_id: 2, value: 950000 })
  const common = { id: 1, enabled: true, created_at, updated_at, timeout_ms: 10000 }
  const connectors: Record<string, Row[]> = {
    xdrop: [{ ...common, name: 'Edge filter', api_url: 'https://filter.example.com', api_key: '***' }],
    bgp: [{ ...common, name: 'Transit routing', bgp_asn: 64512, vtysh_path: '/usr/bin/vtysh',
      address_family: 'ipv4', description: 'Service routing', vendor: 'frr', flowspec_enabled: false }],
    webhook: [{ ...common, name: 'Event hook', url: 'https://hooks.example.com/events', method: 'POST',
      headers: { Authorization: '******' }, global: false }],
    shell: [{ ...common, name: 'Event logger', command: '/usr/bin/logger', default_args: 'xsight-event',
      pass_stdin: true }],
  }
  const responses: Row[] = ['Edge mitigation', 'Transit mitigation', 'Notifications'].map((name, i) => ({
    id: i + 1, name, description: 'Service traffic response', enabled: true, created_at,
    action_count: i === 2 ? 1 : 5, bound_template_count: i === 0 ? 2 : i === 1 ? 1 : 0,
  }))
  const action = (id: number, response_id: number, kind: string, exit = false): Row => ({
    id, response_id, action_type: kind, execution_policy: exit ? 'once_on_exit' : 'once_on_enter',
    priority: 5, config: {}, preconditions: [], enabled: true, trigger_phase: exit ? 'on_expired' : 'on_detected',
    run_mode: 'once', period_seconds: 0, execution: 'automatic',
    webhook_connector_id: kind === 'webhook' ? 1 : null, shell_connector_id: null,
    bgp_connector_id: kind === 'bgp' ? 1 : null, connector_id: kind === 'xdrop' ? null : 1,
    connector_name: connectors[kind]![0]!.name, target_node_ids: kind === 'xdrop' ? [1] : null,
    xdrop_action: kind === 'xdrop' ? exit ? 'unblock' : 'filter_l4' : '',
    xdrop_custom_payload: kind === 'xdrop' ? { dst_ip: '{dst_ip}', action: 'drop' } : null,
    xdrop_fields: kind === 'xdrop' ? ['dst_ip'] : null, xdrop_rate_limit: null,
    shell_extra_args: '', unblock_delay_minutes: 5, bgp_route_map: kind === 'bgp' ? 'SERVICE' : '',
    bgp_withdraw_delay_minutes: 5, ...(kind !== 'webhook' ? exit ? { auto_generated: true } : { paired_with: id + 1 } : {}),
  })
  const actions = [action(1, 1, 'xdrop'), action(2, 1, 'xdrop', true), action(3, 1, 'webhook'),
    action(4, 2, 'bgp'), action(5, 2, 'bgp', true), action(6, 2, 'webhook'), action(7, 3, 'webhook'),
    action(8, 1, 'bgp'), action(9, 1, 'bgp', true), action(10, 2, 'xdrop'), action(11, 2, 'xdrop', true)]
  const conditions = [{ id: 1, action_id: 1, attribute: 'decoder', operator: 'eq', value: 'udp', created_at }]
  actions[0]!.preconditions = conditions
  const rng = random()
  const attacks: Row[] = Array.from({ length: 32 }, (_, i) => {
    const active = i < 2, variant = i % 3, dns = variant === 1
    const age = active ? (i ? 8 : 22) * 60000 : (i - 1) * day / 4.5 + rng() * 3600000
    const duration = (4 + rng() * 38) * 60000
    const started_at = iso(-age), ended_at = active ? null : iso(-age + Math.min(duration, age - 60000))
    const peak_pps = Math.round((active ? i ? 3.2 : 4.8 : 0.7 + rng() * 5.5) * 1e6)
    return { id: i + 1, dst_ip: dns ? '198.51.100.53/32' : variant === 2 ? '2001:db8:100::10/128' : '203.0.113.10/32',
      prefix_id: dns ? 3 : variant === 2 ? 4 : 2, direction: 'receives',
      decoder_family: dns ? 'tcp_syn' : variant === 2 ? 'icmp' : 'udp',
      attack_type: dns ? 'syn_flood' : variant === 2 ? 'icmp_flood' : 'udp_flood',
      severity: peak_pps > 3e6 ? 'high' : 'medium', confidence: 0.96, peak_pps,
      peak_bps: peak_pps * (dns ? 640 : 4800), reason_codes: ['threshold_exceeded'],
      node_sources: dns ? ['probe-b', 'flow-c'] : ['probe-a', 'flow-c'], response_id: dns ? 2 : 1,
      threshold_rule_id: dns ? 21 : variant === 2 ? 30 : 10,
      template_name: templates[dns ? 1 : variant === 2 ? 2 : 0]!.name,
      rule_summary: dns ? 'tcp_syn > 600000 pps' : variant === 2 ? 'icmp > 1200000 pps' : 'udp > 1200000 pps',
      started_at, ended_at, created_at: started_at }
  })
  const xdrop: Row[] = [{ id: 1, attack_id: 1, action_id: 1, action_type: 'xdrop', connector_id: 1,
    connector_name: connectors.xdrop![0]!.name, attack_dst_ip: attacks[0]!.dst_ip, dst_ip: attacks[0]!.dst_ip,
    external_rule_id: 'rule-1', status: 'active', protocol: 'udp', src_port: 53, dst_port: 443,
    action: 'drop', delay_minutes: 5, created_at: iso(-21 * 60000) }]
  const bgp: Row[] = [{ attack_id: 2, action_id: 4, action_type: 'bgp', connector_id: 1,
    connector_name: connectors.bgp![0]!.name, attack_dst_ip: attacks[1]!.dst_ip,
    external_rule_id: '198.51.100.53/32|SERVICE', prefix: '198.51.100.53/32', route_map: 'SERVICE',
    status: 'delayed', scheduled_for: iso(3 * 60000), created_at: iso(-7 * 60000), announcement_id: 1,
    attached_attacks: [{ attack_id: 2, dst_ip: attacks[1]!.dst_ip, decoder: 'tcp_syn',
      response_name: responses[1]!.name, delay_minutes: 5, attached_at: iso(-7 * 60000) }] }]
  xdrop.push({ ...xdrop[0], id: 2, attack_id: 2, action_id: 10, attack_dst_ip: attacks[1]!.dst_ip,
    dst_ip: attacks[1]!.dst_ip, external_rule_id: 'rule-2', protocol: 'tcp', tcp_flags: 'SYN,!ACK',
    src_port: 0, dst_port: 53, action: 'rate_limit', rate_limit: 600000, created_at: iso(-7 * 60000) })
  bgp.push({ ...bgp[0], attack_id: 1, action_id: 8, attack_dst_ip: attacks[0]!.dst_ip,
    external_rule_id: '203.0.113.10/32|SERVICE', prefix: '203.0.113.10/32', status: 'active',
    scheduled_for: undefined, created_at: iso(-20 * 60000), announcement_id: 2,
    attached_attacks: [{ attack_id: 1, dst_ip: attacks[0]!.dst_ip, decoder: 'udp',
      response_name: responses[0]!.name, delay_minutes: 5, attached_at: iso(-20 * 60000) }] })
  const executions: Row[] = [...xdrop, ...bgp].map((r, i) => ({ id: i + 1, attack_id: r.attack_id,
    action_id: r.action_id, action_type: r.action_type, connector_id: r.connector_id,
    connector_name: r.connector_name, response_name: responses[r.attack_id - 1]!.name, trigger_phase: 'on_detected',
    status: r.status === 'delayed' ? 'scheduled' : 'success', status_code: r.status === 'delayed' ? null : 200,
    duration_ms: r.status === 'delayed' ? 0 : 24, error_message: '', request_body: '{}', response_body: '{"ok":true}',
    external_rule_id: r.external_rule_id, executed_at: r.created_at,
    ...(r.action_type === 'bgp' ? { scheduled_for: r.scheduled_for, bgp_role: 'triggered',
      announcement_refcount: 1 } : {}) }))
  const listeners: Row[] = [{ id: 1, node_id: 'flow-c', listen_address: '0.0.0.0:6343',
    protocol_mode: 'sflow', enabled: true, description: 'Service flow input', created_at }]
  const sources: Row[] = [{ id: 1, listener_id: 1, name: 'Router A', device_ip: '203.0.113.254',
    sample_mode: 'auto', sample_rate: 1000, description: 'Service uplink', enabled: true, created_at }]
  const users: Row[] = ['demo', 'ops-admin'].map((username, i) => ({ id: i + 1, username,
    role: i ? 'admin' : 'viewer', enabled: true, created_at, updated_at }))
  const audit: Row[] = [{ id: 1, user_id: 2, entity_type: 'webhook_connector', entity_id: 1, action: 'update',
    diff: { before: { headers: { Authorization: '******' } }, after: { headers: { Authorization: '******' } } },
    delivery_version: 24, created_at: iso(-day) },
  { id: 2, user_id: 2, entity_type: 'watch_prefix', entity_id: 2, action: 'update',
    diff: { before: { name: 'Web' }, after: { name: 'Web A' } }, delivery_version: 23, created_at: iso(-2 * day) }]
  return { now, nodes, prefixes, templates, rules, connectors, responses, actions, conditions, attacks,
    xdrop, bgp, executions, listeners, sources, users, audit }
}
export type Dataset = ReturnType<typeof createData>

// The same absolute sample time always produces the same daily cycle and seeded noise.
export function traffic(time: number, factor = 1) {
  const phase = (time % day) / day * Math.PI * 2
  // Hash the sample slot first; consecutive raw seeds would make the generator's first output a slow ramp.
  let slot = (Math.floor(time / 5000) ^ 9527) >>> 0
  slot = Math.imul(slot ^ (slot >>> 16), 0x45d9f3b) >>> 0
  slot = Math.imul(slot ^ (slot >>> 16), 0x45d9f3b) >>> 0
  const noise = random((slot ^ (slot >>> 16)) >>> 0)()
  const pps = Math.round((1.65e6 + 0.65e6 * Math.sin(phase - 1.2) + (noise - .5) * 120000) * factor)
  const bps = pps * 5600
  const row: Row = { time: new Date(time).toISOString(), pps, bps }
  for (const [decoder, share] of Object.entries({ tcp: .62, udp: .33, icmp: .02, tcp_syn: .035, frag: .003 })) {
    row[decoder + '_pps'] = Math.round(pps * share); row[decoder + '_bps'] = Math.round(bps * share)
  }
  const extras = { tcp_ack: .48, tcp_rst: .008, tcp_fin: .006, gre: .012, esp: .01, igmp: .002,
    ip_other: .006, bad_fragment: .0001, invalid: .0001 }
  row.extra_decoder_pps = Object.fromEntries(Object.entries(extras).map(([k, v]) => [k, Math.round(pps * v)]))
  row.extra_decoder_bps = Object.fromEntries(Object.entries(extras).map(([k, v]) => [k, Math.round(bps * v)]))
  return row
}
