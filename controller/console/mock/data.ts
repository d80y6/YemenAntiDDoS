// @ts-expect-error Native Node contract runner requires the explicit .ts extension.
import { usersSession } from './users.ts'
// @ts-expect-error Native Node contract runner requires the explicit .ts extension.
import { validTarget } from '../src/views/attacks/data.ts'
// @ts-expect-error Native Node contract runner requires the explicit .ts extension.
import { DECODERS } from '../src/config/decoders.ts'
// @ts-expect-error Native Node contract runner requires the explicit .ts extension.
import { cidrText, isIPv4MappedPrefix, ipv6DefaultPrefix } from './cidr.ts'
// @ts-expect-error Native Node contract runner requires the explicit .ts extension.
import { inetText } from './inet.ts'
// Development fixtures follow the local Go handlers; no production code imports this module.
const extras = ['tcp_ack', 'tcp_rst', 'tcp_fin', 'gre', 'esp', 'igmp', 'ip_other', 'bad_fragment', 'invalid']
type MockResult = { status: number; body: any; delay?: number }
export function mockReply(raw: string, mode = 'normal', now = Date.now(),
  overrides = new Map<number, string>()): MockResult {
  const url = new URL(raw, 'http://localhost'), path = url.pathname, q = url.searchParams
  const iso = (offset = 0) => new Date(now + offset).toISOString()
  const empty = mode === 'null'
  const send = (body: unknown, status = 200) => ({ status, body })
  if (path.startsWith('/api/flow-') || mode.startsWith('qh')) {
    const flow = flowSession(mode, now)(raw)
    if (flow) return flow
  }
  const userResult = usersSession(mode, now)(raw)
  if (userResult) return userResult
  const state = fixtureState(now)
  const response = responseSession(mode, now, state)(raw)
  if (response) return response
  const detection = detectionSession(mode, now, state)(raw)
  if (detection) return detection
  const qd = qdReply(raw, mode, now)
  if (qd) return qd
  if (mode === 'error' && path === '/api/stats/total-timeseries') return send({ error: 'timeseries unavailable' }, 503)
  const attack = (id: number, expired = false) => ({ id, dst_ip: id === 1 ? '0.0.0.0/0' : '10.1.2.0/24',
    prefix_id: 1, direction: 'receives', decoder_family: 'udp', attack_type: 'udp_flood', severity: 'high',
    confidence: .95, peak_pps: 1000 + id, peak_bps: id === 2 ? 0 : 80000, reason_codes: ['threshold'],
    node_sources: ['edge-a'], response_id: null, threshold_rule_id: null, started_at: iso(-600000 - id * 5000),
    ended_at: expired ? iso(-100000 - id * 1000) : null, created_at: iso(-600000 - id * 5000) })
  const count = mode === 'bulk' ? 51 : mode === '101' ? 101 : 3
  let allActive = Array.from({ length: count }, (_, i) => ({ ...attack(i + 1),
    ...(mode === '101' ? { started_at: iso(i === 100 ? -840000 : -100000) } : {}),
  }))
  const totalHistory = mode === 'bulk' ? 201 : mode === 'capped' ? 2001 : 4
  let ended = Array.from({ length: totalHistory }, (_, i) => ({ ...attack(1000 + i, true),
    started_at: iso(-500000 - i * (mode === 'capped' ? 100 : 1000)),
    ended_at: iso(-100000 - i * (mode === 'capped' ? 100 : 1000)),
  }))
  // The last row owns an earlier interval, so dropping page two loses a visible band.
  if (ended.length) Object.assign(ended[ended.length - 1]!, { started_at: iso(-890000), ended_at: iso(-880000) })
  if (mode.startsWith('attacks') || mode.startsWith('force-') || mode.startsWith('sample-')) {
    allActive = Array.from({ length: 7 }, (_, i) => ({ ...attack(i + 1), ...attackShape(i + 1, now) })) as any
    ended = Array.from({ length: 45 }, (_, i) => ({ ...attack(1000 + i, true),
      ...attackShape(1000 + i, now), started_at: iso(-7200000 - i * 1000), ended_at: iso(-3600000 - i * 1000) })) as any
    Object.assign(ended[44]!, { started_at: iso(-32 * 86400000), ended_at: iso(-31 * 86400000) })
  }
  if (mode === 'attacks-capped') allActive = Array.from({ length: 1001 }, (_, i) => attack(i + 1))
  const moved = allActive.filter(a => overrides.has(a.id))
    .map(a => ({ ...a, ended_at: overrides.get(a.id)! }))
  allActive = allActive.filter(a => !overrides.has(a.id)); ended = [...moved, ...ended]
  const active = allActive.slice(0, Math.max(0, Number(q.get('limit') || 100)))
  const detailId = /^\/api\/attacks\/(\d+)(?:\/|$)/.exec(path)?.[1]
  const detailAttack = [...allActive, ...ended].find(a => a.id === Number(detailId))
  if (detailId && !detailAttack) return send({ error: 'attack not found' }, 404)
  if (detailId && path.endsWith('/mitigation-summary')) return send(mitigation(detailAttack!, now))
  if (detailId && path.endsWith('/sensor-logs')) {
    if (mode === 'sample-error' || mode === 'attacks' && detailAttack!.id === 6) {
      return send({ error: 'flow query failed' }, 503)
    }
    if (detailAttack!.dst_ip === '0.0.0.0/0') return send({ flows: [], total: 0, expired: false })
    const isExpired = mode === 'sample-expired' || mode === 'attacks' && detailAttack!.id === 1044
    const flows = isExpired || mode === 'sample-empty' || empty
      || mode === 'attacks' && detailAttack!.id === 5 ? null
        : flowRows(detailAttack!.ended_at ? Date.parse(detailAttack!.ended_at) : now)
    return send({ flows, total: flows?.length ?? 0, expired: isExpired,
      window: !detailAttack!.ended_at && now - Date.parse(detailAttack!.started_at) > 3600000 ? 'last_1h' : 'full' })
  }
  if (detailId) return send({ attack: detailAttack, actions_log: [],
    ...(!detailAttack!.ended_at && detailAttack!.id !== 5 ? { timer: timerFor(detailAttack!.id),
      current: { pps: detailAttack!.id === 2 ? 0 : 123, bps: detailAttack!.id === 2 ? 0 : 984 } } : {}) })
  const nodes = [{ id: 'edge-a', description: 'Edge A', mode: 'xdp', enabled: true,
    delivery_version_current: 12, delivery_version_applied: 12, config_status: 'synced', last_ack_at: iso(-5000),
    created_at: iso(-86400000), updated_at: iso(-5000), online: true, last_stats_at: iso(-5000) },
  { id: 'flow-b', description: 'Flow B', mode: 'flow', enabled: true,
    delivery_version_current: 12, delivery_version_applied: 10, config_status: 'pending', last_ack_at: null,
    created_at: iso(-86400000), updated_at: iso(-60000), online: false },
  { ...{ id: 'edge-c', description: 'Edge C', mode: 'xdp', enabled: true },
    delivery_version_current: 12, delivery_version_applied: 12, config_status: 'failed', last_ack_at: iso(-4000),
    created_at: iso(-86400000), updated_at: iso(-4000), online: true, last_stats_at: iso(-4000) }]
  const prefix = (prefix: string, pps: number, bps: number, tcp: number) => ({ prefix, pps, bps,
    tcp_pps: tcp, udp_pps: Math.max(0, pps - tcp), icmp_pps: 0, tcp_bps: tcp * 80, udp_bps: bps - tcp * 80,
    icmp_bps: 0, nodes: [{ id: 'edge-a', mode: 'xdp' }, { id: 'flow-b', mode: 'flow' }] })
  const inbound = [prefix('10.1.0.0/16', 999, 80, 9), prefix('10.2.0.0/16', 1, 999, 1)]
  const outbound = [prefix('10.1.0.0/16', 0, 0, 0), prefix('10.3.0.0/16', 999, 8000, 4)].map(p => ({ ...p,
    nodes: [{ id: 'flow-b', mode: 'flow' }, { id: 'edge-c', mode: 'xdp' }],
  }))
  if (path === '/api/stats/summary') return send({ active_attacks: empty ? 0 : allActive.length,
    total_nodes: empty ? 0 : 3,
    online_nodes: empty ? 0 : 2, total_prefixes: empty ? 0 : 3, total_thresholds: 8, tracker_count: empty ? 0 : count,
    attacks_created: 12, attacks_suppressed: 1, attacks_evicted: 0, action_mode: 'auto' })
  if (path === '/api/nodes') return send(empty ? null : nodes)
  if (path === '/api/nodes/posture') return send(empty ? {} : {
    'edge-a': { xdp_mode: 'inline', inline_enabled: true, filter_rules: 3, validated_clients: 2,
      syn_cookies_replied: 10, syn_cookies_validated: 8, syn_cookies_dropped: 1,
      emergency_drops: 4, burst_alerts: 7, af_xdp_active: true, af_xdp_rx: 1234,
      af_xdp_umem_drops: 0, cpu_pins: [2, 3], cpu_util: [12.4, 3.6],
      redirect_ok: 99, redirect_err: 2, cleanpipe_egress: 'eth1', updated_at: iso(-1000) },
  })
  if (path === '/api/prefixes') return send(empty ? null : ['10.1.0.0/16', '10.2.0.0/16', '10.3.0.0/16'].map(
    (prefix, i) => ({ id: i + 1, prefix, parent_id: null, threshold_template_id: null, name: ['Transit', 'Services',
      'Outbound'][i], ip_group: '', enabled: true, created_at: iso(-86400000) }),
  ))
  if (path === '/api/attacks/active') return send({ attacks: empty ? null : active,
    active_count: empty ? 0 : allActive.length, returned: empty ? 0 : active.length, tracker_count: empty ? 0 : count,
    timers: Object.fromEntries(active.filter(a => a.id !== 5).map(a => [a.id, timerFor(a.id)])),
    ...(empty ? {} : { current: { '1': { pps: 123, bps: 984 }, '2': { pps: 0, bps: 0 } } }) })
  if (path === '/api/attacks') {
    if (mode === 'page-error' && Number(q.get('offset')) >= 200) return send({ error: 'page two failed' }, 500)
    const list = q.get('status') === 'expired' ? ended
      : q.get('status') === 'active' ? allActive : [...ended, ...allActive]
    if (q.get('direction') && !['receives', 'sends'].includes(q.get('direction')!)) {
      return send({ error: "direction must be 'receives' or 'sends'" }, 400)
    }
    if (q.has('ended_after') && !rfc3339(q.get('ended_after')!)) return send({ error: 'invalid ended_after' }, 400)
    if (q.has('dst_ip') && (q.get('dst_ip') !== q.get('dst_ip')!.trim() || !validTarget(q.get('dst_ip')!))) {
      return send({ error: 'invalid dst_ip' }, 400)
    }
    const filtered = list.filter(a => (!q.get('direction') || a.direction === q.get('direction'))
      && (!q.get('dst_ip') || contained(a.dst_ip, q.get('dst_ip')!))
      && (!q.get('ended_after') || !a.ended_at || Date.parse(a.ended_at) >= Date.parse(q.get('ended_after')!))
      && (!q.get('to') || Date.parse(a.started_at) <= Date.parse(q.get('to')!)))
    const start = Number(q.get('offset') || 0), limit = Math.min(200, Number(q.get('limit') || 50))
    if (q.get('sort') === 'peak_pps') filtered.sort((a, b) => b.peak_pps - a.peak_pps)
    return send({ attacks: empty ? null : filtered.slice(start, start + limit), total: empty ? 0 : filtered.length })
  }
  if (path === '/api/attacks/mitigation-brief') {
    const ids = (q.get('ids') || '').split(',')
    if (ids.length > 50) return send({ error: 'ids must contain at most 50 unique positive integers' }, 400)
    return send(Object.fromEntries(ids.map(id => [id, { xdrop_rules: [{ external_rule_id: 'shared-rule',
      status: 'active' }], bgp: [{ prefix: '10.1.0.0/16', route_map: 'defense', status: 'active',
      attached_at: iso(-50000), delay_minutes: 0 }] }])))
  }
  if (path === '/api/active-actions/xdrop' && mode !== 'normal' && mode !== 'null'
    && (mode.startsWith('attacks') || mode.startsWith('force-') || mode.startsWith('sample-'))) {
    return send(holderRows(now))
  }
  if (path.startsWith('/api/active-actions/')) {
    const xdrop = path.endsWith('xdrop')
    return send(empty ? null : ['active', 'delayed', 'failed', 'active'].map((status, i) => ({ attack_id: i + 1,
      attack_dst_ip: '10.1.2.0/24', action_id: 1, action_type: xdrop ? 'xdrop' : 'bgp', connector_name: 'local',
      connector_id: 1, external_rule_id: xdrop ? (i >= 2 ? 'failed-create-' + i : 'shared-rule') : 'bgp-' + i,
      created_at: iso(-50000), status, dst_ip: '10.1.2.0/24', protocol: 'UDP', src_port: 53, dst_port: 123 })))
  }
  if (path === '/api/stats/overview') {
    const direction = q.get('direction') || 'receives'
    const both = [...new Set([...inbound, ...outbound].map(p => p.prefix))].map(cidr => {
      const parts = [...inbound, ...outbound].filter(p => p.prefix === cidr)
      const row = { ...parts[0]!, nodes: [...new Map(parts.flatMap(p => p.nodes).map(n => [n.id, n])).values()] }
      for (const key of ['pps', 'bps', 'tcp_pps', 'tcp_bps', 'udp_pps', 'udp_bps', 'icmp_pps', 'icmp_bps'] as const) {
        row[key] = parts.reduce((n, p) => n + p[key], 0)
      }
      return row
    })
    const rows = direction === 'sends' ? outbound : direction === 'both' ? both : inbound
    return send({ total_pps: empty ? 0 : rows.reduce((n, p) => n + p.pps, 0),
      total_bps: empty ? 0 : rows.reduce((n, p) => n + p.bps, 0), node_count: empty ? 0 : direction === 'both' ? 3 : 2,
      active_prefixes: empty ? 0 : direction === 'sends' ? 7 : 4,
      top_prefixes: empty ? [] : rows.slice(0, Number(q.get('limit') || 20)),
      nodes: empty ? [] : direction === 'receives'
        ? [{ id: 'edge-a', pps: 1000, bps: 1079 }, { id: 'flow-b', pps: 0, bps: 0 }]
        : direction === 'sends' ? [{ id: 'flow-b', pps: 0, bps: 0 }, { id: 'edge-c', pps: 999, bps: 8000 }]
          : [{ id: 'edge-a', pps: 1000, bps: 1079 }, { id: 'flow-b', pps: 0, bps: 0 },
            { id: 'edge-c', pps: 999, bps: 8000 }] })
  }
  if (path === '/api/stats/total-timeseries' || path === '/api/stats/timeseries') {
    if (path === '/api/stats/timeseries' && q.has('dst_ip')
      && Date.parse(q.get('to')!) - Date.parse(q.get('from')!) > 21600000) {
      return send({ error: 'dst_ip queries are limited to 6h' }, 400)
    }
    if (empty || mode === 'empty') return send(null)
    const start = Date.parse(q.get('from') || iso(-3600000)), end = Date.parse(q.get('to') || iso())
    const grain = q.get('resolution') === '5min' ? 300000 : 5000
    const sends = q.get('direction') === 'sends'
    const first = Math.ceil(start / grain) * grain
    return send(Array.from({ length: Math.max(0, Math.floor((end - first) / grain) + 1) }, (_, i) => {
      const n = mode === 'zero' ? 0 : Math.round((700 + Math.sin(i / 9) * 130 + (i % 53 < 15 ? 180 : 0))
        * (sends ? .4 : 1))
      return { time: new Date(first + i * grain).toISOString(), pps: n, bps: n * 800,
        tcp_pps: Math.round(n * .6), tcp_bps: Math.round(n * 480), udp_pps: Math.round(n * .3), udp_bps: n * 240,
        tcp_syn_pps: Math.round(n * .1), tcp_syn_bps: n * 80, icmp_pps: Math.round(n * .02), icmp_bps: n * 16,
        ...(n ? { frag_pps: 1, frag_bps: 80 } : {}),
        extra_decoder_pps: Object.fromEntries(extras.map(k => [k, n ? 2 : 0])),
        extra_decoder_bps: Object.fromEntries(extras.map(k => [k, n ? 160 : 0])) }
    }))
  }
  return send({ error: 'not found' }, 404)
}
function timerFor(id: number) {
  return { state: id === 2 ? 'expiring' : 'active', expires_in: id === 2 ? 125 : 0,
    threshold_value: id === 4 ? 800000 : id === 6 ? 80 : 800,
    threshold_unit: id === 4 ? 'bps' : id === 6 ? 'pct' : 'pps' }
}
function attackShape(id: number, now: number) {
  const targets = ['192.0.2.10/32', '2001:db8::1/128', '0.0.0.0/0', '198.51.100.0/24',
    '198.51.100.7/32', '203.0.113.0/24', '192.0.2.20/32']
  return { dst_ip: targets[(id - 1) % targets.length], direction: id === 4 ? 'sends' : 'receives',
    decoder_family: id === 3 ? 'ip' : 'udp', template_name: id === 5 ? undefined : 'UDP policy',
    rule_summary: id === 5 ? undefined : 'udp > 800 pps', reason_codes: id === 5 ? null : ['threshold_exceeded'],
    node_sources: id === 5 ? null : ['edge-a', 'flow-b'], response_id: 1, threshold_rule_id: 2,
    started_at: new Date(now - (id === 7 ? 9 * 3600000 : 600000)).toISOString() }
}
function flowRows(now: number) {
  return [
    { time: new Date(now - 20000).toISOString(), node_id: 'flow-b', prefix: '192.0.2.0/24', src_ip: '198.51.100.1',
      dst_ip: '192.0.2.10', src_port: 53, dst_port: 123, protocol: 17, tcp_flags: 0, packets: 120, bytes: 153600 },
    { time: new Date(now - 15000).toISOString(), node_id: 'flow-b', prefix: '192.0.2.0/24', src_ip: '198.51.100.2',
      dst_ip: '192.0.2.10', src_port: 443, dst_port: 80, protocol: 6, tcp_flags: 18, packets: 80, bytes: 1048576 },
    { time: new Date(now - 10000).toISOString(), node_id: 'flow-b', prefix: null, src_ip: '198.51.100.1',
      dst_ip: '192.0.2.10', src_port: 53, dst_port: 123, protocol: 6, tcp_flags: 0, packets: 40, bytes: 1023 },
  ]
}
function mitigation(a: any, now: number) {
  const iso = (offset = 0) => new Date(now + offset).toISOString()
  const execution = (id: number, action_type: string, status = 'success') => ({ id, attack_id: a.id,
    action_id: id + 10, response_name: 'Automatic defense', action_type, connector_name: action_type === 'bgp'
      ? 'Transit BGP' : 'Edge XDrop', trigger_phase: 'on_detected', status, status_code: 200,
    error_message: '', request_body: '{}', response_body: '{"ok":true,"count":2}',
    external_rule_id: action_type === 'bgp' ? '192.0.2.0/24|defense' : 'shared-rule', connector_id: 1,
    duration_ms: 12, executed_at: iso(-600000) })
  const executions = [
    { ...execution(90, 'manual_override'), connector_name: '', response_name: '', trigger_phase: 'manual_override' },
    { ...execution(1, 'xdrop') },
    { ...execution(2, 'bgp'), bgp_role: 'triggered', announcement_id: 1, announcement_refcount: 3 },
    { ...execution(3, 'bgp'), bgp_role: 'attached_shared', announcement_id: 1, announcement_refcount: 3 },
    { ...execution(4, 'webhook', 'skipped'), status_code: null, skip_reason: 'mode_observe', duration_ms: 0 },
    { ...execution(5, 'xdrop', 'failed'), status_code: null, error_message: 'connector unavailable',
      skip_reason: 'delivery_failed', detail: 'Rule delivery failed; retained for diagnosis',
      external_rule_id: 'failed-create-5', response_body: 'upstream unavailable' },
    { ...execution(6, 'shell', 'scheduled'), scheduled_for: iso(60000), status_code: null },
    { ...execution(7, 'bgp'), trigger_phase: 'on_expired' },
    { ...execution(8, 'xdrop'), trigger_phase: 'on_expired' },
  ]
  const rule = (id: number, status: string) => ({ id, attack_id: a.id, action_id: id + 10, connector_id: 1,
    external_rule_id: id === 5 ? 'failed-create-5' : id === 8 ? 'old-rule' : 'shared-rule',
    status, delay_minutes: id === 7 ? 5 : 0, created_at: iso(-600000),
    ...(id === 7 ? { delay_started_at: iso(-30000) } : {}),
    ...(id === 8 ? { withdrawn_at: iso(-10000) } : {}),
    ...(id === 5 ? { error_message: 'connector unavailable' } : {}) })
  return { attack: a, executions, xdrop_rules: [rule(1, 'active'), rule(5, 'failed'), rule(7, 'delayed'),
    rule(8, 'withdrawn')], bgp_announcements: [
      { announcement: { gen: 1, id: 1, prefix: '192.0.2.0/24', route_map: 'defense', connector_id: 1,
        first_action_id: 12, status: 'active', refcount: 3, announced_at: iso(-600000), delay_minutes: 5,
        created_at: iso(-600000) }, attached_at: iso(-600000), detached_at: null, attack_delay_minutes: 5,
        attack_action_id: 12 },
      { announcement: { gen: 1, id: 2, prefix: '203.0.113.0/24', route_map: 'delay', connector_id: 1,
        status: 'delayed', refcount: 0, announced_at: iso(-600000), delay_minutes: 5,
        delay_started_at: iso(-60000), created_at: iso(-600000) }, attached_at: iso(-600000),
        detached_at: iso(-60000), attack_delay_minutes: 5, attack_action_id: null },
    ], summary: { total_evaluated: 9, success: 6, failed: 1, skipped: 1, timeout: 0,
      skip_reasons: { mode_observe: 1 } } }
}
function holderRows(now: number) {
  return [1, 2].flatMap(attack_id => [
    { attack_id, attack_dst_ip: '192.0.2.10/32', action_id: 11, action_type: 'xdrop', connector_name: 'Edge XDrop',
      connector_id: 1, external_rule_id: 'shared-rule', created_at: new Date(now - 600000).toISOString(),
      status: 'active', dst_ip: '192.0.2.10', protocol: 'UDP', src_port: 53, dst_port: 123 },
  ])
}
function prefixValue(raw: string) {
  let [ip = '', mask] = raw.split('/'), bits = ip.includes(':') ? 128 : 32
  if (bits === 32) return { bits, mask: Number(mask ?? 32), value: ip.split('.')
    .reduce((n, w) => n * 256n + BigInt(w), 0n) }
  if (ip.includes('.')) {
    const parts = ip.slice(ip.lastIndexOf(':') + 1).split('.').map(Number)
    ip = ip.slice(0, ip.lastIndexOf(':') + 1) + ((parts[0]! << 8) + parts[1]!).toString(16)
      + ':' + ((parts[2]! << 8) + parts[3]!).toString(16)
  }
  const sides = ip.split('::'), left = sides[0] ? sides[0].split(':') : []
  const right = sides[1] ? sides[1].split(':') : []
  const words = sides.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left
  return { bits, mask: Number(mask ?? 128), value: words.reduce((n, w) => n * 65536n + BigInt(parseInt(w, 16)), 0n) }
}
function contained(raw: string, query: string) {
  const a = prefixValue(raw), b = prefixValue(query)
  return a.bits === b.bits && a.mask >= b.mask
    && a.value >> BigInt(a.bits - b.mask) === b.value >> BigInt(b.bits - b.mask)
}
export function mockSession(mode = 'normal', now = Date.now()) {
  const sessionTime = now
  const expired = new Map<number, string>()
  const state = fixtureState(now)
  const detection = detectionSession(mode, now, state)
  const responses = responseSession(mode, now, state)
  const qd = qdSession(mode, now, state)
  const flow = flowSession(mode, now)
  const users = usersSession(mode, now)
  return (raw: string, method = 'GET', body: any = {}, now = sessionTime): MockResult => {
    const userResult = users(raw, method, body)
    if (userResult) return userResult
    const responded = responses(raw, method, body)
    if (responded) return responded
    const detected = detection(raw, method, body)
    if (detected) return detected
    if (method === 'GET' || raw.startsWith('/api/flow-')) {
      const flowed = flow(raw, method, body)
      if (flowed) return flowed
    }
    const write = qd(raw, method, body)
    if (write) {
      if (write.status < 300) flow(raw, method, body)
      return write
    }
    const url = new URL(raw, 'http://localhost'), match = /^\/api\/attacks\/(\d+)\/expire$/.exec(url.pathname)
    if (method === 'POST' && match) {
      const id = Number(match[1]), hold = url.searchParams.get('hold_seconds')
      if (hold !== null && (!/^[0-9]+$/.test(hold) || +hold > 86400)) {
        return { status: 400, body: { error: 'hold_seconds must be an integer between 0 and 86400' } }
      }
      const a = mockReply('/api/attacks/' + id, mode, now)
      if (a.status !== 200) return a
      if (a.body.attack.ended_at || expired.has(id)) return { status: 409, body: { error: 'attack already expired' } }
      expired.set(id, new Date(now).toISOString())
      return { status: 200, body: { ok: true, method: id === 5 ? 'db' : 'tracker' } }
    }
    if (method === 'POST' && url.pathname === '/api/active-actions/force-remove') {
      if (!body || Array.isArray(body) || !['attack_id', 'action_id', 'connector_id'].every(
        k => typeof body[k] === 'number' && Number.isInteger(body[k]) && body[k] !== 0,
      ) || typeof body.external_rule_id !== 'string' || !body.external_rule_id) {
        return { status: 400, body: { error: 'missing required fields' } }
      }
      if (mode === 'force-error') return { status: 500, body: { error: 'connector request failed' } }
      if (mode === 'force-timeout') return { status: 200, body: { ok: true }, delay: 31000 }
      return { status: 200, body: mode === 'force-warning'
        ? { ok: true, warning: 'local hold released; remote pending' }
        : { ok: true } }
    }
    return mockReply(raw, mode, now, expired)
  }
}

function rfc3339(value: string) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(value)
  if (!match) return false
  const [, year, month, day, hour, minute, second, zone] = match
  const days = new Date(Date.UTC(Number(year), Number(month), 0)).getUTCDate()
  return Number(month) >= 1 && Number(month) <= 12 && Number(day) >= 1 && Number(day) <= days
    && Number(hour) <= 23 && Number(minute) <= 59 && Number(second) <= 59
    && (zone === 'Z' || Number(zone!.slice(1, 3)) <= 24 && Number(zone!.slice(4)) <= 60)
}

// Fixtures: field names and omissions follow ActiveResponseAction and getNodeStatus.
export function qdReply(raw: string, mode: string, now: number): MockResult | undefined {
  const url = new URL(raw, 'http://localhost'), path = url.pathname, q = url.searchParams
  const iso = (offset = 0) => new Date(now + offset).toISOString()
  const send = (body: unknown, status = 200, delay = 0) => ({ status, body, delay })
  const empty = mode === 'null' || mode === 'qd-empty'
  const attachment = (attack_id: number, detached = false) => ({ attack_id, dst_ip: '192.0.2.10/32',
    decoder: 'udp', response_name: 'Automatic defense', delay_minutes: 5, attached_at: iso(-600000),
    ...(detached ? { detached_at: iso(-120000) } : {}) })
  const bgp = (n: number, status: string, attack_id = n) => ({ attack_id, action_id: 5, action_type: 'bgp',
    attack_dst_ip: attack_id ? '192.0.2.10/32' : '', connector_name: 'Transit BGP', connector_id: 1,
    external_rule_id: `192.0.2.${16 * n}/28|defense`, prefix: `192.0.2.${16 * n}/28`, route_map: 'defense', status,
    created_at: iso(-600000) })
  if (mode === 'normal' && path === '/api/active-actions/bgp') return send(
    ['active', 'delayed', 'failed', 'active'].map((status, i) => ({ ...bgp(i + 1, status),
      attached_attacks: [attachment(i + 1)] })))
  if (mode === 'normal' && path === '/api/active-actions/xdrop') return send(
    ['active', 'delayed', 'failed', 'active'].map((status, i) => ({ ...holderRows(now)[0]!,
      attack_id: i + 1, external_rule_id: i >= 2 ? 'failed-create-' + i : 'shared-rule', status })))
  if (path === '/api/active-actions/bgp') return send(empty ? null : [
    { ...bgp(1, 'active'), attached_attacks: [attachment(1), { ...attachment(2), detached_at: null },
      attachment(3), attachment(4, true), attachment(5, true)] },
    { ...bgp(2, 'active'), attached_attacks: [attachment(2)] },
    { ...bgp(3, 'delayed'), attached_attacks: [attachment(3)], scheduled_for: iso(125000) },
    bgp(4, 'delayed'), bgp(5, 'failed', 0),
    { ...bgp(6, 'failed', 7), attached_attacks: [attachment(7, true)] },
    ...[8, 9].map(n => ({ ...bgp(n, 'orphan', 0), action_id: 0, is_orphan: true, announcement_id: n,
      connector_name: n === 9 ? '' : 'Transit BGP' })),
  ])
  if (path === '/api/active-actions/bgp/dismissed-orphans') return send(empty || mode === 'qd-dismissed-empty' ? []
    : ['dismissed_on_upgrade', 'dismissed'].map((status, i) => ({ announcement_id: 20 + i,
      prefix: `198.51.100.${16 * i}/28`, route_map: 'defense', connector_id: 1, connector_name: 'Transit BGP',
      status, detected_at: iso(-86400000) })))
  if (path === '/api/active-actions/xdrop') return send(empty ? null : [
    ...holderRows(now).map(r => ({ ...r, action: 'drop' })),
    { attack_id: 5, action_id: 15, action_type: 'xdrop', attack_dst_ip: '198.51.100.7/32', dst_ip: '198.51.100.7/32',
      connector_name: '', connector_id: 1, external_rule_id: 'failed-create-5', created_at: iso(-600000),
      status: 'failed' },
    { ...holderRows(now)[0]!, attack_id: 3, action_id: 13, external_rule_id: 'disabled-rule', connector_id: 2,
      connector_name: 'Disabled XDrop' },
    { ...holderRows(now)[0]!, attack_id: 4, action_id: 14, external_rule_id: 'unavailable-rule',
      status: 'delayed', scheduled_for: iso(125000), protocol: 'tcp', tcp_flags: 'SYN', src_port: 0, dst_port: 443 },
    { ...holderRows(now)[0]!, attack_id: 6, action_id: 16, external_rule_id: 'timeout-rule',
      protocol: '', src_port: 0, dst_port: 0, rate_limit: 1000, action: 'rate_limit' },
  ].map(row => mode === 'qd-tolerant-zero' ? row : omitEmptyMatchFields(row)))
  if (path === '/api/active-actions/xdrop/delivery') {
    const rule = q.get('rule_id')
    if (mode === 'qd-unavailable' || rule === 'unavailable-rule') {
      return send({ error: 'xdrop connector not found' }, 404)
    }
    if (mode === 'qd-delivery-error') return send({ error: 'HTTP 409 epoch mismatch' }, 502)
    if (mode === 'qd-notfound') return send({ found: false })
    if (mode === 'qd-delivery-bad') return send({})
    if (mode === 'qd-timeout' || rule === 'timeout-rule') return send({}, 200, 31000)
    return send({ rule_id: rule, target_gen: 1, epoch: 'epoch-1', nodes: mode === 'qd-delivery-null' ? null
      : mode === 'qd-delivery-empty' ? [] : ['confirmed', 'pending', 'disabled', 'offline', 'incompatible',
        'overloaded', 'rejected'].map((state, i) => ({ name: 'xd-node-' + (i + 1), state,
        ...(state === 'rejected' ? { code: 'E_TABLE_FULL', error: 'rule table full' } : {}) })) })
  }
  if (path === '/api/active-actions/timeline') {
    if (mode === 'qd-timeline-error') return send({ error: 'timeline unavailable' }, 503)
    return send({ attack: null, logs: empty ? null : [
      { id: 1, attack_id: Number(q.get('attack_id')), action_id: Number(q.get('action_id')),
        response_name: 'Automatic defense', connector_name: 'Edge XDrop',
        action_type: q.get('external_rule_id')?.includes('|') ? 'bgp' : 'xdrop',
        trigger_phase: 'on_detected', status: 'success', status_code: 200,
        request_body: '{}', response_body: '{}', external_rule_id: q.get('external_rule_id'),
        connector_id: Number(q.get('connector_id')), duration_ms: 12, executed_at: iso(-600000), error_message: '' },
      { id: 2, attack_id: Number(q.get('attack_id')), action_id: Number(q.get('action_id')),
        response_name: '', connector_name: '', status_code: null, request_body: '', response_body: '',
        connector_id: Number(q.get('connector_id')), external_rule_id: q.get('external_rule_id'),
        action_type: 'manual_override',
        trigger_phase: 'manual_override', status: 'failed', duration_ms: 0, executed_at: iso(-50000),
        error_message: 'upstream busy' },
      { id: 3, attack_id: Number(q.get('attack_id')), action_id: 999, response_name: '', connector_name: '',
        status_code: null, request_body: '', response_body: '', connector_id: Number(q.get('connector_id')),
        external_rule_id: q.get('external_rule_id'), action_type: 'shell', trigger_phase: 'on_expired',
        status: 'failed',
        duration_ms: 0, executed_at: iso(-40000), error_message: 'OTHER ACTION' },
    ] })
  }
  if (/^\/api\/nodes\/[^/]+\/status$/.test(path)) {
    if (mode === 'qd-status-404') return send({ error: 'node not found' }, 404)
    return send({ id: decodeURIComponent(path.split('/')[3]!), mode: 'xdp', online: true,
      config_status: 'synced', delivery_version_current: 12, delivery_version_applied: 12, drift: 0,
      last_ack_at: null, last_stats_at: iso(-5000), stats_age_seconds: 5, connected_at: iso(-600000),
      uptime_seconds: 600, flow_metrics: { decode_errors: 0, unknown_exporter: 0, template_misses: 0,
        updated_at: iso(-5000) },
      source_statuses: [{ device_ip: '192.0.2.1', active: true, last_seen_at: Math.floor((now - 5000) / 1000),
        records_received: 100 }],
      listener_statuses: [{ listen_addr: '0.0.0.0:6343', protocol_mode: 'sflow', records_decoded: 100,
        decode_errors: 0, unknown_exporter: 0, template_misses: 0, source_count: 1 }],
      ...(mode === 'qd-status-none' ? {} : { interfaces: ['eth1', 'eth2'] }),
      ...(mode === 'qd-status-interfaces' || mode === 'qd-status-none' ? {} : {
        capture: [{ interface: 'eth1', upstream_sample_rate: 1 }, { interface: 'eth2', upstream_sample_rate: 0 },
          { interface: 'eth3', upstream_sample_rate: 300 }] }) })
  }
  if (path === '/api/nodes' && mode === 'qd-slash') return send([{ id: 'a/b', description: 'Encoded ID',
    mode: 'flow', enabled: true, delivery_version_current: 7, delivery_version_applied: 4,
    config_status: 'pending', last_ack_at: null, created_at: iso(-86400000), updated_at: iso(-5000), online: false }])
  if (path === '/api/flow-listeners') {
    if (!q.get('node_id')) return send({ error: 'node_id is required' }, 400)
    return send(empty ? [] : [{ id: 1, node_id: q.get('node_id'), listen_address: '0.0.0.0:6343',
      protocol_mode: 'sflow', enabled: true, description: 'Flow input', created_at: iso(-86400000) }])
  }
  return undefined
}
function qdSession(mode: string, now: number, state: State) {
  const nodes = new Set<string>((mockReply('/api/nodes', mode, now).body ?? []).map((n: any) => n.id))
  const announcements = state.announcements
  return (raw: string, method: string, body: any): MockResult | undefined => {
    const path = new URL(raw, 'http://localhost').pathname
    const send = (body: unknown, status = 200) => ({ body, status })
    if (method === 'POST' && path.startsWith('/api/active-actions/bgp/orphan-')) {
      if (!Number.isInteger(body.announcement_id) || !body.announcement_id) {
        return send({ error: 'announcement_id is required' }, 400)
      }
      if (mode === 'qd-orphan-error') return send({ error: 'announcement is not orphan' }, 400)
      if (mode === 'qd-orphan-404') return send({ error: 'announcement not found' }, 404)
      const id = body.announcement_id, status = announcements.get(id)
      if (!status) return send({ error: 'announcement not found' }, 404)
      const operation = path.split('orphan-')[1]
      if (operation === 'force-withdraw' && status !== 'orphan') return send({
        error: `announcement ${id} status=${status} is not orphan; use /force-remove instead`,
      }, 400)
      if (operation === 'dismiss' && status !== 'orphan') return send({
        error: `announcement ${id} status=${status} is not orphan; can only dismiss orphans`,
      }, 400)
      if (operation === 'undismiss' && !['dismissed', 'dismissed_on_upgrade'].includes(status)) return send({
        error: `announcement ${id} status=${status} cannot be undismissed`,
      }, 400)
      if (operation === 'dismiss') announcements.set(id, 'dismissed')
      if (operation === 'undismiss') announcements.set(id, 'orphan')
      return send(mode === 'qd-warning' ? { ok: true, warning: 'vtysh error: mock (row marked failed)' }
        : { ok: true, announcement_id: body.announcement_id })
    }
    if (method === 'POST' && path === '/api/nodes') {
      if (mode === 'qd-create-conflict') return send({ error: 'already exists' }, 409)
      if (!['xdp', 'flow'].includes(body.mode)) return send({ error: "mode must be 'xdp' or 'flow'" }, 400)
      if (nodes.has(body.id)) return send({ error: 'already exists' }, 409)
      nodes.add(body.id)
      return send({ id: body.id }, 201)
    }
    if (method === 'DELETE' && path.startsWith('/api/nodes/')) {
      if (mode === 'qd-delete-error') return send({ error: 'failed to delete flow listener: database error' }, 500)
      nodes.delete(decodeURIComponent(path.slice('/api/nodes/'.length)))
      return send({ ok: true })
    }
    if (method === 'POST' && path === '/api/active-actions/force-remove' && mode === 'qd-force-error') {
      return send({ error: 'force remove failed' }, 500)
    }
    return undefined
  }
}

function omitEmptyMatchFields(row: Record<string, any>) {
  const result = { ...row }
  for (const field of ['dst_ip', 'protocol', 'tcp_flags', 'action', 'src_port', 'dst_port', 'rate_limit']) {
    if (result[field] === '' || result[field] === 0) delete result[field]
  }
  return result
}

// One state for detection and response dispatchers.
export function fixtureState(now: number) {
  const created_at = new Date(now - 86400000).toISOString(), updated_at = new Date(now).toISOString()
  let prefixes: any[] = [
    { id: 1, prefix: '10.1.0.0/16', name: 'Transit', ip_group: 'transit', parent_id: null,
      threshold_template_id: 7, enabled: true, created_at },
    { id: 2, prefix: '10.2.0.0/16', name: 'Services', ip_group: '', parent_id: null,
      threshold_template_id: 7, enabled: true, created_at },
    { id: 3, prefix: '10.3.0.0/16', name: 'Outbound', ip_group: '', parent_id: null,
      threshold_template_id: 7, enabled: false, created_at },
    { id: 4, prefix: '10.1.1.0/24', name: 'Transit child', ip_group: 'transit', parent_id: 1,
      threshold_template_id: 7, enabled: true, created_at },
    { id: 5, prefix: '192.0.2.0/24', name: 'Office', ip_group: 'office', parent_id: null,
      threshold_template_id: 7, enabled: true, created_at },
    { id: 6, prefix: '2001:db8::/48', name: 'IPv6', ip_group: '', parent_id: null,
      threshold_template_id: 7, enabled: true, created_at },
    { id: 8, prefix: '0.0.0.0/0', name: 'Global', ip_group: '', parent_id: null,
      threshold_template_id: 8, enabled: true, created_at },
    { id: 9, prefix: '203.0.113.0/24', name: 'Unbound', ip_group: '', parent_id: null,
      threshold_template_id: null, enabled: true, created_at },
  ]
  let templates: any[] = [
    { id: 7, name: 'Transit defaults', description: 'Shared traffic thresholds', response_id: 1,
      rule_count: 0, prefix_count: 0, created_at, updated_at },
    { id: 8, name: 'Global defaults', description: 'Aggregate subnet traffic', response_id: null,
      rule_count: 0, prefix_count: 0, created_at, updated_at },
    { id: 9, name: 'Unused', description: 'Not bound to any prefix', response_id: null,
      rule_count: 0, prefix_count: 0, created_at, updated_at },
  ]
  const rule = (id: number, decoder: string, extra: any = {}) => ({ id, template_id: 7, prefix_id: null,
    domain: 'internal_ip', direction: 'receives', decoder, unit: 'pps', comparison: 'over', value: 500,
    inheritable: true, response_id: null, enabled: true, created_at, ...extra })
  let rules = [rule(101, 'ip', { value: 0 }), rule(102, 'tcp', { unit: 'pct', value: 80 }),
    rule(103, 'tcp', { direction: 'sends' }), rule(104, 'ip', { unit: 'bps', value: 800000 }),
    rule(105, 'ip', { template_id: 8, domain: 'subnet' }), rule(106, 'udp', { template_id: 9 }),
    rule(107, 'tcp_syn', { template_id: null, prefix_id: 1, value: 12345, response_id: 2 })]
  let config = { enabled: true, deviation_min: 50, deviation_max: 150, stable_weeks: 6,
    min_pps: 2000, min_bps: 16000, ewma_alpha: 0.25 }
  let responses = [
    { id: 1, name: 'Observe', description: 'Webhook notification', enabled: true, created_at },
    { id: 2, name: 'Edge defense', description: 'XDrop action', enabled: false, created_at },
    { id: 3, name: 'IDC-C defense', description: 'Response action suite', enabled: true, created_at },
  ]
  const connector = (id: number, name: string, enabled = true) =>
    ({ id, name, enabled, created_at, updated_at: created_at })
  const connectors: Record<string, any[]> = {
    webhook: [1, 2].map(id => ({ ...connector(id, id === 1 ? 'Alert hook' : 'Disabled hook', id === 1),
      url: 'http://192.0.2.1/hook', method: 'POST', headers: { Authorization: 'Bearer qg-synthetic' },
      timeout_ms: 10000,
      global: false })),
    shell: [1, 2].map(id => ({ ...connector(id, id === 1 ? 'Local shell' : 'Disabled shell', id === 1),
      command: '/bin/true', default_args: '', timeout_ms: 10000, pass_stdin: id === 2 })),
    bgp: [1, 2].map(id => ({ ...connector(id, id === 1 ? 'Edge BGP' : 'Disabled BGP', id === 1),
      bgp_asn: 64512, vtysh_path: '/mock/missing', address_family: 'ipv4', description: '',
      vendor: '', flowspec_enabled: false })),
    xdrop: [
    { id: 1, name: 'Edge XDrop', enabled: true, api_url: 'http://mock-xdrop.invalid', api_key: '***abcd',
      timeout_ms: 10000, created_at, updated_at: new Date(now - 5000).toISOString() },
    { id: 2, name: 'Disabled XDrop', enabled: false, api_url: 'http://mock-disabled.invalid', api_key: '***',
      timeout_ms: 10000, created_at, updated_at: new Date(now - 5000).toISOString() },
  ],
  }
  const action = (id: number, action_type: string, more: any = {}) => ({ id, response_id: 3, action_type,
    execution_policy: 'once_on_enter', priority: 5, config: {}, preconditions: null, enabled: true,
    trigger_phase: 'on_detected', run_mode: 'once', period_seconds: 60, execution: 'automatic',
    webhook_connector_id: action_type === 'webhook' ? 1 : null,
    shell_connector_id: action_type === 'shell' ? 1 : null, bgp_connector_id: action_type === 'bgp' ? 1 : null,
    xdrop_action: '', xdrop_custom_payload: null, shell_extra_args: '', unblock_delay_minutes: 0,
    bgp_route_map: action_type === 'bgp' ? 'RTBH' : '', bgp_withdraw_delay_minutes: 0,
    connector_name: connectors[action_type]?.[0]?.name ?? '', connector_id: action_type === 'xdrop' ? null : 1,
    target_node_ids: null, xdrop_fields: null, xdrop_rate_limit: null, ...more })
  let actions = [action(11, 'webhook'), action(12, 'shell', { run_mode: '', priority: 0, execution: 'manual' }),
    action(13, 'bgp', { paired_with: 14 }), action(14, 'bgp', {
      trigger_phase: 'on_expired', auto_generated: true,
      execution_policy: 'once_on_exit', period_seconds: 0 }),
    action(15, 'xdrop', { xdrop_action: 'filter_l4', paired_with: 16, connector_name: 'Edge XDrop (+1)',
      target_node_ids: [1, 2], xdrop_custom_payload: { dst_ip: '{dst_ip}', action: 'drop' },
      xdrop_fields: ['dst_ip'] }),
    action(16, 'xdrop', { xdrop_action: 'unblock',
      trigger_phase: 'on_expired', auto_generated: true,
      execution_policy: 'once_on_exit', period_seconds: 0, connector_name: 'Edge XDrop (+1)',
      target_node_ids: [1, 2] }),
    action(17, 'xdrop', { priority: 2, xdrop_action: 'rate_limit', connector_name: '(all)', target_node_ids: [],
      xdrop_custom_payload: { dst_ip: '{dst_ip}', action: 'rate_limit', rate_limit: 100000 },
      xdrop_fields: ['dst_ip'], xdrop_rate_limit: 100000 }),
    action(18, 'webhook', { trigger_phase: 'on_expired', execution_policy: 'once_on_exit' }),
    action(1, 'webhook', { response_id: 1 }), action(2, 'xdrop', { response_id: 2, connector_name: '(all)',
      xdrop_action: 'filter_l4', target_node_ids: [], xdrop_fields: ['dst_ip'],
      xdrop_custom_payload: { dst_ip: '{dst_ip}', action: 'drop' } })]
  const conditions = new Map<number, any[]>([[15, [
    { id: 1, action_id: 15, attribute: 'decoder', operator: 'eq', value: 'udp', created_at },
    { id: 2, action_id: 15, attribute: 'peak_pps', operator: 'gte', value: '100000', created_at },
  ]]])
  const sequences = { prefix: 10, template: 10, rule: 108, response: 4, action: 100, condition: 3 }
  return { prefixes, templates, rules, config, responses, connectors, actions, conditions, sequences, action, rule,
    announcements: new Map<number, string>() }
}
type State = ReturnType<typeof fixtureState>
const textOrder = (a: string, b: string) => {
  const left = new TextEncoder().encode(a), right = new TextEncoder().encode(b)
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i]! - right[i]!
  }
  return left.length - right.length
}
const nullableRows = (rows: any[]) => rows.length ? rows : null
const orderedRules = (s: State) => [...s.rules].sort((a, b) =>
  (a.prefix_id ?? Infinity) - (b.prefix_id ?? Infinity)
  || (a.template_id ?? Infinity) - (b.template_id ?? Infinity) || textOrder(a.decoder, b.decoder))
const blockingResponse = (s: State, id: number) => s.actions.some(a =>
  a.response_id === id && ['xdrop', 'bgp'].includes(a.action_type))
function ruleConstraint(s: State, row: any) {
  if (row.prefix_id !== null && !s.prefixes.some(p => p.id === row.prefix_id)) return 'referenced object not found'
  if (row.template_id !== null && !s.templates.some(t => t.id === row.template_id)) return 'referenced object not found'
  if (row.response_id !== null && !s.responses.some(r => r.id === row.response_id)) return 'referenced object not found'
  const same = (r: any) => r.id !== row.id
    && ['decoder', 'unit', 'direction', 'domain'].every(k => r[k] === row[k])
  const templateKey = row.template_id !== null && s.rules.some(r => same(r) && r.template_id === row.template_id)
  const prefixKey = row.prefix_id !== null && s.rules.some(r => same(r) && r.prefix_id === row.prefix_id)
  return templateKey || prefixKey ? 'already exists' : ''
}

// Detection fixtures mirror WatchPrefix, ThresholdTemplate, Threshold and the two dynamic handlers.
function detectionSession(mode: string, now = Date.now(), s = fixtureState(now)) {
  const created_at = new Date(now).toISOString(), updated_at = created_at
  const baselines = [
    { prefix: '10.1.0.0/16', p95_pps: 150, p95_bps: 1500, recommend_pps: 300, recommend_bps: 3000,
      detect_thresh_pps: 450, detect_thresh_bps: 4500, data_points: 360, active: true, source: 'best_node' },
    { prefix: '10.2.0.0/16', p95_pps: 450, p95_bps: 4500, recommend_pps: 900, recommend_bps: 9000,
      detect_thresh_pps: 1350, detect_thresh_bps: 13500, data_points: 360, active: true, source: 'best_node' },
    { prefix: '2001:db8::/48', p95_pps: 0, p95_bps: 0, recommend_pps: 0, recommend_bps: 0,
      detect_thresh_pps: 0, detect_thresh_bps: 0, data_points: 0, active: false, source: 'best_node' },
  ]
  const statuses = [
    { prefix: '2001:db8::/48', expected_pps: 0, expected_bps: 0, current_pps: 90, current_bps: 900,
      thresh_pps: 0, thresh_bps: 0, sample_weeks: 0, status: 'learning', node_count: 1 },
    { prefix: '10.2.0.0/16', expected_pps: 200, expected_bps: 2000, current_pps: 100, current_bps: 20000,
      thresh_pps: 400, thresh_bps: 4000, sample_weeks: 3, status: 'exceeded', node_count: 2 },
    { prefix: '10.1.0.0/16', expected_pps: 100, expected_bps: 1000, current_pps: 80, current_bps: 800,
      thresh_pps: 150, thresh_bps: 1500, sample_weeks: 6, status: 'normal', node_count: 1 },
  ]
  const send = (body: any, status = 200) => ({ body: JSON.parse(JSON.stringify(body)), status })
  const fail = (error: string, status = 400) => send({ error }, status)
  const empty = mode === 'empty' || mode === 'null'
  const bound = (id: number) => s.prefixes.filter(p => p.threshold_template_id === id)
    .sort((a, b) => textOrder(a.prefix, b.prefix))
  const decoderNames = DECODERS.filter(d => d.key !== 'total').map(d => d.key).sort()
  const nameExists = (name: string) => s.templates.some(t => t.name === name)
  function checkParent(parentID: number | null, self: number) {
    if (parentID === null) return ''
    if (!s.prefixes.some(p => p.id === parentID)) return 'parent_id not found'
    const visited = new Set<number>()
    for (let id: number | null = parentID; id !== null; id = s.prefixes.find(p => p.id === id)?.parent_id ?? null) {
      if (id === self || visited.has(id)) return 'parent_id would create a cycle'
      visited.add(id)
    }
    return ''
  }
  function checkBinding(prefix: string, templateID: number | null) {
    if (prefix !== '0.0.0.0/0' || templateID === null) return ''
    const template = s.templates.find(t => t.id === templateID)
    if (!template) return 'threshold_template_id not found'
    if ([template.response_id, ...s.rules.filter(r => r.template_id === templateID).map(r => r.response_id)]
      .some(id => blockingResponse(s, id))) {
      return 'Global prefix (0.0.0.0/0) cannot use responses containing xDrop/BGP actions'
    }
    return ''
  }
  function checkRule(row: any) {
    if (!['pps', 'bps', 'pct'].includes(row.unit)) {
      return `unit must be one of: pps, bps, pct; got ${JSON.stringify(row.unit)}`
    }
    if (!['over', 'under'].includes(row.comparison)) {
      return `comparison must be one of: over, under; got ${JSON.stringify(row.comparison)}`
    }
    if (!['internal_ip', 'subnet'].includes(row.domain)) {
      return `domain must be one of: internal_ip, subnet; got ${JSON.stringify(row.domain)}`
    }
    if (['pps', 'bps'].includes(row.unit) && row.value < 0) {
      return `value must be between 0 and 9223372036854775807, got ${row.value}`
    }
    if (row.decoder !== '' && row.decoder !== 'ip' && !decoderNames.includes(row.decoder)) {
      return 'decoder must be one of: ip, ' + decoderNames.join(', ') + '; got ' + JSON.stringify(row.decoder)
    }
    if (row.direction !== '' && !['receives', 'sends'].includes(row.direction)) {
      return `direction must be 'receives' or 'sends', got ${JSON.stringify(row.direction)}`
    }
    if (row.unit === 'pct' && (row.decoder === 'ip' || row.decoder === '')) {
      return 'percentage thresholds are not meaningful for decoder=ip (always 100%);'
        + ' use a specific decoder like tcp, udp, icmp'
    }
    if (row.unit === 'pct' && (row.value < 1 || row.value > 100)) {
      return `percentage threshold value must be between 1 and 100, got ${row.value}`
    }
    const global = s.prefixes.some(p => p.prefix === '0.0.0.0/0'
      && (p.id === row.prefix_id || row.template_id !== null && p.threshold_template_id === row.template_id))
    if (global && row.domain === 'internal_ip') {
      return 'global prefix (0.0.0.0/0) only supports subnet-level rules, not internal_ip'
    }
    if (blockingResponse(s, row.response_id) && global) {
      return 'global prefix (0.0.0.0/0) rules cannot use responses containing xDrop/BGP actions'
    }
    if (blockingResponse(s, row.response_id) && row.direction === 'sends') {
      return 'outbound (sends) rules cannot use responses containing xDrop/BGP actions'
    }
    return ''
  }
  return (raw: string, method = 'GET', body: any = {}): MockResult | undefined => {
    const path = new URL(raw, 'http://localhost').pathname
    if (!/^\/api\/(prefixes|threshold-templates|threshold-rules|thresholds|responses|baseline|dynamic-detection)(\/|$)/
      .test(path)) return
    const id = Number(path.split('/')[3])
    if (method === 'GET') {
      if (path === '/api/prefixes') return send(empty ? null : nullableRows([...s.prefixes]
        .sort((a, b) => textOrder(a.prefix, b.prefix))))
      if (path === '/api/threshold-templates') return send(empty ? null : nullableRows([...s.templates]
        .sort((a, b) => textOrder(a.name, b.name)).map(t => ({ ...t,
          rule_count: s.rules.filter(r => r.template_id === t.id).length, prefix_count: bound(t.id).length }))))
      if (/^\/api\/threshold-templates\/\d+$/.test(path)) {
        const template = s.templates.find(t => t.id === id)
        if (!template) return fail('template not found', 404)
        return send({ template, rules: empty ? null : nullableRows(s.rules.filter(r => r.template_id === id)
          .sort((a, b) => textOrder(a.decoder, b.decoder) || textOrder(a.unit, b.unit))),
        prefixes_using: empty ? null : nullableRows(bound(id)) })
      }
      if (path === '/api/thresholds') return send(empty ? null : nullableRows(orderedRules(s)))
      if (path === '/api/baseline') return send(empty ? null : baselines)
      if (path === '/api/dynamic-detection/config') return mode === 'qe-config-error'
        ? fail('configuration unavailable', 503) : send(s.config)
      if (path === '/api/dynamic-detection/status') return send({ enabled: s.config.enabled, current_slot: 26,
        current_slot_label: 'Tuesday 02:00 UTC (latest)', total_prefixes: empty ? 0 : 3,
        activated_count: empty ? 0 : 2, learning_count: empty ? 0 : 1, prefixes: empty ? null : statuses })
      return
    }
    if (mode === 'qe-write-400') return fail('invalid JSON')
    if (path === '/api/dynamic-detection/config' && method === 'PUT') {
      const next = { enabled: false, deviation_min: 0, deviation_max: 0, stable_weeks: 0,
        min_pps: 0, min_bps: 0, ewma_alpha: 0 }
      for (const key of Object.keys(next) as (keyof typeof next)[]) {
        if (body[key] !== undefined && body[key] !== null) (next as any)[key] = body[key]
      }
      if (next.deviation_min < 0 || next.deviation_max < 0) return fail('deviation values must be non-negative')
      if (next.deviation_min > next.deviation_max) return fail('deviation_min must be <= deviation_max')
      if (next.stable_weeks < 1) return fail('stable_weeks must be >= 1')
      if (next.ewma_alpha <= 0 || next.ewma_alpha >= 1) return fail('ewma_alpha must be between 0 and 1 (exclusive)')
      if (next.min_pps < 0) return fail('min_pps must be >= 0')
      if (next.min_bps < 0) return fail('min_bps must be >= 0')
      s.config = next
      return send(s.config)
    }
    if (path.startsWith('/api/prefixes')) {
      if (method === 'POST') {
        if (isIPv4MappedPrefix(body.prefix)) return fail('Use IPv4 notation for IPv4-mapped prefixes')
        if (ipv6DefaultPrefix(body.prefix)) {
          return fail('Use 0.0.0.0/0 for global threshold (covers both IPv4 and IPv6)')
        }
        const parentID = body.parent_id ?? null, templateID = body.threshold_template_id ?? null
        const error = checkParent(parentID, 0) || checkBinding(body.prefix, templateID)
        if (error) return fail(error)
        const prefix = cidrText(body.prefix)
        if (!prefix) return fail('invalid input')
        const id = s.sequences.prefix++
        if (templateID !== null && !s.templates.some(t => t.id === templateID)) {
          return fail('referenced object not found')
        }
        s.prefixes.push({ prefix, name: body.name ?? '', ip_group: body.ip_group ?? '',
          parent_id: parentID, threshold_template_id: templateID, id, enabled: true, created_at })
        return send({ id }, 201)
      }
      if (method === 'PUT') {
        const row = s.prefixes.find(p => p.id === id)
        if (!row) return fail('prefix not found', 404)
        const next = { ...row }
        for (const key of ['prefix', 'name', 'ip_group']) if (typeof body[key] === 'string') next[key] = body[key]
        if (isIPv4MappedPrefix(next.prefix)) return fail('Use IPv4 notation for IPv4-mapped prefixes')
        if (ipv6DefaultPrefix(next.prefix)) {
          return fail('Use 0.0.0.0/0 for global threshold (covers both IPv4 and IPv6)')
        }
        for (const key of ['parent_id', 'threshold_template_id']) {
          if (body[key] === null || typeof body[key] === 'number') {
            next[key] = body[key] === null ? null : Math.trunc(body[key])
          }
        }
        const error = checkParent(next.parent_id, id) || checkBinding(next.prefix, next.threshold_template_id)
        if (error) return fail(error)
        const prefix = cidrText(next.prefix)
        if (!prefix) return fail('invalid input')
        if (next.threshold_template_id !== null && !s.templates.some(t => t.id === next.threshold_template_id)) {
          return fail('referenced object not found')
        }
        next.prefix = prefix
        if (typeof body.enabled === 'boolean') next.enabled = body.enabled
        Object.assign(row, next)
      }
      if (method === 'DELETE') {
        s.prefixes = s.prefixes.filter(p => p.id !== id)
        s.prefixes.forEach(p => { if (p.parent_id === id) p.parent_id = null })
        s.rules = s.rules.filter(r => r.prefix_id !== id)
      }
      return send({ ok: true })
    }
    if (path.startsWith('/api/threshold-templates')) {
      const template = s.templates.find(t => t.id === id)
      if (method === 'DELETE') {
        if (bound(id).length) return fail(`template in use by ${bound(id).length} prefixes: [${
          bound(id).map(p => p.prefix).join(' ')}]`, 409)
        s.templates = s.templates.filter(t => t.id !== id)
        s.rules = s.rules.filter(r => r.template_id !== id)
      } else if (path.endsWith('/rules')) {
        const str = (key: string, fallback: string) => typeof body[key] === 'string' ? body[key] : fallback
        const created = s.rule(0, str('decoder', ''), { template_id: id,
          domain: str('domain', 'internal_ip'), direction: str('direction', 'receives'), unit: str('unit', 'pps'),
          comparison: str('comparison', 'over'), value: typeof body.value === 'number' ? Math.trunc(body.value) : 0,
          inheritable: typeof body.inheritable === 'boolean' ? body.inheritable : true,
          response_id: typeof body.response_id === 'number' ? Math.trunc(body.response_id) : null })
        const error = checkRule(created)
        if (error) return fail(error)
        created.id = s.sequences.rule++
        const constraint = ruleConstraint(s, created)
        if (constraint) return fail(constraint, constraint === 'already exists' ? 409 : 400)
        s.rules.push(created)
        return send({ id: created.id }, 201)
      } else if (path.endsWith('/duplicate')) {
        if (!template) return fail('template not found', 404)
        const name = body.name || template.name + ' (Copy)'
        const newID = s.sequences.template++
        if (nameExists(name)) return fail('already exists', 409)
        s.templates.push({ ...template, id: newID, name, created_at, updated_at })
        const copies = s.rules.filter(r => r.template_id === id)
        copies.forEach(r => s.rules.push({ ...r, id: s.sequences.rule++, template_id: newID }))
        return send({ id: newID, name }, 201)
      } else if (method === 'POST') {
        const id = s.sequences.template++
        if (nameExists(body.name)) return fail('already exists', 409)
        s.templates.push({ id, name: body.name, description: body.description, response_id: null,
          rule_count: 0, prefix_count: 0, created_at, updated_at })
        return send({ id }, 201)
      } else if (method === 'PUT') {
        if (!template) return fail('template not found', 404)
        const responseID = body.response_id === undefined ? template.response_id : body.response_id
        if (blockingResponse(s, responseID) && bound(id).some(p => p.prefix === '0.0.0.0/0')) {
          return fail('Global prefix (0.0.0.0/0) cannot use responses containing xDrop/BGP actions')
        }
        if (blockingResponse(s, responseID) && s.rules.some(r => r.template_id === id && r.direction === 'sends')) {
          return fail('Template has outbound (sends) rules — cannot use responses'
            + ' containing xDrop/BGP actions as default')
        }
        if (responseID !== null && !s.responses.some(r => r.id === responseID)) {
          return fail('referenced object not found')
        }
        if (s.templates.some(t => t.id !== id && t.name === (body.name ?? template.name))) {
          return fail('already exists', 409)
        }
        Object.assign(template, body, { updated_at })
      }
      return send({ ok: true })
    }
    if (path.startsWith('/api/thresholds') || path.startsWith('/api/threshold-rules')) {
      if (method === 'DELETE') s.rules = s.rules.filter(r => r.id !== id)
      if (method === 'POST') {
        const created = s.rule(0, '', { template_id: null, domain: '', direction: '', unit: '',
          comparison: '', value: 0, inheritable: false, ...body, enabled: true })
        const error = checkRule(created)
        if (error) return fail(error)
        created.id = s.sequences.rule++
        const constraint = ruleConstraint(s, created)
        if (constraint) return fail(constraint, constraint === 'already exists' ? 409 : 400)
        s.rules.push(created)
        return send({ id: created.id }, 201)
      }
      if (method === 'PUT') {
        const row = s.rules.find(r => r.id === id)
        if (!row) return fail('threshold not found', 404)
        const merged = { ...row, ...body, id: row.id, template_id: row.template_id, prefix_id: row.prefix_id }
        const error = checkRule(merged)
        if (error) return fail(error)
        const constraint = ruleConstraint(s, merged)
        if (constraint) return fail(constraint, constraint === 'already exists' ? 409 : 400)
        Object.assign(row, merged)
      }
      return send({ ok: true })
    }
  }
}

// Response writes read the same detection state.
export function responseSession(mode = 'normal', now = Date.now(), s = fixtureState(now)) {
  if (mode === 'qf-empty') s.actions = []
  const empty = ['qf-empty', 'empty', 'null'].includes(mode), created_at = new Date(now).toISOString()
  const send = (body: any, status = 200): MockResult => ({ body: JSON.parse(JSON.stringify(body)), status })
  const fail = (error: string, status = 400) => send({ error }, status)
  const connectors = connectorSession(mode, now, s)
  const reads = new Map<number, number>()
  function checkCondition(c: any): string {
    const numeric = ['cidr', 'pps', 'bps', 'peak_pps', 'peak_bps', 'dominant_src_port', 'dominant_dst_port',
      'dominant_src_port_pct', 'dominant_dst_port_pct', 'unique_src_ips']
    if (![...numeric, 'decoder', 'severity', 'domain', 'attack_type', 'node', 'carpet_bomb'].includes(c.attribute)) {
      return 'unsupported precondition attribute: ' + c.attribute
    }
    if (!['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'in', 'not_in'].includes(c.operator)) {
      return 'unsupported precondition operator: ' + c.operator
    }
    if (!c.value) return 'precondition value cannot be empty'
    const invalid = `invalid precondition value for ${c.attribute}: ${JSON.stringify(c.value)}`
    const unsupported = `precondition operator ${c.operator} is not supported for attribute ${c.attribute}`
    if (c.attribute === 'carpet_bomb') {
      if (!['eq', 'neq'].includes(c.operator)) return 'carpet_bomb precondition only supports eq/neq'
      return ['true', 'false', '1', '0', 'yes', 'no'].includes(c.value.trim().toLowerCase())
        ? '' : 'unsupported carpet_bomb precondition value'
    }
    if (c.attribute === 'node') return !['eq', 'in'].includes(c.operator) ? unsupported
      : c.value.split(',').every((v: string) => v.trim()) ? '' : invalid
    if (!numeric.includes(c.attribute) && !['eq', 'neq', 'in', 'not_in'].includes(c.operator)) return unsupported
    const values = ['in', 'not_in'].includes(c.operator) ? c.value.split(',').map((v: string) => v.trim()) : [c.value]
    const allowed: Record<string, string[]> = { severity: ['critical', 'high', 'medium', 'low'],
      decoder: ['ip', ...DECODERS.filter(d => d.key !== 'total').map(d => d.key)], domain: ['internal_ip', 'subnet'] }
    if (allowed[c.attribute]) return values.every((v: string) => allowed[c.attribute]!.includes(v)) ? '' : invalid
    if (numeric.includes(c.attribute)) return values.every((v: string) => {
      if (!/^[+-]?\d+$/.test(v.trim())) return false
      const n = BigInt(v.trim())
      return n >= -9223372036854775808n && n <= 9223372036854775807n
    }) ? '' : invalid
    return ''
  }
  function dropAction(id: number) {
    s.actions = s.actions.filter(a => a.id !== id)
    s.conditions.delete(id)
    for (const a of s.actions) if (a.paired_with === id) delete a.paired_with
  }
  function enrich(a: any) {
    const cp = a.xdrop_custom_payload
    if (a.action_type === 'xdrop') a.target_node_ids = [...(a.target_node_ids ?? [])].sort((a, b) => a - b)
    a.connector_id = a.action_type === 'xdrop' ? null : a[a.action_type + '_connector_id']
    a.connector_name = a.action_type === 'xdrop' ? a.target_node_ids?.length
      ? (s.connectors.xdrop!.find(c => c.id === a.target_node_ids[0])?.name ?? '')
        + (a.target_node_ids.length > 1 ? ` (+${a.target_node_ids.length - 1})` : '') : '(all)'
      : s.connectors[a.action_type]?.find(c => c.id === a.connector_id)?.name ?? ''
    a.xdrop_fields = cp ? ['dst_ip', 'src_ip', 'dst_port', 'src_port', 'protocol'].filter(k => k in cp) : null
    a.xdrop_rate_limit = cp?.rate_limit ?? null
  }
  return (raw: string, method = 'GET', body: any = {}): MockResult | undefined => {
    const path = new URL(raw, 'http://localhost').pathname, id = Number(path.split('/')[3])
    const kind = /^\/api\/settings\/(webhook|shell|bgp|xdrop)-connectors$/.exec(path)?.[1]
    if (kind && method === 'GET') {
      if (mode === 'qg-fail' && kind === 'shell') return fail('shell list unavailable', 500)
      if (mode === 'qf-connectors-fail') return fail('connector list unavailable', 500)
      if (['empty', 'null'].includes(mode)) {
        if (kind === 'xdrop') return { ...send(mode === 'null' ? [] : s.connectors.xdrop), delay: 0 }
        return send(s.connectors[kind]!.map(c => ({ ...c, created_at, updated_at: created_at,
          ...(kind === 'webhook' ? { headers: { Authorization: '***' } } : {}),
          ...(kind === 'shell' ? { pass_stdin: false } : {}) })))
      }
      const noRows = s.connectors[kind]!.length === 0 || mode === 'qg-empty' || mode === 'qf-empty'
        || kind === 'xdrop' && ['qd-empty', 'qd-connectors-empty'].includes(mode)
      return send(noRows ? kind === 'xdrop' ? [] : null : s.connectors[kind]!.map(c =>
        kind === 'webhook' ? webhookView(c) : kind === 'shell' && mode !== 'attacks' && !mode.startsWith('qg')
          ? { ...c, pass_stdin: false } : c))
    }
    const connected = connectors(raw, method, body)
    if (connected) return connected
    if (path === '/api/responses') {
      if (method === 'GET') return send(empty ? null : nullableRows([...s.responses].sort((a, b) => a.id - b.id)
        .map(r => ({ ...r, action_count: s.actions.filter(a => a.response_id === r.id).length,
          bound_template_count: s.templates.filter(t => t.response_id === r.id).length }))))
      if (method === 'POST') {
        if (mode === 'qf-write-400') return fail('name is required')
        const id = s.sequences.response++
        s.responses.push({ id, name: body.name, description: body.description ?? '', enabled: true, created_at })
        return send({ id }, 201)
      }
    }
    const rm = /^\/api\/responses\/[^/]+$/.test(path), am = /^\/api\/actions\/[^/]+(?:\/preconditions)?$/.test(path)
    if (!rm && !am && !/^\/api\/responses\/[^/]+\/actions$/.test(path)) return
    if (rm) {
      const row = s.responses.find(r => r.id === id)
      if (method === 'GET') {
        if (!row) return fail('response not found', 404)
        if (mode === 'qf-detail-error') return fail('response detail unavailable', 500)
        return send({ response: { ...row, action_count: 0, bound_template_count: 0 },
          actions: s.actions.filter(a => a.response_id === id)
            .sort((a, b) => textOrder(a.trigger_phase, b.trigger_phase) || a.priority - b.priority) })
      }
      if (method === 'DELETE') {
        const template = [...s.templates].sort((a, b) => textOrder(a.name, b.name))
          .find(t => t.response_id === id)
        if (template) return fail(`response in use by template "${template.name}" (id=${template.id})`, 409)
        const rule = orderedRules(s).find(t => t.response_id === id)
        if (rule) return fail(`response in use by threshold rule id=${rule.id}`, 409)
        for (const action of s.actions.filter(a => a.response_id === id)) dropAction(action.id)
        s.responses = s.responses.filter(r => r.id !== id)
      }
      if (method === 'PUT') {
        if (!row) return fail('response not found', 404)
        if (body.name === '') return fail('name is required')
        Object.assign(row, body)
      }
      return send({ ok: true })
    }
    if (path.endsWith('/preconditions')) {
      if (method === 'GET') {
        reads.set(id, (reads.get(id) ?? 0) + 1)
        if (mode === 'qf-condition-fail' || mode === 'qf-reread-fail' && reads.get(id)! > 1) {
          return fail('preconditions unavailable', 500)
        }
        return send(s.conditions.get(id) ?? [])
      }
      if (mode === 'qf-second-fail') return fail('condition storage failed', 500)
      for (const c of body.preconditions ?? []) {
        const error = checkCondition(c)
        if (error) return fail(error)
      }
      const rows = []
      for (const c of body.preconditions ?? []) {
        const conditionID = s.sequences.condition++
        if (!s.actions.some(a => a.id === id)) return fail('referenced object not found')
        rows.push({ id: conditionID, action_id: id, attribute: c.attribute,
          operator: c.operator, value: c.value, created_at })
      }
      s.conditions.set(id, rows)
      return send({ ok: true })
    }
    let row = am ? s.actions.find(a => a.id === id) : undefined
    if (method === 'DELETE') {
      if (!row) return fail('action not found', 404)
      if (row?.auto_generated) return fail('auto-generated on_expired actions cannot be deleted directly'
        + ' — delete the on_detected action instead')
      if (row.paired_with) dropAction(row.paired_with)
      dropAction(id)
    } else {
      if (!row && method === 'PUT') return fail('action not found', 404)
      if (mode === 'qf-first-fail') return fail('action storage failed', 500)
      if (row?.auto_generated) return fail('auto-generated on_expired actions cannot be edited directly'
        + ' — edit the on_detected action instead')
      if (row && body.action_type !== row.action_type) {
        return fail('cannot change action_type via PUT — delete this action and create a new one instead')
      }
      const data = { ...row, ...body }
      if (!['webhook', 'shell', 'bgp', 'xdrop'].includes(data.action_type)) {
        return fail('action_type must be one of: xdrop, bgp, webhook, shell; got ' + JSON.stringify(data.action_type))
      }
      if (!['', 'once', 'periodic', 'retry_until_success'].includes(data.run_mode)) {
        return fail("run_mode must be one of: '', once, periodic, retry_until_success; got "
          + JSON.stringify(data.run_mode))
      }
      if (!['on_detected', 'on_expired'].includes(data.trigger_phase)) {
        return fail('trigger_phase must be on_detected or on_expired')
      }
      if (data.trigger_phase === 'on_expired' && ['xdrop', 'bgp'].includes(data.action_type)) {
        return fail('xDrop/BGP on_expired actions are auto-generated — '
          + (method === 'POST' ? 'create an' : 'edit the') + ' on_detected action instead')
      }
      if (data.trigger_phase === 'on_expired' && !['', 'once'].includes(data.run_mode)) {
        return fail('on_expired only supports run_mode=once')
      }
      if (['webhook', 'shell', 'bgp'].includes(data.action_type) && data.connector_id == null) {
        return fail(data.action_type + ' action requires connector_id')
      }
      if (data.action_type === 'bgp' && !data.bgp_route_map) {
        return fail('bgp action (on_detected) requires bgp_route_map')
      }
      if (data.bgp_route_map && !/^[A-Za-z0-9_.-]+$/.test(data.bgp_route_map)) {
        return fail("bgp_route_map may only contain letters, digits, '_', '-', '.'")
      }
      if (data.action_type === 'xdrop' && ['filter_l4', 'rate_limit'].includes(data.xdrop_action)) {
        if (!['dst_ip', 'src_ip', 'dst_port', 'src_port', 'protocol'].some(k => k in data.xdrop_custom_payload)) {
          return fail('xDrop filter/rate_limit action requires at least one match field (dst_ip, src_ip,'
            + ' dst_port, src_port, or protocol)')
        }
        if (data.xdrop_action === 'rate_limit' && !(data.xdrop_custom_payload.rate_limit > 0)) {
          return fail('xDrop rate_limit action requires a positive rate_limit value')
        }
      }
      if (data.bgp_withdraw_delay_minutes < 0 || data.bgp_withdraw_delay_minutes > 1440) {
        return fail('bgp_withdraw_delay_minutes must be between 0 and 1440')
      }
      if (data.action_type === 'xdrop' && !['filter_l4', 'rate_limit', 'unblock'].includes(data.xdrop_action)) {
        return fail(data.xdrop_action ? 'xdrop_action must be one of: filter_l4, rate_limit, unblock'
          : 'xdrop_action is required')
      }
      if (data.action_type === 'xdrop' && data.unblock_delay_minutes) {
        if (data.unblock_delay_minutes < 0 || data.unblock_delay_minutes > 1440) {
          return fail('unblock_delay_minutes must be between 0 and 1440')
        }
        if (data.trigger_phase !== 'on_detected') {
          return fail('unblock_delay_minutes is only valid for on_detected actions')
        }
        if (data.xdrop_action === 'unblock') {
          return fail('unblock_delay_minutes is only valid for filter_l4 or rate_limit actions')
        }
      }
      const vars = ['ip', 'dst_ip', 'prefix', 'prefix_len', 'attack_type', 'decoder', 'severity', 'peak_pps',
        'peak_bps', 'event', 'attack_id', 'started_at', 'duration', 'node_sources', 'reason_codes', 'top_src_ips',
        'top_src_ports', 'top_dst_ports', 'dominant_src_port', 'dominant_src_port_pct', 'dominant_dst_port',
        'dominant_dst_port_pct', 'src_ip', 'unique_src_ips', 'flow_summary_json']
      for (const [field, text] of [['xdrop_custom_payload', JSON.stringify(data.xdrop_custom_payload ?? null)],
        ['shell_extra_args', data.shell_extra_args ?? '']]) {
        for (const match of text.matchAll(/(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}/g)) {
          if (!vars.includes(match[1])) return fail(`${field} contains unknown template variable {${match[1]}}`)
        }
      }
      const responseID = row?.response_id ?? id
      if (['xdrop', 'bgp'].includes(data.action_type)) {
        const global = s.prefixes.filter(p => p.prefix === '0.0.0.0/0')
        if (s.templates.some(t => t.response_id === responseID && global.some(p => p.threshold_template_id === t.id))
          || s.rules.some(r => r.response_id === responseID && global.some(p =>
            p.id === r.prefix_id || r.template_id !== null && p.threshold_template_id === r.template_id))) {
          return fail('This response is referenced by global prefix (0.0.0.0/0) rules — cannot add xDrop/BGP action')
        }
        if (s.rules.some(r => r.direction === 'sends' && r.response_id === responseID)) {
          return fail('This response is referenced by outbound (sends) rules — cannot add xDrop/BGP action')
        }
      }
      if (!row) {
        const newID = s.sequences.action++
        if (!s.responses.some(r => r.id === responseID)) return fail('referenced object not found')
        row = s.action(newID, body.action_type, { response_id: id, period_seconds: 0, priority: 0 })
        s.actions.push(row)
      }
      const newID = row.id
      const oldPeriod = row.period_seconds
      Object.assign(row, body)
      if (body.period_seconds === null) row.period_seconds = oldPeriod
      row.execution_policy = row.run_mode === 'periodic' ? 'periodic'
        : row.run_mode === 'retry_until_success' ? 'retry_until_success'
          : row.trigger_phase === 'on_expired' && row.run_mode === 'once' ? 'once_on_exit' : 'once_on_enter'
      if (row.action_type !== 'xdrop') row[row.action_type + '_connector_id'] = row.connector_id
      enrich(row)
      if (mode === 'qf-third-fail' && method === 'PUT' && body.enabled === true) {
        return fail('sync paired action: rollback incomplete: parent row', 500)
      }
      if (['xdrop', 'bgp'].includes(row.action_type) && row.trigger_phase === 'on_detected') {
        let child = s.actions.find(a => a.id === row!.paired_with)
        if (!child) {
          child = s.action(s.sequences.action++, row.action_type)
          s.actions.push(child)
          row.paired_with = child.id
        }
        Object.assign(child, row, { id: child.id, paired_with: undefined, auto_generated: true,
          trigger_phase: 'on_expired', execution_policy: 'once_on_exit', run_mode: 'once', period_seconds: 0,
          execution: 'automatic', preconditions: null, xdrop_custom_payload: null,
          xdrop_action: row.action_type === 'xdrop' ? 'unblock' : '', xdrop_fields: null, xdrop_rate_limit: null })
      }
      if (method === 'POST') return send({ id: newID }, 201)
    }
    return send({ ok: true })
  }
}

function webhookView(row: any) {
  const headers = row.headers && typeof row.headers === 'object' && !Array.isArray(row.headers)
    && Object.values(row.headers).every(v => typeof v === 'string')
    ? Object.fromEntries(Object.keys(row.headers).map(key => [key, '******'])) : null
  return { ...row, headers }
}
export function connectorSession(mode: string, now: number, s = fixtureState(now)) {
  const send = (body: any, status = 200): MockResult => ({ status, body: JSON.parse(JSON.stringify(body)) })
  const fail = (error: string, status = 400) => send({ error }, status)
  const sequences = Object.fromEntries(Object.entries(s.connectors).map(([kind, rows]) =>
    [kind, Math.max(0, ...rows.map(row => row.id)) + 1]))
  const at = new Date(now).toISOString()
  for (const row of [...(qdReply('/api/active-actions/bgp', mode, now)!.body ?? []),
    ...qdReply('/api/active-actions/bgp/dismissed-orphans', mode, now)!.body]) {
    if (row.announcement_id) s.announcements.set(row.announcement_id, row.status)
  }
  return (raw: string, method = 'GET', body: any = {}): MockResult | undefined => {
    const path = new URL(raw, 'http://localhost').pathname
    if (path === '/api/webhooks' && method === 'GET') {
      if (mode === 'qg-legacy-fail') return fail('legacy webhook list unavailable', 500)
      return send(mode === 'qg-empty' ? null : [
        { id: 1, url: 'http://192.0.2.1/legacy', events: ['attack_start', 'attack_update', 'attack_end'],
          enabled: true, headers: { Authorization: '******' }, created_at: at },
        { id: 2, url: 'http://192.0.2.2/legacy', events: ['attack_start', 'attack_end'],
          enabled: false, headers: null, created_at: at },
      ])
    }
    const match = /^\/api\/settings\/(bgp|xdrop|webhook|shell)-connectors(?:\/(\d+)(?:\/(test|routes))?)?$/.exec(path)
    if (!match) return
    const kind = match[1]!, id = Number(match[2]), operation = match[3]
    const rows = s.connectors[kind]!
    const old = rows.find(c => c.id === id)
    if (operation) {
      if (!old) return fail(kind + ' connector not found', 404)
      if (operation === 'routes' && kind === 'bgp' && method === 'GET') return mode === 'qg-test-fail'
        ? fail('vtysh failed: ipv4=mock unavailable ipv6=mock unavailable', 502)
        : send({ output: 'BGP table version 1\n*> 192.0.2.0/24  0.0.0.0  0  i' })
      if (operation !== 'test' || method !== 'POST' || kind === 'shell') return fail('not found', 404)
      if (kind === 'bgp') return mode === 'qg-test-fail' ? fail('vtysh failed: mock unavailable', 502)
        : send({ ok: true, output: 'IPv4 Unicast Summary\nRouter identifier 192.0.2.1, local AS 64512' })
      if (kind === 'xdrop') return mode === 'qg-test-fail'
        ? send({ success: false, error: 'health check failed: mock unavailable' })
        : send({ success: true, status_code: 200, kind: 'machine', name: 'qg-fixture' })
      return mode === 'qg-test-fail' ? send(id === 1 ? { success: false, status_code: 503 }
        : { success: false, error: 'connection refused' })
        : send({ success: true, status_code: 204 })
    }
    if (method === 'GET' && match[2]) return old
      ? send(kind === 'webhook' ? webhookView(old) : old) : fail(kind + ' connector not found', 404)
    if (method === 'DELETE' && match[2]) {
      const count = s.actions.filter(a => kind === 'xdrop' ? a.target_node_ids?.includes(id)
        : a[kind + '_connector_id'] === id).length
      if (count) return fail(`${kind === 'bgp' ? '' : kind === 'xdrop' ? 'xDrop ' : kind + ' '}`
        + `connector in use by ${count} action(s)`, 409)
      const live = kind === 'bgp' && id === 1 ? [...s.announcements.values()].filter(status =>
        ['announcing', 'active', 'delayed', 'withdrawing', 'failed', 'orphan'].includes(status)).length : 0
      if (live) return fail(`connector still has ${live} announcements in FRR-relevant states`, 409)
      s.connectors[kind] = rows.filter(c => c.id !== id)
      return send({ ok: true })
    }
    const create = method === 'POST' && !match[2]
    if (!create && !(method === 'PUT' && match[2])) return
    if (!create && !old) return fail(kind + ' connector not found', 404)
    let next: any = create ? { name: '', enabled: true } : { ...old }
    const fields: Record<string, string[]> = {
      bgp: ['name', 'bgp_asn', 'vtysh_path', 'description', 'vendor', 'flowspec_enabled', 'enabled'],
      xdrop: ['name', 'api_url', 'timeout_ms', 'enabled'],
      webhook: ['name', 'url', 'method', 'headers', 'timeout_ms', 'global', 'enabled'],
      shell: ['name', 'command', 'default_args', 'timeout_ms', 'enabled'],
    }
    for (const field of fields[kind]!) if (Object.hasOwn(body, field)) {
      if (kind === 'bgp' && !create && ['name', 'vtysh_path'].includes(field) && !body[field]) continue
      next[field] = body[field]
    }
    if (!next.name) return fail('name is required')
    if (kind === 'bgp') {
      if (next.bgp_asn == null) return fail('bgp_asn is required')
      if (next.bgp_asn < 1 || next.bgp_asn > 4294967295) {
        return fail(`bgp_asn must be between 1 and 4294967295, got ${next.bgp_asn}`)
      }
      next.vtysh_path ||= '/usr/bin/vtysh'
      next.address_family ??= 'auto'
      next.description ??= ''
      const aliases: Record<string, string> = { '': 'frr', frr: 'frr', cisco: 'cisco_xr', cisco_xr: 'cisco_xr',
        ios_xr: 'cisco_xr', juniper: 'juniper', junos: 'juniper', arista: 'arista', eos: 'arista' }
      const vendor = aliases[String(next.vendor ?? '').toLowerCase().trim()]
      if (!vendor) return fail(`flowspec: unsupported vendor "${next.vendor}" (want frr, cisco_xr, juniper, arista)`)
      next.vendor = vendor
      next.flowspec_enabled ??= false
      if (vendor !== 'frr' && !next.flowspec_enabled) {
        return fail(`vendor "${vendor}" is export-only: set flowspec_enabled=true `
          + '(RTBH cannot be applied to a non-FRR speaker)')
      }
    }
    if (kind === 'xdrop') {
      next.api_url = (next.api_url ?? '').replace(/\/+$/, '')
      if (!next.api_url) return fail('api_url is required')
      if (create && !body.api_key) return fail('api_key is required')
      if (!create && next.api_url !== old.api_url && !body.api_key) {
        return fail('api_url changed: api_key must be re-entered')
      }
      if (body.api_key) next.api_key = body.api_key.length <= 4 ? '***' : '***' + body.api_key.slice(-4)
    }
    if (kind === 'webhook') {
      if (!next.url) return fail('url is required')
      next.method = (next.method || 'POST').trim().toUpperCase()
      if (!['POST', 'PUT', 'PATCH'].includes(next.method)) {
        return fail(`method must be one of: POST, PUT, PATCH; got ${JSON.stringify(body.method)}`)
      }
      if (next.timeout_ms < 0) return fail(`timeout_ms must be >= 0, got ${next.timeout_ms}`)
      next.headers ??= null
      next.global ??= false
      if (next.headers !== null && (Array.isArray(next.headers) || typeof next.headers !== 'object'
        || Object.values(next.headers).some(v => typeof v !== 'string'))) {
        return fail('headers must be a JSON object with string values')
      }
      if (!create) {
        if (!Object.hasOwn(body, 'headers') && next.url !== old.url && Object.keys(old.headers ?? {}).length) {
          return fail('url changed: header values must be re-entered')
        }
        if (next.headers) {
          next.headers = { ...next.headers }
          for (const [key, value] of Object.entries(next.headers)) if (value === '******') {
            if (!Object.hasOwn(old.headers ?? {}, key)) {
              return fail(`header ${key}: masked value has no stored original`)
            }
            if (next.url !== old.url) return fail('url changed: header values must be re-entered')
            next.headers[key] = old.headers[key]
          }
        }
      }
    }
    if (kind === 'shell') {
      if (!next.command) return fail('command is required')
      if (!next.command.startsWith('/')) return fail('command must be an absolute path (start with /)')
      next.default_args ??= ''
      next.pass_stdin ??= false
      const vars = ['ip', 'dst_ip', 'prefix', 'prefix_len', 'attack_type', 'decoder', 'severity', 'peak_pps',
        'peak_bps', 'event', 'attack_id', 'started_at', 'duration', 'node_sources', 'reason_codes', 'top_src_ips',
        'top_src_ports', 'top_dst_ports', 'dominant_src_port', 'dominant_src_port_pct', 'dominant_dst_port',
        'dominant_dst_port_pct', 'src_ip', 'unique_src_ips', 'flow_summary_json']
      for (const match of next.default_args.matchAll(/(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}/g)) {
        if (!vars.includes(match[1])) return fail(`default_args contains unknown template variable {${match[1]}}`)
      }
    }
    if (create) {
      next.id = sequences[kind]!++
      if (kind !== 'bgp') {
        next.enabled = true
        next.timeout_ms ||= kind === 'shell' ? 30000 : 10000
      }
      next.created_at = at
    }
    if (rows.some(c => c.id !== next.id && c.name === next.name)) {
      return fail(kind === 'bgp' ? 'bgp connector already exists' : 'already exists', 409)
    }
    next.updated_at = at
    if (create) rows.push(next)
    else s.connectors[kind] = rows.map(c => c.id === id ? next : c)
    return create ? send({ id: next.id }, 201) : send({ ok: true })
  }
}

// Flow configuration owns new endpoints; legacy list fixtures retain their initial bytes.
function flowSession(mode: string, now: number) {
  const qh = mode.startsWith('qh')
  const iso = (offset = 0) => new Date(now + offset).toISOString()
  const initial = mockReply('/api/nodes', qh ? 'normal' : mode, now).body ?? []
  const nodes = new Map<string, any>(initial.map((n: any) => [n.id, n]))
  if (qh) nodes.set('flow-d', { ...nodes.get('flow-b'), id: 'flow-d', description: 'Flow D' })
  if (qh) for (const row of nodes.values()) if (row.mode === 'flow') {
    row.online = mode !== 'qh-offline' && mode !== 'qh-stale'
  }
  if (mode === 'qh-no-flow') for (const [id, row] of nodes) if (row.mode === 'flow') nodes.delete(id)
  const managed = new Set(qh ? [...nodes.keys()] : [])
  const listeners: any[] = ['qh-empty', 'qd-empty', 'null'].includes(mode) ? [] : [{ id: 1, node_id: 'flow-b',
    listen_address: '0.0.0.0:6343', protocol_mode: 'sflow', enabled: true,
    description: 'Flow input', created_at: iso(-86400000) }]
  if (qh && mode !== 'qh-empty') listeners.push(
    { id: 2, node_id: 'flow-b', listen_address: ':2055', protocol_mode: 'auto', enabled: false,
      description: 'Backup listener', created_at: iso(-86400000) },
    { id: 3, node_id: 'flow-d', listen_address: ':4739', protocol_mode: 'ipfix', enabled: true,
      description: 'Flow D input', created_at: iso(-86400000) },
  )
  const sources: any[] = ['qh-empty', 'qd-empty', 'null'].includes(mode) ? [] : [
    { id: 1, listener_id: 1, name: 'Router IPv4', device_ip: '192.0.2.1/32', sample_mode: 'force',
      sample_rate: 1000, description: 'Core exporter', enabled: true, created_at: iso(-86400000) },
    { id: 2, listener_id: 1, name: 'Router IPv6', device_ip: '2001:db8::1/128', sample_mode: 'auto',
      sample_rate: 0, description: 'IPv6 exporter', enabled: false, created_at: iso(-86400000) },
  ]
  if (qh && mode !== 'qh-empty') sources.push({ id: 3, listener_id: 1, name: 'Standby exporter',
    device_ip: '198.51.100.2/32', sample_mode: 'none', sample_rate: 1, description: '',
    enabled: true, created_at: iso(-86400000) })
  let listenerSequence = Math.max(0, ...listeners.map(r => r.id))
  let sourceSequence = Math.max(0, ...sources.map(r => r.id))
  const send = (body: any, status = 200): MockResult => ({ status, body: JSON.parse(JSON.stringify(body)) })
  const fail = (error: string, status = 400) => send({ error }, status)
  const removeListener = (id: number) => {
    const index = listeners.findIndex(l => l.id === id)
    if (index >= 0) {
      managed.add(listeners[index].node_id)
      listeners.splice(index, 1)
    }
    for (let i = sources.length - 1; i >= 0; i--) if (sources[i].listener_id === id) sources.splice(i, 1)
  }
  return (raw: string, method = 'GET', body: any = {}): MockResult | undefined => {
    const url = new URL(raw, 'http://localhost'), path = url.pathname
    if (path === '/api/nodes' && method === 'POST') {
      nodes.set(body.id, { ...body })
      managed.add(body.id)
      return
    }
    if (path.startsWith('/api/nodes/') && method === 'DELETE') {
      const node = decodeURIComponent(path.slice('/api/nodes/'.length))
      nodes.delete(node)
      managed.add(node)
      for (const row of [...listeners]) if (row.node_id === node) removeListener(row.id)
      return
    }
    if (qh && path === '/api/nodes' && method === 'GET') return send([...nodes.values()])
    if (qh && /^\/api\/nodes\/[^/]+\/status$/.test(path) && method === 'GET') {
      if (mode === 'qh-status-fail') return fail('flow status unavailable', 500)
      const id = decodeURIComponent(path.split('/')[3]!)
      if (!nodes.has(id)) return fail('node not found', 404)
      const status = qdReply(raw, 'normal', now)!.body
      const offline = mode === 'qh-offline' || mode === 'qh-stale'
      return send({ ...status, mode: 'flow', online: !offline,
        ...(mode === 'qh-offline' ? { uptime_seconds: undefined, connected_at: undefined }
          : { uptime_seconds: 274320 }),
        flow_metrics: { decode_errors: 3, unknown_exporter: 2, template_misses: 1, updated_at: iso(-5000) },
        listener_statuses: [{ listen_addr: id === 'flow-d' ? ':4739' : '0.0.0.0:6343',
          protocol_mode: id === 'flow-d' ? 'ipfix' : 'sflow', records_decoded: 18432117,
          decode_errors: 3, unknown_exporter: 2, template_misses: 1, source_count: 3 }],
        source_statuses: [{ device_ip: '192.0.2.1', active: true, last_seen_at: Math.floor(now / 1000),
          records_received: 100 }, { device_ip: '2001:db8::1', active: false,
          last_seen_at: Math.floor(now / 1000) - 90, records_received: 0 }],
      })
    }
    const match = /^\/api\/flow-(listeners|sources)(?:\/(\d+))?$/.exec(path)
    if (!match) return
    const isListener = match[1] === 'listeners', id = Number(match[2])
    const rows = isListener ? listeners : sources, old = rows.find(r => r.id === id)
    const notFound = isListener ? 'flow listener not found' : 'flow source not found'
    if (method === 'GET') {
      if (match[2]) {
        if (!old) return fail(notFound, 404)
        if (isListener && mode === 'qh-detail-fail' && id === 1) return fail('flow sources unavailable', 500)
        return send(isListener ? { listener: old, sources: sources.filter(s => s.listener_id === id) } : old)
      }
      if (isListener) {
        const node = url.searchParams.get('node_id')
        if (!node) return qh ? fail('node_id is required') : qdReply(raw, mode, now)
        if (!managed.has(node)) return qdReply(raw, mode, now)
        return send(listeners.filter(l => l.node_id === node))
      }
      const listener = url.searchParams.get('listener_id') ?? ''
      if (!/^[+-]?\d+$/.test(listener)) return fail('listener_id is required')
      return send(sources.filter(s => s.listener_id === Number(listener)))
    }
    if (method === 'DELETE') {
      if (isListener) removeListener(id)
      else if (old) sources.splice(sources.indexOf(old), 1)
      return send({ ok: true })
    }
    if (method !== 'POST' && method !== 'PUT') return
    if (method === 'PUT' && !old) return fail(notFound, 404)
    const creating = method === 'POST'
    const row = isListener ? {
      node_id: creating ? body.node_id ?? '' : old.node_id,
      listen_address: body.listen_address ?? '', protocol_mode: body.protocol_mode ?? '',
      description: body.description ?? '', enabled: body.enabled ?? old?.enabled ?? false,
    } : {
      listener_id: creating ? body.listener_id ?? 0 : old.listener_id,
      name: body.name ?? '', device_ip: body.device_ip ?? '', sample_mode: body.sample_mode ?? '',
      sample_rate: body.sample_rate ?? 0, description: body.description ?? '',
      enabled: body.enabled ?? old?.enabled ?? false,
    }
    let normalized: string | null = null
    if (isListener) {
      if (creating && !row.protocol_mode) row.protocol_mode = 'auto'
      if (!row.node_id) return fail('node_id is required')
      if (!row.listen_address) return fail('listen_address is required')
      const address = row.listen_address as string
      const hostPort = /^(?:\[[^\[\]]*\]|[^:\[\]]*):([^:\[\]]*)$/.exec(address)
      if (!hostPort && !address.startsWith(':')) return fail('listen_address must be :port or host:port format')
      const port = hostPort ? hostPort[1]! : address.slice(1)
      if (!/^[+-]?\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
        return fail('listen_address port must be 1-65535')
      }
      if (!['auto', 'sflow', 'netflow', 'ipfix'].includes(row.protocol_mode!)) {
        return fail("protocol_mode must be 'auto', 'sflow', 'netflow', or 'ipfix'")
      }
      if (creating) {
        const node = nodes.get(row.node_id!)
        if (!node) return fail('node_id not found: ' + row.node_id)
        if (node.mode !== 'flow') return fail(
          `node ${row.node_id} is mode=${node.mode}, flow listeners require mode=flow`)
      }
    } else {
      if (creating && !row.sample_mode) row.sample_mode = 'auto'
      if (!row.name) return fail('name is required')
      if (!row.device_ip) return fail('device_ip is required')
      normalized = inetText(row.device_ip)
      if (normalized === null) return fail('device_ip must be a valid IPv4 or IPv6 address')
      if (!['auto', 'force', 'none'].includes(row.sample_mode!)) {
        return fail("sample_mode must be 'auto', 'force', or 'none'")
      }
      if (row.sample_mode === 'force' && row.sample_rate! <= 0) {
        return fail("sample_rate must be > 0 when sample_mode is 'force'")
      }
      if (creating && !listeners.some(l => l.id === row.listener_id)) return fail('listener_id not found')
      if (row.sample_rate! < -2147483648 || row.sample_rate! > 2147483647) return fail('database error', 500)
    }
    const newID = creating ? (isListener ? ++listenerSequence : ++sourceSequence) : id
    const duplicate = rows.some(r => r.id !== (creating ? 0 : id) && (isListener
      ? r.node_id === row.node_id && r.listen_address === row.listen_address
      : r.listener_id === row.listener_id && r.device_ip === normalized))
    if (duplicate) return fail('already exists', 409)
    if (!isListener) row.device_ip = normalized!
    else managed.add(row.node_id!)
    if (creating) rows.push({ ...row, id: newID, enabled: true, created_at: iso() })
    else Object.assign(old, row)
    return send(creating ? { id: newID } : { ok: true }, creating ? 201 : 200)
  }
}
