// @ts-expect-error Node's offline scanner uses explicit TypeScript extensions.
import { createData, day, session, traffic, type Dataset, type Row } from './data.ts'
export type Reply = { status: number; body: any }
export type Server = (raw: string, method?: string, body?: any) => Reply

function address(raw: string): { value: bigint; bits: number; length: number } {
  const segments = raw.split('/'), [input = '', suffix] = segments
  let ip = input
  const bits = ip.includes(':') ? 128 : 32, length = suffix === undefined ? bits : Number(suffix)
  if (segments.length > 2 || suffix !== undefined && !/^\d+$/.test(suffix)
    || !Number.isInteger(length) || length < 0 || length > bits) throw Error('address')
  const ipv4 = (value: string) => {
    const parts = value.split('.')
    if (parts.length !== 4 || parts.some(p => !/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255)) {
      throw Error('address')
    }
    return parts.map(Number)
  }
  if (bits === 32) return { value: ipv4(ip).reduce((n, p) => (n << 8n) + BigInt(p), 0n), bits, length }
  if (ip.includes('.')) {
    const at = ip.lastIndexOf(':'), tail = ipv4(ip.slice(at + 1))
    ip = ip.slice(0, at + 1) + ((tail[0]! << 8) + tail[1]!).toString(16)
      + ':' + ((tail[2]! << 8) + tail[3]!).toString(16)
  }
  const doubleColon = ':'.repeat(2)
  const halves = ip.split(doubleColon), [left = '', right = ''] = halves
  const a = left ? left.split(':') : [], b = right ? right.split(':') : []
  if (halves.length > 2 || halves.length === 2 && a.length + b.length >= 8) throw Error('address')
  const parts = halves.length === 2 ? [...a, ...Array(8 - a.length - b.length).fill('0'), ...b] : a
  if (parts.length !== 8 || parts.some(p => !/^[\da-f]{1,4}$/i.test(p))) throw Error('address')
  return { value: parts.reduce((n, p) => (n << 16n) + BigInt(parseInt(p, 16)), 0n),
    bits, length }
}
export function contains(network: string, target: string) {
  try {
    const n = address(network), t = address(target)
    if (n.bits !== t.bits || n.length < 0 || n.length > n.bits || t.length < n.length) return false
    const shift = BigInt(n.bits - n.length)
    return n.value >> shift === t.value >> shift
  } catch { return false }
}
export function createServer(data: Dataset = createData()): Server {
  // All replies are detached snapshots. Requests never mutate the dataset.
  const send = (body: any, status = 200): Reply => ({ status, body: JSON.parse(JSON.stringify(body)) })
  const missing = () => send({ error: 'not found' }, 404)
  const timer = (a: Row) => ({ state: 'active', expires_in: 0,
    threshold_value: a.decoder_family === 'tcp_syn' ? 600000 : 1200000, threshold_unit: 'pps' })
  const nodeShares: Record<string, number> = { 'probe-a': .4, 'probe-b': .35, 'flow-c': .25 }
  const prefixShares: Record<number, number> = { 1: .56, 2: .24, 3: .28, 4: .16 }
  // All views sample the same clock-based series, including the attack's historical interval.
  function sample(time: number, direction = 'receives', node = '', prefix = '', target = ''): Row {
    if (direction === 'both') {
      const incoming = sample(time, 'receives', node, prefix, target)
      const outgoing = sample(time, 'sends', node, prefix, target)
      for (const k of Object.keys(incoming)) {
        if (typeof incoming[k] === 'number') incoming[k] += outgoing[k]
        else if (k.startsWith('extra_decoder_')) for (const decoder of Object.keys(incoming[k])) {
          incoming[k][decoder] += outgoing[k][decoder]
        }
      }
      return incoming
    }
    const selected = data.prefixes.find(p => p.prefix === prefix)
    const factor = (node ? nodeShares[node] ?? 0 : 1) * (selected ? prefixShares[selected.id]! : target ? .02 : 1)
    const row = traffic(time, factor * (direction === 'sends' ? .42 : 1))
    if (direction === 'sends') return row
    for (const a of data.attacks) {
      const start = Date.parse(a.started_at), end = a.ended_at ? Date.parse(a.ended_at) : Infinity
      if (time < start || time > end || prefix && !contains(prefix, a.dst_ip)
        || target && !contains(target, a.dst_ip) || node && !a.node_sources.includes(node)) continue
      const age = (time - start) / 1000
      const ramp = Math.min(1, age / 30)
      const wave = .9 + .1 * Math.sin(age / 75)
      const mitigated = !a.ended_at && age >= 60 ? a.decoder_family === 'udp' ? .35 : .75 : 1
      const share = node ? nodeShares[node]! / a.node_sources.reduce((sum: number, id: string) =>
        sum + nodeShares[id]!, 0) : 1
      const pps = Math.round(a.peak_pps * ramp * wave * mitigated * share)
      const bps = Math.round(a.peak_bps * ramp * wave * mitigated * share)
      row.pps += pps; row.bps += bps
      row[a.decoder_family + '_pps'] += pps; row[a.decoder_family + '_bps'] += bps
      if (a.decoder_family === 'tcp_syn') { row.tcp_pps += pps; row.tcp_bps += bps }
    }
    return row
  }
  const current = (a: Row) => {
    const row = sample(data.now, a.direction, '', '', a.dst_ip)
    return { pps: row.pps, bps: row.bps }
  }
  const rowsFor = (rows: Row[], a: Row) => rows.filter(r => r.attack_id === a.id)
  const attachment = (r: Row, a: Row): Row => r.attached_attacks.find((att: Row) => att.attack_id === a.id)
  const announcement = (r: Row) => {
    const delay = Math.max(...r.attached_attacks.map((att: Row) => att.delay_minutes))
    return { gen: 1, id: r.announcement_id, prefix: r.prefix, route_map: r.route_map,
      connector_id: r.connector_id, first_action_id: r.action_id, status: r.status,
      refcount: r.attached_attacks.length, announced_at: r.created_at, created_at: r.created_at,
      delay_minutes: delay, ...(r.status === 'delayed' ? {
        delay_started_at: new Date(Date.parse(r.scheduled_for) - delay * 60000).toISOString(),
      } : {}) }
  }
  const handle: Server = (raw, method = 'GET', body) => {
    if (typeof raw !== 'string' || typeof method !== 'string') return send({ error: 'invalid request' }, 400)
    const url = new URL(raw, 'https://example.com'), path = url.pathname, q = url.searchParams
    try { decodeURIComponent(path) } catch { return missing() }
    method = method.toUpperCase()
    if (method === 'POST' && path === '/api/login') {
      if (typeof body?.username === 'string' && body.username.length
        && typeof body?.password === 'string' && body.password.length) return send(session)
      return send({ error: 'username and password required' }, 400)
    }
    if (method !== 'GET') return send({ error: 'admin role required' }, 403)
    const number = (key: string, fallback: number) => q.has(key) ? Number(q.get(key)) : fallback
    const page = (rows: Row[]) => rows.slice(Math.max(0, number('offset', 0)),
      Math.max(0, number('offset', 0)) + Math.max(0, Math.min(1000, number('limit', 100))))
    const active = data.attacks.filter(a => !a.ended_at)
    if (path === '/api/stats/summary') return send({ active_attacks: active.length, total_nodes: 3,
      online_nodes: 3, total_prefixes: data.prefixes.length, total_thresholds: data.rules.length,
      tracker_count: active.length, attacks_created: data.attacks.length, attacks_suppressed: 0,
      attacks_evicted: 0, action_mode: 'auto' })
    const direction = q.get('direction') || 'receives'
    if (path === '/api/stats/overview') {
      const node = q.get('node_id') || '', nodes = data.nodes.filter(n => !node || n.id === node)
      const parents = data.prefixes.filter(p => !p.parent_id)
      const top = nodes.length ? parents.map((p): Row => ({ prefix: p.prefix,
        ...sample(data.now, direction, node, p.prefix),
        nodes: nodes.map(n => ({ id: n.id, mode: n.mode })) })).sort((a, b) => b.pps - a.pps) : []
      const totals = sample(data.now, direction, node)
      return send({ total_pps: totals.pps, total_bps: totals.bps, node_count: nodes.length,
        active_prefixes: nodes.length ? data.prefixes.length : 0, top_prefixes: page(top),
        nodes: nodes.map(n => ({ id: n.id, ...sample(data.now, direction, n.id) })) })
    }
    if (path === '/api/stats/timeseries' || path === '/api/stats/total-timeseries') {
      const prefix = q.get('prefix'), target = q.get('dst_ip'), node = q.get('node_id')
      if (prefix && !data.prefixes.some(p => p.prefix === prefix)
        || target && !data.prefixes.some(p => contains(p.prefix, target))
        || node && !data.nodes.some(n => n.id === node)) return send([])
      const start = q.has('from') ? Date.parse(q.get('from')!) : data.now - 3600000
      const end = q.has('to') ? Date.parse(q.get('to')!) : data.now
      if (!Number.isFinite(start + end) || end < start) return send({ error: 'invalid time range' }, 400)
      const resolution = q.get('resolution') ?? '5min'
      if (target && !['5s', '5min'].includes(resolution)) {
        return send({ error: "dst_ip resolution must be '5s' or '5min'" }, 400)
      }
      // Go accepts unknown resolutions: recent raw data uses 5s; the healthy older cagg path uses 5min.
      const specs: Record<string, [number, number]> = {
        '5s': [5000, 7200], '5min': [300000, 2000], '1h': [3600000, 1000],
      }
      const spec = Object.hasOwn(specs, resolution) ? specs[resolution] : undefined
      const [grain, limit] = spec ?? [data.now - start > 90 * 60000 ? 300000 : 5000, 1000]
      const first = Math.ceil(start / grain) * grain
      // The store's ORDER BY bucket ASC LIMIT retains the earliest buckets in the requested window.
      const count = Math.min(limit, Math.max(0, Math.floor((end - first) / grain) + 1))
      return send(Array.from({ length: count },
        (_, i) => sample(first + i * grain, direction, node || '', prefix || '', target || '')))
    }
    if (path === '/api/attacks/active') return send({ attacks: page(active), active_count: active.length,
      returned: page(active).length, tracker_count: active.length,
      timers: Object.fromEntries(page(active).map(a => [a.id, timer(a)])),
      current: Object.fromEntries(page(active).map(a => [a.id, current(a)])) })
    if (path === '/api/attacks') {
      // Go strconv.Atoi with the error ignored: int64 values, saturated on overflow, 0 when not a number.
      const atoi = (key: string, fallback: bigint) => {
        const raw = q.get(key)
        if (!raw) return fallback
        if (!/^[+-]?\d+$/.test(raw)) return 0n
        const value = BigInt(raw), max = 2n ** 63n - 1n, min = -(2n ** 63n)
        return value > max ? max : value < min ? min : value
      }
      const requested = atoi('limit', 50n), limit = requested > 200n ? 200 : requested > 0n ? Number(requested) : 100
      const offset = atoi('offset', 0n), from = Date.parse(q.get('from')!), to = Date.parse(q.get('to')!)
      // PostgreSQL rejects a negative OFFSET with 2201X, which the router maps to 400 invalid input.
      if (offset < 0n) return send({ error: 'invalid input' }, 400)
      const rows = data.attacks.filter(a => (q.get('status') === 'active' ? !a.ended_at
        : q.get('status') === 'expired' ? !!a.ended_at : true)
        && (!q.get('prefix_id') || BigInt(a.prefix_id) === atoi('prefix_id', 0n))
        && (!q.get('direction') || a.direction === q.get('direction'))
        && (!q.get('dst_ip') || contains(q.get('dst_ip')!, a.dst_ip))
        && (!q.get('ended_after') || !a.ended_at || Date.parse(a.ended_at) >= Date.parse(q.get('ended_after')!))
        && (!Number.isFinite(from) || Date.parse(a.started_at) >= from)
        && (!Number.isFinite(to) || Date.parse(a.started_at) <= to))
      rows.sort((a, b) => (q.get('sort') === 'peak_pps' ? b.peak_pps - a.peak_pps : 0)
        || Date.parse(b.started_at) - Date.parse(a.started_at) || b.id - a.id)
      const start = offset >= BigInt(rows.length) ? rows.length : Number(offset)
      return send({ attacks: rows.slice(start, start + limit), total: rows.length })
    }
    if (path === '/api/attacks/mitigation-brief') {
      const ids = q.has('ids') ? q.get('ids')!.split(',').map(Number) : active.map(a => a.id)
      return send(Object.fromEntries(data.attacks.filter(a => ids.includes(a.id)).map(a => [a.id, {
        xdrop_rules: rowsFor(data.xdrop, a), bgp: rowsFor(data.bgp, a).map(r => ({
          prefix: r.prefix, route_map: r.route_map, status: r.status,
          attached_at: attachment(r, a).attached_at, delay_minutes: attachment(r, a).delay_minutes,
          ...(attachment(r, a).detached_at ? { detached_at: attachment(r, a).detached_at } : {}),
        })),
      }])))
    }
    const attackPath = /^\/api\/attacks\/(\d+)(?:\/(action-log|sensor-logs|mitigation-summary))?$/.exec(path)
    if (attackPath) {
      const a = data.attacks.find(a => a.id === Number(attackPath[1]))
      if (!a) return missing()
      const logs = rowsFor(data.executions, a)
      if (attackPath[2] === 'action-log') return send(logs)
      if (attackPath[2] === 'sensor-logs') {
        const end = a.ended_at ? Date.parse(a.ended_at) : data.now
        return send({ total: 8, expired: false, window: 'full', flows: Array.from({ length: 8 }, (_, i) => ({
          time: new Date(end - (i + 1) * 5000).toISOString(), node_id: 'flow-c',
          prefix: data.prefixes.find(p => p.id === a.prefix_id)!.prefix, src_ip: '192.0.2.' + (10 + i),
          dst_ip: a.dst_ip.split('/')[0], src_port: a.decoder_family === 'udp' ? 53 : 49152 + i,
          dst_port: a.decoder_family === 'tcp_syn' ? 53 : 443,
          protocol: a.decoder_family === 'udp' ? 17 : a.decoder_family === 'tcp_syn' ? 6 : 58,
          tcp_flags: a.decoder_family === 'tcp_syn' ? 2 : 0, packets: 18000 + i * 2100, bytes: (18000 + i * 2100) * 600,
        })) })
      }
      if (attackPath[2] === 'mitigation-summary') return send({ executions: logs, xdrop_rules: rowsFor(data.xdrop, a),
        bgp_announcements: rowsFor(data.bgp, a).map(r => ({ announcement: announcement(r),
          attached_at: attachment(r, a).attached_at, detached_at: attachment(r, a).detached_at ?? null,
          attack_delay_minutes: attachment(r, a).delay_minutes, attack_action_id: r.action_id })),
        summary: { total_evaluated: logs.length, success: logs.filter(l => l.status === 'success').length,
          failed: 0, skipped: 0 } })
      return send({ attack: a, actions_log: logs, ...(!a.ended_at ? { timer: timer(a), current: current(a) } : {}) })
    }
    if (path === '/api/active-actions/xdrop') return send(data.xdrop)
    if (path === '/api/active-actions/bgp') return send(data.bgp)
    if (path === '/api/active-actions/xdrop/delivery') {
      const rule = data.xdrop.find(r => (!q.has('rule_id') || r.external_rule_id === q.get('rule_id'))
        && (!q.has('connector_id') || r.connector_id === number('connector_id', 1)))
      return send(rule ? { rule_id: rule.external_rule_id, target_gen: 24, epoch: 'generation-24',
        nodes: data.nodes.filter(n => n.mode === 'xdp').map(n => ({ name: n.id, state: 'confirmed' })) } : { found: false })
    }
    if (path === '/api/active-actions/timeline') {
      const logs = data.executions.filter(r => ['attack_id', 'action_id', 'connector_id', 'external_rule_id']
        .every(k => !q.has(k) || String(r[k]) === q.get(k)))
      return send({ attack: data.attacks.find(a => a.id === number('attack_id', 1)) ?? null, logs })
    }
    if (path === '/api/active-actions/bgp/dismissed-orphans') return send([{ announcement_id: 3,
      prefix: '203.0.113.64/26', route_map: 'SERVICE', connector_id: 1, connector_name: 'Transit routing',
      status: 'dismissed', detected_at: new Date(data.now - day).toISOString() }])
    const nodePath = /^\/api\/nodes\/([^/]+)(\/status)?$/.exec(path)
    if (nodePath) {
      const node = data.nodes.find(n => n.id === decodeURIComponent(nodePath[1]!))
      if (!node) return missing()
      if (!nodePath[2]) return send(node)
      return send({ ...node, drift: 0, stats_age_seconds: (data.now - Date.parse(node.last_stats_at)) / 1000,
        connected_at: new Date(data.now - 4 * day).toISOString(), uptime_seconds: 4 * day / 1000,
        interfaces: ['eth0'], capture: [{ interface: 'eth0', upstream_sample_rate: node.mode === 'flow' ? 1000 : 1 }],
        ...(node.mode === 'flow' ? {
          flow_metrics: { decode_errors: 0, unknown_exporter: 0, template_misses: 0, updated_at: node.last_stats_at },
          source_statuses: data.sources.map(s => ({ device_ip: s.device_ip, active: true,
            last_seen_at: Math.floor(data.now / 1000) - 5, records_received: 128400000 })),
          listener_statuses: data.listeners.map(l => ({ listen_addr: l.listen_address, protocol_mode: l.protocol_mode,
            records_decoded: 128400000, decode_errors: 0, unknown_exporter: 0, template_misses: 0, source_count: 1 })),
        } : {}) })
    }
    const templatePath = /^\/api\/threshold-templates\/(\d+)(\/rules)?$/.exec(path)
    if (templatePath) {
      const template = data.templates.find(t => t.id === Number(templatePath[1]))
      if (!template) return missing()
      const rules = data.rules.filter(r => r.template_id === template.id)
      return send(templatePath[2] ? rules : { template, rules,
        prefixes_using: data.prefixes.filter(p => p.threshold_template_id === template.id) })
    }
    const responsePath = /^\/api\/responses\/(\d+)(\/actions)?$/.exec(path)
    if (responsePath) {
      const response = data.responses.find(r => r.id === Number(responsePath[1]))
      if (!response) return missing()
      const actions = data.actions.filter(a => a.response_id === response.id)
      return send(responsePath[2] ? actions : { response, actions })
    }
    const actionPath = /^\/api\/actions\/(\d+)\/(preconditions|xdrop-targets)$/.exec(path)
    if (actionPath) {
      const action = data.actions.find(a => a.id === Number(actionPath[1]))
      if (!action) return missing()
      return send(actionPath[2] === 'preconditions' ? data.conditions.filter(c => c.action_id === action.id)
        : action.target_node_ids ?? [])
    }
    const connectorPath = /^\/api\/settings\/(webhook|xdrop|shell|bgp)-connectors(?:\/(\d+))?(\/routes)?$/.exec(path)
    if (connectorPath) {
      const list = data.connectors[connectorPath[1]!]!
      const row = list.find(c => c.id === Number(connectorPath[2]))
      if (connectorPath[2] && !row) return missing()
      if (connectorPath[3]) return connectorPath[1] === 'bgp' ? send({ output:
        'Network                 Next Hop        Path\n203.0.113.10/32         203.0.113.254   64512 i\n' }) : missing()
      return send(connectorPath[2] ? row : list)
    }
    if (path === '/api/flow-listeners') return send(data.listeners.filter(l => !q.has('node_id')
      || l.node_id === q.get('node_id')))
    if (path === '/api/flow-sources') return send(data.sources.filter(s => !q.has('listener_id')
      || s.listener_id === number('listener_id', 1)))
    const listenerPath = /^\/api\/flow-listeners\/(\d+)$/.exec(path)
    if (listenerPath) {
      const listener = data.listeners.find(l => l.id === Number(listenerPath[1]))
      return listener ? send({ listener, sources: data.sources.filter(s => s.listener_id === listener.id) }) : missing()
    }
    if (path === '/api/baseline') return send(data.prefixes.map((p, i) => ({ prefix: p.prefix,
      p95_pps: 900000 + i * 80000, p95_bps: (900000 + i * 80000) * 5600,
      recommend_pps: 1400000 + i * 120000, recommend_bps: (1400000 + i * 120000) * 5600,
      data_points: 2016, active: true })))
    if (path === '/api/dynamic-detection/config') return send({ enabled: true, deviation_min: 50, deviation_max: 150,
      stable_weeks: 4, min_pps: 100000, min_bps: 1e9, ewma_alpha: .3 })
    if (path === '/api/dynamic-detection/status') {
      const date = new Date(data.now), weekday = date.toLocaleDateString('en-US', { weekday: 'long', timeZone: 'UTC' })
      return send({ enabled: true, current_slot: ((date.getUTCDay() + 6) % 7) * 24 + date.getUTCHours(),
        current_slot_label: `${weekday} ${String(date.getUTCHours()).padStart(2, '0')}:00 UTC`,
        total_prefixes: 4, activated_count: 4, learning_count: 0, prefixes: data.prefixes.map(p => ({ prefix: p.prefix,
          expected_pps: 900000, expected_bps: 5e9, current_pps: 1100000, current_bps: 6e9,
          thresh_pps: 2250000, thresh_bps: 12.5e9, sample_weeks: 6, status: 'active' })) })
    }
    if (path === '/api/webhooks') return send([{ id: 1, url: 'https://hooks.example.com/archive',
      events: ['attack_detected', 'attack_expired'], enabled: true }])
    if (path === '/api/audit-log') return send(page(data.audit.filter(r => (!q.has('entity_type')
      || r.entity_type === q.get('entity_type')) && (!q.has('user_id') || r.user_id === number('user_id', 0))
      && (!q.has('from') || Date.parse(r.created_at) >= Date.parse(q.get('from')!))
      && (!q.has('to') || Date.parse(r.created_at) <= Date.parse(q.get('to')!)))))
    if (path === '/api/flowspec/announcements') return send({ announcements: [], vendors: [{ id: 'frr', name: 'FRR (local)', executable: true }] })
    if (path === '/api/l7/summary') return send({ generated_at: new Date().toISOString(), window_minutes: 5, bucket_seconds: 60,
      totals: { 'l7_http_flood': 0, 'l7_tls_clienthello': 0, 'l7_slowloris': 0 }, rates: {}, series: [], targets: [],
      sources: [], nodes: [], recent: [], dropped: 0 })
    if (path === '/api/l7/events') return send([])
    if (/^\/api\/nodes\/[^/]+\/tls$/.test(path)) return send({ server: { min_version: 'TLS 1.3', expires_at: new Date(Date.now()+86400000).toISOString(),
      issuer: 'YemenAntiDDoS CA', fingerprint: 'aa:bb:cc:dd', serial: '1', not_before: new Date().toISOString() },
      node: { verified: true, subject: 'CN=flow-c', identity: 'flow-c', sans: ['flow-c'], expires_at: new Date(Date.now()+86400000).toISOString(),
      seen_at: new Date().toISOString() }, warnings: [] })
    const tables: Record<string, Row[]> = { nodes: data.nodes, prefixes: data.prefixes, thresholds: data.rules,
      'threshold-templates': data.templates, responses: data.responses, users: data.users, 'flow-sources': data.sources }
    const tablePath = /^\/api\/([^/]+)(?:\/(\d+))?$/.exec(path)
    if (tablePath && tables[tablePath[1]!]) {
      let rows = tables[tablePath[1]!]!
      if (tablePath[1] === 'thresholds') rows = rows.filter(r => ['template_id', 'prefix_id'].every(k =>
        !q.has(k) || String(r[k]) === q.get(k)))
      const row = rows.find(r => r.id === Number(tablePath[2]))
      return tablePath[2] ? row ? send(row) : missing() : send(rows)
    }
    return missing()
  }
  return (raw, method, body) => {
    try { return handle(raw, method, body) }
    catch { return { status: 500, body: { error: 'internal error' } } }
  }
}
