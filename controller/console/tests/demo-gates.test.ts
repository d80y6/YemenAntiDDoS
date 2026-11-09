import { describe, expect, it } from 'vitest'
// @ts-expect-error Node built-ins run in Vitest; production tsconfig excludes Node globals.
import { readFileSync } from 'node:fs'
// @ts-expect-error Node built-ins run in Vitest; production tsconfig excludes Node globals.
import { resolve } from 'node:path'
import ts from 'typescript'
import { createData, day, traffic, type Row } from '../demo/data'
import { createServer, contains } from '../demo/server'
import { backendRoutes, samplePath } from '../demo/routes.mjs'
import { checkContract } from '../scripts/contract-check.mjs'
import { contract } from '../src/api/contract'
import { hours, grain } from '../src/views/overview/data'
import { curveRequest } from '../src/views/attacks/data'
import { normalize } from '../src/api/data'

const now = Date.UTC(2026, 9, 31, 12), data = createData(now), server = createServer(data)
const routes = backendRoutes(), getRoutes = routes.filter(r => r.method === 'GET')
// No exclusions: /metrics is outside the /api group.
const exclusions: { path: string; reason: string }[] = []
const read = (path: string): string => readFileSync(resolve(path), 'utf8')

describe('demo gates', () => {
  it('G3 covers exactly 57 backend GET routes, including timeline', () => {
    expect(getRoutes).toHaveLength(57)
    expect(exclusions).toEqual([])
    for (const route of getRoutes) {
      const path = samplePath(route.path), reply = server(path)
      expect(reply.status, path).toBe(200)
      expect(reply.body, path).toBeTruthy()
      expect(Object.keys(reply.body).length, path).toBeGreaterThan(0)
    }
    console.log('G3 router.go GET=57 covered=57 exclusions=0')
  })
  it('G3 query filters and authorized page ranges return distinct meaningful samples', () => {
    for (const range of ['15m', '1h', '6h', '24h']) {
      const q = new URLSearchParams({ from: new Date(now - hours(range) * 3600000).toISOString(),
        to: new Date(now).toISOString(), resolution: grain(range) === 5000 ? '5s' : '5min', direction: 'receives' })
      const rows = server('/api/stats/total-timeseries?' + q).body as Row[]
      expect(rows).toHaveLength(hours(range) * 3600000 / grain(range) + 1)
      expect(Math.max(...rows.map(r => r.bps))).toBeGreaterThan(1e9)
      expect(Math.max(...rows.map(r => r.pps))).toBeGreaterThan(1e6)
      expect(new Set(rows.map(r => r.pps)).size).toBeGreaterThan(60)
      console.log('G3 window', range, 'points=' + rows.length, rows[0]!.time, rows.at(-1)!.time)
    }
    const filtered = server('/api/attacks?dst_ip=198.51.100.0%2F24&sort=peak_pps&limit=3').body
    expect(filtered.attacks).toHaveLength(3)
    expect(filtered.attacks.every((a: Row) => contains('198.51.100.0/24', a.dst_ip))).toBe(true)
    expect(filtered.attacks[0].peak_pps).toBeGreaterThan(filtered.attacks[2].peak_pps)
    expect(server('/api/attacks?direction=sends').body.total).toBe(0)
    expect(server('/api/attacks?dst_ip=192.0.2.0%2F24').body.total).toBe(0)
    expect(server('/api/attacks?status=expired&limit=200').body.total).toBe(30)
    expect(server('/api/attacks?ended_after=' + new Date(now + day).toISOString()).body.total).toBe(2)
    expect(server('/api/attacks?status=expired&offset=29&limit=20').body.attacks).toHaveLength(1)
    expect(Object.keys(server('/api/attacks/mitigation-brief?ids=2').body)).toEqual(['2'])
    expect(server('/api/flow-listeners?node_id=probe-a').body).toEqual([])
    expect(server('/api/flow-sources?listener_id=99').body).toEqual([])
    expect(server('/api/thresholds?template_id=2').body.every((r: Row) => r.template_id === 2)).toBe(true)
    expect(server('/api/stats/timeseries?dst_ip=192.0.2.10').body).toEqual([])
    expect(server('/api/stats/timeseries?prefix=203.0.113.0%2F24').body.length).toBeGreaterThan(0)
    expect(server('/api/stats/total-timeseries?node_id=flow-c').body[0].pps)
      .toBeLessThan(server('/api/stats/total-timeseries').body[0].pps)
    expect(server('/api/active-actions/timeline?attack_id=2&action_id=4').body.logs)
      .toEqual(data.executions.filter(r => r.attack_id === 2 && r.action_id === 4))
  })
  it('G3 respects exact requested bounds, including every attack detail and incremental tail', () => {
    function query(path: string, params: Record<string, string>) {
      const reply = server('/api/' + path + '?' + new URLSearchParams(params))
      expect(reply.status).toBe(200)
      const rows = reply.body as Row[], start = Date.parse(params.from!), end = Date.parse(params.to!)
      const step = params.resolution === '5s' ? 5000 : 300000, first = Math.ceil(start / step) * step
      expect(rows).toHaveLength(Math.max(0, Math.floor((end - first) / step) + 1))
      for (const [i, row] of rows.entries()) {
        expect(Date.parse(row.time)).toBe(first + i * step)
        expect(Date.parse(row.time)).toBeGreaterThanOrEqual(start)
        expect(Date.parse(row.time)).toBeLessThanOrEqual(end)
        expect(row.tcp_syn_pps).toBeLessThanOrEqual(row.tcp_pps)
        expect(row.tcp_pps + row.udp_pps + row.icmp_pps).toBeLessThanOrEqual(row.pps + 2)
      }
      return rows
    }
    for (const range of ['15m', '1h', '6h', '24h']) for (const direction of ['receives', 'sends']) {
      query('stats/total-timeseries', { from: new Date(now + 1234 - hours(range) * 3600000).toISOString(),
        to: new Date(now + 1234).toISOString(), direction, resolution: grain(range) === 5000 ? '5s' : '5min' })
    }
    for (const attack of data.attacks) {
      const plan = curveRequest(attack as any, now, [], 5000)
      const rows = query(plan.path, plan.params)
      expect(rows.length).toBeGreaterThan(0)
      const tail = curveRequest(attack as any, now + 10000, normalize(rows as any, 'pps'), plan.grain)
      query(tail.path, tail.params)
      const before = rows.filter(r => Date.parse(r.time) < Date.parse(attack.started_at))
      const during = rows.filter(r => Date.parse(r.time) >= Date.parse(attack.started_at)
        && Date.parse(r.time) <= Date.parse(attack.ended_at || new Date(now).toISOString()))
      expect(Math.max(...during.map(r => r.pps))).toBeGreaterThan(Math.max(...before.map(r => r.pps)) * 2)
    }
    console.log('G3 authorization #1 page windows=8 attack windows=32 incremental tails=32 bounds PASS')
  })
  it('G6 overview, node filters and current attack readings use the same series', () => {
    const overview = server('/api/stats/overview').body
    for (const field of ['pps', 'bps']) {
      // Each part rounds pps before bps = pps * 5600, so allow one rounding step per part.
      const step = field === 'bps' ? 5600 : 1
      for (const parts of [overview.nodes, overview.top_prefixes] as Row[][]) {
        expect(Math.abs(parts.reduce((sum: number, p: Row) => sum + p[field], 0) - overview['total_' + field]))
          .toBeLessThanOrEqual(parts.length * step)
      }
    }
    for (const node of data.nodes) {
      const filtered = server('/api/stats/overview?node_id=' + node.id).body
      expect(filtered.node_count).toBe(1)
      expect(filtered.total_pps).toBe(overview.nodes.find((n: Row) => n.id === node.id).pps)
    }
    for (const a of data.attacks.filter(a => !a.ended_at)) {
      const q = new URLSearchParams({ dst_ip: a.dst_ip, from: new Date(now).toISOString(),
        to: new Date(now).toISOString(), resolution: '5s' })
      const point = server('/api/stats/timeseries?' + q).body[0]
      expect(server('/api/attacks/' + a.id).body.current).toEqual({ pps: point.pps, bps: point.bps })
    }
  })
  it('G4 contract passes with explicit query-value mapping and bound options', async () => {
    const mapping = new Map([
      ['10.1.2.0/24', '203.0.113.0/24'], ['192.0.2.10', '203.0.113.10'], ['1,2', '1,2'],
      ['2026-01-01T00:00:00Z', new Date(now - 7 * day).toISOString()],
    ])
    const report = await checkContract(contract, async (endpoint: string) => {
      const url = new URL(endpoint, 'https://example.com')
      for (const [key, value] of url.searchParams) if (mapping.has(value)) {
        url.searchParams.set(key, mapping.get(value)!)
      }
      const reply = server(url.pathname + url.search)
      expect(reply.status, endpoint).toBe(200)
      return reply.body
    }, { attack: 1, node: 'flow-c', response: 1, listener: 1, mock: true })
    console.log('G4', JSON.stringify({ passed: report.passed, requests: report.requests, paths: report.paths,
      failures: report.results.filter((r: any) => !r.passed) }))
    expect(report.passed).toBe(true)
  })
  it('G5 every non-GET backend route is read-only except login', () => {
    const writes = routes.filter(r => r.method !== 'GET' && r.path !== '/api/login')
    expect(writes.length).toBeGreaterThan(40)
    for (const route of writes) expect(server(samplePath(route.path), route.method, {}), route.path)
      .toEqual({ status: 403, body: { error: 'admin role required' } })
    expect(server('/api/unknown', 'PATCH')).toEqual({ status: 403, body: { error: 'admin role required' } })
    expect(server('/api/unknown')).toEqual({ status: 404, body: { error: 'not found' } })
    for (const username of ['reader', 'operator']) expect(server('/api/login', 'POST', {
      username, password: 'not-a-real-password',
    })).toEqual({ status: 200, body: { token: 'demo-session', user: { id: 1, username: 'demo', role: 'viewer' } } })
    expect(server('/api/login', 'POST', { username: '', password: '' }).status).toBe(400)
    console.log('G5 writes=' + writes.length + ' denied; POST /api/login viewer')
  })
  it('G6 targets, references and time ordering are consistent', () => {
    for (const a of data.attacks) {
      expect(data.prefixes.some(p => contains(p.prefix, a.dst_ip)), 'attack target ' + a.id).toBe(true)
      expect(contains(data.prefixes.find(p => p.id === a.prefix_id)!.prefix, a.dst_ip)).toBe(true)
      expect(data.responses.some(r => r.id === a.response_id)).toBe(true)
      expect(data.rules.some(r => r.id === a.threshold_rule_id)).toBe(true)
      expect(data.rules.find(r => r.id === a.threshold_rule_id)!.decoder).toBe(a.decoder_family)
      for (const id of a.node_sources) expect(data.nodes.some(n => n.id === id)).toBe(true)
      expect(Date.parse(a.started_at)).toBeLessThanOrEqual(now)
      if (a.ended_at === null) expect(a.id).toBeLessThanOrEqual(2)
      else {
        expect(Date.parse(a.started_at)).toBeLessThan(Date.parse(a.ended_at))
        expect(Date.parse(a.ended_at)).toBeLessThanOrEqual(now)
      }
    }
    for (const r of [...data.xdrop, ...data.bgp, ...data.executions]) {
      const attack = data.attacks.find(a => a.id === r.attack_id)!
      const action = data.actions.find(a => a.id === r.action_id)!
      expect(attack).toBeTruthy(); expect(action).toBeTruthy()
      expect(action.response_id).toBe(attack.response_id)
      expect(data.connectors[r.action_type]!.some(c => c.id === r.connector_id)).toBe(true)
      expect(Date.parse(r.created_at ?? r.executed_at)).toBeGreaterThanOrEqual(Date.parse(attack.started_at))
      expect(Date.parse(r.created_at ?? r.executed_at)).toBeLessThanOrEqual(now)
    }
    for (const a of data.actions) for (const id of a.target_node_ids ?? []) {
      expect(data.connectors.xdrop!.some(c => c.id === id)).toBe(true)
    }
    for (const l of data.listeners) expect(data.nodes.some(n => n.id === l.node_id && n.mode === 'flow')).toBe(true)
    for (const s of data.sources) expect(data.listeners.some(l => l.id === s.listener_id)).toBe(true)
    expect(createData(now)).toEqual(data)
    expect(createData(now + day).attacks[0]!.started_at).not.toBe(data.attacks[0]!.started_at)
    expect(traffic(now)).toEqual(traffic(now))
    const before = JSON.stringify(data)
    server('/api/nodes').body[0].id = 'changed'
    expect(JSON.stringify(data)).toBe(before)
    console.log('G6 attacks=32 prefixes=4 nodes=3 references/time/determinism PASS')
  })
  it('G7 entry is exactly the prescribed transformation outside banner', () => {
    const source = read('src/main.ts').split('\n').map(line => line.startsWith('import ')
      ? line.replaceAll("'./", "'../src/") : line).join('\n').replace('makeRouter()',
      'makeRouter(createWebHashHistory())')
    const expected = "import './shim'\nimport { createWebHashHistory } from 'vue-router'\n" + source
    const demo = read('demo/main.ts')
    expect(demo.match(/^\/\/ demo-banner:start$/gm)).toHaveLength(1)
    expect(demo.match(/^\/\/ demo-banner:end$/gm)).toHaveLength(1)
    expect(demo.replace(/^\/\/ demo-banner:start\n[\s\S]*?^\/\/ demo-banner:end\n?/m, '')).toBe(expected)
    console.log('G7 exact line comparison PASS')
  })
  it('G7 shim import graph cannot evaluate application state before session seeding', () => {
    const visited = new Set<string>()
    function inspect(file: string) {
      if (visited.has(file)) return
      visited.add(file)
      expect(file).not.toMatch(/src\/(state|api\/client|router|i18n)(?:\.|\/|$)/)
      const visit = (node: ts.Node) => {
        const specifier = ts.isImportDeclaration(node) || ts.isExportDeclaration(node) ? node.moduleSpecifier
          : ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword ? node.arguments[0]
            : undefined
        if (specifier) {
          expect(ts.isStringLiteral(specifier) || ts.isNoSubstitutionTemplateLiteral(specifier)).toBe(true)
          const name = (specifier as ts.StringLiteral).text
          expect(name.startsWith('.')).toBe(true)
          inspect(resolve(file, '..', name.endsWith('.ts') ? name : name + '.ts'))
        }
        ts.forEachChild(node, visit)
      }
      visit(ts.createSourceFile(file, read(file), ts.ScriptTarget.Latest, true))
    }
    inspect(resolve('demo/shim.ts'))
    expect(visited.size).toBe(3)
  })
})
