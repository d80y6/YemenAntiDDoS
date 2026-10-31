import { expect, it } from 'vitest'
// @ts-expect-error Node built-ins are used only by the offline test runner.
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
// @ts-expect-error Node built-ins are used only by the offline test runner.
import { tmpdir } from 'node:os'
import { createData, type Row } from '../demo/data'
import { createServer, contains } from '../demo/server'
import { countdown, delaySeconds } from '../src/views/attacks/data'
import { scanSources, scanArtifacts } from '../demo/scan.mjs'

const now = Date.UTC(2026, 9, 31, 12), data = createData(now), server = createServer(data)
const ids = (rows: Row[]) => rows.map(r => r.id).sort((a, b) => a - b)
const series = (query: string) => server('/api/stats/total-timeseries?' + query)
const windowQuery = 'from=2026-10-31T11:00:00Z&to=2026-10-31T12:00:00Z'

it('F01 BGP detail countdown and brief agree with the list and Go shapes', () => {
  const list = server('/api/active-actions/bgp').body.find((r: Row) => r.attack_id === 2)
  const view = server('/api/attacks/2/mitigation-summary').body.bgp_announcements[0]
  const brief = server('/api/attacks/mitigation-brief?ids=2').body[2].bgp[0]
  const seconds = (Date.parse(list.scheduled_for) - now) / 1000
  console.log('F01', { listSeconds: seconds, detailSeconds: delaySeconds(view.announcement, now), brief })
  expect(delaySeconds(view.announcement, now)).toBe(seconds)
  expect(countdown(delaySeconds(view.announcement, now))).toBe('3:00')
  expect(seconds).toBeGreaterThan(0)
  expect(view.announcement).toMatchObject({ id: list.announcement_id, delay_minutes: 5, refcount: 1 })
  expect(view.announcement).not.toHaveProperty('announcement_id')
  expect(view).toMatchObject({ attached_at: list.attached_attacks[0].attached_at,
    detached_at: null, attack_delay_minutes: 5, attack_action_id: 4 })
  expect(brief).toEqual({ prefix: list.prefix, route_map: list.route_map, status: list.status,
    attached_at: list.attached_attacks[0].attached_at, delay_minutes: 5 })
})
it('F02 IPv4-tail IPv6 containment accepts equivalent addresses and rejects malformed input', () => {
  expect(contains('2001:db8:100::0.0.0.0/96', '2001:db8:100::10/128')).toBe(true)
  expect(server('/api/attacks?dst_ip=2001:db8:100::0.0.0.0/96').body.total).toBe(10)
  for (const invalid of ['203.0.113.10/999', '203.0.113.10/-1', '203.0.113.10/24.5',
    '203.0.113.10/32/1', '203.0.113.10/', '203.0.113.10/ 32', '203.0.113.256']) {
    expect(contains('203.0.113.0/24', invalid), invalid).toBe(false)
  }
  for (const invalid of ['2001:db8::1::2', '2001:db8::1/129', '2001:db8:1:2:3:4:5:6::',
    '2001:db8:1:2:3:4:5', '2001:db8:1:2:3:4:5:6:7', '2001:db8::256.0.0.1']) {
    expect(contains('2001:db8::/32', invalid), invalid).toBe(false)
  }
  expect(contains('2001:db8::/32', '2001:db8:1:2:3:4:192.0.2.1')).toBe(true)
})
it('F03 resolutions include 1h, default 5min and Go raw/cagg handling of unknown values', () => {
  for (const [resolution, count, step] of [['5s', 721, 5000], ['5min', 13, 300000],
    ['1h', 2, 3600000], ['', 13, 300000], ['unknown', 721, 5000]] as const) {
    const rows = series(windowQuery + (resolution ? '&resolution=' + resolution : '')).body
    console.log('F03', resolution || 'default', rows.length)
    expect(rows).toHaveLength(count)
    expect(Date.parse(rows[1].time) - Date.parse(rows[0].time)).toBe(step)
  }
  expect(series(windowQuery.replace('11:00', '10:00') + '&resolution=unknown').body).toHaveLength(25)
  expect(series(windowQuery + '&dst_ip=203.0.113.10&resolution=unknown').status).toBe(400)
})
it('F04 attack filter ID sets and pagination follow Go handler and store semantics', () => {
  const checks: [string, Row[]][] = [
    ['prefix_id=3', data.attacks.filter(a => a.prefix_id === 3)],
    ['from=2026-10-31T11:59:00Z', []], ['status=all', data.attacks],
    ['from=2026-10-31T11:40:00Z&to=2026-10-31T11:55:00Z', data.attacks.filter(a =>
      Date.parse(a.started_at) >= now - 20 * 60000 && Date.parse(a.started_at) <= now - 5 * 60000)],
  ]
  for (const [query, expected] of checks) {
    const reply = server('/api/attacks?' + query).body
    console.log('F04', query, reply.total, 'expected', expected.length)
    expect(ids(reply.attacks)).toEqual(ids(expected)); expect(reply.total).toBe(expected.length)
  }
  const many = createServer({ ...data, attacks: Array.from({ length: 250 }, (_, i) =>
    ({ ...data.attacks[0], id: i + 1 })) })
  for (const [query, count] of [['', 50], ['limit=999', 200], ['limit=0', 100], ['limit=oops', 100],
    ['limit=-1', 100], ['limit=10&offset=245', 5]] as const) {
    expect(many('/api/attacks?' + query).body.attacks, query).toHaveLength(count)
  }
  expect(many('/api/attacks?offset=-1')).toEqual({ status: 400, body: { error: 'invalid input' } })
  // Go int64 parsing beyond Number.MAX_SAFE_INTEGER, saturated on overflow.
  for (const [query, count] of [['offset=9007199254740992', 0], ['offset=9223372036854775807', 0],
    ['offset=99999999999999999999', 0], ['limit=9007199254740992', 200]] as const) {
    expect(many('/api/attacks?' + query).body.attacks, query).toHaveLength(count)
  }
  for (const query of ['offset=-9007199254740992', 'offset=-99999999999999999999']) {
    expect(many('/api/attacks?' + query).status, query).toBe(400)
  }
})
it('F07 malformed paths and huge windows always return bounded replies, earliest buckets first', () => {
  expect(server('/api/nodes/%')).toEqual({ status: 404, body: { error: 'not found' } })
  for (const [resolution, count, step] of [['5s', 7200, 5000], ['5min', 2000, 300000],
    ['1h', 1000, 3600000]] as const) {
    const reply = series('from=0001-01-01T00:00:00Z&to=9999-01-01T00:00:00Z&resolution=' + resolution)
    console.log('F07', resolution, reply.status, reply.body.length)
    expect(reply.status).toBe(200); expect(reply.body).toHaveLength(count)
    expect(reply.body[0].time).toBe('0001-01-01T00:00:00.000Z')
    expect(Date.parse(reply.body.at(-1).time) - Date.parse(reply.body[0].time)).toBe((count - 1) * step)
  }
  for (const raw of [null, {}, Symbol('bad'), 'http://[', '/api/nodes/%E0%A4']) {
    expect(() => server(raw as string)).not.toThrow()
  }
})
it('F07 shim converts an unexpected server exception to 500 and counts it', async () => {
  const { installShim } = await import('../demo/shim')
  const restore = installShim(window, localStorage, '/xsight/', () => { throw Error('test failure') })
  try {
    const reply = await window.fetch('/api/nodes')
    expect(reply.status).toBe(500); expect(await reply.json()).toEqual({ error: 'internal error' })
    expect(window.__xsDemoMisses).toBe(1)
  } finally { restore() }
})
it('F08 full build version is mandatory; banner and other versions cannot satisfy the gate', () => {
  const dir = mkdtempSync(tmpdir() + '/demo-version-')
  try {
    mkdirSync(dir + '/prod'); mkdirSync(dir + '/demo')
    writeFileSync(dir + '/prod/index.js', 'const production = true')
    for (const value of ['xs-demo-banner', 'c912976', 'other-demo', 'xc912976-demo']) {
      writeFileSync(dir + '/demo/index.js', JSON.stringify(value))
      expect(scanArtifacts(dir + '/prod', dir + '/demo', 'c912976').failures.length).toBeGreaterThan(0)
    }
    writeFileSync(dir + '/demo/index.js', 'const version = "c912976-demo"')
    expect(scanArtifacts(dir + '/prod', dir + '/demo', 'c912976').failures).toEqual([])
    expect(() => scanArtifacts(dir + '/prod', dir + '/demo', '')).toThrow(/version/i)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})
it.each(["banner.dataset.password = 'hunter2'", "export const password='hunter2'",
  "const obj = {password:('hunter2')}", "a['password'] = ('hunter2')"])(
  'F09 sensitive AST contexts reject %s', source => {
    const dir = mkdtempSync(tmpdir() + '/demo-source-')
    try {
      writeFileSync(dir + '/injected.ts', source)
      expect(scanSources(dir)).toEqual(expect.arrayContaining([expect.objectContaining({ kind: 'credential' })]))
      writeFileSync(dir + '/injected.ts', source.replace('hunter2', '******'))
      expect(scanSources(dir)).toEqual([])
    } finally { rmSync(dir, { recursive: true, force: true }) }
  },
)
