import { beforeAll, afterAll, describe, it, expect, vi } from 'vitest'
// @ts-expect-error Node built-ins run in Vitest; production tsconfig excludes Node globals.
import { readFileSync, readdirSync } from 'node:fs'
// @ts-expect-error Node built-ins run in Vitest; production tsconfig excludes Node globals.
import { join } from 'node:path'
// @ts-expect-error Node built-ins run in Vitest; production tsconfig excludes Node globals.
import { isIP } from 'node:net'
import { middlewareProbe } from './qe-fixtures.mjs'
import { exportSeed, parityDirectory, parityTime } from '../scripts/parity-seed.mjs'
import { root } from '../scripts/lib.mjs'
import { userBody } from '../src/views/users/data'
import { prefixBody } from '../src/views/prefixes/data'
import { ruleBody, flatBody } from '../src/views/thresholds/data'
import { configBody } from '../src/views/baseline/data'
import { payload } from '../src/views/responses/data'
import { listenerBody, sourceBody } from '../src/views/flow/data'
import { connectorBody } from '../src/views/connectors/data'
import { cidrText } from '../mock/cidr'
import { mockReply, mockSession } from '../mock/data'

type Row = Record<string, any>
type Result = { status: number; body: any }
type Step = { id: string; site: string; why: string; method: string; path: string; body: any; reads: string[];
  builder?: { fn: string; form: Row; extra?: Row }; mask?: { path: string; why: string }[] }
const read = (file: string) => JSON.parse(readFileSync(join(parityDirectory, file), 'utf8'))
const manifest = read('requests.json') as { steps: Step[]; sites: Row[] }
const seed = read('seed.json')
const golden = read('golden.json') as { id: string; path: string; result: Result }[]

function normalize(path: string, body: any): any {
  function walk(value: any): any {
    if (Array.isArray(value)) return value.map(walk)
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) =>
      [k, k.endsWith('_at') && v !== null ? '<ts>' : walk(v)]))
    return value
  }
  const out = walk(body)
  let rows: Row[] | undefined, keys: string[] = []
  if (path === '/api/thresholds') {
    rows = out
    keys = ['prefix_id', 'template_id', 'decoder']
  } else if (/^\/api\/threshold-templates\/\d+$/.test(path)) {
    rows = out?.rules
    keys = ['decoder', 'unit']
  } else if (/^\/api\/responses\/\d+$/.test(path)) {
    rows = out?.actions
    keys = ['trigger_phase', 'priority']
  }
  for (let start = 0; rows && start < rows.length;) {
    let end = start + 1
    while (end < rows.length && keys.every(k => rows![start]![k] === rows![end]![k])) end++
    rows.splice(start, end - start, ...rows.slice(start, end).sort((a, b) => a.id - b.id))
    start = end
  }
  return out
}
function difference(a: any, b: any, path = '$.body'): string {
  if (Object.is(a, b)) return ''
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return `${path}.length: ${a.length} != ${b.length}`
    for (let i = 0; i < a.length; i++) {
      const diff = difference(a[i], b[i], `${path}[${i}]`)
      if (diff) return diff
    }
    return ''
  }
  if (a && b && !Array.isArray(a) && !Array.isArray(b) && typeof a === 'object' && typeof b === 'object') {
    for (const key of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
      if (Object.hasOwn(a, key) !== Object.hasOwn(b, key)) return `${path}.${key}: key presence differs`
      const diff = difference(a[key], b[key], `${path}.${key}`)
      if (diff) return diff
    }
    return ''
  }
  return `${path}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`
}
function compare(path: string, a: Result, b: Result) {
  if (a.status !== b.status) return `$.status: ${a.status} != ${b.status}`
  return difference(normalize(path, a.body), normalize(path, b.body))
}

const expected500 = `[["qh-source-int32-overflow","POST","/api/flow-sources","database error"],
["qh-source-int32-update-overflow","PUT","/api/flow-sources/9","database error"],
["qi-user-pw-73","POST","/api/users","hash failed"],
["qi-user-pw-multibyte","POST","/api/users","hash failed"],
["qi-user-pw-update-73","PUT","/api/users/9","hash failed"]]`
function apparatus(id: string, method: string, path: string, result: Result) {
  const context = `${id} apparatus ${method} ${path}`
  expect(result.body, `${context} JSON`).not.toBeUndefined()
  const allowed = JSON.parse(expected500) as string[][]
  const entry = allowed.find(([step, verb, url]) => id === step && method === verb && path === url)
  if (entry) {
    expect(result, context).toEqual({ status: 500, body: { error: entry[3] } })
  } else expect(result.status, context).toBeLessThan(500)
}
it('G-parity C1 apparatus exact allowlist and payload W37', () => {
  const failure = { status: 500, body: { error: 'database error' } }
  expect(() => apparatus('unlisted-step', 'POST', '/api/flow-sources', failure)).toThrow(/apparatus/)
  expect(() => apparatus('qh-source-int32-overflow', 'POST', '/api/flow-sources',
    { status: 500, body: { error: 'x' } })).toThrow(/apparatus/)
  expect(() => apparatus('qh-source-int32-overflow', 'GET', '/api/flow-sources', failure)).toThrow(/apparatus/)
  expect(() => apparatus('qh-source-int32-overflow', 'POST', '/api/flow-sources/9', failure)).toThrow(/apparatus/)
  expect(() => apparatus('qh-source-int32-overflow', 'POST', '/api/flow-sources',
    { ...failure, status: 201 })).toThrow(/apparatus/)
  expect(() => apparatus('qh-source-int32-overflow', 'POST', '/api/flow-sources',
    { status: 500, body: { error: 'database error', extra: 1 } })).toThrow(/apparatus/)
  expect(() => apparatus('ordinary', 'GET', '/api/flow-sources',
    { status: 200, body: undefined })).toThrow(/apparatus/)
  apparatus('qh-source-int32-overflow', 'POST', '/api/flow-sources', failure)
  apparatus('qh-source-int32-update-overflow', 'PUT', '/api/flow-sources/9', failure)
  apparatus('ordinary', 'GET', '/api/flow-sources', { status: 200, body: [] })
})

it.each([
  ['qi-user-pw-73', 'POST', '/api/users', 'database error'],
  ['qh-source-int32-overflow', 'POST', '/api/flow-sources', 'hash failed'],
])('G-parity auth1 apparatus W41 wrong original %s', (id, method, path, error) => {
  expect(() => apparatus(id, method, path, { status: 500, body: { error } })).toThrow(/apparatus/)
})
it('G-parity auth1 reads and unlisted writes cannot use hash failed allowance', () => {
  const failure = { status: 500, body: { error: 'hash failed' } }
  expect(() => apparatus('qi-user-pw-73', 'GET', '/api/users', failure)).toThrow(/apparatus/)
  expect(() => apparatus('unlisted-step', 'POST', '/api/users', failure)).toThrow(/apparatus/)
  expect(() => apparatus('qi-user-pw-update-73', 'PUT', '/api/users/10', failure)).toThrow(/apparatus/)
  apparatus('qi-user-pw-73', 'POST', '/api/users', failure)
  apparatus('qi-user-pw-multibyte', 'POST', '/api/users', failure)
  apparatus('qi-user-pw-update-73', 'PUT', '/api/users/9', failure)
})

describe('G-parity same middleware session, in request order', () => {
  let invoke: Awaited<ReturnType<typeof middlewareProbe>>
  let offset = 0
  beforeAll(async () => {
    vi.stubEnv('XSIGHT_API', '')
    vi.stubEnv('XSIGHT_MOCK_CASE', '')
    vi.spyOn(Date, 'now').mockReturnValue(parityTime)
    invoke = await middlewareProbe()
  })
  afterAll(() => {
    vi.restoreAllMocks()
    vi.unstubAllEnvs()
  })
  for (const step of manifest.steps) it(step.id, async () => {
    for (const [index, path] of [step.path, ...step.reads].entries()) {
      const method = index ? 'GET' : step.method
      const result = await invoke(method, path, index ? undefined : step.body)
      apparatus(step.id, method, path, result)
      const expected = golden[offset++]!
      expect([expected?.id, expected?.path]).toEqual([step.id, path])
      const mismatch = compare(path, result, expected.result)
      const context = `${step.id} · ${method} ${path} · read=${index > 0}`
      expect.soft(mismatch, `${context} · ${mismatch}`).toBe('')
    }
  })
  it('G-parity coverage and complete golden consumption', () => {
    expect(manifest.steps.length).toBeGreaterThanOrEqual(60)
    expect(manifest.steps.filter(s => s.method !== 'GET').length).toBeGreaterThanOrEqual(45)
    expect(manifest.steps.reduce((n, s) => n + s.reads.length, 0)).toBeGreaterThanOrEqual(100)
    expect(manifest.steps.filter(s => s.method !== 'GET').reduce((n, s) => n + s.reads.length, 0))
      .toBeGreaterThanOrEqual(100)
    expect(offset).toBe(golden.length)
    expect(new Set(manifest.steps.map(s => s.id)).size).toBe(manifest.steps.length)
    expect(manifest.steps.every(s => s.why && s.site)).toBe(true)
  })
})

it('G-seed fixed clock, fresh session; regenerate: node scripts/parity-seed.mjs', async () => {
  expect(await exportSeed()).toEqual(seed)
})
it('G-cidr immutable PG corpus: 75 entries, 53 texts and 22 errors', () => {
  const entries = read('cidr-corpus.json').entries as { input: string; text?: string; error?: string }[]
  expect(entries).toHaveLength(75)
  expect(entries.filter(e => e.text !== undefined)).toHaveLength(53)
  expect(entries.filter(e => e.error === '22P02')).toHaveLength(22)
  for (const entry of entries) {
    const text = cidrText(entry.input)
    const result = text === undefined ? { error: '22P02' } : { text }
    const { input, ...expected } = entry
    expect.soft(result, input).toEqual(expected)
  }
})
function addressValue(address: string): { bits: number; value: bigint } {
  if (!address.includes(':')) {
    return { bits: 32, value: address.split('.').reduce((n, p) => n * 256n + BigInt(Number(p)), 0n) }
  }
  address = address.replace(/\d+\.\d+\.\d+\.\d+$/, tail => {
    const p = tail.split('.').map(Number)
    return ((p[0]! << 8) + p[1]!).toString(16) + ':' + ((p[2]! << 8) + p[3]!).toString(16)
  })
  const halves = address.split('::')
  const left = halves[0] ? halves[0].split(':') : []
  const right = halves[1] ? halves[1].split(':') : []
  const groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
  return { bits: 128, value: groups.reduce((n, p) => n * 65536n + BigInt('0x' + p), 0n) }
}
function addressLiterals(text: string): string[] {
  const v4 = [...text.matchAll(/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g)]
    .map(m => m[0]).filter(ip => ip.split('.').every(p => Number(p) <= 255))
  const v6 = [...text.matchAll(/[0-9a-fA-F:.]+/g)].map(m => m[0]).filter(ip => isIP(ip) === 6)
  return [...new Set([...v4, ...v6])]
}
it('G-address documentation/private/IETF special literals and rendered mock fixtures', () => {
  // Explicit documentation/private/special ranges; unknown ranges fail closed.
  const ranges = [
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    '::/8', '100::/64', '64:ff9b::/96', '64:ff9b:1::/48', '2001::/23', '2001:db8::/32',
    '2002::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
  ].map(raw => {
    const [ip, mask] = raw.split('/')
    return { ...addressValue(ip!), mask: Number(mask) }
  })
  const unsafe = (text: string) => addressLiterals(text).filter(ip => {
    const { bits, value } = addressValue(ip)
    return !ranges.some(r => r.bits === bits
      && value >> BigInt(bits - r.mask) === r.value >> BigInt(bits - r.mask))
  })
  // Construct the positive witness only in memory; no complete public literal in source.
  const positive = ['2001', ['d', 'b', 'd'].join(''), '5', '', '1'].join(':')
  expect(unsafe(positive)).toEqual([positive])
  const sources = ['requests.json', 'seed.json', 'golden.json', 'cidr-corpus.json']
    .map(file => ({ name: file, text: readFileSync(join(parityDirectory, file), 'utf8') as string }))
  sources.push({ name: 'mock/data.ts', text: readFileSync(join(root, 'mock/data.ts'), 'utf8') })
  // Template expressions need their rendered values too: source-only matching cannot see n/i.
  for (const mode of ['normal', 'attacks']) {
    const session = mockSession(mode, parityTime)
    for (const path of ['/api/active-actions/bgp', '/api/active-actions/bgp/dismissed-orphans']) {
      sources.push({ name: `mock/data.ts rendered ${mode} ${path}`, text: JSON.stringify(session(path).body) })
    }
  }
  const counts: Row = {}
  for (const source of sources) {
    counts[source.name] = addressLiterals(source.text).length
    expect(counts[source.name], source.name + ' nonempty address scan').toBeGreaterThan(0)
    expect.soft(unsafe(source.text).length, source.name + ' addresses outside approved ranges').toBe(0)
  }
  console.info('G-address counts=' + JSON.stringify(counts) + ' positive=1')
})
it('C5 empty/null connector bodies retain aa1275a literals in both mock entry points', () => {
  const now = vi.spyOn(Date, 'now').mockReturnValue(0)
  const at = '1970-01-01T00:00:00.000Z'
  const before = '1969-12-31T00:00:00.000Z', updated = '1969-12-31T23:59:55.000Z'
  const expected: Row = {
    webhook: [
      { id: 1, name: 'Alert hook', enabled: true, created_at: at, updated_at: at,
        url: 'http://192.0.2.1/hook', method: 'POST', headers: { Authorization: '***' },
        timeout_ms: 10000, global: false },
      { id: 2, name: 'Disabled hook', enabled: false, created_at: at, updated_at: at,
        url: 'http://192.0.2.1/hook', method: 'POST', headers: { Authorization: '***' },
        timeout_ms: 10000, global: false },
    ],
    shell: [
      { id: 1, name: 'Local shell', enabled: true, created_at: at, updated_at: at,
        command: '/bin/true', default_args: '', timeout_ms: 10000, pass_stdin: false },
      { id: 2, name: 'Disabled shell', enabled: false, created_at: at, updated_at: at,
        command: '/bin/true', default_args: '', timeout_ms: 10000, pass_stdin: false },
    ],
    bgp: [
      { id: 1, name: 'Edge BGP', enabled: true, created_at: at, updated_at: at,
        bgp_asn: 64512, vtysh_path: '/mock/missing', address_family: 'ipv4', description: '',
        vendor: '', flowspec_enabled: false },
      { id: 2, name: 'Disabled BGP', enabled: false, created_at: at, updated_at: at,
        bgp_asn: 64512, vtysh_path: '/mock/missing', address_family: 'ipv4', description: '',
        vendor: '', flowspec_enabled: false },
    ],
    xdrop: [
      { id: 1, name: 'Edge XDrop', enabled: true, api_url: 'http://mock-xdrop.invalid', api_key: '***abcd',
        timeout_ms: 10000, created_at: before, updated_at: updated },
      { id: 2, name: 'Disabled XDrop', enabled: false, api_url: 'http://mock-disabled.invalid', api_key: '***',
        timeout_ms: 10000, created_at: before, updated_at: updated },
    ],
  }
  try {
    for (const mode of ['empty', 'null']) {
      const session = mockSession(mode, 0)
      for (const kind of Object.keys(expected)) {
        const path = `/api/settings/${kind}-connectors`
        const body = mode === 'null' && kind === 'xdrop' ? [] : expected[kind]
        const result = { status: 200, body, ...(kind === 'xdrop' ? { delay: 0 } : {}) }
        expect(mockReply(path, mode, 0), `${mode} ${kind} reply`).toEqual(result)
        expect(session(path), `${mode} ${kind} session`).toEqual(result)
      }
    }
    const session = mockSession('qf-empty', 0)
    for (const kind of Object.keys(expected)) {
      expect(session(`/api/settings/${kind}-connectors`)).toEqual({ status: 200, body: kind === 'xdrop' ? [] : null })
    }
  } finally {
    now.mockRestore()
  }
})
it('G-parity initial read set is exactly the specified set', () => {
  const expected = ['/api/prefixes', '/api/threshold-templates',
    ...seed.templates.map((t: Row) => `/api/threshold-templates/${t.id}`),
    '/api/thresholds', '/api/dynamic-detection/config', '/api/responses',
    ...seed.responses.map((r: Row) => `/api/responses/${r.id}`),
    ...seed.actions.map((a: Row) => `/api/actions/${a.id}/preconditions`),
    ...['webhook', 'shell', 'bgp', 'xdrop'].map(k => `/api/settings/${k}-connectors`)]
  expect([manifest.steps[0]!.path, ...manifest.steps[0]!.reads]).toEqual(expected)
})
function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((d: { name: string; isDirectory(): boolean }) =>
    d.isDirectory() ? files(join(dir, d.name)) : [join(dir, d.name)])
}
it('G-sites write literals per file, exact exclusions and step ownership', () => {
  const src = join(root, 'src')
  const found = files(src).flatMap(file => {
    const count = [...readFileSync(file, 'utf8').matchAll(/['"](?:POST|PUT|DELETE)['"]/g)].length
    return count ? [{ file: file.slice(src.length + 1), count }] : []
  }).sort((a, b) => a.file < b.file ? -1 : 1)
  expect(found).toEqual(manifest.sites.map(({ file, count }) => ({ file, count })))
  expect(manifest.sites.filter(s => s.excluded).map(s => s.file).sort()).toEqual([
    'views/Login.vue', 'views/attacks/AttackDetail.vue', 'views/attacks/ExpireConfirm.vue',
    'views/connectors/probe.ts', // 测试 / 路由端点真发 HTTP / exec，不进入差分执行器
    'views/mitigations/Flowspec.vue', // CLI 渲染与撤回守卫由 Go 测试覆盖；JS mock 不模拟 Flowspec 端点
  ])
  for (const site of manifest.sites) {
    if (site.excluded) expect(site.excluded.length).toBeGreaterThan(0)
    else {
      expect(site.steps.length, site.file).toBeGreaterThan(0)
      for (const id of site.steps) {
        const step = manifest.steps.find(s => s.id === id)
        expect(step?.site, id).toBe(site.file)
        expect(['POST', 'PUT', 'DELETE']).toContain(step?.method)
      }
    }
  }
})
function builderNeeded(s: Step) {
  if (!['POST', 'PUT'].includes(s.method)) return false
  return /^\/api\/prefixes(?:\/\d+)?$/.test(s.path)
    || /^\/api\/settings\/(?:bgp|xdrop|webhook|shell)-connectors(?:\/\d+)?$/.test(s.path)
    || /^\/api\/users(?:\/\d+)?$/.test(s.path)
    || /^\/api\/flow-(?:listeners|sources)(?:\/\d+)?$/.test(s.path)
    || s.site === 'views/thresholds/RuleDrawer.vue'
    || s.path === '/api/dynamic-detection/config'
    || /^\/api\/(?:responses\/\d+\/actions|actions\/\d+)$/.test(s.path)
}
it('G-shape constructors required for every corresponding write', () => {
  expect(manifest.steps.filter(s => builderNeeded(s) && !s.builder).map(s => s.id)).toEqual([])
})
for (const step of manifest.steps.filter(s => s.builder)) it(`G-shape ${step.id}`, () => {
  const { fn, form, extra } = step.builder!
  let body: Row
  switch (fn) {
    case 'userBody': body = userBody(form as any, form.row); break
    case 'listenerBody': body = listenerBody(form as any, form.row); break
    case 'sourceBody': body = sourceBody(form as any, form.listener_id, form.row); break
    case 'connectorBody': body = connectorBody(form.kind, form as any, form.row); break
    case 'prefixBody': body = prefixBody(form, step.method === 'PUT'); break
    case 'ruleBody': body = ruleBody(form); break
    case 'flatBody': body = flatBody(form); break
    case 'configBody': body = configBody(form as any); break
    case 'payload': body = payload(form as any, form.phase); break
    default: throw new Error(`unknown builder ${fn}`)
  }
  if (extra) {
    expect(fn).toBe('payload')
    expect(Object.keys(extra)).toEqual(['enabled'])
    expect(typeof extra.enabled).toBe('boolean')
  }
  if (fn === 'sourceBody' && !form.toggle) expect(body.sample_rate).toBeGreaterThanOrEqual(1)
  expect({ ...body, ...extra }).toEqual(step.body)
})
it('G-mask pinned step/path list and no error/status masks', () => {
  const masks = manifest.steps.flatMap(s => (s.mask ?? []).map(m => [s.id, m.path]))
  expect(masks).toEqual([])
  for (const [, path] of masks) expect(path).not.toMatch(/error|status/)
  expect(normalize('/api/responses', { x_at: null, y_at: 'value', at: 'keep', status: 409, error: 'keep' }))
    .toEqual({ x_at: null, y_at: '<ts>', at: 'keep', status: 409, error: 'keep' })
})
describe('G-cmp handwritten witnesses', () => {
  const cases: [string, string, Result, Result, boolean][] = [
    ['status', '/api/responses', { status: 409, body: { error: 'same' } },
      { status: 400, body: { error: 'same' } }, false],
    ['error', '/api/responses', { status: 400, body: { error: 'one' } },
      { status: 400, body: { error: 'two' } }, false],
    ['timestamps', '/api/responses', { status: 200, body: { created_at: 'a' } },
      { status: 200, body: { created_at: 'b' } }, true],
    ['null timestamp', '/api/responses', { status: 200, body: { created_at: null } },
      { status: 200, body: { created_at: 'b' } }, false],
    ['same segment', '/api/thresholds', { status: 200, body: [{ id: 2, decoder: 'ip' }, { id: 1, decoder: 'ip' }] },
      { status: 200, body: [{ id: 1, decoder: 'ip' }, { id: 2, decoder: 'ip' }] }, true],
    ['cross segment', '/api/thresholds', { status: 200, body: [{ id: 2, decoder: 'tcp' }, { id: 1, decoder: 'ip' }] },
      { status: 200, body: [{ id: 1, decoder: 'ip' }, { id: 2, decoder: 'tcp' }] }, false],
  ]
  for (const [name, path, a, b, equal] of cases) it(name, () => expect(compare(path, a, b) === '').toBe(equal))
  for (const [path, property, key] of [
    ['/api/threshold-templates/7', 'rules', 'decoder'], ['/api/responses/3', 'actions', 'priority'],
  ]) it(`${property} continuous segments only`, () => {
    const a = { status: 200, body: { [property!]: [{ id: 2, [key!]: 'a' }, { id: 1, [key!]: 'a' }] } }
    const b = { status: 200, body: { [property!]: [{ id: 1, [key!]: 'a' }, { id: 2, [key!]: 'a' }] } }
    expect(compare(path!, a, b)).toBe('')
    b.body[property!]![0]![key!] = 'b'
    expect(compare(path!, a, b)).not.toBe('')
  })
})

it('G-audit-window every audit read has a bounded to and unique seed times', () => {
  for (const step of manifest.steps) for (const path of [step.path, ...step.reads]) {
    const url = new URL(path, 'http://localhost')
    if (url.pathname !== '/api/audit-log') continue
    const to = url.searchParams.get('to')
    expect(to, step.id + ' to required').not.toBeNull()
    expect(Date.parse(to!), step.id + ' bounded window').toBeLessThanOrEqual(parityTime)
  }
  const times = seed.audit.map((row: Row) => Date.parse(row.created_at)) as number[]
  expect(new Set(times).size).toBe(times.length)
  for (const time of times) expect(time).toBeLessThanOrEqual(parityTime)
})
