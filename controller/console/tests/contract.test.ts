import { it, expect, describe } from 'vitest'
import { inspect, checkContract } from '../scripts/contract-check.mjs'
import { contract } from '../src/api/contract'
import { mockReply } from '../mock/data'
describe('G-contract three states and exact optional whitelist', () => {
  it.each([
    [{ a: 0 }, 'a', {}, 'hit'], [{ a: null }, 'a', { nullable: true }, 'hit'],
    [{ a: null }, 'a', {}, 'missing'], [{}, 'a', {}, 'missing'],
    [{}, 'a.b', { nullable: true }, 'missing'], [{ a: null }, 'a.b', { nullable: true }, 'uncovered'],
    [[], '[].a', {}, 'uncovered'], [{ rows: [] }, 'rows[].a', {}, 'uncovered'],
    [{}, 'frag_pps', { optional: 'TimeseriesPoint.FragPPS + omitempty' }, 'hit-absent'],
    [{}, 'parent.frag_pps', { optional: 'TimeseriesPoint.FragPPS + omitempty' }, 'missing'],
    [{ current: { '1': { pps: 0 } } }, 'current.*.pps', {}, 'hit'],
    [{}, 'current.*.pps', {}, 'missing'],
  ])('inspect %j %s %j => %s', (body, path, entry, state) => { expect(inspect(body, path, entry)).toBe(state) })
  it('uncovered and missing are red; reason can permit only uncovered', async () => {
    const entries = [{ endpoint: '/api/nodes', path: '[].id' }]
    expect((await checkContract(entries, async () => [])).passed).toBe(false)
    expect((await checkContract([{ ...entries[0], allowUncovered: 'empty fixture' }], async () => [])).passed)
      .toBe(true)
    expect((await checkContract([{ ...entries[0], allowUncovered: 'empty fixture' }], async () => [{}])).passed)
      .toBe(false)
  })
  it('required field optional and misspelled optional path both fail, real omitted leaf is green', async () => {
    for (const path of ['[].pps', '[].frag_ps']) {
      const r = await checkContract([{ endpoint: '/api/stats/total-timeseries', path,
        optional: 'TimeseriesPoint.FragPPS + omitempty' }], async () => [{}])
      expect(r.passed).toBe(false)
      expect(r.results[0].detail).toContain('not in full-path Go omitempty whitelist')
    }
    const r = await checkContract([{ endpoint: '/api/stats/total-timeseries', path: '[].frag_pps',
      optional: 'TimeseriesPoint.FragPPS + omitempty' }], async () => [{}])
    expect(r.results[0].state).toBe('hit-absent')
    expect(r.passed).toBe(true)
  })
  it('mock samples cover all declared paths', async () => {
    const result = await checkContract(contract, async (endpoint: string) => mockReply(endpoint).body,
      { attack: 2, node: 'edge-a', response: 3, listener: 1, mock: true })
    expect(result.passed).toBe(true)
    expect(result.paths).toBe(643)
    expect(result.requests).toBe(43)
  })
})
describe('G-contract conditional parents and attack templates', () => {
  const parent = { endpoint: '/api/attacks/{attack}', path: 'timer', conditional: 'tracker branch' }
  it('conditional parent missing makes parent and descendants hit-absent', async () => {
    const report = await checkContract([parent, { endpoint: parent.endpoint, path: 'timer.state' }],
      async () => ({}), { attack: 2 })
    expect(report.results.map((r: any) => r.state)).toEqual(['hit-absent', 'hit-absent'])
    expect(report.conditionalAbsent).toEqual(['/api/attacks/{attack}::timer', '/api/attacks/{attack}::timer.state'])
    expect(report.passed).toBe(true)
    const typo = await checkContract([parent, { endpoint: parent.endpoint, path: 'timer.sttae' }],
      async () => ({ timer: { state: 'active' } }), { attack: 2 })
    expect(typo.results[1].state).toBe('missing')
    expect(typo.passed).toBe(false)
  })
  it('conditional outside the exact whitelist is red, including mandatory active timers', async () => {
    for (const [endpoint, path] of [['/api/attacks/{attack}', 'timer.state'], ['/api/attacks/active', 'timers']]) {
      const report = await checkContract([{ endpoint, path, conditional: 'claimed branch' }],
        async () => ({ timers: {}, timer: { state: 'active' } }), { attack: 2 })
      expect(report.passed).toBe(false)
      expect(report.results[0].detail).toContain('not in full-path Go branch whitelist')
    }
    expect(contract.find(e => e.endpoint === '/api/attacks/active' && e.path === 'timers'))
      .not.toHaveProperty('conditional')
    const missing = await checkContract(contract.filter(e => e.endpoint === '/api/attacks/active'
      && e.path === 'timers'), async () => ({}))
    expect(missing.results[0].state).toBe('missing')
  })
  it('mock mode rejects conditional-absent inside checkContract', async () => {
    const report = await checkContract([parent], async () => ({}), { attack: 2, node: 'edge-a', mock: true })
    expect(report.passed).toBe(false)
    expect(report.results[0].detail).toBe('mock conditional-absent is forbidden')
  })
  it('template without --attack is red and fetch is never called for that template', async () => {
    let calls = 0
    const report = await checkContract([parent], async () => { calls++; return { timer: {} } })
    expect(report.passed).toBe(false)
    expect(report.results[0].detail).toContain('requires --attack')
    expect(calls).toBe(0)
  })
})
describe('G-contract node template and optional array parent', () => {
  it('node template requires --node and encodes a/b', async () => {
    const entries = [{ endpoint: '/api/nodes/{node}/status', path: 'id' }]
    let seen = ''
    const fetcher = async (url: string) => { seen = url; return { id: 'a/b' } }
    const absent = await checkContract(entries, fetcher)
    expect(absent.passed).toBe(false)
    expect(absent.results[0].detail).toContain('requires --node')
    expect(seen).toBe('')
    expect((await checkContract(entries, fetcher, { node: 'a/b' })).passed).toBe(true)
    expect(seen).toBe('/api/nodes/a%2Fb/status')
  })
  it.each([
    [[{ attached_attacks: [{ attack_id: 7 }] }, { is_orphan: true }], true, 'hit'],
    [[{ attached_attacks: [{ attak_id: 7 }] }], false, 'missing'],
    [[{ attached_attacks: [{ attak_id: 7 }] }, { is_orphan: true }], false, 'missing'],
  ])('optional parent preserves per-element child checking %j', async (sample, passed, state) => {
    const entries = [{ endpoint: '/api/active-actions/bgp', path: '[].attached_attacks', optional: 'omitempty' },
      { endpoint: '/api/active-actions/bgp', path: '[].attached_attacks[].attack_id' }]
    const report = await checkContract(entries, async () => sample)
    expect(report.passed).toBe(passed)
    expect(report.results[1].state).toBe(state)
  })
})
