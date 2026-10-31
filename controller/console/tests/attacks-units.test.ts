import { describe, it, expect, vi } from 'vitest'
import { validTarget, target, curveWindow, tailFrom, mergeTail, wholeCurve, threshold, canForceRemoveRow,
  forceBody, holdInputValid, expireURL, expireResult, aggregateTop, protoName, formatTCPFlags, formattedJSON,
  statusInfo, listParams, connectorName, curveRequest } from '../src/views/attacks/data'
import { otherHolders, isSyntheticRuleId } from '../src/api/xdropRules'
import { bytes1024, dateTime, fullDateTime } from '../src/format'
import { request } from '../src/api/client'
import XConfirm from '../src/components/XConfirm.vue'
import XChart from '../src/components/chart/XChart.vue'
import { render } from './helpers'
const now = Date.parse('2026-10-28T12:00:00Z')
const attack = (start: string, end: string | null = null, dst = '192.0.2.10/32') => ({
  id: 1, dst_ip: dst, direction: 'receives', started_at: start, ended_at: end,
} as any)
const point = (time: number, value = 1) => ({ time, values: { total: value } })
describe('G-units targets (Go verified)', () => {
  it.each([
    ['192.0.2.10/32', 'single', '192.0.2.10'], ['2001:db8::1/128', 'single', '2001:db8::1'],
    ['198.51.100.0/24', 'network', '198.51.100.0/24'], ['0.0.0.0/0', 'global', '0.0.0.0/0'],
    ['::/0', 'network', '::/0'],
  ])('target %s => %s %s', (input, kind, text) => expect(target(input)).toEqual({ kind, text }))
  it.each([
    ['198.51.100.7', true], ['198.51.100.0/24', true], ['198.51.100.7/24', true],
    ['198.51.100.7/00024', true], ['2001:db8::/32', true], ['2001:db8::1', true],
    ['2001:db8:0:0:0:0:0:1', true], ['::ffff:192.0.2.1', true], ['::ffff:192.0.2.0/120', true],
    [' 198.51.100.7 ', true], ['198.51', false], ['abc', false], ['198.51.100.0/33', false],
    ['198.51..7', false], ['198.51.100.7/', false], ['198.51.100.7/32/1', false], ['198.51.100.07', false],
    ['::ffff:192.0.2.01', false], ['1:2:3:4:5:6:7:8::', false], ['2001:db8::1::2', false],
    ['fe80::1%eth0', false], ['2001:db8::/129', false],
  ])('W1 W34 strict target %s => %s', (input, expected) => expect(validTarget(input)).toBe(expected))
  it('search trims outgoing value and empty query is absent', () => {
    const f = { status: 'all', dir: 'all', win: '24h', q: ' 198.51.100.7 ', page: 1 }
    expect(listParams(f, 'all', now)).toEqual({ dst_ip: '198.51.100.7', limit: 50, offset: 0 })
    expect(listParams({ ...f, q: '' }, 'all', now)).toEqual({ limit: 50, offset: 0 })
  })
})
describe('G-units holders', () => {
  const self = { attack_id: 1, action_id: 11, external_rule_id: 'shared' }
  it('U1 three statuses, pair dedup and self excluded', () => {
    const rows = [
      { ...self, status: 'active' }, { ...self, attack_id: 2, status: 'active' },
      { ...self, attack_id: 2, status: 'delayed' }, { ...self, action_id: 12, status: 'failed' },
      { ...self, attack_id: 3, status: 'withdrawn' }, { ...self, attack_id: 4, status: 'withdrawing' },
      { ...self, attack_id: 5, status: 'scheduled' }, { ...self, attack_id: 6, status: 'pending' },
      { ...self, attack_id: 7, status: 'active', external_rule_id: 'different' },
    ]
    expect(otherHolders(rows, self)).toBe(2)
  })
  it('W6 U2 synthetic self and another holder of that same ID count zero', () => {
    const row = { ...self, external_rule_id: 'failed-create-5' }
    expect(otherHolders([{ ...row, attack_id: 2, status: 'failed' }], row)).toBe(0)
  })
  it('U3 synthetic prefix is case sensitive', () => {
    expect(isSyntheticRuleId('failed-create-5')).toBe(true)
    expect(isSyntheticRuleId('Failed-create-5')).toBe(false)
    expect(isSyntheticRuleId(null)).toBe(false)
    const row = { ...self, external_rule_id: 'Failed-create-5' }
    expect(otherHolders([{ ...row, attack_id: 2, status: 'failed' }], row)).toBe(1)
    expect(otherHolders(null, self)).toBe(0)
  })
})
describe('G-units curve window and merge', () => {
  it.each([
    ['2026-10-28T11:55:00Z', null, '192.0.2.10/32', '2026-10-28T11:30:00Z', '2026-10-28T12:00:00Z', 5000],
    ['2026-10-28T11:20:00Z', null, '192.0.2.10/32', '2026-10-28T11:12:00Z', '2026-10-28T12:00:00Z', 5000],
    ['2026-10-28T11:20:00Z', '2026-10-28T11:50:00Z', '192.0.2.10/32', '2026-10-28T11:10:00Z', '2026-10-28T12:00:00Z', 5000],
    ['2026-10-28T00:00:00Z', '2026-10-28T09:00:00Z', '192.0.2.10/32', '2026-10-28T03:10:00Z', '2026-10-28T09:10:00Z', 300000],
    ['2026-10-27T06:00:00Z', null, '198.51.100.0/24', '2026-10-27T12:00:00Z', '2026-10-28T12:00:00Z', 300000],
  ])('W10 window %s %s %s', (start, end, dst, from, to, grain) => {
    const w = curveWindow(attack(start, end, dst), now)
    expect(w.bounds.map(n => new Date(n).toISOString())).toEqual([from, to].map(s => s.replace('Z', '.000Z')))
    expect(w.grain).toBe(grain)
  })
  it.each([
    ['2026-10-28T12:00:07Z', 5000, '2026-10-28T11:00:00Z', '2026-10-28T12:00:00Z'],
    ['2026-10-28T11:57:30Z', 300000, '2026-10-28T11:00:00Z', '2026-10-28T11:50:00Z'],
    ['2026-10-28T11:57:30Z', 300000, '2026-10-28T11:55:01Z', '2026-10-28T11:55:01Z'],
  ])('tail alignment %s', (last, grain, start, from) => {
    expect(tailFrom(Date.parse(last), grain, Date.parse(start))).toBe(Date.parse(from))
  })
  it('W9 merge replaces all tail points, not only identical timestamps', () => {
    expect(mergeTail([point(0), point(5), point(10)], [point(5), point(10, 9), point(15)], 5, 0))
      .toEqual([point(0), point(5), point(10, 9), point(15)])
    const base = Date.parse('2026-10-28T11:50:00Z')
    expect(mergeTail([point(base - 5000), point(base + 5000), point(base + 10000)], [point(base)], base, base))
      .toEqual([point(base)])
  })
  it('four whole-window conditions and prior-day stale last point', () => {
    expect(wholeCurve([point(10)], 300000, 5000, 0, false)).toBe(true)
    expect(wholeCurve([], 5000, 5000, 0, false)).toBe(true)
    expect(wholeCurve([point(10)], 5000, 5000, 11, false)).toBe(true)
    expect(wholeCurve([point(10)], 5000, 5000, 0, true)).toBe(true)
    expect(wholeCurve([point(10)], 5000, 5000, 0, false)).toBe(false)
    const request = curveRequest(attack('2026-10-27T20:00:00Z'), Date.parse('2026-10-28T06:00:00Z'),
      [point(Date.parse('2026-10-27T23:55:00Z'))], 300000)
    expect(request.whole).toBe(true)
    expect(request.params.from).toBe('2026-10-28T00:00:00.000Z')
    expect(request.to - request.from).toBe(21600000)
  })
  it('threshold existence includes zero and rejects percent/incomplete rate lines', () => {
    const a = attack('2026-10-28T11:00:00Z')
    expect(threshold(a, { state: 'active', expires_in: 0, threshold_value: 0, threshold_unit: 'pps' }))
      .toEqual({ metric: 'pps', line: 0, pct: undefined })
    expect(threshold(a, { state: 'active', expires_in: 0, threshold_value: 80, threshold_unit: 'pct' }))
      .toEqual({ metric: 'pps', line: undefined, pct: 80 })
    expect(threshold(a, { state: 'active', expires_in: 0, threshold_value: 80 }).line).toBeUndefined()
  })
})
describe('G-units actions, status and formats', () => {
  const a = attack('2026-10-28T11:00:00Z')
  const row = { trigger_phase: 'on_detected', status: 'success', action_type: 'bgp', connector_id: 1,
    external_rule_id: '192.0.2.0/24|defense', action_id: 12, attack_id: 999 }
  it('old six force guards and four-key body use route id', () => {
    expect(canForceRemoveRow(row, a)).toBe(true)
    for (const change of [{ trigger_phase: 'on_expired' }, { status: 'failed' }, { action_type: 'webhook' },
      { connector_id: null }, { external_rule_id: '' }]) expect(canForceRemoveRow({ ...row, ...change }, a)).toBe(false)
    expect(canForceRemoveRow(null, a)).toBe(false)
    expect(canForceRemoveRow(row, { ...a, ended_at: '2026-10-28T12:00:00Z' })).toBe(false)
    expect(forceBody(1, row)).toEqual({ attack_id: 1, action_id: 12, connector_id: 1,
      external_rule_id: '192.0.2.0/24|defense' })
  })
  it.each([['', true], ['0', true], ['600', true], ['86400', true], ['86401', false], ['-1', false],
    ['01', false], ['1.5', false], [' ', false]])('hold %s => %s', (raw, expected) => {
    expect(holdInputValid(raw)).toBe(expected)
  })
  it('W4 three expiration URLs and W5 four result branches', () => {
    expect(expireURL(1, '')).toBe('/api/attacks/1/expire')
    expect(expireURL(1, '0')).toBe('/api/attacks/1/expire?hold_seconds=0')
    expect(expireURL(1, '600')).toBe('/api/attacks/1/expire?hold_seconds=600')
    expect(expireResult(1, '', 'db')).toEqual({ tone: 'warn', key: 'expiredNotHeld', values: { id: 1, n: 0 } })
    expect(expireResult(1, '', 'tracker').key).toBe('expiredGlobal')
    expect(expireResult(1, '0', 'tracker').key).toBe('expiredNoHold')
    expect(expireResult(1, '600', 'tracker').key).toBe('expiredHeld')
  })
  it('status branches distinguish untracked, excluded and capped IDs', () => {
    const active = { attacks: [a], timers: {}, active_count: 1, returned: 1 }
    expect(statusInfo(a, active).key).toBe('untracked')
    expect(statusInfo(a, { ...active, attacks: [] }).tip).toBe('pending')
    expect(statusInfo(a, { ...active, attacks: [], active_count: 1001, returned: 1000 }).tip).toBe('truncated')
    expect(statusInfo(a, undefined, 'backend failed').tip).toBe('backend failed')
    expect(statusInfo(a, { ...active, timers: { 1: { state: 'expiring', expires_in: 61 } } }).key).toBe('falling')
    expect(statusInfo(a, { ...active, timers: { 1: { state: 'active', expires_in: 0 } } }).key).toBe('breaching')
  })
  it('aggregation sums packets, rounds percentage and takes ten', () => {
    const flows = [{ src_ip: 'a', packets: 3 }, { src_ip: 'b', packets: 2 }, { src_ip: 'a', packets: 1 }]
    expect(aggregateTop(flows, 'src_ip')).toEqual([{ key: 'a', pct: '66.7' }, { key: 'b', pct: '33.3' }])
    expect(aggregateTop(Array.from({ length: 11 }, (_, i) => ({ src_ip: String(i), packets: i + 1 })), 'src_ip'))
      .toEqual([{ key: '10', pct: '16.7' }, { key: '9', pct: '15.2' }, { key: '8', pct: '13.6' },
        { key: '7', pct: '12.1' }, { key: '6', pct: '10.6' }, { key: '5', pct: '9.1' },
        { key: '4', pct: '7.6' }, { key: '3', pct: '6.1' }, { key: '2', pct: '4.5' }, { key: '1', pct: '3.0' }])
  })
  it('protocols, flags, bytes and JSON preserve exact values', () => {
    expect([1, 2, 6, 17, 47, 50, 58, 99].map(protoName))
      .toEqual(['ICMP', 'IGMP', 'TCP', 'UDP', 'GRE', 'ESP', 'ICMPv6', 99])
    expect(formatTCPFlags(0x12)).toBe('SYN ACK'); expect(formatTCPFlags(0)).toBe('...')
    expect(formatTCPFlags(0x12, 17)).toBe('-')
    expect([1023, 1024, 1572864].map(bytes1024)).toEqual(['1023 B', '1.0 K', '1.5 M'])
    expect(formattedJSON('{"a":1}')).toBe('{\n  "a": 1\n}')
    expect(formattedJSON('bad JSON')).toBe('bad JSON'); expect(formattedJSON('')).toBe('—')
    const local = new Date(2026, 9, 28, 1, 2, 3).toISOString()
    expect(fullDateTime(local)).toBe('2026-10-28 01:02:03'); expect(dateTime(local)).toBe('10-28 01:02:03')
  })
  it('connector names skip blank manual rows and separate colliding connector IDs', () => {
    const rows = [{ action_type: 'manual_override', connector_id: 1, connector_name: '' },
      { action_type: 'bgp', connector_id: 1, connector_name: 'Transit' },
      { action_type: 'xdrop', connector_id: 1, action_id: 11, connector_name: 'Edge' }]
    expect(connectorName(rows, { connector_id: 1, action_id: 11 }, 'xdrop')).toBe('Edge')
    expect(connectorName(rows, { connector_id: 1 }, 'bgp')).toBe('Transit')
  })
})
describe('G-shared additions', () => {
  it('confirm optional label/tone and unchanged default label', async () => {
    const props = { modelValue: true, title: 'test', description: '', action: async () => {} }
    const w = render(XConfirm, { props })
    expect(w.get('.primary').text()).toBe('确认')
    await w.setProps({ confirmLabel: '结束', tone: 'danger' })
    expect(w.get('.danger').text()).toBe('结束')
  })
  it('timeout is true only for the timeout branch; network remains false', async () => {
    vi.useFakeTimers()
    vi.mocked(fetch).mockImplementationOnce((_path, options) => new Promise((_resolve, reject) => {
      options?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
    }))
    const timed = request('/api/test', { timeout: 100 }).catch(e => e)
    await vi.advanceTimersByTimeAsync(100)
    expect(await timed).toMatchObject({ status: 0, timeout: true, message: '请求超时' })
    vi.mocked(fetch).mockRejectedValueOnce(new Error('offline'))
    await expect(request('/api/test')).rejects.toMatchObject({ status: 0, timeout: false, message: 'offline' })
  })
  it('threshold line, metric label and ceiling; omitting it restores original DOM', async () => {
    const props = { points: [point(0, 5), point(5, 10)], selected: ['total'], slots: {},
      bounds: [0, 5] as [number, number] }
    const w = render(XChart, { props }), original = w.html()
    await w.setProps({ threshold: 1000 })
    expect(w.get('.threshold text').text()).toBe('阈值 1k')
    expect(Number(w.get('.threshold line').attributes('y1'))).toBeGreaterThanOrEqual(8)
    expect(w.findAll('.grid text').map(n => n.text())).toContain('2k')
    await w.setProps({ threshold: undefined })
    expect(w.html()).toBe(original)
  })
})
