import { it, expect, vi } from 'vitest'
import { dtRate } from '../src/format'
import { prefixBody, prefixBaseline } from '../src/views/prefixes/data'
import { recommendation, globalTemplate, ruleForm, changeUnit, ruleBody, flatBody,
  decoderOptions, zeroHint, pctError } from '../src/views/thresholds/data'
import { profiles, exceededValues, configBody } from '../src/views/baseline/data'
import { DECODERS } from '../src/config/decoders'
it.each([
  [999500, '1.0M'], [999999, '1.0M'], [999950000, '1.0G'], [12345, '12K'], [1420000, '1.4M'],
  [1499, '1K'], [500, '500'], [-1500, '-2K'], [NaN, '—'],
])('G-units W1 dtRate %s = %s', (n, value) => { expect(dtRate(n)).toBe(value) })
it('G-units W2 W3 W4 prefix bodies exact keys and numeric/null identifiers', () => {
  const form = { prefix: ' 192.0.2.0/24 ', name: 'Office', ip_group: 'office', parent_id: '',
    threshold_template_id: '7', enabled: false }
  expect(prefixBody(form, false)).toEqual({ prefix: '192.0.2.0/24', name: 'Office', ip_group: 'office',
    parent_id: null, threshold_template_id: 7 })
  expect(prefixBody({ ...form, parent_id: '2', threshold_template_id: '' }, true)).toEqual({ name: 'Office',
    ip_group: 'office', parent_id: 2, threshold_template_id: null, enabled: false })
  expect(prefixBody(form, true)).toEqual({ name: 'Office', ip_group: 'office', parent_id: null,
    threshold_template_id: 7, enabled: false })
})
it.each([
  [false, [], { text: '—' }], [true, [], { text: '—' }],
  [true, [{ prefix: 'a', active: false }], { text: '⏳', tip: 'prefixes.waitBaseline' }],
  [true, [{ prefix: 'a', active: true, p95_pps: 150, recommend_pps: 300 }], { text: 'P95 150', next: '→ 300' }],
])('G-units prefix baseline %j', (enabled, rows, result) => {
  expect(prefixBaseline({ prefix: 'a', enabled }, rows)).toEqual(result)
})
const prefixes = [{ prefix: 'a' }, { prefix: 'b' }, { prefix: 'c' }]
const baselines = [{ prefix: 'a', active: false, recommend_pps: 900, recommend_bps: 9000 },
  { prefix: 'b', active: true, recommend_pps: 300, recommend_bps: 3000 },
  { prefix: 'c', active: true, recommend_pps: 0, recommend_bps: 0 }]
it.each([
  [{ direction: 'sends', decoder: 'tcp' }, { text: '—', tip: 'templates.recommendInboundOnly' }],
  [{ direction: 'receives', decoder: 'tcp' }, { key: 'templates.prefixLevel' }],
  [{ decoder: 'ip', unit: 'pps' }, { text: '→ 300' }],
  [{ decoder: '', unit: 'pct' }, { text: '→ 300' }],
  [{ decoder: 'ip', unit: 'bps' }, { text: '→ 3K' }],
])('G-units W19 W20 W21 recommendation %j', (rule, expected) => {
  expect(recommendation(rule, prefixes, baselines)).toEqual(expected)
})
it('G-units recommendation waiting and min–max ignore zero, unbound, inactive', () => {
  expect(recommendation({ decoder: 'ip' }, [], baselines)).toEqual({ text: '⏳', tip: 'templates.waitBaseline' })
  expect(recommendation({ decoder: '' }, [{ prefix: 'a' }], baselines)).toEqual({
    text: '⏳', tip: 'templates.waitBaseline' })
  expect(recommendation({ decoder: 'ip' }, prefixes, [...baselines,
    { prefix: 'c', active: true, recommend_pps: 500 }, { prefix: 'd', active: true, recommend_pps: 999 }]))
    .toEqual({ text: '→ 300–500' })
  expect(recommendation({ decoder: 'ip' }, prefixes, [
    { prefix: 'a', active: true, recommend_pps: 300 }, { prefix: 'b', active: true, recommend_pps: 300 },
  ])).toEqual({ text: '→ 300–300' })
})
it('G-units W15 global uses exact CIDR rather than counts', () => {
  expect(globalTemplate([{ prefix: '0.0.0.0/0', prefix_count: 0 }])).toBe(true)
  expect(globalTemplate([{ prefix: '0.0.0.0/1', prefix_count: 9 }])).toBe(false)
})
it('G-units W17 W18 defaults unit transitions and zero backfill', () => {
  expect(ruleForm(true)).toEqual({ domain: 'subnet', direction: 'receives', decoder: 'tcp_syn', unit: 'pps',
    comparison: 'over', value: 500, inheritable: true })
  expect(ruleForm(false, { value: 0 }).value).toBe(0)
  expect(ruleForm(true, { value: 0 }).domain).toBe('internal_ip')
  const form = ruleForm()
  changeUnit(form, 'pct'); expect(form.value).toBe(100)
  changeUnit(form, 'bps'); expect(form.value).toBe(500)
})
it.each([[0, 'over', true], [0, 'under', false], [5, 'over', false]])(
  'G-units W35 zero hint %s %s', (value, comparison, expected) => {
    expect(zeroHint({ value, comparison })).toBe(expected)
  })
it('G-units pct defense returns literal warning and performs no request', () => {
  const fetcher = vi.fn()
  vi.stubGlobal('fetch', fetcher)
  expect(pctError({ unit: 'pct', value: 101 }, 'pct 阈值必须在 1–100 之间')).toBe('pct 阈值必须在 1–100 之间')
  expect(pctError({ unit: 'pct', value: 100 }, 'warning')).toBe('')
  expect(fetcher).not.toHaveBeenCalled()
})
it('G-units W14 W23 rule seven keys and flat eight keys', () => {
  const form = { domain: 'internal_ip', direction: 'sends', decoder: 'tcp', unit: 'pps', comparison: 'under',
    value: 0, inheritable: false, response_id: 2, enabled: true, id: 7, prefix_id: 3 }
  expect(ruleBody(form)).toEqual({ domain: 'internal_ip', direction: 'sends', decoder: 'tcp', unit: 'pps',
    comparison: 'under', value: 0, inheritable: false })
  expect(flatBody(form)).toEqual({ prefix_id: 3, domain: 'internal_ip', direction: 'receives', decoder: 'tcp',
    unit: 'pps', comparison: 'under', value: 0, inheritable: false })
})
it('G-units W22 decoders ip first total absent exact order', () => {
  expect(decoderOptions.map(d => d.value)).toEqual(['ip', 'tcp', 'udp', 'icmp', 'tcp_syn', 'tcp_ack', 'tcp_rst',
    'tcp_fin', 'gre', 'esp', 'igmp', 'ip_other', 'fragment', 'bad_fragment', 'invalid'])
  expect(decoderOptions).toHaveLength(15)
  expect(decoderOptions.slice(1).map(d => d.value)).toEqual(DECODERS.filter(d => d.key !== 'total').map(d => d.key))
})
it('G-units W28 W30 profiles sort and hover includes four literal numbers', () => {
  expect(profiles([{ prefix: 'z' }, { prefix: 'a' }]).map(p => p.prefix)).toEqual(['a', 'z'])
  expect(profiles(null)).toEqual([])
  expect(exceededValues({ current_pps: 100, current_bps: 20000, thresh_pps: 2000, thresh_bps: 16000 }))
    .toEqual({ pps: '100', bps: '20K', tpps: '2K', tbps: '16K' })
  expect(configBody({ enabled: true, deviation_min: 50, deviation_max: 150, stable_weeks: 6,
    min_pps: 2000, min_bps: 16000, ewma_alpha: 0.25 })).toEqual({ enabled: true, deviation_min: 50,
    deviation_max: 150, stable_weeks: 6, min_pps: 2000, min_bps: 16000, ewma_alpha: 0.25 })
})
