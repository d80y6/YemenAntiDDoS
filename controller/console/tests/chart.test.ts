import { describe, it, expect, vi } from 'vitest'
import { nextTick, defineComponent, h } from 'vue'
import { render } from './helpers'
import XChart from '../src/components/chart/XChart.vue'
import XSpark from '../src/components/chart/XSpark.vue'
import DecoderPicker from '../src/components/chart/DecoderPicker.vue'
import { selection, choose, loadSelection } from '../src/components/chart/selection'
import { niceStep, mergeBands, assignSlots, downsample, zoomWindow, formatTick, segments, nearest,
  type Point, type Band } from '../src/components/chart/math'
const point = (time: number, n = 2): Point => ({ time, values: { tcp: n, udp: n + 1, total: n + 3 } })
const band = (start: number, end: number | null): Band => ({ start, end, target: '10.1.0.0/16', type: 'UDP flood' })
import { pointer } from './pointer'
describe('G-chart pure functions', () => {
  it.each([
    [0, 1], [.1, .1], [.11, .2], [.2, .2], [.21, .5], [.5, .5], [.51, 1], [1, 1],
    [1.01, 2], [2, 2], [2.01, 5], [5, 5], [5.01, 10], [10, 10], [10.01, 20],
  ])('niceStep(%s) = %s', (value, result) => { expect(niceStep(value)).toBe(result) })
  it.each([
    ['disjoint', [band(0, 2), band(3, 4)], [[0, 2], [3, 4]]],
    ['overlap W1', [band(0, 4), band(2, 6)], [[0, 6]]],
    ['contained', [band(0, 8), band(2, 3)], [[0, 8]]],
    ['touching', [band(0, 2), band(2, 4)], [[0, 4]]],
    ['ongoing', [band(0, 2), band(3, null)], [[0, 2], [3, 10]]],
  ] as const)('mergeBands %s', (_name, input, expected) => { expect(mergeBands([...input], 10)).toEqual(expected) })
  it('W2 removing UDP never changes ICMP color, GRE fills smallest free slot', () => {
    expect(assignSlots(['tcp', 'udp', 'icmp'])).toEqual({ tcp: 1, udp: 2, icmp: 3 })
    expect(assignSlots(['tcp', 'icmp', 'gre'], { tcp: 1, udp: 2, icmp: 3 }))
      .toEqual({ tcp: 1, icmp: 3, gre: 2 })
    expect(assignSlots(['total', 'tcp'])).toEqual({ tcp: 1 })
  })
  it('downsample keeps endpoints with literal interior indices', () => {
    expect(downsample([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], 4)).toEqual([0, 3, 6, 9])
    expect(downsample([1, 2], 4)).toEqual([1, 2])
  })
  it('zoomWindow pans half a window without passing bounds', () => {
    expect(zoomWindow([20, 60], [0, 100], -.5)).toEqual([0, 40])
    expect(zoomWindow([70, 100], [0, 100], .5)).toEqual([70, 100])
    expect(zoomWindow([0, 200], [0, 100])).toEqual([0, 100])
  })
  it('formatTick delegates to existing formatters', () => {
    expect(formatTick(1000, 'pps')).toBe('1k')
    expect(formatTick(1000000, 'bps')).toBe('1M')
  })
  it('exactly twice the grain connects; greater than twice splits before downsampling', () => {
    expect(segments([point(0), point(10000), point(20001)], 5000).map(p => p.map(x => x.time)))
      .toEqual([[0, 10000], [20001]])
    const full = Array.from({ length: 1000 }, (_, i) => point(i * 5000))
    const result = segments(full, 5000, 4)
    expect(result).toHaveLength(1)
    expect(result[0]!.map(p => p.time)).toEqual([0, 1665000, 3330000, 4995000])
  })
  it('independent nearest timestamps at 3.2 seconds', () => {
    expect(nearest([point(0), point(5000), point(10000)], 3200)?.time).toBe(5000)
    expect(nearest([point(2000), point(7000), point(12000)], 3200)?.time).toBe(2000)
  })
})
describe('G-chart rendering', () => {
  const props = () => ({ points: [point(0), point(5000)], bounds: [0, 10000] as [number, number],
    selected: ['tcp'], slots: { tcp: 1 } })
  it('zero-valued points render a 0–1 axis and line, one point renders only a dot', async () => {
    const w = render(XChart, { props: { ...props(), points: [point(0, 0), point(5000, 0)] } })
    expect(w.find('svg').exists()).toBe(true)
    expect(w.findAll('.grid text').slice(0, 2).map(t => t.text())).toEqual(['0', '1'])
    expect(w.get('.curve').attributes('d')).toBe('M44,180 L318,180')
    await w.setProps({ points: [point(0)] })
    expect(w.find('.curve').exists()).toBe(false)
    expect(w.findAll('circle')).toHaveLength(1)
  })
  it.each([
    [{ loading: true }, '加载中…'], [{ selected: [] }, '未选择 decoder'],
    [{ points: [] }, '暂无数据'], [{ error: 'backend 原文' }, 'backend 原文'],
  ])('empty/error state %j has no pointer handlers', async (override, text) => {
    const w = render(XChart, { props: { ...props(), ...override } })
    expect(w.text()).toContain(text)
    if (text === '未选择 decoder') expect(w.text()).not.toContain('暂无数据')
    expect(w.find('svg').exists()).toBe(false)
    expect(w.find('.chart-tip').exists()).toBe(false)
  })
  it('total is the bottom line, overlaps merge, outbound has no bands', async () => {
    const w = render(XChart, { props: { ...props(), selected: ['tcp', 'total'],
      bands: [band(0, 6000), band(5000, 10000)] } })
    expect(w.findAll('.curve').map(p => p.attributes('data-key'))).toEqual(['total', 'tcp'])
    expect(w.findAll('rect.band')).toHaveLength(1)
    await w.setProps({ outbound: true })
    expect(w.findAll('rect.band')).toHaveLength(0)
  })
  it('offset input timestamps hover at 5 s, output at 2 s; tooltips contain raw exact values', async () => {
    const input = render(XChart, { props: { ...props(), points: [point(0), point(5000, 15), point(10000)] } })
    const output = render(XChart, { props: { ...props(), points: [point(2000, 22), point(7000), point(12000)] } })
    await pointer(input.get('svg').element, 'pointermove', 219.36)
    await pointer(output.get('svg').element, 'pointermove', 219.36)
    expect(input.get('.chart-tip').text()).toContain('tcp: 15 pps')
    expect(output.get('.chart-tip').text()).toContain('tcp: 22 pps')
    expect(input.get('.hover-mark').attributes('cx')).toBe('318')
    expect(output.get('.hover-mark').attributes('cx')).toBe('153.60000000000002')
  })
  it('drag requires five points; Esc cancels; absolute endpoints survive new points', async () => {
    const w = render(XChart, { props: { ...props(), zoomable: true,
      points: [0, 1000, 2000, 3000, 4000, 5000, 6000].map(n => point(n)) } })
    await pointer(w.get('svg').element, 'pointerdown', 44)
    await pointer(w.get('svg').element, 'pointerup', 71.4)
    expect(w.emitted('update:window')).toBeUndefined()
    await pointer(w.get('svg').element, 'pointerdown', 44)
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await pointer(w.get('svg').element, 'pointerup', 400)
    expect(w.emitted('update:window')).toBeUndefined()
    await pointer(w.get('svg').element, 'pointerdown', 44)
    await pointer(w.get('svg').element, 'pointerup', 318)
    expect(w.emitted('update:window')?.[0]).toEqual([[0, 5000]])
    await w.setProps({ window: [1000, 5000] })
    const before = w.findAll('.grid text').slice(-4).map(t => t.text())
    await w.setProps({ points: [...w.props('points'), point(20000)], bounds: [0, 20000] })
    expect(w.props('window')).toEqual([1000, 5000])
    expect(w.findAll('.grid text').slice(-4).map(t => t.text())).toEqual(before)
  })
  it('spark empty text, single dot and neutral total color', () => {
    expect(render(XSpark, { props: { values: [] } }).text()).toBe('没有近期读数')
    expect(render(XSpark, { props: { values: [2] } }).findAll('circle')).toHaveLength(1)
  })
})
describe('G-picker', () => {
  it('W3 full sequence: 3 → fourth disabled → clear → defaults → full; total never occupies a slot', async () => {
    loadSelection()
    const parent = defineComponent({ setup: () => () => h('div', [h(DecoderPicker), h(XChart, {
      points: [point(0)], bounds: [0, 10000], selected: selection.keys, slots: selection.slots,
    })]) })
    const w = render(parent)
    await w.get('.decoder-picker > button').trigger('click')
    const check = (label: string) => w.findAll('[role=checkbox]').find(b => b.text().includes(label))!
    expect(selection.keys).toEqual(['tcp', 'udp'])
    await check('icmp').trigger('click')
    expect(selection.keys).toEqual(['tcp', 'udp', 'icmp'])
    expect(check('gre').attributes('disabled')).toBeDefined()
    expect(w.text()).toContain('已选满 3 条，先取消一条')
    await check('合计').trigger('click')
    expect(selection.keys).toEqual(['tcp', 'udp', 'icmp', 'total'])
    await w.findAll('.text-button').find(b => b.text() === '清空')!.trigger('click')
    expect(selection.keys).toEqual([])
    expect(w.text()).toContain('未选择 decoder')
    expect(check('gre').attributes('disabled')).toBeUndefined()
    await w.findAll('.text-button').find(b => b.text() === '恢复默认')!.trigger('click')
    expect(selection.keys).toEqual(['tcp', 'udp'])
    await check('icmp').trigger('click')
    expect(check('gre').attributes('disabled')).toBeDefined()
  })
  it('legacy five keys filter invalid names and truncate to three; clear reloads defaults', () => {
    localStorage.setItem('xsight.chart.visibleDecoders', '["bad","tcp","udp","icmp","gre","esp"]')
    loadSelection()
    expect(selection.keys).toEqual(['tcp', 'udp', 'icmp'])
    choose([]); loadSelection()
    expect(selection.keys).toEqual(['tcp', 'udp'])
  })
})
