import { it, expect, vi, describe, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { i18n } from '../src/i18n'
import { render, response } from './helpers'
import { pointer } from './pointer'
import { mockReply } from '../mock/data'
import OverviewPage from '../src/views/overview/Overview.vue'
import TrafficPage from '../src/views/traffic/Traffic.vue'
import XChart from '../src/components/chart/XChart.vue'
import XListbox from '../src/components/XListbox.vue'
import XSeg from '../src/components/XSeg.vue'
import { allAttacks } from '../src/views/overview/data'
import { briefs, containsCIDR, normalize } from '../src/api/data'
import { choose, loadSelection } from '../src/components/chart/selection'
beforeEach(() => loadSelection())
function fixture(mode = 'normal', change?: (path: string, body: any) => any) {
  const stamp = Date.now()
  const fetcher = vi.fn(async (raw: any) => {
    const path = String(raw), reply = mockReply(path, mode, stamp)
    return response(reply.status, change ? change(path, reply.body) : reply.body)
  })
  vi.stubGlobal('fetch', fetcher)
  return fetcher
}
function calls(path: string) { return vi.mocked(fetch).mock.calls.filter(([p]) => String(p).split('?')[0] === path) }
const params = (call: any) => new URL(String(call[0]), 'http://localhost').searchParams
async function page(which: 'overview' | 'traffic', url = '/' + which, mode = 'normal',
  change?: (path: string, body: any) => any) {
  fixture(mode, change)
  const component = which === 'overview' ? OverviewPage : TrafficPage
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/overview', component: OverviewPage }, { path: '/traffic', component: TrafficPage },
    { path: '/attacks/:id', component: { template: '<p>detail</p>' } },
    { path: '/:pathMatch(.*)*', component: { template: '<p>other</p>' } },
  ] })
  await router.push(url)
  const w = render(component, { global: { plugins: [i18n, router] } })
  await flushPromises()
  return { w, router }
}
const fixed = () => { vi.useFakeTimers(); vi.setSystemTime(new Date('2026-10-28T00:00:00Z')) }
describe('G-overview', () => {
  it('W6 KPI active+delayed, shared XDrop=2; missing current is —, zero is 0 and peak bps=0 is —', async () => {
    fixed()
    const { w, router } = await page('overview')
    expect(w.findAll('.kpi .v').map(e => e.text())).toEqual(['1.00K', '3', '2 / 3', '3', '2'])
    expect(w.findAll('.kpi')[4]!.attributes('title')).toContain('规则记录')
    const rows = w.findAll('table')[0]!.findAll('tbody tr')
    expect(rows.slice(0, 3).map(r => r.findAll('td')[2]!.text())).toEqual(['123', '0', '—'])
    expect(rows[1]!.findAll('td')[2]!.get('span').attributes('title')).toContain('/ —')
    await rows[0]!.trigger('click'); await flushPromises()
    expect(router.currentRoute.value.path).toBe('/attacks/1')
  })
  it('current maps two distinct positive IDs and entire missing current is safe', async () => {
    const { w } = await page('overview', '/overview', 'normal', (path, body) => {
      if (path.includes('attacks/active')) body.current = { '1': { pps: 321 }, '2': { pps: 456 } }
      return body
    })
    expect(w.findAll('table')[0]!.findAll('tbody tr').slice(0, 3).map(r => r.findAll('td')[2]!.text()))
      .toEqual(['321', '456', '—'])
    w.unmount()
    const second = await page('overview', '/overview', 'normal', (path, body) => {
      if (path.includes('attacks/active')) delete body.current
      return body
    })
    expect(second.w.findAll('table')[0]!.findAll('tbody tr').slice(0, 3).map(r => r.findAll('td')[2]!.text()))
      .toEqual(['—', '—', '—'])
  })
  it('node rates and heartbeat use new fields; absent node is —; keyboard separator persists', async () => {
    fixed()
    const { w } = await page('overview')
    const rows = w.findAll('table')[2]!.findAll('tbody tr')
    expect(rows[0]!.text()).toContain('1.00K')
    expect(rows[0]!.text()).toContain('5 秒前')
    expect(rows[1]!.text()).toContain('落后 2')
    expect(rows[2]!.findAll('td')[3]!.text()).toBe('—')
    expect(rows[1]!.findAll('td')[6]!.text()).toBe('—')
    await w.get('[role=separator]').trigger('keydown', { key: 'ArrowRight' })
    expect(JSON.parse(localStorage.getItem('xs-ov-layout')!).ratio).toBe(57)
  })
  it('W10 51 active briefs produce exactly 50+1 and all 51 rows carry pills', async () => {
    const { w } = await page('overview', '/overview', 'bulk')
    const batch = calls('/api/attacks/mitigation-brief').map(params)
      .map(p => p.get('ids')!.split(',')).filter(ids => Number(ids[0]) < 1000)
    expect(batch.map(ids => ids.length)).toEqual([50, 1])
    const rows = w.findAll('table')[0]!.findAll('tbody tr')
    expect(rows.slice(0, 51).every(row => row.text().includes('XDrop 1') && row.text().includes('BGP 1'))).toBe(true)
    expect(rows).toHaveLength(252)
  })
  it('W11 201 ended rows use two pages; last row owns a band and is present in table', async () => {
    fixed()
    const { w } = await page('overview', '/overview', 'bulk')
    const ended = calls('/api/attacks').filter(c => params(c).get('status') === 'expired')
    expect(ended.map(c => params(c).get('offset'))).toEqual(['0', '200'])
    expect(w.findAll('table')[0]!.findAll('tbody tr')).toHaveLength(252)
    expect(w.findAllComponents(XChart)[0]!.props('bands')).toContainEqual({
      start: Date.parse('2026-10-27T23:45:10Z'), end: Date.parse('2026-10-27T23:45:20Z'),
      target: '10.1.2.0/24', type: 'udp_flood',
    })
    expect(w.findAllComponents(XChart)[0]!.findAll('rect.band')).toHaveLength(2)
    const overlap = calls('/api/attacks').filter(c => !params(c).has('status'))
    expect(overlap.map(c => params(c).get('offset'))).toEqual(['0', '200'])
    expect(new Set(overlap.map(c => params(c).get('ended_after'))).size).toBe(1)
  })
  it('page two failure retains prior rows/bands and displays original error', async () => {
    fixed()
    const { w } = await page('overview', '/overview', 'bulk')
    const beforeBands = w.findAllComponents(XChart)[0]!.props('bands')
    const old = vi.mocked(fetch).getMockImplementation()!
    vi.mocked(fetch).mockImplementation(async (...args) => params(args).get('offset') === '200'
      ? response(500, { error: 'page two failed' }) : old(...args))
    await vi.advanceTimersByTimeAsync(60000); await flushPromises()
    expect(w.findAll('table')[0]!.findAll('tbody tr')).toHaveLength(252)
    expect(w.findAllComponents(XChart)[0]!.props('bands')).toEqual(beforeBands)
    expect(w.text()).toContain('page two failed')
  })
  it('2000 caps have distinct text and never request page 11', async () => {
    const { w } = await page('overview', '/overview', 'capped')
    expect(w.text()).toContain('仅显示最近 2000 条已结束攻击')
    expect(w.text()).toContain('底纹仅取最近 2000 条攻击')
    expect(calls('/api/attacks').every(c => Number(params(c).get('offset')) <= 1800)).toBe(true)
    expect(calls('/api/attacks')).toHaveLength(20)
  })
  it('101st active attack missing from active response is restored by overlap route with no status', async () => {
    fixed()
    const { w } = await page('overview', '/overview', '101', (path, body) => {
      if (path.split('?')[0] === '/api/attacks' && !new URL(path, 'http://localhost').searchParams.has('status')) {
        body.attacks = [{ ...body.attacks.at(-1), id: 101, started_at: '2026-10-27T23:46:00Z', ended_at: null }]
        body.total = 1
      }
      return body
    })
    expect(w.findAllComponents(XChart)[0]!.props('bands')).toContainEqual({
      start: Date.parse('2026-10-27T23:46:00Z'), end: null, target: '10.1.2.0/24', type: 'udp_flood',
    })
    expect(calls('/api/attacks/active')).toHaveLength(1)
    expect(params(calls('/api/attacks').find(c => !params(c).has('status'))!).has('status')).toBe(false)
  })
  it('W7 null arrays render all three specific empty slots; zero IDs mean zero brief calls', async () => {
    const { w } = await page('overview', '/overview', 'null')
    expect(w.text()).toContain('24 小时内没有攻击')
    expect(w.text()).toContain('没有近期前缀流量')
    expect(w.text()).toContain('尚未注册节点')
    expect(calls('/api/attacks/mitigation-brief')).toHaveLength(0)
    expect(w.findAll('.kpi .v').map(e => e.text())).toEqual(['0', '0', '0 / 0', '0', '0'])
  })
  it('overview selection is reused by traffic page', async () => {
    const a = await page('overview'); choose(['icmp', 'gre']); a.w.unmount()
    const b = await page('traffic')
    expect(b.w.findComponent(XChart).props('selected')).toEqual(['icmp', 'gre'])
    choose([]); b.w.unmount()
    const c = await page('overview')
    expect(c.w.findComponent(XChart).props('selected')).toEqual([])
  })
})
describe('G-traffic', () => {
  it('both KPI uses deduplicated active nodes and separate prefix counts; Top100 and node mode tags', async () => {
    const { w } = await page('traffic', '/traffic?direction=both')
    expect(w.findAll('.kpi .v')[3]!.text()).toBe('入 4 / 出 7')
    expect(w.text()).toContain('活跃节点 3')
    expect(w.findAllComponents(XSeg).at(-1)!.props('options').map((o: any) => o.value))
      .toEqual(['10', '20', '50', '100'])
    expect(w.text()).toContain('edge-a · XDP'); expect(w.text()).toContain('flow-b · FLOW')
    expect(calls('/api/stats/overview').map(c => params(c).get('direction'))).toEqual(['receives', 'sends', 'both'])
    const charts = w.findAllComponents(XChart)
    expect(charts).toHaveLength(2)
    expect(charts[0]!.props('sharedMax')).toBe(charts[1]!.props('sharedMax'))
  })
  it('W5 sends component values are real; missing opposite side is —; actual zero is 0', async () => {
    const { w } = await page('traffic', '/traffic?direction=both')
    const rows = w.findAll('tbody tr')
    const first = rows.find(r => r.text().includes('10.1.0.0/16'))!.findAll('td')
    expect(first[7]!.text()).toBe('0'); expect(first[9]!.text()).toBe('0')
    const last = rows.find(r => r.text().includes('10.3.0.0/16'))!.findAll('td')
    expect(last[2]!.text()).toBe('—'); expect(last[9]!.text()).toBe('4')
  })
  it('W4 bps sorting uses tcp_bps, outbound sort orders 999 before 0', async () => {
    const { w } = await page('traffic', '/traffic?direction=both&metric=bps', 'normal', (path, body) => {
      if (path.includes('stats/overview')
        && new URL(path, 'http://localhost').searchParams.get('direction') === 'receives') {
        body.top_prefixes[0].tcp_pps = 999; body.top_prefixes[0].tcp_bps = 1
        body.top_prefixes[1].tcp_pps = 1; body.top_prefixes[1].tcp_bps = 999
      }
      return body
    })
    const th = w.findAll('th').find(e => e.text() === '入 TCP bps')!
    await th.trigger('click'); await th.trigger('click')
    expect(w.findAll('tbody tr')[0]!.text()).toContain('10.2.0.0/16')
    const out = w.findAll('th').find(e => e.text() === '出 PPS')!
    await out.trigger('click'); await out.trigger('click')
    expect(w.findAll('tbody tr')[0]!.text()).toContain('10.3.0.0/16')
  })
  it('URL restores filters and decoders; searchable prefix, offline node, row URL update', async () => {
    const { w, router } = await page('traffic', '/traffic?direction=sends&range=6h&metric=bps&limit=100'
      + '&node=flow-b&prefix=10.1.0.0%2F16&decoders=icmp,gre')
    const selects = w.findAllComponents(XListbox)
    expect(selects[0]!.props('modelValue')).toBe('flow-b')
    expect(selects[0]!.props('options')[2]).toMatchObject({ value: 'flow-b', label: 'flow-b · FLOW（离线）' })
    expect(selects[0]!.props('options')[2]).not.toHaveProperty('disabled')
    expect(selects[1]!.props('mode')).toBe('search')
    expect(w.findComponent(XChart).props('selected')).toEqual(['icmp', 'gre'])
    expect(params(calls('/api/stats/total-timeseries')[0]!).get('resolution')).toBe('5min')
    await w.findAll('tbody tr').find(r => r.text().includes('10.3.0.0/16'))!.trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.prefix).toBe('10.3.0.0/16')
    expect(router.currentRoute.value.query.range).toBe('6h')
    expect(router.currentRoute.value.query.decoders).toBe('icmp,gre')
  })
  it('CIDR whole subnet and address family; local filter matches server dst_ip', async () => {
    expect(containsCIDR('10.1.2.0/24', '10.1.0.0/16')).toBe(true)
    expect(containsCIDR('10.1.0.0/16', '10.1.2.0/24')).toBe(false)
    expect(containsCIDR('10.10.0.1', '10.1.0.0/16')).toBe(false)
    expect(containsCIDR('2001:db8:1::/48', '2001:db8::/32')).toBe(true)
    expect(containsCIDR('2001:db8::/32', '2001:db8:1::/48')).toBe(false)
    expect(containsCIDR('::ffff:10.1.2.3', '10.1.0.0/16')).toBe(false)
    const { w } = await page('traffic', '/traffic?prefix=10.1.2.0%2F24', 'normal', (path, body) => {
      if (path.includes('attacks/active')) body.attacks[0].dst_ip = '10.1.0.0/16'
      return body
    })
    expect(w.findComponent(XChart).props('bands')!.some((b: any) => b.target === '10.1.0.0/16')).toBe(false)
    expect(params(calls('/api/attacks')[0]!).get('dst_ip')).toBe('10.1.2.0/24')
    expect(params(calls('/api/attacks')[0]!).has('node_id')).toBe(false)
  })
  it('clear stays empty in this page, removes decoder URL persistence, refresh restores tcp+udp', async () => {
    const first = await page('traffic', '/traffic?decoders=icmp,gre')
    choose([]); await flushPromises()
    expect(first.w.findComponent(XChart).props('selected')).toEqual([])
    expect(first.router.currentRoute.value.query.decoders).toBeUndefined()
    const url = first.router.currentRoute.value.fullPath
    first.w.unmount()
    loadSelection() // A browser refresh creates a new app and reads storage again.
    const refreshed = await page('traffic', url)
    expect(refreshed.w.findComponent(XChart).props('selected')).toEqual(['tcp', 'udp'])
  })
  it('null bank has specific Top empty text', async () => {
    const { w } = await page('traffic', '/traffic?direction=both', 'null')
    expect(w.text()).toContain('没有近期前缀流量')
    expect(w.findAllComponents(XChart).every(c => c.props('points').length === 0)).toBe(true)
  })
  it('absolute zoom endpoints survive polling; range change resets', async () => {
    fixed()
    const { w } = await page('traffic'), chart = w.getComponent(XChart)
    await pointer(chart.get('svg').element, 'pointerdown', 44)
    await pointer(chart.get('svg').element, 'pointerup', 318)
    expect(chart.props('window')).toEqual([Date.parse('2026-10-27T23:00:00Z'), Date.parse('2026-10-27T23:30:00Z')])
    await vi.advanceTimersByTimeAsync(10000); await flushPromises()
    expect(chart.props('window')).toEqual([Date.parse('2026-10-27T23:00:00Z'), Date.parse('2026-10-27T23:30:00Z')])
    w.findAllComponents(XSeg).find(c => c.props('label') === '时间范围')!.vm.$emit('update:modelValue', '6h')
    await flushPromises(); expect(chart.props('window')).toBeNull()
  })
})
describe('D8 curve poll fake clocks and data shape', () => {
  it('10s → 60s → 10s, changed filters immediate, not due skips, unmount stops every request', async () => {
    fixed()
    const { w } = await page('traffic'), count = () => calls('/api/stats/total-timeseries').length
    expect(count()).toBe(1)
    await vi.advanceTimersByTimeAsync(9999); expect(count()).toBe(1)
    await vi.advanceTimersByTimeAsync(1); expect(count()).toBe(2)
    const ranges = w.findAllComponents(XSeg).find(c => c.props('label') === '时间范围')!
    ranges.vm.$emit('update:modelValue', '6h'); await flushPromises(); expect(count()).toBe(3)
    await vi.advanceTimersByTimeAsync(59999); expect(count()).toBe(3)
    await vi.advanceTimersByTimeAsync(1); expect(count()).toBe(4)
    ranges.vm.$emit('update:modelValue', '1h'); await flushPromises(); expect(count()).toBe(5)
    await vi.advanceTimersByTimeAsync(10000); expect(count()).toBe(6)
    w.findAllComponents(XListbox)[0]!.vm.$emit('update:modelValue', 'flow-b'); await flushPromises()
    expect(count()).toBe(7)
    const before = vi.mocked(fetch).mock.calls.length
    w.unmount(); await vi.advanceTimersByTimeAsync(120000)
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(before)
  })
  it('overview requests timeseries once for both charts; correct resolution/include_extras/from', async () => {
    fixed()
    const { w } = await page('overview')
    expect(calls('/api/stats/total-timeseries')).toHaveLength(1)
    expect(params(calls('/api/stats/total-timeseries')[0]!).get('include_extras')).toBe('true')
    w.findComponent(XSeg).vm.$emit('update:modelValue', '24h'); await flushPromises()
    const curve = params(calls('/api/stats/total-timeseries').at(-1)!)
    expect(curve.get('resolution')).toBe('5min'); expect(curve.get('from')).toBe('2026-10-27T00:00:00.000Z')
    const history = calls('/api/attacks').filter(c => params(c).has('status'))
    expect(params(history[0]!).get('ended_after')).toBe('2026-10-27T00:00:00.000Z')
  })
  it('pagination increments raw count before dedup and stops at empty with fixed params', async () => {
    fixture()
    vi.mocked(fetch).mockImplementation(async (...args) => response(200, {
      attacks: params(args).get('offset') === '0' ? [{ id: 1 }, { id: 1 }] : [], total: 5,
    }))
    expect((await allAttacks({ status: 'expired', ended_after: 'fixed' })).rows).toEqual([{ id: 1 }])
    expect(calls('/api/attacks').map(c => params(c).get('offset'))).toEqual(['0', '2'])
    expect(calls('/api/attacks').map(c => params(c).get('ended_after'))).toEqual(['fixed', 'fixed'])
    expect(await briefs([])).toEqual({})
  })
  it('ten short nonempty pages still report the page cap when total remains larger', async () => {
    fixture()
    vi.mocked(fetch).mockImplementation(async (...args) => response(200, {
      attacks: [{ id: Number(params(args).get('offset')) + 1 }], total: 100,
    }))
    const result = await allAttacks({ status: 'expired' })
    expect(result.capped).toBe(true)
    expect(result.rows).toHaveLength(10)
    expect(calls('/api/attacks').map(c => params(c).get('offset')))
      .toEqual(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'])
  })
  it('omitted optional frag/extras fields normalize to zero', () => {
    expect(normalize([{ time: '1970-01-01T00:00:00Z', pps: 0 }], 'bps')[0]!.values)
      .toMatchObject({ total: 0, fragment: 0, gre: 0, tcp_syn: 0 })
  })
})
