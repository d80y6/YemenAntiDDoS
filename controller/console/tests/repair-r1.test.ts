import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, reactive, ref } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { i18n } from '../src/i18n'
import XChart from '../src/components/chart/XChart.vue'
import Traffic from '../src/views/traffic/Traffic.vue'
import { useData } from '../src/views/overview/data'
import { resource } from '../src/api/data'
import { loadSelection } from '../src/components/chart/selection'
import type { Window } from '../src/components/chart/math'
import { mockReply } from '../mock/data'
import { render, response, deferred } from './helpers'
import { sourceText, sourceExists } from './r1-files.mjs'

const stamp = Date.parse('2026-10-28T00:00:00Z')
function fakeTime() { vi.useFakeTimers(); vi.setSystemTime(stamp) }
beforeEach(() => loadSelection())
const chartProps = { selected: ['tcp'], slots: { tcp: 1 }, bounds: [0, 40000] as Window, grain: 5000 }
const sample = (time: number, tcp: number) => ({ time, values: { tcp } })
async function bothTraffic(replace?: (url: string) => unknown) {
  fakeTime()
  vi.stubGlobal('fetch', vi.fn(async (raw: unknown) => {
    const path = String(raw), original = mockReply(path, 'normal', stamp)
    return response(original.status, replace?.(path) ?? original.body)
  }))
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/traffic', component: Traffic }] })
  await router.push('/traffic?direction=both')
  const view = render(Traffic, { global: { plugins: [i18n, router] } })
  await flushPromises()
  return view
}

describe('R1 render regressions', () => {
  it('R1-01 multiple isolated readings retain three distinct dots without a duplicate endpoint', () => {
    const view = render(XChart, { props: { ...chartProps,
      points: [sample(0, 100), sample(15000, 1), sample(30000, 50)] } })
    expect(view.findAll('.curve')).toHaveLength(0)
    expect(view.findAll('circle').map(c => [Number(c.attributes('cx')), Number(c.attributes('cy'))]))
      .toEqual([[44, 94], [249.5, 179.14], [455, 137]])
  })
  it('R1-01 isolated peak between two continuous segments remains visible', () => {
    const view = render(XChart, { props: { ...chartProps, points: [
      sample(0, 10), sample(5000, 20), sample(20000, 100), sample(35000, 40), sample(40000, 30),
    ] } })
    expect(view.findAll('.curve')).toHaveLength(2)
    expect(view.findAll('circle').map(c => [Number(c.attributes('cx')), Number(c.attributes('cy'))]))
      .toEqual([[318, 94], [592, 154.2]])
  })
  it('R1-02 both shared maxima and both SVG axes equal the hand-calculated 900-pps fixture', async () => {
    const view = await bothTraffic(url => {
      if (!url.startsWith('/api/stats/total-timeseries?')) return undefined
      if (new URL(url, 'http://localhost').searchParams.get('direction') === 'receives') return [{
        time: '2026-10-27T23:00:00Z', pps: 150, bps: 1200, tcp_pps: 100, tcp_bps: 800,
        udp_pps: 50, udp_bps: 400, tcp_syn_pps: 10, tcp_syn_bps: 80, icmp_pps: 0, icmp_bps: 0,
      }]
      return [{ time: '2026-10-27T23:00:02Z', pps: 1000, bps: 8000, tcp_pps: 900, tcp_bps: 7200,
        udp_pps: 100, udp_bps: 800, tcp_syn_pps: 0, tcp_syn_bps: 0, icmp_pps: 0, icmp_bps: 0 }]
    })
    const charts = view.findAllComponents(XChart)
    expect(charts).toHaveLength(2)
    expect(charts.map(c => c.props('sharedMax'))).toEqual([900, 900])
    // niceStep(900 × 1.06 / 4) = 500; ceiling = 2000. Expected labels are literal.
    expect(charts[0]!.findAll('.grid g text').map(t => t.text())).toEqual(['0', '500', '1k', '1.50k', '2k'])
    expect(charts[1]!.findAll('.grid g text').map(t => t.text())).toEqual(['0', '500', '1k', '1.50k', '2k'])
  })
  it('R1-03 both page imports put the shared CSS inside the unchanged scanner scope', () => {
    expect(sourceText('src/views/overview/Overview.vue')).toContain("import '../../styles/pages.css'")
    expect(sourceText('src/views/traffic/Traffic.vue')).toContain("import '../../styles/pages.css'")
    expect(sourceExists('src/styles/pages.css')).toBe(true)
    expect(sourceExists('src/views/overview/pages.css')).toBe(false)
  })
  it('R1-06 empty absolute zoom can reset through its visible controls into the full chart', async () => {
    const window = ref<Window | null>([0, 5000])
    const host = defineComponent({ setup: () => () => h(XChart, { ...chartProps,
      points: [sample(20000, 1)], bounds: [10000, 30000], window: window.value, zoomable: true,
      'onUpdate:window': value => { window.value = value },
    }) })
    const view = render(host)
    expect(view.text()).toContain('暂无数据')
    expect(view.find('svg').exists()).toBe(false)
    expect(view.findAll('button')).toHaveLength(3)
    await view.findAll('button').find(button => button.text() === '重置缩放')!.trigger('click')
    expect(window.value).toBeNull()
    expect(view.find('svg').exists()).toBe(true)
    expect(view.get('circle').attributes('cx')).toBe('318')
  })
  it('R1-08 both active-node KPI distinguishes union 3 from single side 2 and sum 4', async () => {
    const input = mockReply('/api/stats/overview?direction=receives', 'normal', stamp).body
    const output = mockReply('/api/stats/overview?direction=sends', 'normal', stamp).body
    const both = mockReply('/api/stats/overview?direction=both', 'normal', stamp).body
    expect(input.nodes.map((n: any) => n.id)).toEqual(['edge-a', 'flow-b'])
    expect(output.nodes.map((n: any) => n.id)).toEqual(['flow-b', 'edge-c'])
    expect(both.nodes.map((n: any) => n.id)).toEqual(['edge-a', 'flow-b', 'edge-c'])
    expect([input.node_count, output.node_count, both.node_count]).toEqual([2, 2, 3])
    const view = await bothTraffic()
    expect(view.findAll('.kpi')[2]!.get('.v2').text()).toBe('活跃节点 3')
  })
})

describe('R1 lifecycle and refresh regressions', () => {
  it.each(['band-page', 'band-terminal', 'active', 'active-brief', 'history-brief'])(
    'R1-04 unmount while %s is pending prevents every subsequent request', async scenario => {
      fakeTime()
      const pending = deferred<Response>()
      const mode = scenario === 'band-terminal' ? 'normal' : 'bulk'
      let held = ''
      vi.stubGlobal('fetch', vi.fn(async (raw: unknown) => {
        const path = String(raw), url = new URL(path, 'http://localhost')
        const bandStart = url.pathname === '/api/attacks' && !url.searchParams.has('status')
          && url.searchParams.get('offset') === '0'
        const firstBrief = url.pathname === '/api/attacks/mitigation-brief'
        const shouldHold = scenario.startsWith('band-') ? bandStart
          : scenario === 'active' ? url.pathname === '/api/attacks/active'
            : firstBrief && url.searchParams.get('ids')?.startsWith(scenario === 'active-brief' ? '1,' : '1000,')
        if (!held && shouldHold) { held = path; return pending.promise }
        const answer = mockReply(path, mode, stamp)
        return response(answer.status, answer.body)
      }))
      const host = defineComponent({ setup() {
        useData(reactive({ range: '15m', node: '', prefix: '', direction: 'receives', limit: '5' }), true)
        return () => h('div')
      } })
      const view = render(host)
      await flushPromises()
      expect(held).not.toBe('')
      const countAtUnmount = vi.mocked(fetch).mock.calls.length
      view.unmount()
      const answer = mockReply(held, mode, stamp)
      pending.resolve(response(answer.status, answer.body))
      await flushPromises()
      expect(vi.mocked(fetch).mock.calls.slice(countAtUnmount).map(([url]) => String(url))).toEqual([])
      await vi.advanceTimersByTimeAsync(120000)
      expect(fetch).toHaveBeenCalledTimes(countAtUnmount)
    },
  )
  it('R1-05 A-B-A forces an immediate A request after B, then clears loading on A success', async () => {
    fakeTime()
    const filter = ref('A'), b = deferred<number>(), aAgain = deferred<number>()
    const requested: string[] = []
    let state!: ReturnType<typeof resource<number>>
    const host = defineComponent({ setup() {
      state = resource(0, 10000, () => filter.value, async () => {
        requested.push(filter.value)
        if (requested.length === 1) return 7
        return filter.value === 'B' ? b.promise : aAgain.promise
      }, () => 60000)
      return () => h('output', String(state.loading.value))
    } })
    render(host)
    await flushPromises()
    expect(state.data.value).toBe(7)
    filter.value = 'B'; await flushPromises()
    filter.value = 'A'; await flushPromises()
    b.resolve(9); await flushPromises()
    expect(requested).toEqual(['A', 'B', 'A'])
    expect(state.data.value).toBe(7)
    expect(state.loading.value).toBe(true)
    aAgain.resolve(15); await flushPromises()
    expect(state.data.value).toBe(15)
    expect(state.loading.value).toBe(false)
  })
  it('R1-09 successful display time is completion 00:00:20 rather than request start 00:00:00', async () => {
    fakeTime()
    const answer = deferred<number>()
    let state!: ReturnType<typeof resource<number>>
    const host = defineComponent({ setup() {
      state = resource(0, 10000, () => 'fixed', () => answer.promise)
      return () => h('time', new Date(state.updated.value).toISOString().slice(11, 19))
    } })
    const view = render(host)
    await vi.advanceTimersByTimeAsync(20000)
    answer.resolve(42); await flushPromises()
    expect(state.updated.value).toBe(Date.parse('2026-10-28T00:00:20Z'))
    expect(view.get('time').text()).toBe('00:00:20')
  })
})
