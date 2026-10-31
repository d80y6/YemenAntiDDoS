import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountPage, clock, calls, params, tick } from './attacks-harness'
import { deferred, response } from './helpers'
import * as data from '../src/views/attacks/data'
import XChart from '../src/components/chart/XChart.vue'
import XPager from '../src/components/XPager.vue'
import ActionDrawer from '../src/views/attacks/ActionDrawer.vue'
beforeEach(clock)
const curves = () => calls('/api/stats/timeseries')
const chart = (w: any) => w.findComponent(XChart)
describe('r1 authorized repairs', () => {
  it('R1-01 W35 failed grain transition retries the whole window and removes old 5s points', async () => {
    let n = 0
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, result) => {
      if (path.split('?')[0] === '/api/attacks/1') result.body.attack.started_at = '2026-10-28T11:08:00Z'
      if (path.startsWith('/api/stats/timeseries') && ++n === 2) return response(503, { error: 'grain unavailable' })
    })
    await tick(10000)
    expect(w.text()).toContain('grain unavailable')
    expect(chart(w).props('grain')).toBe(5000)
    await tick(10000)
    expect(params(curves()[2]).get('from')).toBe('2026-10-28T11:00:00.000Z')
    expect(chart(w).props('grain')).toBe(300000)
    expect(chart(w).props('points').every((p: any) => p.time % 300000 === 0)).toBe(true)
  })
  it('R1-02 W36 metric change loads a whole pps window and never relabels 8000 as pps', async () => {
    let detail = 0, curve = 0
    const pending = deferred<Response>()
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, result) => {
      if (path.split('?')[0] === '/api/attacks/1') {
        if (++detail === 1) result.body.timer.threshold_unit = 'bps'
        else { delete result.body.timer; delete result.body.current }
      }
      if (path.startsWith('/api/stats/timeseries')) {
        if (++curve === 1) return response(200, [{ time: '2026-10-28T11:59:55Z', pps: 10, bps: 8000 }])
        return pending.promise
      }
    })
    expect(chart(w).props('metric')).toBe('bps')
    await tick(5000)
    expect(chart(w).props('loading') || chart(w).props('metric') === 'bps').toBe(true)
    await tick(5000)
    expect(params(curves()[1]).get('from')).toBe('2026-10-28T11:30:10.000Z')
    pending.resolve(response(200, [
      { time: '2026-10-28T11:59:55Z', pps: 10, bps: 8000 },
      { time: '2026-10-28T12:00:00Z', pps: 20, bps: 16000 },
    ]))
    await flushPromises()
    expect(chart(w).props('metric')).toBe('pps')
    expect(chart(w).props('points').map((p: any) => p.values.total)).toEqual([10, 20])
    expect(chart(w).props('loading')).toBe(false)
  })
  it('R1-03 W37 old polling summary cannot overwrite newer manual refresh', async () => {
    const pending = deferred<Response>(); let n = 0, old: any
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, result) => {
      if (!path.includes('mitigation-summary')) return
      n++
      if (n === 2) {
        old = result.body; old.executions[1].response_name = 'Old polling response'; return pending.promise
      }
      if (n === 3) result.body.executions[1].response_name = 'New manual response'
    })
    await tick(5000)
    await w.get('.refresh-row button').trigger('click'); await flushPromises()
    expect(w.text()).toContain('New manual response')
    pending.resolve(response(200, old)); await flushPromises()
    expect(w.text()).toContain('New manual response')
    expect(w.text()).not.toContain('Old polling response')
  })
  it('R1-04 W38 same-component URL restore preserves page two without rewriting query', async () => {
    const { w, router } = await mountPage('/attacks?status=active')
    await router.push('/attacks?status=all&page=2'); await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/attacks?status=all&page=2')
    expect(w.findComponent(XPager).props('modelValue')).toBe(2)
    expect(params(calls('/api/attacks').filter(c => params(c).get('limit') === '50').at(-1)).get('offset')).toBe('50')
  })
  it.each([
    ['bgp', 'on_expired', 'BGP 撤回', '结束时'],
    ['xdrop', 'on_expired', 'XDrop 撤销', '结束时'],
    ['manual_override', 'manual_override', '手动操作', '手动'],
  ])('R1-05 W39 log and drawer map %s + %s', async (action, phase, expectedAction, expectedPhase) => {
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, result) => {
      if (path.includes('mitigation-summary')) result.body.executions = [
        { ...result.body.executions[1], action_type: action, trigger_phase: phase },
      ]
    })
    const cells = w.get('.action-log tbody tr').findAll('td')
    expect(cells[1]!.text()).toBe(expectedAction); expect(cells[3]!.text()).toBe(expectedPhase)
    await w.get('.action-log .text-button').trigger('click'); await flushPromises()
    expect(document.querySelector('.drawer-head h2')!.textContent).toContain(expectedAction)
    expect(document.querySelector('.drawer-body .kv dd')!.textContent).toBe(expectedPhase)
    await w.findComponent(ActionDrawer).vm.$emit('update:modelValue', false)
  })
  it('R1-06 W40 ended attack retries summary until one successful response', async () => {
    let n = 0
    const { w } = await mountPage('/attacks/1000', 'attacks', (path, _init, result) => {
      if (path.includes('mitigation-summary')) {
        if (++n === 1) return response(503, { error: 'summary unavailable' })
        result.body.executions[1].response_name = 'Recovered summary'
      }
    })
    expect(w.text()).toContain('summary unavailable')
    await tick(5000)
    expect(calls('/api/attacks/1000/mitigation-summary')).toHaveLength(2)
    expect(w.text()).toContain('Recovered summary')
  })
  it('R1-07 W41 deterministic curve failure waits for five-second polling rather than microtask retries', async () => {
    const original = data.curveRequest; let faults = 0
    vi.spyOn(data, 'curveRequest').mockImplementation((...args) => {
      if (++faults <= 8) throw new Error('curve planning failed')
      return original(...args)
    })
    const { w } = await mountPage('/attacks/1')
    expect(calls('/api/attacks/1').length).toBeLessThanOrEqual(1)
    expect(w.text()).toContain('curve planning failed')
    await tick(5000)
    expect(calls('/api/attacks/1')).toHaveLength(2)
  })
  it('R1-09 W43 failed first-ended window retries at 12:00:15, not 12:00:10', async () => {
    let n = 0
    await mountPage('/attacks/1', 'attacks', (path, _init, result) => {
      if (path.split('?')[0] === '/api/attacks/1') Object.assign(result.body.attack, {
        started_at: '2026-10-28T11:20:00Z',
        ended_at: Date.now() >= Date.parse('2026-10-28T12:00:05Z') ? '2026-10-28T12:00:00Z' : null,
      })
      if (path.startsWith('/api/stats/timeseries') && ++n === 2) return response(503, { error: 'end window failed' })
    })
    await tick(5000); expect(curves()).toHaveLength(2)
    expect(params(curves()[1]).get('to')).toBe('2026-10-28T12:00:05.000Z')
    await tick(5000); expect(curves()).toHaveLength(2)
    await tick(5000); expect(curves()).toHaveLength(3)
    expect(params(curves()[2]).get('from')).toBe('2026-10-28T11:10:00.000Z')
    expect(params(curves()[2]).get('to')).toBe('2026-10-28T12:00:15.000Z')
  })
  it('R1-12 W44 loaded detail survives a 503, clears warning after retry, and still handles 404', async () => {
    const { w, intercept } = await mountPage('/attacks/1')
    intercept(path => path.split('?')[0] === '/api/attacks/1'
      ? response(503, { error: 'detail temporarily unavailable' })
      : undefined)
    await tick(5000)
    expect(chart(w).exists()).toBe(true); expect(w.findAll('.kpi')).toHaveLength(5)
    expect(w.get('[role=alert]').text()).toContain('detail temporarily unavailable')
    intercept(); await w.findAll('button').find(b => b.text() === '重试')!.trigger('click'); await flushPromises()
    expect(w.findAll('[role=alert]')).toHaveLength(0); expect(chart(w).exists()).toBe(true)
    intercept(path => path.split('?')[0] === '/api/attacks/1'
      ? response(404, { error: 'attack not found' }) : undefined)
    await tick(5000); expect(w.text()).toContain('没有这个攻击。'); expect(chart(w).exists()).toBe(false)
  })
})
