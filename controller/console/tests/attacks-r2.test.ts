import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { clock, mountPage, calls, params, tick } from './attacks-harness'
import { deferred, response } from './helpers'
import * as data from '../src/views/attacks/data'
import XChart from '../src/components/chart/XChart.vue'
import XSeg from '../src/components/XSeg.vue'
import XPager from '../src/components/XPager.vue'

beforeEach(clock)
describe('r2 authorized polling and filter repairs', () => {
  it('R2-01 W45 returning to the same id replaces an aborted lifecycle without advancing time', async () => {
    const suspended = deferred<Response>()
    let summaryRequests = 0
    const { w, router } = await mountPage('/attacks/1', 'attacks', path => {
      if (path.split('?')[0] === '/api/attacks/1/mitigation-summary' && ++summaryRequests === 1) {
        return suspended.promise
      }
    })
    expect(calls('/api/attacks/1')).toHaveLength(1)
    await router.push('/attacks/2'); await flushPromises()
    await router.push('/attacks/1'); await flushPromises()
    suspended.resolve(response(200, { executions: [], xdrop_rules: [], bgp_announcements: [], summary: {} }))
    await flushPromises()
    expect(calls('/api/attacks/1')).toHaveLength(2)
    expect(calls('/api/attacks/2')).toHaveLength(0)
    expect(w.findAll('[role=alert]')).toHaveLength(0)
    expect(w.findComponent(XChart).find('svg').exists()).toBe(true)
    expect(Date.now()).toBe(Date.parse('2026-10-28T12:00:00.000Z'))
  })
  it('R2-02 W46 ended attack clears a one-shot polling exception when the next result is accepted', async () => {
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, result) => {
      if (path.split('?')[0] === '/api/attacks/1') result.body.attack.ended_at = '2026-10-28T12:00:00Z'
    })
    const planner = data.curveRequest
    vi.spyOn(data, 'curveRequest').mockImplementationOnce(() => { throw new Error('one-shot curve planning failure') })
      .mockImplementation(planner)
    await tick(10000)
    expect(w.get('.detail-warning').text()).toContain('one-shot curve planning failure')
    expect(w.findComponent(XChart).find('svg').exists()).toBe(true)
    await tick(5000)
    expect(calls('/api/attacks/1')).toHaveLength(1)
    expect(calls('/api/stats/timeseries')).toHaveLength(2)
    expect(params(calls('/api/stats/timeseries')[1]).get('to')).toBe('2026-10-28T12:00:15.000Z')
    expect(w.findAll('[role=alert]')).toHaveLength(0)
    expect(w.findComponent(XChart).find('svg').exists()).toBe(true)
  })
  it.each(['search', 'direction'])(
    'R2-03 W47 one %s change on page three emits one complete request group', async change => {
      const { w, fetcher, router } = await mountPage('/attacks?status=all&page=2')
      fetcher.mockClear()
      if (change === 'search') {
        await w.get('input[type=search]').setValue('192.0.2.10')
        await w.get('input[type=search]').trigger('keydown', { key: 'Enter' })
      } else await w.findComponent(XSeg).vm.$emit('update:modelValue', 'sends')
      await flushPromises()
      const list = calls('/api/attacks')
      expect(list.map(c => ({ limit: params(c).get('limit'), offset: params(c).get('offset'),
        status: params(c).get('status') }))).toEqual([
        { limit: '50', offset: '0', status: null },
        { limit: '1', offset: '0', status: 'active' },
        { limit: '1', offset: '0', status: 'expired' },
      ])
      expect(list.map(c => params(c).get('dst_ip'))).toEqual(change === 'search'
        ? ['192.0.2.10', '192.0.2.10', '192.0.2.10'] : [null, null, null])
      expect(list.map(c => params(c).get('direction'))).toEqual(change === 'direction'
        ? ['sends', 'sends', 'sends'] : [null, null, null])
      expect(w.findComponent(XPager).props('modelValue')).toBe(1)
      expect(router.currentRoute.value.query.page).toBe('1')
      expect(router.currentRoute.value.query[change === 'search' ? 'q' : 'dir'])
        .toBe(change === 'search' ? '192.0.2.10' : 'sends')
      await tick(1000)
      expect(calls('/api/attacks')).toHaveLength(3)
    },
  )
})
