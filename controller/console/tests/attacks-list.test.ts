import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountPage, clock, calls, params, tick } from './attacks-harness'
import { response } from './helpers'
import XSeg from '../src/components/XSeg.vue'
import XPager from '../src/components/XPager.vue'
const attackRow = (w: any, id: number) => w.findAll('tbody tr')
  .find((r: any) => r.find('td a').text() === '#' + id)!
beforeEach(clock)
describe('G-list parameters and navigation', () => {
  it.each([
    ['active', 'active', null], ['expired', 'expired', '2026-10-27T12:00:00.000Z'], ['all', null, null],
  ])('W3 chip %s exact status/window parameters', async (status, outgoing, after) => {
    const { w } = await mountPage('/attacks?status=' + status)
    const list = calls('/api/attacks').find(c => params(c).get('limit') === '50')!
    expect(params(list).get('sort')).toBe(status === 'active' ? 'peak_pps' : null)
    expect(calls('/api/attacks').filter(c => params(c).get('limit') === '1')
      .every(c => !params(c).has('sort'))).toBe(true)
    expect(params(list).get('status')).toBe(outgoing)
    expect(params(list).get('ended_after')).toBe(after)
    expect(w.findAllComponents(XSeg).some(c => c.props('options').some((o: any) => o.value === '7d')))
      .toBe(status === 'expired')
    expect(calls('/api/attacks')).toHaveLength(3)
  })
  it('W2 seven-day cutoff and W20 direction/search appear in all three requests', async () => {
    await mountPage('/attacks?status=expired&win=7d&dir=receives&q=192.0.2.0%2F24')
    expect(calls('/api/attacks')).toHaveLength(3)
    for (const c of calls('/api/attacks')) {
      expect(params(c).get('direction')).toBe('receives')
      expect(params(c).get('dst_ip')).toBe('192.0.2.0/24')
      expect(params(c).has('from')).toBe(false)
      expect(params(c).get('ended_after')).toBe(params(c).get('status') === 'expired'
        ? '2026-10-21T12:00:00.000Z' : null)
    }
  })
  it('W3 all preserves 31-day-old ended attack and links to detail', async () => {
    const { w, router } = await mountPage('/attacks?status=all')
    expect(w.text()).toContain('#1044')
    await w.get('a[href="/attacks/1044"]').trigger('click'); await flushPromises()
    expect(router.currentRoute.value.path).toBe('/attacks/1044')
    expect(w.find('.attack-detail').exists()).toBe(true)
  })
  it('W21 third page offset is 100 and out-of-range falls to the last page', async () => {
    const a = await mountPage('/attacks?status=all&page=3')
    expect(params(calls('/api/attacks')[0]).get('offset')).toBe('100')
    a.w.unmount()
    const b = await mountPage('/attacks?status=all&page=99'); await flushPromises()
    expect(b.w.findComponent(XPager).props('modelValue')).toBe(2)
    expect(params(calls('/api/attacks').find(c => params(c).get('offset') === '50')!).get('offset')).toBe('50')
  })
  it('default status follows the active count and malformed URL values recover', async () => {
    const a = await mountPage('/attacks')
    expect(a.w.get('.chip[aria-pressed=true]').text()).toBe('进行中 7')
    a.w.unmount()
    const b = await mountPage('/attacks?status=garbage&dir=x&win=x&page=-1', 'null')
    expect(b.w.get('.chip[aria-pressed=true]').text()).toBe('全部 0')
    expect(b.router.currentRoute.value.query).toMatchObject({ status: 'all', dir: 'all', win: '24h', page: '1' })
  })
  it.each(['198.51..7', '198.51.100.7/', '198.51.100.7/32/1'])('W1 invalid search %s sends zero requests',
    async input => {
      const { w, fetcher } = await mountPage('/attacks?status=all')
      fetcher.mockClear(); await w.get('input[type=search]').setValue(input); await tick(450)
      expect(fetcher).toHaveBeenCalledTimes(0)
      expect(w.text()).toContain('请输入 IP 地址或网段，如 198.51.100.7 或 198.51.100.0/24')
    })
  it('empty search omits dst_ip; enter/blur/debounce commit trimmed target and reset page', async () => {
    const { w, fetcher, router } = await mountPage('/attacks?status=all&page=3')
    expect(calls('/api/attacks').every(c => !params(c).has('dst_ip'))).toBe(true)
    fetcher.mockClear()
    await w.get('input[type=search]').setValue(' 192.0.2.10 ')
    await w.get('input[type=search]').trigger('keydown', { key: 'Enter' }); await flushPromises()
    expect(calls('/api/attacks').every(c => params(c).get('dst_ip') === '192.0.2.10')).toBe(true)
    expect(router.currentRoute.value.query.q).toBe('192.0.2.10')
    expect(router.currentRoute.value.query.page).toBe('1')
    await w.get('input[type=search]').setValue(''); await w.get('input[type=search]').trigger('blur')
    await flushPromises(); expect(params(calls('/api/attacks').at(-1)).has('dst_ip')).toBe(false)
  })
  it('chips use three distinct response totals; count failure is — without damaging table', async () => {
    const { w } = await mountPage('/attacks?status=all')
    expect(w.findAll('.chip').map(c => c.text())).toEqual(['进行中 7', '已结束 44', '全部 52'])
    w.unmount()
    const b = await mountPage('/attacks?status=all', 'attacks', (path) => {
      const p = new URL(path, 'http://localhost').searchParams
      if (p.get('limit') === '1' && p.get('status') === 'expired') return response(503, { error: 'count failed' })
    })
    expect(b.w.findAll('.chip')[1]!.text()).toBe('已结束 —')
    expect(b.w.findAll('tbody tr')).toHaveLength(50)
  })
})
describe('G-list rendering, states and polling', () => {
  it('W11 /32 display, global/outbound pills, decoder tooltip, peak zero and brief pills', async () => {
    const { w } = await mountPage('/attacks?status=active')
    const rows = w.findAll('tbody tr')
    expect(rows.map(r => Number(r.get('td a').text().slice(1)))).toEqual([7, 6, 5, 4, 3, 2, 1])
    expect(attackRow(w, 1).findAll('td')[1]!.text()).toBe('192.0.2.10')
    expect(attackRow(w, 2).findAll('td')[1]!.text()).toBe('2001:db8::1')
    expect(attackRow(w, 3).text()).toContain('全局'); expect(attackRow(w, 3).text()).toContain('IP 总量')
    expect(attackRow(w, 4).text()).toContain('出向')
    expect(attackRow(w, 1).findAll('td')[2]!.attributes('title')).toBe('udp_flood · udp')
    expect(attackRow(w, 2).findAll('td')[5]!.text()).toBe('—')
    expect(rows.every(r => r.findAll('td')[6]!.text().includes('XDrop') && r.text().includes('BGP'))).toBe(true)
    expect(calls('/api/attacks/mitigation-brief')).toHaveLength(1)
    expect(params(calls('/api/attacks/mitigation-brief')[0]).get('ids')).toBe('7,6,5,4,3,2,1')
    expect(attackRow(w, 1).findAll('td')[8]!.attributes('title')).toContain('2026-10-28')
  })
  it('W18 timer, expiring, untracked and missing branches and active failure preserves last success', async () => {
    const { w, intercept } = await mountPage('/attacks?status=active')
    const status = () => [1, 2, 3, 4, 5].map(id => attackRow(w, id).findAll('td')[10]!.text())
    expect(status().slice(0, 5)).toEqual(['超阈中', '回落中 2:05', '超阈中', '超阈中', '未在实时检测中'])
    intercept(path => path.startsWith('/api/attacks/active') ? response(500, { error: 'timers failed' }) : undefined)
    await tick(5000)
    expect(status().slice(0, 5)).toEqual(['超阈中', '回落中 2:05', '超阈中', '超阈中', '未在实时检测中'])
  })
  it.each([[1001, 1000, '实时状态只取峰值前 1000 条'], [7, 7, '实时状态暂未取到（可能刚结束）']])(
    'excluded ID active_count=%s returned=%s', async (count, returned, title) => {
      const { w } = await mountPage('/attacks?status=active', 'attacks', (path, _init, r) => {
        if (path.startsWith('/api/attacks/active')) {
          r.body.attacks = []; r.body.timers = {}; r.body.active_count = count; r.body.returned = returned
        }
      })
      const cell = w.findAll('tbody tr')[0]!.findAll('td')[10]!
      expect(cell.text()).toBe('—'); expect(cell.attributes('title')).toBe(title)
    })
  it('first active request failure displays original error in status tooltip', async () => {
    const { w } = await mountPage('/attacks?status=active', 'attacks', path => path.startsWith('/api/attacks/active')
      ? response(503, { error: 'live status unavailable' }) : undefined)
    const cell = w.findAll('tbody tr')[0]!.findAll('td')[10]!
    expect(cell.text()).toBe('—'); expect(cell.attributes('title')).toBe('live status unavailable')
  })
  it('ended page never requests active timers; non-admin has no end buttons', async () => {
    const a = await mountPage('/attacks?status=expired')
    expect(calls('/api/attacks/active')).toHaveLength(0); a.w.unmount()
    const b = await mountPage('/attacks?status=active', 'attacks', undefined, false)
    expect(b.w.findAll('tbody button')).toHaveLength(0)
  })
  it('list failure retains rows and original error; null means empty and no brief request', async () => {
    const { w, intercept, fetcher } = await mountPage('/attacks?status=active')
    intercept(path => path.startsWith('/api/attacks?') ? response(500, { error: 'list unavailable' }) : undefined)
    await tick(5000)
    expect(w.findAll('tbody tr')).toHaveLength(7); expect(w.text()).toContain('list unavailable')
    expect(attackRow(w, 1).findAll('td')[9]!.text()).toBe('10m 5s')
    w.unmount(); const before = fetcher.mock.calls.length; await tick(10000)
    expect(fetcher).toHaveBeenCalledTimes(before)
    const b = await mountPage('/attacks?status=all', 'null')
    expect(b.w.text()).toContain('没有符合条件的攻击')
    expect(b.w.findAll('[role=alert]')).toHaveLength(0)
    expect(calls('/api/attacks/mitigation-brief')).toHaveLength(0)
  })
})
