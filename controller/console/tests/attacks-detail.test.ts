import { describe, it, expect, vi, beforeEach } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountPage, clock, calls, params, tick } from './attacks-harness'
import { response, deferred } from './helpers'
import { notifications } from '../src/notifications'
import XChart from '../src/components/chart/XChart.vue'
import XTabs from '../src/components/XTabs.vue'
import XSeg from '../src/components/XSeg.vue'
import Samples from '../src/views/attacks/Samples.vue'
beforeEach(clock)
const curveCalls = () => [...calls('/api/stats/timeseries'), ...calls('/api/stats/total-timeseries')]
const changeDetail = (r: any, values: any) => Object.assign(r.body.attack, values)
const emptyMitigation = (r: any) => Object.assign(r.body, { xdrop_rules: [], bgp_announcements: [], executions: [] })
const forceButtons = (w: any) => w.findAll('button').filter((b: any) => b.text() === '强制移除')
const setFlow = async (w: any) => { await w.findComponent(XTabs).vm.$emit('update:modelValue', 'flow');
  await flushPromises()
}
describe('G-detail curves and lifecycle', () => {
  it.each([
    [1, '/api/stats/timeseries', 'dst_ip', '192.0.2.10', 'receives'],
    [4, '/api/stats/timeseries', 'prefix', '198.51.100.0/24', 'sends'],
    [3, '/api/stats/total-timeseries', null, null, 'receives'],
  ])('W11 target %s chooses exact request shape', async (id, path, key, value, direction) => {
    const { w } = await mountPage('/attacks/' + id)
    expect(curveCalls()).toHaveLength(1)
    const c = calls(path)[0]!
    if (key) expect(params(c).get(key)).toBe(value)
    else { expect(params(c).has('dst_ip')).toBe(false); expect(params(c).has('prefix')).toBe(false) }
    expect(params(c).get('direction')).toBe(direction)
    expect(params(c).get('include_extras')).toBe('true')
    expect(w.findComponent(XChart).props('outbound')).toBeFalsy()
    expect(w.findComponent(XChart).findAll('rect.band').length).toBeGreaterThan(0)
  })
  it('W10 nine-hour single IP uses exactly six hours and cap note', async () => {
    const { w } = await mountPage('/attacks/7')
    const p = params(curveCalls()[0]); expect(p.get('from')).toBe('2026-10-28T06:00:00.000Z')
    expect(p.get('to')).toBe('2026-10-28T12:00:00.000Z')
    expect(w.text()).toContain('只显示最近 6 小时（逐 IP 读数单次最长 6 小时）')
  })
  it('W8 second ongoing curve request uses aligned tail rather than whole window', async () => {
    await mountPage('/attacks/1')
    await tick(5000); expect(curveCalls()).toHaveLength(1)
    await tick(5000); expect(curveCalls()).toHaveLength(2)
    expect(params(curveCalls()[1]).get('from')).toBe('2026-10-28T11:59:55.000Z')
    expect(params(curveCalls()[1]).get('to')).toBe('2026-10-28T12:00:10.000Z')
  })
  it('W25 crossing one hour refetches the exact whole window and removes every 5s point', async () => {
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, r) => {
      if (path.split('?')[0] === '/api/attacks/1') changeDetail(r, { started_at: '2026-10-28T11:08:00Z' })
    })
    expect(params(curveCalls()[0]).get('resolution')).toBe('5s')
    await tick(10000)
    expect(params(curveCalls()[1]).get('resolution')).toBe('5min')
    expect(params(curveCalls()[1]).get('from')).toBe('2026-10-28T11:00:00.000Z')
    const points = w.findComponent(XChart).props('points')
    expect(points).toHaveLength(13)
    expect(points.every((p: any) => p.time % 300000 === 0)).toBe(true)
  })
  it('hidden six-hour gap resumes with a capped whole request and no retry loop', async () => {
    await mountPage('/attacks/7')
    const hidden = vi.spyOn(document, 'hidden', 'get')
    hidden.mockReturnValue(true); document.dispatchEvent(new Event('visibilitychange'))
    await tick(21600000); expect(curveCalls()).toHaveLength(1)
    hidden.mockReturnValue(false); document.dispatchEvent(new Event('visibilitychange')); await flushPromises()
    expect(curveCalls()).toHaveLength(2)
    expect(params(curveCalls()[1]).get('from')).toBe('2026-10-28T12:00:00.000Z')
    expect(params(curveCalls()[1]).get('to')).toBe('2026-10-28T18:00:00.000Z')
  })
  it('W26 tail failure retry recomputes from current window: 00:00:00 then 00:00:10', async () => {
    vi.setSystemTime(new Date('2026-10-28T05:59:50Z'))
    let count = 0
    const { w } = await mountPage('/attacks/7', 'attacks', (path, _init, r) => {
      if (path.split('?')[0] === '/api/attacks/7') changeDetail(r, { started_at: '2026-10-27T20:00:00Z' })
      if (path.startsWith('/api/stats/timeseries')) {
        count++
        if (count === 1) return response(200, [{ time: '2026-10-28T00:05:00Z', pps: 123, bps: 984 }])
        if (count === 2) return response(503, { error: 'tail temporarily failed' })
      }
    })
    const before = w.findComponent(XChart).props('points')
    await tick(10000)
    expect(params(curveCalls()[1]).get('from')).toBe('2026-10-28T00:00:00.000Z')
    expect(w.findComponent(XChart).props('points')).toEqual(before)
    expect(w.findComponent(XChart).props('error')).toBe('')
    expect(w.text()).toContain('tail temporarily failed')
    await tick(10000)
    expect(params(curveCalls()[2]).get('from')).toBe('2026-10-28T00:00:10.000Z')
    expect(params(curveCalls()[2]).get('to')).toBe('2026-10-28T06:00:10.000Z')
  })
  it('W33 first observed end refetches 11:10 even without a grain change', async () => {
    vi.setSystemTime(new Date('2026-10-28T11:59:55Z'))
    await mountPage('/attacks/1', 'attacks', (path, _init, r) => {
      if (path.split('?')[0] === '/api/attacks/1') changeDetail(r, { started_at: '2026-10-28T11:20:00Z',
        ended_at: Date.now() >= Date.parse('2026-10-28T12:00:00Z') ? '2026-10-28T12:00:00Z' : null })
    })
    await tick(10000)
    expect(params(curveCalls()[1]).get('from')).toBe('2026-10-28T11:10:00.000Z')
    expect(params(curveCalls()[1]).get('resolution')).toBe('5s')
  })
  it('W27 ended curve fills 12:01–12:10, clamps final to and then stops', async () => {
    vi.setSystemTime(new Date('2026-10-28T12:00:05Z'))
    const { w, fetcher } = await mountPage('/attacks/1', 'attacks', (path, _init, r) => {
      if (path.split('?')[0] === '/api/attacks/1') changeDetail(r,
        { started_at: '2026-10-28T11:20:00Z', ended_at: '2026-10-28T12:00:00Z' })
    })
    await tick(660000)
    const points = w.findComponent(XChart).props('points')
    expect(points.some((p: any) => p.time === Date.parse('2026-10-28T12:01:00Z'))).toBe(true)
    expect(points.at(-1)!.time).toBe(Date.parse('2026-10-28T12:10:00Z'))
    expect(params(curveCalls().at(-1)).get('to')).toBe('2026-10-28T12:10:00.000Z')
    fetcher.mockClear(); await tick(20000); expect(curveCalls()).toHaveLength(0)
  })
  it('W22 ended with no active/delayed mitigation only loads once; delayed polls summary only', async () => {
    const first = await mountPage('/attacks/1000', 'attacks', (path, _init, r) => {
      if (path.includes('mitigation-summary')) emptyMitigation(r)
    })
    expect(curveCalls()).toHaveLength(1)
    first.fetcher.mockClear(); await tick(20000); expect(first.fetcher).toHaveBeenCalledTimes(0)
    first.w.unmount()
    const second = await mountPage('/attacks/1000')
    second.fetcher.mockClear(); await tick(5000)
    expect(calls('/api/attacks/1000/mitigation-summary')).toHaveLength(1)
    expect(calls('/api/active-actions/xdrop')).toHaveLength(1)
    expect(calls('/api/attacks/1000')).toHaveLength(0); expect(curveCalls()).toHaveLength(0)
    second.w.unmount(); const n = second.fetcher.mock.calls.length; await tick(20000)
    expect(second.fetcher).toHaveBeenCalledTimes(n)
  })
  it.each(['abc', '0', '-1', '1.5'])('invalid id %s makes zero requests', async id => {
    const { w, fetcher } = await mountPage('/attacks/' + id)
    expect(fetcher).toHaveBeenCalledTimes(0); expect(w.text()).toContain('没有这个攻击。')
  })
  it('404 is not-found; 500 preserves raw error and retry succeeds', async () => {
    const a = await mountPage('/attacks/9999'); expect(a.w.text()).toContain('没有这个攻击。'); a.w.unmount()
    const b = await mountPage('/attacks/1', 'attacks', path => path.split('?')[0] === '/api/attacks/1'
      ? response(500, { error: 'attack query failed' }) : undefined)
    expect(b.w.text()).toContain('attack query failed')
    b.intercept(); await b.w.get('button').trigger('click'); await flushPromises()
    expect(b.w.findComponent(XChart).exists()).toBe(true)
  })
  it.each([[1, 'pps', 800, null], [4, 'bps', 800000, null], [6, 'pps', undefined, '触发阈值 80%']])(
    'W19 W24 threshold id=%s metric=%s', async (id, metric, line, text) => {
      const { w } = await mountPage('/attacks/' + id)
      expect(w.findComponent(XChart).props('metric')).toBe(metric)
      expect(w.findComponent(XChart).props('threshold')).toBe(line)
      if (text) expect(w.text()).toContain(text)
    })
  it('ended has no threshold; missing current is — while real zero is visible', async () => {
    const a = await mountPage('/attacks/1000')
    expect(a.w.findComponent(XChart).props('threshold')).toBeUndefined()
    expect(a.w.text()).toContain('仅进行中的攻击能取到触发阈值'); a.w.unmount()
    const b = await mountPage('/attacks/5')
    expect(b.w.findAll('.kpi .v')[0]!.text()).toBe('—'); b.w.unmount()
    const c = await mountPage('/attacks/2')
    expect(c.w.findAll('.kpi .v')[0]!.text()).toBe('0 pps')
  })
  it('W31 unmount while summary pending aborts it and never starts xdrop after resolution', async () => {
    const pending = deferred<Response>(); let signal: AbortSignal | undefined
    const { w, fetcher } = await mountPage('/attacks/1', 'attacks', (path, init) => {
      if (path.includes('/mitigation-summary')) { signal = init.signal!; return pending.promise }
    })
    w.unmount(); expect(signal?.aborted).toBe(true)
    pending.resolve(response(200, { executions: [{ action_type: 'xdrop' }], xdrop_rules: [] }))
    await flushPromises(); expect(calls('/api/active-actions/xdrop')).toHaveLength(0)
    const n = fetcher.mock.calls.length; await tick(20000); expect(fetcher).toHaveBeenCalledTimes(n)
  })
  it('W31 switching id aborts pending old summary and never starts its xdrop', async () => {
    const pending = deferred<Response>(); let signal: AbortSignal | undefined
    const { w, router } = await mountPage('/attacks/1', 'attacks', (path, init) => {
      if (path.includes('/1/mitigation-summary')) { signal = init.signal!; return pending.promise }
    })
    await router.push('/attacks/2'); await flushPromises(); expect(signal?.aborted).toBe(true)
    pending.resolve(response(200, { executions: [{ action_type: 'xdrop' }], xdrop_rules: [] }))
    await flushPromises()
    expect(calls('/api/active-actions/xdrop')).toHaveLength(1)
    expect(w.text()).toContain('2001:db8::1')
  })
})
describe('G-detail mitigation, logs and samples', () => {
  it('W28 W29 summary owns logs; read-only mitigation has shared/delayed rows and all old row entries', async () => {
    const { w } = await mountPage('/attacks/1')
    expect(calls('/api/attacks/1/action-log')).toHaveLength(0)
    expect(w.get('.mitigation-panel').findAll('button')).toHaveLength(0)
    expect(w.get('.mitigation-panel a').attributes('href')).toBe('/mitigations')
    expect(w.get('.mitigation-panel').text()).toContain('共持 1')
    expect(w.get('.mitigation-panel').text()).toContain('引用数 3')
    expect(w.get('.mitigation-panel').text()).toContain('延迟撤回 4:00')
    expect(w.get('.mitigation-panel').text()).toContain('Edge XDrop')
    expect(w.get('.mitigation-panel').text()).toContain('Transit BGP')
    expect(w.text()).toContain('Automatic defense')
    expect(forceButtons(w)).toHaveLength(3)
    const bgp = forceButtons(w).slice(1)
    expect(bgp).toHaveLength(2)
    expect(w.text()).toContain('手动操作')
    const skipped = w.findAll('tr').find(r => r.text().includes('Webhook'))!
    expect(skipped.text()).toContain('—')
    expect(skipped.text()).not.toContain('0 ms')
    expect(w.findAll('th').filter(n => n.text() === 'HTTP')).toHaveLength(1)
  })
  it('W23 ended, failed/skipped/webhook and W16 viewer never gain force entries', async () => {
    const a = await mountPage('/attacks/1000'); expect(forceButtons(a.w)).toHaveLength(0); a.w.unmount()
    const b = await mountPage('/attacks/1', 'attacks', undefined, false)
    expect(forceButtons(b.w)).toHaveLength(0)
    expect(b.w.findAll('button').some(n => n.text() === '结束攻击')).toBe(false)
  })
  it('W15 four-key request uses route id, W32 BGP confirmation says refcount minus one', async () => {
    const { w } = await mountPage('/attacks/1', 'attacks', (path, _init, r) => {
      if (path.includes('mitigation-summary')) r.body.executions.forEach((e: any) => { e.attack_id = 999 })
    })
    await forceButtons(w)[1]!.trigger('click')
    expect(w.get('[role=alertdialog]').text()).toContain('该路由还与另外 2 个攻击共享。')
    await w.get('[role=alertdialog] .danger').trigger('click'); await flushPromises()
    const c = calls('/api/active-actions/force-remove')[0]!
    expect(JSON.parse(String(c[1]!.body))).toEqual({ attack_id: 1, action_id: 12, connector_id: 1,
      external_rule_id: '192.0.2.0/24|defense' })
    expect(notifications.at(-1)).toMatchObject({ tone: 'ok', message: '已强制移除' })
  })
  it('XDrop shared and last-holder confirmations, failed holder refresh preserves last holder set', async () => {
    const { w, intercept } = await mountPage('/attacks/1')
    await forceButtons(w)[0]!.trigger('click')
    expect(w.get('[role=alertdialog]').text()).toContain('本 xSight 还有 1 个其他持有方，规则保留。')
    await w.get('[role=alertdialog] .btn:not(.danger)').trigger('click')
    intercept(path => path.startsWith('/api/active-actions/xdrop') 
      ? response(500, { error: 'holders failed' }) : undefined)
    await tick(5000); await forceButtons(w)[0]!.trigger('click')
    expect(w.get('[role=alertdialog]').text()).toContain('还有 1 个其他持有方')
    await w.get('[role=alertdialog] .btn:not(.danger)').trigger('click')
    intercept(path => path.startsWith('/api/active-actions/xdrop') ? response(200, []) : undefined)
    await tick(5000); await forceButtons(w)[0]!.trigger('click')
    expect(w.get('[role=alertdialog]').text()).toContain('其他系统可能仍持有该规则。')
  })
  it.each([
    ['attacks', 'ok', '已释放持有'],
    ['force-warning', 'warn', 'local hold released; remote pending'],
    ['force-error', 'crit', 'connector request failed'],
  ])('force result %s => %s %s', async (mode, tone, message) => {
    const { w } = await mountPage('/attacks/1', mode)
    await forceButtons(w)[0]!.trigger('click')
    await w.get('[role=alertdialog] .danger').trigger('click'); await flushPromises()
    expect(notifications.at(-1)).toMatchObject({ tone, message })
    expect(w.find('[role=alertdialog]').exists()).toBe(mode === 'force-error')
  })
  it.each([[0, 'warn', '请求超时，后台可能仍在处理。'], [1, 'crit', '请求超时']])(
    'W7 force timeout action index %s => %s', async (index, tone, message) => {
      const { w } = await mountPage('/attacks/1', 'attacks', (path, init) => {
        if (path === '/api/active-actions/force-remove') return new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
        })
      })
      await forceButtons(w)[index]!.trigger('click')
      await w.get('[role=alertdialog] .danger').trigger('click'); await tick(30000)
      expect(notifications.at(-1)).toMatchObject({ tone, message })
    })
  it('drawer keeps error/skip/detail together, switches raw and resets formatted on reopening', async () => {
    const { w } = await mountPage('/attacks/1')
    const buttons = () => w.findAll('button').filter(n => n.text() === '详情 →')
    await buttons()[5]!.trigger('click'); await flushPromises()
    expect(document.body.textContent).toContain('connector unavailable')
    expect(document.body.textContent).toContain('delivery_failed')
    expect(document.body.textContent).toContain('Rule delivery failed; retained for diagnosis')
    await w.findComponent({ name: 'ActionDrawer' }).vm.$emit('update:modelValue', false); await flushPromises()
    await buttons()[1]!.trigger('click'); await flushPromises()
    const segment = () => w.findAllComponents(XSeg).find(s => s.props('label') === '响应内容')!
    expect(document.body.querySelector('pre')!.textContent).toBe('{\n  "ok": true,\n  "count": 2\n}')
    await segment().vm.$emit('update:modelValue', 'raw'); await flushPromises()
    expect(document.body.querySelector('pre')!.textContent).toBe('{"ok":true,"count":2}')
    await w.findComponent({ name: 'ActionDrawer' }).vm.$emit('update:modelValue', false); await flushPromises()
    await buttons()[1]!.trigger('click'); await flushPromises()
    expect(segment().props('modelValue')).toBe('formatted')
  })
  it('W12 old-id refresh cannot overwrite new summary or finish its pending refresh', async () => {
    const old = deferred<Response>(), fresh = deferred<Response>()
    const { w, router, intercept } = await mountPage('/attacks/1')
    let second = false, holderRequest = ''
    intercept((path, _init, r) => {
      if (path.includes('/1/mitigation-summary')) {
        r.body.executions[1].response_name = 'Old summary'; holderRequest = 'old'
      }
      if (path.includes('/2/mitigation-summary')) {
        r.body.executions[1].response_name = second ? 'New summary' : 'New initial'
        holderRequest = second ? 'fresh' : ''
      }
      if (path.startsWith('/api/active-actions/xdrop')) {
        const next = holderRequest; holderRequest = ''
        if (next === 'old') return old.promise
        if (next === 'fresh') return fresh.promise
      }
    })
    await w.get('.refresh-row button').trigger('click')
    await router.push('/attacks/2'); await flushPromises()
    second = true; await w.get('.refresh-row button').trigger('click')
    old.resolve(response(200, []))
    await flushPromises()
    expect(w.get('.refresh-row button').attributes('disabled')).toBeDefined()
    expect(w.text()).not.toContain('Old summary')
    fresh.resolve(response(200, []))
    await flushPromises(); expect(w.text()).toContain('New summary')
    expect(w.get('.refresh-row button').attributes('disabled')).toBeUndefined()
  })
  it.each([
    ['sample-empty', 1, '该攻击暂无流量数据。'], ['sample-expired', 1044, '流量日志已过期'],
    ['sample-error', 1, '流量样本加载失败'], ['attacks', 3, '全局攻击无流量明细'],
  ])('W13 sample state %s', async (mode, id, text) => {
    const { w } = await mountPage('/attacks/' + id, mode)
    expect(calls('/api/attacks/' + id + '/sensor-logs')).toHaveLength(0)
    await setFlow(w); expect(w.findComponent(Samples).text()).toContain(text)
    if (id === 3) {
      expect(calls('/api/attacks/3/sensor-logs')).toHaveLength(0)
      expect(w.find('.refresh-row button').exists()).toBe(false)
    }
    if (mode === 'sample-error') expect(notifications.at(-1)).toMatchObject({ message: 'flow query failed' })
  })
  it('samples load once, show loading, Top aggregates, last-hour note and local sorting', async () => {
    const pending = deferred<Response>()
    const { w, intercept } = await mountPage('/attacks/7', 'sample-last', path => {
      if (path.includes('sensor-logs')) return pending.promise
    })
    await setFlow(w); expect(w.findComponent(Samples).props('loading')).toBe(true)
    intercept()
    pending.resolve(response(200, { flows: [
      { time: '2026-10-28T11:59:00Z', protocol: 6, src_ip: 'a', dst_ip: 'b', src_port: 1, dst_port: 2,
        tcp_flags: 18, packets: 3, bytes: 1024 },
      { time: '2026-10-28T11:59:01Z', protocol: 17, src_ip: 'c', dst_ip: 'b', src_port: 3, dst_port: 2,
        tcp_flags: 0, packets: 1, bytes: 4096 },
    ], expired: false, window: 'last_1h' }))
    await flushPromises()
    const s = w.findComponent(Samples)
    expect(s.text()).toContain('75.0%'); expect(s.text()).toContain('进行中且超过 1 小时的攻击只取最近 1 小时')
    expect(s.text()).toContain('SYN ACK'); expect(s.text()).toContain('1.0 K')
    const header = s.findAll('th').find(n => n.text() === '字节数')!
    await header.trigger('click'); await header.trigger('click')
    expect(header.attributes('aria-sort')).toBe('descending')
    expect(s.findAll('table').at(-1)!.findAll('tbody tr')[0]!.text()).toContain('4.0 K')
    await w.findComponent(XTabs).vm.$emit('update:modelValue', 'log'); await flushPromises()
    await setFlow(w); await tick(10000)
    expect(calls('/api/attacks/7/sensor-logs')).toHaveLength(1)
  })
})
