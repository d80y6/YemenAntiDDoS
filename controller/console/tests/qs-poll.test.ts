import { beforeEach, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQD, calls, clock, tick, clickText } from './qd-harness'
import { deferred, response } from './helpers'
import Mitigations from '../src/views/mitigations/Mitigations.vue'
const paths = ['/api/active-actions/bgp', '/api/active-actions/bgp/dismissed-orphans',
  '/api/active-actions/xdrop', '/api/settings/xdrop-connectors']
const setup = (w: any) => w.findComponent(Mitigations).vm.$.setupState as any
const timestamp = (w: any) => w.get('.page-head > .sub').text()
const base = new Date('2026-10-28T12:00:00').getTime()
beforeEach(() => { clock(); vi.setSystemTime(base) })
const noNames = (rows: any[]) => rows.map(r => ({ ...r, connector_name: '' }))
it('K2 pending xdrop leaves other datasets independent and updated at the minimum', async () => {
  const { w, intercept } = await mountQD('/mitigations', 'qd', (p, _init, r) => p === paths[2]
    ? response(200, noNames(r.body)) : undefined)
  expect(timestamp(w)).toBe('更新于 12:00:00')
  const pending = deferred<Response>()
  let rules: any[] = []
  intercept((p, _init, r) => {
    if (p === paths[2]) { rules = noNames(r.body); return pending.promise }
    if (p === paths[0]) return response(200, r.body.map((v: any) => ({ ...v, route_map: 'fresh-bgp' })))
    if (p === paths[1]) return response(200, r.body.map((v: any) => ({ ...v, route_map: 'fresh-dismissed' })))
    if (p === paths[3]) return response(200, r.body.map((v: any) => ({ ...v, name: 'fresh-connector' })))
  })
  await tick(5000)
  await w.get('[data-testid=bgp] .panel-head button').trigger('click')
  expect(w.text()).toContain('fresh-bgp')
  expect(w.text()).toContain('fresh-dismissed')
  expect(w.text()).toContain('fresh-connector')
  expect(timestamp(w)).toBe('更新于 12:00:00')
  await tick(2000)
  pending.resolve(response(200, rules)); await flushPromises()
  expect(timestamp(w)).toBe('更新于 12:00:05')
})
it('K2 staggered success, non-earliest failure freezes updated until recovery', async () => {
  const initial = paths.map(() => deferred<Response>()), bodies: any[] = []
  const { w, intercept } = await mountQD('/mitigations', 'qd', (p, _init, r) => {
    const i = paths.indexOf(p)
    if (i >= 0) { bodies[i] = r.body; return initial[i]!.promise }
  })
  for (let i = 0; i < 4; i++) {
    vi.setSystemTime(base + i * 1000)
    initial[i]!.resolve(response(200, bodies[i])); await flushPromises()
  }
  expect(timestamp(w)).toBe('更新于 12:00:00')
  const next = paths.map(() => deferred<Response>())
  intercept(p => next[paths.indexOf(p)]?.promise)
  const refreshed = setup(w).poll.refresh()
  vi.setSystemTime(base + 4000)
  next[3]!.resolve(response(503, { error: 'connectors unavailable' })); await flushPromises()
  for (let i = 0; i < 3; i++) {
    vi.setSystemTime(base + (i + 5) * 1000)
    next[i]!.resolve(response(200, bodies[i])); await flushPromises()
    expect(timestamp(w)).toBe('更新于 12:00:00')
  }
  await refreshed
  vi.setSystemTime(base + 8000)
  intercept()
  await setup(w).poll.refresh(); await flushPromises()
  expect(timestamp(w)).toBe('更新于 12:00:08')
})
it('K2 first connectors pending blocks button and execute, explicit failure permits release', async () => {
  const pending = deferred<Response>()
  const { w } = await mountQD('/mitigations', 'qd', p => p === paths[3] ? pending.promise : undefined)
  const button = () => w.get('[data-testid=xdrop] tr.link button')
  expect(button().attributes('disabled')).toBeDefined()
  await button().trigger('click')
  expect(calls('/api/active-actions/force-remove')).toHaveLength(0)
  const page = setup(w)
  page.ask(page.xdrop[0], 'xdrop')
  await expect(page.execute()).rejects.toThrow('加载中…')
  expect(calls('/api/active-actions/force-remove')).toHaveLength(0)
  pending.resolve(response(503, { error: 'connector lookup failed' })); await flushPromises()
  expect(button().attributes('disabled')).toBeUndefined()
  await page.execute(); await flushPromises()
  expect(calls('/api/active-actions/force-remove')).toHaveLength(1)
})
it('K2 dismissed first pending shows loading, empty only after arrival', async () => {
  const pending = deferred<Response>()
  const { w } = await mountQD('/mitigations', 'qd', p => p === paths[1] ? pending.promise : undefined)
  await w.get('[data-testid=bgp] .panel-head button').trigger('click')
  expect(w.get('.sub-tbl').text()).toContain('加载中…')
  expect(w.get('.sub-tbl').text()).not.toContain('无已忽略的孤立路由')
  pending.resolve(response(200, [])); await flushPromises()
  expect(w.get('.sub-tbl').text()).toContain('无已忽略的孤立路由')
  expect(w.get('.sub-tbl').text()).not.toContain('加载中…')
})
it('K2 pending node overview does not block the node list', async () => {
  const pending = deferred<Response>()
  const { w } = await mountQD('/nodes', 'qd', p => p.startsWith('/api/stats/overview') ? pending.promise : undefined)
  expect(w.findAll('tbody tr').length).toBeGreaterThan(0)
  expect(w.text()).toContain('edge-a')
  expect(w.text()).not.toContain('更新于')
  pending.resolve(response(200, { nodes: [] })); await flushPromises()
  expect(w.text()).toContain('更新于 12:00:00')
})
it.each([0, 1, 2, 3])('K2 write refresh invalidates late dataset %s with different data', async index => {
  const old = deferred<Response>()
  let count = 0, oldBody: any
  const fresh = index === 2 ? '203.0.113.99' : 'fresh-dataset'
  const stale = index === 2 ? '203.0.113.88' : 'stale-dataset'
  const changed = (rows: any[], value: string) => rows.map(row => ({ ...row,
    ...{ [index === 2 ? 'dst_ip' : index === 3 ? 'name' : 'route_map']: value } }))
  const { w } = await mountQD('/mitigations', 'qd', (p, _init, r) => {
    if (p === paths[2]) r.body = noNames(r.body)
    if (p !== paths[index]) return
    count++
    if (count === 2) { oldBody = changed(r.body, stale); return old.promise }
    if (count >= 3) return response(200, changed(r.body, fresh))
  })
  await tick(5000)
  expect(calls(paths[index]!)).toHaveLength(2)
  await w.get('[data-testid=bgp] tr.link button').trigger('click'); await flushPromises()
  await clickText(w.get('[role=alertdialog]'), '撤回')
  expect(calls(paths[index]!)).toHaveLength(3)
  if (index === 1) await w.get('[data-testid=bgp] .panel-head button').trigger('click')
  expect(w.text()).toContain(fresh)
  old.resolve(response(200, oldBody)); await flushPromises()
  expect(w.text()).toContain(fresh)
  expect(w.text()).not.toContain(stale)
})
