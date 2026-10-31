import { it, expect, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQD, calls, clock, tick, params, clickText, dialog, domClick } from './qd-harness'
import { deferred, response } from './helpers'
import { notifications } from '../src/notifications'
const rows = (w: any) => w.findAll('.nodes-page > .tbl-wrap tbody tr')
const fill = async (selector: string, value: string) => {
  const input = dialog().querySelector<HTMLInputElement>(selector)!
  input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })); await flushPromises()
}
it('nodes two requests 5s unmount zero and null empty', async () => {
  clock(); const { w } = await mountQD('/nodes')
  expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2)
  expect(calls('/api/nodes')).toHaveLength(1)
  expect(params(calls('/api/stats/overview')[0]).get('direction')).toBe('receives')
  await tick(5000); expect(vi.mocked(fetch)).toHaveBeenCalledTimes(4)
  w.unmount(); await tick(10000); expect(vi.mocked(fetch)).toHaveBeenCalledTimes(4)
  const empty = await mountQD('/nodes', 'null'); expect(empty.w.text()).toContain('暂无节点')
})
it('W19 W21 eight columns, 2/3 online, neutral offline missing heartbeat no suffix; config and readings', async () => {
  const { w } = await mountQD('/nodes')
  expect(w.findAll('th')).toHaveLength(8); expect(w.text()).toContain('2 / 3 在线')
  expect(rows(w)[1].get('.dot').classes()).toContain('neutral')
  expect(rows(w)[1].get('.dot').classes()).not.toContain('crit')
  expect(rows(w)[1].text()).not.toContain('前')
  expect(rows(w)[0].text()).toContain('1.00K'); expect(rows(w)[0].text()).toContain('1.08 Kbps')
  expect(rows(w)[2].findAll('td')[3].text()).toBe('—')
  expect(rows(w)[0].text()).toContain('已同步'); expect(rows(w)[1].text()).toContain('待下发 · 落后 2')
  expect(rows(w)[2].get('.pill').classes()).toContain('crit')
  expect(rows(w)[1].findAll('td')[6].text()).toBe('—')
})
it.each(['qd', 'qd-status-interfaces', 'qd-status-none', 'qd-status-404'])('XDP detail %s capture and exact 15m curve',
  async mode => {
    clock(); const { w } = await mountQD('/nodes', mode)
    await rows(w)[0].trigger('click'); await flushPromises()
    expect(calls('/api/nodes/edge-a/status')).toHaveLength(1)
    expect(calls('/api/flow-listeners')).toHaveLength(0)
    expect(Object.fromEntries(params(calls('/api/stats/total-timeseries')[0]))).toEqual({ node_id: 'edge-a',
      direction: 'receives', resolution: '5s', from: '2026-10-28T11:45:00.000Z' })
    expect(dialog().querySelector('svg')?.getAttribute('viewBox')).toBe('0 0 400 56')
    expect(dialog().querySelector('svg')?.getAttribute('aria-label')).toBe('最近 15 分钟入向 pps')
    expect(dialog().textContent).not.toMatch(/镜像|mirror|erspan/i)
    expect(dialog().textContent).not.toMatch(/拒绝|reject/i)
    if (mode === 'qd') for (const text of ['eth1 · 不采样', 'eth2 · 不采样', 'eth3 · 1:300 采样']) {
      expect(dialog().textContent).toContain(text)
    }
    if (mode === 'qd-status-interfaces') expect(dialog().textContent).toContain('eth1, eth2')
    if (mode === 'qd-status-none' || mode === 'qd-status-404') expect(dialog().querySelector('.capture')?.textContent)
      .toContain('—')
  })
it('W26 Flow offline detail listener only no status no timeseries', async () => {
  const { w } = await mountQD('/nodes')
  await rows(w)[1].trigger('click'); await flushPromises()
  expect(calls('/api/flow-listeners')).toHaveLength(1)
  expect(params(calls('/api/flow-listeners')[0]).get('node_id')).toBe('flow-b')
  expect(calls('/api/nodes/flow-b/status')).toHaveLength(0)
  expect(calls('/api/stats/total-timeseries')).toHaveLength(0)
  expect(dialog().textContent).toContain('Flow 监听 1')
  expect(dialog().textContent).toContain('节点离线，没有近期读数。')
})
it('W20 slash DELETE encoded, success closes and refreshes', async () => {
  const { w } = await mountQD('/nodes', 'qd-slash')
  await rows(w)[0].trigger('click'); await flushPromises(); await domClick('删除…'); await domClick('删除')
  expect(calls('/api/nodes/a%2Fb')).toHaveLength(1)
  expect(calls('/api/nodes/a%2Fb')[0]![1]?.method).toBe('DELETE')
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(notifications.at(-1)).toMatchObject({ message: '已删除', tone: 'ok' })
  expect(calls('/api/nodes')).toHaveLength(2)
})
it('delete 500 original message confirmation remains', async () => {
  const { w } = await mountQD('/nodes', 'qd-delete-error')
  await rows(w)[0].trigger('click'); await flushPromises(); await domClick('删除…'); await domClick('删除')
  expect(dialog().querySelector('[role=alertdialog]')?.textContent)
    .toContain('failed to delete flow listener: database error')
  expect(notifications.at(-1)?.tone).toBe('crit')
})
it('add empty disabled generate 64 hex, snippets update Flow body original, resets after 201', async () => {
  const { w } = await mountQD('/nodes'); await clickText(w, '添加节点')
  expect([...dialog().querySelectorAll('button')].find(b => b.textContent === '添加')?.disabled).toBe(true)
  await fill('input', ' edge-03 '); await domClick('生成')
  expect(dialog().querySelector<HTMLInputElement>('#node-key')!.value).toMatch(/^[a-f0-9]{64}$/)
  await fill('#node-key', ' literal-key ')
  await fill('input[placeholder="如 机房 C · 核心交换机"]', ' room C ')
  await domClick('Flow'); expect(dialog().querySelector('pre')?.textContent).toMatch(/^mode: flow\n/)
  await domClick('添加')
  const post = calls('/api/nodes').find(c => c[1]?.method === 'POST')!
  expect(JSON.parse(String(post[1]?.body))).toEqual({ id: ' edge-03 ', api_key: ' literal-key ',
    description: ' room C ', mode: 'flow' })
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(notifications.at(-1)).toMatchObject({ message: '节点已创建', tone: 'ok' })
  expect(calls('/api/nodes').filter(c => !c[1]?.method)).toHaveLength(2)
  await clickText(w, '添加节点')
  expect(dialog().querySelector<HTMLInputElement>('input')!.value).toBe('')
  expect(dialog().querySelector('pre')?.textContent).not.toMatch(/^mode: flow/)
})
it('add 409 keeps drawer and original error', async () => {
  const { w } = await mountQD('/nodes', 'qd-create-conflict'); await clickText(w, '添加节点')
  await fill('input', 'edge-03'); await fill('#node-key', 'abc'); await domClick('添加')
  expect(dialog().textContent).toContain('already exists')
  expect(notifications.at(-1)).toMatchObject({ message: 'already exists', tone: 'crit' })
})
it.each(['edge/03', '.', '..'])('W33 add invalid %s blocks and never POSTs', async id => {
  const { w } = await mountQD('/nodes'); await clickText(w, '添加节点')
  await fill('input', id); await fill('#node-key', 'abc')
  expect(dialog().textContent).toContain('节点 ID 不能包含 /，也不能是 . 或 ..')
  expect([...dialog().querySelectorAll('button')].find(b => b.textContent === '添加')?.disabled).toBe(true)
  expect(calls('/api/nodes').filter(c => c[1]?.method === 'POST')).toHaveLength(0)
})
it('W16 viewer has no add or delete entrance', async () => {
  const { w } = await mountQD('/nodes', 'qd', undefined, false)
  expect(w.findAll('button').some(b => b.text() === '添加节点')).toBe(false)
  await rows(w)[0].trigger('click'); await flushPromises()
  expect(dialog().textContent).not.toContain('删除节点')
  expect(dialog().querySelector('.danger-zone')).toBeNull()
})
for (const op of ['add', 'delete']) for (const outcome of ['success', 'error']) it('W28 node ' + op
  + ' route-unmounted ' + outcome + ' global notification', async () => {
  const pending = deferred<Response>()
  const { w, router } = await mountQD('/nodes', 'qd', (_p, init) => ['POST', 'DELETE'].includes(init.method || '')
    ? pending.promise : undefined)
  if (op === 'add') {
    await clickText(w, '添加节点'); await fill('input', 'edge-03'); await fill('#node-key', 'abc')
    await domClick('添加')
  } else { await rows(w)[0].trigger('click'); await flushPromises(); await domClick('删除…'); await domClick('删除') }
  await router.push('/other'); await flushPromises(); expect(document.querySelector('[role=dialog]')).toBeNull()
  pending.resolve(response(outcome === 'error' ? 500 : op === 'add' ? 201 : 200,
    outcome === 'error' ? { error: 'raw node failure' } : { ok: true }))
  await flushPromises()
  expect(notifications.at(-1)?.tone).toBe(outcome === 'error' ? 'crit' : 'ok')
  if (outcome === 'error') expect(notifications.at(-1)?.message).toBe('raw node failure')
})
it('nodes and overview independent retain previous data on errors', async () => {
  clock(); const { w, intercept } = await mountQD('/nodes')
  intercept(p => p.split('?')[0] === '/api/stats/overview' ? response(503, { error: 'overview down' }) : undefined)
  await tick(5000); expect(rows(w)[0].text()).toContain('1.00K')
  intercept(p => p.split('?')[0] === '/api/nodes' ? response(503, { error: 'nodes raw' }) : undefined)
  await tick(5000); expect(w.text()).toContain('nodes raw'); expect(rows(w)).toHaveLength(3)
})
it('node write refresh supersedes an older pending list round', async () => {
  clock(); let requests = 0
  const old = deferred<Response>()
  const { w } = await mountQD('/nodes', 'qd', (p, init) => p.split('?')[0] === '/api/nodes' && !init.method
    && ++requests === 2 ? old.promise : undefined)
  await clickText(w, '添加节点'); await fill('input', 'edge-03'); await fill('#node-key', 'abc')
  await tick(5000); await domClick('添加')
  expect(calls('/api/nodes').filter(c => !c[1]?.method)).toHaveLength(3)
  old.resolve(response(200, null)); await flushPromises(); expect(rows(w)).toHaveLength(3)
})

it('W20 slash node href encoded independently of DELETE', async () => {
  const { w } = await mountQD('/nodes', 'qd-slash')
  expect(w.get('a').attributes('href')).toBe('/flow/a%2Fb')
})
