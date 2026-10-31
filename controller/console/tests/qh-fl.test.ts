import { expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQE, clickText, domClick, dialog, textInput, input, clock, tick, writes, body } from './qe-harness'
import { response } from './helpers'
import { notifications } from '../src/notifications'
const calls = () => vi.mocked(fetch).mock.calls.map(([path]) => String(path))
const mount = (path = '/flow/flow-b', change?: any, admin = true, mode = 'qh') => mountQE(path, change, admin, mode)
const first = (w: any) => w.get('tr.fl-row')
const openSources = async (w: any) => clickText(first(w), '数据源 3')
it('G-fl first flow redirect and mount request set W23', async () => {
  const { w, router } = await mount('/flow')
  expect(router.currentRoute.value.path).toBe('/flow/flow-b')
  expect(calls().sort()).toEqual(['/api/nodes', '/api/nodes/flow-b/status',
    '/api/flow-listeners?node_id=flow-b', '/api/flow-listeners/1', '/api/flow-listeners/2'].sort())
  expect(w.findAll('.fl-row')).toHaveLength(2)
  expect(first(w).text()).toContain('18.4M')
  expect(first(w).get('[title="18432117"]').exists()).toBe(true)
  expect(w.findAll('.fl-row')[1]!.text()).toContain('—')
})
it.each(['/flow/edge-a', '/flow/absent'])('G-fl non-flow or absent node %s', async path => {
  const { w } = await mount(path)
  expect(w.text()).toContain(path.slice(6) + ' 不是 Flow 节点。')
  expect(w.text()).toContain('打开第一个 Flow 节点')
  expect(calls()).toEqual(['/api/nodes'])
})
it('G-fl no Flow nodes and null node list', async () => {
  const { w, router } = await mount('/flow', undefined, true, 'qh-no-flow')
  expect(w.text()).toContain('还没有 Flow 节点。在节点页添加 mode = flow 的节点。')
  expect(router.currentRoute.value.path).toBe('/flow')
  w.unmount()
  const other = await mount('/flow', (p: string) => p === '/api/nodes' ? response(200, null) : undefined)
  expect(other.w.text()).toContain('还没有 Flow 节点。')
})
it('G-fl node list failure raw message and retry', async () => {
  const { w, intercept } = await mount('/flow', (p: string) => p === '/api/nodes'
    ? response(500, { error: 'nodes failed' }) : undefined)
  expect(w.get('[role=alert]').text()).toContain('nodes failed')
  intercept(undefined)
  await clickText(w, '重试')
  expect(w.findAll('.fl-row')).toHaveLength(2)
})
it('G-fl status alone polls three times in 30s; leaves no timer W8 W10', async () => {
  clock()
  const { w, router } = await mount()
  const initial = calls().length
  await tick(30000)
  expect(calls().slice(initial)).toEqual(Array(3).fill('/api/nodes/flow-b/status'))
  await router.push('/users'); await flushPromises()
  const before = calls().length
  await tick(30000)
  expect(calls()).toHaveLength(before)
  expect(vi.getTimerCount()).toBe(0)
  w.unmount()
})
it.each(['listeners', 'status'])('G-fl switch aborts and discards late %s response W9', async kind => {
  let finish!: (r: Response) => void, signal: AbortSignal | undefined
  const pending = new Promise<Response>(resolve => { finish = resolve })
  const path = kind === 'listeners' ? '/api/flow-listeners?node_id=flow-b' : '/api/nodes/flow-b/status'
  const { w, router } = await mount('/flow/flow-b', (p: string, init: RequestInit) => {
    if (p === path) { signal = init.signal as AbortSignal; return pending }
  })
  await router.push('/flow/flow-d'); await flushPromises()
  expect(signal!.aborted).toBe(true)
  expect(w.text()).toContain(':4739')
  finish(response(200, kind === 'listeners' ? [{ id: 99, node_id: 'flow-b', listen_address: ':9999',
    protocol_mode: 'auto', description: 'STALE', enabled: true }] : { online: false, uptime_seconds: 999 }))
  await flushPromises()
  expect(w.text()).toContain(':4739')
  expect(w.text()).not.toContain(':9999')
  expect(w.get('.fl-status').text()).toContain('在线')
  expect(w.get('.fl-status').text()).not.toContain('16m')
})
it('G-fl status failure preserves last values and emits no notification W11', async () => {
  clock()
  const { w, intercept } = await mount()
  const before = notifications.length
  const health = w.get('.fl-health').text()
  intercept((p: string) => p.endsWith('/status') ? response(500, { error: 'flow status unavailable' }) : undefined)
  await tick(10000)
  expect(w.get('.fl-health').text()).toBe(health)
  expect(w.get('.fl-status-error').text()).toBe('flow status unavailable')
  expect(notifications).toHaveLength(before)
})
it('G-fl initial qh-status-fail remains local', async () => {
  const before = notifications.length
  const { w } = await mount('/flow/flow-b', undefined, true, 'qh-status-fail')
  expect(w.get('.fl-status-error').text()).toBe('flow status unavailable')
  expect(w.find('.fl-health').exists()).toBe(false)
  expect(notifications).toHaveLength(before)
})
it.each([['qh-offline', false], ['qh-stale', true]] as const)(
  'G-fl %s stale metrics and independent connection uptime W27', async (mode, connected) => {
    const { w } = await mount('/flow/flow-b', undefined, true, mode)
    expect(w.get('.fl-status').text()).toContain('离线')
    expect(w.get('.fl-health').text()).toContain('指标已过期（离线前最后一次上报）')
    expect(w.get('.fl-health').text().includes('连接时长 3d 4h 12m')).toBe(connected)
    expect(w.findAll('.fl-muted')).toHaveLength(3)
  })
it('G-fl no metrics hides three cards; absent uptime hides duration', async () => {
  const { w } = await mount('/flow/flow-b', (p: string) => p.endsWith('/status')
    ? response(200, { online: false }) : undefined)
  expect(w.findAll('.kpi')).toHaveLength(1)
  expect(w.text()).not.toContain('连接时长')
})
it('G-fl empty listeners and list retry', async () => {
  const { w } = await mount('/flow/flow-b', undefined, true, 'qh-empty')
  expect(w.get('.fl-panel').text()).toContain('暂无数据')
  w.unmount()
  const failed = await mount('/flow/flow-b', (p: string) => p.startsWith('/api/flow-listeners?')
    ? response(500, { error: 'list failed' }) : undefined)
  expect(failed.w.get('.fl-panel [role=alert]').text()).toContain('list failed')
  failed.intercept(undefined)
  await clickText(failed.w, '重试')
  expect(failed.w.findAll('.fl-row')).toHaveLength(2)
})
it('G-fl detail failure unknown count and source retry', async () => {
  const { w, intercept } = await mount('/flow/flow-b', undefined, true, 'qh-detail-fail')
  expect(first(w).text()).toContain('数据源 —')
  await clickText(first(w), '数据源 —')
  expect(dialog().textContent).toContain('flow sources unavailable')
  intercept((p: string) => p === '/api/flow-listeners/1' ? response(200, { listener: {}, sources: [] }) : undefined)
  await domClick('重试')
  expect(dialog().textContent).toContain('暂无数据')
})
it('G-fl Listener toggle complete body and optimistic rollback W4 W12', async () => {
  const { w, intercept } = await mount()
  await first(w).get('[role=switch]').trigger('click')
  expect(body()).toEqual({ listen_address: '0.0.0.0:6343', protocol_mode: 'sflow',
    description: 'Flow input', enabled: false })
  await flushPromises()
  expect(notifications.at(-1)?.message).toBe('已更新')
  let finish!: (r: Response) => void
  const pending = new Promise<Response>(resolve => { finish = resolve })
  intercept((p: string, init: RequestInit) => init.method === 'PUT' ? pending : undefined)
  await first(w).get('[role=switch]').trigger('click')
  expect(first(w).get('[role=switch]').attributes('aria-checked')).toBe('true')
  expect(first(w).get('[role=switch]').attributes('disabled')).toBeDefined()
  finish(response(500, { error: 'toggle failed' })); await flushPromises()
  expect(first(w).get('[role=switch]').attributes('aria-checked')).toBe('false')
  expect(notifications.at(-1)?.message).toBe('toggle failed')
})
it('G-fl Listener create/edit and backend 400 stays open', async () => {
  const { w } = await mount()
  await clickText(w, '添加 Listener')
  await domClick('保存')
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe('请输入监听地址')
  expect(writes()).toHaveLength(0)
  await textInput('监听地址', '16343')
  await domClick('保存')
  expect(dialog().textContent).toContain('listen_address must be :port or host:port format')
  expect(notifications.at(-1)?.message).toBe('listen_address must be :port or host:port format')
  await textInput('监听地址', ' :16343 ')
  await domClick('保存')
  expect(body()).toEqual({ node_id: 'flow-b', listen_address: ':16343', protocol_mode: 'auto', description: '' })
  expect(document.querySelector('[role=dialog]')).toBeNull()
  await first(w).trigger('click')
  await textInput('描述', ' updated ')
  await domClick('保存')
  expect(body()).toEqual({ listen_address: '0.0.0.0:6343', protocol_mode: 'sflow',
    description: ' updated ', enabled: true })
})
it('G-fl Listener delete known count and failure keeps confirmation W16', async () => {
  const { w, intercept } = await mount()
  await clickText(first(w), '删除')
  expect(w.get('[role=alertdialog]').text()).toContain('它下面的 3 个数据源会一起删除。')
  intercept((p: string, init: RequestInit) => init.method === 'DELETE'
    ? response(500, { error: 'delete failed' }) : undefined)
  await clickText(w.get('[role=alertdialog]'), '删除')
  expect(w.get('[role=alertdialog]').text()).toContain('delete failed')
  intercept(undefined)
  await clickText(w.get('[role=alertdialog]'), '删除')
  expect(w.findAll('.fl-row')).toHaveLength(1)
  expect(notifications.at(-1)?.message).toBe('已删除')
})
it('G-fl Listener delete unknown count uses explicit cascade warning', async () => {
  const { w } = await mount('/flow/flow-b', undefined, true, 'qh-detail-fail')
  await clickText(first(w), '删除')
  expect(w.get('[role=alertdialog]').text()).toContain('它下面的数据源会一起删除。')
})
it('G-fl source list prefix removal and live status during polling', async () => {
  clock()
  const { w, intercept } = await mount()
  await openSources(w)
  expect(dialog().textContent).toContain('192.0.2.1')
  expect(dialog().textContent).not.toContain('/32')
  expect([...dialog().querySelectorAll('.fl-source-row')].map(r => r.children[2]!.textContent!.trim()))
    .toEqual(['在线', '离线', '—'])
  intercept((p: string) => p.endsWith('/status') ? response(200, { online: true,
    source_statuses: [{ device_ip: '192.0.2.1', active: false }] }) : undefined)
  await tick(10000)
  expect(dialog().querySelector('.fl-source-row')!.children[2]!.textContent).toContain('离线')
})
it('G-fl source three views, validation, create and edit strips prefix W3 W13', async () => {
  const { w } = await mount()
  await openSources(w)
  await domClick('添加数据源')
  expect(dialog().querySelector('input[aria-label="采样率"]')).toBeNull()
  await domClick('保存')
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe('请输入名称')
  await textInput('名称', ' New ')
  await domClick('保存')
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe('请输入设备 IP')
  await textInput('设备 IP', '192.0.2.2/32')
  await domClick('保存')
  expect(dialog().textContent).toContain('device_ip must be a valid IPv4 or IPv6 address')
  await textInput('设备 IP', ' 192.0.2.2 ')
  await domClick('保存')
  expect(body()).toEqual({ listener_id: 1, name: 'New', device_ip: '192.0.2.2', sample_mode: 'auto',
    sample_rate: 1000, description: '' })
  expect(dialog().querySelectorAll('.fl-source-row')).toHaveLength(4)
  ;(dialog().querySelector('.fl-source-row') as HTMLElement).click(); await flushPromises()
  expect((dialog().querySelector('input[placeholder="192.0.2.1"]') as HTMLInputElement).value).toBe('192.0.2.1')
  await textInput('名称', ' Edited ')
  await domClick('保存')
  expect(body()).toEqual({ name: 'Edited', device_ip: '192.0.2.1', sample_mode: 'force', sample_rate: 1000,
    description: 'Core exporter', enabled: true })
  await domClick('添加数据源'); await domClick('← 数据源')
  expect(dialog().querySelectorAll('.fl-source-row')).toHaveLength(4)
})
it.each([['1.5', 2], ['0', 1]] as const)('G-fl force rate blur %s -> %s W14', async (typed, want) => {
  const { w } = await mount()
  await openSources(w); await domClick('添加数据源')
  await domClick('强制')
  await textInput('名称', 'Forced')
  await textInput('设备 IP', '203.0.113.3')
  await input('采样率', typed)
  await domClick('保存')
  expect(body().sample_mode).toBe('force')
  expect(body().sample_rate).toBe(want)
})
it('G-fl source toggle preserves zero, failure rollback, and deletion', async () => {
  const { w, intercept } = await mount()
  await openSources(w)
  const switchAt = () => dialog().querySelectorAll<HTMLButtonElement>('[role=switch]')[1]!
  switchAt().click(); await flushPromises()
  expect(body()).toEqual({ name: 'Router IPv6', device_ip: '2001:db8::1', sample_mode: 'auto', sample_rate: 0,
    description: 'IPv6 exporter', enabled: true })
  let finish!: (r: Response) => void
  intercept((p: string, init: RequestInit) => init.method === 'PUT'
    ? new Promise<Response>(resolve => { finish = resolve }) : undefined)
  switchAt().click(); await flushPromises()
  expect(switchAt().getAttribute('aria-checked')).toBe('false')
  finish(response(500, { error: 'source failed' })); await flushPromises()
  expect(switchAt().getAttribute('aria-checked')).toBe('true')
  intercept(undefined)
  const row = dialog().querySelector('.fl-source-row')!
  ;(row.querySelector('.danger') as HTMLElement).click(); await flushPromises()
  expect(dialog().querySelector('[role=alertdialog]')?.textContent).toContain('删除数据源 Router IPv4？')
  ;(dialog().querySelector('[role=alertdialog] .danger') as HTMLElement).click(); await flushPromises()
  expect(dialog().querySelectorAll('.fl-source-row')).toHaveLength(2)
})
it('G-fl viewer has no writes, switches or deletion and both drawers are read-only W15', async () => {
  const { w } = await mount('/flow/flow-b', undefined, false)
  expect(w.find('[role=switch]').exists()).toBe(false)
  expect(w.text()).not.toMatch(/添加 Listener|删除/)
  await first(w).trigger('click')
  expect(dialog().textContent).toContain('查看 Listener')
  expect([...dialog().querySelectorAll('input')].every(i => i.disabled)).toBe(true)
  expect(dialog().textContent).not.toContain('保存')
  await domClick('取消')
  await openSources(w)
  expect(dialog().querySelector('[role=switch]')).toBeNull()
  expect(dialog().textContent).not.toMatch(/添加数据源|删除/)
  ;(dialog().querySelector('.fl-source-row') as HTMLElement).click(); await flushPromises()
  expect(dialog().textContent).toContain('查看数据源 Router IPv4')
  expect([...dialog().querySelectorAll('input')].every(i => i.disabled)).toBe(true)
  expect(dialog().textContent).not.toContain('保存')
})
it('G-fl visible label for/id and XSeg labelledby literal associations W24', async () => {
  const { w } = await mount()
  await clickText(w, '添加 Listener')
  const check = () => {
    const d = dialog()
    for (const control of d.querySelectorAll<HTMLInputElement>('input')) {
      expect(control.id).not.toBe('')
      const label = [...d.querySelectorAll('label')].find(l => l.htmlFor === control.id)
      expect(label?.textContent?.trim()).not.toBe('')
      expect(label).toBeDefined()
      label!.click()
      // Native label focus is verified in the built-in browser; jsdom omits that default action.
    }
    for (const group of d.querySelectorAll('[role=group]')) {
      const labelId = group.getAttribute('aria-labelledby')
      expect(labelId).toBeTruthy()
      expect(document.getElementById(labelId!)?.textContent?.trim()).not.toBe('')
    }
  }
  check()
  await domClick('取消')
  await openSources(w); await domClick('添加数据源'); await domClick('强制')
  check()
})
it('G-fl leaving while write pending still emits its result W25', async () => {
  let finish!: (r: Response) => void
  const { w, router } = await mount('/flow/flow-b', (p: string, init: RequestInit) => init.method === 'POST'
    ? new Promise<Response>(resolve => { finish = resolve }) : undefined)
  await clickText(w, '添加 Listener')
  await textInput('监听地址', ':16343')
  await domClick('保存')
  await router.push('/users'); await flushPromises()
  finish(response(201, { id: 4 })); await flushPromises()
  expect(notifications.at(-1)?.message).toBe('Listener 已创建')
})
it('G-fl A1 row switches have literal accessible names without repeated visible labels', async () => {
  const { w } = await mount()
  expect(first(w).find('label').exists()).toBe(false)
  const listener = first(w).get('[role=switch]')
  expect(listener.attributes('aria-label')).toBe('启用 Listener 0.0.0.0:6343')
  await listener.trigger('click'); await flushPromises()
  expect(body().enabled).toBe(false)
  await openSources(w)
  const row = dialog().querySelector('.fl-source-row')!
  expect(row.querySelector('label')).toBeNull()
  const source = row.querySelector<HTMLButtonElement>('[role=switch]')!
  expect(source.getAttribute('aria-label')).toBe('启用数据源 Router IPv4')
  source.click(); await flushPromises()
  expect(body().enabled).toBe(false)
})
it('G-fl old node save cannot close or reload the new node drawer W34', async () => {
  let finish!: (r: Response) => void
  const { w, router } = await mount('/flow/flow-b', (_: string, init: RequestInit) => init.method === 'POST'
    ? new Promise<Response>(resolve => { finish = resolve }) : undefined)
  await clickText(w, '添加 Listener'); await textInput('监听地址', ':16343'); await domClick('保存')
  expect(dialog().getAttribute('aria-busy')).toBe('true')
  await router.push('/flow/flow-d'); await flushPromises()
  await clickText(w, '添加 Listener'); await textInput('监听地址', ':16344')
  expect.soft(dialog().getAttribute('aria-busy')).toBe('false')
  const before = calls().slice()
  finish(response(201, { id: 4 })); await flushPromises()
  expect(document.querySelector('[role=dialog]')).not.toBeNull()
  expect(dialog().querySelector<HTMLInputElement>('input')!.value).toBe(':16344')
  expect(dialog().textContent).toContain('添加 Listener')
  expect(calls()).toEqual(before)
  expect(notifications.at(-1)?.message).toBe('Listener 已创建')
})
it.each(['success', 'failure'])('G-fl latest status wins over old %s response W35', async outcome => {
  clock()
  const { w, intercept } = await mount()
  let finish!: (r: Response) => void, count = 0
  intercept((p: string) => {
    if (!p.endsWith('/status')) return
    if (++count === 1) return new Promise<Response>(resolve => { finish = resolve })
    return response(200, { online: true,
      flow_metrics: { decode_errors: 3, unknown_exporter: 0, template_misses: 0 } })
  })
  await tick(10000); await tick(10000)
  expect(w.get('.fl-status').text()).toContain('在线')
  expect(w.findAll('.fl-health .kpi')[1]!.get('.v').text()).toBe('3')
  const updated = w.get('.page-head .sub').text()
  await tick(1000)
  finish(outcome === 'success' ? response(200, { online: false,
    flow_metrics: { decode_errors: 2, unknown_exporter: 0, template_misses: 0 } })
    : response(500, { error: 'old status failure' }))
  await flushPromises()
  expect(w.get('.fl-status').text()).toContain('在线')
  expect(w.findAll('.fl-health .kpi')[1]!.get('.v').text()).toBe('3')
  expect(w.get('.page-head .sub').text()).toBe(updated)
  expect(w.find('.fl-status-error').exists()).toBe(false)
})
it('G-fl B3 force int32 overflow reaches backend and keeps form with raw 500', async () => {
  const { w } = await mount()
  await openSources(w); await domClick('添加数据源')
  await textInput('名称', 'Overflow'); await textInput('设备 IP', '192.0.2.8'); await domClick('强制')
  await input('采样率', '2147483648'); await domClick('保存')
  expect(body().sample_rate).toBe(2147483648)
  expect(dialog().textContent).toContain('添加数据源')
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe('database error')
  expect(notifications.at(-1)?.message).toBe('database error')
})
it('G-fl B4 editing Auto zero seed only changes name and sends 1000', async () => {
  const { w } = await mount()
  await openSources(w)
  ;(dialog().querySelectorAll('.fl-source-row')[1] as HTMLElement).click(); await flushPromises()
  await textInput('名称', 'Renamed IPv6'); await domClick('保存')
  expect(body()).toEqual({ name: 'Renamed IPv6', device_ip: '2001:db8::1', sample_mode: 'auto',
    sample_rate: 1000, description: 'IPv6 exporter', enabled: false })
  expect(dialog().textContent).toContain('Renamed IPv6')
})
