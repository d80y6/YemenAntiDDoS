import { expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQE, clickText, calls, clock, tick, writes, textInput } from './qe-harness'
import { deferred, response } from './helpers'
import { notifications } from '../src/notifications'
const mount = (url = '/responses', mode = 'qf', admin = true) => mountQE(url, undefined, admin, mode)
it('G-rs list one GET no polling 60s, eight columns and null empty', async () => {
  clock()
  const { w, intercept } = await mount()
  expect(calls('/api/responses')).toHaveLength(1)
  await tick(60000)
  expect(calls('/api/responses')).toHaveLength(1)
  expect(w.findAll('th').map(c => c.text())).toEqual([
    'ID', '名称', '描述', '动作 ?含攻击结束时自动生成的解除 / 撤回动作', '绑定模板', '已启用', '创建时间', '操作'])
  expect(w.findAll('tbody tr')).toHaveLength(3)
  expect(w.find('[role=tooltip]').text()).toContain('含攻击结束时自动生成')
  intercept(path => path === '/api/responses' ? response(500, { error: 'list unavailable' }) : undefined)
  // Re-enter gives a fresh load; null is tested independently below.
  w.unmount()
  const empty = await mount('/responses', 'qf-empty')
  expect(empty.w.text()).toContain('暂无数据')
})
it('G-rs delete 409 exact original remains open with global notification', async () => {
  const { w } = await mount()
  await w.findAll('tbody tr')[0]!.findAll('button').at(-1)!.trigger('click')
  expect(w.find('[role=alertdialog]').text()).toContain('删除响应「Observe」？')
  await clickText(w.find('[role=alertdialog]'), '删除')
  expect(w.find('[role=alertdialog]').text()).toContain('response in use by template "Transit defaults" (id=7)')
  expect(notifications.at(-1)?.message).toBe('response in use by template "Transit defaults" (id=7)')
})
it('G-rs adding empty name disabled, focused, POST two keys stays list and reloads', async () => {
  const { w, router } = await mount()
  await clickText(w, '添加响应')
  expect(document.activeElement?.getAttribute('autocomplete')).toBe('off')
  const dialog = document.querySelector('[role=dialog]')!
  expect([...dialog.querySelectorAll('button')].find(b => b.textContent === '创建')?.disabled).toBe(true)
  await textInput('名称', ' New response ')
  await textInput('描述', 'description')
  ;[...dialog.querySelectorAll('button')].find(b => b.textContent === '创建')!.click()
  await flushPromises()
  expect(writes().map(([p, init]) => [p, JSON.parse(String(init?.body))]))
    .toEqual([['/api/responses', { name: 'New response', description: 'description' }]])
  expect(router.currentRoute.value.path).toBe('/responses')
  expect(calls('/api/responses').filter(c => !c[1]?.method)).toHaveLength(2)
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(notifications.at(-1)?.message).toBe('响应已创建')
})
it('G-rs add 400 original retains drawer', async () => {
  const { w } = await mount('/responses', 'qf-write-400')
  await clickText(w, '添加响应'); await textInput('名称', 'new')
  ;[...document.querySelectorAll('[role=dialog] button')].find(b => b.textContent === '创建')!
    .dispatchEvent(new MouseEvent('click', { bubbles: true }))
  await flushPromises()
  expect(document.querySelector('[role=dialog]')?.textContent).toContain('name is required')
  expect(notifications).toHaveLength(1)
})
it('G-rs detail five GET, two phases no generated children, first-match tooltip W22', async () => {
  const { w } = await mount('/responses/3')
  expect(vi.mocked(fetch).mock.calls.map(c => c[0])).toEqual(['/api/responses/3',
    '/api/settings/webhook-connectors', '/api/settings/shell-connectors',
    '/api/settings/bgp-connectors', '/api/settings/xdrop-connectors'])
  expect(w.findAll('[data-phase=on_detected] [data-action]').map(r => r.attributes('data-action')))
    .toEqual(['17', '15', '12', '11', '13'])
  expect(w.findAll('[data-phase=on_expired] [data-action]').map(r => r.attributes('data-action'))).toEqual(['18'])
  expect(w.findAll('.rs-divider')).toHaveLength(3)
  expect(w.findAll('.rs-first')).toHaveLength(4)
  expect(w.find('[data-action="12"]').text()).toContain('""')
  expect(w.find('[role=tooltip]').exists()).toBe(true)
  expect(w.text()).not.toMatch(/192\.0\.2|\/bin\/true|api_key|Authorization/)
})
it.each(['/responses/404', '/responses/nope'])('G-rs 404 and nonnumeric %s', async url => {
  const { w } = await mount(url)
  expect(w.text()).toContain('没有这个响应。回到列表')
  expect(w.find('nav a').attributes('href')).toBe('/responses')
})
it('G-rs detail 500 original and retry; connector failures silent', async () => {
  const { w, intercept } = await mount('/responses/3', 'qf-detail-error')
  expect(w.find('[role=alert]').text()).toContain('response detail unavailable')
  intercept(path => path === '/api/responses/3' ? response(200, { response: { id: 3, name: 'Recovered' }, actions: [] })
    : undefined)
  await clickText(w, '重试')
  expect(w.find('h1').text()).toBe('Recovered')
})
it('G-rs detail changed id abort and ignores late response W26', async () => {
  const old = deferred<Response>()
  const pending = mountQE('/responses/3', (p, init) => p === '/api/responses/3' ? old.promise : undefined, true, 'qf')
  const { w, router } = await pending
  const signal = calls('/api/responses/3')[0]![1]!.signal!
  await router.push('/responses/2'); await flushPromises()
  expect(signal.aborted).toBe(true)
  old.resolve(response(200, { response: { id: 3, name: 'STALE' }, actions: [] }))
  await flushPromises()
  expect(w.find('h1').text()).toBe('Edge defense')
  expect(w.text()).not.toContain('STALE')
})
it('G-rs basic PUT exactly three keys and blank name disabled W27', async () => {
  const { w } = await mount('/responses/3')
  const inputs = w.findAll('.rs-basic input')
  await inputs[0]!.setValue('  ')
  expect(w.find('.rs-basic .primary').attributes('disabled')).toBeDefined()
  await inputs[0]!.setValue('Renamed'); await inputs[1]!.setValue('new description')
  await w.find('.rs-basic [role=switch]').trigger('click')
  await clickText(w.find('.rs-basic'), '保存')
  expect(JSON.parse(String(writes()[0]![1]!.body))).toEqual({ name: 'Renamed', 
    description: 'new description', enabled: false })
  expect(w.find('h1').text()).toBe('Renamed')
  expect(notifications.at(-1)?.message).toBe('已更新')
})
it.each([[15, true], [13, true], [11, false], [12, false], [18, false]])(
  'G-rs action delete pairing only detected xdrop/bgp %s W25', async (id, hint) => {
    const { w } = await mount('/responses/3')
    await clickText(w.find(`[data-action="${id}"]`), '删除')
    expect(w.find('[role=alertdialog]').text().includes('会一起删除')).toBe(hint)
    expect(writes()).toHaveLength(0)
  },
)
it('G-rs deletion succeeds refresh and failure stays original', async () => {
  const { w, intercept } = await mount('/responses/3')
  await clickText(w.find('[data-action="15"]'), '删除')
  intercept((p, init) => p === '/api/actions/15' && init.method === 'DELETE'
    ? response(500, { error: 'delete rejected' }) : undefined)
  await clickText(w.find('[role=alertdialog]'), '删除')
  expect(w.find('[role=alertdialog]').text()).toContain('delete rejected')
  intercept()
  await clickText(w.find('[role=alertdialog]'), '删除')
  expect(w.find('[data-action="15"]').exists()).toBe(false)
  expect(notifications.at(-1)?.message).toBe('已删除')
})
it('G-rs viewer no write controls, rows use View; list row navigation', async () => {
  const { w, router } = await mount('/responses', 'qf', false)
  expect(w.findAll('button')).toHaveLength(1) // action-count help
  await w.findAll('tbody tr')[2]!.trigger('click')
  await flushPromises()
  expect(router.currentRoute.value.path).toBe('/responses/3')
  expect(w.text()).not.toContain('添加动作')
  expect(w.text()).not.toContain('删除')
  expect(w.findAll('.rs-basic input').every(i => i.attributes('disabled') !== undefined)).toBe(true)
  expect(w.findAll('[data-action] button').filter(b => b.text() === '查看')).toHaveLength(6)
})
it('G-rs list read failure retains last table and retry recovers', async () => {
  const { w, intercept } = await mount()
  let failed = true
  intercept((p, init) => p === '/api/responses' && !init.method && failed
    ? response(500, { error: 'list unavailable' }) : undefined)
  await clickText(w.findAll('tbody tr')[2]!, '删除')
  await clickText(w.find('[role=alertdialog]'), '删除')
  expect(w.find('[role=alert]').text()).toContain('list unavailable')
  expect(w.findAll('tbody tr')).toHaveLength(3)
  failed = false
  await clickText(w, '重试')
  expect(w.findAll('tbody tr')).toHaveLength(2)
})
it('G-rs connector failure silent, xdrop backend string fallback', async () => {
  const { w } = await mount('/responses/3', 'qf-connectors-fail')
  expect(w.find('[role=alert]').exists()).toBe(false)
  expect(w.find('[data-action="17"]').text()).toContain('(all)')
})
