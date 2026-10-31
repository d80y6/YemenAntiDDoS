import { expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQE, clickText, domClick, dialog, input, choose, textInput, calls } from './qe-harness'
import { deferred, response } from './helpers'
import { mockSession } from '../mock/data'

const mount = () => mountQE('/responses/3', undefined, true, 'qf')
async function addWebhook(w: any) {
  await clickText(w.find('[data-phase=on_detected]'), '+ 添加动作')
  await choose('连接器', 'Alert hook')
  await domClick('+ 添加条件')
  const property = dialog().querySelector<HTMLButtonElement>('[aria-label="属性"]')!
  property.click()
  await flushPromises()
  ;[...document.querySelectorAll<HTMLButtonElement>('[role=option]')]
    .find(b => b.textContent?.trim() === '严重度')!.click()
  await flushPromises()
  await input('值', 'critical')
}
it('G-auth1 B1 create success closes drawer and renders new row in detected stage W35', async () => {
  const { w } = await mount()
  await addWebhook(w)
  await domClick('保存')
  expect(document.querySelector('[role=dialog]')).toBeNull()
  const row = w.find('[data-phase=on_detected] [data-action="100"]')
  expect(row.exists()).toBe(true)
  expect(row.findAll('td').slice(0, 6).map(c => c.text()))
    .toEqual(['5', 'webhook', 'Alert hook', '单次', '自动', '是'])
  expect(row.findAll('td')[6]!.findAll('button').map(b => b.text())).toEqual(['编辑', '删除'])
  expect(w.find('[data-phase=on_expired] [data-action="100"]').exists()).toBe(false)
})
it('G-auth1 B1 priority 5 to 2 renders saved value and reopening fills 2 W35', async () => {
  const { w } = await mount()
  expect(w.find('[data-action="11"] td').text()).toBe('5')
  await clickText(w.find('[data-action="11"]'), '编辑')
  await input('优先级', '2')
  await domClick('保存')
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(w.find('[data-action="11"] td').text()).toBe('2')
  await clickText(w.find('[data-action="11"]'), '编辑')
  expect(dialog().querySelector<HTMLInputElement>('[aria-label="优先级"]')!.value).toBe('2')
})
it('G-auth1 B1 parent refresh updates actions only and preserves failed editor form', async () => {
  const { w, intercept } = await mount()
  await textInput('名称', 'Unsaved basic')
  intercept((p, init) => p === '/api/responses/3' ? response(200, {
    response: { id: 3, name: 'POISON BASIC' }, actions: [],
  }) : init.method === 'POST' ? response(500, { error: 'storage rejected' }) : undefined)
  await addWebhook(w)
  await domClick('保存')
  expect(calls('/api/responses/3')).toHaveLength(2)
  expect(w.findAll('[data-action]')).toHaveLength(0)
  expect(w.find('h1').text()).toBe('IDC-C defense')
  expect(w.find<HTMLInputElement>('.rs-basic input').element.value).toBe('Unsaved basic')
  expect(dialog().querySelector<HTMLInputElement>('[aria-label="值"]')!.value).toBe('critical')
  expect(dialog().textContent).toContain('storage rejected')
})
it('G-auth1 B1 old refresh is discarded after A to B to A route generations', async () => {
  const { w, router, intercept } = await mount()
  const old = deferred<Response>()
  intercept(p => p === '/api/responses/3' ? old.promise : undefined)
  await clickText(w.find('[data-action="11"]'), '编辑')
  await input('优先级', '2')
  await domClick('保存')
  expect(document.querySelector('[role=dialog]')).toBeNull()
  intercept()
  await router.push('/responses/2')
  await flushPromises()
  await router.push('/responses/3')
  await flushPromises()
  old.resolve(response(200, { response: { id: 3 }, actions: [] }))
  await flushPromises()
  expect(w.find('[data-action="11"] td').text()).toBe('2')
})
it('G-auth1 B1 refresh failure is swallowed after successful write', async () => {
  const { w, intercept } = await mount()
  intercept(p => p === '/api/responses/3' ? response(500, { error: 'refresh rejected' }) : undefined)
  await clickText(w.find('[data-action="11"]'), '编辑')
  await input('优先级', '2')
  await domClick('保存')
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(w.text()).not.toContain('refresh rejected')
  expect(w.find('[data-action="11"] td').text()).toBe('5')
})
it.each(['/responses/nope', '/responses/999'])(
  'G-auth1 B2 404 terminal without loading %s W36', async url => {
    const { w } = await mountQE(url, undefined, true, 'qf')
    expect(w.text()).toContain('没有这个响应。回到列表')
    expect(w.find('a[href="/responses"]').exists()).toBe(true)
    expect(w.text()).not.toContain('加载中')
  },
)
it('G-auth1 B3 second delete returns exact 404 action not found W37', () => {
  const mock = mockSession('qf')
  expect(mock('/api/actions/11', 'DELETE')).toEqual({ status: 200, body: { ok: true } })
  expect(mock('/api/actions/11', 'DELETE')).toEqual({ status: 404, body: { error: 'action not found' } })
})
it('G-auth1 B3 stale page action delete keeps confirmation and original error W37', async () => {
  const { w } = await mount()
  expect((await fetch('/api/actions/11', { method: 'DELETE' })).status).toBe(200)
  await clickText(w.find('[data-action="11"]'), '删除')
  await clickText(w.find('[role=alertdialog]'), '删除')
  expect(w.find('[role=alertdialog]').exists()).toBe(true)
  expect(w.find('[role=alertdialog] [role=alert]').text()).toBe('action not found')
  expect(w.find('[data-action="11"]').exists()).toBe(true)
})
