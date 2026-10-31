import { expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mountQE, clickText, domClick, dialog, input, calls } from './qe-harness'
import { deferred, response } from './helpers'

async function prepare() {
  const mounted = await mountQE('/responses/3', undefined, true, 'qf')
  const old = deferred<Response>()
  let snapshot: Response | undefined
  mounted.intercept((path, init, result) => {
    if (path === '/api/responses/3' && !init.method && !snapshot) {
      snapshot = response(result.status, result.body)
      return old.promise
    }
  })
  async function save(priority: string) {
    await clickText(mounted.w.find('[data-action="11"]'), '编辑')
    await input('优先级', priority)
    await domClick('保存')
    expect(document.querySelector('[role=dialog]')).toBeNull()
  }
  return { ...mounted, save, release: () => old.resolve(snapshot!) }
}
it('G-auth2 B4 saves 2 then 4 discard older refresh and reopen with 4 W38', async () => {
  const { w, save, release } = await prepare()
  expect(w.find('[data-action="11"] td').text()).toBe('5')
  await save('2')
  expect(calls('/api/responses/3')).toHaveLength(2)
  expect(w.find('[data-action="11"] td').text()).toBe('5')
  await save('4')
  expect(calls('/api/responses/3')).toHaveLength(3)
  expect(w.find('[data-action="11"] td').text()).toBe('4')
  release()
  await flushPromises()
  expect(w.find('[data-action="11"] td').text()).toBe('4')
  await clickText(w.find('[data-action="11"]'), '编辑')
  expect(dialog().querySelector<HTMLInputElement>('[aria-label="优先级"]')!.value).toBe('4')
})
it('G-auth2 B4 delete load wins over pending save refresh without resurrecting row W38', async () => {
  const { w, save, release } = await prepare()
  await save('2')
  expect(calls('/api/responses/3')).toHaveLength(2)
  await clickText(w.find('[data-action="11"]'), '删除')
  await clickText(w.find('[role=alertdialog]'), '删除')
  expect(calls('/api/responses/3')).toHaveLength(3)
  expect(w.find('[data-action="11"]').exists()).toBe(false)
  release()
  await flushPromises()
  expect(w.find('[data-action="11"]').exists()).toBe(false)
  expect(w.find('[data-action="12"]').exists()).toBe(true)
})
