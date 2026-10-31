import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'
import Users from '../src/views/users/Users.vue'
import UserDrawer from '../src/views/users/UserDrawer.vue'
import { userForm, userGate } from '../src/views/users/data'
import { configureClient, request } from '../src/api/client'
import { makeRouter } from '../src/router'
import { state, saveSession } from '../src/state'
import { notifications } from '../src/notifications'
import { deferred, response } from './helpers'
import { body, clickText, dialog, domClick, mountQE, textInput, writes } from './qe-harness'
const row = (w: any, id: number) => w.get(`[data-user="${id}"]`)
const vm = (w: any) => w.getComponent(Users).vm as any
const drawer = (w: any) => w.getComponent(UserDrawer).vm as any
const getCount = () => vi.mocked(fetch).mock.calls.filter(([p, init]) => p === '/api/users' && !init?.method).length
const settle = async () => { await flushPromises(); await flushPromises() }
beforeEach(() => { expect(userGate.inFlight).toBe(0) })
afterEach(() => { configureClient(makeRouter(createMemoryHistory())) })
async function fillNew(w: any, username = ' ops ', password = ' parity-only-1 ') {
  await clickText(w, '添加用户')
  await textInput('用户名', username)
  await textInput('密码', password)
}
async function startSelf(w: any) {
  await row(w, 1).trigger('click')
  await domClick('保存')
}
describe('G-us read, rows and forms', () => {
  it('mount only users GET and literal role cells', async () => {
    const { w } = await mountQE('/users', undefined, true, 'qi')
    expect(vi.mocked(fetch).mock.calls.map(([p]) => p)).toEqual(['/api/users'])
    expect(w.findAll('thead th').map(c => c.text())).toEqual([
      'ID', '用户名', '角色 ?admin 可以修改配置；operator 和 viewer 只能查看，两者权限相同。', '状态', '删除',
    ])
    expect(row(w, 1).text()).toContain('demo（你）')
    expect(row(w, 1).get('.pill').classes()).toContain('crit')
    expect(row(w, 2).get('.pill').classes()).toContain('warn')
    expect(row(w, 1).text()).toContain('可写')
    expect(row(w, 2).text()).toContain('只读')
    expect(row(w, 3).text()).toContain('只读')
    expect(w.get('[role=tooltip]').text()).toBe('admin 可以修改配置；operator 和 viewer 只能查看，两者权限相同。')
  })
  it('read failure shows raw error and retry without notification', async () => {
    const h = await mountQE('/users', undefined, true, 'qi-users-fail')
    expect(h.w.get('[role=alert]').text()).toContain('users unavailable')
    expect(notifications).toHaveLength(0)
    expect(h.w.get('.primary').attributes('disabled')).toBeDefined()
    h.intercept((p, _, result) => p === '/api/users' ? response(200, []) : response(result.status, result.body))
    await clickText(h.w, '重试')
    expect(h.w.text()).toContain('暂无数据')
    expect(h.w.get('.primary').attributes('disabled')).toBeUndefined()
  })
  it('new submits exactly three keys, raw password, then reloads', async () => {
    const { w } = await mountQE('/users', undefined, true, 'qi')
    await fillNew(w)
    expect(dialog().textContent).toContain('新建的用户总是启用。')
    await domClick('创建')
    expect(body()).toEqual({ username: 'ops', password: ' parity-only-1 ', role: 'viewer' })
    expect(getCount()).toBe(2)
    expect(w.text()).toContain('ops')
    expect(notifications.at(-1)?.message).toBe('用户已创建')
    expect(dialog()).toBeNull()
  })
  it.each([[400, 'invalid user body'], [409, 'already exists']])(
    'new %s stays open with raw error', async (code, raw) => {
    const { w } = await mountQE('/users', (_, init) => init.method === 'POST' ? response(code, { error: raw })
      : undefined, true, 'qi')
    await fillNew(w)
    await domClick('创建')
    expect(dialog().querySelector('[role=alert]')?.textContent).toBe(raw)
    expect(notifications.at(-1)?.message).toBe(raw)
    expect(getCount()).toBe(2)
    expect(userGate.inFlight).toBe(0)
  })
  it.each(['', ' parity-only-2 '])('edit other with password %j', async password => {
    const { w } = await mountQE('/users', undefined, true, 'qi')
    await row(w, 2).trigger('click')
    expect(dialog().textContent).toContain('保存后 noc-01 当前的登录会立即失效，需要重新登录。')
    expect(dialog().textContent).toContain('留空保持当前密码。')
    expect(dialog().querySelector<HTMLInputElement>('input[readonly]')?.value).toBe('noc-01')
    if (password) await textInput('新密码', password)
    await domClick('保存')
    expect(body()).toEqual({ role: 'operator', enabled: true, ...(password ? { password } : {}) })
    expect(getCount()).toBe(2)
  })
  it('blank edit password blocks; unknown role preserved V11', async () => {
    const { w } = await mountQE('/users', (p, _, result) => {
      if (p === '/api/users') return response(200, result.body.map((u: any) =>
        u.id === 2 ? { ...u, role: 'legacy-x' } : u))
    }, true, 'qi')
    await row(w, 2).trigger('click')
    expect(dialog().querySelector('[role=combobox]')?.getAttribute('aria-label')).toBe('角色: legacy-x · 只读')
    await textInput('新密码', '   ')
    await domClick('保存')
    expect(dialog().textContent).toContain('新密码不能全是空格')
    expect(writes()).toHaveLength(0)
    await textInput('新密码', '')
    await domClick('保存')
    expect(body()).toEqual({ role: 'legacy-x', enabled: true })
  })
  it('new required messages in order', async () => {
    const { w } = await mountQE('/users', undefined, true, 'qi')
    await fillNew(w, '', '')
    await domClick('创建')
    expect(dialog().textContent).toContain('请输入用户名')
    await textInput('用户名', 'ops')
    await domClick('创建')
    expect(dialog().textContent).toContain('请输入密码')
    expect(writes()).toHaveLength(0)
  })
  it('last admin disables controls and direct handlers V1 V4', async () => {
    const { w } = await mountQE('/users', undefined, true, 'qi-last-admin')
    const current = vm(w).users[0]
    expect(row(w, 1).get('button').attributes('disabled')).toBeDefined()
    expect(row(w, 1).text()).toContain('这是唯一启用的 admin，不能删除。')
    await vm(w).remove(current)
    expect(writes()).toHaveLength(0)
    await row(w, 1).trigger('click')
    expect(dialog().textContent).toContain('这是唯一启用的 admin，不能降级或禁用。')
    expect(dialog().querySelector<HTMLButtonElement>('[role=switch]')!.disabled).toBe(true)
    ;(dialog().querySelector('[role=combobox]') as HTMLButtonElement).click()
    await settle()
    for (const option of document.querySelectorAll<HTMLButtonElement>('[role=option]')) {
      expect(option.disabled).toBe(!option.textContent!.startsWith('admin'))
    }
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await settle()
    drawer(w).form.role = 'viewer'
    await drawer(w).submit()
    expect(dialog().querySelector('[role=alert]')?.textContent).toBe('这是唯一启用的 admin，不能降级或禁用。')
    await expect(vm(w).save({ ...userForm(current), enabled: false }, current)).rejects.toThrow('不能降级或禁用')
    expect(writes()).toHaveLength(0)
  })
  it('two enabled admins permit self deletion and demotion', async () => {
    const { w } = await mountQE('/users', undefined, true, 'qi')
    expect(row(w, 1).get('button').attributes('disabled')).toBeUndefined()
    await row(w, 1).trigger('click')
    expect(dialog().querySelector<HTMLButtonElement>('[role=switch]')!.disabled).toBe(false)
    drawer(w).form.role = 'viewer'
    await drawer(w).submit()
    expect(body()).toEqual({ role: 'viewer', enabled: true })
  })
  it('viewer audit-ro is read only and self uses id V12', async () => {
    const { w } = await mountQE('/users', undefined, false, 'qi')
    saveSession('development-viewer', { id: 3, username: 'audit-ro', role: 'viewer' })
    await settle()
    expect(w.findAll('thead th')).toHaveLength(4)
    expect(w.text()).not.toContain('添加用户')
    expect(w.text()).not.toContain('删除')
    expect(row(w, 3).text()).toContain('audit-ro（你）')
    expect(row(w, 1).text()).not.toContain('（你）')
    await row(w, 1).trigger('click')
    expect(dialog()).toBeNull()
    await vm(w).save(userForm(vm(w).users[0]), vm(w).users[0])
    await vm(w).remove(vm(w).users[0])
    expect(writes()).toHaveLength(0)
  })
  it('visible labels bind real controls and listbox accessible name V29', async () => {
    const { w } = await mountQE('/users', undefined, true, 'qi')
    await fillNew(w)
    for (const label of dialog().querySelectorAll<HTMLLabelElement>('label.field')) {
      expect(label.getAttribute('for')).toBeTruthy()
      expect(document.getElementById(label.htmlFor)).toBe(label.querySelector('input'))
    }
    expect(dialog().querySelector('[role=combobox]')?.getAttribute('aria-label')).toBe('角色: viewer · 只读：只能查看')
    await domClick('取消')
    await row(w, 2).trigger('click')
    const status = [...dialog().querySelectorAll('label')].find(l => l.textContent === '状态')!
    expect(document.getElementById(status.htmlFor)).toBe(dialog().querySelector('[role=switch]'))
  })
})
describe('G-us writes, identity and navigation', () => {
  it.each([false, true])('delete confirm success/failure=%s', async fail => {
    const { w } = await mountQE('/users', (_, init) => fail && init.method === 'DELETE'
      ? response(409, { error: 'delete denied' }) : undefined, true, 'qi')
    await row(w, 2).get('button').trigger('click')
    expect(w.get('[role=alertdialog]').text()).toContain('删除用户 noc-01？')
    await clickText(w.get('[role=alertdialog]'), '删除')
    expect(writes().at(-1)?.[0]).toBe('/api/users/2')
    expect(w.find('[role=alertdialog]').exists()).toBe(fail)
    if (fail) expect(w.get('[role=alertdialog]').text()).toContain('delete denied')
    else expect(w.find('[data-user="2"]').exists()).toBe(false)
  })
  it.each([false, true])('self update/delete=%s clears session with notice V5 V6', async deleting => {
    const { w, router } = await mountQE('/users', undefined, true, 'qi')
    if (deleting) {
      await row(w, 1).get('button').trigger('click')
      expect(w.get('[role=alertdialog]').text()).toContain('这是你当前登录的账号，删除后会退出登录。')
      await clickText(w.get('[role=alertdialog]'), '删除')
    } else await startSelf(w)
    await settle()
    expect(getCount()).toBe(1)
    expect(state.token).toBe('')
    expect(state.user).toBeNull()
    expect(router.currentRoute.value.fullPath).toBe(deleting ? '/login?notice=account-deleted'
      : '/login?notice=account-updated&next=/users')
    expect(w.get('[role=status]').text()).toBe(deleting ? '你的账号已删除。' : '你的账号已更新，请重新登录。')
  })
  it.each(['401', 'leave'])('pending self write after %s V7 V33', async kind => {
    const pending = deferred<Response>()
    const h = await mountQE('/users', (p, init) => init.method === 'PUT' ? pending.promise
      : p === '/api/qi-expired' ? response(401, { error: 'expired' }) : undefined, true, 'qi')
    configureClient(h.router)
    await startSelf(h.w)
    if (kind === '401') {
      await expect(request('/api/qi-expired')).rejects.toThrow('expired')
      await settle()
      expect(h.router.currentRoute.value.fullPath).toBe('/login?next=/users')
      expect(state.user).toBeNull()
    } else {
      await h.router.push('/audit')
      await settle()
      expect(state.user?.id).toBe(1)
    }
    expect(h.w.findComponent(Users).exists()).toBe(false)
    const before = getCount()
    pending.resolve(response(200, { ok: true }))
    await settle()
    expect(h.router.currentRoute.value.fullPath).toBe('/login?notice=account-updated&next=/users')
    expect(getCount()).toBe(before)
    expect(state.user).toBeNull()
    expect(notifications.at(-1)?.message).toBe('已更新')
  })
  it('failed self write preserves session and reloads', async () => {
    const { w, router } = await mountQE('/users', (_, init) => init.method === 'PUT'
      ? response(409, { error: 'write failed' }) : undefined, true, 'qi')
    await startSelf(w)
    expect(router.currentRoute.value.path).toBe('/users')
    expect(state.user?.id).toBe(1)
    expect(getCount()).toBe(2)
    expect(dialog().textContent).toContain('write failed')
  })
  it.each([200, 409])('write result after unmount %s V30', async status => {
    const pending = deferred<Response>()
    const { w, router } = await mountQE('/users', (_, init) => init.method === 'POST' ? pending.promise : undefined,
      true, 'qi')
    await fillNew(w)
    await domClick('创建')
    await router.push('/audit')
    await settle()
    pending.resolve(response(status, status === 200 ? { id: 5 } : { error: 'late failure' }))
    await settle()
    expect(notifications.at(-1)?.message).toBe(status === 200 ? '用户已创建' : 'late failure')
    expect(userGate.inFlight).toBe(0)
  })
})
describe('G-us shared write gate and read generation', () => {
  it.each([false, true])('pending deletion; new page instance=%s V31 V34', async navigate => {
    const write = deferred<Response>(), reload = deferred<Response>()
    let holdRead = false, newRows: any
    const h = await mountQE('/users', (p, init, result) => {
      if (init.method === 'DELETE' && p === '/api/users/4') return write.promise
      if (p === '/api/users' && holdRead) { newRows = result.body; return reload.promise }
    }, true, 'qi')
    try {
      const oldVm = vm(h.w)
      await row(h.w, 4).get('button').trigger('click')
      await clickText(h.w.get('[role=alertdialog]'), '删除')
      expect(writes()).toHaveLength(1)
      if (navigate) {
        await h.router.push('/audit')
        await h.router.push('/users')
        await settle()
        expect(vm(h.w)).not.toBe(oldVm)
        expect(vm(h.w).users.filter((u: any) => u.role === 'admin').length).toBe(2)
      }
      const current = vm(h.w), demo = current.users[0]
      const addDisabled = h.w.get('.primary').attributes('disabled')
      const deleteDisabled = row(h.w, 1).get('button').attributes('disabled')
      await current.remove(demo)
      expect(writes()).toHaveLength(1)
      expect(addDisabled).toBeDefined()
      expect(deleteDisabled).toBeDefined()
      await row(h.w, 1).trigger('click')
      drawer(h.w).form.role = 'viewer'
      expect(dialog().querySelector<HTMLButtonElement>('.primary')!.disabled).toBe(true)
      await drawer(h.w).submit()
      await current.save({ ...userForm(demo), role: 'viewer' }, demo)
      expect(writes()).toHaveLength(1)
      holdRead = true
      write.resolve(response(200, { ok: true }))
      await settle()
      expect(userGate.inFlight).toBe(0)
      await current.remove(demo)
      expect(writes()).toHaveLength(1)
      expect(dialog().querySelector<HTMLButtonElement>('.primary')!.disabled).toBe(true)
      expect(newRows.map((u: any) => u.id)).toEqual([1, 2, 3])
      reload.resolve(response(200, newRows))
      await settle()
      expect(row(h.w, 1).text()).toContain('这是唯一启用的 admin，不能删除。')
      await current.remove(demo)
      expect(writes()).toHaveLength(1)
      expect(dialog().textContent).toContain('这是唯一启用的 admin，不能降级或禁用。')
    } finally {
      write.resolve(response(200, { ok: true }))
      reload.resolve(response(200, newRows ?? []))
      await settle()
    }
  })
  it('write reload failure locks writes but drawer cancellation and retry work V32', async () => {
    let gets = 0
    const h = await mountQE('/users', (p, init) => {
      if (p === '/api/users' && !init.method && ++gets === 2) return response(500, { error: 'reload failed' })
      if (init.method === 'PUT') return response(409, { error: 'save failed' })
    }, true, 'qi')
    await row(h.w, 2).trigger('click')
    await domClick('保存')
    expect(h.w.text()).toContain('reload failed')
    expect(dialog().textContent).toContain('save failed')
    expect(dialog().querySelector<HTMLButtonElement>('.primary')!.disabled).toBe(true)
    await vm(h.w).remove(vm(h.w).users[1])
    expect(writes()).toHaveLength(1)
    await domClick('取消')
    expect(dialog()).toBeNull()
    await clickText(h.w, '重试')
    expect(h.w.get('.primary').attributes('disabled')).toBeUndefined()
  })
  it('successful deletion with failed reload never becomes a failed delete', async () => {
    let gets = 0
    const { w } = await mountQE('/users', (p, init) => p === '/api/users' && !init.method && ++gets === 2
      ? response(500, { error: 'reload failed' }) : undefined, true, 'qi')
    await row(w, 4).get('button').trigger('click')
    await clickText(w.get('[role=alertdialog]'), '删除')
    expect(w.find('[role=alertdialog]').exists()).toBe(false)
    expect(w.text()).toContain('reload failed')
    expect(notifications.at(-1)?.message).toBe('已删除')
  })
  it.each([200, 500])('older read cannot change result, error or writable status=%s V35', async status => {
    const old = deferred<Response>(), latest = deferred<Response>()
    const h = await mountQE('/users', undefined, true, 'qi')
    let count = 0
    h.intercept(p => p === '/api/users' ? (++count === 1 ? old.promise : latest.promise) : undefined)
    const first = vm(h.w).load(), second = vm(h.w).load()
    latest.resolve(response(500, { error: 'latest failed' }))
    await second
    await settle()
    old.resolve(response(status, status === 200 ? [{ id: 99, username: 'stale', role: 'admin', enabled: true }]
      : { error: 'stale failed' }))
    await first
    await settle()
    expect(h.w.text()).not.toContain('stale')
    expect(h.w.text()).toContain('latest failed')
    expect(vm(h.w).writable).toBe(false)
    expect(h.w.get('.primary').attributes('disabled')).toBeDefined()
    expect(h.w.get('section').attributes('aria-busy')).toBe('false')
  })
})
