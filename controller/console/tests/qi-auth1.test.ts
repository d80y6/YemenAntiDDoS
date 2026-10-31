import { describe, expect, it } from 'vitest'
import { usersSession } from '../mock/users'
import { userBody } from '../src/views/users/data'
import { notifications } from '../src/notifications'
import { body, clickText, dialog, domClick, mountQE, textInput, writes } from './qe-harness'

const form = { username: 'parity-pw-test', password: 'x'.repeat(72), role: 'viewer', enabled: true }
const failure = { status: 500, body: { error: 'hash failed' } }
const row = { id: 2, username: 'noc-01', role: 'operator', enabled: true, created_at: '', updated_at: '' }
const at = Date.parse('2026-10-28T00:00:00.000Z')
describe('auth1 bcrypt boundary and Go handler ordering', () => {
  it('POST validates required username before hashing', () => {
    const mock = usersSession('qi', at)
    expect(mock('/api/users', 'POST', userBody({ ...form, username: '', password: 'x'.repeat(73) })))
      .toEqual({ status: 400, body: {
        error: "Key: 'Username' Error:Field validation for 'Username' failed on the 'required' tag",
      } })
  })
  it('POST hashes raw whitespace and hashes before duplicate INSERT', () => {
    const mock = usersSession('qi', at)
    expect(mock('/api/users', 'POST', userBody({ ...form, password: ' ' + form.password + ' ' })))
      .toEqual(failure)
    expect(mock('/api/users', 'POST', userBody({ ...form, username: 'demo', password: '中'.repeat(25) })))
      .toEqual(failure)
    expect(mock('/api/users', 'POST', userBody(form))).toEqual({ status: 201, body: { id: 5 } })
  })
  it('PUT missing row returns 404 before hashing', () => {
    const mock = usersSession('qi', at)
    expect(mock('/api/users/999', 'PUT', userBody({ ...form, password: 'x'.repeat(73) }, row)))
      .toEqual({ status: 404, body: { error: 'user not found' } })
  })
  it('PUT hash failure changes neither role, enabled nor timestamps', () => {
    const mock = usersSession('qi', at), before = mock('/api/users')
    expect(mock('/api/users/2', 'PUT', userBody({ ...form, enabled: false, password: 'x'.repeat(73) }, row)))
      .toEqual(failure)
    expect(mock('/api/users')).toEqual(before)
  })
  it.each([
    0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0, 0x1680,
    0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
    0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
  ])('PUT trims Go White_Space codepoint %i at both ends', codepoint => {
    const mock = usersSession('qi', at), space = String.fromCodePoint(codepoint)
    expect(mock('/api/users/2', 'PUT', userBody({ ...form, password: space + form.password + space }, row)))
      .toEqual({ status: 200, body: { ok: true } })
  })
  it.each([0x180e, 0x200b, 0xfeff])('PUT retains non-Go-space codepoint %i', codepoint => {
    const mock = usersSession('qi', at), space = String.fromCodePoint(codepoint)
    expect(mock('/api/users/2', 'PUT', userBody({ ...form, password: space + form.password + space }, row)))
      .toEqual(failure)
  })
  it('PUT preserves interior whitespace', () => {
    const mock = usersSession('qi', at)
    expect(mock('/api/users/2', 'PUT', userBody({ ...form, password: 'x'.repeat(36) + ' ' + 'x'.repeat(36) }, row)))
      .toEqual(failure)
  })
})
describe('auth1 page keeps backend hash failed original', () => {
  it('POST multibyte password reaches mock, keeps drawer and shows original', async () => {
    const { w } = await mountQE('/users', undefined, true, 'qi')
    await clickText(w, '添加用户')
    await textInput('用户名', 'parity-pw-page')
    await textInput('密码', '中'.repeat(25))
    await domClick('创建')
    expect(writes()).toHaveLength(1)
    expect(body()).toEqual({ username: 'parity-pw-page', password: '中'.repeat(25), role: 'viewer' })
    expect(dialog().querySelector('[role=alert]')?.textContent).toBe('hash failed')
    expect(notifications.at(-1)?.message).toBe('hash failed')
    expect(w.findAll('[data-user]')).toHaveLength(4)
  })
  it('PUT 73-byte password reaches mock and keeps editor with original', async () => {
    const { w } = await mountQE('/users', undefined, true, 'qi')
    await w.get('[data-user="2"]').trigger('click')
    await textInput('新密码', 'x'.repeat(73))
    await domClick('保存')
    expect(writes()).toHaveLength(1)
    expect(body()).toEqual({ role: 'operator', enabled: true, password: 'x'.repeat(73) })
    expect(dialog().querySelector('[role=alert]')?.textContent).toBe('hash failed')
    expect(notifications.at(-1)?.message).toBe('hash failed')
  })
})
