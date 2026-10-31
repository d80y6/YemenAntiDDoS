import { describe, expect, it } from 'vitest'
import { adminGuard, userBody, userForm, userValidation } from '../src/views/users/data'
import type { UserRow } from '../src/views/users/data'
import { auditTime, auditQuery, diffPreview, entityTypes, userLabel } from '../src/views/audit/data'
const admin = { id: 1, username: 'demo', role: 'admin', enabled: true } as UserRow
const other = { ...admin, id: 4, username: 'ops-2' }
const form = { username: ' ops ', password: ' p w ', role: 'viewer', enabled: false }
describe('G-units user body and validation', () => {
  it('new is exactly three keys and preserves raw password V8 V10', () => {
    expect(userBody(form)).toEqual({ username: 'ops', password: ' p w ', role: 'viewer' })
    expect(userForm()).toEqual({ username: '', password: '', role: 'viewer', enabled: true })
  })
  it('edit excludes username id and empty password V8 V9', () => {
    expect(userBody({ ...form, password: '' }, admin)).toEqual({ role: 'viewer', enabled: false })
    expect(userBody(form, admin)).toEqual({ role: 'viewer', enabled: false, password: ' p w ' })
    expect(userForm({ ...other, role: 'unknown' })).toEqual({ username: 'ops-2', role: 'unknown',
      enabled: true, password: '' })
  })
  it.each([
    ['', '', false, 'users.needUsername'], ['  ', 'parity-only-1', false, 'users.needUsername'],
    ['ops', '', false, 'users.needPassword'], ['ops', ' ', false, ''],
    ['ops', ' ', true, 'users.blankPassword'], ['ops', '', true, ''],
  ])('validation %j %j edit=%s', (username, password, edit, expected) => {
    expect(userValidation({ ...form, username, password }, edit ? admin : undefined)).toBe(expected)
  })
})
describe('G-units adminGuard V1 V2 V3', () => {
  const changes = ['delete', { role: 'viewer', enabled: true }, { role: 'operator', enabled: true },
    { role: 'admin', enabled: false }] as const
  for (const next of changes) {
    it('two enabled admins allow ' + JSON.stringify(next), () => {
      expect(adminGuard([admin, other], admin, next)).toBe('')
    })
    it('only enabled admin blocks ' + JSON.stringify(next), () => {
      expect(adminGuard([admin, { ...other, enabled: false }], admin, next))
        .toBe(next === 'delete' ? 'users.lastDelete' : 'users.lastEdit')
    })
  }
  it('password-only stays allowed', () => {
    expect(adminGuard([admin], admin, { role: 'admin', enabled: true })).toBe('')
  })
  it.each(['operator', 'viewer', 'unknown'])('non-admin %s does not count', role => {
    const row = { ...other, role }
    expect(adminGuard([admin, row], admin, 'delete')).toBe('users.lastDelete')
    expect(adminGuard([admin, row], row, 'delete')).toBe('')
  })
  it('disabled admin may be deleted', () => {
    const disabled = { ...other, enabled: false }
    expect(adminGuard([admin, disabled], disabled, 'delete')).toBe('')
  })
})
describe('G-units audit time and query V14 V17', () => {
  it.each([
    ['2026-10-27', 2026, 9, 27, 0, 0, 0], ['2026-10-27 08:00', 2026, 9, 27, 8, 0, 0],
    ['2026-10-27T08:00:30', 2026, 9, 27, 8, 0, 30], ['2026-2-3 8:05', 2026, 1, 3, 8, 5, 0],
  ])('valid local time %s', (text, y, m, d, h, minute, second) => {
    expect(auditTime(text)).toBe(new Date(y, m, d, h, minute, second).getTime())
  })
  it.each(['2026-02-31', '2026-10-27 25:00', '2026-10-27 08:60', '27/10/2026', 'abc'])('invalid %s', text => {
    expect(Number.isNaN(auditTime(text))).toBe(true)
  })
  it('absent time differs from invalid', () => {
    expect(auditTime('')).toBeNull()
    expect(auditTime('  ')).toBeNull()
    expect(auditTime()).toBeNull()
  })
  it.each([[1, 0], [2, 50], [3, 100]])('page %s offset %s', (page, offset) => {
    expect(auditQuery({}, page)).toBe('/api/audit-log?limit=51&offset=' + offset)
  })
  it('query literal order, free text and ISO times', () => {
    const from = encodeURIComponent(new Date(2026, 9, 27, 8).toISOString())
    const to = encodeURIComponent(new Date(2026, 9, 27, 12).toISOString())
    expect(auditQuery({ entity_type: 'new/type &', user_id: '2', from: '2026-10-27 08:00',
      to: '2026-10-27 12:00' }, 2))
      .toBe(`/api/audit-log?entity_type=new%2Ftype+%26&user_id=2&from=${from}&to=${to}&limit=51&offset=50`)
    expect(auditQuery({ from: 'bad', to: '', entity_type: '', user_id: '' }, 1))
      .toBe('/api/audit-log?limit=51&offset=0')
  })
  it('diff preview and user label literals', () => {
    expect(diffPreview(null)).toBe('-')
    expect(diffPreview({ x: 'a'.repeat(150) })).toBe('{"x":"' + 'a'.repeat(94))
    expect(userLabel(null, [admin])).toBe('—')
    expect(userLabel(1, [admin])).toBe('demo')
    expect(userLabel(7, [admin])).toBe('#7')
    expect(entityTypes).toHaveLength(19)
    expect(entityTypes).toEqual([...entityTypes].sort())
  })
})
