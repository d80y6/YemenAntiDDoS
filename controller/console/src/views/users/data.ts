import { reactive } from 'vue'
import { request } from '../../api/client'
import { state } from '../../state'

export type UserRow = { id: number; username: string; role: string; enabled: boolean;
  created_at: string; updated_at: string }
export type UserForm = { username: string; password: string; role: string; enabled: boolean }
// Shared by every mounted instance in this tab, including navigation during a write.
export const userGate = reactive({ inFlight: 0, writeGen: 0 })
export function beginUserWrite() {
  userGate.inFlight++
  userGate.writeGen++
}
export function endUserWrite() {
  userGate.inFlight--
  userGate.writeGen++
}
export const isSelf = (row: UserRow) => row.id === state.user?.id
export const rawError = (error: unknown) => error instanceof Error ? error.message : String(error)
export function userForm(row?: UserRow): UserForm {
  return { username: row?.username ?? '', password: '', role: row?.role ?? 'viewer', enabled: row?.enabled ?? true }
}
export function userBody(form: UserForm, row?: UserRow) {
  if (!row) return { username: form.username.trim(), password: form.password, role: form.role }
  return { role: form.role, enabled: form.enabled, ...(form.password !== '' ? { password: form.password } : {}) }
}
export function userValidation(form: UserForm, row?: UserRow) {
  if (!row && !form.username.trim()) return 'users.needUsername'
  if (!row && form.password === '') return 'users.needPassword'
  if (row && form.password !== '' && !form.password.trim()) return 'users.blankPassword'
  return ''
}
export function adminGuard(users: UserRow[], row: UserRow, next: 'delete' | Pick<UserForm, 'role' | 'enabled'>) {
  const last = row.role === 'admin' && row.enabled
    && users.filter(u => u.role === 'admin' && u.enabled).length === 1
  if (last && (next === 'delete' || next.role !== 'admin' || !next.enabled)) {
    return next === 'delete' ? 'users.lastDelete' : 'users.lastEdit'
  }
  return ''
}
export function saveUser(form: UserForm, row?: UserRow) {
  return request(row ? `/api/users/${row.id}` : '/api/users', {
    method: row ? 'PUT' : 'POST', body: JSON.stringify(userBody(form, row)),
  })
}
export const deleteUser = (id: number) => request(`/api/users/${id}`, { method: 'DELETE' })
