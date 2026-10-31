import { expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { userGate } from '../src/views/users/data'
import { response } from './helpers'
import { body, choose, dialog, domClick, mountQE, writes } from './qe-harness'

it('G-us-409 last admin response keeps drawer open and reloads unchanged admin', async () => {
  const raw = 'at least one enabled admin is required'
  const reads: number[] = []
  const { w } = await mountQE('/users', (path, init) => {
    if (path === '/api/users' && !init.method) reads.push(userGate.inFlight)
    if (path === '/api/users/4' && init.method === 'PUT') return response(409, { error: raw })
  }, true, 'qi')
  expect(userGate.inFlight).toBe(0)
  expect(reads).toEqual([0])
  expect(w.get('[data-user="1"]').get('.pill').text()).toBe('admin')
  expect(w.get('[data-user="4"]').get('.pill').text()).toBe('admin')
  await w.get('[data-user="4"]').trigger('click')
  await choose('角色', 'viewer · 只读：只能查看', dialog())
  await domClick('保存')
  await flushPromises()
  expect(writes()).toHaveLength(1)
  expect(writes()[0]?.[0]).toBe('/api/users/4')
  expect(body()).toEqual({ role: 'viewer', enabled: true })
  expect(dialog()).not.toBeNull()
  expect(dialog().querySelector('[role=alert]')?.textContent).toBe(raw)
  expect(userGate.inFlight).toBe(0)
  expect(reads).toEqual([0, 0])
  const calls = vi.mocked(fetch).mock.calls.map(([path, init]) => [path, init?.method || 'GET'])
  expect(calls).toEqual([['/api/users', 'GET'], ['/api/users/4', 'PUT'], ['/api/users', 'GET']])
  expect(w.get('[data-user="4"]').text()).toContain('ops-2')
  expect(w.get('[data-user="4"]').get('.pill').text()).toBe('admin')
})
