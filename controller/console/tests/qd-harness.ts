import { vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { defineComponent, h } from 'vue'
import { render, response } from './helpers'
import { state } from '../src/state'
import { i18n } from '../src/i18n'
import { mockSession } from '../mock/data'
import Mitigations from '../src/views/mitigations/Mitigations.vue'
import Nodes from '../src/views/nodes/Nodes.vue'
import Notifications from '../src/components/Notifications.vue'
import type { Intercept } from './attacks-harness'
export { clock, calls, params, tick } from './attacks-harness'
export async function mountQD(url = '/mitigations', mode = 'qd', change?: Intercept, admin = true) {
  const seed = Date.now(), mock = mockSession(mode)
  let intercept = change
  state.user = { id: 1, username: 'demo', role: admin ? 'admin' : 'viewer' }; state.token = 'development'
  vi.stubGlobal('fetch', vi.fn(async (raw: any, init: RequestInit = {}) => {
    const path = String(raw), body = init.body ? JSON.parse(String(init.body)) : {}
    const result = mock(path, init.method || 'GET', body, seed)
    return intercept?.(path, init, result) ?? response(result.status, result.body)
  }))
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/mitigations', component: Mitigations }, { path: '/nodes', component: Nodes },
    { path: '/:pathMatch(.*)*', component: { template: '<p>Other page</p>' } },
  ] })
  await router.push(url)
  const host = defineComponent({ setup: () => () => [h(RouterView), h(Notifications)] })
  const w = render(host, { global: { plugins: [i18n, router] }, attachTo: document.body })
  await flushPromises()
  return { w, router, intercept: (value?: Intercept) => { intercept = value } }
}
export const clickText = async (root: any, text: string) => {
  const button = root.findAll('button').find((b: any) => b.text() === text)
  if (!button) throw new Error('button not found: ' + text)
  await button.trigger('click'); await flushPromises()
}
export const dialog = () => document.querySelector<HTMLElement>('[role=dialog]')!
export async function domClick(text: string) {
  const b = [...dialog().querySelectorAll('button')].find(b => b.textContent?.trim() === text)
  if (!b) throw new Error('dialog button not found: ' + text)
  b.click(); await flushPromises()
}
