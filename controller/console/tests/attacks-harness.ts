import { vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { defineComponent, h } from 'vue'
import { render, response } from './helpers'
import { state } from '../src/state'
import { i18n } from '../src/i18n'
import { mockSession } from '../mock/data'
import Attacks from '../src/views/attacks/Attacks.vue'
import AttackDetail from '../src/views/attacks/AttackDetail.vue'
import Notifications from '../src/components/Notifications.vue'
export type Intercept = (path: string, init: RequestInit, result: any) => Response | Promise<Response> | undefined
export const fixedNow = '2026-10-28T12:00:00.000Z'
export function clock() { vi.useFakeTimers(); vi.setSystemTime(new Date(fixedNow)) }
export const calls = (path: string) => vi.mocked(fetch).mock.calls.filter(([p]) => String(p).split('?')[0] === path)
export const params = (call: any) => new URL(String(call[0]), 'http://localhost').searchParams
export async function tick(ms: number) { await vi.advanceTimersByTimeAsync(ms); await flushPromises() }
export async function mountPage(url: string, mode = 'attacks', change?: Intercept, admin = true) {
  const seed = Date.now(), mock = mockSession(mode)
  let intercept = change
  state.user = { id: 1, username: 'demo', role: admin ? 'admin' : 'viewer' }; state.token = 'development'
  const fetcher = vi.fn(async (raw: any, init: RequestInit = {}) => {
    const path = String(raw), body = init.body ? JSON.parse(String(init.body)) : {}
    const result = mock(path, init.method || 'GET', body, seed)
    const override = intercept?.(path, init, result)
    return override ?? response(result.status, result.body)
  })
  vi.stubGlobal('fetch', fetcher)
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/attacks', component: Attacks }, { path: '/attacks/:id', component: AttackDetail },
    { path: '/:pathMatch(.*)*', component: { template: '<p>Other page</p>' } },
  ] })
  await router.push(url)
  const host = defineComponent({ setup: () => () => [h(RouterView), h(Notifications)] })
  const w = render(host, { global: { plugins: [i18n, router] }, attachTo: document.body })
  await flushPromises()
  return { w, router, fetcher, intercept: (value?: Intercept) => { intercept = value } }
}
