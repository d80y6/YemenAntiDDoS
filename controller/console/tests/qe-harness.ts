import { vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { createMemoryHistory, RouterView } from 'vue-router'
import { makeRouter } from '../src/router'
import { mockSession } from '../mock/data'
import { state } from '../src/state'
import { i18n } from '../src/i18n'
import Notifications from '../src/components/Notifications.vue'
import { render, response } from './helpers'
import type { Intercept } from './attacks-harness'
export { clock, calls, tick } from './attacks-harness'
export { clickText, domClick, dialog } from './qd-harness'
export const writes = () => vi.mocked(fetch).mock.calls.filter(([, init]) => init?.method && init.method !== 'GET')
export const body = () => JSON.parse(String(writes().at(-1)?.[1]?.body))
export async function mountQE(url: string, change?: Intercept, admin = true, mode = 'qe') {
  state.token = 'development'
  state.user = { id: 1, username: 'demo', role: admin ? 'admin' : 'viewer' }
  const mock = mockSession(mode)
  const accepted: { path: string; method: string; data: any }[] = []
  let intercept = change
  vi.stubGlobal('fetch', vi.fn(async (raw: any, init: RequestInit = {}) => {
    const path = String(raw), data = init.body ? JSON.parse(String(init.body)) : {}
    const method = init.method || 'GET'
    if (method === 'GET') {
      const result = mock(path, method, data)
      return intercept?.(path, init, result) ?? response(result.status, result.body)
    }
    const preview = mockSession(mode)
    for (const previous of accepted) preview(previous.path, previous.method, previous.data)
    const result = preview(path, method, data)
    const reply = await (intercept?.(path, init, result) ?? response(result.status, result.body))
    if (reply.ok) {
      mock(path, method, data)
      accepted.push({ path, method, data })
    }
    return reply
  }))
  const router = makeRouter(createMemoryHistory())
  await router.push(url)
  await router.isReady()
  const host = defineComponent({ setup: () => () => [h(RouterView), h(Notifications)] })
  const w = render(host, { attachTo: document.body, global: { plugins: [i18n, router] } })
  await flushPromises()
  return { w, router, intercept: (next?: Intercept) => { intercept = next } }
}
export async function choose(label: string, option: string, root: ParentNode = document) {
  const button = [...root.querySelectorAll<HTMLButtonElement>('[role=combobox]')]
    .find(b => b.getAttribute('aria-label')?.startsWith(label + ':'))
  if (!button) throw new Error('combobox not found: ' + label)
  button.click()
  await flushPromises()
  const choice = [...document.querySelectorAll<HTMLButtonElement>('[role=option]')]
    .find(b => b.textContent?.trim() === option)
  if (!choice) throw new Error('option not found: ' + option)
  choice.click()
  await flushPromises()
}
export async function input(label: string, value: string, root: ParentNode = document) {
  const element = root.querySelector<HTMLInputElement>(`input[aria-label="${label}"]`)!
  if (!element) throw new Error('input not found: ' + label)
  element.focus()
  element.value = value
  element.dispatchEvent(new Event('input', { bubbles: true }))
  element.blur()
  await flushPromises()
  return element
}
export async function textInput(label: string, value: string) {
  const field = [...document.querySelectorAll('label')].find(l => l.querySelector('span')?.textContent === label)
  const element = field?.querySelector<HTMLInputElement | HTMLTextAreaElement>('input,textarea')
  if (!element) throw new Error('field not found: ' + label)
  element.value = value
  element.dispatchEvent(new Event('input', { bubbles: true }))
  await flushPromises()
  return element
}
