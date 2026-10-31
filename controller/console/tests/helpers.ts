import { mount, type ComponentMountingOptions } from '@vue/test-utils'
import type { Component } from 'vue'
import { i18n } from '../src/i18n'

export function render(component: Component, options: ComponentMountingOptions<any> = {}) {
  return mount(component, {
    ...options,
    global: { plugins: [i18n, ...(options.global?.plugins || [])], ...options.global },
  })
}

export function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((a, b) => {
    resolve = a
    reject = b
  })
  return { promise, resolve, reject }
}

export const response = (status: number, body: unknown) => new Response(JSON.stringify(body), {
  status,
  headers: { 'Content-Type': 'application/json' },
})
