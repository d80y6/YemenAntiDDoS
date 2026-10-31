import type { Router } from 'vue-router'
import { clearSession, state } from '../state'
import { i18n } from '../i18n'

export class ApiError extends Error {
  constructor(public status: number, message: string, public timeout = false) {
    super(message)
    this.name = 'ApiError'
  }
}

export function safeNext(raw: unknown): string {
  if (
    typeof raw !== 'string'
    || !raw.startsWith('/')
    || raw.startsWith('//')
    || /[\\\x00-\x1f\x7f]/.test(raw)
  ) return '/overview'
  try {
    decodeURIComponent(raw) // Validate escapes only; never use a second decoded value.
    if (new URL(raw, location.origin).origin !== location.origin) return '/overview'
    return raw
  } catch {
    return '/overview'
  }
}

let navigation: Pick<Router, 'replace' | 'currentRoute'> | undefined

export function configureClient(router: Pick<Router, 'replace' | 'currentRoute'>) {
  navigation = router
}

export interface RequestOptions extends RequestInit {
  allow?: number[]
  timeout?: number
}

export async function request<T = unknown>(path: string, options: RequestOptions = {}): Promise<T> {
  const { allow = [], timeout = 30000, signal, ...init } = options
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeout)
  const abort = () => controller.abort(signal?.reason)
  if (signal?.aborted) abort()
  else signal?.addEventListener('abort', abort, { once: true })
  const headers = new Headers(init.headers)
  if (state.token) headers.set('Authorization', `Bearer ${state.token}`)
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  try {
    const response = await fetch(path, { ...init, headers, signal: controller.signal })
    let body: unknown
    try {
      body = await response.json()
    } catch (error) {
      if (controller.signal.aborted || !(error instanceof SyntaxError)) throw error
      body = undefined
    }
    if (response.status === 401 && path !== '/api/login') {
      const next = navigation?.currentRoute.value.fullPath || '/overview'
      clearSession()
      if (navigation?.currentRoute.value.path !== '/login') {
        await navigation?.replace({ path: '/login', query: { next } })
      }
    }
    if (!response.ok && !allow.includes(response.status)) {
      const error = body && typeof body === 'object' && 'error' in body
        ? (body as { error: unknown }).error
        : undefined
      throw new ApiError(response.status, typeof error === 'string' && error ? error : `HTTP ${response.status}`)
    }
    return body as T
  } catch (error) {
    if (timedOut) throw new ApiError(0, i18n.global.t('api.timeout'), true)
    if (
      error instanceof ApiError
      || ((error instanceof Error || error instanceof DOMException) && error.name === 'AbortError')
    ) throw error
    throw new ApiError(0, error instanceof Error ? error.message : i18n.global.t('api.network'))
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', abort)
  }
}
