import { describe, it, expect, vi } from 'vitest'
import { defineComponent, h, onUnmounted, nextTick } from 'vue'
import { flushPromises } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { state, saveSession, readTheme, readLocale, summaryBadges } from '../src/state'
import { request, safeNext, configureClient, ApiError } from '../src/api/client'
import { i18n } from '../src/i18n'
import { notifications, notify, notifyWrite } from '../src/notifications'
import { usePoll } from '../src/composables/usePoll'
import { isAdmin, AdminOnly } from '../src/auth'
import { makeRouter, businessPaths } from '../src/router'
import App from '../src/App.vue'
import Shell from '../src/components/Shell.vue'
import Login from '../src/views/Login.vue'
import About from '../src/views/About.vue'
import { pps, bps, dtRate, thousands, duration, relativeTime } from '../src/format'
import { render, deferred, response } from './helpers'

const session = () => saveSession('session-token', { id: 7, username: 'Mira', role: 'admin' })

describe('G-behavior request', () => {
  it('401 clears both keys and navigates with next', async () => {
    session()
    const router = makeRouter(createMemoryHistory())
    await router.push('/attacks/1?q=a')
    configureClient(router)
    vi.mocked(fetch).mockResolvedValue(response(401, { error: 'expired' }))
    await expect(request('/api/stats/summary')).rejects.toMatchObject({ status: 401, message: 'expired' })
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('user')).toBeNull()
    expect(state.user).toBeNull()
    expect(router.currentRoute.value.path).toBe('/login')
    expect(router.currentRoute.value.query.next).toBe('/attacks/1?q=a')
  })

  it('concurrent 401 preserves the original next after the first redirect', async () => {
    session()
    const router = makeRouter(createMemoryHistory())
    const original = '/attacks/1?tab=logs&scope=active#details'
    await router.push(original)
    configureClient(router)
    const replace = vi.spyOn(router, 'replace')
    const first = deferred<Response>()
    const second = deferred<Response>()
    vi.mocked(fetch).mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise)
    const firstRequest = request('/api/stats/summary').catch(error => error)
    const secondRequest = request('/api/nodes').catch(error => error)
    expect(fetch).toHaveBeenCalledTimes(2)

    first.resolve(response(401, { error: 'first expired' }))
    await expect(firstRequest).resolves.toMatchObject({ status: 401, message: 'first expired' })
    expect(router.currentRoute.value.path).toBe('/login')
    expect(router.currentRoute.value.query.next).toBe(original)

    second.resolve(response(401, { error: 'second expired' }))
    await expect(secondRequest).resolves.toMatchObject({ status: 401, message: 'second expired' })
    expect(router.currentRoute.value.path).toBe('/login')
    expect(router.currentRoute.value.query.next).toBe(original)
    expect(replace).toHaveBeenCalledTimes(1)
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('user')).toBeNull()
  })

  it('401 on login preserves existing query without another navigation', async () => {
    const router = makeRouter(createMemoryHistory())
    await router.push('/login?next=%2Ftraffic%3Frange%3D1h&source=bookmark#form')
    const original = router.currentRoute.value.fullPath
    session()
    configureClient(router)
    const replace = vi.spyOn(router, 'replace')
    vi.mocked(fetch).mockResolvedValue(response(401, { error: 'expired' }))
    await expect(request('/api/stats/summary')).rejects.toMatchObject({ status: 401, message: 'expired' })
    expect(router.currentRoute.value.fullPath).toBe(original)
    expect(router.currentRoute.value.query).toEqual({ next: '/traffic?range=1h', source: 'bookmark' })
    expect(replace).not.toHaveBeenCalled()
    expect(localStorage.getItem('token')).toBeNull()
    expect(localStorage.getItem('user')).toBeNull()
  })

  it('login 401 does not clear the existing session', async () => {
    session()
    vi.mocked(fetch).mockResolvedValue(response(401, { error: 'invalid credentials' }))
    await expect(request('/api/login', { method: 'POST' })).rejects.toMatchObject({ status: 401 })
    expect(localStorage.getItem('token'), 'login 401 retains token').toBe('session-token')
    expect(JSON.parse(localStorage.getItem('user')!).username).toBe('Mira')
  })

  it('503 retains session and backend text', async () => {
    session()
    vi.mocked(fetch).mockResolvedValue(response(503, { error: 'service unavailable 原文' }))
    await expect(request('/api/stats/summary')).rejects.toMatchObject({
      status: 503,
      message: 'service unavailable 原文',
    })
    expect(state.token).toBe('session-token')
    expect(localStorage.getItem('user')).not.toBeNull()
  })

  it('sends Bearer and allows explicitly requested failure statuses', async () => {
    session()
    vi.mocked(fetch).mockResolvedValue(response(409, { error: 'in use' }))
    expect(await request('/api/item', { allow: [409] })).toEqual({ error: 'in use' })
    expect((vi.mocked(fetch).mock.calls[0]![1]!.headers as Headers).get('Authorization')).toBe('Bearer session-token')
  })

  it.each(['', 'not json'])('non-JSON/empty errors use HTTP status (%s)', async body => {
    vi.mocked(fetch).mockResolvedValue(new Response(body, { status: 500 }))
    await expect(request('/api/item')).rejects.toMatchObject({ message: 'HTTP 500' })
  })

  it.each([['zh', '请求超时'], ['en', 'Request timed out']] as const)(
    '30s timeout has %s text',
    async (locale, message) => {
      vi.useFakeTimers()
      state.locale = locale
      vi.mocked(fetch).mockImplementation((_path, init) => new Promise(
        (_resolve, reject) => init?.signal?.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
        ),
      ))
      const pending = expect(request('/api/slow')).rejects.toMatchObject({ message, status: 0 })
      await vi.advanceTimersByTimeAsync(30000)
      await pending
    },
  )
})

describe('G-behavior safeNext', () => {
  it('accepts router-decoded path without decoding again', () => {
    expect(safeNext('/attacks/1')).toBe('/attacks/1')
    expect(safeNext('/attacks/%252f')).toBe('/attacks/%252f')
  })

  it.each([
    '//evil.invalid',
    '/\\evil.invalid',
    '/attacks\\1',
    '/attacks\t1',
    '/attacks\n1',
    'https://evil.invalid',
    'javascript:alert(1)',
    ['/a','/b'],
    '/%',
    undefined,
    3,
  ])('rejects unsafe next %j', input => {
    expect(safeNext(input)).toBe('/overview')
  })
})

describe('G-behavior preferences and roles', () => {
  it.each([['classic','light'],['amber','dark']] as const)(
    'legacy theme %s maps and rewrites to %s',
    (old, theme) => {
      localStorage.setItem('theme', old)
      expect(readTheme(localStorage)).toBe(theme)
      expect(localStorage.getItem('theme')).toBe(theme)
    },
  )

  it('theme changes apply immediately; auto removes attribute', () => {
    state.theme = 'dark'
    expect(document.documentElement.dataset.theme).toBe('dark')
    state.theme = 'light'
    expect(document.documentElement.dataset.theme).toBe('light')
    state.theme = 'auto'
    expect(document.documentElement.hasAttribute('data-theme')).toBe(false)
  })

  it.each([['zh-CN','zh'],['zh-TW','zh'],['en-US','en'],['fr-FR','en']] as const)(
    'locale inference %s',
    (language, expected) => {
      expect(readLocale(localStorage, language)).toBe(expected)
    },
  )

  it('stored locale takes priority and changes persist', () => {
    localStorage.setItem('locale','en')
    expect(readLocale(localStorage,'zh-CN')).toBe('en')
    state.locale = 'en'
    expect(localStorage.getItem('locale')).toBe('en')
    expect(document.documentElement.lang).toBe('en')
  })

  it.each(['viewer','operator','admin'])('AdminOnly for %s', role => {
    state.user = { id: 1, username: 'Mira', role }
    const w = render(AdminOnly, { slots: { default: '<button>Write</button>' } })
    expect(isAdmin()).toBe(role === 'admin')
    expect(w.find('button').exists()).toBe(role === 'admin')
  })
})

describe('G-behavior notification lifetime', () => {
  it('write completes after initiating route A unmounts and notification appears on B', async () => {
    session()
    const write = deferred<void>()
    let unmounted = false
    const A = defineComponent({
      setup() {
        onUnmounted(() => unmounted = true)
        return () => h('button', {
          id: 'write',
          onClick: () => void notifyWrite(write.promise, 'Written successfully'),
        }, 'Write')
      },
    })
    const B = defineComponent({ render: () => h('p', { id: 'destination' }, 'B') })
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/a', component: A },
        { path: '/b', component: B },
        { path: '/:rest(.*)', component: B },
      ],
    })
    await router.push('/a')
    const w = render(App, { global: { plugins: [i18n, router] }, attachTo: document.body })
    await flushPromises()
    await w.get('#write').trigger('click')
    await router.replace('/b')
    await flushPromises()
    expect(unmounted).toBe(true)
    expect(w.find('#write').exists()).toBe(false)
    expect(w.get('#destination').text()).toBe('B')
    write.resolve()
    await flushPromises()
    expect(w.get('.toast[role=status]').text()).toBe('Written successfully')
  })

  it('stacks notices for 3s and preserves raw failure', async () => {
    vi.useFakeTimers()
    notify('ok')
    notify('raw error', 'crit')
    expect(notifications).toHaveLength(2)
    expect(notifications[1]!.raw).toBe(true)
    await vi.advanceTimersByTimeAsync(2999)
    expect(notifications).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(1)
    expect(notifications).toHaveLength(0)
    await expect(notifyWrite(Promise.reject(new Error('Original error')), 'Success')).rejects.toThrow('Original error')
    expect(notifications[0]!.message).toBe('Original error')
  })
})

describe('G-behavior usePoll', () => {
  function fixture(fn: () => Promise<number>, accept: (v: number) => void) {
    return render(defineComponent({
      setup() {
        usePoll(fn, 1000, accept)
        return () => h('div')
      },
    }))
  }

  it('unmount during first request discards result and stops polling', async () => {
    vi.useFakeTimers()
    const call = deferred<number>()
    const accept = vi.fn()
    const fn = vi.fn(() => call.promise)
    const w = fixture(fn, accept)
    await nextTick()
    w.unmount()
    call.resolve(1)
    await flushPromises()
    await vi.advanceTimersByTimeAsync(5000)
    expect(accept).not.toHaveBeenCalled()
    expect(fn).toHaveBeenCalledTimes(1)
  })

  it('hidden completion schedules nothing, visibility resumes once', async () => {
    vi.useFakeTimers()
    const first = deferred<number>()
    const second = deferred<number>()
    const fn = vi.fn().mockReturnValueOnce(first.promise).mockReturnValue(second.promise)
    const accept = vi.fn()
    const w = fixture(fn, accept)
    Object.defineProperty(document, 'hidden', { configurable: true, value: true })
    document.dispatchEvent(new Event('visibilitychange'))
    first.resolve(1)
    await flushPromises()
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(1)
    expect(accept).not.toHaveBeenCalled()
    Object.defineProperty(document, 'hidden', { configurable: true, value: false })
    document.dispatchEvent(new Event('visibilitychange'))
    await nextTick()
    expect(fn).toHaveBeenCalledTimes(2)
    await vi.advanceTimersByTimeAsync(5000)
    expect(fn).toHaveBeenCalledTimes(2)
    w.unmount()
    second.resolve(2)
    await flushPromises()
  })

  it('resume during flight never overlaps and discards obsolete reply', async () => {
    vi.useFakeTimers()
    const first = deferred<number>()
    const second = deferred<number>()
    const accept = vi.fn()
    let inFlight = 0
    let max = 0
    let calls = 0
    const fn = vi.fn(async () => {
      inFlight++
      calls++
      max = Math.max(max, inFlight)
      const result = await (calls === 1 ? first.promise : second.promise)
      inFlight--
      return result
    })
    const w = fixture(fn, accept)
    for (const hidden of [true, false, true, false]) {
      Object.defineProperty(document, 'hidden', { configurable: true, value: hidden })
      document.dispatchEvent(new Event('visibilitychange'))
    }
    expect(fn).toHaveBeenCalledTimes(1)
    first.resolve(1)
    await flushPromises()
    expect(fn).toHaveBeenCalledTimes(2)
    expect(accept).not.toHaveBeenCalled()
    second.resolve(2)
    await flushPromises()
    expect(accept).toHaveBeenCalledWith(2)
    expect(max).toBe(1)
    w.unmount()
  })
})

describe('G-behavior shell/routing/login', () => {
  it('missing action_mode uses dash, badges computed, sidebar persists', async () => {
    session()
    state.summary = { active_attacks: 4, total_nodes: 6, online_nodes: 2 }
    expect(summaryBadges(state.summary)).toEqual({ attacks: 4, nodes: 4 })
    vi.mocked(fetch).mockResolvedValue(response(200, state.summary))
    const router = makeRouter(createMemoryHistory())
    await router.push('/overview')
    const w = render(Shell, { global: { plugins: [i18n, router] } })
    await flushPromises()
    expect(w.get('[data-testid=action-mode]').text()).toBe('—')
    expect(w.findAll('.nav a')).toHaveLength(13)
    expect(w.findAll('.nav .badge').map(b => b.text())).toEqual(['4','4'])
    expect(w.get('[aria-current=page]').attributes('href')).toBe('/overview')
    expect(w.text()).toContain('Mira')
    await w.get('.side-tog').trigger('click')
    expect(state.sideCollapsed).toBe(true)
    expect(localStorage.getItem('xs-side')).toBe('1')
    expect(w.findAll('.side-mini button')).toHaveLength(3)
    state.summary = { ...state.summary!, action_mode: 'observe' }
    await nextTick()
    expect(w.get('[data-testid=action-mode]').text()).toBe('观察')
    await w.get('.user button').trigger('click')
    await flushPromises()
    expect(state.token).toBe('')
    expect(router.currentRoute.value.path).toBe('/login')
  })

  it.each([
    ['/traffic-overview','/traffic'],
    ['/templates','/thresholds'],
    ['/dynamic-detection','/baseline'],
    ['/webhooks','/connectors/webhook'],
    ['/settings/bgp-connectors','/connectors/bgp'],
    ['/settings/xdrop-connectors','/connectors/xdrop'],
    ['/settings/webhook-connectors','/connectors/webhook'],
    ['/settings/shell-connectors','/connectors/shell'],
    ['/nodes/node-1/flow','/flow/node-1'],
  ])('legacy redirect %s', async (from,to) => {
    session()
    const router = makeRouter(createMemoryHistory())
    await router.push(from)
    expect(router.currentRoute.value.path).toBe(to)
  })

  it('guards routes, logged-in login/root go overview', async () => {
    const router = makeRouter(createMemoryHistory())
    await router.push('/nodes')
    expect(router.currentRoute.value.path).toBe('/login')
    expect(router.currentRoute.value.query.next).toBe('/nodes')
    session()
    await router.push('/login?x=1')
    expect(router.currentRoute.value.path).toBe('/overview')
    await router.push('/')
    expect(router.currentRoute.value.path).toBe('/overview')
    expect(businessPaths.every(p => !p.startsWith('/api/') && p !== '/metrics')).toBe(true)
  })

  it.each([401,429,503])('login status %s uses generic failure', async status => {
    const router = makeRouter(createMemoryHistory())
    await router.push('/login')
    const w = render(Login, { global: { plugins: [i18n, router] } })
    vi.mocked(fetch).mockResolvedValue(response(status, { error: 'Sensitive detail' }))
    await w.get('#login-user').setValue('name')
    await w.get('input[type=password]').setValue('bad')
    await w.get('form').trigger('submit')
    await flushPromises()
    expect(w.get('[role=alert]').text()).toBe('用户名或密码错误')
    expect(w.text()).not.toContain('Sensitive detail')
  })

  it('login busy prevents repeats, saves session and uses safe next', async () => {
    const router = makeRouter(createMemoryHistory())
    await router.push('/login?next=/attacks/1')
    const pending = deferred<Response>()
    vi.mocked(fetch).mockReturnValue(pending.promise)
    const w = render(Login, { global: { plugins: [i18n, router] } })
    await w.get('#login-user').setValue('Mira')
    await w.get('input[type=password]').setValue('secret')
    await w.get('form').trigger('submit')
    await w.get('form').trigger('submit')
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(w.get('[type=submit]').attributes('aria-busy')).toBe('true')
    pending.resolve(response(200, { token: 'new-token', user: { id: 7, username: 'Mira', role: 'admin' } }))
    await flushPromises()
    expect(state.token).toBe('new-token')
    expect(JSON.parse(localStorage.getItem('user')!).username).toBe('Mira')
    expect(router.currentRoute.value.path).toBe('/attacks/1')
  })

  it('about renders version and full license text', async () => {
    vi.mocked(fetch).mockResolvedValue(response(200, [
      { name:'font',version:'1',license:'OFL-1.1',licenseText:'Full original text' },
    ]))
    const w = render(About)
    await flushPromises()
    expect(w.text()).toContain(__XS_VERSION__)
    expect(w.get('pre').text()).toBe('Full original text')
  })
})

it('formatters preserve traffic/config precision', () => {
  expect(pps(1420000)).toBe('1.42M')
  expect(bps(9.62e9)).toBe('9.62 Gbps')
  expect(dtRate(12345)).toBe('12K')
  expect(dtRate(1420000)).toBe('1.4M')
  expect(thousands(1234)).toBe('1,234')
  expect(duration(3661)).toBe('1h 1m')
  expect(relativeTime(0,60000)).toContain('1')
})


describe('R2 F1 response-body cancellation', () => {
  function receiveHeadersWithPendingBody() {
    const headers = deferred<Response>()
    vi.mocked(fetch).mockImplementation((_path, init) => {
      const body = new ReadableStream<Uint8Array>({
        start(reader) {
          reader.enqueue(new TextEncoder().encode('{"reading":'))
          init?.signal?.addEventListener('abort', () => {
            reader.error(new DOMException('Reading interrupted', 'AbortError'))
          }, { once: true })
        },
      })
      const reply = new Response(body, { status: 200, headers: { 'Content-Type': 'application/json' } })
      headers.resolve(reply)
      return Promise.resolve(reply)
    })
    return headers.promise
  }

  it.each([['zh', '请求超时'], ['en', 'Request timed out']] as const)(
    'R2 F1 timeout while reading a body rejects with %s ApiError',
    async (locale, message) => {
      vi.useFakeTimers()
      state.locale = locale
      const headers = receiveHeadersWithPendingBody()
      const result = request('/api/streaming-summary').catch(error => error)
      const reply = await headers
      await flushPromises()
      expect(reply.status).toBe(200)
      expect(reply.bodyUsed).toBe(true)
      await vi.advanceTimersByTimeAsync(30000)
      const failure = await result
      expect(failure).toBeInstanceOf(ApiError)
      expect(failure).toMatchObject({ status: 0, message })
    },
  )

  it('R2 F1 body transport failure is not accepted as a JSON parse fallback', async () => {
    const body = new ReadableStream<Uint8Array>({
      start(reader) {
        reader.error(new TypeError('Body transport failed'))
      },
    })
    vi.mocked(fetch).mockResolvedValue(new Response(body, { status: 200 }))
    await expect(request('/api/failed-body')).rejects.toMatchObject({ status: 0, message: 'Body transport failed' })
  })

  it('R2 F1 externally aborted body rejects and never reaches poll accept', async () => {
    vi.useFakeTimers()
    const external = new AbortController()
    const headers = receiveHeadersWithPendingBody()
    const accepted = vi.fn()
    const rejected = vi.fn()
    render(defineComponent({
      setup() {
        usePoll(
          () => request('/api/streaming-nodes', { signal: external.signal }),
          5000,
          accepted,
          rejected,
        )
        return () => h('div')
      },
    }))
    const reply = await headers
    await flushPromises()
    expect(reply.bodyUsed).toBe(true)
    external.abort()
    await flushPromises()
    expect(accepted).not.toHaveBeenCalled()
    expect(rejected).toHaveBeenCalledTimes(1)
    expect(rejected.mock.calls[0]?.[0]).toMatchObject({ name: 'AbortError' })
  })
})
