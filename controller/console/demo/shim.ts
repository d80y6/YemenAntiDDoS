import { session } from './data'
import { createServer, type Server, type Reply } from './server'

declare global { interface Window { __xsDemoMisses: number } }
export function installShim(host: Window, storage: Storage, base: string, server: Server = createServer()) {
  const original = host.fetch.bind(host)
  let user
  try { user = JSON.parse(storage.getItem('user') || 'null') } catch { user = null }
  if (storage.getItem('token') !== session.token || user?.id !== 1
    || user?.username !== session.user.username || user?.role !== 'viewer') {
    storage.setItem('token', session.token)
    storage.setItem('user', JSON.stringify(session.user))
  }
  host.__xsDemoMisses = 0
  host.fetch = async (input, init) => {
    const request = typeof Request !== 'undefined' && input instanceof Request ? input : undefined
    const raw = request ? request.url : String(input)
    const url = new URL(raw, host.location.href)
    if (url.pathname.startsWith('/api/')) {
      const signal = init?.signal ?? request?.signal
      if (signal?.aborted) throw new DOMException('Aborted', 'AbortError')
      let body: unknown = init?.body
      if (body === undefined && request && !['GET', 'HEAD'].includes(request.method)) body = await request.clone().text()
      if (typeof body === 'string') {
        try { body = JSON.parse(body) } catch { body = undefined }
      }
      let reply: Reply
      try { reply = server(url.pathname + url.search, init?.method ?? request?.method ?? 'GET', body) }
      catch { reply = { status: 500, body: { error: 'internal error' } } }
      if (reply.status === 404 || reply.status >= 500) host.__xsDemoMisses++
      return new Response(JSON.stringify(reply.body), { status: reply.status,
        headers: { 'Content-Type': 'application/json' } })
    }
    if (url.pathname === '/third-party.json') {
      const rewritten = new URL(base + 'third-party.json', host.location.origin)
      return original(request ? new Request(rewritten, request) : rewritten.toString(), init)
    }
    return original(input, init)
  }
  return () => { host.fetch = original }
}
installShim(window, localStorage, import.meta.env.BASE_URL)
