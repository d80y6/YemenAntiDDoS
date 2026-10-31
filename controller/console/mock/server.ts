import type { Plugin } from 'vite'
import { mockSession } from './data'

// __XS_MOCK__ -- this sentinel must never enter dist.
export function mockPlugin(): Plugin {
  return {
    name: 'xsight-development-mock',
    configureServer(server) {
      const mode = process.env.XSIGHT_MOCK_CASE || 'attacks'
      const mock = mockSession(mode)
      server.middlewares.use(async (req, res, next) => {
        if (process.env.XSIGHT_API || !req.url?.startsWith('/api/')) return next()
        function reply(status: number, body: unknown) {
          res.statusCode = status
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify(body))
        }
        if (req.method === 'POST' && req.url === '/api/login') {
          let raw = ''
          for await (const chunk of req) raw += chunk
          let body: { username?: string; password?: string }
          try {
            body = JSON.parse(raw)
          } catch {
            reply(400, { error: 'username and password required' })
            return
          }
          if (!body.username || !body.password) {
            reply(400, { error: 'username and password required' })
            return
          }
          if (body.username === 'limited') {
            res.setHeader('Retry-After', '60')
            reply(429, { error: 'too many login attempts' })
            return
          }
          if (body.username === 'unavailable') {
            reply(503, { error: 'authentication service unavailable' })
            return
          }
          if (mode.startsWith('qi') && body.username === 'audit-ro' && body.password === 'demo') {
            reply(200, { token: 'development-audit-session', user: { id: 3, username: 'audit-ro', role: 'viewer' } })
            return
          }
          if (mode.startsWith('qh') && body.username === 'viewer' && body.password === 'demo') {
            reply(200, { token: 'development-viewer-session', user: { id: 2, username: 'viewer', role: 'viewer' } })
            return
          }
          if (body.username === 'demo' && body.password === 'demo') {
            reply(200, {
              token: 'development-session',
              user: { id: 1, username: 'demo', role: 'admin' },
            })
            return
          }
          reply(401, { error: 'invalid credentials' })
          return
        }
        if (['GET', 'POST', 'PUT', 'DELETE'].includes(req.method || '')) {
          let body = ''
          if (req.method === 'POST' || req.method === 'PUT') for await (const chunk of req) body += chunk
          let parsed
          try { parsed = body ? JSON.parse(body) : {} }
          catch { reply(400, { error: 'invalid JSON' }); return }
          const result = mock(req.url, req.method, parsed)
          if (req.url.startsWith('/api/stats/summary') && process.env.XSIGHT_MOCK_ACTION) {
            if (process.env.XSIGHT_MOCK_ACTION === 'missing') delete result.body.action_mode
            else result.body.action_mode = process.env.XSIGHT_MOCK_ACTION
          }
          if (mode === 'loading' && (req.url.startsWith('/api/stats/total-timeseries')
            || req.url.split('?')[0].endsWith('/sensor-logs'))) {
            setTimeout(() => reply(result.status, result.body), 20000)
          } else if (result.delay) setTimeout(() => reply(result.status, result.body), result.delay)
          else reply(result.status, result.body)
          return
        }
        reply(404, { error: 'not found' })
      })
    },
  }
}
