import { expect, it, vi } from 'vitest'

it('demo shim seeds viewer, intercepts Request and string APIs, counts misses and rewrites About', async () => {
  const upstream = vi.fn().mockResolvedValue(new Response('[]'))
  window.fetch = upstream
  localStorage.setItem('token', 'unrelated')
  localStorage.setItem('user', JSON.stringify({ role: 'admin' }))
  const { installShim } = await import('../demo/shim')
  // Import side effect has already seeded the session before any application imports.
  expect(localStorage.getItem('token')).toBe('demo-session')
  expect(JSON.parse(localStorage.getItem('user')!).role).toBe('viewer')
  window.fetch = upstream
  const restore = installShim(window, localStorage, '/xsight/')
  try {
    expect((await (await window.fetch('/api/nodes')).json()).length).toBe(3)
    expect(upstream).not.toHaveBeenCalled()
    const request = new Request(location.origin + '/api/login', { method: 'POST',
      body: JSON.stringify({ username: 'reader', password: 'sample-input' }) })
    expect((await (await window.fetch(request)).json()).user.role).toBe('viewer')
    expect((await window.fetch('/api/nodes/1', { method: 'PUT', body: '{}' })).status).toBe(403)
    expect((await window.fetch('/api/unknown')).status).toBe(404)
    expect(window.__xsDemoMisses).toBe(1)
    await window.fetch('/third-party.json')
    expect(upstream).toHaveBeenLastCalledWith(location.origin + '/xsight/third-party.json', undefined)
    const options = { method: 'HEAD' }
    await window.fetch('/assets/example.svg', options)
    expect(upstream).toHaveBeenLastCalledWith('/assets/example.svg', options)
    localStorage.removeItem('token'); localStorage.removeItem('user')
    expect((await (await window.fetch('/api/login', { method: 'POST', body: JSON.stringify({
      username: 'viewer', password: 'sample-input',
    }) })).json()).token).toBe('demo-session')
    const controller = new AbortController(); controller.abort()
    await expect(window.fetch('/api/nodes', { signal: controller.signal }))
      .rejects.toMatchObject({ name: 'AbortError' })
  } finally { restore() }
})
