import { Readable } from 'node:stream'
export async function middlewareProbe() {
  const modulePath = '../mock/server.ts'
  const { mockPlugin } = await import(modulePath)
  let middleware
  mockPlugin().configureServer({ middlewares: { use: fn => { middleware = fn } } })
  return async (method, url, body) => {
    const req = Object.assign(Readable.from([JSON.stringify(body)]), { method, url })
    /** @type {any} */
    let result
    const res = { statusCode: 0, setHeader() {}, end(raw) { result = JSON.parse(raw) } }
    await middleware(req, res, () => { throw new Error('unexpected next') })
    return { status: res.statusCode, body: result }
  }
}
