type User = { id: number; username: string; role: string; enabled: boolean; created_at: string; updated_at: string }
type Audit = { id: number; user_id: number | null; entity_type: string; entity_id: string; action: string;
  diff: any; delivery_version: number | null; created_at: string }
const at = '2026-10-27T00:00:00.000Z'
function fixtures(): Audit[] {
  const rows: Audit[] = Array.from({ length: 52 }, (_, i) => ({ id: i + 1, user_id: i % 3 + 1,
    entity_type: 'watch_prefix', entity_id: String(i + 1), action: 'update',
    diff: { old: { name: 'Before' }, new: { name: `Prefix ${i + 1}`, enabled: true } },
    delivery_version: i + 1, created_at: new Date(Date.parse(at) + i * 60000).toISOString() }))
  const extra = [
    { entity_type: 'user', user_id: 3, action: 'create', diff: { username: 'audit-ro', role: 'viewer' } },
    { entity_type: 'node', user_id: 1, action: 'delete', diff: null },
    { entity_type: 'webhook_connector', user_id: 2, action: 'update',
      diff: { old: { headers: { Authorization: 'example-token' } }, new: [{ HEADERS: { X: 'example-value' } }] } },
    { entity_type: 'response_action', user_id: null, action: 'force_remove', diff: { headers: 7 } },
    { entity_type: 'response_action', user_id: 1, action: 'create', diff: [{ headers: ['example-value'] }] },
    { entity_type: 'response_action', user_id: 2, action: 'update', diff: { Headers: { X: null } } },
    { entity_type: 'webhook', user_id: null, action: 'dismiss', diff: { headers: { X: 'example-token' } } },
  ]
  return rows.concat(extra.map((row, i) => ({ id: 53 + i, entity_id: String(i + 1), delivery_version: null,
    created_at: new Date(Date.parse(at) + (52 + i) * 60000).toISOString(), ...row })))
}
function mask(value: any): any {
  if (Array.isArray(value)) return value.map(mask)
  if (!value || typeof value !== 'object') return value
  return Object.fromEntries(Object.entries(value).map(([key, v]) => {
    if (key.toLowerCase() !== 'headers') return [key, mask(v)]
    const table = v && typeof v === 'object' && !Array.isArray(v)
      && Object.values(v).every(entry => entry === null || typeof entry === 'string')
    return [key, table ? Object.fromEntries(Object.keys(v).map(k => [k, '******'])) : null]
  }))
}
function time(raw: string | null) {
  if (!raw || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(raw)) return NaN
  return Date.parse(raw.replace(',', '.'))
}
// Go strings.TrimSpace delegates to unicode.IsSpace (Unicode White_Space).
// U+0085 is included; U+FEFF and U+180E are not whitespace in Go.
function trimGoSpace(value: string) {
  return value.replace(/^[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/, '')
    .replace(/[\t-\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/, '')
}
export function usersSession(mode: string, now: number) {
  let users: User[] = [
    { id: 1, username: 'demo', role: 'admin', enabled: true, created_at: at, updated_at: at },
    { id: 2, username: 'noc-01', role: 'operator', enabled: true, created_at: at, updated_at: at },
    { id: 3, username: 'audit-ro', role: 'viewer', enabled: true, created_at: at, updated_at: at },
    { id: 4, username: 'ops-2', role: 'admin', enabled: mode !== 'qi-last-admin', created_at: at, updated_at: at },
  ]
  const audit = fixtures()
  let sequence = 4
  const send = (body: unknown, status = 200) => ({ status, body: structuredClone(body) })
  const fail = (error: string, status = 500) => send({ error }, status)
  const counted = (row: Pick<User, 'role' | 'enabled'>) => row.role === 'admin' && row.enabled === true
  const lastAdmin = (row: User) => counted(row) && !users.some(u => u.id !== row.id && counted(u))
  return (raw: string, method = 'GET', body: any = {}) => {
    const url = new URL(raw, 'http://localhost'), path = url.pathname, q = url.searchParams
    const match = /^\/api\/users\/(\d+)$/.exec(path)
    if (path === '/api/users' && method === 'GET') {
      if (mode === 'qi-users-fail') return fail('users unavailable')
      return send(users.length ? users : null)
    }
    if (path === '/api/users' && method === 'POST') {
      const invalid = ['Username', 'Password'].filter(key => !body[key.toLowerCase()])
      if (invalid.length) return fail(invalid.map(key =>
        `Key: '${key}' Error:Field validation for '${key}' failed on the 'required' tag`).join('\n'), 400)
      const role = body.role || 'viewer'
      if (new TextEncoder().encode(body.password).length > 72) return fail('hash failed')
      const id = ++sequence
      if (users.some(u => u.username === body.username)) return fail('already exists', 409)
      users.push({ id, username: body.username, role, enabled: true,
        created_at: new Date(now).toISOString(), updated_at: new Date(now).toISOString() })
      return send({ id }, 201)
    }
    if (match && method === 'PUT') {
      const row = users.find(u => u.id === Number(match[1]))
      if (!row) return fail('user not found', 404)
      const password = trimGoSpace(body.password ?? '')
      if (password && new TextEncoder().encode(password).length > 72) return fail('hash failed')
      const next = { role: body.role || row.role, enabled: body.enabled ?? row.enabled }
      if (lastAdmin(row) && !counted(next)) return fail('at least one enabled admin is required', 409)
      const username = body.username || row.username
      if (users.some(u => u.id !== row.id && u.username === username)) return fail('already exists', 409)
      Object.assign(row, { username, role: body.role || row.role, enabled: body.enabled ?? row.enabled,
        updated_at: new Date(now).toISOString() })
      return send({ ok: true })
    }
    if (match && method === 'DELETE') {
      const id = Number(match[1])
      const row = users.find(u => u.id === id)
      if (row && lastAdmin(row)) return fail('at least one enabled admin is required', 409)
      users = users.filter(u => u.id !== id)
      for (const row of audit) if (row.user_id === id) row.user_id = null
      return send({ ok: true })
    }
    if (path !== '/api/audit-log' || method !== 'GET') return
    if (mode === 'qi-audit-fail' || mode === 'qi-audit-page-fail' && Number(q.get('offset')) > 0) {
      return fail('audit unavailable')
    }
    const from = time(q.get('from')), to = time(q.get('to'))
    const integer = (key: string, fallback: number) => !q.has(key) ? fallback
      : /^[+-]?\d+$/.test(q.get(key)!) ? Number(q.get(key)) : 0
    const requested = integer('limit', 50), limit = requested <= 0 ? 100 : Math.min(200, requested)
    const offset = Math.max(0, integer('offset', 0))
    const rows = audit.filter(row => (!q.get('entity_type') || row.entity_type === q.get('entity_type'))
      && (!q.get('user_id') || row.user_id === integer('user_id', 0))
      && (!Number.isFinite(from) || Date.parse(row.created_at) >= from)
      && (!Number.isFinite(to) || Date.parse(row.created_at) <= to))
      .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).slice(offset, offset + limit)
      .map(row => ({ ...row, diff: ['webhook_connector', 'webhook', 'response_action'].includes(row.entity_type)
        ? mask(row.diff) : row.diff }))
    return send(mode === 'qi-audit-empty' || !rows.length ? null : rows)
  }
}
