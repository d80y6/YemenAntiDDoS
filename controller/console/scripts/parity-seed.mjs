import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { main, root } from './lib.mjs'

export const parityTime = Date.parse('2026-10-28T00:00:00.000Z')
export const parityDirectory = join(root, '../internal/store/postgres/testdata/mock-parity')
export async function exportSeed() {
  const { mockSession } = await import('../mock/data.ts')
  const session = mockSession('attacks', parityTime)
  const get = path => {
    const r = session(path)
    if (r.status !== 200) throw new Error(`seed GET ${path}: ${r.status}`)
    return r.body
  }
  const nodes = get('/api/nodes')
  const listeners = nodes.filter(n => n.mode === 'flow')
    .flatMap(n => get(`/api/flow-listeners?node_id=${encodeURIComponent(n.id)}`))
  const details = listeners.map(l => get(`/api/flow-listeners/${l.id}`))
  const responses = get('/api/responses')
  const actions = responses.flatMap(r => get(`/api/responses/${r.id}`).actions)
  return {
    users: get('/api/users'), audit: get('/api/audit-log?limit=200&offset=0'),
    prefixes: get('/api/prefixes'), templates: get('/api/threshold-templates'),
    rules: get('/api/thresholds'), config: get('/api/dynamic-detection/config'), responses, actions,
    conditions: actions.flatMap(a => get(`/api/actions/${a.id}/preconditions`)),
    connectors: Object.fromEntries(['webhook', 'shell', 'bgp', 'xdrop']
      .map(kind => [kind, get(`/api/settings/${kind}-connectors`)])),
    nodes, flow_listeners: details.map(d => d.listener), flow_sources: details.flatMap(d => d.sources),
    announcements: [...get('/api/active-actions/bgp').filter(a => a.announcement_id),
      ...get('/api/active-actions/bgp/dismissed-orphans')],
  }
}
if (main(import.meta.url)) {
  const path = join(parityDirectory, 'seed.json')
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(await exportSeed(), null, 2) + '\n')
  console.log('G-seed generated', path)
}
