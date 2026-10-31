import { readFileSync } from 'node:fs'

// Read Go declarations, including nested groups; never derive coverage from demo handlers.
const moduleURL = import.meta.url
export function backendRoutes(file = new URL('../../internal/api/router.go', moduleURL)) {
  const source = readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '')
  const groups = new Map([['r', '']]), routes = []
  const declarations = /(\w+)\s*:=\s*(\w+)\.Group\("([^"]+)"\)|(\w+)\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\("([^"]+)"/g
  for (const m of source.matchAll(declarations)) {
    if (m[1]) {
      if (!groups.has(m[2])) throw Error('Unknown route group: ' + m[2])
      groups.set(m[1], groups.get(m[2]) + m[3])
    } else {
      if (!groups.has(m[4])) throw Error('Unknown route group: ' + m[4])
      const path = groups.get(m[4]) + m[6]
      if (path.startsWith('/api/')) routes.push({ method: m[5], path })
    }
  }
  return routes
}
export function samplePath(path) {
  const id = path.startsWith('/api/nodes/') ? 'flow-c' : path.startsWith('/api/thresholds/') ? '10' : '1'
  const resolved = path.replaceAll(':id', id)
  const queries = {
    '/api/attacks/mitigation-brief': 'ids=1,2',
    '/api/active-actions/timeline': 'attack_id=1&action_id=1&connector_id=1&external_rule_id=rule-1',
    '/api/active-actions/xdrop/delivery': 'connector_id=1&rule_id=rule-1',
    '/api/flow-listeners': 'node_id=flow-c',
    '/api/flow-sources': 'listener_id=1',
  }
  return resolved + (queries[resolved] ? '?' + queries[resolved] : '')
}
