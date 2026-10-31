import { pathToFileURL } from 'node:url'
import { resolve, join } from 'node:path'
import { mkdirSync, writeFileSync } from 'node:fs'
import { root, out, main } from './lib.mjs'

// Exact endpoint + path permissions, independent of the contract being checked.
const optional = new Set([
  ...['paired_with', 'auto_generated'].map(f => '/api/responses/{response}::actions[].' + f),
  ...['scheduled_for', 'is_orphan', 'announcement_id', 'attached_attacks',
    'attached_attacks[].decoder', 'attached_attacks[].response_name', 'attached_attacks[].detached_at']
    .map(f => '/api/active-actions/bgp::[].' + f),
  ...['scheduled_for', 'tcp_flags', 'action', 'rate_limit'].map(f => '/api/active-actions/xdrop::[].' + f),
  '/api/nodes::[].last_stats_at',
  ...['/api/stats/total-timeseries', '/api/stats/timeseries'].flatMap(endpoint =>
    ['frag_pps', 'frag_bps', 'extra_decoder_pps', 'extra_decoder_bps'].map(f => endpoint + '::[].' + f)),
  ...['template_name', 'rule_summary'].flatMap(f => ['/api/attacks::attacks[].' + f,
    '/api/attacks/{attack}::attack.' + f]),
  ...['threshold_value', 'threshold_unit'].flatMap(f => ['/api/attacks/active::timers.*.' + f,
    '/api/attacks/{attack}::timer.' + f]),
  ...['bgp_role', 'announcement_refcount', 'skip_reason', 'detail']
    .map(f => '/api/attacks/{attack}/mitigation-summary::executions[].' + f),
  ...['delay_started_at', 'withdrawn_at']
    .map(f => '/api/attacks/{attack}/mitigation-summary::xdrop_rules[].' + f),
  '/api/attacks/{attack}/mitigation-summary::bgp_announcements[].announcement.delay_started_at',
  ...['dst_ip', 'protocol', 'src_port', 'dst_port'].map(f => '/api/active-actions/xdrop::[].' + f),
  '/api/attacks/mitigation-brief::*.xdrop_rules[].scheduled_for',
])
const conditional = new Set([
  ...['last_stats_at', 'stats_age_seconds', 'connected_at', 'uptime_seconds', 'flow_metrics',
    'source_statuses', 'listener_statuses', 'interfaces', 'capture'].map(f => '/api/nodes/{node}/status::' + f),
  '/api/attacks/{attack}::timer', '/api/attacks/{attack}::current',
  '/api/attacks/active::current', '/api/attacks/{attack}/sensor-logs::window',
])
export function inspect(value, path, entry = {}) {
  const tokens = path.replaceAll('[]', '.[]').split('.').filter(Boolean)
  function visit(current, index) {
    if (index === tokens.length) return [current === null && !entry.nullable ? 'missing' : 'hit']
    if (current === null) return ['uncovered']
    if (current === undefined) return ['missing']
    const token = tokens[index]
    if (token === '[]' || token === '*') {
      if (token === '[]' ? !Array.isArray(current) : typeof current !== 'object') return ['missing']
      const values = Object.values(current)
      return values.length ? values.flatMap(v => visit(v, index + 1)) : ['uncovered']
    }
    if (typeof current !== 'object' || !Object.hasOwn(current, token)) {
      return [index === tokens.length - 1 && typeof current === 'object'
        && (entry.optional || entry.conditional)
        || entry.optionalParents?.some(p => p.replaceAll('[]', '.[]').split('.').filter(Boolean)
          .join('.') === tokens.slice(0, index + 1).join('.')) ? 'hit-absent' : 'missing']
    }
    return visit(current[token], index + 1)
  }
  const states = visit(value, 0)
  return states.includes('missing') ? 'missing' : states.includes('hit') ? 'hit'
    : states.includes('hit-absent') ? 'hit-absent' : 'uncovered'
}
export async function checkContract(entries, fetcher, options = {}) {
  const samples = new Map(), results = []
  for (const entry of entries) {
    const endpoint = entry.endpoint.split('?')[0], full = endpoint + '::' + entry.path
    let state, detail = '', conditionalAbsent = false
    if (Object.hasOwn(entry, 'optional')
      && (!optional.has(full) || typeof entry.optional !== 'string' || !entry.optional.trim())) {
      state = 'missing'; detail = 'invalid optional: not in full-path Go omitempty whitelist'
    } else if (Object.hasOwn(entry, 'conditional') && (!conditional.has(full)
      || typeof entry.conditional !== 'string' || !entry.conditional.trim())) {
      state = 'missing'; detail = 'invalid conditional: not in full-path Go branch whitelist'
    } else if (entry.endpoint.includes('{attack}') && !/^[1-9]\d*$/.test(String(options.attack ?? ''))) {
      state = 'missing'; detail = 'template requires --attack <positive id>'
    } else if (entry.endpoint.includes('{response}') && !/^[1-9]\d*$/.test(String(options.response ?? ''))) {
      state = 'missing'; detail = 'template requires --response <positive id>'
    } else if (entry.endpoint.includes('{listener}') && !/^[1-9]\d*$/.test(String(options.listener ?? ''))) {
      state = 'missing'; detail = 'template requires --listener <positive id>'
    } else if (entry.endpoint.includes('{node}') && !String(options.node ?? '')) {
      state = 'missing'; detail = 'template requires --node <id>'
    } else {
      if (!samples.has(entry.endpoint)) {
        try { samples.set(entry.endpoint, { value: await fetcher(
          entry.endpoint.replaceAll('{attack}', String(options.attack))
            .replaceAll('{response}', String(options.response))
            .replaceAll('{listener}', String(options.listener))
            .replaceAll('{node}', encodeURIComponent(String(options.node))),
        ) }) }
        catch (error) { samples.set(entry.endpoint, { error: String(error) }) }
      }
      const sample = samples.get(entry.endpoint)
      if (sample.error) { state = 'missing'; detail = sample.error }
      else {
        const parents = entries.filter(e => e.endpoint.split('?')[0] === endpoint && e.conditional
          && conditional.has(endpoint + '::' + e.path)
          && (entry.path === e.path || entry.path.startsWith(e.path + '.') || entry.path.startsWith(e.path + '[]')))
        conditionalAbsent = parents.some(parent => inspect(sample.value, parent.path, parent) === 'hit-absent')
        const optionalParents = entries.filter(e => e.endpoint.split('?')[0] === endpoint && e.optional
          && optional.has(endpoint + '::' + e.path) && e.path.includes('[]')
          && (entry.path.startsWith(e.path + '.') || entry.path.startsWith(e.path + '[]'))).map(e => e.path)
        state = conditionalAbsent ? 'hit-absent' : inspect(sample.value, entry.path, { ...entry, optionalParents })
      }
    }
    const passed = !(options.mock && conditionalAbsent) && (state === 'hit' || state === 'hit-absent'
      || state === 'uncovered' && typeof entry.allowUncovered === 'string' && !!entry.allowUncovered.trim())
    if (options.mock && conditionalAbsent) detail = 'mock conditional-absent is forbidden'
    results.push({ ...entry, state, detail, passed, conditionalAbsent })
  }
  return { passed: results.every(r => r.passed), requests: samples.size, paths: results.length, results,
    conditionalAbsent: results.filter(r => r.conditionalAbsent).map(r => r.endpoint + '::' + r.path) }
}
if (main(import.meta.url)) {
  const arg = name => { const i = process.argv.indexOf(name); return i < 0 ? undefined : process.argv[i + 1] }
  const file = resolve(arg('--contract') || join(root, 'src/api/contract.ts'))
  const { contract } = await import(pathToFileURL(file).href)
  const base = arg('--base'), attack = arg('--attack'), node = arg('--node'), response = arg('--response')
  const listener = arg('--listener')
  const { mockReply } = base ? {} : await import('../mock/data.ts')
  const report = await checkContract(contract, async endpoint => {
    if (!base) {
      const reply = mockReply(endpoint)
      if (reply.status !== 200) throw new Error('mock HTTP ' + reply.status)
      return reply.body
    }
    const response = await fetch(new URL(endpoint, base), {
      headers: process.env.XSIGHT_TOKEN ? { Authorization: 'Bearer ' + process.env.XSIGHT_TOKEN } : {},
    })
    if (!response.ok) throw new Error('HTTP ' + response.status)
    return response.json()
  }, { attack, node, response, listener, mock: !base })
  mkdirSync(out, { recursive: true })
  writeFileSync(arg('--report') || join(out, 'contract.json'), JSON.stringify(report, null, 2))
  console.log('G-contract', JSON.stringify({ passed: report.passed, requests: report.requests, paths: report.paths,
    counts: report.results.reduce((r, item) => ({ ...r, [item.state]: (r[item.state] || 0) + 1 }), {}),
    conditionalAbsent: report.conditionalAbsent, failures: report.results.filter(r => !r.passed) }))
  process.exitCode = report.passed ? 0 : 1
}
