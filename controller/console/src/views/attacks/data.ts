import type { Attack, Active, Timer } from '../../api/data'
import type { Point, Window } from '../../components/chart/math'
export type Row = Record<string, any>
export function validTarget(raw: string) {
  const parts = raw.trim().split('/'), ip = parts[0]!
  if (parts.length > 2 || !ip || ip.includes('%')) return false
  const v4 = (text: string) => text.split('.').length === 4 && text.split('.').every(
    w => /^(0|[1-9]\d{0,2})$/.test(w) && Number(w) <= 255,
  )
  const family = ip.includes(':') ? 128 : 32
  if (family === 32) { if (!v4(ip)) return false }
  else {
    let text = ip
    if (text.includes('.')) {
      const tail = text.slice(text.lastIndexOf(':') + 1)
      if (!v4(tail)) return false
      text = text.slice(0, text.lastIndexOf(':') + 1) + 'ffff:ffff'
    }
    const sides = text.split('::')
    if (sides.length > 2) return false
    const words = sides.flatMap(s => s ? s.split(':') : [])
    if (words.some(w => !/^[0-9a-f]{1,4}$/i.test(w))) return false
    if (sides.length === 1 ? words.length !== 8 : words.length >= 8) return false
  }
  return parts.length === 1 || /^[0-9]+$/.test(parts[1]!) && Number(parts[1]) <= family
}
export function target(raw: string) {
  const [ip = '', mask] = raw.split('/'), bits = ip.includes(':') ? 128 : 32
  const kind = raw === '0.0.0.0/0' ? 'global' : mask === undefined || Number(mask) === bits ? 'single' : 'network'
  return { kind, text: kind === 'single' ? ip : raw }
}
export interface Filters { status: string; dir: string; win: string; q: string; page: number }
export const PAGE = 50
export function listParams(f: Filters, status: string, now: number, count = false) {
  return { ...(status === 'all' ? {} : { status }), ...(f.dir === 'all' ? {} : { direction: f.dir }),
    ...(status === 'active' && !count ? { sort: 'peak_pps' } : {}),
    ...(f.q.trim() ? { dst_ip: f.q.trim() } : {}),
    ...(status === 'expired' ? { ended_after: new Date(now - ({ '24h': 1, '7d': 7, '30d': 30 }[f.win] ?? 1)
      * 86400000).toISOString() } : {}), limit: count ? 1 : PAGE, offset: count ? 0 : (f.page - 1) * PAGE }
}
export const countdown = (seconds: number) => {
  const n = Math.max(0, Math.ceil(seconds))
  return `${Math.floor(n / 60)}:${String(n % 60).padStart(2, '0')}`
}
export function statusInfo(a: Attack, active?: Active, error = '') {
  if (a.ended_at) return { key: 'ended', tip: '', seconds: 0 }
  const timer = active?.timers?.[a.id]
  if (timer) return { key: timer.state === 'expiring' ? 'falling' : 'breaching',
    tip: timer.state === 'expiring' ? 'fallingTip' : 'breachingTip', seconds: timer.expires_in }
  if (active?.attacks?.some(row => row.id === a.id)) return { key: 'untracked', tip: 'untrackedTip', seconds: 0 }
  return { key: 'missing', tip: active ? active.active_count > active.returned ? 'truncated' : 'pending'
    : error, seconds: 0 }
}
export function curveWindow(a: Attack, now: number) {
  const start = Date.parse(a.started_at), ended = a.ended_at ? Date.parse(a.ended_at) : null
  const end = ended === null ? now : ended + 600000
  const original = start - (ended === null ? Math.max(8, 30 - (now - start) / 60000) : 10) * 60000
  const cap = target(a.dst_ip).kind === 'single' ? 21600000 : 86400000
  const from = Math.max(original, end - cap), grain = end - from <= 3600000 ? 5000 : 300000
  return { bounds: [from, end] as Window, to: Math.min(now, end), grain, capped: from > original, cap }
}
export function tailFrom(last: number, grain: number, start: number) {
  return Math.max(start, Math.floor(last / grain) * grain - grain)
}
export function wholeCurve(points: Point[], grain: number, oldGrain: number, start: number, firstEnded: boolean) {
  return grain !== oldGrain || !points.length || points.at(-1)!.time < start || firstEnded
}
export function mergeTail(old: Point[], incoming: Point[], from: number, start: number) {
  return [...new Map([...old.filter(p => p.time < from), ...incoming].map(p => [p.time, p])).values()]
    .filter(p => p.time >= start).sort((a, b) => a.time - b.time)
}
export function curveRequest(a: Attack, now: number, points: Point[], oldGrain: number, firstEnded = false,
  metricChanged = false) {
  const w = curveWindow(a, now), t = target(a.dst_ip)
  const whole = wholeCurve(points, w.grain, oldGrain, w.bounds[0], firstEnded) || metricChanged
  const from = whole ? w.bounds[0] : tailFrom(points.at(-1)!.time, w.grain, w.bounds[0])
  return { ...w, whole, from, path: t.kind === 'global' ? 'stats/total-timeseries' : 'stats/timeseries',
    params: { ...(t.kind === 'global' ? {} : t.kind === 'single' ? { dst_ip: t.text } : { prefix: a.dst_ip }),
      direction: a.direction, include_extras: 'true', resolution: w.grain === 5000 ? '5s' : '5min',
      from: new Date(from).toISOString(), to: new Date(w.to).toISOString() } }
}
export function threshold(a: Attack, timer?: Timer) {
  const present = !a.ended_at && timer && Object.hasOwn(timer, 'threshold_value')
    && Object.hasOwn(timer, 'threshold_unit')
  return { metric: timer?.threshold_unit === 'bps' ? 'bps' : 'pps',
    line: present && ['pps', 'bps'].includes(timer.threshold_unit!) ? timer.threshold_value : undefined,
    pct: present && timer.threshold_unit === 'pct' ? timer.threshold_value : undefined }
}
export function canForceRemoveRow(row: Row | null, attack: Attack | null) {
  if (!row) return false
  if (row.trigger_phase !== 'on_detected') return false
  if (row.status !== 'success') return false
  if (row.action_type !== 'bgp' && row.action_type !== 'xdrop') return false
  if (!row.external_rule_id || !row.connector_id) return false
  if (attack && attack.ended_at) return false
  return true
}
export const forceBody = (id: number, row: Row) => ({ attack_id: id, action_id: row.action_id,
  connector_id: row.connector_id, external_rule_id: row.external_rule_id })
export const holdInputValid = (raw: string) => raw === '' || /^(0|[1-9]\d{0,4})$/.test(raw) && Number(raw) <= 86400
export const expireURL = (id: number, raw: string) => `/api/attacks/${id}/expire`
  + (raw === '' ? '' : `?hold_seconds=${raw}`)
export function expireResult(id: number, raw: string, method: string) {
  return { tone: method === 'db' ? 'warn' as const : 'ok' as const,
    key: method === 'db' ? 'expiredNotHeld' : raw === '' ? 'expiredGlobal'
      : raw === '0' ? 'expiredNoHold' : 'expiredHeld',
    values: { id, n: Number(raw) } }
}
export function aggregateTop(flows: Row[], field: string, n = 10) {
  const map = new Map<string, number>(), total = flows.reduce((sum, f) => sum + (f.packets || 0), 0)
  for (const f of flows) map.set(String(f[field]), (map.get(String(f[field])) ?? 0) + (f.packets || 0))
  return [...map].sort((a, b) => b[1] - a[1]).slice(0, n)
    .map(([key, value]) => ({ key, pct: total > 0 ? (value / total * 100).toFixed(1) : '0' }))
}
export const protoName = (n: number) => ({ 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE',
  50: 'ESP', 58: 'ICMPv6' }[n] ?? n)
export const formatTCPFlags = (flags: number, protocol = 6) => protocol !== 6 ? '-'
  : ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'].filter((_, i) => flags & 1 << i).join(' ') || '...'
export function formattedJSON(raw: string) {
  if (!raw) return '—'
  try { return JSON.stringify(JSON.parse(raw), null, 2) } catch { return raw }
}
export const delaySeconds = (row: Row, now: number) => row.delay_started_at
  ? (Date.parse(row.delay_started_at) + row.delay_minutes * 60000 - now) / 1000 : 0
export function connectorName(executions: Row[], row: Row, type: string) {
  return executions.find(e => e.action_type === type && e.connector_id === row.connector_id
    && (type !== 'xdrop' || e.action_id === row.action_id) && e.connector_name)?.connector_name
    || '#' + row.connector_id
}
export const activeMitigations = (summary: Row) => [...(summary.xdrop_rules ?? []),
  ...(summary.bgp_announcements ?? []).map((b: Row) => b.announcement)]
  .some(row => ['active', 'delayed'].includes(row.status))

export function actionKey(row: Row) {
  if (row.action_type === 'manual_override') return 'manual_override'
  if (row.trigger_phase === 'on_expired' && row.action_type === 'bgp') return 'bgp_withdraw'
  if (row.trigger_phase === 'on_expired' && row.action_type === 'xdrop') return 'xdrop_unblock'
  return row.action_type
}
export const phaseKey = (phase: string) => phase === 'manual_override' ? 'manual' : phase
