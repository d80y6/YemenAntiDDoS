import { computed, ref, watch, type Ref } from 'vue'
import { api, resource, briefs, containsCIDR, type Attack, type Active, type Brief } from '../../api/data'
import { isSyntheticRuleId } from '../../api/xdropRules'
import type { Point, Band, Window } from '../../components/chart/math'
export interface NodeInfo extends Record<string, unknown> {
  id: string; description: string; mode: string; online: boolean; last_stats_at?: string
  delivery_version_current: number; delivery_version_applied: number
}
export interface PrefixInfo { prefix: string; name: string }
export interface PrefixTraffic extends Record<string, unknown> {
  prefix: string; pps: number; bps: number; tcp_pps: number; udp_pps: number; icmp_pps: number
  tcp_bps: number; udp_bps: number; icmp_bps: number; nodes: { id: string; mode: string }[]
}
export interface Overview {
  total_pps: number; total_bps: number; node_count: number; active_prefixes: number
  top_prefixes: PrefixTraffic[] | null; nodes: { id: string; pps: number; bps: number }[] | null
}
export interface Action { status: string; external_rule_id: string }
export interface Summary { active_attacks: number; total_nodes: number; online_nodes: number }
export type RawPoint = Record<string, unknown> & { time: string }
export const emptyOverview = (): Overview => ({ total_pps: 0, total_bps: 0, node_count: 0,
  active_prefixes: 0, top_prefixes: [], nodes: [] })
export async function allAttacks(params: Record<string, string | number>, signal?: AbortSignal) {
  const rows: Attack[] = []
  let offset = 0, total = 0, capped = false
  for (let page = 0; page < 10; page++) {
    const result = await api<{ attacks: Attack[] | null; total: number }>('attacks',
      { ...params, limit: 200, offset }, signal)
    const raw = result.attacks ?? []
    rows.push(...raw)
    total = result.total
    offset += raw.length
    if (!raw.length || offset >= total) break
    if (page === 9) capped = true
  }
  return { rows: [...new Map(rows.map(a => [a.id, a])).values()], capped }
}
export const hours = (range: string) => ({ '15m': .25, '1h': 1, '6h': 6, '24h': 24 }[range] ?? 1)
export const grain = (range: string) => hours(range) <= 1 ? 5000 : 300000
export const curveInterval = (range: string) => hours(range) <= 1 ? 10000 : 60000
export interface Filters { range: string; node: string; prefix: string; direction: string; limit: string }
export function useData(filters: Filters, overview = false) {
  const key = () => JSON.stringify(filters)
  const nodes = resource<NodeInfo[]>([], 10000, () => '',
    async signal => (await api<NodeInfo[] | null>('nodes', {}, signal)) ?? [])
  const prefixes = resource<PrefixInfo[]>([], 2147483647, () => '',
    async signal => (await api<PrefixInfo[] | null>('prefixes', {}, signal)) ?? [], () => Infinity)
  const fast = resource({ summary: { active_attacks: 0, total_nodes: 0, online_nodes: 0 } as Summary,
    incoming: emptyOverview(), outgoing: emptyOverview(), both: emptyOverview(), 
    active: { attacks: [], timers: {}, active_count: 0, returned: 0 } as Active,
    bgp: [] as Action[], xdrop: [] as Action[], brief: {} as Record<string, Brief> }, 5000, key, async signal => {
    const common = { node_id: filters.node, limit: overview ? 5 : filters.limit }
    const [summary, incoming, outgoing, both, active, bgp, xdrop] = await Promise.all([
      api<Summary>('stats/summary', {}, signal),
      api<Overview>('stats/overview', { ...common, direction: 'receives' }, signal),
      overview ? emptyOverview() : api<Overview>('stats/overview', { ...common, direction: 'sends' }, signal),
      !overview && filters.direction === 'both'
        ? api<Overview>('stats/overview', { ...common, direction: 'both' }, signal)
        : emptyOverview(),
      api<Active>('attacks/active', {}, signal), overview ? api<Action[] | null>('active-actions/bgp', {}, signal) : [],
      overview ? api<Action[] | null>('active-actions/xdrop', {}, signal) : [],
    ])
    const activeRows = active.attacks ?? []
    return { summary, incoming, outgoing, both, active: { ...active, attacks: activeRows }, bgp: bgp ?? [],
      xdrop: xdrop ?? [], brief: overview ? await briefs(activeRows.map(a => a.id), signal) : {} }
  })
  const history = resource({ expired: [] as Attack[], overlap: [] as Attack[], brief: {} as Record<string, Brief>,
    tableCapped: false, bandCapped: false }, 60000, key, async signal => {
    const now = Date.now(), to = new Date(now).toISOString()
    const overlap = await allAttacks({ direction: 'receives', dst_ip: filters.prefix, to,
      ended_after: new Date(now - hours(filters.range) * 3600000).toISOString() }, signal)
    const expired = overview ? await allAttacks({ status: 'expired',
      ended_after: new Date(now - 86400000).toISOString() }, signal) : { rows: [], capped: false }
    return { expired: expired.rows, overlap: overlap.rows, brief: await briefs(expired.rows.map(a => a.id), signal),
      tableCapped: expired.capped, bandCapped: overlap.capped }
  })
  const curves = resource({ incoming: [] as RawPoint[], outgoing: [] as RawPoint[],
    bounds: [Date.now() - hours(filters.range) * 3600000, Date.now()] as Window }, 10000, key, async signal => {
    const now = Date.now(), start = now - hours(filters.range) * 3600000
    const params = { from: new Date(start).toISOString(), to: new Date(now).toISOString(),
      resolution: grain(filters.range) === 5000 ? '5s' : '5min', include_extras: 'true',
      node_id: filters.node, prefix: filters.prefix }
    const [incoming, outgoing] = await Promise.all([
      filters.direction === 'sends' ? [] : api<RawPoint[] | null>('stats/total-timeseries',
        { ...params, direction: 'receives' }, signal),
      overview || filters.direction === 'receives' ? [] : api<RawPoint[] | null>('stats/total-timeseries',
        { ...params, direction: 'sends' }, signal),
    ])
    return { incoming: incoming ?? [], outgoing: outgoing ?? [], bounds: [start, now] as Window }
  }, () => curveInterval(filters.range))
  const bands = computed<Band[]>(() => [...new Map([
    ...history.data.value.overlap, ...(fast.data.value.active.attacks ?? []),
  ].map(a => [a.id, a])).values()].filter(a => a.direction === 'receives'
    && (!filters.prefix || containsCIDR(a.dst_ip, filters.prefix)))
    .map(a => ({ start: Date.parse(a.started_at), end: a.ended_at ? Date.parse(a.ended_at) : null,
      target: a.dst_ip, type: a.attack_type })))
  const updated = computed(() => Math.max(fast.updated.value, nodes.updated.value, curves.updated.value,
    history.updated.value, prefixes.updated.value))
  return { nodes, prefixes, fast, history, curves, bands, updated }
}
export function held(rows: Action[], xdrop = false) {
  return rows.filter(a => ['active', 'delayed'].includes(a.status)
    && (!xdrop || !isSyntheticRuleId(a.external_rule_id)))
}
export function attackRate(attack: Attack, active: Active) {
  return attack.ended_at ? attack.peak_pps : active.current?.[String(attack.id)]?.pps
}
export function useZoom(range: Ref<string>) {
  const window = ref<Window | null>(null)
  watch(range, () => { window.value = null })
  return window
}
