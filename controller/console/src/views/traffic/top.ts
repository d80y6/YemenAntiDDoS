import type { Overview, PrefixTraffic } from '../overview/data'
export interface TopRow extends Record<string, unknown> {
  prefix: string; incoming?: PrefixTraffic; outgoing?: PrefixTraffic
}
export function topRows(incoming: Overview, outgoing: Overview): TopRow[] {
  const rows = new Map<string, TopRow>()
  for (const p of incoming.top_prefixes ?? []) rows.set(p.prefix, { prefix: p.prefix, incoming: p })
  for (const p of outgoing.top_prefixes ?? []) {
    const row = rows.get(p.prefix) || { prefix: p.prefix }
    row.outgoing = p
    rows.set(p.prefix, row)
  }
  return [...rows.values()]
}
export function topValue(row: TopRow, column: string, metric: string) {
  const [side, field = 'pps'] = column.split(':')
  const source = side === 'out' ? row.outgoing : row.incoming
  return source?.[field === 'tcp' || field === 'udp' || field === 'icmp' ? `${field}_${metric}` : field] as
    number | undefined
}
export function sortTop(rows: TopRow[], column: string, metric: string, direction: string) {
  return [...rows].sort((a, b) => {
    const x = topValue(a, column, metric), y = topValue(b, column, metric)
    if (x === undefined) return y === undefined ? 0 : 1
    if (y === undefined) return -1
    return (x - y) * (direction === 'ascending' ? 1 : -1)
  })
}
