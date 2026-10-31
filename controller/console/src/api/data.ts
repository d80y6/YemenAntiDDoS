import { ref, shallowRef, watch, onUnmounted } from 'vue'
import { request } from './client'
import { usePoll } from '../composables/usePoll'
import { DECODERS } from '../config/decoders'
import type { Point } from '../components/chart/math'
export type RawPoint = Record<string, unknown> & { time: string }
export interface Attack extends Record<string, unknown> {
  decoder_family: string; severity: string; confidence: number; reason_codes: string[] | null
  node_sources: string[] | null; template_name?: string; rule_summary?: string
  response_id: number | null; threshold_rule_id: number | null; prefix_id: number | null
  id: number; dst_ip: string; direction: string; attack_type: string
  started_at: string; ended_at: string | null; peak_pps: number; peak_bps: number
}
export interface Brief {
  xdrop_rules: { status: string; external_rule_id: string; scheduled_for?: string }[] | null
  bgp: { status: string; prefix: string; route_map: string; attached_at: string;
    detached_at?: string; delay_minutes: number }[] | null
}
export interface Timer {
  state: string; expires_in: number; threshold_value?: number; threshold_unit?: string
}
export interface Active {
  timers: Record<string, Timer>; active_count: number; returned: number
  attacks: Attack[] | null; current?: Record<string, { pps: number; bps: number }>
}
export const query = (values: Record<string, string | number>) => new URLSearchParams(
  Object.entries(values).filter(([, v]) => v !== '').map(([k, v]) => [k, String(v)]),
).toString()
export const api = <T>(path: string, values: Record<string, string | number> = {}, signal?: AbortSignal) => {
  signal?.throwIfAborted()
  return request<T>(`/api/${path}?${query(values)}`, { signal })
}
export async function briefs(ids: number[], signal?: AbortSignal) {
  const unique = [...new Set(ids)]
  const result: Record<string, Brief> = {}
  for (let offset = 0; offset < unique.length; offset += 50) {
    Object.assign(result, await api<Record<string, Brief>>('attacks/mitigation-brief', {
      ids: unique.slice(offset, offset + 50).join(','),
    }, signal))
  }
  return result
}
export function normalize(points: RawPoint[] | null, metric: string): Point[] {
  return (points ?? []).map(point => ({ time: Date.parse(point.time), values: Object.fromEntries(DECODERS.map(d => {
    const value = point[metric === 'bps' ? d.bpsField : d.ppsField]
    return [d.key, Number(d.extraKey ? (value as Record<string, number> | undefined)?.[d.extraKey] ?? 0 : value ?? 0)]
  })) })).sort((a, b) => a.time - b.time)
}
// Poll registrations are synchronous. Only accept applies results, including errors and successful timestamps.
export function resource<T>(initial: T, ms: number, key: () => string, fetcher: (signal: AbortSignal) => Promise<T>,
  interval: () => number = () => 0) {
  const data = shallowRef(initial), error = ref(''), loading = ref(true), updated = ref(0)
  const lifetime = new AbortController()
  onUnmounted(() => lifetime.abort())
  let last: string | null = null, lastAt = 0, generation = 0
  const poll = usePoll(async () => {
    const snapshot = key(), now = Date.now(), seq = generation
    if (snapshot === last && now - lastAt < interval()) return { snapshot, now, seq, idle: true }
    try { return { snapshot, now, seq, value: await fetcher(lifetime.signal), error: '' } }
    catch (e) { return { snapshot, now, seq, error: e instanceof Error ? e.message : String(e) } }
  }, ms, result => {
    if (result.snapshot !== key() || result.seq !== generation) { queueMicrotask(() => void poll.refresh()); return }
    if ('idle' in result) return
    loading.value = false
    error.value = result.error
    if ('value' in result) {
      data.value = result.value as T
      updated.value = Date.now()
      last = result.snapshot
      lastAt = result.now
    }
  })
  watch(key, () => {
    generation++
    last = null
    loading.value = true
    void poll.refresh()
  })
  return { data, error, loading, updated, refresh: poll.refresh }
}
function cidr(raw: string): { family: number; bits: number; value: bigint } | null {
  const [ip = '', mask] = raw.split('/')
  if (ip.includes(':')) {
    let text = ip
    if (text.includes('.')) {
      const last = text.slice(text.lastIndexOf(':') + 1).split('.').map(Number)
      if (last.length !== 4 || last.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null
      text = text.slice(0, text.lastIndexOf(':') + 1) + ((last[0]! << 8) + last[1]!).toString(16)
        + ':' + ((last[2]! << 8) + last[3]!).toString(16)
    }
    const sides = text.split('::')
    if (sides.length > 2) return null
    const left = sides[0] ? sides[0].split(':') : [], right = sides[1] ? sides[1].split(':') : []
    const words = sides.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left
    if (words.length !== 8 || words.some(w => !/^[0-9a-f]{1,4}$/i.test(w))) return null
    const bits = mask === undefined ? 128 : Number(mask)
    return Number.isInteger(bits) && bits >= 0 && bits <= 128
      ? { family: 128, bits, value: words.reduce((n, w) => n * 65536n + BigInt(parseInt(w, 16)), 0n) } : null
  }
  const words = ip.split('.').map(Number), bits = mask === undefined ? 32 : Number(mask)
  if (words.length !== 4 || words.some(n => !Number.isInteger(n) || n < 0 || n > 255)
    || !Number.isInteger(bits) || bits < 0 || bits > 32) return null
  return { family: 32, bits, value: words.reduce((n, w) => n * 256n + BigInt(w), 0n) }
}
export function containsCIDR(target: string, prefix: string) {
  try {
    const a = cidr(target), b = cidr(prefix)
    return !!a && !!b && a.family === b.family && a.bits >= b.bits
      && a.value >> BigInt(a.family - b.bits) === b.value >> BigInt(b.family - b.bits)
  } catch { return false }
}
