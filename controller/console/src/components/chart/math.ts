import { bps, pps } from '../../format'

export interface Point { time: number; values: Record<string, number> }
export interface Band { start: number; end: number | null; target: string; type: string }
export type Window = [number, number]
export function niceStep(value: number) {
  if (!(value > 0)) return 1
  const base = 10 ** Math.floor(Math.log10(value))
  return [1, 2, 5, 10].find(n => n * base >= value)! * base
}
export function mergeBands(bands: Band[], now: number): Window[] {
  const sorted = bands.map(b => [b.start, b.end ?? now] as Window).sort((a, b) => a[0] - b[0])
  const result: Window[] = []
  for (const band of sorted) {
    const last = result.at(-1)
    if (last && band[0] <= last[1]) last[1] = Math.max(last[1], band[1])
    else result.push([...band])
  }
  return result
}
export function assignSlots(selected: string[], previous: Record<string, number> = {}) {
  const result: Record<string, number> = {}
  for (const key of selected.filter(k => k !== 'total')) {
    const slot = previous[key]
    if (slot && slot >= 1 && slot <= 3 && !Object.values(result).includes(slot)) result[key] = slot
  }
  for (const key of selected.filter(k => k !== 'total')) if (!result[key]) {
    const slot = [1, 2, 3].find(n => !Object.values(result).includes(n))
    if (slot) result[key] = slot
  }
  return result
}
export function downsample<T>(points: T[], cap = 360): T[] {
  if (points.length <= cap) return points
  return Array.from({ length: cap }, (_, i) => points[Math.round(i * (points.length - 1) / (cap - 1))]!)
}
export function segments(points: Point[], grain: number, cap = 360): Point[][] {
  const groups: Point[][] = []
  for (const point of points) {
    const last = groups.at(-1)
    if (last && point.time - last.at(-1)!.time <= 2 * grain) last.push(point)
    else groups.push([point])
  }
  return groups.map(group => downsample(group, cap))
}
export function zoomWindow(window: Window, bounds: Window, shift = 0): Window {
  const width = Math.min(window[1] - window[0], bounds[1] - bounds[0])
  const start = Math.max(bounds[0], Math.min(bounds[1] - width, window[0] + shift * width))
  return [start, start + width]
}
export function formatTick(value: number, metric: string) {
  const text = metric === 'bps' ? bps(value) : pps(value)
  return text.replace(' bps', '').replace(' Kbps', 'k').replace(' Mbps', 'M')
    .replace(' Gbps', 'G').replace(' Tbps', 'T').replace('K', 'k').replace('.00', '')
}
export function nearest(points: Point[], time: number) {
  return points.reduce<Point | undefined>((a, p) => !a || Math.abs(p.time - time) < Math.abs(a.time - time) ? p : a,
    undefined)
}
export function maximum(points: Point[], selected: string[]) {
  return points.reduce((max, p) => Math.max(max, ...selected.map(key => p.values[key] ?? 0)), 0)
}
export const lineColor = (key: string, slots: Record<string, number>) =>
  key === 'total' ? 'var(--dec-total)' : `var(--dec-slot-${slots[key] || 1})`
