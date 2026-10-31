import { dtRate } from '../../format'
import type { Row } from '../thresholds/data'
export function slotLabel(raw: string, t: (key: string) => string) {
  const match = /^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday) (\d{2}):00 UTC( \(latest\))?$/.exec(raw)
  return match ? `${t('baseline.weekday.' + match[1])} ${match[2]}:00 UTC`
    + (match[3] ? t('baseline.latestSlot') : '') : raw
}
export const defaultConfig = { enabled: false, deviation_min: 100, deviation_max: 200, stable_weeks: 4,
  min_pps: 100000, min_bps: 1000000000, ewma_alpha: 0.30 }
export function configBody(form: typeof defaultConfig) {
  return { enabled: form.enabled, deviation_min: form.deviation_min, deviation_max: form.deviation_max,
    stable_weeks: form.stable_weeks, min_pps: form.min_pps, min_bps: form.min_bps, ewma_alpha: form.ewma_alpha }
}
export function profiles(rows: Row[] | null) {
  return [...(rows ?? [])].sort((a, b) => a.prefix < b.prefix ? -1 : a.prefix > b.prefix ? 1 : 0)
}
export function exceededValues(row: Row) {
  return { pps: dtRate(row.current_pps), bps: dtRate(row.current_bps),
    tpps: dtRate(row.thresh_pps), tbps: dtRate(row.thresh_bps) }
}
export const fields = [
  { key: 'deviation_max', min: 50, max: 500, digits: 0 },
  { key: 'deviation_min', min: 10, max: 500, digits: 0 },
  { key: 'stable_weeks', min: 1, max: 12, digits: 0 },
  { key: 'min_pps', min: 0, max: Infinity, digits: 0 },
  { key: 'min_bps', min: 0, max: Infinity, digits: 0 },
  { key: 'ewma_alpha', min: 0.01, max: 0.99, digits: 2 },
] as const
