import { state } from './state'

const scaled = (n: number, units: string[], digits: number) => {
  if (!Number.isFinite(n)) return '—'
  const slot = Math.min(units.length - 1, Math.max(0, Math.floor(Math.log10(Math.abs(n) || 1) / 3)))
  return (n / 1000 ** slot).toFixed(slot ? digits : 0) + units[slot]
}

export const pps = (n: number) => scaled(n, ['', 'K', 'M', 'G', 'T'], 2)
export const bps = (n: number) => scaled(n, [' bps', ' Kbps', ' Mbps', ' Gbps', ' Tbps'], 2)
export const thousands = (n: number) => new Intl.NumberFormat(state.locale).format(n)

// Configuration pages use whole K and one decimal M/G/T, unlike traffic metrics.
export function dtRate(n: number) {
  if (!Number.isFinite(n)) return '—'
  const absolute = Math.abs(n)
  if (absolute < 1000) return String(n)
  const units = ['T', 'G', 'M', 'K']
  const divisors = [1e12, 1e9, 1e6, 1e3]
  let index = divisors.findIndex(divisor => absolute >= divisor)
  let value = (absolute / divisors[index]!).toFixed(index === 3 ? 0 : 1)
  if (Number(value) >= 1000 && index > 0) {
    index--
    value = (absolute / divisors[index]!).toFixed(index === 3 ? 0 : 1)
  }
  return (n < 0 ? '-' : '') + value + units[index]
}

export function duration(seconds: number) {
  if (!Number.isFinite(seconds)) return '—'
  const n = Math.max(0, Math.floor(seconds))
  const d = Math.floor(n / 86400)
  const h = Math.floor(n % 86400 / 3600)
  const m = Math.floor(n % 3600 / 60)
  return [d ? `${d}d` : '', h ? `${h}h` : '', m ? `${m}m` : '', !d && !h ? `${n % 60}s` : '']
    .filter(Boolean)
    .join(' ')
}

export function relativeTime(time: string | number, now = Date.now()) {
  const delta = (new Date(time).getTime() - now) / 1000
  if (!Number.isFinite(delta)) return '—'
  const unit = Math.abs(delta) >= 86400
    ? 'day'
    : Math.abs(delta) >= 3600
      ? 'hour'
      : Math.abs(delta) >= 60 ? 'minute' : 'second'
  const divisor = { day: 86400, hour: 3600, minute: 60, second: 1 }[unit]
  return new Intl.RelativeTimeFormat(state.locale, { numeric: 'auto' }).format(Math.round(delta / divisor), unit)
}

export function fullDateTime(iso: string) {
  const d = new Date(iso), pad = (n: number) => String(n).padStart(2, '0')
  if (!Number.isFinite(d.getTime())) return '—'
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
    + ` ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
export const dateTime = (iso: string) => fullDateTime(iso).slice(5)
export function bytes1024(n: number) {
  if (!Number.isFinite(n)) return '—'
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' K'
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' M'
  return (n / 1073741824).toFixed(2) + ' G'
}
