// @ts-expect-error Native Node contract runner requires the explicit .ts extension.
import { cidrText } from './cidr.ts'

// Go ParseIP acceptance, calibrated only against the sealed inet corpus.
export function inetText(raw: string): string | null {
  if (raw.includes('/') || raw.includes('%')) return null
  if (!raw.includes(':')) {
    const parts = raw.split('.')
    if (parts.length !== 4 || parts.some(p => !/^(0|[1-9]\d{0,2})$/.test(p) || Number(p) > 255)) return null
    return raw + '/32'
  }
  return cidrText(raw) ?? null
}
