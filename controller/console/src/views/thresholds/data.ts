import { DECODERS } from '../../config/decoders'
import { dtRate } from '../../format'
export type Row = Record<string, any>
export const decoderOptions = ['ip', ...DECODERS.filter(d => d.key !== 'total').map(d => d.key)]
  .map(value => ({ value, label: value }))
export const options = (values: string[]) => values.map(value => ({ value, label: value }))
export const numericID = (value: string) => value === '' ? null : Number(value)
export function globalTemplate(prefixes: Row[]) {
  return prefixes.some(p => p.prefix === '0.0.0.0/0')
}
export function ruleForm(global = false, row?: Row) {
  return { domain: row ? row.domain || 'internal_ip' : global ? 'subnet' : 'internal_ip',
    direction: row?.direction ?? 'receives',
    decoder: row?.decoder ?? 'tcp_syn', unit: row?.unit ?? 'pps', comparison: row?.comparison ?? 'over',
    value: row?.value ?? 500, inheritable: row?.inheritable !== false }
}
export function changeUnit(form: Row, unit: string) {
  if (unit === form.unit) return
  if (unit === 'pct') form.value = 100
  else if (form.unit === 'pct') form.value = 500
  form.unit = unit
}
export function zeroHint(form: Row) {
  return form.value === 0 && form.comparison === 'over'
}
export function ruleBody(form: Row) {
  return { domain: form.domain, direction: form.direction, decoder: form.decoder, unit: form.unit,
    comparison: form.comparison, value: form.value, inheritable: form.inheritable }
}
export function flatBody(form: Row) {
  return { prefix_id: form.prefix_id, ...ruleBody({ ...form, direction: 'receives' }) }
}
export function pctError(form: Row, warning: string) {
  return form.unit === 'pct' && (form.value < 1 || form.value > 100) ? warning : ''
}
export function recommendation(rule: Row, prefixes: Row[], baselines: Row[]) {
  if (rule.direction === 'sends') return { text: '—', tip: 'templates.recommendInboundOnly' }
  if (rule.decoder && rule.decoder !== 'ip') return { key: 'templates.prefixLevel' }
  const bound = new Set(prefixes.map(p => p.prefix))
  const values = baselines.filter(b => bound.has(b.prefix) && b.active)
    .map(b => b[rule.unit === 'bps' ? 'recommend_bps' : 'recommend_pps']).filter(v => v > 0)
  if (!values.length) return { text: '⏳', tip: 'templates.waitBaseline' }
  const min = Math.min(...values), max = Math.max(...values)
  return { text: '→ ' + dtRate(min) + (values.length === 1 ? '' : '–' + dtRate(max)) }
}
