import { dtRate } from '../../format'
import { numericID, type Row } from '../thresholds/data'
export function prefixForm(row?: Row) {
  return { prefix: row?.prefix ?? '', name: row?.name ?? '', ip_group: row?.ip_group ?? '',
    parent_id: String(row?.parent_id ?? ''), threshold_template_id: String(row?.threshold_template_id ?? ''),
    enabled: row?.enabled ?? true }
}
export function prefixBody(form: Row, editing: boolean) {
  const common = { name: form.name, ip_group: form.ip_group, parent_id: numericID(form.parent_id),
    threshold_template_id: numericID(form.threshold_template_id) }
  return editing ? { ...common, enabled: form.enabled } : { prefix: form.prefix.trim(), ...common }
}
export function prefixBaseline(prefix: Row, baselines: Row[]) {
  const baseline = baselines.find(b => b.prefix === prefix.prefix)
  if (!prefix.enabled || !baseline) return { text: '—' }
  if (!baseline.active) return { text: '⏳', tip: 'prefixes.waitBaseline' }
  return { text: 'P95 ' + dtRate(baseline.p95_pps), next: '→ ' + dtRate(baseline.recommend_pps) }
}
