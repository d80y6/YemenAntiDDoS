import type { Row, Translate } from '../mitigations/data'
export function generateKey() {
  return [...crypto.getRandomValues(new Uint8Array(32))].map(n => n.toString(16).padStart(2, '0')).join('')
}
export const validNodeId = (id: string) => !id.includes('/') && id !== '.' && id !== '..'
export function snippet(id: string, key: string, mode: string, t: Translate) {
  return (mode === 'flow' ? 'mode: flow\n' : '') + 'node_id: ' + JSON.stringify(id || 'edge-03')
    + '\ncontroller:\n  address: ' + JSON.stringify(t('nodes.addressPlaceholder'))
    + '\nauth:\n  node_api_key: ' + JSON.stringify(key || t('nodes.keyPlaceholder'))
    + '\n' + t(mode === 'flow' ? 'nodes.flowComment' : 'nodes.xdpComment')
}
export function configCell(row: Row, t: Translate) {
  const a = row.delivery_version_applied, c = row.delivery_version_current
  if (row.config_status === 'synced') return { tone: 'ok', text: t('nodes.synced'), tip: t('nodes.syncedTip', { a }) }
  if (row.config_status === 'failed') return { tone: 'crit', text: t('nodes.failed'), tip: t('nodes.failedTip', { c }) }
  return { tone: 'warn', text: t('nodes.pending', { n: c - a }),
    tip: t(row.online ? 'nodes.pendingTip' : 'nodes.offlineTip', { a, c }) }
}
export function captureText(status: Row | undefined, t: Translate) {
  if (status?.capture) return status.capture.map((c: Row) => c.interface + ' · '
    + (c.upstream_sample_rate > 1 ? t('nodes.sampling', { n: c.upstream_sample_rate })
      : t('nodes.noSampling'))).join('\n')
  return status?.interfaces?.join(', ') || '—'
}
export const nodeReadings = (nodes: Row[], readings: Row[]): Row[] => nodes.map(n => ({ ...n,
  reading: readings.find(r => r.id === n.id) }))
