import { request } from '../../api/client'

export interface Listener {
  id: number
  node_id: string
  listen_address: string
  protocol_mode: string
  description: string
  enabled: boolean
}
export interface Source {
  id: number
  listener_id: number
  name: string
  device_ip: string
  sample_mode: string
  sample_rate: number
  description: string
  enabled: boolean
}
export interface FlowNode { id: string; mode: string; online: boolean }
export interface FlowStatus {
  online: boolean
  uptime_seconds?: number
  flow_metrics?: { decode_errors: number; unknown_exporter: number; template_misses: number }
  listener_statuses?: { listen_addr: string; records_decoded: number }[]
  source_statuses?: { device_ip: string; active: boolean }[]
}
export interface Detail { listener: Listener; sources: Source[] }
export type ListenerForm = Omit<Listener, 'id'> & { toggle?: boolean }
export type SourceForm = Omit<Source, 'id' | 'listener_id'> & { toggle?: boolean }
export const withoutPrefix = (ip: string) => ip.replace(/\/\d+$/, '')
export const rawError = (error: unknown) => error instanceof Error ? error.message : String(error)
export function listenerForm(node: string, row?: Listener): ListenerForm {
  return { node_id: node, listen_address: row?.listen_address ?? '', protocol_mode: row?.protocol_mode ?? 'auto',
    description: row?.description ?? '', enabled: row?.enabled ?? true }
}
export function sourceForm(row?: Source): SourceForm {
  return { name: row?.name ?? '', device_ip: withoutPrefix(row?.device_ip ?? ''),
    sample_mode: row?.sample_mode ?? 'auto', sample_rate: row?.sample_rate || 1000,
    description: row?.description ?? '', enabled: row?.enabled ?? true }
}
export function listenerBody(form: ListenerForm, row?: Listener) {
  const fields = { listen_address: form.toggle ? row!.listen_address : form.listen_address.trim(),
    protocol_mode: form.toggle ? row!.protocol_mode : form.protocol_mode,
    description: form.toggle ? row!.description : form.description }
  return row ? { ...fields, enabled: form.enabled } : { node_id: form.node_id, ...fields }
}
export function sourceBody(form: SourceForm, listenerId: number, row?: Source) {
  const fields = { name: form.toggle ? row!.name : form.name.trim(),
    device_ip: form.toggle ? withoutPrefix(row!.device_ip) : form.device_ip.trim(),
    sample_mode: form.toggle ? row!.sample_mode : form.sample_mode,
    sample_rate: form.toggle ? row!.sample_rate : form.sample_rate,
    description: form.toggle ? row!.description : form.description }
  return row ? { ...fields, enabled: form.enabled } : { listener_id: listenerId, ...fields }
}
export function listenerValidation(form: ListenerForm) {
  return form.listen_address.trim() ? '' : 'flow.needAddress'
}
export function sourceValidation(form: SourceForm) {
  if (!form.name.trim()) return 'flow.needName'
  return form.device_ip.trim() ? '' : 'flow.needIP'
}
export function listenerRecords(row: Listener, status?: FlowStatus) {
  return status?.listener_statuses?.find(s => s.listen_addr === row.listen_address)?.records_decoded
}
export function runtimeIP(raw: string) {
  const ip = withoutPrefix(raw)
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip)
  if (mapped) return mapped[1]!
  const compatible = /^::(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip)
  if (!compatible) return ip
  const h = Number(compatible[1]) * 256 + Number(compatible[2])
  const l = Number(compatible[3]) * 256 + Number(compatible[4])
  if (!h) return l ? '::' + l.toString(16) : '::'
  return '::' + h.toString(16) + ':' + l.toString(16)
}
export function sourceActive(row: Source, status?: FlowStatus) {
  return status?.source_statuses?.find(s => s.device_ip === runtimeIP(row.device_ip))?.active
}
export function records(value: number | undefined) {
  if (value === undefined) return '—'
  if (value >= 1e6) return (value / 1e6).toFixed(1) + 'M'
  if (value >= 1e3) return (value / 1e3).toFixed(1) + 'K'
  return String(value)
}
export function connectionTime(seconds: number) {
  const minutes = Math.floor(seconds / 60)
  const days = Math.floor(minutes / 1440), hours = Math.floor(minutes % 1440 / 60)
  if (days) return `${days}d ${hours}h ${minutes % 60}m`
  if (hours) return `${hours}h ${minutes % 60}m`
  return minutes ? `${minutes}m` : `${seconds}s`
}
export function saveListener(form: ListenerForm, row?: Listener) {
  return request(row ? `/api/flow-listeners/${row.id}` : '/api/flow-listeners', {
    method: row ? 'PUT' : 'POST', body: JSON.stringify(listenerBody(form, row)),
  })
}
export function saveSource(form: SourceForm, listenerId: number, row?: Source) {
  return request(row ? `/api/flow-sources/${row.id}` : '/api/flow-sources', {
    method: row ? 'PUT' : 'POST', body: JSON.stringify(sourceBody(form, listenerId, row)),
  })
}
export const deleteListener = (id: number) => request(`/api/flow-listeners/${id}`, { method: 'DELETE' })
export const deleteSource = (id: number) => request(`/api/flow-sources/${id}`, { method: 'DELETE' })
