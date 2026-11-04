import { request } from '../../api/client'

export const methods = ['POST', 'PUT', 'PATCH'] as const
export const kinds = ['bgp', 'xdrop', 'webhook', 'shell'] as const
export type Kind = typeof kinds[number]
export type TestKind = Exclude<Kind, 'shell'>
export const kindName: Record<Kind, string> = { bgp: 'BGP', xdrop: 'XDrop', webhook: 'Webhook', shell: 'Shell' }
export const vendors = ['frr', 'cisco_xr', 'juniper', 'arista'] as const
export type Vendor = typeof vendors[number]
export const vendorName: Record<Vendor, string> = {
  frr: 'FRR', cisco_xr: 'Cisco IOS XR', juniper: 'Juniper Junos', arista: 'Arista EOS',
}
interface CommonRow {
  id: number
  name: string
  enabled: boolean
  created_at: string
  updated_at: string
}
export interface BGPRow extends CommonRow {
  bgp_asn: number
  vtysh_path: string
  description: string
  address_family: string
  vendor: string
  flowspec_enabled: boolean
}
export interface XDropRow extends CommonRow {
  api_url: string
  api_key: string
  timeout_ms: number
}
export interface WebhookRow extends CommonRow {
  url: string
  method: string
  headers: Record<string, string> | null
  timeout_ms: number
  global: boolean
}
export interface ShellRow extends CommonRow {
  command: string
  default_args: string
  timeout_ms: number
  pass_stdin: boolean
}
export type ConnectorRow = BGPRow | XDropRow | WebhookRow | ShellRow
export interface LegacyRow { id: number; url: string; events: string[]; enabled: boolean }
export interface Form {
  name: string
  bgp_asn: number
  vtysh_path: string
  description: string
  vendor: string
  flowspec_enabled: boolean
  api_url: string
  api_key: string
  url: string
  method: string
  headers: string
  timeout_ms: number
  global: boolean
  command: string
  default_args: string
  enabled: boolean
}
export const timeoutMax = (kind: Kind) => kind === 'webhook' ? 10000 : 30000
export const normalizeURL = (value: string) => value.trim().replace(/\/+$/, '')
const objectHeaders = (value: unknown): value is Record<string, string> => !!value
  && typeof value === 'object' && !Array.isArray(value)
  && Object.values(value).every(v => typeof v === 'string')
export function fillForm(kind: Kind, row?: ConnectorRow): Form {
  const form: Form = {
    name: '', bgp_asn: 65000, vtysh_path: '/usr/bin/vtysh', description: '',
    vendor: 'frr', flowspec_enabled: false, api_url: '', api_key: '',
    url: '', method: methods[0], headers: '', timeout_ms: kind === 'shell' ? 30000 : 10000,
    global: false, command: '', default_args: '', enabled: true,
  }
  if (!row) return form
  form.name = row.name
  form.enabled = row.enabled
  if (kind === 'bgp') {
    const bgp = row as BGPRow
    form.bgp_asn = bgp.bgp_asn
    form.vtysh_path = bgp.vtysh_path
    form.description = bgp.description
    form.vendor = bgp.vendor || 'frr'
    form.flowspec_enabled = bgp.flowspec_enabled === true
  } else {
    const timed = row as XDropRow | WebhookRow | ShellRow
    form.timeout_ms = timed.timeout_ms > 0 ? Math.min(timed.timeout_ms, timeoutMax(kind)) : form.timeout_ms
    if (kind === 'xdrop') form.api_url = (row as XDropRow).api_url
    if (kind === 'webhook') {
      const hook = row as WebhookRow
      form.url = hook.url
      form.method = hook.method
      form.global = hook.global
      form.headers = objectHeaders(hook.headers) ? JSON.stringify(hook.headers, null, 2) : ''
    }
    if (kind === 'shell') {
      form.command = (row as ShellRow).command
      form.default_args = (row as ShellRow).default_args
    }
  }
  return form
}
export interface Message { key: string; args?: Record<string, string | number> }
export function connectorCheck(kind: Kind, form: Form, row?: ConnectorRow): Message | undefined {
  const error = (key: string, args?: Message['args']) => ({ key, args })
  if (!form.name.trim()) return error(kind === 'shell' ? 'shellNameRequired' : 'nameRequired')
  if (kind === 'bgp' && form.vendor === 'frr' && !form.vtysh_path.trim()) return error('vtyshRequired')
  if (kind === 'bgp' && form.vendor !== 'frr' && !form.flowspec_enabled) {
    return error('vendorNeedsFlowspec', { vendor: vendorName[form.vendor as Vendor] ?? form.vendor })
  }
  if (kind === 'xdrop') {
    if (!normalizeURL(form.api_url)) return error('apiUrlRequired')
    if (!row && !form.api_key.trim()) return error('apiKeyRequired')
    if (row && normalizeURL(form.api_url) !== (row as XDropRow).api_url && !form.api_key.trim()) {
      return error('keyChanged')
    }
  }
  if (kind === 'webhook') {
    if (!form.url.trim()) return error('urlRequired')
    let headers: Record<string, string> = {}
    try {
      if (form.headers.trim()) headers = JSON.parse(form.headers)
      if (!objectHeaders(headers)) return error('headersInvalid')
    } catch { return error('headersInvalid') }
    const hook = row as WebhookRow | undefined
    if (hook && form.url.trim() !== hook.url && Object.values(headers).includes('******')) {
      return error('headersChanged')
    }
    if (hook) for (const [key, value] of Object.entries(headers)) {
      if (value === '******' && !Object.hasOwn(hook.headers ?? {}, key)) return error('headerMissing', { key })
    }
  }
  if (kind === 'shell' && !form.command.trim().startsWith('/')) return error('commandValidation')
}
export function connectorBody(kind: Kind, form: Form, row?: ConnectorRow): Record<string, unknown> {
  const name = form.name.trim()
  if (kind === 'bgp') return {
    name, bgp_asn: form.bgp_asn, vtysh_path: form.vtysh_path.trim(),
    description: form.description, vendor: form.vendor, flowspec_enabled: form.flowspec_enabled,
    enabled: form.enabled,
  }
  const edit = row ? { enabled: form.enabled } : {}
  if (kind === 'xdrop') return {
    name, api_url: normalizeURL(form.api_url), timeout_ms: form.timeout_ms, ...edit,
    ...(!row || form.api_key.trim() ? { api_key: form.api_key.trim() } : {}),
  }
  if (kind === 'webhook') return {
    name, url: form.url.trim(), method: form.method, headers: form.headers.trim() ? JSON.parse(form.headers) : {},
    timeout_ms: form.timeout_ms, global: form.global, ...edit,
  }
  return { name, command: form.command.trim(), default_args: form.default_args.trim(),
    timeout_ms: form.timeout_ms, ...edit }
}
export function deletionHint(raw: string): string {
  if (raw.includes('action(s)')) return 'inUseActions'
  if (raw.includes('active rules') || raw.includes('announcements')) return 'inUseRules'
  return ''
}
export interface ProbeReply { success?: boolean; ok?: boolean; status_code?: number; error?: string;
  name?: string; kind?: string; output?: string }
export interface ProbeResult extends Message { ok: boolean; detail: string }
export function testResult(kind: TestKind, reply?: ProbeReply, error?: string): ProbeResult {
  const failKey = kind + 'TestFailed'
  if (error !== undefined) return { ok: false, key: failKey, detail: error }
  if (kind === 'bgp') return { ok: reply?.ok === true, key: reply?.ok ? 'connectionOk' : failKey,
    detail: reply?.output ?? reply?.error ?? '' }
  if (kind === 'xdrop') return { ok: reply?.success === true, key: reply?.success ? 'xdropTestSuccess' : failKey,
    args: { name: reply?.name ?? '' }, detail: reply?.success ? '' : reply?.error ?? '' }
  return { ok: reply?.success === true, key: reply?.success ? 'webhookSuccessHTTP' : failKey,
    args: { status: reply?.status_code ?? '' },
    detail: reply?.success ? '' : reply?.error
      ?? (reply?.status_code === undefined ? '' : `HTTP ${reply.status_code}`) }
}

export function saveConnector(kind: Kind, form: Form, row?: ConnectorRow) {
  return request(`/api/settings/${kind}-connectors${row ? '/' + row.id : ''}`, {
    method: row ? 'PUT' : 'POST', body: JSON.stringify(connectorBody(kind, form, row)),
  })
}
