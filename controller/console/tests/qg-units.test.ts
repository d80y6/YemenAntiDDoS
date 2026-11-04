import { expect, it } from 'vitest'
import { connectorBody, connectorCheck, fillForm, deletionHint, testResult } from '../src/views/connectors/data'
import type { Form, Kind, ConnectorRow } from '../src/views/connectors/data'
import { responseSession, fixtureState, mockSession } from '../mock/data'
import { scanArtifacts } from '../scripts/artifact-scan.mjs'
import { root } from '../scripts/lib.mjs'
import { sourceText } from './r1-files.mjs'
import zh from '../src/i18n/ar'
import en from '../src/i18n/en'
const base: Form = { name: '  Edge  ', bgp_asn: 65001, vtysh_path: ' /usr/bin/vtysh ', description: ' memo ',
  vendor: 'arista', flowspec_enabled: true,
  api_url: ' https://xdrop.example.com/api/v1// ', api_key: ' key1234 ', url: ' https://hooks.example.net/notify ',
  method: 'PATCH', headers: '', timeout_ms: 1500, global: true, command: ' /bin/true ',
  default_args: ' --ip {dst_ip} ', enabled: false }
const row = { id: 2, name: 'Old', enabled: false, created_at: 'a', updated_at: 'b',
  api_url: 'https://xdrop.example.com/api/v1', api_key: '***1234', timeout_ms: 500,
  headers: { Authorization: '******' }, url: 'https://hooks.example.net/notify', method: 'PUT', global: true,
  command: '/bin/true', default_args: '--ip {dst_ip}', pass_stdin: true,
  bgp_asn: 4294967295, vtysh_path: '/mock/missing', description: ' old ',
  vendor: 'juniper', flowspec_enabled: true }
const expected: Record<Kind, Record<string, unknown>> = {
  bgp: { name: 'Edge', bgp_asn: 65001, vtysh_path: '/usr/bin/vtysh', description: ' memo ',
    vendor: 'arista', flowspec_enabled: true, enabled: false },
  xdrop: { name: 'Edge', api_url: 'https://xdrop.example.com/api/v1', api_key: 'key1234', timeout_ms: 1500 },
  webhook: { name: 'Edge', url: 'https://hooks.example.net/notify', method: 'PATCH', headers: {},
    timeout_ms: 1500, global: true },
  shell: { name: 'Edge', command: '/bin/true', default_args: '--ip {dst_ip}', timeout_ms: 1500 },
}
it.each(['bgp', 'xdrop', 'webhook', 'shell'] as const)('G-units %s create/edit exact payload W3 W4 W10 W12', kind => {
  expect(connectorBody(kind, base)).toEqual(expected[kind])
  expect(connectorBody(kind, base, row)).toEqual({ ...expected[kind], enabled: false })
  expect(connectorBody(kind, base, row)).not.toHaveProperty('pass_stdin')
  expect(connectorBody(kind, base, row)).not.toHaveProperty('address_family')
})
it('G-units XDrop empty edit key omitted, mask never copied, URL normalized W1 W2', () => {
  const form = { ...base, api_key: '  ' }
  expect(connectorBody('xdrop', form, row)).toEqual({ name: 'Edge',
    api_url: 'https://xdrop.example.com/api/v1', timeout_ms: 1500, enabled: false })
  expect(connectorCheck('xdrop', form, row)).toBeUndefined()
  expect(fillForm('xdrop', row).api_key).toBe('')
})
it('G-units Webhook empty object and unchanged masked edit payload W5 W6', () => {
  expect(connectorBody('webhook', { ...base, headers: '  ' }, row)).toEqual({
    name: 'Edge', url: 'https://hooks.example.net/notify', method: 'PATCH', headers: {},
    timeout_ms: 1500, global: true, enabled: false,
  })
  expect(connectorBody('webhook', { ...base, headers: '{"Authorization":"******","X-ID":"abc"}' }, row))
    .toEqual({ name: 'Edge', url: 'https://hooks.example.net/notify', method: 'PATCH',
      headers: { Authorization: '******', 'X-ID': 'abc' }, timeout_ms: 1500, global: true, enabled: false })
})
it.each([
  ['bgp', { name: ' ', vtysh_path: '' }, 'nameRequired', 'الرجاء إدخال اسم'],
  ['shell', { name: ' ', command: '' }, 'shellNameRequired', 'الاسم مطلوب'],
  ['webhook', { name: ' ', url: '' }, 'nameRequired', 'الرجاء إدخال اسم'],
  ['xdrop', { name: ' ', api_url: '', api_key: '' }, 'nameRequired', 'الرجاء إدخال اسم'],
  ['bgp', { vtysh_path: ' ', vendor: 'frr' }, 'vtyshRequired', 'الرجاء إدخال مسار vtysh'],
  ['bgp', { vendor: 'cisco_xr', flowspec_enabled: false }, 'vendorNeedsFlowspec',
    '{vendor} للتصدير فقط: مكّن BGP Flowspec لهذا الموصّل.'],
  ['xdrop', { api_url: ' /// ', api_key: '' }, 'apiUrlRequired', 'الرجاء إدخال عنوان API'],
  ['xdrop', { api_key: ' ' }, 'apiKeyRequired', 'الرجاء إدخال مفتاح API'],
  ['webhook', { url: ' ', headers: '[' }, 'urlRequired', 'الرجاء إدخال رابط'],
  ['webhook', { headers: '[' }, 'headersInvalid', 'يجب أن تكون الترويسات كائن JSON بقيم نصية.'],
  ['shell', { command: 'relative.sh' }, 'commandValidation', 'يجب أن يبدأ الأمر بـ /'],
])('G-units validation order %s %j', (kind, overrides, key, literal) => {
  const check = connectorCheck(kind as Kind, { ...base, ...overrides })
  expect(check?.key).toBe(key)
  expect((zh.connectors as any)[check!.key]).toBe(literal)
})
it.each(['null', '[]', '123', 'true', '"text"', '{"k":1}', '{"k":null}', '{"k":{}}', '{"k":false}'])(
  'G-units non-string headers %s rejected W8', headers => {
    expect(connectorCheck('webhook', { ...base, headers })?.key).toBe('headersInvalid')
  },
)
it('G-units edit checks URL then mask own keys W2 W7', () => {
  expect(connectorCheck('xdrop', { ...base, api_url: 'https://new.example.com', api_key: '' }, row)?.key)
    .toBe('keyChanged')
  expect(zh.connectors.keyChanged).toBe('تغيّر عنوان API؛ أعد إدخال مفتاح API.')
  const form = { ...base, url: 'https://new.example.com', headers: '{"Missing":"******"}' }
  expect(connectorCheck('webhook', form, row)?.key).toBe('headersChanged')
  expect(zh.connectors.headersChanged).toBe('تغيّر الرابط؛ أعد إدخال قيمة كل ترويسة.')
  for (const key of ['Missing', 'authorization', 'toString', 'constructor', '__proto__']) {
    const result = connectorCheck('webhook', { ...base, headers: `{"${key}":"******"}` }, row)
    expect(result).toEqual({ key: 'headerMissing', args: { key } })
  }
  expect(zh.connectors.headerMissing).toBe('الترويسة {key} ليس لها أصل مخزَّن؛ أدخل قيمتها الحقيقية.')
  expect(connectorCheck('webhook', { ...base, headers: '{"Authorization":"******"}' }, row)).toBeUndefined()
  expect(connectorCheck('webhook', { ...base, url: 'https://new.example.com', headers: '{}' }, row)).toBeUndefined()
  expect(connectorCheck('shell', { ...base, default_args: '{unknown}' })).toBeUndefined()
})
it.each(['bgp', 'xdrop', 'webhook', 'shell'] as const)('G-units %s all default fields and refill', kind => {
  expect(fillForm(kind)).toEqual({ name: '', bgp_asn: 65000, vtysh_path: '/usr/bin/vtysh', description: '',
    vendor: 'frr', flowspec_enabled: false,
    api_url: '', api_key: '', url: '', method: 'POST', headers: '', timeout_ms: kind === 'shell' ? 30000 : 10000,
    global: false, command: '', default_args: '', enabled: true })
  const form = fillForm(kind, row)
  expect(form.name).toBe('Old')
  expect(form.enabled).toBe(false)
  if (kind === 'bgp') expect([form.bgp_asn, form.vtysh_path, form.description, form.vendor, form.flowspec_enabled])
    .toEqual([4294967295, '/mock/missing', ' old ', 'juniper', true])
  if (kind === 'webhook') expect([form.url, form.method, form.headers, form.global])
    .toEqual(['https://hooks.example.net/notify', 'PUT', '{\n  "Authorization": "******"\n}', true])
  if (kind === 'shell') expect([form.command, form.default_args]).toEqual(['/bin/true', '--ip {dst_ip}'])
  if (kind !== 'bgp') expect(form.timeout_ms).toBe(500)
})
it.each(['xdrop', 'webhook', 'shell'] as const)('G-units %s timeout zero/high/normal and null headers', kind => {
  for (const [value, want] of [[0, kind === 'shell' ? 30000 : 10000], [99999, kind === 'webhook' ? 10000 : 30000],
    [1234, 1234]]) expect(fillForm(kind, { ...row, timeout_ms: value! }).timeout_ms).toBe(want)
  for (const headers of [null, 'bad', []]) {
    expect(fillForm('webhook', { ...row, headers } as ConnectorRow).headers).toBe('')
  }
})
it.each([
  ['connector in use by 2 action(s)', 'inUseActions'],
  ['xDrop connector still has active rules', 'inUseRules'],
  ['connector still has 2 announcements in FRR-relevant states', 'inUseRules'],
  ['already exists', ''],
])('G-units 409 classification %s W16', (raw, key) => expect(deletionHint(raw)).toBe(key))
it('G-units test response shapes W14', () => {
  expect(testResult('webhook', { success: true, status_code: 204 })).toEqual({ ok: true,
    key: 'webhookSuccessHTTP', args: { status: 204 }, detail: '' })
  expect(testResult('webhook', { success: false, status_code: 503 })).toEqual({ ok: false,
    key: 'webhookTestFailed', args: { status: 503 }, detail: 'HTTP 503' })
  expect(testResult('webhook', { success: false, error: 'request failed' }).detail).toBe('request failed')
  expect(testResult('xdrop', { success: true, name: 'machine' })).toEqual({ ok: true,
    key: 'xdropTestSuccess', args: { name: 'machine' }, detail: '' })
  expect(testResult('xdrop', { success: false, error: 'invalid auth' })).toEqual({ ok: false,
    key: 'xdropTestFailed', args: { name: '' }, detail: 'invalid auth' })
  expect(testResult('bgp', { ok: true, output: 'BGP output' })).toEqual({ ok: true,
    key: 'connectionOk', detail: 'BGP output' })
  expect(testResult('bgp', { ok: false, error: 'vtysh error' })).toEqual({ ok: false,
    key: 'bgpTestFailed', detail: 'vtysh error' })
})
it.each(['bgp', 'webhook', 'xdrop'] as const)('G-units %s request failures retain original', kind => {
  for (const error of ['Forbidden', 'not found', 'network failed', 'timeout']) {
    expect(testResult(kind, undefined, error)).toEqual({ ok: false, key: kind + 'TestFailed', detail: error })
  }
})
it('G-units mock masks read copies and preserves synthetic original on masked PUT W6b', () => {
  const state = fixtureState(0)
  const mock = responseSession('qg', 0, state)
  expect(state.connectors.webhook![0]!.headers).toEqual({ Authorization: 'Bearer qg-synthetic' })
  const result = mock('/api/settings/webhook-connectors/1', 'PUT', {
    name: 'Alert hook', url: 'http://192.0.2.1/hook', method: 'POST', headers: { Authorization: '******' },
    timeout_ms: 10000, global: false, enabled: true,
  })
  expect(result).toEqual({ status: 200, body: { ok: true } })
  expect(state.connectors.webhook![0]!.headers).toEqual({ Authorization: 'Bearer qg-synthetic' })
  expect(mock('/api/settings/webhook-connectors')?.body[0].headers).toEqual({ Authorization: '******' })
})
it('G-artifact example hostname exception has three adversarial rejected URLs W27', () => {
  const scan = scanArtifacts(root + '/tests/fixtures/artifact-example')
  expect(scan.exceptions.map((v: any) => [v.url, v.type]).sort()).toEqual([
    ['https://hooks.example.net/notify', 'example'], ['https://xdrop.example.com:8000/api/v1', 'example'],
  ])
  expect(scan.violations.map((v: any) => v.url).sort()).toEqual([
    'https://example.com.attacker.test/x', 'https://example.com@evil.test/x', 'https://notexample.com/x',
  ])
  expect(scan.schemaErrors).toEqual([])
})
it.each([['ar', zh], ['en', en]] as const)('G-i18n specified old connector literals exact %s', (lang, dict) => {
  const source = sourceText('tests/fixtures/legacy-i18n/' + lang + '.js.txt')
  const mapping: Record<string, Record<string, string>> = {
    xdropConnectors: { decoderScopeTitle: 'decoderScopeTitle', decoderScopeBody: 'decoderScopeBody',
      apiUrlHint: 'apiUrlHint', apiKeyTip: 'apiKeyTip', timeoutTip: 'xdropTimeoutTip',
      testSuccess: 'xdropTestSuccess', testFailed: 'xdropTestFailed' },
    webhookConnectors: { timeoutTip: 'webhookTimeoutTip', testSuccess: 'webhookTestSuccess',
      testFailed: 'webhookTestFailed' },
    bgpConnectors: { connectionOk: 'connectionOk', testFailed: 'bgpTestFailed',
      fetchRoutesFailed: 'fetchRoutesFailed', bgpRoutes: 'bgpRoutes' },
    shellConnectors: { timeoutTip: 'shellTimeoutTip', commandHint: 'commandHint',
      commandValidation: 'commandValidation', nameRequired: 'shellNameRequired' },
  }
  for (const [section, keys] of Object.entries(mapping)) {
    const block = source.match(new RegExp('  ' + section + ': \\{\\n([\\s\\S]*?)\\n  \\},'))![1]!
    for (const [oldKey, key] of Object.entries(keys)) {
      const literal = block.match(new RegExp("\\b" + oldKey + ": '([^']*)'"))![1]
      expect((dict.connectors as any)[key], section + '.' + oldKey).toBe(literal)
    }
  }
})
it('G-units mock list reads still mask originals after PUT', () => {
  const mock = mockSession('qg', 0)
  expect(mock('/api/settings/webhook-connectors').body[0].headers).toEqual({ Authorization: '******' })
  expect(mock('/api/settings/shell-connectors').body[1].pass_stdin).toBe(true)
})

it.each([
  ['xdrop', { name: 'Explicit disabled XDrop', api_url: 'https://xdrop.example.com/api/v1',
    api_key: 'synthetic-key', timeout_ms: 1000, enabled: false }],
  ['webhook', { name: 'Explicit disabled Webhook', url: 'https://hooks.example.net/notify',
    method: 'POST', headers: {}, timeout_ms: 1000, global: false, enabled: false }],
  ['shell', { name: 'Explicit disabled Shell', command: '/bin/true', default_args: '',
    timeout_ms: 1000, enabled: false }],
])('G-units %s POST explicit enabled false reads true W26 supplement', (kind, payload) => {
  const mock = mockSession('normal', 0)
  expect(mock(`/api/settings/${kind}-connectors`, 'POST', payload))
    .toEqual({ status: 201, body: { id: 3 } })
  const rows = mock(`/api/settings/${kind}-connectors`).body
  expect(rows.find((r: ConnectorRow) => r.id === 3).enabled).toBe(true)
})
it.each(['bgp', 'webhook', 'shell', 'xdrop'] as const)(
  'G-units normal %s deleted empty list matches Go W32', kind => {
    const state = fixtureState(0)
    state.actions = []
    state.announcements.clear()
    const mock = responseSession('normal', 0, state)
    for (const id of [1, 2]) {
      expect(mock(`/api/settings/${kind}-connectors/${id}`, 'DELETE'))
        .toEqual({ status: 200, body: { ok: true } })
    }
    expect(mock(`/api/settings/${kind}-connectors`))
      .toEqual({ status: 200, body: kind === 'xdrop' ? [] : null })
  },
)
