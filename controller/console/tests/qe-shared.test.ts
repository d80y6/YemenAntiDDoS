import { it, expect } from 'vitest'
import { sourceText } from './r1-files.mjs'
import { middlewareProbe } from './qe-fixtures.mjs'
import { flushPromises } from '@vue/test-utils'
import { mockReply } from '../mock/data'
import { contract } from '../src/api/contract'
import { checkContract } from '../scripts/contract-check.mjs'
import { mountQE } from './qe-harness'
import zh from '../src/i18n/zh'
import en from '../src/i18n/en'
it('G-shared W31 POST and PUT actual middleware forwards nondefault body without opening a port', async () => {
  const invoke = await middlewareProbe()
  expect(await invoke('POST', '/api/threshold-templates', { name: 'Middleware', description: 'Body witness' }))
    .toEqual({ status: 201, body: { id: 10 } })
  const listed = await invoke('GET', '/api/threshold-templates', {})
  expect(listed.status).toBe(200)
  expect(Array.isArray(listed.body)).toBe(true)
  expect(listed.body!.find((row: any) => row.id === 10)).toMatchObject({ name: 'Middleware',
    description: 'Body witness', response_id: null })
  expect(await invoke('PUT', '/api/dynamic-detection/config', { enabled: false, deviation_min: 88,
    deviation_max: 211, stable_weeks: 9, min_pps: 8765, min_bps: 76543, ewma_alpha: 0.37 }))
    .toEqual({ status: 200, body: { enabled: false, deviation_min: 88, deviation_max: 211,
      stable_weeks: 9, min_pps: 8765, min_bps: 76543, ewma_alpha: 0.37 } })
})
it('G-shared W32 all five production routes resolve actual mounted components and legacy redirects', async () => {
  const { w, router } = await mountQE('/prefixes')
  for (const [path, marker] of [['/prefixes', '.prefixes-page'], ['/thresholds', '.templates-page'],
    ['/thresholds/rules', '.all-rules'], ['/thresholds/7', '.template-detail'], ['/baseline', '.baseline-page']]) {
    await router.push(path!); await flushPromises()
    expect(router.resolve(path!).matched.at(-1)?.path).toBe(path === '/thresholds/7' ? '/thresholds/:id' : path)
    expect(w.find(marker!).exists()).toBe(true)
  }
  await router.push('/templates'); await flushPromises()
  expect(router.currentRoute.value.path).toBe('/thresholds')
  expect(w.find('.templates-page').exists()).toBe(true)
  await router.push('/dynamic-detection'); await flushPromises()
  expect(router.currentRoute.value.path).toBe('/baseline')
  expect(w.find('.baseline-page').exists()).toBe(true)
})
it('G-contract template detail standalone exact full fields mock strict with concrete id', async () => {
  const endpoint = '/api/threshold-templates/7'
  const entries: any[] = []
  for (const [parent, fields, nullable] of [
    ['template.', 'id name description response_id rule_count prefix_count created_at updated_at', 'response_id'],
    ['rules[].', 'id template_id prefix_id domain direction decoder unit comparison value inheritable'
      + ' response_id enabled created_at',
      'template_id prefix_id response_id'],
    ['prefixes_using[].', 'id prefix parent_id threshold_template_id name ip_group enabled created_at',
      'parent_id threshold_template_id'],
  ]) for (const key of fields!.split(' ')) entries.push({ endpoint, path: parent + key,
    ...(nullable!.split(' ').includes(key) ? { nullable: true } : {}) })
  const report = await checkContract(entries, async (p: string) => mockReply(p, 'qe').body, { mock: true })
  expect(report.passed).toBe(true)
  expect(report.paths).toBe(29)
  expect(report.requests).toBe(1)
  expect(report.results.every((r: any) => r.state === 'hit')).toBe(true)
  expect(contract.some(e => e.endpoint.includes('threshold-templates/'))).toBe(false)
  expect(mockReply(endpoint).body.template).toMatchObject({ rule_count: 0, prefix_count: 0 })
})
it('G-contract W33 nullable parent_id all-null fixture strict and status nullable', async () => {
  const entry = contract.filter(e => e.endpoint === '/api/prefixes' && e.path === '[].parent_id')
  const report = await checkContract(entry, async () => [{ parent_id: null }], { mock: true })
  expect(report.passed).toBe(true)
  expect(report.results[0].state).toBe('hit')
  expect(contract.find(e => e.endpoint === '/api/dynamic-detection/status' && e.path === 'prefixes'))
    .toHaveProperty('nullable', true)
})
it.each([['zh', zh], ['en', en]])('G-i18n W34 exact old texts %s', (lang, dictionary) => {
  const old = sourceText('tests/fixtures/legacy-i18n/' + lang + '.js.txt')
  for (const [section, keys] of [['templates', ['recommendInboundOnly', 'prefixLevel']], ['thresholds',
    ['globalSubnetOnly', 'pctRange', 'pctWarning', 'noResponse', 'useDefault']], ['baseline',
    ['infoTitle', 'infoDesc', 'infoEwma', 'infoSlots', 'infoDeviation', 'infoMinThreshold']]] as const) {
    for (const key of keys) {
      const literal = old.match(new RegExp('\\b' + key + ": '([^']*)'"))![1]
      expect((dictionary[section] as any)[key]).toBe(literal)
    }
  }
})
