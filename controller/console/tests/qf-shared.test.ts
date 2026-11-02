import { expect, it } from 'vitest'
import { cliContract } from './qf-runtime.mjs'
import { checkContract } from '../scripts/contract-check.mjs'
import { contract } from '../src/api/contract'
import { mockReply } from '../mock/data'
import { sourceText } from './r1-files.mjs'
import zh from '../src/i18n/ar'
import en from '../src/i18n/en'
import { mountQE } from './qe-harness'
import { flushPromises } from '@vue/test-utils'
const endpoint = '/api/responses/{response}'
it.each([undefined, 0, 'abc', -1])(
  'G-shared missing/invalid response retains ALL entries red %s W29', async response => {
  const entries = contract.filter(e => e.endpoint === endpoint)
  let fetches = 0
  const r = await checkContract(entries, async () => { fetches++; return {} }, { response })
  expect(r.paths).toBe(32)
  expect(r.results).toHaveLength(32)
  expect(r.results.every((i: any) => i.state === 'missing' && i.detail.includes('requires --response'))).toBe(true)
  expect(r.passed).toBe(false)
  expect(fetches).toBe(0)
})
it('G-shared response substitution and actual CLI option pipeline', async () => {
  let seen = ''
  const r = await checkContract([{ endpoint, path: 'response.id' }], async (p: string) => {
    seen = p; return { response: { id: 3 } }
  }, { response: 3 })
  expect(r.passed).toBe(true)
  expect(seen).toBe('/api/responses/3')
  const run = cliContract()
  expect(run.status, run.text).toBe(0)
  const positive = cliContract(true)
  expect(positive.status, positive.text).toBe(0)
})
it.each(['paired_with', 'auto_generated'])(
  'G-shared exact omitempty leaf %s, missing parent and typo red', async key => {
  const entry = { endpoint, path: 'actions[].' + key, optional: 'ResponseAction + omitempty' }
  const check = (sample: any, path = entry.path) => checkContract([{ ...entry, path }], async () => sample,
    { response: 3 })
  expect((await check({ actions: [{}] })).passed).toBe(true)
  expect((await check({})).results[0].state).toBe('missing')
  expect((await check({ actions: [{}] }, entry.path + '_typo')).passed).toBe(false)
})
it('G-contract complete actionView and connector paths mock hits; conditions DTO full keys', async () => {
  const r = await checkContract(contract, async (p: string) => mockReply(p).body,
    { attack: 2, node: 'edge-a', response: 3, listener: 1, mock: true })
  expect(r.paths).toBe(641)
  expect(r.requests).toBe(43)
  expect(r.passed).toBe(true)
  const conditions = mockReply('/api/actions/15/preconditions', 'qf').body
  expect(Object.keys(conditions[0]).sort()).toEqual(['action_id', 'attribute', 'created_at', 'id', 'operator', 'value'])
})
it('G-shared both production routes mount new response components', async () => {
  const { w, router } = await mountQE('/responses', undefined, true, 'qf')
  expect(w.find('.rs-list').exists()).toBe(true)
  await router.push('/responses/3'); await flushPromises()
  expect(w.find('.rs-detail').exists()).toBe(true)
})
it.each([['ar', zh], ['en', en]])('G-i18n all 42 old responses literals exact %s', (lang, dictionary) => {
  const old = sourceText('tests/fixtures/legacy-i18n/' + lang + '.js.txt')
    .match(/  responses: \{\n([\s\S]*?)\n  \},/)![1]!
  const entries = [...old.matchAll(/(\w+): '([^']*)'/g)]
  expect(entries).toHaveLength(42)
  for (const [, key, literal] of entries) expect((dictionary.responses as any)[key!]).toBe(literal)
})
