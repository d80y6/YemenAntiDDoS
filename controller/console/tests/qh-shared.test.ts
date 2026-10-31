import { expect, it } from 'vitest'
import { checkContract } from '../scripts/contract-check.mjs'
import { contract } from '../src/api/contract'
import { inetText } from '../mock/inet'
// @ts-expect-error Node built-ins run only in the test harness.
import { readFileSync } from 'node:fs'
const corpus = JSON.parse(readFileSync('../internal/store/postgres/testdata/mock-parity/inet-corpus.json', 'utf8'))
it('G-inet TS sealed corpus: 43 inputs, 28 accepted, 15 rejected W17', () => {
  expect(corpus).toHaveLength(43)
  expect(corpus.filter((e: any) => e.go_valid)).toHaveLength(28)
  for (const entry of corpus) expect.soft(inetText(entry.input), entry.input)
    .toBe(entry.go_valid ? entry.pg_text : null)
})
it.each([undefined, 0, 'abc', -1])('G-shared listener ALL template entries missing %s W22', async listener => {
  const entries = contract.filter(e => e.endpoint === '/api/flow-listeners/{listener}')
  let fetches = 0
  const result = await checkContract(entries, async () => { fetches++; return {} }, { listener })
  expect(entries).toHaveLength(14)
  expect(result.results).toHaveLength(14)
  expect(result.results.every((r: any) => r.state === 'missing' && r.detail.includes('requires --listener')))
    .toBe(true)
  expect(result.passed).toBe(false)
  expect(fetches).toBe(0)
})
it('G-shared listener substitutes positive id', async () => {
  let seen = ''
  const result = await checkContract([{ endpoint: '/api/flow-listeners/{listener}', path: 'listener.id' }],
    async (path: string) => { seen = path; return { listener: { id: 1 } } }, { listener: 1 })
  expect(seen).toBe('/api/flow-listeners/1')
  expect(result.passed).toBe(true)
})
