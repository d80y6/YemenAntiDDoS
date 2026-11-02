import { it, expect } from 'vitest'
const join = (...parts: string[]) => parts.join('/')
import zh from '../src/i18n/ar'
import en from '../src/i18n/en'
import { root } from '../scripts/lib.mjs'
import { scanArtifacts } from '../scripts/artifact-scan.mjs'
import { scanNative } from '../scripts/native-scan.mjs'
import { scanCSS } from '../scripts/css-scan.mjs'

export function checkDictionaries(a: unknown, b: unknown) {
  function flatten(value: any, prefix = ''): Record<string, unknown> {
    return Object.fromEntries(Object.entries(value).flatMap(([key, v]) => v && typeof v === 'object'
      ? Object.entries(flatten(v, prefix + key + '.'))
      : [[prefix + key, v]]))
  }
  const left = flatten(a)
  const right = flatten(b)
  const keys = new Set([...Object.keys(left), ...Object.keys(right)])
  return [...keys].filter(key => !(key in left)
    || !(key in right)
    || typeof left[key] !== 'string'
    || typeof right[key] !== 'string'
    || !(left[key] as string).trim()
    || !(right[key] as string).trim())
}

it('G-i18n identical keys/no blanks and missing-key positive', () => {
  expect(checkDictionaries(zh,en)).toEqual([])
  const missing = structuredClone(en)
  delete (missing.pages as Partial<typeof en.pages>).about
  expect(checkDictionaries(zh,missing)).toEqual(['pages.about'])
})

it('G-artifact V9 rejects URL in validated non-license metadata', () => {
  const scan = scanArtifacts(join(root,'tests/fixtures/artifact'))
  expect(scan.schemaErrors).toEqual([])
  expect(scan.violations, 'non-licenseText URL must be rejected').toHaveLength(1)
  expect(scan.violations[0]?.url).toBe('https://evil.invalid/metadata')
})

it('G-native AST catches four positives but ignores component', () => {
  const result = scanNative(join(root,'tests/fixtures/native'))
  expect(result.violations).toHaveLength(4)
  expect(result.violations.some((v: { file: string }) => v.file.endsWith('component.vue'))).toBe(false)
  expect(scanNative(join(root,'src')).violations).toEqual([])
})

it('G-css same enumeration finds CSS/SFC positives', () => {
  expect(scanCSS(join(root,'src')).hits).toEqual([])
  const positive = scanCSS(join(root,'tests/fixtures/css'))
  expect(positive.hits).toHaveLength(2)
  expect(new Set(positive.hits.map((h: { file: string }) => h.file)).size).toBe(2)
})


it.each(['uppercase.vue', 'mixed-binding.vue'])(
  'R2 F5 native scanner rejects case-insensitive type in %s',
  name => {
    const scan = scanNative(join(root, 'tests/fixtures/native-case'))
    const hits = scan.violations.filter((hit: { file: string }) => hit.file.endsWith('/' + name))
    expect(hits).toHaveLength(1)
    expect(hits[0]?.kind).toBe('input-type')
  },
)
