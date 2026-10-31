import { join, basename } from 'node:path'
import { mkdirSync, writeFileSync } from 'node:fs'
import { PROJECT_URL } from '../src/project.js'
import { root, out, walk, read, main } from './lib.mjs'

const namespaces = new Set([
  'http://www.w3.org/2000/svg',
  'http://www.w3.org/1998/Math/MathML',
  'http://www.w3.org/1999/xlink',
  'http://www.w3.org/1999/xhtml',
])

function exampleURL(value) {
  try {
    const hostname = new URL(value).hostname
    return ['example.com', 'example.net', 'example.org'].some(domain =>
      hostname === domain || hostname.endsWith('.' + domain))
  } catch { return false }
}

export function scanArtifacts(directory) {
  const violations = []
  const exceptions = []
  const schemaErrors = []
  let mock = 0
  let dev = 0
  let google = 0
  let prototype = 0
  let files = 0
  function scanText(source, file, licenseAllowed = false) {
    mock += (source.match(/__XS_MOCK__/g) || []).length
    dev += (source.match(/\/__dev\//g) || []).length
    google += (source.match(/fonts\.googleapis|fonts\.gstatic/g) || []).length
    prototype += (source.match(/原型|示例数据|proto-tag/g) || []).length
    for (const match of source.matchAll(/https?:\/\/[^\s<>"'`]+/g)) {
      const url = match[0]
      const hit = {
        file,
        url,
        context: source.slice(Math.max(0, match.index - 45), match.index + url.length + 45),
      }
      const type = namespaces.has(url)
        ? 'namespace'
        : url === PROJECT_URL
          ? 'project'
          : licenseAllowed
            ? 'licenseText'
            : file.endsWith('.js') && url.startsWith('https://vuejs.org/error-reference/#') ? 'vue-diagnostic' : ''
      if (type) exceptions.push({ ...hit, type })
      else if (exampleURL(url)) exceptions.push({ ...hit, type: 'example' })
      else violations.push(hit)
    }
  }
  for (const file of walk(directory).filter(f => /\.(html|js|css|json|ts|vue)$/.test(f))) {
    files++
    const source = read(file)
    if (basename(file) === 'third-party.json') {
      let manifest
      try {
        manifest = JSON.parse(source)
      } catch {
        schemaErrors.push(file)
        scanText(source, file)
        continue
      }
      const keys = ['group', 'name', 'version', 'license', 'licenseText', 'note']
      const valid = Array.isArray(manifest) && manifest.every(e => e
        && typeof e === 'object'
        && Object.keys(e).every(k => keys.includes(k))
        && ['font', 'browser'].includes(e.group)
        && ['name', 'version', 'license', 'licenseText'].every(k => typeof e[k] === 'string' && e[k].length > 0)
        && (e.note === undefined || typeof e.note === 'string'))
      if (!valid) {
        schemaErrors.push(file)
        scanText(source, file)
        continue
      }
      for (const entry of manifest) for (const [field, value] of Object.entries(entry)) scanText(
        String(value),
        file,
        field === 'licenseText',
      )
    } else scanText(source, file)
  }
  return { files, violations, exceptions, schemaErrors, mock, dev, google, prototype }
}

export function cleanArtifact(result) {
  return !result.violations.length
    && !result.schemaErrors.length
    && !result.mock
    && !result.dev
    && !result.google
    && !result.prototype
}

if (main(import.meta.url)) {
  const production = scanArtifacts(join(root, 'dist'))
  const mock = scanArtifacts(join(root, 'mock'))
  const dev = scanArtifacts(join(root, 'src/dev'))
  const v9 = scanArtifacts(join(root, 'tests/fixtures/artifact'))
  for (const hit of production.exceptions) console.log('exception', JSON.stringify(hit))
  console.log('G-artifact', JSON.stringify({
    ...production,
    exceptions: production.exceptions.length,
    positive: { mock: mock.mock, dev: dev.dev },
    v9RejectedLinks: v9.violations.length,
  }))
  mkdirSync(out, { recursive: true })
  writeFileSync(join(out, 'artifact-scan.json'), JSON.stringify({ production, mock, dev, v9 }, null, 2))
  process.exitCode = !cleanArtifact(production) || mock.mock < 1 || dev.dev < 1 || v9.violations.length !== 1 ? 1 : 0
}
