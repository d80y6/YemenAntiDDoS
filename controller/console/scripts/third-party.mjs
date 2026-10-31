import { existsSync, readFileSync, readdirSync, writeFileSync, mkdirSync, statSync } from 'node:fs'
import { resolve, dirname, join, relative } from 'node:path'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { root, out, walk, read, json, main } from './lib.mjs'

function owner(id) {
  const clean = id.replaceAll('\\', '/').split('?')[0]
  const index = clean.lastIndexOf('/node_modules/')
  if (index < 0) return null
  const tail = clean.slice(index + 14).split('/')
  const count = tail[0].startsWith('@') ? 2 : 1
  const dir = clean.slice(0, index + 14) + tail.slice(0, count).join('/')
  if (!existsSync(join(dir, 'package.json'))) return null
  return { dir, ...json(join(dir, 'package.json')) }
}

function licenseText(dir) {
  return readdirSync(dir)
    .filter(name => /^(LICENSE|LICENCE|COPYING|NOTICE)(\b|[._-])/i.test(name)
      && statSync(join(dir, name)).isFile())
    .map(name => read(join(dir, name)))
    .join('\n\n')
}

export function generateThirdParty(_options, bundle) {
  const packages = new Map()
  for (const item of Object.values(bundle)) {
    if (item.type === 'chunk') for (const [id, info] of Object.entries(item.modules)) {
      const pkg = info.renderedLength > 0 ? owner(id) : null
      if (pkg) packages.set(pkg.name, pkg)
    }
    if (item.type === 'asset' && /\.woff2?$/.test(item.fileName)) for (const source of item.originalFileNames || []) {
      const pkg = owner(resolve(root, source))
      if (!pkg || !pkg.name.startsWith('@fontsource/')) throw new Error('Unrecognized font: ' + source)
      packages.set(pkg.name, pkg)
    }
  }
  const entries = [...packages.values()].map(pkg => {
    const text = licenseText(pkg.dir)
    if (!text || !pkg.license) throw new Error('Missing license: ' + pkg.name)
    return {
      group: pkg.name.startsWith('@fontsource/') ? 'font' : 'browser',
      name: pkg.name,
      version: pkg.version,
      license: pkg.license,
      licenseText: text,
    }
  }).sort((a, b) => a.name.localeCompare(b.name))
  this.emitFile({ type: 'asset', fileName: 'third-party.json', source: JSON.stringify(entries, null, 2) + '\n' })
}

export function serveThirdParty(server) {
  server.middlewares.use((req, res, next) => {
    if (req.url !== '/third-party.json') return next()
    try {
      res.setHeader('Content-Type', 'application/json')
      res.end(read(join(root, 'dist/third-party.json')))
    } catch {
      res.statusCode = 404
      res.end()
    }
  })
}

export function compareLicenseManifest(manifest, expected) {
  const actual = manifest.map(p => p.name + '@' + p.version).sort()
  const wanted = [...expected].sort()
  const missing = wanted.filter(p => !actual.includes(p))
  const extra = actual.filter(p => !wanted.includes(p))
  const invalid = manifest.filter(p => {
    const dir = join(root, 'node_modules', p.name)
    return !existsSync(join(dir, 'package.json'))
      || json(join(dir, 'package.json')).license !== p.license
      || licenseText(dir) !== p.licenseText
  }).map(p => p.name)
  return { missing, extra, invalid, duplicates: actual.length - new Set(actual).size }
}

// Independent witness: source maps for JS and content-addressed CSS font references.
export function independentPackages(build) {
  const packages = new Set()
  const files = walk(build)
  for (const file of files.filter(f => f.endsWith('.map'))) for (const source of json(file).sources) {
    const match = /node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(source)
    if (match) {
      const pkg = json(join(root, 'node_modules', match[1], 'package.json'))
      packages.add(pkg.name + '@' + pkg.version)
    }
  }
  const digest = file => createHash('sha256').update(readFileSync(file)).digest('hex')
  const fonts = new Map()
  for (const name of ['ibm-plex-sans', 'ibm-plex-mono']) {
    const dir = join(root, 'node_modules/@fontsource', name)
    const pkg = json(join(dir, 'package.json'))
    for (const file of walk(dir).filter(f => /\.woff2?$/.test(f))) fonts.set(digest(file), pkg.name + '@' + pkg.version)
  }
  const referenced = new Set()
  for (const file of files.filter(f => f.endsWith('.css'))) for (
    const hit of read(file).matchAll(/url\(["']?([^"')]+)["']?\)/g)
  ) {
    if (!/\.woff2?$/.test(hit[1])) continue
    const target = hit[1].startsWith('/') ? join(build, hit[1]) : resolve(dirname(file), hit[1])
    referenced.add(resolve(target))
    const pkg = fonts.get(digest(target))
    if (!pkg) throw new Error('Unrecognized font bytes: ' + target)
    packages.add(pkg)
  }
  const emitted = files.filter(f => /\.woff2?$/.test(f)).map(f => resolve(f))
  if (
    emitted.length !== referenced.size || emitted.some(f => !referenced.has(f))
  ) throw new Error('Font references differ from emitted files')
  return packages
}

if (main(import.meta.url) && process.argv.includes('--check')) {
  const witness = join(out, 'license-witness')
  mkdirSync(out, { recursive: true })
  execFileSync(
    process.execPath,
    [join(root, 'node_modules/vite/bin/vite.js'), 'build', '--sourcemap', '--outDir', witness],
    { cwd: root, env: process.env, stdio: 'pipe' },
  )
  const expected = independentPackages(witness)
  const manifest = json(process.env.XSIGHT_LICENSE_JSON || join(root, 'dist/third-party.json'))
  const result = compareLicenseManifest(manifest, expected)
  const positive = compareLicenseManifest(manifest.slice(1), expected)
  const font = manifest.find(p => p.name === '@fontsource/ibm-plex-sans' && p.license === 'OFL-1.1')
  console.log('G-license', JSON.stringify({
    packages: manifest.length,
    expected: expected.size,
    ...result,
    fontOFL: !!font,
    positiveMissing: positive.missing,
  }))
  writeFileSync(join(out, 'license.json'), JSON.stringify({ expected: [...expected], result, positive }, null, 2))
  process.exitCode = result.missing.length
    || result.extra.length
    || result.invalid.length
    || result.duplicates
    || !font
    || !positive.missing.length ? 1 : 0
}
