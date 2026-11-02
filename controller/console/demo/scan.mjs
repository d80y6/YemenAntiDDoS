import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { basename, extname, join, resolve } from 'node:path'
import { isIP } from 'node:net'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'
import { backendRoutes, samplePath } from './routes.mjs'
import { createServer } from './server.ts'

const textExtensions = new Set(['.js', '.css', '.html', '.json', '.txt', '.svg'])
const walk = dir => readdirSync(dir).sort().flatMap(name => {
  const file = join(dir, name)
  return statSync(file).isDirectory() ? walk(file) : [file]
})
export function literals(text) {
  const found = new Set()
  for (const m of text.matchAll(/(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,3})?(?![\w./])/g)) {
    const [ip, prefix] = m[0].split('/')
    if (isIP(ip) === 4 && (prefix === undefined || Number(prefix) <= 32)) found.add(m[0])
  }
  for (const m of text.matchAll(/(?<![\w.:])(?:[\da-fA-F]{0,4}:){2,}[\da-fA-F:.]*(?:\/\d{1,3})?(?![\w.:])/g)) {
    const [ip, prefix] = m[0].split('/')
    if (isIP(ip) === 6 && (prefix === undefined || Number(prefix) <= 128)) found.add(m[0])
  }
  // Interpolated identifiers are expressions, not part of a URL literal (bundlers rename them).
  for (const m of text.matchAll(/[a-z][a-z\d+.-]*:\/\/[^\s<>"'`\\)]+/gi)) found.add(m[0].split('${')[0])
  return [...found]
}
const special = value => [[0, 0, 0, 0].join('.'), [127, 0, 0, 1].join('.'),
  ':'.repeat(2), ':'.repeat(2) + '1'].includes(value)
export function permitted(value, allowSpecial = false) {
  if (value.includes('://')) {
    try {
      const u = new URL(value)
      return !u.username && !u.password && ['example.com', 'example.net', 'example.org']
        .some(domain => u.hostname === domain || u.hostname.endsWith('.' + domain))
    } catch { return false }
  }
  const [ip, suffix] = value.split('/'), family = isIP(ip)
  if (special(ip)) return allowSpecial && suffix === undefined
  if (family === 4) return /^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip)
    && (suffix === undefined || Number(suffix) >= 24)
  if (family === 6) {
    return /^2001:0*db8:/i.test(ip) && (suffix === undefined || Number(suffix) >= 32)
  }
  return false
}
const masked = value => typeof value === 'string' && /^(?:\*{3}|\*{6}|\*{3}[\w-]{4})$/.test(value)
const sensitive = name => /password|secret|token|key|authorization/i.test(name)
const goSpecialField = name => /^(listen_address|listen_addr)$/.test(name)
function literalField(node, parsed) {
  let expression = node
  while (ts.isParenthesizedExpression(expression.parent) || ts.isAsExpression(expression.parent)
    || ts.isNonNullExpression(expression.parent)) expression = expression.parent
  const parent = expression.parent
  const name = node => ts.isIdentifier(node) || ts.isStringLiteral(node) ? node.text
    : ts.isPropertyAccessExpression(node) ? node.name.text
      : ts.isElementAccessExpression(node) && ts.isStringLiteral(node.argumentExpression)
        ? node.argumentExpression.text : node.getText(parsed)
  if ((ts.isPropertyAssignment(parent) || ts.isVariableDeclaration(parent) || ts.isBindingElement(parent))
    && parent.initializer === expression) return name(parent.name)
  if (ts.isBinaryExpression(parent) && parent.right === expression
    && parent.operatorToken.kind === ts.SyntaxKind.EqualsToken) return name(parent.left)
  return ''
}
export function scanValue(value, location = 'value', failures = [], field = '') {
  if (sensitive(field) && value !== null && value !== undefined && value !== ''
    && value !== 'demo-session' && !masked(value)) failures.push({ location, kind: 'credential', field })
  if (typeof value === 'string') {
    for (const item of literals(value)) if (!permitted(item, goSpecialField(field))) {
      failures.push({ location, kind: 'address-or-url', value: item })
    }
    for (const m of value.matchAll(/Bearer\s+([^\s"']+)/gi)) {
      if (m[1] !== 'demo-session' && !masked(m[1])) failures.push({ location, kind: 'bearer' })
    }
    if (/^\s*[\[{]/.test(value)) {
      try { scanValue(JSON.parse(value), location + ':json', failures) } catch { /* not embedded JSON */ }
    }
  } else if (value && typeof value === 'object') {
    for (const [name, child] of Object.entries(value)) scanValue(child, location + '.' + name, failures, name)
  }
  return failures
}
export function scanSources(directory) {
  const failures = []
  for (const file of walk(directory).filter(f => /\.(ts|mjs|js|json|html|css)$/.test(f))) {
    const source = readFileSync(file, 'utf8')
    if (/\.(ts|mjs|js)$/.test(file)) {
      const parsed = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true)
      const visit = node => {
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
          || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
          const field = literalField(node, parsed)
          // Raw text intentionally does not decode escaped address fragments (registered limitation).
          const raw = node.getText(parsed).slice(1, -1)
          scanValue(raw, file + ':' + parsed.getLineAndCharacterOfPosition(node.getStart()).line, failures, field)
        }
        ts.forEachChild(node, visit)
      }
      visit(parsed)
    } else if (file.endsWith('.json')) scanValue(JSON.parse(source), file, failures)
    else scanValue(source, file, failures)
  }
  return failures
}
function artifactText(file) {
  const source = readFileSync(file, 'utf8')
  if (basename(file) !== 'third-party.json') return source
  const manifest = JSON.parse(source)
  if (!Array.isArray(manifest) || !manifest.every(e => ['font', 'browser'].includes(e.group)
    && ['name', 'version', 'license', 'licenseText'].every(k => typeof e[k] === 'string' && e[k]))) {
    throw Error('Invalid third-party manifest: ' + file)
  }
  return JSON.stringify(manifest.map(({ licenseText, ...entry }) => entry))
}
export function scanArtifacts(prod, demo, buildVersion = process.env.XSIGHT_VERSION) {
  if (typeof buildVersion !== 'string' || !buildVersion.trim()) throw Error('XSIGHT_VERSION build version required')
  const expectedVersion = buildVersion + '-demo'
  if (!prod || !existsSync(prod) || !statSync(prod).isDirectory() || !walk(prod).length) {
    throw Error('Production dist is missing or empty')
  }
  const productionFiles = walk(prod).filter(f => textExtensions.has(extname(f)))
  if (!productionFiles.length) throw Error('Production dist has no text files')
  const baseline = new Set(productionFiles.flatMap(f => literals(artifactText(f))))
  const files = walk(demo).filter(f => textExtensions.has(extname(f))), failures = []
  let version = false
  for (const file of files) {
    const text = artifactText(file)
    if (file.endsWith('.js') && !version) {
      const visit = node => {
        if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))
          && node.text === expectedVersion) version = true
        ts.forEachChild(node, visit)
      }
      visit(ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true))
    }
    for (const value of literals(text)) if (!baseline.has(value) && !permitted(value, true)) {
      failures.push({ file, kind: 'artifact', value })
    }
  }
  if (!files.length || !version) failures.push({ kind: 'missing-demo-version', expectedVersion })
  return { files: files.length, baselineLiterals: baseline.size, failures }
}
export function scanData(server = createServer()) {
  const routes = backendRoutes().filter(r => r.method === 'GET'), failures = []
  if (routes.length !== 54) throw Error('GET route count must be 54; got ' + routes.length)
  for (const route of routes) {
    const path = samplePath(route.path), reply = server(path)
    if (reply.status !== 200) failures.push({ path, status: reply.status })
    scanValue(reply.body, path, failures)
  }
  return { endpoints: routes.length, failures }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const arg = name => process.argv[process.argv.indexOf(name) + 1]
    if (!process.argv.includes('--prod') || !process.argv.includes('--demo')) throw Error('--prod and --demo required')
    const artifacts = scanArtifacts(resolve(arg('--prod')), resolve(arg('--demo')))
    const data = scanData(), source = scanSources(fileURLToPath(new URL('.', import.meta.url)))
    const failures = [...artifacts.failures, ...data.failures, ...source]
    console.log('G2', JSON.stringify({ endpoints: data.endpoints, textFiles: artifacts.files,
      baselineLiterals: artifacts.baselineLiterals, failures, passed: failures.length === 0 }))
    process.exitCode = failures.length ? 1 : 0
  } catch (error) { console.error('G2 FAIL', error.message); process.exitCode = 1 }
}
