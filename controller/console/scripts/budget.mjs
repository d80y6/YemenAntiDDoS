import { root, out, walk, read, main } from './lib.mjs'
import { join, relative } from 'node:path'
import { statSync, mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import ts from 'typescript'

const lines = files => files.reduce(
  (n, f) => n + read(f).split('\n').length - (read(f).endsWith('\n') ? 1 : 0),
  0,
)

function exceptionLines(file, source, project) {
  const result = new Map()
  const name = relative(project, file).replaceAll('\\', '/')
  const textLines = source.split('\n')
  const parsed = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true)
  function allow(node, reason) {
    const start = node.getStart(parsed)
    const end = node.getEnd()
    const first = parsed.getLineAndCharacterOfPosition(start)
    const last = parsed.getLineAndCharacterOfPosition(end)
    if (first.line !== last.line) return
    const line = textLines[first.line].trim()
    if (line.replace(/[,;]$/, '') === node.getText(parsed)) result.set(first.line + 1, reason)
  }
  function table(node) {
    while (ts.isAsExpression(node) || ts.isParenthesizedExpression(node)) node = node.expression
    if (!ts.isArrayLiteralExpression(node)) return
    for (const cell of node.elements) {
      allow(cell, 'test-data-cell')
      if (ts.isArrayLiteralExpression(cell)) table(cell)
    }
  }
  function visit(node) {
    if (
      /^src\/i18n\/(?:ar|en)\.ts$/.test(name)
      && ts.isPropertyAssignment(node)
      && ts.isStringLiteral(node.initializer)
    ) allow(node, 'i18n-string')
    if (
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))
      && /^https?:\/\/\S+$/.test(node.text)
    ) allow(node, 'url')
    if (
      name.startsWith('tests/')
      && ts.isCallExpression(node)
      && /^(?:it|test|describe)\.each$/.test(node.expression.getText(parsed))
      && node.arguments[0]
    ) table(node.arguments[0])
    ts.forEachChild(node, visit)
  }
  visit(parsed)
  for (const [index, line] of textLines.entries()) if (
    /^\s*(?:href|src)="https?:\/\/[^"\s]+"\s*(?:\/?>)?\s*$/.test(line)
  ) result.set(index + 1, 'url')
  return result
}

export function scanFormat(project = root, directories = ['src', 'tests', 'scripts', 'mock']) {
  const files = directories.flatMap(directory => walk(join(project, directory)))
    .filter(file => /\.(?:[cm]?js|[jt]sx?|vue|css|json)$/.test(file))
  // Locale files (ar/en) hold translation strings whose length is inherent to
  // the language — they are budgeted by line count below, not by line width.
  const localeData = /^src\/i18n\/(?:ar|en)\.ts$/
  const violations = []
  const exceptions = []
  let rawOver120 = 0
  let maxLine = 0
  for (const file of files) {
    const rel = relative(project, file).replaceAll('\\', '/')
    if (localeData.test(rel)) continue
    const source = read(file)
    const allowed = exceptionLines(file, source, project)
    for (const [index, line] of source.split('\n').entries()) {
      const length = [...line].length
      maxLine = Math.max(maxLine, length)
      if (length <= 120) continue
      rawOver120++
      const hit = { file: rel, line: index + 1, length }
      const reason = allowed.get(index + 1)
      if (reason) exceptions.push({ ...hit, reason })
      else violations.push(hit)
    }
  }
  return { files: files.length, rawOver120, maxLine, exceptions, violations }
}

if (main(import.meta.url)) {
  const source = walk(join(root, 'src')).filter(f => /\.(ts|js|vue|css)$/.test(f))
  const dist = walk(join(root, 'dist'))
  const measured = {
    src: lines(source),
    ar: lines([join(root, 'src/i18n/ar.ts')]),
    en: lines([join(root, 'src/i18n/en.ts')]),
    mock: lines(walk(join(root, 'mock'))),
    tests: lines(walk(join(root, 'tests'))),
    distBytes: dist.reduce((n, f) => n + statSync(f).size, 0),
    maxJS: Math.max(...dist.filter(f => f.endsWith('.js')).map(f => statSync(f).size)),
  }
  const limits = {
    src: 12700,
    ar: 1240,
    en: 1180,
    mock: 1950,
    tests: 10200,
    distBytes: 2500000,
    maxJS: 600000,
  }
  console.log('G-budget', JSON.stringify({ measured, limits }))
  const production = scanFormat()
  mkdirSync(out, { recursive: true })
  const fixture = mkdtempSync(join(out, 'format-positive-'))
  let positive
  try {
    writeFileSync(join(fixture, 'positive.ts'), 'x'.repeat(121) + '\n')
    positive = scanFormat(fixture, ['.'])
  } finally {
    rmSync(fixture, { recursive: true, force: true })
  }
  console.log('G-format', JSON.stringify({ production, positive }))
  writeFileSync(join(out, 'format.json'), JSON.stringify({ production, positive }, null, 2))
  process.exitCode = Object.entries(measured).some(([key, n]) => n > limits[key])
    || production.violations.length
    || positive.violations.length !== 1
    || positive.violations[0]?.length !== 121 ? 1 : 0
}
