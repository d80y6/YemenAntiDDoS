import { parse } from 'vue/compiler-sfc'
import { root, walk, read, main } from './lib.mjs'
import { join, basename } from 'node:path'

export function scanCSS(directory) {
  const hits = []
  const files = walk(directory).filter(file => file.endsWith('.vue')
    || file.endsWith('.css') && (file.includes('/styles/') || directory !== join(root, 'src')))
  for (const file of files) {
    if (basename(file) === 'tokens.css') continue
    const segments = file.endsWith('.vue')
      ? parse(read(file)).descriptor.styles.map(style => style.content)
      : [read(file)]
    for (const source of segments) for (
      const match of source.matchAll(/#[0-9a-f]{3,8}\b|rgba?\s*\(|hsl\s*\(/gi)
    ) hits.push({
      file,
      literal: match[0],
    })
  }
  return { files: files.length, hits }
}

if (main(import.meta.url)) {
  const production = scanCSS(join(root, 'src'))
  const positive = scanCSS(join(root, 'tests/fixtures/css'))
  console.log('G-css', JSON.stringify({ production, positive }))
  process.exitCode = production.hits.length || new Set(positive.hits.map(h => h.file)).size !== 2 ? 1 : 0
}
