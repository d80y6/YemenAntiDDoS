import { parse } from 'vue/compiler-sfc'
import { root, walk, read, main } from './lib.mjs'
import { join } from 'node:path'

export function scanNative(directory) {
  const violations = []
  const counts = { files: 0, elements: 0, dialogs: 0 }
  for (const file of walk(directory).filter(f => /\.(vue|ts)$/.test(f))) {
    counts.files++
    const source = read(file)
    const descriptor = file.endsWith('.vue') ? parse(source, { filename: file }).descriptor : null
    const scripts = descriptor
      ? [descriptor.script?.content || '', descriptor.scriptSetup?.content || ''].join('\n')
      : source
    for (const match of scripts.matchAll(/(?:\bwindow\s*\.\s*)?\b(alert|confirm|prompt)\s*\(/g)) {
      counts.dialogs++
      violations.push({ file, kind: 'dialog', source: match[0] })
    }
    const visit = node => {
      if (node.type === 1 && node.tagType === 0) {
        if (['select', 'datalist'].includes(node.tag)) {
          counts.elements++
          violations.push({ file, kind: node.tag })
        }
        if (node.tag === 'input') for (const prop of node.props) {
          const literal = prop.type === 6 && prop.name === 'type' ? prop.value?.content : undefined
          const binding = prop.type === 7 && prop.name === 'bind' && (prop.arg?.content === 'type' || !prop.arg)
          const staticBinding = binding ? /^(['"])([^'"\n]+)\1$/.exec(prop.exp?.content?.trim() || '')?.[2] : undefined
          const nativeType = (literal || staticBinding)?.toLowerCase()
          if (
            nativeType
              && ['checkbox','radio','date','time','datetime-local','month','week','color','range']
                .includes(nativeType)
              || binding && !staticBinding
          ) {
            counts.elements++
            violations.push({ file, kind: 'input-type', source: prop.loc.source })
          }
        }
      }
      for (const child of node.children || []) visit(child)
    }
    if (descriptor?.template?.ast) visit(descriptor.template.ast)
  }
  return { ...counts, violations }
}

if (main(import.meta.url)) {
  const production = scanNative(join(root, 'src'))
  const fixtures = scanNative(join(root, 'tests/fixtures/native'))
  const fixtureCounts = Object.fromEntries(walk(join(root, 'tests/fixtures/native')).map(file => [
    file.split('/').pop(),
    fixtures.violations.filter(v => v.file === file).length,
  ]))
  const caseFixtures = scanNative(join(root, 'tests/fixtures/native-case'))
  const caseFixtureCounts = Object.fromEntries(walk(join(root, 'tests/fixtures/native-case')).map(file => [
    file.split('/').pop(),
    caseFixtures.violations.filter(v => v.file === file).length,
  ]))
  console.log('G-native', JSON.stringify({ production, fixtureCounts, caseFixtureCounts }))
  process.exitCode = production.violations.length || Object.entries(fixtureCounts).some(
    ([name, count]) => name === 'component.vue' ? count !== 0 : count < 1,
  ) || Object.values(caseFixtureCounts).some(count => count !== 1) ? 1 : 0
}
