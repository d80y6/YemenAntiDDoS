import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { root, out, main, json } from './lib.mjs'

export function validVitestReport(r) {
  return r?.success === true
    && r.numPassedTests > 0
    && r.numFailedTests === 0
    && r.numPendingTests === 0
    && r.numTodoTests === 0
}

export function verifyInstalled() {
  const pkg = json(join(root, 'package.json'))
  const lock = json(join(root, 'package-lock.json'))
  const mismatches = []
  for (const section of ['dependencies', 'devDependencies']) if (
    JSON.stringify(pkg[section]) !== JSON.stringify(lock.packages[''][section])
  ) mismatches.push(section)
  let checked = 0
  let optionalAbsent = 0
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue
    const file = join(root, path, 'package.json')
    if (!existsSync(file) && entry.optional) {
      optionalAbsent++
      continue
    }
    if (!existsSync(file) || json(file).version !== entry.version) mismatches.push(path)
    else checked++
  }
  return { lockfileVersion: lock.lockfileVersion, checked, optionalAbsent, mismatches }
}

if (main(import.meta.url)) {
  mkdirSync(out, { recursive: true })
  const installed = verifyInstalled()
  console.log('installed-lock', JSON.stringify(installed))
  let failed = installed.lockfileVersion !== 3 || installed.mismatches.length > 0
  for (const [name, file, args] of [
    ['vue-tsc', 'vue-tsc/bin/vue-tsc.js', ['--noEmit']],
    ['vitest', 'vitest/vitest.mjs', ['run', '--reporter=json', `--outputFile=${join(out, 'vitest.json')}`]],
    ['vite', 'vite/bin/vite.js', ['build']],
  ]) {
    if (name === 'vitest') rmSync(join(out, 'vitest.json'), { force: true })
    const command = join(root, 'node_modules', file)
    const run = spawnSync(process.execPath, [command, ...args], { cwd: root, encoding: 'utf8', env: process.env })
    const raw = (run.stdout || '') + (run.stderr || '')
    const diagnostics = raw.split('\n').filter(line => /error TS\d+/.test(line)).length
    writeFileSync(join(out, name + '.log'), raw)
    console.log(`${process.execPath} ${command} ${args.join(' ')} RC=${run.status} diagnostics=${diagnostics}`)
    failed ||= run.status !== 0 || diagnostics !== 0
    if (name === 'vitest') {
      try {
        const r = json(join(out, 'vitest.json'))
        console.log(`vitest passed=${r.numPassedTests} failed=${
          r.numFailedTests
        } skipped=${r.numPendingTests} todo=${r.numTodoTests}`)
        failed ||= !validVitestReport(r)
      } catch {
        failed = true
      }
    }
  }
  process.exitCode = failed ? 1 : 0
}
