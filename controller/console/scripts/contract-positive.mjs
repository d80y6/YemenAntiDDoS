import { spawnSync } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { root, out } from './lib.mjs'
mkdirSync(out, { recursive: true })
const source = readFileSync(join(root, 'src/api/contract.ts'), 'utf8')
const copy = join(out, 'contract-positive.ts'), report = join(out, 'contract-positive.json')
writeFileSync(copy, source.replace('"path": "active_attacks"', '"path": "active_attacks_typo"'))
const run = spawnSync(process.execPath, [join(root, 'scripts/contract-check.mjs'), '--contract', copy,
  '--report', report, '--attack', '2', '--node', 'edge-a', '--response', '3', '--listener', '1'],
  { cwd: root, env: process.env, encoding: 'utf8' })
writeFileSync(join(out, 'contract-positive.log'), (run.stdout || '') + (run.stderr || ''))
const result = JSON.parse(readFileSync(report, 'utf8'))
const failures = result.results.filter(r => !r.passed).map(r => [r.path, r.state])
const passed = run.status === 1 && JSON.stringify(failures) === JSON.stringify([['active_attacks_typo', 'missing']])
console.log('G-contract-positive', JSON.stringify({ passed, exit: run.status, failures }))
process.exitCode = passed ? 0 : 1
