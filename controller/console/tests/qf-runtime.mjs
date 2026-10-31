import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { root, out } from '../scripts/lib.mjs'
export function cliContract(positive = false) {
  const args = positive ? [join(root, 'scripts/contract-positive.mjs')]
    : [join(root, 'scripts/contract-check.mjs'), '--attack', '2', '--node', 'edge-a',
      '--response', '3', '--listener', '1', '--report', join(out, 'qf-cli-contract.json')]
  const run = spawnSync(process.execPath, args, { cwd: root, env: process.env, encoding: 'utf8' })
  return { status: run.status, text: run.stdout + run.stderr }
}
