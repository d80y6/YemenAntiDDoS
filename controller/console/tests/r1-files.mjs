import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { root } from '../scripts/lib.mjs'
export const sourceExists = path => existsSync(join(root, path))
export const sourceText = path => readFileSync(join(root, path), 'utf8')
