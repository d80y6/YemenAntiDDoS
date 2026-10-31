import { readdirSync, statSync, readFileSync } from 'node:fs'
import { resolve, join, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const moduleURL = import.meta.url
export const root = resolve(dirname(fileURLToPath(moduleURL)), '..')
export const out = resolve(process.env.XSIGHT_OUT || join(root, '../../..', 'out'))
export const walk = dir => readdirSync(dir).sort().flatMap(name => {
  const file = join(dir, name)
  return statSync(file).isDirectory() ? walk(file) : [file]
})
export const read = file => readFileSync(file, 'utf8')
export const json = file => JSON.parse(read(file))
export const main = url => !!process.argv[1] && url === pathToFileURL(resolve(process.argv[1])).href
