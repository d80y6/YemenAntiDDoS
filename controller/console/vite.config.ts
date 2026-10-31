import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { execFileSync } from 'node:child_process'
import { generateThirdParty, serveThirdParty } from './scripts/third-party.mjs'
function version() { return process.env.XSIGHT_VERSION || execFileSync('git', ['describe', '--always'], { encoding: 'utf8' }).trim() }
export default defineConfig(async ({ command, mode }) => ({
  base: '/',
  define: { __XS_VERSION__: JSON.stringify(version()) },
  plugins: [vue(), { name: 'third-party', generateBundle: generateThirdParty, configureServer: serveThirdParty }, ...(command === 'serve' && mode === 'development' ? [(await import('./mock/server')).mockPlugin()] : [])],
  build: { outDir: 'dist', emptyOutDir: true, assetsInlineLimit: 0 },
  server: { host: '127.0.0.1', port: 5173, strictPort: true, ...(process.env.XSIGHT_API ? { proxy: { '/api': process.env.XSIGHT_API } } : {}) },
  test: { environment: 'jsdom', include: ['tests/**/*.test.ts'], setupFiles: ['tests/setup.ts'], restoreMocks: true },
}))
