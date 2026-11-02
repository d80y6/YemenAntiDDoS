import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { execFileSync } from 'node:child_process'
import { generateThirdParty } from './scripts/third-party.mjs'

const version = process.env.XSIGHT_VERSION || execFileSync('git', ['describe', '--always'], { encoding: 'utf8' }).trim()
export default defineConfig({
  base: '/YemenAntiDDoS/',
  define: { __XS_VERSION__: JSON.stringify(version + '-demo') },
  plugins: [vue(), { name: 'third-party', generateBundle: generateThirdParty }, {
    name: 'demo-root-html',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const html = bundle['demo/index.html']
      if (!html || html.type !== 'asset') this.error('Missing demo/index.html')
      html.fileName = 'index.html'
    },
  }],
  build: { rollupOptions: { input: 'demo/index.html' }, outDir: 'demo-dist', emptyOutDir: true, assetsInlineLimit: 0 },
})
