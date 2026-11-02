import './shim'
import { createWebHashHistory } from 'vue-router'
import { createApp } from 'vue'
import App from '../src/App.vue'
import { makeRouter } from '../src/router'
import { configureClient } from '../src/api/client'
import { i18n } from '../src/i18n'
import '@fontsource/ibm-plex-sans/latin-400.css'
import '@fontsource/ibm-plex-sans/latin-500.css'
import '@fontsource/ibm-plex-sans/latin-600.css'
import '@fontsource/ibm-plex-mono/latin-400.css'
import '@fontsource/ibm-plex-mono/latin-500.css'
import '@fontsource/ibm-plex-mono/latin-600.css'
import '../src/styles/tokens.css'
import '../src/styles/base.css'
const router = makeRouter(createWebHashHistory())
configureClient(router)
createApp(App).use(router).use(i18n).mount('#app')
// demo-banner:start
import { watch } from 'vue'
const banner = document.createElement('div')
banner.id = 'xs-demo-banner'
banner.style.cssText = 'position:fixed;bottom:12px;right:16px;z-index:3000;padding:5px 9px;border-radius:4px;background:var(--panel);color:var(--muted);border:1px solid var(--line);font-size:12px;pointer-events:none'
document.body.append(banner)
watch(i18n.global.locale, locale => {
  banner.textContent = locale === 'ar' ? '演示 · 示例数据' : 'Demo · sample data'
  // Keep the document language in step with the UI so translation prompts and screen readers match.
  document.documentElement.lang = locale === 'ar' ? 'zh-CN' : 'en'
}, { immediate: true })
// demo-banner:end
