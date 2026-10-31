import { createApp } from 'vue'
import App from './App.vue'
import { makeRouter } from './router'
import { configureClient } from './api/client'
import { i18n } from './i18n'
import '@fontsource/ibm-plex-sans/latin-400.css'
import '@fontsource/ibm-plex-sans/latin-500.css'
import '@fontsource/ibm-plex-sans/latin-600.css'
import '@fontsource/ibm-plex-mono/latin-400.css'
import '@fontsource/ibm-plex-mono/latin-500.css'
import '@fontsource/ibm-plex-mono/latin-600.css'
import './styles/tokens.css'
import './styles/base.css'
const router = makeRouter()
configureClient(router)
createApp(App).use(router).use(i18n).mount('#app')
