import { createI18n } from 'vue-i18n'
import { watch } from 'vue'
import zh from './zh'
import en from './en'
import { state } from '../state'
export const i18n = createI18n({ legacy: false, locale: state.locale, fallbackLocale: 'en', messages: { zh, en } })
watch(() => state.locale, value => { i18n.global.locale.value = value }, { flush: 'sync' })
