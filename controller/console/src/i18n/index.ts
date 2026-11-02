import { createI18n } from 'vue-i18n'
import en from './en'
import ar from './ar'
import { state } from '../state'

export const i18n = createI18n({ legacy: false, locale: state.locale, fallbackLocale: 'en', messages: { ar, en } })
