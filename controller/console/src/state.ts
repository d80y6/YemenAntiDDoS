import { reactive, watch } from 'vue'

export type Theme = 'auto' | 'light' | 'dark'
export type Locale = 'ar' | 'en'

export interface User {
  id: number
  username: string
  role: string
}

export interface Summary {
  active_attacks: number
  total_nodes: number
  online_nodes: number
  action_mode?: string
}

export function readTheme(storage: Storage): Theme {
  const raw = storage.getItem('theme')
  const mapped = raw === 'classic' ? 'light' : raw === 'amber' ? 'dark' : raw
  const theme = mapped === 'light' || mapped === 'dark' ? mapped : 'auto'
  if (raw !== theme) storage.setItem('theme', theme)
  return theme
}

export function readLocale(storage: Storage, language: string): Locale {
  const saved = storage.getItem('locale')
  if (saved === 'ar' || saved === 'en') return saved
  return language.toLowerCase().startsWith('ar') ? 'ar' : 'en'
}

function readUser(): User | null {
  try {
    return JSON.parse(localStorage.getItem('user') || 'null')
  } catch {
    return null
  }
}

export const state = reactive({
  token: localStorage.getItem('token') || '',
  user: readUser(),
  theme: readTheme(localStorage),
  locale: readLocale(localStorage, navigator.language),
  sideCollapsed: localStorage.getItem('xs-side') === '1',
  summary: null as Summary | null,
})

export function applyTheme(theme: Theme) {
  if (theme === 'auto') document.documentElement.removeAttribute('data-theme')
  else document.documentElement.dataset.theme = theme
}

applyTheme(state.theme)
watch(
  () => state.theme,
  theme => {
    localStorage.setItem('theme', theme)
    applyTheme(theme)
  },
  { flush: 'sync' },
)
watch(
  () => state.locale,
  locale => {
    localStorage.setItem('locale', locale)
    document.documentElement.lang = locale === 'ar' ? 'ar' : 'en'
    document.documentElement.dir = locale === 'ar' ? 'rtl' : 'ltr'
  },
  { immediate: true, flush: 'sync' },
)
watch(
  () => state.sideCollapsed,
  value => localStorage.setItem('xs-side', value ? '1' : '0'),
  { flush: 'sync' },
)

export function saveSession(token: string, user: User) {
  state.token = token
  state.user = user
  localStorage.setItem("token", token)
  localStorage.setItem("user", JSON.stringify(user))
}

export function clearSession() {
  state.token = ""
  state.user = null
  localStorage.removeItem("token")
  localStorage.removeItem("user")
}
