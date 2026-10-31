import { expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'
import Login from '../src/views/Login.vue'
import { makeRouter } from '../src/router'
import { i18n } from '../src/i18n'
import { state } from '../src/state'
import { render } from './helpers'
it.each([
  ['zh', 'account-updated', '你的账号已更新，请重新登录。'], ['zh', 'account-deleted', '你的账号已删除。'],
  ['en', 'account-updated', 'Your account has been updated. Please sign in again.'],
  ['en', 'account-deleted', 'Your account has been deleted.'],
  ['zh', 'anything-else', ''], ['en', 'anything-else', ''], ['zh', '', ''], ['en', '', ''],
])('G-login notice %s %s V28', async (locale, notice, expected) => {
  state.locale = locale as 'zh' | 'en'
  const router = makeRouter(createMemoryHistory())
  await router.push('/login' + (notice ? '?notice=' + notice : ''))
  const w = render(Login, { global: { plugins: [i18n, router] } })
  await flushPromises()
  expect(w.find('[role=status]').exists()).toBe(!!expected)
  if (expected) expect(w.get('[role=status]').text()).toBe(expected)
})
