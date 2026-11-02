import { afterEach, beforeEach, vi } from 'vitest'
import { enableAutoUnmount } from '@vue/test-utils'
import { state } from '../src/state'
import { notifications } from '../src/notifications'
import { drawerCount, activeConfirm } from '../src/components/overlay'

enableAutoUnmount(afterEach)
beforeEach(() => {
  localStorage.clear()
  state.token = ''
  state.user = null
  state.summary = null
  state.theme = 'auto'
  state.locale = 'ar'
  state.sideCollapsed = false
  notifications.splice(0)
  drawerCount.value = 0
  activeConfirm.value = null
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
    JSON.stringify({ active_attacks: 0, total_nodes: 0, online_nodes: 0 }),
    { status: 200 },
  )))
})
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  document.body.innerHTML = ''
})
