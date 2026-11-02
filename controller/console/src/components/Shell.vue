<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { state, clearSession, type Summary } from '../state'
import { request } from '../api/client'
import { usePoll } from '../composables/usePoll'
import { icons } from '../icons'
import { notify } from '../notifications'
import XTip from './XTip.vue'
import Appearance from './Appearance.vue'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const groups = [
  { name: 'monitoring', items: ['overview', 'traffic', 'attacks', 'mitigations', 'l7', 'nodes'] },
  { name: 'detection', items: ['prefixes', 'thresholds', 'baseline', 'flow'] },
  { name: 'response', items: ['responses', 'connectors'] },
  { name: 'system', items: ['users', 'audit'] },
]
const badges = computed(() => ({ attacks: state.summary?.active_attacks || 0, nodes: state.summary?.online_nodes || 0 }))
const actionMode = computed(() => state.summary?.action_mode === 'auto'
  ? t('common.auto')
  : state.summary?.action_mode === 'observe' ? t('nav.observe') : '—')

usePoll(
  () => request<Summary>('/api/stats/summary'),
  30000,
  summary => state.summary = summary,
  error => notify(error instanceof Error ? error.message : String(error), 'crit'),
)

function logout() {
  clearSession()
  void router.replace('/login')
}

function cycleTheme() {
  state.theme = state.theme === 'auto' ? 'light' : state.theme === 'light' ? 'dark' : 'auto'
}

function count(item: string) {
  return item === 'attacks' ? badges.value.attacks : item === 'nodes' ? badges.value.nodes : 0
}
</script>

<template>
  <div class="shell" :class="{ collapsed: state.sideCollapsed }">
    <aside class="side">
      <div class="brand">
        <span class="mark" aria-hidden="true" />
        <span class="lbl">YEMENANTIDDOS</span>
      </div>
      <nav class="nav" :aria-label="t('nav.main')">
        <template v-for="group in groups" :key="group.name">
          <div class="sec">{{ t(`nav.${group.name}`) }}</div>
          <RouterLink
            v-for="item in group.items"
            :key="item"
            :to="`/${item}`"
            :aria-current="route.path.split('/')[1] === item ? 'page' : undefined"
            :title="t(`nav.${item}`)"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true" v-html="icons[item]" />
            <span class="lbl">{{ t(`nav.${item}`) }}</span>
            <span
              v-if="count(item)"
              class="badge"
              :class="{ crit: item === 'attacks' }"
              :title="t(item === 'attacks' ? 'nav.attackCount' : 'nav.offlineCount', { n: count(item) })"
            >
              {{ count(item) }}
            </span>
          </RouterLink>
        </template>
      </nav>
      <div class="side-foot">
        <div class="mode">
          <span class="muted">
            {{ t('nav.action') }} <XTip :text="t('nav.modeTip')" direction="up-right" wide />
          </span>
          <span
            data-testid="action-mode"
            class="val"
            :class="{ auto: state.summary?.action_mode === 'auto', obs: state.summary?.action_mode === 'observe' }"
          >
            {{ actionMode }}
          </span>
        </div>
        <div class="appearance">
          <Appearance />
        </div>
        <div class="user">
          <span>{{ state.user?.username }}</span>
          <RouterLink to="/about">{{ t('pages.about') }}</RouterLink>
          <button type="button" class="text-button" @click="logout">{{ t('common.logout') }}</button>
        </div>
        <div class="side-mini">
          <button
            type="button"
            class="mini-b"
            :aria-label="`${t('common.theme')}: ${t(`common.${state.theme}`)}`"
            @click="cycleTheme"
          >◐</button>
          <button
            type="button"
            class="mini-b"
            :aria-label="t('common.language')"
            @click="state.locale = state.locale === 'ar' ? 'en' : 'ar'"
          >
            {{ state.locale === 'ar' ? 'عربي' : 'EN' }}
          </button>
          <button
            type="button"
            class="mini-b"
            :aria-label="`${state.user?.username} · ${t('common.logout')}`"
            @click="logout"
          >⇥</button>
        </div>
        <button
          type="button"
          class="side-tog"
          :aria-expanded="!state.sideCollapsed"
          :aria-label="t(state.sideCollapsed ? 'nav.expand' : 'nav.collapse')"
          @click="state.sideCollapsed = !state.sideCollapsed"
        >
          <span aria-hidden="true">{{ state.sideCollapsed ? '»' : '«' }}</span>
          <span class="lbl">{{ t('nav.collapse') }}</span>
        </button>
      </div>
    </aside>
    <main id="main" class="main">
      <slot />
    </main>
  </div>
</template>
