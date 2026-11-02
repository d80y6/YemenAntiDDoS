<script setup lang="ts">
import { onUnmounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { request, safeNext } from '../api/client'
import { saveSession, type User } from '../state'
import XPassword from '../components/XPassword.vue'
import Appearance from '../components/Appearance.vue'

const { t } = useI18n()
const route = useRoute()
const router = useRouter()
const username = ref('')
const password = ref('')
const busy = ref(false)
const failed = ref(false)
let alive = true

onUnmounted(() => {
  alive = false
})

async function submit() {
  if (busy.value || !username.value.trim() || !password.value) return
  busy.value = true
  failed.value = false
  try {
    const result = await request<{ token: string; user: User }>('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username: username.value.trim(), password: password.value }),
    })
    if (!alive) return
    saveSession(result.token, result.user)
    password.value = ''
    await router.replace(safeNext(route.query.next))
  } catch {
    if (alive) failed.value = true
  } finally {
    if (alive) busy.value = false
  }
}
</script>

<template>
  <main class="login-wrap">
    <form class="login panel lg-card" @submit.prevent="submit">
      <div class="lg-brand">
        <span class="logo-full" aria-hidden="true" />
        <div class="lg-name">YEMENANTIDDOS</div>
        <div class="sub">{{ t('login.subtitle') }}</div>
      </div>
      <p v-if="route.query.notice === 'account-updated' || route.query.notice === 'account-deleted'"
        class="sub" role="status">{{ t(route.query.notice === 'account-updated'
          ? 'login.accountUpdated' : 'login.accountDeleted') }}</p>
      <label for="login-user" class="sub">{{ t('login.username') }}</label>
      <input
        id="login-user"
        v-model="username"
        type="text"
        autocomplete="username"
        :readonly="busy"
        spellcheck="false"
      >
      <label for="login-password" class="sub">{{ t('login.password') }}</label>
      <XPassword
        id="login-password"
        v-model="password"
        :label="t('login.password')"
        autocomplete="current-password"
        :disabled="busy"
      />
      <p v-if="failed" class="crit" role="alert">{{ t('login.invalid') }}</p>
      <button type="submit" class="btn primary lg-go" :disabled="busy" :aria-busy="busy">
        {{ t(busy ? 'login.busy' : 'login.signIn') }}
      </button>
      <div class="lg-foot">
        <span class="sub">{{ t('common.theme') }}</span>
        <Appearance />
      </div>
    </form>
  </main>
</template>
