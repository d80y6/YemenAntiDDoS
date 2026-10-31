<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { request } from '../../api/client'
import { isAdmin } from '../../auth'
import { clearSession, state } from '../../state'
import { notifyWrite } from '../../notifications'
import XPill from '../../components/XPill.vue'
import XTip from '../../components/XTip.vue'
import XConfirm from '../../components/XConfirm.vue'
import UserDrawer from './UserDrawer.vue'
import { adminGuard, beginUserWrite, deleteUser, endUserWrite, isSelf, rawError, saveUser,
  userGate, userValidation } from './data'
import type { UserForm, UserRow } from './data'
import './users.css'
const { t } = useI18n()
const router = useRouter()
const users = ref<UserRow[]>([]), error = ref(''), loading = ref(false), loaded = ref(false)
const readGen = ref(-1), appliedSequence = ref(0), sequence = ref(0)
const open = ref(false), editing = ref<UserRow>(), confirm = ref<number>(), busy = ref(false)
let alive = true, controller = new AbortController()
const writable = computed(() => userGate.inFlight === 0 && loaded.value
  && readGen.value === userGate.writeGen && appliedSequence.value === sequence.value)
async function load() {
  if (!state.token) return
  const seq = ++sequence.value, gen = userGate.writeGen
  controller.abort()
  controller = new AbortController()
  loading.value = true
  error.value = ''
  loaded.value = false
  try {
    const rows = await request<UserRow[] | null>('/api/users', { signal: controller.signal })
    if (!alive || seq !== sequence.value) return
    users.value = rows ?? []
    loaded.value = true
    readGen.value = gen
    appliedSequence.value = seq
  } catch (reason) {
    if (alive && seq === sequence.value) { error.value = rawError(reason); loaded.value = false }
  } finally { if (alive && seq === sequence.value) loading.value = false }
}
watch(() => userGate.writeGen, () => {
  if (userGate.inFlight === 0 && state.token) void load()
})
onMounted(load)
onUnmounted(() => { alive = false; sequence.value++; controller.abort() })
function edit(row?: UserRow, event?: MouseEvent) {
  if (!isAdmin() || event && (event.target as HTMLElement).closest('button,[role=alertdialog]')) return
  editing.value = row
  open.value = true
}
async function perform(row: UserRow | undefined, operation: () => Promise<unknown>, message: string, deleted = false) {
  const self = row !== undefined && isSelf(row)
  beginUserWrite()
  busy.value = true
  try {
    await notifyWrite(operation(), message)
    if (self) {
      clearSession()
      await router.replace({ path: '/login', query: deleted ? { notice: 'account-deleted' }
        : { notice: 'account-updated', next: '/users' } })
    }
    return true
  } finally {
    busy.value = false
    endUserWrite()
  }
}
async function save(form: UserForm, row?: UserRow) {
  if (!isAdmin() || !writable.value) return false
  const invalid = userValidation(form, row) || (row ? adminGuard(users.value, row, form) : '')
  if (invalid) throw new Error(t(invalid))
  return perform(row, () => saveUser(form, row), t(row ? 'users.updated' : 'users.created'))
}
async function remove(row: UserRow) {
  if (!isAdmin() || !writable.value || adminGuard(users.value, row, 'delete')) return
  await perform(row, () => deleteUser(row.id), t('users.deleted'), true)
}
defineExpose({ remove, save, load, edit, users, writable })
</script>
<template>
  <div class="page us-page">
    <div class="page-head"><h1>{{ t('users.title') }}</h1>
      <button v-if="isAdmin()" class="btn primary" :disabled="!writable" @click="edit()">
        {{ t('users.add') }}</button></div>
    <p v-if="error" class="crit" role="alert">{{ error }}
      <button class="btn" @click="load">{{ t('users.retry') }}</button></p>
    <section class="panel" :aria-busy="loading">
      <div class="tbl-wrap"><table class="us-table"><thead><tr>
        <th>{{ t('users.id') }}</th><th>{{ t('users.username') }}</th>
        <th>{{ t('users.role') }} <XTip :text="t('users.roleTip')" wide /></th>
        <th>{{ t('users.status') }}</th><th v-if="isAdmin()">{{ t('users.delete') }}</th>
      </tr></thead><tbody>
        <template v-for="row in users" :key="row.id">
          <tr :class="{ 'us-clickable': isAdmin() }" :data-user="row.id" @click="edit(row, $event)">
            <td class="num sub">{{ row.id }}</td><td><strong class="mono">{{ row.username }}</strong>
              <span v-if="isSelf(row)" class="sub">{{ t('users.you') }}</span></td>
            <td><XPill class="mono"
              :tone="row.role === 'admin' ? 'crit' : row.role === 'operator' ? 'warn' : 'neutral'">
              {{ row.role }}</XPill> <span class="sub">
                {{ t(row.role === 'admin' ? 'users.writable' : 'users.readonly') }}
              </span></td>
            <td><span class="us-status" :class="row.enabled ? 'ok' : 'sub'">
              {{ t(row.enabled ? 'users.enabled' : 'users.disabled') }}</span></td>
            <td v-if="isAdmin()"><button class="btn sm danger"
              :disabled="!writable || !!adminGuard(users, row, 'delete')" @click="confirm = row.id">
              {{ t('users.delete') }}</button>
              <small v-if="adminGuard(users, row, 'delete')" class="sub us-last">
                {{ t('users.lastDelete') }}</small></td>
          </tr>
          <tr v-if="confirm === row.id && isAdmin()"><td colspan="5">
            <XConfirm :model-value="true" :title="t('users.deleteTitle', { name: row.username })"
              :description="isSelf(row) ? t('users.deleteSelf') : ''" :action="() => remove(row)"
              :confirm-label="t('users.delete')" tone="danger" @update:model-value="confirm = undefined" /></td></tr>
        </template>
        <tr v-if="!users.length"><td :colspan="isAdmin() ? 5 : 4" class="empty">
          {{ t(loading ? 'common.loading' : 'common.empty') }}</td></tr>
      </tbody></table></div>
    </section>
    <UserDrawer v-model="open" :row="editing" :users="users" :writable="writable" :busy="busy" :save="save" />
  </div>
</template>
