<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import { request } from '../../api/client'
import { fullDateTime } from '../../format'
import XListbox from '../../components/XListbox.vue'
import XPager from '../../components/XPager.vue'
import XPill from '../../components/XPill.vue'
import AuditDrawer from './AuditDrawer.vue'
import { actionTone, auditQuery, auditTime, diffPreview, entityTypes, userLabel,
  entityLabel, actionLabel } from './data'
import type { AuditFilters, AuditRow } from './data'
import { rawError } from '../users/data'
import type { UserRow } from '../users/data'
import './audit.css'
const { t } = useI18n()
const id = useId(), filters = reactive<AuditFilters>({}), draft = reactive({ from: '', to: '' })
const users = ref<UserRow[]>([]), rows = ref<AuditRow[]>([]), page = ref(1), hasNext = ref(false)
const loading = ref(false), error = ref(''), retained = ref(false), selected = ref<AuditRow>(), open = ref(false)
const types = computed(() => [{ value: '', label: t('audit.allTypes') },
  ...entityTypes.map(v => ({ value: v, label: entityLabel(v, t) }))])
const userOptions = computed(() => [{ value: '', label: t('audit.allUsers') },
  ...users.value.map(u => ({ value: String(u.id), label: u.username }))])
const from = computed(() => auditTime(filters.from)), to = computed(() => auditTime(filters.to))
const inverted = computed(() => from.value !== null && to.value !== null && from.value > to.value)
let sequence = 0, alive = true, controller = new AbortController()
const userController = new AbortController()
async function load(target = 1, filterChange = true) {
  const seq = ++sequence
  controller.abort()
  controller = new AbortController()
  error.value = ''
  retained.value = false
  if (filterChange) { rows.value = []; page.value = 1; hasNext.value = false }
  if (inverted.value) { loading.value = false; return }
  loading.value = true
  try {
    const result = await request<AuditRow[] | null>(auditQuery(filters, target), { signal: controller.signal })
    if (!alive || seq !== sequence) return
    rows.value = (result ?? []).slice(0, 50)
    hasNext.value = (result?.length ?? 0) > 50
    page.value = target
  } catch (reason) {
    if (!alive || seq !== sequence) return
    error.value = rawError(reason)
    retained.value = !filterChange
  } finally { if (alive && seq === sequence) loading.value = false }
}
async function loadUsers() {
  try {
    const result = await request<UserRow[] | null>('/api/users', { signal: userController.signal })
    if (alive) users.value = result ?? []
  } catch { if (alive) users.value = [] }
}
function commitTime(key: 'from' | 'to', clear = false) {
  if (clear) draft[key] = ''
  if (filters[key] === draft[key]) return
  filters[key] = draft[key]
  void load()
}
function selectFilter(key: 'entity_type' | 'user_id', value: string) {
  if (key === 'entity_type') value = entityTypes.find(v => ['ar', 'en']
    .some(locale => t('audit.entity.' + v, {}, { locale }) === value)) ?? value
  filters[key] = value
  void load()
}
onMounted(() => { void loadUsers(); void load() })
onUnmounted(() => { alive = false; sequence++; controller.abort(); userController.abort() })
defineExpose({ load })
const columns = ['id', 'user', 'entityType', 'entityId', 'action', 'version', 'createdAt', 'diff']
</script>
<template>
  <div class="page au-page">
    <div class="page-head"><h1>{{ t('audit.title') }}</h1></div>
    <div class="au-filters">
      <div class="field"><span>{{ t('audit.entityType') }}</span>
        <XListbox :model-value="filters.entity_type ?? ''" :options="types" mode="free" :label="t('audit.entityType')"
          @update:model-value="selectFilter('entity_type', $event)" /></div>
      <div class="au-range">
        <template v-for="key in (['from', 'to'] as const)" :key="key">
          <span v-if="key === 'to'" class="sub au-to">{{ t('audit.until') }}</span>
          <div class="field au-time"><label :for="id + '-' + key">{{ t('audit.' + key) }}</label>
            <div class="au-time-control"><input :id="id + '-' + key" v-model="draft[key]" class="mono"
              :placeholder="t('audit.' + key + 'Placeholder')"
              :aria-invalid="inverted || Number.isNaN(auditTime(filters[key]))"
              @blur="commitTime(key)" @keydown.enter.prevent="commitTime(key)">
              <button v-if="draft[key]" class="btn sm" :aria-label="t('audit.clear_' + key)"
                @click="commitTime(key, true)">×</button></div>
            <small v-if="Number.isNaN(auditTime(filters[key]))" class="sub">{{ t('audit.invalidTime') }}</small>
          </div>
        </template>
      </div>
      <div class="field"><span>{{ t('audit.user') }}</span>
        <XListbox :model-value="filters.user_id ?? ''" :options="userOptions" mode="search" :label="t('audit.user')"
          @update:model-value="selectFilter('user_id', $event)" /></div>
    </div>
    <p v-if="error && retained" class="crit" role="alert">{{ t('audit.queryFailed') }} {{ error }}
      {{ t('audit.retained', { page }) }}</p>
    <section class="panel" :aria-busy="loading"><div class="tbl-wrap"><table class="au-table">
      <thead><tr><th v-for="key in columns" :key="key">{{ t('audit.' + key) }}</th></tr></thead><tbody>
        <tr v-if="inverted || error && !retained"><td colspan="8" class="empty crit" role="alert">
          {{ inverted ? t('audit.inverted') : t('audit.queryFailed') + ' ' + error }}</td></tr>
        <template v-else>
          <tr v-for="row in rows" :key="row.id" @click="selected = row; open = true">
            <td class="num sub">{{ row.id }}</td><td class="mono"
              :class="{ sub: row.user_id !== null && !users.some(u => u.id === row.user_id) }">
              {{ userLabel(row.user_id, users) }}</td><td class="mono" :title="row.entity_type">
              {{ entityLabel(row.entity_type, t) }}</td>
            <td class="mono">{{ row.entity_id }}</td><td><XPill class="mono" :tone="actionTone(row.action)"
              :title="row.action">{{ actionLabel(row.action, t) }}</XPill></td>
            <td class="num">{{ row.delivery_version ?? '' }}</td>
            <td class="mono">{{ fullDateTime(row.created_at) }}</td>
            <td class="au-diff mono">{{ diffPreview(row.diff) }}</td>
          </tr>
          <tr v-if="!rows.length"><td colspan="8" class="empty">
            {{ t(loading ? 'common.loading' : 'common.empty') }}</td></tr>
        </template>
      </tbody></table></div>
      <div class="au-pager"><span class="sub">{{ t('audit.page', { page }) }}</span>
        <span v-if="loading" class="sub">{{ t('common.loading') }}</span>
        <XPager :model-value="page" :has-next="hasNext" :busy="loading" @update:model-value="load($event, false)" />
      </div>
    </section>
    <AuditDrawer v-if="selected" v-model="open" :row="selected" :users="users" />
  </div>
</template>
