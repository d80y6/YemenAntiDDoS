<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import XDrawer from '../../components/XDrawer.vue'
import { fullDateTime } from '../../format'
import { userLabel, entityLabel, actionLabel } from './data'
import type { AuditRow } from './data'
import type { UserRow } from '../users/data'
defineProps<{ modelValue: boolean; row: AuditRow; users: UserRow[] }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()
const { t } = useI18n()
</script>
<template>
  <XDrawer :model-value="modelValue" :width="600"
    :title="t('audit.detail', { type: entityLabel(row.entity_type, t), id: row.entity_id })"
    @update:model-value="emit('update:modelValue', $event)">
    <dl class="au-kv">
      <template v-for="[key, value] in [['id', row.id], ['user', userLabel(row.user_id, users)],
        ['entityType', entityLabel(row.entity_type, t)], ['entityId', row.entity_id],
        ['action', actionLabel(row.action, t)],
        ['version', row.delivery_version ?? '—'], ['createdAt', fullDateTime(row.created_at)]]" :key="String(key)">
        <dt class="sub">{{ t('audit.' + key) }}</dt><dd class="mono">{{ value }}</dd>
      </template>
    </dl>
    <h3>{{ t('audit.diff') }}</h3>
    <pre class="au-json mono">{{ row.diff === null ? '-' : JSON.stringify(row.diff, null, 2) }}</pre>
  </XDrawer>
</template>
