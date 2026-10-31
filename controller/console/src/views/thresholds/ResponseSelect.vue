<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import XListbox from '../../components/XListbox.vue'
import { numericID, type Row } from './data'
import { write } from './reads'
const props = defineProps<{ row: Row; responses: Row[]; rule?: boolean }>()
const emit = defineEmits<{ saved: []; error: [value: string] }>()
const { t } = useI18n()
const value = ref(String(props.row.response_id ?? '')), busy = ref(false), error = ref('')
const saved = ref(value.value)
watch(() => props.row.response_id, v => { saved.value = String(v ?? ''); value.value = saved.value })
const choices = computed(() => [{ value: '', label: t(props.rule ? 'thresholds.useDefault' : 'thresholds.noResponse') },
  ...props.responses.map(r => ({ value: String(r.id), label: r.name }))])
async function save(next: string) {
  const previous = saved.value
  value.value = next
  busy.value = true
  error.value = ''
  emit('error', '')
  try {
    await write((props.rule ? 'threshold-rules/' : 'threshold-templates/') + props.row.id, 'PUT',
      { response_id: numericID(next) }, t(props.rule ? 'templates.ruleResponseUpdated' : 'templates.defaultUpdated'))
    saved.value = next
    emit('saved')
  } catch (e) {
    value.value = previous
    error.value = (e as Error).message
    emit('error', error.value)
  } finally { busy.value = false }
}
</script>
<template>
  <XListbox :model-value="value" :options="choices" :disabled="busy || !isAdmin()"
    :label="t(rule ? 'thresholds.response' : 'thresholds.defaultResponse')" @update:model-value="save" />
  <p v-if="!rule && error" class="crit mono" role="alert">{{ error }}</p>
</template>
