<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import XDrawer from '../../components/XDrawer.vue'
import { write } from './reads'
import type { Row } from './data'
const props = defineProps<{ modelValue: boolean; row?: Row }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; saved: [] }>()
const { t } = useI18n()
const name = ref(''), description = ref(''), error = ref(''), busy = ref(false)
watch(() => props.modelValue, open => {
  if (open) { name.value = props.row?.name ?? ''; description.value = props.row?.description ?? ''; error.value = '' }
})
async function save() {
  busy.value = true
  error.value = ''
  try {
    await write('threshold-templates' + (props.row ? '/' + props.row.id : ''), props.row ? 'PUT' : 'POST',
      { name: name.value.trim(), description: description.value },
      t(props.row ? 'prefixes.updated' : 'templates.created'))
    emit('update:modelValue', false)
    emit('saved')
  } catch (e) { error.value = (e as Error).message }
  finally { busy.value = false }
}
</script>
<template>
  <XDrawer :model-value="modelValue" :width="460" :busy="busy"
    :title="t(row ? 'templates.editName' : 'prefixes.create')" @update:model-value="emit('update:modelValue', $event)">
    <div class="form dt-form"><label class="field"><span>{{ t('prefixes.name') }}</span>
      <input v-model="name" :aria-label="t('prefixes.name')"></label>
      <label class="field"><span>{{ t('prefixes.description') }}</span><textarea v-model="description" /></label></div>
    <p v-if="error" class="crit mono" role="alert">{{ error }}</p>
    <template #footer><button class="btn" :disabled="busy" @click="emit('update:modelValue', false)">
      {{ t('common.cancel') }}</button><button class="btn primary" :disabled="busy || !name.trim()" @click="save">
        {{ t(row ? 'prefixes.save' : 'prefixes.create') }}</button></template>
  </XDrawer>
</template>
