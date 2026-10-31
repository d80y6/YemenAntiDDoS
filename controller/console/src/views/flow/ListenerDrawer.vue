<script setup lang="ts">
import { computed, reactive, ref, useId, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import { notifyWrite } from '../../notifications'
import XDrawer from '../../components/XDrawer.vue'
import XSeg from '../../components/XSeg.vue'
import { listenerForm, listenerValidation, rawError, saveListener } from './data'
import type { Listener } from './data'
const props = defineProps<{ modelValue: boolean; node: string; row?: Listener }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; saved: [] }>()
const { t } = useI18n()
const id = useId()
const form = reactive(listenerForm(props.node))
const busy = ref(false), message = ref(''), tone = ref('crit')
const disabled = computed(() => busy.value || !isAdmin())
const title = computed(() => props.row
  ? t(isAdmin() ? 'flow.editListener' : 'flow.viewListener', { address: props.row.listen_address })
  : t('flow.addListener'))
const options = computed(() => [
  ['auto', t('flow.modeAuto')], ['sflow', 'sFlow'], ['netflow', 'NetFlow'], ['ipfix', 'IPFIX'],
]
  .map(([value, label]) => ({ value: value!, label: label!, disabled: disabled.value })))
watch(() => props.modelValue, open => {
  if (open) { Object.assign(form, listenerForm(props.node, props.row)); message.value = '' }
})
async function save() {
  if (disabled.value) return
  const invalid = listenerValidation(form)
  if (invalid) { message.value = t(invalid); tone.value = 'warn'; return }
  busy.value = true
  message.value = ''
  try {
    await notifyWrite(saveListener(form, props.row), t(props.row ? 'flow.updated' : 'flow.listenerCreated'))
    emit('update:modelValue', false)
    emit('saved')
  } catch (error) { message.value = rawError(error); tone.value = 'crit' }
  finally { busy.value = false }
}
</script>
<template>
  <XDrawer :model-value="modelValue" :title="title" :width="460" :busy="busy"
    @update:model-value="emit('update:modelValue', $event)">
    <div class="form fl-form">
      <label class="field" :for="id + '-address'"><span>{{ t('flow.address') }}</span>
        <input :id="id + '-address'" v-model="form.listen_address" class="mono" placeholder=":2055"
          autocomplete="off" :disabled="disabled">
        <small class="sub">{{ t('flow.addressHint') }}</small></label>
      <div class="field"><span :id="id + '-protocol'">{{ t('flow.protocol') }}</span>
        <XSeg v-model="form.protocol_mode" :options="options" :label="t('flow.protocol')"
          :aria-labelledby="id + '-protocol'" /></div>
      <label class="field" :for="id + '-description'"><span>{{ t('flow.description') }}</span>
        <input :id="id + '-description'" v-model="form.description" :disabled="disabled" autocomplete="off"></label>
    </div>
    <template #footer>
      <div class="fl-footer">
        <small class="sub">{{ row ? t('flow.listenerEditNote', { id: node }) : t('flow.listenerNewNote') }}</small>
        <p v-if="message" :class="tone" role="alert">{{ message }}</p>
        <div class="toolbar">
          <button class="btn" :disabled="busy" @click="emit('update:modelValue', false)">{{ t('flow.cancel') }}</button>
          <button v-if="isAdmin()" class="btn primary" :disabled="busy" @click="save">
            {{ t(busy ? 'flow.saving' : 'flow.save') }}</button>
        </div>
      </div>
    </template>
  </XDrawer>
</template>
