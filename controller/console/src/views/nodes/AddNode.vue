<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import XDrawer from '../../components/XDrawer.vue'
import XSeg from '../../components/XSeg.vue'
import XCopy from '../../components/XCopy.vue'
import { request } from '../../api/client'
import { notify } from '../../notifications'
import { generateKey, snippet, validNodeId } from './data'
const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: boolean]; saved: [] }>()
const { t } = useI18n()
const form = reactive({ id: '', api_key: '', mode: 'xdp', description: '' }), error = ref(''), busy = ref(false)
const open = computed({ get: () => props.modelValue, set: value => emit('update:modelValue', value) })
watch(open, value => { if (value) { Object.assign(form, { id: '', api_key: '', mode: 'xdp', description: '' })
  error.value = '' } })
const valid = computed(() => form.id.trim() && form.api_key.trim() && validNodeId(form.id))
const config = computed(() => snippet(form.id, form.api_key, form.mode, t))
async function save() {
  if (!valid.value || busy.value) return
  busy.value = true
  error.value = ''
  try {
    await request('/api/nodes', { method: 'POST', body: JSON.stringify({ ...form }) })
    notify(t('nodes.created'))
    open.value = false
    Object.assign(form, { id: '', api_key: '', mode: 'xdp', description: '' })
    emit('saved')
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e)
    notify(error.value, 'crit')
  } finally { busy.value = false }
}
</script>
<template>
  <XDrawer v-model="open" :width="460" :title="t('nodes.addNode')" :busy="busy">
    <div class="form">
      <label class="field"><span>{{ t('nodes.id') }}</span><input v-model="form.id" autocomplete="off"
        :placeholder="t('nodes.idPlaceholder')"><small class="sub">{{ t('nodes.idHint') }}</small></label>
      <p v-if="!validNodeId(form.id)" class="crit" role="alert">{{ t('nodes.invalidId') }}</p>
      <div class="field"><span>{{ t('nodes.mode') }}</span><XSeg v-model="form.mode" :label="t('nodes.mode')"
        :options="[{ value: 'xdp', label: 'XDP' }, { value: 'flow', label: 'Flow' }]" />
        <small class="sub">{{ t(form.mode === 'flow' ? 'nodes.flowHint' : 'nodes.xdpHint') }}</small></div>
      <label class="field"><span>{{ t('nodes.description') }}</span><input v-model="form.description"
        :placeholder="t('nodes.descriptionPlaceholder')"></label>
      <div class="field"><label for="node-key">{{ t('nodes.apiKey') }}</label><div class="keyrow">
        <input id="node-key" v-model="form.api_key" class="mono" autocomplete="off">
        <button class="btn sm" @click="form.api_key = generateKey()">{{ t('nodes.generate') }}</button>
        <XCopy :text="form.api_key" /></div><small class="sub">{{ t('nodes.keyHint') }}</small></div>
    </div>
    <div class="dh"><h3>{{ t('nodes.snippetTitle') }}</h3><XCopy :text="config" /></div>
    <pre class="raw">{{ config }}</pre>
    <p v-if="error" class="crit mono" role="alert">{{ error }}</p>
    <template #footer><p class="sub">{{ t('nodes.saveHint') }}</p><div class="toolbar">
      <button class="btn" :disabled="busy" @click="open = false">{{ t('common.cancel') }}</button>
      <button class="btn primary" :disabled="!valid || busy" @click="save">{{ t('nodes.add') }}</button>
    </div></template>
  </XDrawer>
</template>
<style scoped>
.form { display: flex; flex-direction: column; gap: 12px; }
.field { display: flex; flex-direction: column; align-items: stretch; gap: 5px; }
input { width: 100%; min-width: 0; box-sizing: border-box; }
.keyrow, .dh { display: flex; align-items: center; gap: 6px; }
.dh { justify-content: space-between; margin-top: 16px; }
h3 { font-size: 13px; font-weight: 500; }
.raw { white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
