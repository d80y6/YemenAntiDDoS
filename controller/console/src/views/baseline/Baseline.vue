<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, shallowRef } from 'vue'
import { useI18n } from 'vue-i18n'
import { isAdmin } from '../../auth'
import { api } from '../../api/data'
import { dtRate } from '../../format'
import XTip from '../thresholds/Tip.vue'
import XNumber from '../../components/XNumber.vue'
import XSwitch from '../../components/XSwitch.vue'
import XEmpty from '../../components/XEmpty.vue'
import { rounds } from '../mitigations/poll'
import { write } from '../thresholds/reads'
import type { Row } from '../thresholds/data'
import { defaultConfig, configBody, profiles, exceededValues, fields, slotLabel } from './data'
import '../thresholds/detection.css'
const { t, locale } = useI18n()
const info = ref(true), config = ref({ ...defaultConfig }), configLoaded = ref(false), configError = ref('')
const saving = ref(false), saveError = ref(''), status = shallowRef<Row>(), statusError = ref('')
const lifetime = new AbortController()
const rows = computed(() => profiles(status.value?.prefixes ?? null))
async function loadConfig() {
  configError.value = ''
  try {
    const value = await api<typeof defaultConfig>('dynamic-detection/config', {}, lifetime.signal)
    if (!lifetime.signal.aborted) { config.value = configBody(value); configLoaded.value = true }
  } catch (e) { if (!lifetime.signal.aborted) { configError.value = (e as Error).message; configLoaded.value = false } }
}
async function save() {
  if (!configLoaded.value || saving.value) return
  const snapshot = configBody(config.value)
  saving.value = true
  saveError.value = ''
  try {
    const result = await write('dynamic-detection/config', 'PUT', snapshot, t('baseline.saved'))
    config.value = configBody(result as typeof defaultConfig)
  } catch (e) { saveError.value = (e as Error).message }
  finally { saving.value = false }
}
const poll = rounds(async () => {
  try { return { value: await api<Row>('dynamic-detection/status', {}, lifetime.signal), error: '' } }
  catch (e) { return { value: undefined, error: (e as Error).message } }
}, 30000, result => {
  statusError.value = result.error
  if (result.value) status.value = result.value
})
onMounted(loadConfig)
onUnmounted(() => lifetime.abort())
</script>
<template>
  <div class="page detection baseline-page">
    <div class="page-head"><h1>{{ t('nav.baseline') }}
      <span v-if="locale === 'zh'" class="sub count">{{ t('baseline.subtitle') }}</span></h1></div>
    <section class="panel"><div class="panel-head"><h2>{{ t('baseline.infoTitle') }}</h2>
      <button class="btn sm ghost" :aria-expanded="info" @click="info = !info">
        {{ t(info ? 'baseline.less' : 'baseline.more') }}</button></div>
      <div v-if="info" class="info"><p>{{ t('baseline.infoDesc') }}</p><ul>
        <li v-for="key in ['infoEwma', 'infoSlots', 'infoDeviation', 'infoMinThreshold']" :key="key">
          {{ t('baseline.' + key) }}</li></ul></div></section>
    <section class="panel config"><h2>{{ t('baseline.config') }}</h2>
      <p v-if="configError" class="crit mono" role="alert">{{ configError }}
        <button class="btn sm" @click="loadConfig">{{ t('prefixes.retry') }}</button></p>
      <div class="meta"><span>{{ t('baseline.enabled') }}</span>
        <XSwitch v-model="config.enabled" :label="t('baseline.enabled')" :disabled="!isAdmin()" />
        <span>{{ t(config.enabled ? 'prefixes.enabled' : 'prefixes.disabled') }}</span></div>
      <div class="config-grid"><div v-for="field in fields" :key="field.key" class="field">
        <span>{{ t('baseline.' + field.key) }}<XTip :text="t('baseline.' + field.key + 'Tip')" wide /></span>
        <XNumber v-model="config[field.key]" :label="t('baseline.' + field.key)" :min="field.min" :max="field.max"
          :digits="field.digits" :disabled="!isAdmin()" /></div></div>
      <div class="meta"><button v-if="isAdmin()" class="btn primary sm"
        :disabled="!configLoaded || saving" :title="!configLoaded ? t('baseline.unloaded') : undefined" @click="save">
        {{ t(saving ? 'baseline.saving' : 'prefixes.save') }}</button>
        <p v-if="saveError" class="crit mono" role="alert">{{ saveError }}</p></div></section>
    <section class="panel profiles"><div class="panel-head"><h2>{{ t('baseline.profiles') }}</h2>
      <div class="toolbar"><span class="sub">{{ t('baseline.interval') }}</span>
        <button class="btn sm ghost" @click="poll.refresh">{{ t('baseline.refresh') }}</button></div></div>
      <p v-if="statusError" class="crit mono" role="alert">{{ statusError }}
        <button v-if="!status" class="btn sm" @click="poll.refresh">{{ t('prefixes.retry') }}</button></p>
      <div v-if="status" class="meta sub"><span>{{ t('baseline.slot') }}
        <b class="mono">{{ slotLabel(status.current_slot_label, t) }}</b> (#{{ status.current_slot }})</span>
        <span>{{ t('baseline.total') }} <b class="num">{{ status.total_prefixes }}</b></span>
        <span>{{ t('baseline.activated') }} <b class="ok num">{{ status.activated_count }}</b></span>
        <span>{{ t('baseline.learningCount') }} <b class="learn num">{{ status.learning_count }}</b></span></div>
      <div class="tbl-wrap"><table><thead><tr><th>{{ t('baseline.prefix') }}</th><th>{{ t('baseline.current') }}</th>
        <th>{{ t('baseline.expected') }}</th><th>{{ t('baseline.threshold') }}</th><th>{{ t('baseline.weeks') }}</th>
        <th>{{ t('prefixes.status') }}</th></tr></thead><tbody><tr v-for="row in rows" :key="row.prefix"
          :class="{ exceeded: row.status === 'exceeded' }"><td class="mono"><strong>{{ row.prefix }}</strong></td>
          <td class="r num">{{ dtRate(row.current_pps) }}</td><td class="r num">{{ dtRate(row.expected_pps) }}</td>
          <td class="r num">{{ dtRate(row.thresh_pps) }}</td><td class="r num">{{ row.sample_weeks }}</td>
          <td><span class="pill" :class="{ learn: row.status === 'learning', ok: row.status === 'normal',
            crit: row.status === 'exceeded', mono: !['learning', 'normal', 'exceeded'].includes(row.status) }">
            {{ ['learning', 'normal', 'exceeded'].includes(row.status)
              ? t('baseline.' + row.status) : row.status }}</span>
            <XTip v-if="row.status === 'exceeded'" :text="t('baseline.exceededTip', exceededValues(row))"
              direction="up-right" wide /></td>
        </tr></tbody></table><XEmpty v-if="!rows.length" /></div></section>
  </div>
</template>
