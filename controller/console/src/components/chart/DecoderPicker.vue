<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import XCheck from '../XCheck.vue'
import { DECODERS } from '../../config/decoders'
import { selection, choose, CAP } from './selection'
import { lineColor } from './math'
const { t } = useI18n()
const open = ref(false)
const root = ref<HTMLElement>()
const full = computed(() => selection.keys.filter(k => k !== 'total').length >= CAP)
const groups = ['summary', 'l4', 'flags', 'ip', 'anomaly']
function toggle(key: string, checked: boolean) {
  if (checked && key !== 'total' && full.value) return
  choose(checked ? [...selection.keys, key] : selection.keys.filter(k => k !== key))
}
function outside(e: Event) { if (!root.value?.contains(e.target as Node)) open.value = false }
onMounted(() => document.addEventListener('pointerdown', outside))
onUnmounted(() => document.removeEventListener('pointerdown', outside))
</script>
<template>
  <div ref="root" class="decoder-picker" @keydown.esc.stop="open = false">
    <button class="btn sm" :aria-expanded="open" @click="open = !open">{{ t('chart.decoders') }}</button>
    <div v-if="open" role="dialog" :aria-label="t('chart.decoders')" class="decoder-pop">
      <fieldset v-for="group in groups" :key="group">
        <legend>{{ t('chart.' + group) }}</legend>
        <div v-for="d in DECODERS.filter(d => d.group === group)" :key="d.key" class="decoder-item">
          <i :style="{ background: lineColor(d.key, selection.slots) }" />
          <XCheck :label="d.key === 'total' ? t('chart.total') : d.key" :model-value="selection.keys.includes(d.key)"
            :disabled="full && d.key !== 'total' && !selection.keys.includes(d.key)"
            @update:model-value="toggle(d.key, $event)" />
        </div>
      </fieldset>
      <p v-if="full" class="sub" role="status">{{ t('chart.cap') }}</p>
      <div class="toolbar">
        <button class="text-button" @click="choose([])">{{ t('chart.clear') }}</button>
        <button class="text-button" @click="choose(['tcp', 'udp'])">{{ t('chart.defaults') }}</button>
      </div>
    </div>
  </div>
</template>
<style scoped>
.decoder-picker { position: relative; }
.decoder-pop {
  position: absolute; right: 0; top: 100%; z-index: 30; width: 280px; max-width: calc(100vw - 40px);
  background: var(--panel); border: 1px solid var(--line); padding: 12px; box-shadow: 0 6px 20px var(--shadow);
}
fieldset { border: 0; padding: 4px 0; margin: 0; display: flex; gap: 8px; flex-wrap: wrap; }
legend { color: var(--muted); font-size: 11px; }
.decoder-item { display: flex; align-items: center; gap: 4px; }
i { width: 7px; height: 7px; border-radius: 50%; }
</style>
