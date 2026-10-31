<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { downsample } from './math'
const props = withDefaults(defineProps<{ values: number[]; width?: number; height?: number }>(),
  { width: 120, height: 32 })
const { t } = useI18n()
const path = computed(() => {
  const points = downsample(props.values, 90)
  const max = Math.max(1, ...points)
  return points.map((value, i) => {
    const x = i / Math.max(1, points.length - 1) * props.width
    return `${i ? 'L' : 'M'}${x},${props.height - 2 - value / max * (props.height - 4)}`
  })
    .join(' ')
})
</script>
<template>
  <svg v-if="values.length" :viewBox="`0 0 ${width} ${height}`"
    :style="{ width: `${width}px`, height: `${height}px` }" role="img" :aria-label="t('chart.trend')">
    <path :d="path" /><circle v-if="values.length === 1" cx="0" :cy="values[0] ? 2 : height - 2" r="2" />
  </svg>
  <span v-else class="sub">{{ t('chart.noRecent') }}</span>
</template>
<style scoped>
svg { width: 120px; height: 32px; fill: var(--dec-total); }
path { stroke: var(--dec-total); stroke-width: 1.4; fill: none; }
</style>
