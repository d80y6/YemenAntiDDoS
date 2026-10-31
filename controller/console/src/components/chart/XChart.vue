<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted, useId } from 'vue'
import { useI18n } from 'vue-i18n'
import XEmpty from '../XEmpty.vue'
import { thousands } from '../../format'
import { type Point, type Band, type Window, niceStep, mergeBands, segments, nearest, maximum,
  zoomWindow, formatTick, lineColor } from './math'
const props = withDefaults(defineProps<{
  points: Point[]; selected: string[]; slots: Record<string, number>; bands?: Band[]; bounds: Window
  window?: Window | null; metric?: string; grain?: number; sharedMax?: number; zoomable?: boolean
  loading?: boolean; error?: string; outbound?: boolean; threshold?: number
}>(), { metric: 'pps', grain: 5000, bands: () => [] })
const emit = defineEmits<{ 'update:window': [value: Window | null] }>()
const { t } = useI18n()
const host = ref<HTMLElement>()
const width = ref(600)
const height = 200
const hover = ref<number | null>(null)
const drag = ref<number | null>(null)
const hintId = useId(), announcement = ref('')
let keyboardDrag = false
const view = computed(() => props.window || props.bounds)
const visible = computed(() => props.points.filter(p => p.time >= view.value[0] && p.time <= view.value[1]))
const empty = computed(() => props.loading || props.error || !props.selected.length || !visible.value.length)
const keys = computed(() => [...props.selected].sort((a, b) => Number(b === 'total') - Number(a === 'total')))
const max = computed(() => Math.max(props.sharedMax ?? maximum(visible.value, props.selected), props.threshold ?? 0))
const step = computed(() => niceStep(max.value * 1.06 / 4))
const ceiling = computed(() => max.value === 0 ? 1 : step.value * 4)
const ticks = computed(() => max.value === 0 ? [0, 1] : [0, 1, 2, 3, 4].map(n => n * step.value))
const x = (time: number) => 44 + (time - view.value[0]) / (view.value[1] - view.value[0] || 1) * (width.value - 52)
const y = (value: number) => height - 20 - value / ceiling.value * (height - 28)
const timeAt = (event: PointerEvent) => {
  const box = host.value!.getBoundingClientRect()
  const px = Math.max(44, Math.min(width.value - 8, event.clientX - box.left))
  return view.value[0] + (px - 44) / (width.value - 52) * (view.value[1] - view.value[0])
}
const lines = computed(() => segments(visible.value, props.grain))
const merged = computed(() => props.outbound ? [] : mergeBands(props.bands, props.bounds[1])
  .filter(b => b[1] >= view.value[0] && b[0] <= view.value[1]))
const at = computed(() => hover.value === null ? undefined : nearest(visible.value, hover.value))
const attacksAt = computed(() => hover.value === null || props.outbound ? [] : props.bands.filter(
  b => b.start <= hover.value! && (b.end ?? props.bounds[1]) >= hover.value!,
))
const clock = (time: number) => new Date(time).toLocaleTimeString([], { hour12: false })
const readout = computed(() => at.value ? [clock(at.value.time), ...keys.value.map(key =>
  `${key === 'total' ? t('chart.total') : key}: ${thousands(at.value!.values[key] ?? 0)} ${props.metric}`),
...attacksAt.value.map(band => `${band.target} · ${band.type}`)] : [])
function move(e: PointerEvent) { hover.value = timeAt(e) }
function start(e: PointerEvent) {
  if (e.button !== 0 || !props.zoomable) return
  keyboardDrag = false
  drag.value = timeAt(e)
  hover.value = drag.value
  ;(e.currentTarget as Element).setPointerCapture?.(e.pointerId)
}
function finish(e: PointerEvent) {
  if (drag.value === null) return
  complete(timeAt(e))
}
function complete(end: number) {
  if (drag.value === null) return
  const range: Window = [Math.min(drag.value, end), Math.max(drag.value, end)]
  if (visible.value.filter(p => p.time >= range[0] && p.time <= range[1]).length >= 2) emit('update:window', range)
  drag.value = null
  keyboardDrag = false
}
function keydown(event: KeyboardEvent) {
  const key = event.key
  if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(key)) {
    const points = [...visible.value].sort((a, b) => a.time - b.time)
    const index = points.findIndex(p => p.time === at.value?.time), last = points.length - 1
    const next = key === 'Home' ? 0 : key === 'End' || hover.value === null ? last
      : Math.max(0, Math.min(last, index + (key === 'ArrowLeft' ? -1 : 1)))
    hover.value = points[next]!.time
    announcement.value = readout.value.join(' ')
  } else if (key === 'Escape') {
    if (drag.value === null) { hover.value = null; announcement.value = '' }
  } else if (key === 'Enter' && props.zoomable && hover.value !== null) {
    if (drag.value === null) { drag.value = hover.value; keyboardDrag = true }
    else complete(hover.value)
  } else return
  event.preventDefault()
}
function blur() {
  hover.value = null
  announcement.value = ''
  if (keyboardDrag) { drag.value = null; keyboardDrag = false }
}
const cancel = (event: KeyboardEvent) => { if (event.key === 'Escape') drag.value = null }
let observer: ResizeObserver | undefined
let frame = 0
onMounted(() => {
  if (typeof ResizeObserver !== 'undefined') {
    observer = new ResizeObserver(entries => {
      const measured = Math.max(280, entries[0]!.contentRect.width)
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => { width.value = measured })
    })
    observer.observe(host.value!)
  }
  window.addEventListener('keydown', cancel)
})
onUnmounted(() => {
  observer?.disconnect(); cancelAnimationFrame(frame); window.removeEventListener('keydown', cancel)
})
</script>
<template>
  <div ref="host" class="x-chart">
    <div v-if="!loading && !error && !selected.length" class="empty" role="status">{{ t('chart.unselected') }}</div>
    <XEmpty v-else-if="empty" :loading="loading" :error="error" />
    <template v-else>
      <svg :viewBox="`0 0 ${width} ${height}`" :aria-label="t('chart.trend')" role="img"
        tabindex="0" :aria-describedby="hintId" @keydown="keydown" @blur="blur"
        @pointermove="move" @pointerleave="hover = null" @pointerdown="start" @pointerup="finish"
        @pointercancel="drag = null">
        <rect v-for="b in merged" :key="b[0]" class="band" :x="x(Math.max(b[0], view[0]))" y="8"
          :width="x(Math.min(b[1], view[1])) - x(Math.max(b[0], view[0]))" :height="height - 28" />
        <g class="grid">
          <g v-for="value in ticks" :key="value">
            <line x1="44" :x2="width - 8" :y1="y(value)" :y2="y(value)" />
            <text x="39" :y="y(value) + 3" text-anchor="end">{{ formatTick(value, metric) }}</text>
          </g>
          <text v-for="i in [0, 1, 2, 3]" :key="i" :x="44 + i * (width - 52) / 3" :y="height - 3"
            :text-anchor="i === 0 ? 'start' : i === 3 ? 'end' : 'middle'">
            {{ clock(view[0] + i * (view[1] - view[0]) / 3).slice(0, 5) }}
          </text>
        </g>
        <g v-for="key in keys" :key="key" :stroke="lineColor(key, slots)" :fill="lineColor(key, slots)">
          <path v-for="(part, index) in lines.filter(p => p.length > 1)" :key="index" class="curve" :data-key="key"
            :d="part.map((p, i) => `${i ? 'L' : 'M'}${x(p.time)},${y(p.values[key] ?? 0)}`).join(' ')" />
          <circle v-for="part in lines.filter(p => p.length === 1)" :key="'single-' + part[0]!.time"
            class="isolated" :cx="x(part[0]!.time)" :cy="y(part[0]!.values[key] ?? 0)" r="3" />
          <circle v-if="lines.at(-1)!.length > 1" :cx="x(visible.at(-1)!.time)"
            :cy="y(visible.at(-1)!.values[key] ?? 0)" r="3" />
          <circle v-if="at" :cx="x(at.time)" :cy="y(at.values[key] ?? 0)" r="3" class="hover-mark" />
        </g>
        <g v-if="threshold !== undefined" class="threshold">
          <line x1="44" :x2="width - 8" :y1="y(threshold)" :y2="y(threshold)" />
          <text :x="width - 8" :y="y(threshold) - 4" text-anchor="end">
            {{ t('attacks.threshold', { value: formatTick(threshold, metric) }) }}
          </text>
        </g>
        <line v-if="hover !== null" class="crosshair" :x1="x(hover)" :x2="x(hover)" y1="8" :y2="height - 20" />
        <rect v-if="drag !== null && hover !== null" class="band" :x="x(Math.min(drag, hover))" y="8"
          :width="Math.abs(x(hover) - x(drag))" :height="height - 28" />
      </svg>
      <span :id="hintId" class="sr-only">{{ t(zoomable ? 'chart.keysHintZoom' : 'chart.keysHint') }}</span>
      <span class="sr-only" role="status">{{ announcement }}</span>
      <div v-if="at" class="chart-tip" :style="{ left: `${x(at.time)}px`,
        transform: x(at.time) > width - 210 ? 'translateX(-100%)' : 'none' }">
        <div v-for="(line, i) in readout" :key="i">{{ line }}</div>
      </div>
      <div class="chart-legend">
        <span v-for="key in keys" :key="key"><i :style="{ background: lineColor(key, slots) }" />
          {{ key === 'total' ? t('chart.total') : key }}</span>
        <span v-if="!outbound"><i class="band" />{{ t('chart.attack') }}</span>
      </div>
    </template>
    <div v-if="zoomable && window" class="toolbar zoom-tools">
      <button class="btn sm" :aria-label="t('chart.panLeft')"
        @click="emit('update:window', zoomWindow(view, bounds, -.5))">‹</button>
      <button class="btn sm" :aria-label="t('chart.panRight')"
        @click="emit('update:window', zoomWindow(view, bounds, .5))">›</button>
      <button class="text-button" @click="emit('update:window', null)">{{ t('chart.reset') }}</button>
    </div>
  </div>
</template>
<style scoped>
.x-chart { position: relative; min-width: 280px; min-height: 140px; }
svg { display: block; width: 100%; touch-action: pan-y; }
.grid { stroke: var(--line); fill: var(--muted); font: 10.5px var(--font-num); }
.grid text { stroke: none; }
.band { fill: var(--band); background: var(--band); }
.curve { fill: none; stroke-width: 1.4px; }
.threshold { pointer-events: none; fill: var(--warn); font: 10.5px var(--font-num); }
.threshold line { stroke: var(--warn); stroke-dasharray: 5 4; }
.crosshair { stroke: var(--muted); stroke-dasharray: 3 3; pointer-events: none; }
.hover-mark, circle, .chart-tip { pointer-events: none; }
.chart-tip {
  position: absolute; top: 12px; background: var(--panel); border: 1px solid var(--line); padding: 7px 9px;
  z-index: 5; white-space: nowrap; box-shadow: 0 3px 10px var(--shadow); font: 11px var(--font-num);
}
.chart-legend { display: flex; gap: 12px; flex-wrap: wrap; color: var(--muted); font-size: 11px; }
.chart-legend span { display: inline-flex; align-items: center; gap: 5px; }
.chart-legend i { width: 8px; height: 8px; border-radius: 2px; }
.zoom-tools { justify-content: flex-end; padding-top: 4px; }
</style>
