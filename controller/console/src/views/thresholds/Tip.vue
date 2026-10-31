<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import XTip from '../../components/XTip.vue'
defineProps<{ text: string; wide?: boolean; direction?: 'down' | 'up-right' }>()
let anchor: HTMLElement | undefined
function relocate() {
  const bubble = anchor?.querySelector<HTMLElement>('.tip-text')
  if (!anchor?.isConnected || !bubble) return
  const rect = anchor.getBoundingClientRect()
  const width = bubble.offsetWidth, height = bubble.offsetHeight
  const top = rect.top >= height + 8 ? rect.top - height - 6 : rect.bottom + 6
  Object.assign(bubble.style, { position: 'fixed', right: 'auto', bottom: 'auto',
    left: `${Math.max(8, Math.min(rect.left, innerWidth - width - 8))}px`,
    top: `${Math.max(8, Math.min(top, innerHeight - height - 8))}px` })
}
function activate(event: Event) { anchor = event.currentTarget as HTMLElement; relocate() }
onMounted(() => {
  window.addEventListener('resize', relocate)
  window.addEventListener('scroll', relocate, true)
})
onUnmounted(() => {
  window.removeEventListener('resize', relocate)
  window.removeEventListener('scroll', relocate, true)
})
</script>
<template>
  <XTip class="detection-tip" :text="text" :wide="wide" :direction="direction"
    @mouseenter="activate" @focusin="activate" />
</template>
<style>
.detection-tip .tip-text { position: fixed; }
</style>
