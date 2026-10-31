<script setup lang="ts">
withDefaults(defineProps<{ tone?: 'ok' | 'warn' | 'crit' | 'neutral'; label?: string }>(), { tone: 'neutral' })
</script>

<template>
  <span class="dot" :class="tone" :aria-label="label">
    <slot />
  </span>
</template>
