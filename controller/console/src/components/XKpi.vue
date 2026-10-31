<script setup lang="ts">
defineProps<{ label: string; value: string | number; secondary?: string; tone?: string }>()
</script>

<template>
  <div class="kpi" :class="tone">
    <div class="k">{{ label }}</div>
    <div class="v">{{ value }}</div>
    <div v-if="secondary" class="v2">{{ secondary }}</div>
  </div>
</template>
