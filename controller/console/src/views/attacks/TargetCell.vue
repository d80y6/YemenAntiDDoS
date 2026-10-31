<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import XPill from '../../components/XPill.vue'
import { target } from './data'
const props = defineProps<{ value: string; direction?: string }>()
const { t } = useI18n(), parsed = computed(() => target(props.value))
</script>
<template>
  <span class="target-cell">
    <XPill v-if="parsed.kind === 'global'" :title="t('attacks.globalTip')">{{ t('attacks.global') }}</XPill>
    <span v-else class="mono">{{ parsed.text }}</span>
    <XPill v-if="direction === 'sends'" :title="t('attacks.outboundTip')">{{ t('data.sends') }}</XPill>
  </span>
</template>
<style scoped>
.target-cell { display: inline-flex; align-items: center; gap: 5px; }
</style>
