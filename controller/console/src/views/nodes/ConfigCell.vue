<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { configCell } from './data'
import type { Row } from '../mitigations/data'
defineProps<{ row: Row }>()
const { t } = useI18n()
</script>
<template><span class="pill" :class="configCell(row, t).tone" :title="configCell(row, t).tip">
  {{ configCell(row, t).text }}</span></template>
