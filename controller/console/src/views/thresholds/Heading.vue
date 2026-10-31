<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import XSeg from '../../components/XSeg.vue'
defineProps<{ view: string; count?: number }>()
const { t } = useI18n()
const router = useRouter()
</script>
<template>
  <div class="page-head"><div class="toolbar"><h1>{{ t('nav.thresholds') }}
    <span v-if="view === 'rules'" class="sub num count" :title="t('thresholds.total', { n: count })">
      {{ count }}</span></h1>
    <XSeg :model-value="view" :label="t('nav.thresholds')" :options="[
      { value: 'templates', label: t('thresholds.templates') }, { value: 'rules', label: t('thresholds.allRules') }]"
      @update:model-value="router.push($event === 'rules' ? '/thresholds/rules' : '/thresholds')" />
    <span v-if="view === 'templates' && count !== undefined" class="sub">
      {{ t('thresholds.total', { n: count }) }}</span></div><slot /></div>
</template>
