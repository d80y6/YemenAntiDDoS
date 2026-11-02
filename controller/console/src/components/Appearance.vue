<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import XSeg from './XSeg.vue'
import { state, type Theme, type Locale } from '../state'

const { t } = useI18n()
const themes = computed(() => ['auto', 'light', 'dark'].map(value => ({ value, label: t(`common.${value}`) })))
</script>

<template>
  <XSeg
    :model-value="state.theme"
    :options="themes"
    :label="t('common.theme')"
    @update:model-value="state.theme = $event as Theme"
  />
  <XSeg
    :model-value="state.locale"
    :options="[{ value: 'ar', label: 'عربي' }, { value: 'en', label: 'EN' }]"
    :label="t('common.language')"
    @update:model-value="state.locale = $event as Locale"
  />
</template>
