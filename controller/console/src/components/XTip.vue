<script setup lang="ts">
import { useId } from 'vue'
import { useI18n } from 'vue-i18n'

withDefaults(defineProps<{ text: string; direction?: 'down' | 'up-right'; wide?: boolean }>(), { direction: 'down' })
const id = useId()
const { t } = useI18n()
</script>

<template>
  <span class="tip-wrap" :class="[direction, { wide }]">
    <button type="button" class="tip" :aria-label="t('common.help')" :aria-describedby="id">?</button>
    <span :id="id" role="tooltip" class="tip-text">{{ text }}</span>
  </span>
</template>
