<script setup lang="ts">
import { useI18n } from 'vue-i18n'

defineProps<{ error?: string; loading?: boolean }>()
const { t } = useI18n()
</script>

<template>
  <div class="empty" :role="error ? 'alert' : 'status'">
    <span>{{ t(loading ? 'common.loading' : error ? 'common.failed' : 'common.empty') }}</span>
    <p v-if="error" class="mono crit">{{ error }}</p>
    <slot />
  </div>
</template>
