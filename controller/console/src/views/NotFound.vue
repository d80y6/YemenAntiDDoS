<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>

<template>
  <div class="page">
    <h1>404 · {{ t('pages.notFound') }}</h1>
    <section class="panel empty-page">
      <RouterLink to="/overview">{{ t('pages.back') }}</RouterLink>
    </section>
  </div>
</template>
