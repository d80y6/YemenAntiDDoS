<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { useRoute } from 'vue-router'

const { t } = useI18n()
const route = useRoute()
</script>

<template>
  <div class="page">
    <header class="page-head">
      <h1>{{ t(`nav.${route.path.split('/')[1]}`) }}</h1>
    </header>
    <section class="panel empty-page">{{ t('pages.placeholder') }}</section>
  </div>
</template>
