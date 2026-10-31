<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { isSyntheticRuleId } from '../../api/xdropRules'
import type { Row } from './data'
defineProps<{ row: Row; holders: number }>()
const { t } = useI18n()
</script>
<template>
  <span v-if="isSyntheticRuleId(row.external_rule_id)">— <span class="pill"
    :title="t('mitigations.createFailedTip', { id: row.external_rule_id })">
    {{ t('mitigations.createFailed') }}</span></span>
  <template v-else>
    <strong class="mono rule-id" :title="row.external_rule_id">{{ row.external_rule_id }}</strong>
    <span v-if="holders > 0" class="pill" :title="t('mitigations.sharedTip', { n: holders })">
      {{ t('mitigations.shared') }}
    </span>
  </template>
</template>
<style scoped>
.rule-id { display: inline-block; max-width: 150px; overflow: hidden; text-overflow: ellipsis; vertical-align: middle; }
</style>
