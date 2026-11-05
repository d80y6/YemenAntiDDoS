<script setup lang="ts">
import { computed, ref, shallowRef } from 'vue'
import { useI18n } from 'vue-i18n'
import { request } from '../../api/client'
import { usePoll } from '../../composables/usePoll'
import { thousands, fullDateTime } from '../../format'
import { isAdmin } from '../../auth'
import XKpi from '../../components/XKpi.vue'
import XTip from '../../components/XTip.vue'
import XEmpty from '../../components/XEmpty.vue'
import { notify } from '../../notifications'

const { t } = useI18n()

interface InlineRule {
  ID: number
  DstIP: string
  DstPrefixLen: number
  SrcIP: string
  SrcPrefixLen: number
  Protocol: number
  DstPort: number
  SrcPort: number
  Action: string
  RateLimitPPS: number
  Priority: number
  ExpiresUnix: number
  Reason: string
}

interface Mitigation {
  AttackID: number
  TargetIP: string
  Decoder: string
  Nodes: string[] | null
  Phase: string
  Rules: InlineRule[] | null
  StartedAt: string
  NarrowedAt?: string
  PeakPPS: number
  Rebreadths: number
  Version: number
}

interface MitigationsResponse {
  enabled: boolean
  active: number
  pushes: number
  push_errors: number
  mitigations: Mitigation[] | null
}

interface Posture {
  xdp_mode: string
  inline_enabled: boolean
  filter_rules: number
  validated_clients: number
  syn_cookies_replied: number
  syn_cookies_validated: number
  syn_cookies_dropped: number
  emergency_drops: number
  burst_alerts: number
  af_xdp_active: boolean
  af_xdp_umem_drops: number
  af_xdp_rx: number
  cpu_pins?: number[] | null
  cleanpipe_egress?: string
  updated_at: string
}

const data: MitigationsResponse = {
  enabled: false, active: 0, pushes: 0, push_errors: 0, mitigations: [],
}
const mitigations = shallowRef<MitigationsResponse>(data)
const posture = shallowRef<Record<string, Posture>>({})
const loading = ref(true)
const error = ref('')
const busy = ref(false)

function fetchMitigations() {
  return request<MitigationsResponse>('/api/inline/mitigations').then(r => {
    mitigations.value = { ...r, mitigations: r.mitigations ?? [] }
    error.value = ''
  }).catch(e => { error.value = e instanceof Error ? e.message : String(e) })
}

function fetchPosture() {
  return request<Record<string, Posture>>('/api/nodes/posture').then(r => { posture.value = r ?? {} })
}

usePoll(() => Promise.all([fetchMitigations(), fetchPosture()]), 5000,
  () => { loading.value = false },
  () => { loading.value = false })

const nodes = computed(() => Object.entries(posture.value).map(([id, p]) => ({ id, ...p })))
const inlineNodes = computed(() => nodes.value.filter(n => n.inline_enabled).length)
const totalRules = computed(() => nodes.value.reduce((sum, n) => sum + (n.filter_rules || 0), 0))
const totalEmergency = computed(() => nodes.value.reduce((sum, n) => sum + (n.emergency_drops || 0), 0))
const afxdpHealthy = computed(() => nodes.value.filter(n => n.af_xdp_active).length)

async function reconcile() {
  busy.value = true
  try {
    await request('/api/inline/reconcile', { method: 'POST' })
    notify(t('inline.reconciled'), 'ok')
    await Promise.all([fetchMitigations(), fetchPosture()])
  } catch (e) {
    notify(e instanceof Error ? e.message : String(e), 'crit')
  } finally {
    busy.value = false
  }
}

function actionLabel(rule: InlineRule) {
  if (rule.Action === 'rate_limit') return `rate ≤ ${thousands(rule.RateLimitPPS)} pps`
  if (rule.Action === 'syn_cookie') return 'SYN cookie'
  const proto = rule.Protocol === 6 ? 'tcp' : rule.Protocol === 17 ? 'udp' : 'ip'
  return rule.DstPort ? `${rule.Action} ${proto}/${rule.DstPort}` : rule.Action
}

function phaseClass(phase: string) {
  return phase === 'narrow' ? 'ok' : 'warn'
}
</script>
<template>
  <div class="page inline-page">
    <div class="page-head">
      <h1>{{ t('nav.inline') }}
        <span class="sub num count">{{ t('inline.activeCount', { n: mitigations.active }) }}</span>
      </h1>
      <div class="toolbar">
        <span class="sub">{{ t('inline.nodesInline', { inline: inlineNodes, total: nodes.length }) }}</span>
        <button v-if="isAdmin()" class="btn sm" :disabled="busy" @click="reconcile">
          {{ t('inline.reconcile') }}
        </button>
      </div>
    </div>

    <p v-if="error" class="crit mono" role="alert">{{ error }}</p>

    <div class="kpis">
      <XKpi :label="t('inline.kpiActive')" :value="String(mitigations.active)"
        :secondary="t('inline.kpiActiveHint')" />
      <XKpi :label="t('inline.kpiRules')" :value="thousands(totalRules)"
        :secondary="t('inline.kpiRulesHint')" />
      <XKpi :label="t('inline.kpiEmergency')" :value="thousands(totalEmergency)"
        :secondary="t('inline.kpiEmergencyHint')" />
      <XKpi :label="t('inline.kpiAfxdp')" :value="`${afxdpHealthy}/${nodes.length}`"
        :secondary="t('inline.kpiAfxdpHint')" />
    </div>

    <div class="panel">
      <div class="panel-head">
        <h2>{{ t('inline.mitigationsTitle') }}</h2>
        <span class="sub">{{ t('inline.pushes', { n: mitigations.pushes }) }}
          <template v-if="mitigations.push_errors">
            · <span class="crit">{{ t('inline.pushErrors', { n: mitigations.push_errors }) }}</span>
          </template>
        </span>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>{{ t('inline.attack') }}</th>
              <th>{{ t('inline.target') }}</th>
              <th>{{ t('inline.phase') }}<XTip :text="t('inline.phaseTip')" /></th>
              <th>{{ t('inline.rules') }}</th>
              <th>{{ t('inline.nodes') }}</th>
              <th>{{ t('inline.started') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="m in mitigations.mitigations" :key="m.AttackID">
              <td><RouterLink :to="`/attacks/${m.AttackID}`" class="mono">#{{ m.AttackID }}</RouterLink></td>
              <td><strong class="mono">{{ m.TargetIP }}</strong><div class="sub">{{ m.Decoder }}</div></td>
              <td>
                <span class="dot" :class="phaseClass(m.Phase)" /> {{ m.Phase }}
                <small v-if="m.Rebreadths" class="sub">×{{ m.Rebreadths }}</small>
              </td>
              <td>
                <div v-for="(r, i) in (m.Rules || [])" :key="i" class="mono sub">{{ actionLabel(r) }}</div>
              </td>
              <td class="mono sub">{{ (m.Nodes || []).join(', ') || '—' }}</td>
              <td class="num sub">{{ fullDateTime(m.StartedAt) }}</td>
            </tr>
          </tbody>
        </table>
        <XEmpty v-if="!(mitigations.mitigations || []).length" :loading="loading" />
      </div>
    </div>

    <div class="panel">
      <div class="panel-head">
        <h2>{{ t('inline.postureTitle') }}</h2>
        <span class="sub">{{ t('inline.postureHint') }}</span>
      </div>
      <div class="tbl-wrap">
        <table>
          <thead>
            <tr>
              <th>{{ t('inline.node') }}</th>
              <th>XDP</th>
              <th>{{ t('inline.filterRules') }}</th>
              <th>{{ t('inline.synCookie') }}</th>
              <th>{{ t('inline.emergency') }}</th>
              <th>AF_XDP</th>
              <th>{{ t('inline.cpuPins') }}</th>
              <th>{{ t('inline.updated') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="n in nodes" :key="n.id">
              <td><strong class="mono">{{ n.id }}</strong>
                <div class="sub">{{ n.inline_enabled ? t('inline.inlineOn') : t('inline.inlineOff') }}</div>
              </td>
              <td class="mono">{{ n.xdp_mode || '—' }}</td>
              <td class="num">{{ thousands(n.filter_rules) }}
                <div class="sub num">{{ t('inline.validated', { n: thousands(n.validated_clients) }) }}</div>
              </td>
              <td class="num">
                <span class="ok">{{ thousands(n.syn_cookies_replied) }}</span> /
                <span>{{ thousands(n.syn_cookies_validated) }}</span> /
                <span class="crit">{{ thousands(n.syn_cookies_dropped) }}</span>
              </td>
              <td class="num">{{ thousands(n.emergency_drops) }}
                <div class="sub num">{{ t('inline.alerts', { n: thousands(n.burst_alerts) }) }}</div>
              </td>
              <td>
                <span class="dot" :class="n.af_xdp_active ? 'ok' : 'neutral'" />
                <span class="sub num">{{ thousands(n.af_xdp_rx) }}</span>
                <div v-if="n.af_xdp_umem_drops" class="sub num crit">
                  {{ t('inline.umemDrops', { n: thousands(n.af_xdp_umem_drops) }) }}
                </div>
              </td>
              <td class="mono sub">{{ (n.cpu_pins || []).join(',') || '—' }}</td>
              <td class="num sub">{{ n.updated_at ? fullDateTime(n.updated_at) : '—' }}</td>
            </tr>
          </tbody>
        </table>
        <XEmpty v-if="!nodes.length" :loading="loading" />
      </div>
    </div>
  </div>
</template>
<style scoped>
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 16px; }
.panel + .panel { margin-top: 16px; }
</style>
