<script setup lang="ts">
import { ref, shallowRef, onMounted, onUnmounted, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { request } from '../../api/client'
import { dateTime, fullDateTime, thousands } from '../../format'
import { isAdmin } from '../../auth'
import { notify } from '../../notifications'
import XConfirm from '../../components/XConfirm.vue'
import XTip from '../../components/XTip.vue'
import XEmpty from '../../components/XEmpty.vue'
import XDrawer from '../../components/XDrawer.vue'
import XCopy from '../../components/XCopy.vue'
import XPill from '../../components/XPill.vue'
import XBadge from '../../components/XBadge.vue'

const { t } = useI18n()

interface Rule {
  Name: string
  Prefix: string
  Protocol?: number
  DstPort?: number
  SrcPort?: number
  Action: string
  RateLimit?: number
}

interface AttackRef {
  attack_id: number
  action_id?: number
  attached_at: string
  detached_at?: string
}

interface VendorInfo {
  id: string
  name: string
  executable: boolean
}

interface Announcement {
  announcement_id: number
  prefix: string
  rule_name: string
  connector_id: number
  connector_name: string
  vendor: string
  executable: boolean
  status: string
  refcount: number
  error_message?: string
  announced_at: string
  delay_started_at?: string
  delay_minutes: number
  rule?: Rule
  commands?: string[]
  withdraw_commands?: string[]
  attacks?: AttackRef[]
}

interface AnnouncementsResp {
  announcements: Announcement[]
  vendors: VendorInfo[]
}

interface PreviewReq {
  vendor: string
  name: string
  prefix: string
  protocol?: number
  dst_port?: number
  src_port?: number
  action: string
  rate_limit?: number
}

interface PreviewResp {
  vendor: string
  rule: Rule
  commands: string[]
  withdraw_commands: string[]
  executable: boolean
}

const announcements = shallowRef<Announcement[]>([])
const vendors = shallowRef<VendorInfo[]>([])
const loading = ref(true)
const error = ref<string>()
const abortCtrl = new AbortController()
let timer: ReturnType<typeof setInterval>

const drawerOpen = ref(false)
const detail = shallowRef<Announcement | null>(null)
const confirming = ref(false)
const confirmTarget = ref<{ id: number; rule: string }>()

const previewVendor = ref('frr')
const previewPrefix = ref('')
const previewProtocol = ref<string>('')
const previewDstPort = ref<string>('')
const previewAction = ref('drop')
const previewRate = ref<string>('')
const previewResult = shallowRef<PreviewResp | null>(null)

function fetchAnnouncements() {
  loading.value = true
  request<AnnouncementsResp>('/api/flowspec/announcements', { signal: abortCtrl.signal })
    .then(r => { announcements.value = r.announcements; vendors.value = r.vendors; error.value = ''; loading.value = false })
    .catch(e => { if (!abortCtrl.signal.aborted) { error.value = e instanceof Error ? e.message : String(e); loading.value = false } })
}

function startPoll() { timer = setInterval(fetchAnnouncements, 5000) }
function stopPoll() { clearInterval(timer) }

onMounted(() => { fetchAnnouncements(); startPoll() })
onUnmounted(() => { stopPoll(); abortCtrl.abort() })

function openDetail(a: Announcement) { detail.value = a; drawerOpen.value = true }
function closeDetail() { drawerOpen.value = false; detail.value = null }

function askWithdraw(a: Announcement) {
  confirmTarget.value = { id: a.announcement_id, rule: a.rule_name }
  confirming.value = true
}
async function executeWithdraw() {
  if (!confirmTarget.value) return
  const { id, rule } = confirmTarget.value
  try {
    const res = await request<{ ok: true; announcement_id: number; commands?: string[]; output?: string; warning?: string; already_withdrawn?: boolean }>(
      `/api/flowspec/announcements/${id}/withdraw`, { method: 'POST', signal: abortCtrl.signal })
    notify(res.warning ? t('flowspec.forceDone', { rule }) + ': ' + res.warning : t('flowspec.forceDone', { rule }), res.warning ? 'warn' : 'ok')
    confirming.value = false
    confirmTarget.value = undefined
    await fetchAnnouncements()
  } catch (e) {
    notify(e instanceof Error ? e.message : String(e), 'crit')
  }
}

function runPreview() {
  if (!previewPrefix.value.trim()) { notify(t('flowspec.preview.empty'), 'warn'); return }
  const p: PreviewReq = {
    vendor: previewVendor.value, name: previewPrefix.value, prefix: previewPrefix.value,
    protocol: previewProtocol.value ? Number(previewProtocol.value) : undefined,
    dst_port: previewDstPort.value ? Number(previewDstPort.value) : undefined,
    action: previewAction.value, rate_limit: previewRate.value ? Number(previewRate.value) : undefined
  }
  request<PreviewResp>('/api/flowspec/preview', { method: 'POST', body: JSON.stringify(p), signal: abortCtrl.signal })
    .then(r => { previewResult.value = r })
    .catch(e => { previewResult.value = null; notify(e instanceof Error ? e.message : String(e), 'crit') })
}

function protocolLabel(p?: number) {
  if (!p) return t('flowspec.preview.protocolNone')
  if (p === 6) return 'TCP (6)'
  if (p === 17) return 'UDP (17)'
  if (p === 1) return 'ICMP (1)'
  return String(p)
}

function statusTone(s: string) {
  if (s === 'active') return 'ok'
  if (s === 'delayed') return 'warn'
  if (s === 'failed') return 'crit'
  return 'neutral'
}

function matchSummary(rule?: Rule) {
  if (!rule) return '—'
  const parts = []
  parts.push(protocolLabel(rule.Protocol))
  if (rule.DstPort) parts.push(`dport=${rule.DstPort}`)
  if (rule.SrcPort) parts.push(`sport=${rule.SrcPort}`)
  parts.push(rule.Action === 'rate-limit' ? `rate=${thousands(rule.RateLimit ?? 0)} B/s` : 'drop')
  return parts.join(' · ')
}
</script>
<template>
  <div class="flowspec-page">
    <div class="page-head">
      <h1>{{ t('flowspec.title') }}<span class="sub"> {{ t('flowspec.subtitle') }}</span></h1>
    </div>

    <p v-if="loading" class="sub">{{ t('flowspec.loading') }}</p>
    <p v-else-if="error" class="crit mono" role="alert">
      {{ error }} <button class="btn sm" @click="fetchAnnouncements">{{ t('flowspec.retry') }}</button>
    </p>

    <div v-else>
      <section class="panel">
        <div class="panel-head"><h2>{{ t('flowspec.announcements') }}</h2></div>
        <div class="tbl-wrap">
          <table><thead><tr>
            <th>{{ t('flowspec.col.prefix') }}</th>
            <th>{{ t('flowspec.col.rule') }}</th>
            <th>{{ t('flowspec.col.connector') }}</th>
            <th>{{ t('flowspec.col.vendor') }}</th>
            <th>{{ t('flowspec.col.match') }}</th>
            <th>{{ t('flowspec.col.holders') }}</th>
            <th>{{ t('flowspec.col.announced') }}</th>
            <th>{{ t('flowspec.col.status') }}</th>
            <th>{{ t('flowspec.col.actions') }}</th>
          </tr></thead><tbody>
            <tr v-for="a in announcements" :key="a.announcement_id" class="link" @click="openDetail(a)">
              <td class="mono strong">{{ a.prefix }}</td>
              <td class="mono">{{ a.rule_name }}</td>
              <td>{{ a.connector_name }}</td>
              <td><XBadge :tone="a.executable ? 'ok' : 'warn'">{{ a.vendor }}</XBadge></td>
              <td class="mono">{{ matchSummary(a.rule) }}</td>
              <td class="num">{{ a.refcount }}</td>
              <td class="sub">{{ dateTime(a.announced_at).slice(6) }}</td>
              <td><XPill :tone="statusTone(a.status)">{{ t('flowspec.status.' + a.status) || t('flowspec.status.other', { s: a.status }) }}</XPill></td>
              <td v-if="isAdmin()" class="ops">
                <button class="btn sm" @click.stop="askWithdraw(a)">{{ t('flowspec.forceWithdraw') }}</button>
              </td>
            </tr>
          </tbody></table>
          <XEmpty v-if="!announcements.length" :label="t('flowspec.empty')" />
        </div>
      </section>

      <section class="panel preview-panel">
        <div class="panel-head"><h2>{{ t('flowspec.preview.title') }}</h2></div>
        <div class="preview-form">
          <div class="field"><label>{{ t('flowspec.preview.vendor') }}</label>
            <select v-model="previewVendor">
              <option v-for="v in vendors" :key="v.id" :value="v.id">{{ v.name }} {{ v.executable ? '' : '(' + t('flowspec.exportOnly') + ')' }}</option>
            </select></div>
          <div class="field"><label>{{ t('flowspec.preview.prefix') }}</label>
            <input v-model="previewPrefix" type="text" placeholder="198.51.100.7/32" /></div>
          <div class="field"><label>{{ t('flowspec.preview.protocol') }}</label>
            <select v-model="previewProtocol"><option value="">{{ t('flowspec.preview.protocolNone') }}</option>
              <option value="6">TCP (6)</option><option value="17">UDP (17)</option><option value="1">ICMP (1)</option></select></div>
          <div class="field"><label>{{ t('flowspec.preview.dstPort') }}</label>
            <input v-model="previewDstPort" type="number" placeholder="443" min="1" max="65535" /></div>
          <div class="field"><label>{{ t('flowspec.preview.action') }}</label>
            <select v-model="previewAction"><option value="drop">{{ t('flowspec.preview.actionDrop') }}</option>
              <option value="rate-limit">{{ t('flowspec.preview.actionRate') }}</option></select></div>
          <div class="field" v-if="previewAction === 'rate-limit'"><label>{{ t('flowspec.preview.rate') }}</label>
            <input v-model="previewRate" type="number" placeholder="1000000" min="1" /></div>
          <button class="btn" @click="runPreview">{{ t('flowspec.preview.run') }}</button>
        </div>
        <div v-if="previewResult" class="preview-result">
          <h3>{{ t('flowspec.preview.result') }}</h3>
          <pre class="mono">{{ previewResult.commands.join('\n') }}</pre>
          <XCopy :text="previewResult.commands.join('\n')" />
        </div>
      </section>
    </div>

    <XDrawer v-model="drawerOpen" :width="600" :title="detail?.rule_name || t('flowspec.detail.identity')">
      <p v-if="!detail" class="empty">{{ t('common.loading') }}</p>
      <div v-else>
        <dl class="kv">
          <dt>{{ t('flowspec.detail.identity') }}</dt><dd>{{ detail.announcement_id }}</dd>
          <dt>{{ t('flowspec.detail.rule') }}</dt><dd class="mono">{{ detail.rule?.Name || detail.rule_name }}</dd>
          <dt>{{ t('flowspec.detail.prefix') }}</dt><dd class="mono">{{ detail.prefix }}</dd>
          <dt>{{ t('flowspec.detail.vendor') }}</dt><dd><XBadge :tone="detail.executable ? 'ok' : 'warn'">{{ detail.vendor }}</XBadge></dd>
          <dt>{{ t('flowspec.detail.status') }}</dt><dd><XPill :tone="statusTone(detail.status)">{{ t('flowspec.status.' + detail.status) || detail.status }}</XPill></dd>
          <dt>{{ t('flowspec.detail.refcount') }}</dt><dd>{{ detail.refcount }}</dd>
        </dl>
        <div class="subh">{{ t('flowspec.detail.commands') }}</div>
        <pre class="mono cmd">{{ detail.commands?.join('\n') || t('flowspec.preview.empty') }}</pre>
        <XCopy :text="detail.commands?.join('\n') || ''" />
        <div class="subh">{{ t('flowspec.detail.withdrawCommands') }}</div>
        <pre class="mono cmd">{{ detail.withdraw_commands?.join('\n') || t('flowspec.preview.empty') }}</pre>
        <XCopy :text="detail.withdraw_commands?.join('\n') || ''" />
        <div class="subh">{{ t('flowspec.detail.attacks') }}</div>
        <ul v-if="detail.attacks?.length" class="attacks-list">
          <li v-for="atk in detail.attacks" :key="atk.attack_id">
            <RouterLink :to="'/attacks/' + atk.attack_id">#{{ atk.attack_id }}</RouterLink>
            <span v-if="atk.detached_at" class="sub detached">{{ t('flowspec.detail.detached') }}</span>
            <span class="sub" :title="fullDateTime(atk.attached_at)">{{ dateTime(atk.attached_at).slice(6, 11) }}</span>
          </li>
        </ul>
        <p v-else class="empty">{{ t('flowspec.empty') }}</p>
      </div>
    </XDrawer>

    <XConfirm v-model="confirming" :title="t('flowspec.forceTitle', { rule: confirmTarget?.rule })" :description="t('flowspec.forceDesc')" :confirm-label="t('flowspec.forceWithdraw')" tone="danger" :action="executeWithdraw" />
  </div>
</template>
<style scoped>
.page-head { margin-bottom: 16px; }
.ops { text-align: right; }
.preview-panel { background: var(--bg-elev); border: 1px solid var(--line); border-radius: var(--r); }
.preview-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; align-items: end; padding: 12px; }
.field { display: flex; flex-direction: column; gap: 4px; }
.field label { font-size: 12px; color: var(--muted); }
.field input, .field select { padding: 6px 8px; border: 1px solid var(--line); border-radius: var(--r); background: var(--bg); color: var(--ink); }
.preview-result { margin-top: 12px; padding: 12px; background: var(--bg); border: 1px solid var(--line); border-radius: var(--r); }
.preview-result h3 { margin: 0 0 8px; font-size: 13px; }
.preview-result pre { margin: 0; max-height: 200px; overflow: auto; }
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--line); }
th { font-weight: 600; font-size: 12px; color: var(--muted); background: var(--bg); position: sticky; top: 0; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.mono { font-family: var(--font-num); }
.strong { font-weight: 600; }
.link:hover td { background: var(--bg-elev); }
.attacks-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 4px; }
.attacks-list li { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.detached { color: var(--muted); }
.cmd { margin: 8px 0; max-height: 200px; overflow: auto; background: var(--bg); padding: 8px; border-radius: var(--r); border: 1px solid var(--line); }
.subh { font-size: 12.5px; font-weight: 500; margin: 14px 0 6px; }
.kv { grid-template-columns: 110px minmax(0, 1fr); }
</style>