import { reactive } from 'vue'
import { DECODERS } from '../../config/decoders'
import { assignSlots } from './math'

export const CAP = 3
export const selection = reactive({ keys: ['tcp', 'udp'], slots: { tcp: 1, udp: 2 } as Record<string, number> })
let initialized = false
export function initSelection() { if (!initialized) loadSelection() }
export function loadSelection() {
  initialized = true
  let keys: string[] = []
  let slots = {}
  try {
    const stored: unknown = JSON.parse(localStorage.getItem('xsight.chart.visibleDecoders') || '[]')
    if (Array.isArray(stored)) {
      let count = 0
      keys = [...new Set(stored)].filter(k => DECODERS.some(d => d.key === k)
        && (k === 'total' || ++count <= CAP))
    }
    slots = JSON.parse(localStorage.getItem('xs-ov-slot') || '{}') || {}
  } catch { /* Invalid old preferences use the defaults. */ }
  selection.keys = keys.length ? keys : ['tcp', 'udp']
  selection.slots = assignSlots(selection.keys, slots)
}
export function choose(keys: string[]) {
  initialized = true
  selection.slots = assignSlots(keys, selection.slots)
  selection.keys = keys
  localStorage.setItem('xsight.chart.visibleDecoders', JSON.stringify(keys))
  localStorage.setItem('xs-ov-slot', JSON.stringify(selection.slots))
}
