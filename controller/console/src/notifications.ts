import { reactive } from 'vue'

export type Tone = 'ok' | 'warn' | 'crit'
export const notifications = reactive<{ id: number; message: string; tone: Tone; raw: boolean }[]>([])
let sequence = 0

export function notify(message: string, tone: Tone = 'ok', raw = tone !== 'ok') {
  const id = ++sequence
  notifications.push({ id, message, tone, raw })
  setTimeout(() => {
    const index = notifications.findIndex(n => n.id === id)
    if (index >= 0) notifications.splice(index, 1)
  }, 3000)
  return id
}

export async function notifyWrite<T>(operation: Promise<T>, success: string): Promise<T> {
  try {
    const result = await operation
    notify(success)
    return result
  } catch (error) {
    notify(error instanceof Error ? error.message : String(error), 'crit', true)
    throw error
  }
}
