import { nextTick } from 'vue'
export async function pointer(element: Element, name: string, clientX: number, buttons = 1) {
  const event = new Event(name, { bubbles: true })
  Object.defineProperties(event, { clientX: { value: clientX }, button: { value: 0 }, buttons: { value: buttons },
    pointerId: { value: 1 } })
  element.dispatchEvent(event)
  await nextTick()
}
