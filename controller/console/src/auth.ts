import { defineComponent } from 'vue'
import { state } from './state'

export function isAdmin() {
  return state.user?.role === 'admin'
}

export const AdminOnly = defineComponent({
  name: 'AdminOnly',
  setup(_, { slots }) {
    return () => isAdmin() ? slots.default?.() : null
  },
})
