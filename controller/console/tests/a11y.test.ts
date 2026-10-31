import { describe, it, expect, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { defineComponent, h, nextTick, ref } from 'vue'
import { createMemoryHistory } from 'vue-router'
import { makeRouter } from '../src/router'
import { state } from '../src/state'
import { render } from './helpers'
import XListbox from '../src/components/XListbox.vue'
import XDrawer from '../src/components/XDrawer.vue'
import XConfirm from '../src/components/XConfirm.vue'
import XTip from '../src/components/XTip.vue'
import XSwitch from '../src/components/XSwitch.vue'
import XCheck from '../src/components/XCheck.vue'
import XSeg from '../src/components/XSeg.vue'
import XTabs from '../src/components/XTabs.vue'
import XNumber from '../src/components/XNumber.vue'
import XTable from '../src/components/XTable.vue'
import XPager from '../src/components/XPager.vue'
import XPassword from '../src/components/XPassword.vue'
import XCopy from '../src/components/XCopy.vue'
import XBadge from '../src/components/XBadge.vue'
import XPill from '../src/components/XPill.vue'
import XDot from '../src/components/XDot.vue'
import XKpi from '../src/components/XKpi.vue'
import XEmpty from '../src/components/XEmpty.vue'
import { placePopup } from '../src/components/popup'
import { drawerCount } from '../src/components/overlay'

const options = [
  { value: 'a', label: 'Alpha' },
  { value: 'b', label: 'Blocked', disabled: true },
  { value: 'c', label: 'Charlie' },
]

describe('G-a11y XListbox', () => {
  it('expanded/controls, skips disabled, Enter selects, Escape closes, Home/End', async () => {
    const wrapper = render(XListbox, {
      props: { modelValue: 'a', options, label: 'Choice' },
      attachTo: document.body,
    })
    const button = wrapper.get('button')
    expect(button.attributes('aria-expanded')).toBe('false')
    await button.trigger('click')
    expect(button.attributes('aria-expanded')).toBe('true')
    const list = document.getElementById(button.attributes('aria-controls')!)!
    expect(list.getAttribute('role')).toBe('listbox')
    expect(list.querySelector('[aria-selected=true]')?.textContent).toBe('Alpha')
    await button.trigger('keydown', { key: 'ArrowDown' })
    const active = document.getElementById(button.attributes('aria-activedescendant')!)
    expect(active?.textContent, 'disabled option must be skipped').toBe('Charlie')
    await button.trigger('keydown', { key: 'Enter' })
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual(['c'])
    await button.trigger('click')
    await button.trigger('keydown', { key: 'End' })
    expect(document.getElementById(button.attributes('aria-activedescendant')!)?.textContent).toBe('Charlie')
    await button.trigger('keydown', { key: 'Home' })
    expect(document.getElementById(button.attributes('aria-activedescendant')!)?.textContent).toBe('Alpha')
    await button.trigger('keydown', { key: 'ArrowUp' })
    expect(document.getElementById(button.attributes('aria-activedescendant')!)?.textContent).toBe('Charlie')
    await button.trigger('keydown', { key: 'Escape' })
    expect(button.attributes('aria-expanded')).toBe('false')
  })

  it('outside pointer closes; fixed position; disabled is not selectable', async () => {
    const w = render(XListbox, {
      props: { modelValue: 'a', options, label: 'Choice' },
      attachTo: document.body,
    })
    await w.get('button').trigger('click')
    expect((document.querySelector('.mpop') as HTMLElement).style.position).toBe('fixed')
    const disabled = document.querySelector('[role=option][aria-disabled=true]') as HTMLButtonElement
    expect(disabled.disabled).toBe(true)
    disabled.click()
    expect(w.emitted('update:modelValue')).toBeUndefined()
    document.body.dispatchEvent(new Event('pointerdown', { bubbles: true }))
    await nextTick()
    expect(w.get('button').attributes('aria-expanded')).toBe('false')
  })

  it.each(['search', 'free'] as const)('%s mode has accessible combobox and search', async mode => {
    const w = render(XListbox, {
      props: { modelValue: 'a', options, label: 'Choice', mode },
      attachTo: document.body,
    })
    await w.get('button').trigger('click')
    const input = document.querySelector('input[role=combobox]') as HTMLInputElement
    expect(input.getAttribute('aria-expanded')).toBe('true')
    expect(document.getElementById(input.getAttribute('aria-controls')!)).not.toBeNull()
    input.value = mode === 'free' ? 'Custom' : 'Char'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    await nextTick()
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
    await nextTick()
    expect(w.emitted('update:modelValue')?.[0]).toEqual([mode === 'free' ? 'Custom' : 'c'])
  })

  it('free text commits on outside blur and selected options keep their value', async () => {
    const w = render(XListbox, {
      props: { modelValue: 'a', options, label: 'Choice', mode: 'free' },
      attachTo: document.body,
    })
    await w.get('button').trigger('click')
    let input = document.querySelector('input[role=combobox]') as HTMLInputElement
    input.value = 'Custom'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    document.body.dispatchEvent(new Event('pointerdown', { bubbles: true }))
    await nextTick()
    expect(w.emitted('update:modelValue')?.[0]).toEqual(['Custom'])
    await w.get('button').trigger('click')
    input = document.querySelector('input[role=combobox]') as HTMLInputElement
    input.value = 'Char'
    input.dispatchEvent(new Event('input', { bubbles: true }))
    await nextTick()
    ;(document.querySelector('[role=option]') as HTMLButtonElement).click()
    await nextTick()
    expect(w.emitted('update:modelValue')?.at(-1)).toEqual(['c'])
  })

  it('drawer-owned popup stays inside focus trap; Escape closes just popup', async () => {
    const Host = defineComponent({
      setup() {
        const open = ref(true)
        return () => h(XDrawer, {
          modelValue: open.value,
          title: 'Details',
          'onUpdate:modelValue': value => open.value = value,
        }, {
          default: () => h(XListbox, { modelValue: 'a', options, label: 'Choice', mode: 'search' }),
        })
      },
    })
    const w = render(Host, { attachTo: document.body })
    await flushPromises()
    await w.getComponent(XListbox).get('button').trigger('click')
    await flushPromises()
    const dialog = document.querySelector('[role=dialog]')!
    const popup = dialog.querySelector('.mpop')!
    expect(popup).not.toBeNull()
    const input = popup.querySelector('input')!
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await nextTick()
    expect(document.querySelector('.mpop')).toBeNull()
    expect(document.querySelector('[role=dialog]')).not.toBeNull()
  })

  it('placePopup chooses above and clamps horizontal bounds', () => {
    const result = placePopup(
      { left: 360, right: 390, top: 500, bottom: 530, width: 100 },
      { width: 390, height: 600 },
    )
    expect(result.up).toBe(true)
    expect(Number.parseFloat(result.top)).toBeLessThan(500)
    expect(result.left).toBe('202px')
    expect(placePopup(
      { left: 0, right: 100, top: 30, bottom: 50, width: 100 },
      { width: 390, height: 700 },
    ).up).toBe(false)
  })
})

describe('G-a11y XDrawer', () => {
  it('dialog semantics, initial focus, both trap directions and focus return', async () => {
    const opener = document.createElement('button')
    document.body.append(opener)
    opener.focus()
    const w = render(XDrawer, {
      props: { modelValue: true, title: 'Details' },
      slots: { default: '<input aria-label="Inside"><button id="last">Last</button>' },
      attachTo: document.body,
    })
    await flushPromises()
    const dialog = document.querySelector('[role=dialog]')!
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    expect(document.getElementById(dialog.getAttribute('aria-labelledby')!)?.textContent).toBe('Details')
    const close = dialog.querySelector('button')!
    const last = document.getElementById('last')!
    expect(document.activeElement).toBe(close)
    last.focus()
    last.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }))
    expect(document.activeElement).toBe(close)
    close.dispatchEvent(new KeyboardEvent('keydown', {
      key: 'Tab',
      shiftKey: true,
      bubbles: true,
      cancelable: true,
    }))
    expect(document.activeElement).toBe(last)
    await w.setProps({ modelValue: false })
    await flushPromises()
    expect(document.activeElement, 'focus must return to opener').toBe(opener)
  })

  it('Escape, scrim and close request closure, busy blocks all', async () => {
    const w = render(XDrawer, {
      props: { modelValue: true, title: 'Busy', busy: true },
      attachTo: document.body,
    })
    await flushPromises()
    const scrim = document.querySelector('.scrim')!
    const dialog = document.querySelector('[role=dialog]')!
    scrim.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    expect(w.emitted('update:modelValue')).toBeUndefined()
    expect((dialog.querySelector('button') as HTMLButtonElement).disabled).toBe(true)
    await w.setProps({ busy: false })
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    expect(w.emitted('update:modelValue')?.[0]).toEqual([false])
    scrim.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    ;(dialog.querySelector('button') as HTMLButtonElement).click()
    expect(w.emitted('update:modelValue')?.length).toBe(3)
  })

  it.each([460,600,680,780] as const)('supports width %s', width => {
    render(XDrawer, { props: { modelValue: true, title: 'Width', width }, attachTo: document.body })
    expect((document.querySelector('.drawer') as HTMLElement).style.width).toBe(`${width}px`)
  })
})

describe('G-a11y XConfirm/XTip', () => {
  it('confirm has name, description, initial focus and preserves raw failure', async () => {
    const w = render(XConfirm, {
      props: {
        modelValue: true,
        title: 'Remove',
        description: 'Remove item?',
        action: async () => {
          throw new Error('backend 原文')
        },
      },
      attachTo: document.body,
    })
    await flushPromises()
    const dialog = w.get('[role=alertdialog]')
    expect(document.getElementById(dialog.attributes('aria-labelledby')!)?.textContent).toBe('Remove')
    expect(document.getElementById(dialog.attributes('aria-describedby')!)?.textContent).toBe('Remove item?')
    expect(dialog.element.contains(document.activeElement)).toBe(true)
    await w.get('button').trigger('click')
    await flushPromises()
    expect(w.get('[role=alert]').text()).toBe('backend 原文')
    expect(w.emitted('update:modelValue')).toBeUndefined()
    drawerCount.value = 1
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    document.body.dispatchEvent(new Event('pointerdown', { bubbles: true }))
    expect(w.emitted('update:modelValue')).toBeUndefined()
    drawerCount.value = 0
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    expect(w.emitted('update:modelValue')?.[0]).toEqual([false])
  })

  it('only one confirm opens; outside closes; success closes', async () => {
    const a = ref(true)
    const b = ref(false)
    const host = render(defineComponent({
      setup() {
        return () => h('div', [
          h(XConfirm, {
            modelValue: a.value,
            title: 'A',
            description: 'A',
            action: async () => {},
            'onUpdate:modelValue': v => a.value = v,
          }),
          h(XConfirm, {
            modelValue: b.value,
            title: 'B',
            description: 'B',
            action: async () => {},
            'onUpdate:modelValue': v => b.value = v,
          }),
        ])
      },
    }), { attachTo: document.body })
    await flushPromises()
    b.value = true
    await flushPromises()
    expect(a.value).toBe(false)
    const second = host.findAllComponents(XConfirm)[1]!
    await second.get('button').trigger('click')
    await flushPromises()
    expect(b.value).toBe(false)
  })

  it('tip describes a real node with original help text', () => {
    const w = render(XTip, {
      props: { text: 'Original help', direction: 'up-right', wide: true },
      attachTo: document.body,
    })
    expect(document.getElementById(w.get('button').attributes('aria-describedby')!)?.textContent).toBe('Original help')
    expect(w.get('[role=tooltip]').classes()).toContain('tip-text')
  })
})

describe('G-a11y toggles and tabs', () => {
  it.each([[XSwitch, 'switch'], [XCheck, 'checkbox']] as const)(
    '%s uses role and Space toggle',
    async (component, role) => {
      const w = render(component, { props: { modelValue: false, label: 'Enabled' } })
      expect(w.get(`[role=${role}]`).attributes('aria-checked')).toBe('false')
      await w.get('button').trigger('keydown', { key: ' ', code: 'Space' })
      expect(w.emitted('update:modelValue')?.[0]).toEqual([true])
      await w.setProps({ modelValue: true })
      expect(w.get('button').attributes('aria-checked')).toBe('true')
    },
  )

  it('XSeg arrows select and focus, aria-pressed tracks selection', async () => {
    const w = render(XSeg, {
      props: { modelValue: 'a', options, label: 'Segments' },
      attachTo: document.body,
    })
    expect(w.get('button').attributes('aria-pressed')).toBe('true')
    await w.get('button').trigger('keydown', { key: 'ArrowRight' })
    expect(w.emitted('update:modelValue')?.[0]).toEqual(['c'])
    expect(document.activeElement?.textContent).toBe('Charlie')
    await w.findAll('button')[2]!.trigger('keydown', { key: 'ArrowLeft' })
    expect(w.emitted('update:modelValue')?.[1]).toEqual(['a'])
  })

  it('XTabs panel links, selected state, keyboard focus and query positioning', async () => {
    state.token = 'session'
    const router = makeRouter(createMemoryHistory())
    await router.push('/attacks/1?tab=c')
    await router.isReady()
    const w = render(XTabs, {
      props: { modelValue: 'a', tabs: options.filter(o => !o.disabled), label: 'Details', query: true },
      global: { plugins: [(await import('../src/i18n')).i18n, router] },
      attachTo: document.body,
    })
    const tabs = w.findAll('[role=tab]')
    expect(tabs[1]!.attributes('aria-selected')).toBe('true')
    for (const tab of tabs) expect(
      document.getElementById(tab.attributes('aria-controls')!)?.getAttribute('role'),
    ).toBe('tabpanel')
    await tabs[1]!.trigger('keydown', { key: 'ArrowRight' })
    await flushPromises()
    expect(router.currentRoute.value.query.tab).toBe('a')
    expect(document.activeElement).toBe(tabs[0]!.element)
    expect(tabs[0]!.attributes('aria-selected')).toBe('true')
    await tabs[0]!.trigger('keydown', { key: 'ArrowLeft' })
    await flushPromises()
    expect(router.currentRoute.value.query.tab).toBe('c')
    expect(document.activeElement).toBe(tabs[1]!.element)
  })
})

describe('G-behavior XNumber', () => {
  it.each([['99',10],['-1',0],['',5],['wrong',5],['2.56',2.6]])(
    'clamps/restores %s -> %s',
    async (draft, value) => {
      const w = render(XNumber, { props: { modelValue: 5, label: 'Number', min: 0, max: 10, digits: 1 } })
      await w.get('input').setValue(draft)
      await w.get('input').trigger('blur')
      expect(w.emitted('update:modelValue')?.[0]).toEqual([value])
      expect((w.get('input').element as HTMLInputElement).value).toBe(String(value))
    },
  )

  it('remembers latest valid value rather than initial value', async () => {
    const w = render(XNumber, { props: { modelValue: 5, label: 'Number', min: 0, max: 10 } })
    await w.get('input').setValue('7')
    await w.get('input').trigger('blur')
    await w.get('input').setValue('')
    await w.get('input').trigger('blur')
    expect(w.emitted('update:modelValue')?.[1]).toEqual([7])
  })

  it('validate-only keeps invalid text and emits no clamped value', async () => {
    const w = render(XNumber, { props: { modelValue: 5, label: 'ASN', min: 1, max: 10, validateOnly: true } })
    await w.get('input').setValue('99')
    await w.get('input').trigger('blur')
    expect(w.get('input').attributes('aria-invalid')).toBe('true')
    expect(w.emitted('valid')?.[0]).toEqual([false])
    expect(w.emitted('update:modelValue')).toBeUndefined()
    expect((w.get('input').element as HTMLInputElement).value).toBe('99')
  })
})

describe('G-a11y table and remaining components', () => {
  it('XTable sorts by Enter/Space, ignores nested controls, exposes heat and three states', async () => {
    const w = render(XTable, {
      props: {
        rows: [{ name: 'A', value: 40 }],
        columns: [
          { key: 'name', label: 'Name', sortable: true },
          { key: 'value', label: 'Share', heat: true },
        ],
        clickable: true,
        sortKey: 'name',
        sortDirection: 'ascending',
      },
      slots: { name: '<button>Action</button><a href="#">Link</a><div role="alertdialog">Confirm</div>' },
    })
    expect(w.get('th').attributes('aria-sort')).toBe('ascending')
    await w.get('th').trigger('keydown', { key: 'Enter' })
    await w.get('th').trigger('keydown', { key: ' ' })
    expect(w.emitted('sort')).toEqual([['name','descending'],['name','descending']])
    for (const control of w.findAll('tbody button,tbody a,[role=alertdialog]')) await control.trigger('click')
    expect(w.emitted('row')).toBeUndefined()
    await w.get('tbody tr').trigger('click')
    expect(w.emitted('row')?.length).toBe(1)
    expect(w.get('.heat').attributes('style')).toContain('--w: 40%')
    await w.setProps({ loading: true })
    expect(w.get('[role=status]').text()).toContain('加载中')
    await w.setProps({ loading: false, error: 'raw error' })
    expect(w.get('[role=alert]').text()).toContain('raw error')
    await w.setProps({ error: '', rows: [] })
    expect(w.get('[role=status]').text()).toContain('暂无数据')
  })

  it('XPager total pages and cursor mode', async () => {
    const w = render(XPager, { props: { modelValue: 1, total: 48, pageSize: 20 } })
    expect(w.text()).toContain('48')
    expect(w.findAll('button')[0]!.attributes('disabled')).toBeDefined()
    await w.findAll('button').at(-1)!.trigger('click')
    expect(w.emitted('update:modelValue')?.[0]).toEqual([2])
    await w.setProps({ total: undefined, hasNext: false })
    expect(w.findAll('button')).toHaveLength(2)
    expect(w.findAll('button')[1]!.attributes('disabled')).toBeDefined()
  })

  it('XPassword switches two static inputs and preserves value', async () => {
    const w = render(XPassword, { props: { modelValue: 'secret', label: 'Password' } })
    expect(w.get('input').attributes('type')).toBe('password')
    await w.get('button').trigger('click')
    expect(w.get('input').attributes('type')).toBe('text')
    expect((w.get('input').element as HTMLInputElement).value).toBe('secret')
    expect(w.get('button').attributes('aria-pressed')).toBe('true')
  })

  it('XCopy feedback succeeds/fails and resets at 1.5s', async () => {
    vi.useFakeTimers()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    const w = render(XCopy, { props: { text: 'copied text' } })
    await w.get('button').trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith('copied text')
    expect(w.text()).toContain('已复制')
    await vi.advanceTimersByTimeAsync(1500)
    expect(w.text()).toBe('复制')
    writeText.mockRejectedValue(new Error('Denied'))
    await w.get('button').trigger('click')
    await flushPromises()
    expect(w.text()).toContain('复制失败')
  })

  it.each([XBadge, XPill, XDot])('status marker preserves tone/name/content', component => {
    const w = render(component, {
      props: { tone: 'warn', label: 'Warning' },
      slots: { default: '3' },
    })
    expect(w.attributes('aria-label')).toBe('Warning')
    expect(w.classes()).toContain('warn')
    expect(w.text()).toBe('3')
  })

  it('XKpi shows paired metrics; XEmpty keeps raw errors', () => {
    const kpi = render(XKpi, { props: { label: 'Traffic', value: '1.42M', secondary: '9.62 Gbps' } })
    expect(kpi.text()).toContain('1.42M')
    expect(kpi.text()).toContain('9.62 Gbps')
    const empty = render(XEmpty, { props: { error: 'backend raw' } })
    expect(empty.get('.mono').text()).toBe('backend raw')
  })
})


describe('R2 F2 drawer hidden ancestor candidates', () => {
  it.each([
    ['hidden', false],
    ['hidden', true],
    ['inert', false],
    ['inert', true],
    ['display-none', false],
    ['display-none', true],
  ] as const)('R2 F2 excludes %s descendants, reverse=%s', async (kind, reverse) => {
    render(XDrawer, {
      props: { modelValue: true, title: 'Visible controls' },
      slots: {
        default: () => [
          h('button', { 'data-visible-end': '' }, 'Visible end'),
          h('section', {
            role: 'tabpanel',
            hidden: kind === 'hidden',
            inert: kind === 'inert',
            style: kind === 'display-none' ? { display: 'none' } : undefined,
          }, [h('button', { 'data-hidden-descendant': '' }, 'Unavailable panel control')]),
          h('button', { disabled: true }, 'Disabled tail'),
        ],
      },
      attachTo: document.body,
    })
    await flushPromises()
    const dialog = document.querySelector<HTMLElement>('[role=dialog]')!
    const first = dialog.querySelector<HTMLButtonElement>('header button')!
    const last = dialog.querySelector<HTMLButtonElement>('[data-visible-end]')!
    const start = reverse ? first : last
    start.focus()
    const tab = new KeyboardEvent('keydown', {
      key: 'Tab',
      shiftKey: reverse,
      bubbles: true,
      cancelable: true,
    })
    start.dispatchEvent(tab)
    expect(tab.defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(reverse ? last : first)
  })
})

describe('R2 F3 drawer fallback focus', () => {
  it('R2 F3 initially busy modal moves focus from its opener to the dialog', async () => {
    const opener = document.createElement('button')
    opener.textContent = 'Launch busy modal'
    document.body.append(opener)
    opener.focus()
    render(XDrawer, {
      props: { modelValue: true, title: 'Pending', busy: true },
      slots: { default: '<p>Waiting for content</p>' },
      attachTo: document.body,
    })
    await flushPromises()
    const dialog = document.querySelector<HTMLElement>('[role=dialog]')!
    expect(document.activeElement).toBe(dialog)
    expect(dialog.getAttribute('tabindex')).toBe('-1')
    expect(dialog.querySelector<HTMLButtonElement>('button')?.disabled).toBe(true)
  })

  it.each([false, true])('R2 F3 empty candidate list traps Tab, reverse=%s', async reverse => {
    render(XDrawer, {
      props: { modelValue: true, title: 'No available controls', busy: true },
      slots: { default: '<button disabled>Unavailable action</button>' },
      attachTo: document.body,
    })
    await flushPromises()
    const dialog = document.querySelector<HTMLElement>('[role=dialog]')!
    // Set up an already-focused dialog to isolate the empty-list trap from initial focus.
    dialog.setAttribute('tabindex', '-1')
    dialog.focus()
    const tab = new KeyboardEvent('keydown', {
      key: 'Tab',
      shiftKey: reverse,
      bubbles: true,
      cancelable: true,
    })
    dialog.dispatchEvent(tab)
    expect(tab.defaultPrevented).toBe(true)
    expect(document.activeElement).toBe(dialog)
  })
})

describe('R2 F4 select-only combobox relationship', () => {
  it('R2 F4 focused select trigger owns a visible active option as a combobox', async () => {
    const w = render(XListbox, {
      props: { modelValue: 'a', options, label: 'Select a value', mode: 'select' },
      attachTo: document.body,
    })
    const trigger = w.get('button')
    ;(trigger.element as HTMLElement).focus()
    await trigger.trigger('click')
    await trigger.trigger('keydown', { key: 'ArrowDown' })
    const focused = document.activeElement!
    expect(focused).toBe(trigger.element)
    expect(focused.getAttribute('role')).toBe('combobox')
    expect(focused.getAttribute('aria-haspopup')).toBe('listbox')
    expect(focused.getAttribute('aria-expanded')).toBe('true')
    const list = document.getElementById(focused.getAttribute('aria-controls')!)!
    const active = document.getElementById(focused.getAttribute('aria-activedescendant')!)!
    expect(list.getAttribute('role')).toBe('listbox')
    expect(list.contains(active)).toBe(true)
    expect(active.getAttribute('role')).toBe('option')
    expect(active.getAttribute('aria-disabled')).toBe('false')
    expect(active.closest('[hidden],[inert]')).toBeNull()
    expect((active as HTMLElement).hidden).toBe(false)
  })
})

describe('R3 R2-1 drawer dialog-origin navigation', () => {
  it.each([false, true])('R3 traps both Tab directions from dialog after busy finished=%s', async finished => {
    const opener = document.createElement('button')
    document.body.append(opener)
    opener.focus()
    const w = render(XDrawer, {
      props: { modelValue: true, title: 'Background operation', busy: true },
      slots: {
        default: () => [
          h('button', { 'data-first-action': '' }, 'First action'),
          h('button', { 'data-last-action': '' }, 'Last action'),
        ],
      },
      attachTo: document.body,
    })
    await flushPromises()
    const dialog = document.querySelector<HTMLElement>('[role=dialog]')!
    expect(document.activeElement).toBe(dialog)
    if (finished) await w.setProps({ busy: false })
    expect(document.activeElement).toBe(dialog)
    const close = dialog.querySelector<HTMLButtonElement>('header button')!
    const first = finished ? close : dialog.querySelector<HTMLButtonElement>('[data-first-action]')!
    const last = dialog.querySelector<HTMLButtonElement>('[data-last-action]')!
    expect(close.disabled).toBe(!finished)
    for (const reverse of [true, false]) {
      dialog.focus()
      const tab = new KeyboardEvent('keydown', {
        key: 'Tab',
        shiftKey: reverse,
        bubbles: true,
        cancelable: true,
      })
      dialog.dispatchEvent(tab)
      expect(tab.defaultPrevented, `dialog-origin Tab reverse=${reverse}`).toBe(true)
      expect(document.activeElement, `dialog-origin target reverse=${reverse}`).toBe(reverse ? last : first)
    }
  })
})
