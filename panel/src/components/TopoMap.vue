<script setup lang="ts">
// Топология сети на «Обзоре»: устройства → роутер → маршруты. Узлы — разметка, провода — один SVG поверх,
// координаты считаются по положению узлов (ResizeObserver). Движение — пунктир по активным проводам на CSS,
// без библиотек; при «уменьшить движение» пунктир стоит.
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { MonitorSmartphone, Router } from 'lucide-vue-next'
import ServiceLogo from './ServiceLogo.vue'

export type Tone = 'vpn' | 'zapret' | 'idle' | 'ok' | 'warn' | 'bad'
export interface TopoBranch {
  key: string
  kind: 'vpn' | 'zapret' | 'direct'
  name: string
  meta: string
  /** Трафик по маршруту идёт: провод с движением. */
  live: boolean
  tone: Tone
  items: { id: string; name: string }[]
  domains: string[]
  more: number
  note?: string
}
export interface TopoDevice { mac: string; initials: string; hue: number; name: string }

const props = defineProps<{
  branches: TopoBranch[]
  devices: { title: string; meta: string; avatars: TopoDevice[]; extra: number }
  hub: { tone: Tone; meta: string }
}>()
const emit = defineEmits<{ devices: [] }>()

const root = ref<HTMLElement | null>(null)
const devEl = ref<HTMLElement | null>(null)
const hubEl = ref<HTMLElement | null>(null)
const dst = ref<HTMLElement[]>([])
const box = ref({ w: 0, h: 0 })
interface Wire { key: string; d: string; kind: string; live: boolean }
const wires = ref<Wire[]>([])

/** Плавная кривая слева направо: от правого края одного узла к левому краю другого. */
function curve(x1: number, y1: number, x2: number, y2: number): string {
  const dx = Math.max(24, (x2 - x1) / 2)
  return `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`
}
function layout() {
  const r = root.value?.getBoundingClientRect()
  if (!r || !devEl.value || !hubEl.value) return
  // на телефоне узлы стоят столбиком, провода рисует CSS
  if (getComputedStyle(root.value!).getPropertyValue('--topo-svg').trim() === '0') { wires.value = []; return }
  box.value = { w: r.width, h: r.height }
  const at = (el: HTMLElement) => { const b = el.getBoundingClientRect(); return { l: b.left - r.left, r: b.right - r.left, y: b.top - r.top + Math.min(b.height / 2, 28) } }
  const d = at(devEl.value), h = at(hubEl.value)
  const anyLive = props.branches.some((b) => b.live)
  const out: Wire[] = [{ key: 'in', d: curve(d.r, d.y, h.l, h.y), kind: 'base', live: anyLive }]
  props.branches.forEach((b) => {
    const el = dst.value.find((x) => x.dataset.key === b.key)
    if (!el) return
    const t = at(el)
    out.push({ key: b.key, d: curve(h.r, h.y, t.l, t.y), kind: b.kind, live: b.live })
  })
  wires.value = out
}
let ro: ResizeObserver | undefined
onMounted(() => {
  ro = new ResizeObserver(() => layout())
  if (root.value) ro.observe(root.value)
  void nextTick(layout)
})
onBeforeUnmount(() => ro?.disconnect())
watch(() => props.branches, () => void nextTick(layout), { deep: true })
</script>

<template>
  <div ref="root" class="topo">
    <svg class="topo__wires" :viewBox="`0 0 ${box.w} ${box.h}`" :width="box.w" :height="box.h" aria-hidden="true">
      <g v-for="w in wires" :key="w.key">
        <path :d="w.d" :class="['wire', `wire--${w.kind}`, { 'wire--off': !w.live }]" />
        <path v-if="w.live" :d="w.d" :class="['wire__flow', `wire--${w.kind}`]" />
      </g>
    </svg>

    <div class="topo__col topo__col--src">
      <button ref="devEl" type="button" class="tnode" @click="emit('devices')">
        <span class="tnode__head"><MonitorSmartphone :size="16" class="tnode__icon" aria-hidden="true" /><span class="tnode__name">{{ devices.title }}</span></span>
        <span class="meta">{{ devices.meta }}</span>
        <span v-if="devices.avatars.length" class="tnode__faces" aria-hidden="true">
          <span v-for="a in devices.avatars" :key="a.mac" class="face" :style="{ '--h': a.hue }" :title="a.name">{{ a.initials }}</span>
          <span v-if="devices.extra" class="face face--more">+{{ devices.extra }}</span>
        </span>
      </button>
    </div>

    <div class="topo__col topo__col--hub">
      <div ref="hubEl" class="tnode tnode--hub">
        <span class="tnode__head"><Router :size="16" class="tnode__icon" aria-hidden="true" /><span class="tnode__name">Роутер</span></span>
        <span class="tnode__state"><span :class="['led', `led--${hub.tone}`]" aria-hidden="true" /><span class="meta">{{ hub.meta }}</span></span>
      </div>
    </div>

    <ul class="topo__col topo__col--dst" aria-label="Маршруты">
      <li v-for="b in branches" :key="b.key" ref="dst" :data-key="b.key" :class="['tdst', `tdst--${b.kind}`, { 'tdst--off': !b.live }]">
        <div class="tdst__head">
          <span :class="['led', `led--${b.tone}`]" aria-hidden="true" />
          <span class="tdst__name">{{ b.name }}</span>
          <span class="meta tdst__meta">{{ b.meta }}</span>
        </div>
        <p v-if="b.note" class="tdst__note">{{ b.note }}</p>
        <ul v-if="b.items.length || b.domains.length" class="tdst__items">
          <li v-for="x in b.items" :key="x.id" class="tdst__item"><ServiceLogo :id="x.id" size="sm" />{{ x.name }}</li>
          <li v-for="d in b.domains" :key="d" class="tdst__item meta">{{ d }}</li>
          <li v-if="b.more" class="tdst__item meta">ещё {{ b.more }}</li>
        </ul>
      </li>
    </ul>
  </div>
</template>
