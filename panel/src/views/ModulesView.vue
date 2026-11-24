<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Message from 'primevue/message'
import { HardDrive, Usb } from 'lucide-vue-next'
import { manage, type StorageInfo } from '../api'
import { t } from '../i18n'

const info = ref<StorageInfo | null>(null)
const failed = ref(false)
let timer: number | undefined
async function load() {
  clearTimeout(timer)
  try {
    const r = await manage.storage()
    if (r.status === 200) { info.value = r.body.storage; failed.value = false } else failed.value = true
  } catch { failed.value = true }
  // служба обновляет сведения раз в минуту: флешку вставили — она появится сама
  timer = window.setTimeout(() => void load(), 30_000)
}
onMounted(() => void load())
onBeforeUnmount(() => clearTimeout(timer))

/** Байты по-человечески: МБ до гигабайта, дальше ГБ с одним знаком. */
function size(b: number): string {
  const mb = b / 1024 / 1024
  return mb < 1024 ? t('{n} МБ', { n: Math.round(mb) }) : t('{n} ГБ', { n: (mb / 1024).toFixed(1).replace(/\.0$/, '') })
}
const pct = (s: { total: number; free: number }) => (s.total ? Math.round(((s.total - s.free) / s.total) * 100) : 0)
const usb = computed(() => info.value?.usb ?? [])
const title = (u: StorageInfo['usb'][number]) => [u.vendor, u.model].filter(Boolean).join(' ') || t('USB-накопитель')
</script>

<template>
  <section class="sect" :aria-label="t('Модули')">
    <p class="lead">{{ t('Модули добавляют пакету новые протоколы VPN (VLESS, Hysteria2, AmneziaWG и другие). Они большие, поэтому ставятся на флешку, подключённую к роутеру, или во внутреннюю память, если в ней хватает места.') }}</p>

    <div class="card">
      <div>
        <h2 class="card__title">{{ t('Накопители') }}</h2>
        <p class="card__sub">{{ t('Роутер проверяет подключённые накопители раз в минуту') }}</p>
      </div>
      <Message v-if="failed" severity="warn" :closable="false">{{ t('Сведения о накопителях не загрузились. Обновите страницу.') }}</Message>
      <p v-else-if="!info" class="muted">{{ t('Загружаю…') }}</p>
      <template v-else>
        <ul class="drives">
          <li v-if="info.data" class="drive">
            <HardDrive :size="20" class="drive__icon" aria-hidden="true" />
            <div class="drive__body">
              <div class="drive__head"><span class="drive__name">{{ t('Внутренняя память') }}</span><span class="drive__free num">{{ t('свободно {free} из {total}', { free: size(info.data.free), total: size(info.data.total) }) }}</span></div>
              <div class="meter" role="meter" :aria-valuenow="pct(info.data)" aria-valuemin="0" aria-valuemax="100" :aria-label="t('Занято {n}%', { n: pct(info.data) })"><span class="meter__fill" :style="{ width: `${pct(info.data)}%` }" /></div>
            </div>
          </li>
          <li v-for="u in usb" :key="u.path" class="drive">
            <Usb :size="20" class="drive__icon" aria-hidden="true" />
            <div class="drive__body">
              <div class="drive__head"><span class="drive__name">{{ title(u) }}</span><span class="drive__free num">{{ t('свободно {free} из {total}', { free: size(u.free), total: size(u.total) }) }}</span></div>
              <div class="meter" role="meter" :aria-valuenow="pct(u)" aria-valuemin="0" aria-valuemax="100" :aria-label="t('Занято {n}%', { n: pct(u) })"><span class="meter__fill" :style="{ width: `${pct(u)}%` }" /></div>
              <span class="drive__meta num">{{ u.path }} · {{ u.fs }}<template v-if="!u.writable"> · {{ t('только чтение') }}</template></span>
            </div>
          </li>
        </ul>
        <p v-if="!usb.length" class="hint">{{ t('Флешка не подключена. Вставьте её в USB-порт роутера — она появится здесь в течение минуты.') }}</p>
      </template>
    </div>

    <div class="card">
      <div>
        <h2 class="card__title">{{ t('Доступные модули') }}</h2>
        <p class="card__sub">{{ t('Первые модули — VLESS и Hysteria2, затем AmneziaWG — появятся в следующих обновлениях. Установка — здесь, одной кнопкой.') }}</p>
      </div>
    </div>
  </section>
</template>

<style scoped>
.drives { display: grid; gap: 1rem; margin: 0; padding: 0; list-style: none; }
.drive { display: flex; gap: 0.875rem; align-items: flex-start; }
.drive__icon { flex: none; margin-top: 0.125rem; color: var(--muted); }
.drive__body { display: grid; gap: 0.375rem; flex: 1; min-width: 0; }
.drive__head { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 0.25rem 1rem; }
.drive__name { font-weight: 600; overflow-wrap: anywhere; }
.drive__free, .drive__meta { font-size: 0.8125rem; color: var(--muted); overflow-wrap: anywhere; }
.meter { height: 6px; border-radius: 3px; background: var(--idle-soft); overflow: hidden; }
.meter__fill { display: block; height: 100%; background: var(--accent); border-radius: 3px; }
</style>
