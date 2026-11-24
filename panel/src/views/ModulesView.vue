<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import Message from 'primevue/message'
import { HardDrive, Package, Usb } from 'lucide-vue-next'
import { manage, type ModuleInfo, type ModulesResponse, type StorageDrive, type StorageInfo } from '../api'
import { notify } from '../store'
import HistoryCard from '../components/HistoryCard.vue'
import { t } from '../i18n'

const info = ref<StorageInfo | null>(null)
const mods = ref<ModulesResponse | null>(null)
const failed = ref(false)
let timer: number | undefined
async function load() {
  clearTimeout(timer)
  try {
    const [s, m] = await Promise.all([manage.storage(), manage.modules()])
    if (s.status === 200) info.value = s.body.storage
    if (m.status === 200) mods.value = m.body
    failed.value = s.status !== 200 || m.status !== 200
  } catch { failed.value = true }
  // идёт установка — опрос чаще; иначе служба обновляет накопители раз в минуту
  timer = window.setTimeout(() => void load(), mods.value?.running ? 2000 : 30_000)
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
const title = (u: StorageDrive) => [u.vendor, u.model].filter(Boolean).join(' ') || t('USB-накопитель')
const drives = computed<StorageDrive[]>(() => [...(info.value?.data ? [info.value.data] : []), ...usb.value])
const driveName = (d: StorageDrive) => (d === info.value?.data ? t('Внутренняя память') : title(d))

// ---- установка ----
const target = ref<Record<string, string>>({})
/** Почему на накопитель нельзя поставить модуль (null — можно). */
function why(d: StorageDrive, m: ModuleInfo): string | null {
  if (!d.writable) return t('только чтение')
  if (d.free < m.need_bytes) return t('мало места: нужно {n}', { n: size(m.need_bytes) })
  return null
}
function pickDefault(m: ModuleInfo): string {
  // по умолчанию — флешка с местом, иначе внутренняя память, если хватает
  const ok = drives.value.filter((d) => !why(d, m))
  return (ok.find((d) => d !== info.value?.data) ?? ok[0])?.path ?? ''
}
const chosen = (m: ModuleInfo) => target.value[m.name] ?? pickDefault(m)
const busy = computed(() => !!mods.value?.running)
const opFor = (m: ModuleInfo) => (mods.value?.op && mods.value.op.name === m.name ? mods.value.op : null)
async function install(m: ModuleInfo, path: string) {
  const r = await manage.installModule(m.name, path)
  if (r.status !== 202) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  notify.show('info', t('Устанавливаю {m}', { m: m.title }))
  await load()
}
/** Накопитель установленного модуля — для обновления на то же место. */
function driveOf(m: ModuleInfo): string {
  const p = m.installed?.path ?? ''
  const d = drives.value.find((x) => p === `${x.path}/modules/${m.name}` || p === `${x.path}/mi-lumruri-modules/${m.name}`)
  return d?.path ?? ''
}
const confirmRemove = ref<string | null>(null)
async function remove(m: ModuleInfo) {
  if (confirmRemove.value !== m.name) { confirmRemove.value = m.name; return }
  confirmRemove.value = null
  const r = await manage.removeModule(m.name)
  if (r.status !== 202) { notify.show('error', t('Не получилось'), r.body.error?.message); return }
  await load()
}
const stateText = (m: ModuleInfo) => {
  switch (m.installed?.state) {
    case 'ok': return t('Работает')
    case 'missing': return t('Накопитель не подключён — серверы модуля работают до перезагрузки роутера или не работают')
    case 'bad': return t('Файлы модуля повреждены — переустановите его')
    default: return t('Состояние уточняется')
  }
}
</script>

<template>
  <section class="sect" :aria-label="t('Модули')">
    <p class="lead">{{ t('Модули добавляют пакету новые протоколы VPN (VLESS, Hysteria2, AmneziaWG и другие). Они большие, поэтому ставятся на флешку, подключённую к роутеру, или во внутреннюю память, если в ней хватает места.') }}</p>
    <Message v-if="failed" severity="warn" :closable="false">{{ t('Сведения о накопителях не загрузились. Обновите страницу.') }}</Message>

    <div v-for="m in mods?.modules ?? []" :key="m.name" class="card">
      <div class="card__head">
        <div class="mod__head">
          <Package :size="22" class="drive__icon" aria-hidden="true" />
          <div>
            <h2 class="card__title">{{ m.title }} <span class="mod__ver num">{{ m.version }}</span></h2>
            <p class="card__sub">{{ t('Протоколы: {list}', { list: m.protocols.join(', ') }) }}</p>
          </div>
        </div>
      </div>
      <p class="meta">{{ t('Скачать {d}, в памяти роутера во время работы {r}', { d: size(m.download_bytes), r: size(m.ram_bytes) }) }}</p>

      <Message v-if="opFor(m)?.state === 'running'" severity="info" :closable="false">{{ opFor(m)?.message ?? t('Устанавливаю…') }}</Message>
      <Message v-else-if="opFor(m)?.state === 'failed'" severity="error" :closable="false">{{ t('Не получилось: {e}', { e: opFor(m)?.message ?? '' }) }}</Message>

      <template v-if="m.installed">
        <span :class="['adblock__state', { 'adblock__state--bad': m.installed.state !== 'ok' }]">
          <span :class="['led', m.installed.state === 'ok' ? 'led--ok' : 'led--warn']" aria-hidden="true" />
          <span class="meta">{{ stateText(m) }}</span>
        </span>
        <p class="meta num">{{ t('Версия {v}, лежит в {p}', { v: m.installed.version, p: m.installed.path }) }}</p>
        <p v-if="m.used_by.length" class="hint">{{ t('Используют серверы: {list}', { list: m.used_by.join(', ') }) }}</p>
        <div class="mod__actions">
          <Button v-if="m.installed.update && driveOf(m)" :label="t('Обновить до {v}', { v: m.version })" size="small" :disabled="busy" @click="install(m, driveOf(m))" />
          <Button v-if="m.installed.state === 'bad' && driveOf(m)" :label="t('Переустановить')" size="small" :disabled="busy" @click="install(m, driveOf(m))" />
          <Button :label="confirmRemove === m.name ? t('Точно удалить модуль?') : t('Удалить модуль')" size="small" variant="text"
            :severity="confirmRemove === m.name ? 'danger' : 'secondary'" :disabled="busy || m.used_by.length > 0" @click="remove(m)" />
        </div>
        <p v-if="m.used_by.length" class="hint">{{ t('Чтобы удалить модуль, сначала удалите его серверы на экране «Сервер».') }}</p>
      </template>

      <template v-else>
        <fieldset class="mod__targets">
          <legend class="field__label">{{ t('Куда поставить') }}</legend>
          <label v-for="d in drives" :key="d.path" :class="['mod__target', { 'mod__target--off': !!why(d, m) }]">
            <input type="radio" :name="`target-${m.name}`" :value="d.path" :checked="chosen(m) === d.path" :disabled="!!why(d, m)" @change="target[m.name] = d.path" />
            <span class="mod__target-name">{{ driveName(d) }}</span>
            <span class="meta num">{{ why(d, m) ?? t('свободно {free}', { free: size(d.free) }) }}</span>
          </label>
        </fieldset>
        <p v-if="!chosen(m)" class="hint">{{ t('Места не хватает ни на одном накопителе. Подключите флешку к USB-порту роутера.') }}</p>
        <Button :label="t('Установить')" class="self-start" :disabled="busy || !chosen(m)" :loading="opFor(m)?.state === 'running'" @click="install(m, chosen(m))" />
      </template>
    </div>

    <HistoryCard :storage="info" />

    <div class="card">
      <div>
        <h2 class="card__title">{{ t('Накопители') }}</h2>
        <p class="card__sub">{{ t('Роутер проверяет подключённые накопители раз в минуту') }}</p>
      </div>
      <p v-if="!info && !failed" class="muted">{{ t('Загружаю…') }}</p>
      <template v-else-if="info">
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
.mod__head { display: flex; gap: 0.75rem; align-items: flex-start; }
.mod__ver { font-size: 0.8125rem; font-weight: 400; color: var(--muted); }
.mod__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
.mod__targets { display: grid; gap: 0.5rem; margin: 0; padding: 0; border: 0; min-width: 0; }
.mod__target { display: flex; flex-wrap: wrap; align-items: center; gap: 0.25rem 0.625rem; padding: 0.625rem 0.75rem; border: 1px solid var(--line); border-radius: 10px; cursor: pointer; }
.mod__target:has(input:checked) { border-color: var(--accent); }
.mod__target:has(input:focus-visible) { outline: 2px solid var(--focus); outline-offset: 1px; }
.mod__target--off { opacity: 0.6; cursor: not-allowed; }
.mod__target-name { font-weight: 500; flex: 1; min-width: 8rem; overflow-wrap: anywhere; }
</style>
