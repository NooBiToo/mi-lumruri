<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import InputText from 'primevue/inputtext'
import ToggleSwitch from 'primevue/toggleswitch'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'
import type { ListsUpdate } from '../api'
import { CUSTOM_DNS, DNS_PRESETS, dnsPresetIp, dnsPresetOf, dnsToForm, formToDns, type DnsForm } from '../manage'
import { config, save, service } from '../store'
import { when } from '../status'
import { saveNow, useAutosave, type Blocker } from '../autosave'
import { dnsIcon } from '../brand'
import ServiceLogo from '../components/ServiceLogo.vue'
import Segmented from '../components/Segmented.vue'

defineProps<{ totp: boolean }>()
const emit = defineEmits<{ navigate: [tab: 'zapret' | 'hosts' | 'diag'] }>()

interface Draft { dns: DnsForm }
const toDraft = (): Draft => ({ dns: dnsToForm(config.value?.dns) })
const draft = ref<Draft>(toDraft())
const pristine = ref(JSON.stringify(draft.value))
const dirty = computed(() => JSON.stringify(draft.value) !== pristine.value)
watch(config, () => {
  if (!dirty.value) { draft.value = toDraft(); pristine.value = JSON.stringify(draft.value); custom.value = dnsPresetOf(draft.value.dns.resolver) === CUSTOM_DNS }
})

// ---- DNS: готовый сервер или свой адрес ----
/** «Свой адрес» выбран явно: пока адрес не дописан, он может совпасть с готовым или быть пустым. */
const custom = ref(dnsPresetOf(draft.value.dns.resolver) === CUSTOM_DNS)
const dnsChoice = computed(() => (custom.value ? CUSTOM_DNS : dnsPresetOf(draft.value.dns.resolver)))
const DNS_OPTIONS = [...DNS_PRESETS, { id: CUSTOM_DNS, name: 'Свой адрес', ip: '', desc: 'Любой публичный DNS-сервер (IPv4)' }]
const dnsNote = computed(() => DNS_PRESETS.find((p) => p.id === dnsChoice.value)?.note ?? null)
function chooseDns(id: string) {
  const ip = dnsPresetIp(id)
  custom.value = ip === null
  if (ip !== null) draft.value.dns.resolver = ip
}

const totpHelp = ref(false)

// ---- обновление готовых списков сайтов: сохраняется сразу ----
const LISTS_UPDATES = [
  { value: '6h' as const, label: 'Каждые 6 часов' }, { value: 'daily' as const, label: 'Раз в сутки' },
  { value: 'weekly' as const, label: 'Раз в неделю' }, { value: 'manual' as const, label: 'Вручную' },
]
const listsUpdate = ref<ListsUpdate>(config.value?.schedule?.lists ?? 'daily')
watch(() => config.value?.schedule?.lists, (v) => { listsUpdate.value = v ?? 'daily' })
watch(listsUpdate, async (v) => {
  const c = config.value
  if (!c || (c.schedule?.lists ?? 'daily') === v) return
  const ok = await saveNow(() => save({ ...c, schedule: { ...c.schedule, lists: v } }, ''))
  if (!ok) listsUpdate.value = config.value?.schedule?.lists ?? 'daily'
})

// ---- автосохранение ----
/** Адрес DNS проверяем мягко до сохранения, чтобы не отправлять недописанный «1.1». Точнее проверит контроллер. */
const resolverOk = computed(() => {
  const v = draft.value.dns.resolver.trim()
  return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v)
})
// ---- блокировка рекламы ----
const ADBLOCK_SOURCES = [
  { value: 'light' as const, label: 'HaGeZi Light', desc: 'Реклама и трекеры, почти не мешает сайтам — около 90 тыс. доменов. Рекомендуется' },
  { value: 'normal' as const, label: 'HaGeZi Normal', desc: 'Шире: больше трекеров и телеметрии, изредка может мешать отдельным сайтам — около 200 тыс. доменов' },
  { value: 'url' as const, label: 'Своя ссылка', desc: 'Любой список доменов или hosts по ссылке https' },
]
const adblockUrlOk = computed(() => draft.value.dns.adblockSource !== 'url' || /^https:\/\/[^\s"'`\\$<>|;]+$/.test(draft.value.dns.adblockUrl.trim()))
/** Итог загрузки — только если он про текущую ссылку (после смены списка ждём новую загрузку). */
const adblockState = computed(() => {
  const a = service.value?.adblock
  return a && (!a.url || a.url === currentAdblockUrl.value) ? a : null
})
const HAGEZI = { light: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt', normal: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt' }
const currentAdblockUrl = computed(() => {
  const a = config.value?.dns?.adblock
  return !a ? null : a.source === 'url' ? (a.url ?? null) : HAGEZI[a.source ?? 'light']
})
const adblockText = computed(() => {
  const a = adblockState.value
  if (!adblockUrlOk.value) return 'Не сохранено: сначала укажите ссылку https://…'
  if (dirty.value) return 'Сохраняется…'
  if (!a) return 'Роутер скачает список в течение минуты'
  if (a.error) return `Список не обновился: ${a.error}. Пока действует прежний, если он был`
  return `${(a.domains ?? 0).toLocaleString('ru-RU')} доменов · список ${a.updated ? `от ${when(a.updated)}` : 'загружен'} · проверен ${when(a.checked)}`
})

// ---- защищённый DNS (DoH/DoT) ----
const SECURE_MODES = [{ value: 'off' as const, label: 'Выключен' }, { value: 'doh' as const, label: 'DoH' }, { value: 'dot' as const, label: 'DoT' }]
const SECURE_SERVERS = [
  { id: 'cloudflare' as const, name: 'Cloudflare', desc: 'Быстрый, без фильтров' },
  { id: 'quad9' as const, name: 'Quad9', desc: 'Не открывает опасные сайты' },
  { id: 'google' as const, name: 'Google', desc: 'Надёжный, без фильтров' },
  { id: 'adguard' as const, name: 'AdGuard DNS', desc: 'Блокирует рекламу и трекеры' },
  { id: 'nextdns' as const, name: 'NextDNS', desc: 'Свои фильтры, нужен ID профиля' },
  { id: 'custom' as const, name: 'Свой сервер', desc: 'Ссылка или имя и IP-адреса' },
]
// DoH у Quad9 не работает (только HTTP/2): при переключении на DoH — Cloudflare
watch(() => draft.value.dns.secure, (m) => { if (m === 'doh' && draft.value.dns.secureServer === 'quad9') draft.value.dns.secureServer = 'cloudflare' })
/** Мягкая проверка до сохранения: NextDNS — 6 символов, свой — ссылка/имя и хотя бы один IP. Точнее проверит контроллер. */
const secureOk = computed(() => {
  const f = draft.value.dns
  if (f.secure === 'off') return true
  if (f.secureServer === 'nextdns') return /^[0-9a-f]{6}$/i.test(f.nextdnsId.trim())
  if (f.secureServer !== 'custom') return true
  const url = f.secureUrl.trim()
  const urlOk = f.secure === 'doh' ? /^https:\/\/[a-z0-9.-]+(:\d+)?(\/\S*)?$/i.test(url) : /^[a-z0-9.-]+\.[a-z0-9-]+(:\d+)?$/i.test(url)
  return urlOk && f.secureIps.split(/[\s,;]+/).filter(Boolean).length > 0
})
/** Состояние прокси: только если он включён в сохранённых настройках и пишет состояние. */
const secureState = computed(() => {
  const p = service.value?.dns_proxy
  if (!p || !config.value?.dns?.secure || dirty.value) return null
  const via = p.upstream.startsWith('dot') ? 'DoT' : 'DoH'
  if (!p.upstream_ok && p.fallback) return { tone: 'warn', text: `Сервер недоступен — ответы идут через DNS провайдера${p.last_error ? `: ${p.last_error}` : ''}` }
  // единичные сбои (например, при загрузке, пока часы роутера не выставлены) — не повод для предупреждения
  if (p.fallback) return { tone: p.fallback * 20 > p.upstream_ok + p.fallback ? 'warn' : 'ok',
    text: `Работает (${via}): ответов ${p.upstream_ok}, через провайдера при сбоях — ${p.fallback}${p.last_error ? ` · последняя ошибка: ${p.last_error}` : ''}` }
  return { tone: 'ok', text: p.queries ? `Работает (${via}): ответов через защищённый сервер — ${p.upstream_ok}` : `Включён (${via}), вопросов пока не было` }
})

function blocker(): Blocker | null {
  if (!secureOk.value) return { text: 'Защищённый DNS: проверьте ID NextDNS или адрес своего сервера' }
  if (!adblockUrlOk.value) return { text: 'Ссылка на список рекламы — https://…' }
  return resolverOk.value ? null : { text: 'Свой DNS-сервер — адрес IPv4, например 1.1.1.1.' }
}
useAutosave({
  source: draft,
  dirty: () => dirty.value,
  blocker,
  run: async () => {
    if (!config.value) return 'Настройки ещё не загружены.'
    const sent = JSON.stringify(draft.value)
    const next = { ...config.value }
    const dns = formToDns(draft.value.dns)
    if (dns) next.dns = dns
    else delete next.dns
    const r = await save(next, '')
    if (r.ok) {
      // сохранённое — новая точка отсчёта; правки, сделанные во время запроса, останутся несохранёнными
      pristine.value = sent
      if (!dirty.value) { draft.value = toDraft(); pristine.value = JSON.stringify(draft.value) }
    }
    return r
  },
})
</script>

<template>
  <section class="sect" aria-label="Дополнительно">
    <p class="lead">Обычно здесь ничего менять не нужно. Изменения сохраняются сами</p>

    <!-- телефон: разделы, которых нет в нижней панели -->
    <nav class="card card--flush settings more-links" aria-label="Другие разделы">
      <button type="button" class="setrow more-link" @click="emit('navigate', 'zapret')">
        <span class="setrow__text"><span class="setrow__title">Zapret</span><span class="setrow__desc">Способ обхода блокировок, подбор, автопроверка</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
      <button type="button" class="setrow more-link" @click="emit('navigate', 'hosts')">
        <span class="setrow__text"><span class="setrow__title">Свои DNS-записи</span><span class="setrow__desc">Домашние серверы по своим именам</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
      <button type="button" class="setrow more-link" @click="emit('navigate', 'diag')">
        <span class="setrow__text"><span class="setrow__title">Диагностика</span><span class="setrow__desc">Проверка работы, журналы, перезапуск службы</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
    </nav>

    <div class="card card--flush settings">
      <div class="setblock" role="group" aria-labelledby="adblock-title">
        <label class="setrow setrow--bare">
          <span class="setrow__text">
            <span id="adblock-title" class="setrow__title">Блокировка рекламы</span>
            <span class="setrow__desc">Работает через DNS роутера: на домены из списка рекламы и трекеров роутер отвечает «такого сайта нет».
              Действует на все устройства, которые получают DNS от роутера</span>
          </span>
          <ToggleSwitch v-model="draft.dns.adblock" input-id="adblock" />
        </label>
        <template v-if="draft.dns.adblock">
          <Segmented v-model="draft.dns.adblockSource" class="self-start" :options="ADBLOCK_SOURCES" label="Список рекламы" name="adblock-source" />
          <span class="field__hint">{{ ADBLOCK_SOURCES.find((o) => o.value === draft.dns.adblockSource)?.desc }}</span>
          <div v-if="draft.dns.adblockSource === 'url'" class="field dns__custom dns__custom--wide">
            <label for="adblock-url" class="field__label">Ссылка на список</label>
            <InputText id="adblock-url" v-model="draft.dns.adblockUrl" placeholder="https://…/list.txt" spellcheck="false" autocomplete="off"
              :invalid="!adblockUrlOk" aria-describedby="adblock-url-hint" />
            <span id="adblock-url-hint" :class="adblockUrlOk ? 'field__hint' : 'field__error'">{{ adblockUrlOk
              ? 'По домену в строке или строки hosts (0.0.0.0 домен); # — комментарий'
              : 'Нужна ссылка https://…' }}</span>
          </div>
          <span :class="['adblock__state', { 'adblock__state--bad': adblockState?.error }]">
            <span :class="['led', adblockState ? (adblockState.error ? 'led--warn' : 'led--ok') : 'led--idle']" aria-hidden="true" />
            <span class="meta">{{ adblockText }}</span>
          </span>
        </template>
      </div>

      <div class="setblock" role="group" aria-labelledby="dns-title">
        <span class="setrow__text">
          <span id="dns-title" class="setrow__title">DNS для сайтов через VPN</span>
          <span class="setrow__desc">Через него, внутри VPN, узнаются адреса сайтов из ваших списков. Обычно подходит Cloudflare.</span>
        </span>
        <div class="dns" role="radiogroup" aria-labelledby="dns-title">
          <label v-for="o in DNS_OPTIONS" :key="o.id" :class="['dns__opt', { 'dns__opt--on': dnsChoice === o.id }]">
            <input type="radio" name="dns" class="dns__radio" :value="o.id" :checked="dnsChoice === o.id" @change="chooseDns(o.id)" />
            <ServiceLogo :icon="dnsIcon(o.id)" />
            <span class="dns__text">
              <span class="dns__name">{{ o.name }}<span v-if="o.ip" class="dns__ip num">{{ o.ip }}</span></span>
              <span class="dns__desc">{{ o.desc }}</span>
            </span>
          </label>
        </div>
        <p v-if="dnsNote" class="dns__note">{{ dnsNote }}</p>
        <div v-if="dnsChoice === 'custom'" class="field dns__custom">
          <label for="dns" class="field__label">Адрес DNS-сервера</label>
          <InputText id="dns" v-model="draft.dns.resolver" class="num" placeholder="например, 1.0.0.1" inputmode="decimal" :invalid="!resolverOk" aria-describedby="dns-hint" />
          <span id="dns-hint" :class="resolverOk ? 'field__hint' : 'field__error'">{{ resolverOk ? 'Публичный адрес IPv4.' : 'Нужен адрес IPv4, например 1.0.0.1.' }}</span>
        </div>
      </div>

      <div class="setblock" role="group" aria-labelledby="secure-title">
        <span class="setrow__text">
          <span id="secure-title" class="setrow__title">Защищённый DNS для остальных сайтов</span>
          <span class="setrow__desc">Адреса сайтов не через VPN (в том числе с обходом блокировок) роутер узнаёт по шифрованному каналу —
            провайдер не видит и не подменяет ответы. Если сервер недоступен, роутер временно спрашивает DNS провайдера, чтобы интернет не пропадал</span>
        </span>
        <Segmented v-model="draft.dns.secure" class="self-start" :options="SECURE_MODES" label="Защищённый DNS" name="secure-mode" />
        <template v-if="draft.dns.secure !== 'off'">
          <p v-if="draft.dns.secure === 'dot'" class="dns__note">Провайдеры в России часто блокируют DoT (порт 853). Если в состоянии ниже ответы идут через провайдера — выберите DoH</p>
          <div class="dns" role="radiogroup" aria-label="Сервер защищённого DNS">
            <label v-for="o in SECURE_SERVERS" :key="o.id" :class="['dns__opt', { 'dns__opt--on': draft.dns.secureServer === o.id, 'dns__opt--off': o.id === 'quad9' && draft.dns.secure === 'doh' }]">
              <input v-model="draft.dns.secureServer" type="radio" name="secure-server" class="dns__radio" :value="o.id" :disabled="o.id === 'quad9' && draft.dns.secure === 'doh'" />
              <ServiceLogo :icon="dnsIcon(o.id)" />
              <span class="dns__text">
                <span class="dns__name">{{ o.name }}</span>
                <span class="dns__desc">{{ o.id === 'quad9' && draft.dns.secure === 'doh' ? 'Только DoT: DoH у Quad9 — HTTP/2' : o.desc }}</span>
              </span>
            </label>
          </div>
          <div v-if="draft.dns.secureServer === 'nextdns'" class="field dns__custom">
            <label for="nextdns-id" class="field__label">ID профиля NextDNS</label>
            <InputText id="nextdns-id" v-model="draft.dns.nextdnsId" class="num" placeholder="abc123" spellcheck="false" autocomplete="off" :invalid="!secureOk" />
            <span class="field__hint">6 символов из личного кабинета NextDNS (раздел «Настройка»)</span>
          </div>
          <div v-if="draft.dns.secureServer === 'custom'" class="row2 dns__custom--wide">
            <div class="field">
              <label for="secure-url" class="field__label">{{ draft.dns.secure === 'doh' ? 'Ссылка DoH' : 'Имя сервера DoT' }}</label>
              <InputText id="secure-url" v-model="draft.dns.secureUrl" :placeholder="draft.dns.secure === 'doh' ? 'https://dns.example/dns-query' : 'dns.example'"
                spellcheck="false" autocomplete="off" :invalid="!secureOk" />
            </div>
            <div class="field">
              <label for="secure-ips" class="field__label">IP-адреса сервера</label>
              <InputText id="secure-ips" v-model="draft.dns.secureIps" class="num" placeholder="203.0.113.5, 203.0.113.6" spellcheck="false" autocomplete="off" :invalid="!secureOk" />
            </div>
            <span class="field__hint">IP нужны, чтобы подключаться к серверу без DNS: до 4 адресов через запятую</span>
          </div>
          <span :class="['adblock__state', { 'adblock__state--bad': secureState?.tone === 'warn' }]">
            <span :class="['led', `led--${secureState?.tone ?? 'idle'}`]" aria-hidden="true" />
            <span class="meta">{{ secureState?.text ?? (dirty ? 'Сохраняется…' : 'Роутер включит защищённый DNS в течение минуты') }}</span>
          </span>
        </template>
      </div>

      <div class="setblock" role="group" aria-labelledby="lists-title">
        <span class="setrow__text">
          <span id="lists-title" class="setrow__title">Обновление списков сайтов</span>
          <span class="setrow__desc">Как часто роутер проверяет новые версии готовых списков (allow-domains). «Вручную» — только по кнопке «Обновить» на «Обзоре»</span>
        </span>
        <Segmented v-model="listsUpdate" class="self-start" :options="LISTS_UPDATES" label="Обновление списков сайтов" name="lists-update" />
      </div>

      <div class="setrow setrow--top">
        <span class="setrow__text">
          <span class="setrow__title">Вход в панель</span>
          <span class="setrow__desc">{{ totp ? 'По паролю и коду из приложения-аутентификатора.' : 'Только по паролю. Можно добавить второй шаг: код из приложения на телефоне (Google Authenticator и подобные).' }}</span>
          <template v-if="!totp">
            <button type="button" class="disclose" :aria-expanded="totpHelp" aria-controls="totp-help" @click="totpHelp = !totpHelp">
              <ChevronDown :size="16" :class="['disclose__icon', { 'disclose__icon--open': totpHelp }]" aria-hidden="true" />Как включить
            </button>
            <span v-show="totpHelp" id="totp-help" class="setrow__desc">Подключитесь к роутеру по SSH и выполните
              <code>sh /data/mi-trusttunnel/mitt-boot.sh auth reset-totp</code>, отсканируйте QR-код приложением, затем
              <code>sh /data/mi-trusttunnel/mitt-boot.sh auth confirm</code>. Подробнее — в инструкции, раздел «Второй фактор».</span>
          </template>
        </span>
        <span :class="['badge', totp ? 'badge--ok' : 'badge--idle']">{{ totp ? 'Пароль и код' : 'Только пароль' }}</span>
      </div>
    </div>

  </section>
</template>
