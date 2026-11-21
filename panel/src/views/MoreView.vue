<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import InputText from 'primevue/inputtext'
import ToggleSwitch from 'primevue/toggleswitch'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'
import { CUSTOM_DNS, DNS_PRESETS, dnsPresetIp, dnsPresetOf, dnsToForm, formToDns, tunnelSecureModes, type DnsForm } from '../manage'
import { config, save, service } from '../store'
import { when } from '../status'
import { saveNow, useAutosave, type Blocker } from '../autosave'
import { dnsIcon } from '../brand'
import ServiceLogo from '../components/ServiceLogo.vue'
import Segmented from '../components/Segmented.vue'
import UpdateCard from '../components/UpdateCard.vue'
import BackupCard from '../components/BackupCard.vue'
import LangSwitch from '../components/LangSwitch.vue'
import { dateTag, t } from '../i18n'

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
const DNS_OPTIONS = computed(() => [...DNS_PRESETS, { id: CUSTOM_DNS, name: t('Свой адрес'), ip: '', desc: t('Любой публичный DNS-сервер (IPv4)') }])
const dnsNote = computed(() => DNS_PRESETS.find((p) => p.id === dnsChoice.value)?.note ?? null)
function chooseDns(id: string) {
  const ip = dnsPresetIp(id)
  custom.value = ip === null
  if (ip !== null) draft.value.dns.resolver = ip
}

const totpHelp = ref(false)

// ---- IPv6 через VPN (для источников «весь интернет через VPN») ----
const ipv6 = ref(!!config.value?.ipv6_via_vpn)
watch(() => config.value?.ipv6_via_vpn, (v) => { ipv6.value = !!v })
async function setIpv6(v: boolean) {
  const c = config.value
  if (!c || !!c.ipv6_via_vpn === v) return
  const next = { ...c }
  if (v) next.ipv6_via_vpn = true
  else delete next.ipv6_via_vpn
  if (!(await saveNow(() => save(next, '')))) ipv6.value = !!config.value?.ipv6_via_vpn
}


// ---- автосохранение ----
/** Адрес DNS проверяем мягко до сохранения, чтобы не отправлять недописанный «1.1». Точнее проверит контроллер. */
const resolverOk = computed(() => {
  const v = draft.value.dns.resolver.trim()
  return /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v)
})
// ---- блокировка рекламы ----
const ADBLOCK_SOURCES = computed(() => [
  { value: 'light' as const, label: 'HaGeZi Light', desc: t('Реклама и трекеры, почти не мешает сайтам — около 90 тыс. доменов. Рекомендуется') },
  { value: 'normal' as const, label: 'HaGeZi Normal', desc: t('Шире: больше трекеров и телеметрии, изредка может мешать отдельным сайтам — около 200 тыс. доменов') },
  { value: 'url' as const, label: t('Своя ссылка'), desc: t('Любой список доменов или hosts по ссылке https') },
])
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
  if (!adblockUrlOk.value) return t('Не сохранено: сначала укажите ссылку https://…')
  if (dirty.value) return t('Сохраняется…')
  if (!a) return t('Роутер скачает список в течение минуты')
  if (a.error) return t('Список не обновился: {e}. Пока действует прежний, если он был', { e: a.error })
  const n = (a.domains ?? 0).toLocaleString(dateTag())
  return a.updated
    ? t('{n} доменов · список от {updated} · проверен {checked}', { n, updated: when(a.updated), checked: when(a.checked) })
    : t('{n} доменов · список загружен · проверен {checked}', { n, checked: when(a.checked) })
})

// ---- шифрование DNS через VPN (DoH/DoT поверх туннеля) ----
const tunnelModes = computed(() => tunnelSecureModes(draft.value.dns.resolver.trim()))
const tunnelSecureLabel = (m: 'off' | 'doh' | 'dot'): string => (m === 'off' ? t('Обычный') : m === 'doh' ? 'DoH' : 'DoT')
const TUNNEL_SECURE_MODES = computed(() => tunnelModes.value.map((m) => ({ value: m, label: tunnelSecureLabel(m) })))
// выбранный сервер не поддерживает текущее шифрование — сбросить на доступное
watch(tunnelModes, (m) => { if (!m.includes(draft.value.dns.tunnelSecure)) draft.value.dns.tunnelSecure = 'off' })
const tunnelSecureHint = computed(() => {
  const m = tunnelModes.value
  if (m.length === 1) return t('Для этого сервера доступен только обычный режим: шифрование есть для Cloudflare, Google, AdGuard и Quad9 (DoT)')
  if (!m.includes('doh')) return t('У Quad9 — только DoT: его DoH работает лишь через HTTP/2')
  return draft.value.dns.tunnelSecure === 'off'
    ? t('Обычно не нужно: вопросы и так внутри туннеля')
    : t('Если туннель не работает, вопросы не уходят к провайдеру — сайты из списка ждут, пока VPN снова заработает')
})
const tunnelState = computed(() => {
  const p = service.value?.dns_tunnel
  if (!p || !config.value?.dns?.tunnel_secure || dirty.value) return null
  if (p.upstream_ok) return { tone: 'ok', text: t('Работает: шифрованных ответов через туннель — {n}', { n: p.upstream_ok }) }
  if (p.failed) return { tone: 'bad', text: p.last_error ? t('Сервер не отвечает через туннель: {e}', { e: p.last_error }) : t('Сервер не отвечает через туннель') }
  return { tone: 'ok', text: t('Включено, вопросов пока не было') }
})

// ---- защищённый DNS (DoH/DoT) ----
const SECURE_MODES = computed(() => [{ value: 'off' as const, label: t('Выключен') }, { value: 'doh' as const, label: 'DoH' }, { value: 'dot' as const, label: 'DoT' }])
const SECURE_SERVERS = computed(() => [
  { id: 'cloudflare' as const, name: 'Cloudflare', desc: t('Быстрый, без фильтров') },
  { id: 'quad9' as const, name: 'Quad9', desc: t('Не открывает опасные сайты') },
  { id: 'google' as const, name: 'Google', desc: t('Надёжный, без фильтров') },
  { id: 'adguard' as const, name: 'AdGuard DNS', desc: t('Блокирует рекламу и трекеры') },
  { id: 'nextdns' as const, name: 'NextDNS', desc: t('Свои фильтры, нужен ID профиля') },
  { id: 'custom' as const, name: t('Свой сервер'), desc: t('Ссылка или имя и IP-адреса') },
])
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
  if (!p.upstream_ok && p.fallback) return { tone: 'warn', text: p.last_error ? t('Сервер недоступен — ответы идут через DNS провайдера: {e}', { e: p.last_error }) : t('Сервер недоступен — ответы идут через DNS провайдера') }
  // единичные сбои (например, при загрузке, пока часы роутера не выставлены) — не повод для предупреждения
  if (p.fallback) return { tone: p.fallback * 20 > p.upstream_ok + p.fallback ? 'warn' : 'ok',
    text: t('Работает ({via}): ответов {ok}, через провайдера при сбоях — {fallback}', { via, ok: p.upstream_ok, fallback: p.fallback }) + (p.last_error ? t(' · последняя ошибка: {e}', { e: p.last_error }) : '') }
  return { tone: 'ok', text: p.queries ? t('Работает ({via}): ответов через защищённый сервер — {ok}', { via, ok: p.upstream_ok }) : t('Включён ({via}), вопросов пока не было', { via }) }
})

function blocker(): Blocker | null {
  if (!secureOk.value) return { text: t('Защищённый DNS: проверьте ID NextDNS или адрес своего сервера') }
  if (!adblockUrlOk.value) return { text: t('Ссылка на список рекламы — https://…') }
  return resolverOk.value ? null : { text: t('Свой DNS-сервер — адрес IPv4, например 1.1.1.1.') }
}
useAutosave({
  source: draft,
  dirty: () => dirty.value,
  blocker,
  run: async () => {
    if (!config.value) return t('Настройки ещё не загружены.')
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
  <section class="sect" :aria-label="t('Дополнительно')">
    <p class="lead">{{ t('Обычно здесь ничего менять не нужно. Изменения сохраняются сами') }}</p>

    <!-- телефон: разделы, которых нет в нижней панели -->
    <nav class="card card--flush settings more-links" :aria-label="t('Другие разделы')">
      <button type="button" class="setrow more-link" @click="emit('navigate', 'zapret')">
        <span class="setrow__text"><span class="setrow__title">Zapret</span><span class="setrow__desc">{{ t('Способ обхода блокировок, подбор, автопроверка') }}</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
      <button type="button" class="setrow more-link" @click="emit('navigate', 'hosts')">
        <span class="setrow__text"><span class="setrow__title">{{ t('Свои DNS-записи') }}</span><span class="setrow__desc">{{ t('Домашние серверы по своим именам') }}</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
      <button type="button" class="setrow more-link" @click="emit('navigate', 'diag')">
        <span class="setrow__text"><span class="setrow__title">{{ t('Диагностика') }}</span><span class="setrow__desc">{{ t('Проверка работы, журналы, перезапуск службы') }}</span></span>
        <ChevronRight :size="18" class="more-link__icon" aria-hidden="true" />
      </button>
    </nav>

    <div class="card card--flush settings">
      <div class="setblock" role="group" aria-labelledby="adblock-title">
        <label class="setrow setrow--bare">
          <span class="setrow__text">
            <span id="adblock-title" class="setrow__title">{{ t('Блокировка рекламы') }}</span>
            <span class="setrow__desc">{{ t('Работает через DNS роутера: на домены из списка рекламы и трекеров роутер отвечает «такого сайта нет». Действует на все устройства, которые получают DNS от роутера') }}</span>
          </span>
          <ToggleSwitch v-model="draft.dns.adblock" input-id="adblock" />
        </label>
        <template v-if="draft.dns.adblock">
          <Segmented v-model="draft.dns.adblockSource" class="self-start" :options="ADBLOCK_SOURCES" :label="t('Список рекламы')" name="adblock-source" />
          <span class="field__hint">{{ ADBLOCK_SOURCES.find((o) => o.value === draft.dns.adblockSource)?.desc }}</span>
          <div v-if="draft.dns.adblockSource === 'url'" class="field dns__custom dns__custom--wide">
            <label for="adblock-url" class="field__label">{{ t('Ссылка на список') }}</label>
            <InputText id="adblock-url" v-model="draft.dns.adblockUrl" placeholder="https://…/list.txt" spellcheck="false" autocomplete="off"
              :invalid="!adblockUrlOk" aria-describedby="adblock-url-hint" />
            <span id="adblock-url-hint" :class="adblockUrlOk ? 'field__hint' : 'field__error'">{{ adblockUrlOk
              ? t('По домену в строке или строки hosts (0.0.0.0 домен); # — комментарий')
              : t('Нужна ссылка https://…') }}</span>
          </div>
          <span :class="['adblock__state', { 'adblock__state--bad': adblockState?.error }]">
            <span :class="['led', adblockState ? (adblockState.error ? 'led--warn' : 'led--ok') : 'led--idle']" aria-hidden="true" />
            <span class="meta">{{ adblockText }}</span>
          </span>
        </template>
      </div>

      <div class="setblock" role="group" aria-labelledby="dns-title">
        <span class="setrow__text">
          <span id="dns-title" class="setrow__title">{{ t('DNS для сайтов через VPN') }}</span>
          <span class="setrow__desc">{{ t('Через него узнаются адреса сайтов из ваших списков. Вопросы идут внутри VPN-туннеля — провайдер их не видит. Шифрование DoH/DoT защищает ещё и участок от VPN-сервера до DNS-сервера') }}</span>
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
        <div class="field">
          <span id="tunnel-secure-title" class="field__label">{{ t('Шифрование') }}</span>
          <Segmented v-model="draft.dns.tunnelSecure" class="self-start" :options="TUNNEL_SECURE_MODES" :label="t('Шифрование DNS через VPN')" name="tunnel-secure" />
          <span class="field__hint">{{ tunnelSecureHint }}</span>
          <span v-if="tunnelState" :class="['adblock__state', { 'adblock__state--bad': tunnelState.tone === 'bad' }]">
            <span :class="['led', `led--${tunnelState.tone}`]" aria-hidden="true" />
            <span class="meta">{{ tunnelState.text }}</span>
          </span>
        </div>
        <div v-if="dnsChoice === 'custom'" class="field dns__custom">
          <label for="dns" class="field__label">{{ t('Адрес DNS-сервера') }}</label>
          <InputText id="dns" v-model="draft.dns.resolver" class="num" :placeholder="t('например, 1.0.0.1')" inputmode="decimal" :invalid="!resolverOk" aria-describedby="dns-hint" />
          <span id="dns-hint" :class="resolverOk ? 'field__hint' : 'field__error'">{{ resolverOk ? t('Публичный адрес IPv4.') : t('Нужен адрес IPv4, например 1.0.0.1.') }}</span>
        </div>
      </div>

      <label class="setrow">
        <span class="setrow__text">
          <span class="setrow__title">{{ t('IPv6 через VPN') }}</span>
          <span class="setrow__desc">{{ t('Для устройств, у которых через VPN идёт весь интернет («Всё через VPN» или «Весь интернет» у устройства), IPv6 тоже пойдёт через туннель. Нужен IPv6 на VPN-сервере. Остальным устройствам с правилами IPv6 по-прежнему закрыт: сайты из списков сопоставляются только по IPv4') }}</span>
        </span>
        <ToggleSwitch v-model="ipv6" input-id="ipv6" @update:model-value="(v: boolean) => setIpv6(v)" />
      </label>

      <div class="setblock" role="group" aria-labelledby="secure-title">
        <span class="setrow__text">
          <span id="secure-title" class="setrow__title">{{ t('Защищённый DNS для остальных сайтов') }}</span>
          <span class="setrow__desc">{{ t('Адреса сайтов не через VPN (в том числе с обходом блокировок) роутер узнаёт по шифрованному каналу — провайдер не видит и не подменяет ответы. Если сервер недоступен, роутер временно спрашивает DNS провайдера, чтобы интернет не пропадал') }}</span>
        </span>
        <Segmented v-model="draft.dns.secure" class="self-start" :options="SECURE_MODES" :label="t('Защищённый DNS')" name="secure-mode" />
        <template v-if="draft.dns.secure !== 'off'">
          <p v-if="draft.dns.secure === 'dot'" class="dns__note">{{ t('Провайдеры в России часто блокируют DoT (порт 853). Если в состоянии ниже ответы идут через провайдера — выберите DoH') }}</p>
          <div class="dns" role="radiogroup" :aria-label="t('Сервер защищённого DNS')">
            <label v-for="o in SECURE_SERVERS" :key="o.id" :class="['dns__opt', { 'dns__opt--on': draft.dns.secureServer === o.id, 'dns__opt--off': o.id === 'quad9' && draft.dns.secure === 'doh' }]">
              <input v-model="draft.dns.secureServer" type="radio" name="secure-server" class="dns__radio" :value="o.id" :disabled="o.id === 'quad9' && draft.dns.secure === 'doh'" />
              <ServiceLogo :icon="dnsIcon(o.id)" />
              <span class="dns__text">
                <span class="dns__name">{{ o.name }}</span>
                <span class="dns__desc">{{ o.id === 'quad9' && draft.dns.secure === 'doh' ? t('Только DoT: DoH у Quad9 — HTTP/2') : o.desc }}</span>
              </span>
            </label>
          </div>
          <div v-if="draft.dns.secureServer === 'nextdns'" class="field dns__custom">
            <label for="nextdns-id" class="field__label">{{ t('ID профиля NextDNS') }}</label>
            <InputText id="nextdns-id" v-model="draft.dns.nextdnsId" class="num" placeholder="abc123" spellcheck="false" autocomplete="off" :invalid="!secureOk" />
            <span class="field__hint">{{ t('6 символов из личного кабинета NextDNS (раздел «Настройка»)') }}</span>
          </div>
          <div v-if="draft.dns.secureServer === 'custom'" class="row2 dns__custom--wide">
            <div class="field">
              <label for="secure-url" class="field__label">{{ draft.dns.secure === 'doh' ? t('Ссылка DoH') : t('Имя сервера DoT') }}</label>
              <InputText id="secure-url" v-model="draft.dns.secureUrl" :placeholder="draft.dns.secure === 'doh' ? 'https://dns.example/dns-query' : 'dns.example'"
                spellcheck="false" autocomplete="off" :invalid="!secureOk" />
            </div>
            <div class="field">
              <label for="secure-ips" class="field__label">{{ t('IP-адреса сервера') }}</label>
              <InputText id="secure-ips" v-model="draft.dns.secureIps" class="num" placeholder="203.0.113.5, 203.0.113.6" spellcheck="false" autocomplete="off" :invalid="!secureOk" />
            </div>
            <span class="field__hint">{{ t('IP нужны, чтобы подключаться к серверу без DNS: до 4 адресов через запятую') }}</span>
          </div>
          <span :class="['adblock__state', { 'adblock__state--bad': secureState?.tone === 'warn' }]">
            <span :class="['led', `led--${secureState?.tone ?? 'idle'}`]" aria-hidden="true" />
            <span class="meta">{{ secureState?.text ?? (dirty ? t('Сохраняется…') : t('Роутер включит защищённый DNS в течение минуты')) }}</span>
          </span>
        </template>
      </div>


      <div class="setblock" role="group" aria-labelledby="lang-title">
        <span class="setrow__text"><span id="lang-title" class="setrow__title">{{ t('Язык интерфейса') }}</span>
          <span class="setrow__desc">{{ t('По умолчанию — язык браузера. Выбор запоминается в этом браузере') }}</span></span>
        <LangSwitch />
      </div>

      <UpdateCard />

      <BackupCard />

      <div class="setrow setrow--top">
        <span class="setrow__text">
          <span class="setrow__title">{{ t('Вход в панель') }}</span>
          <span class="setrow__desc">{{ totp ? t('По паролю и коду из приложения-аутентификатора.') : t('Только по паролю. Можно добавить второй шаг: код из приложения на телефоне (Google Authenticator и подобные).') }}</span>
          <template v-if="!totp">
            <button type="button" class="disclose" :aria-expanded="totpHelp" aria-controls="totp-help" @click="totpHelp = !totpHelp">
              <ChevronDown :size="16" :class="['disclose__icon', { 'disclose__icon--open': totpHelp }]" aria-hidden="true" />{{ t('Как включить') }}
            </button>
            <span v-show="totpHelp" id="totp-help" class="setrow__desc">{{ t('Подключитесь к роутеру по SSH и выполните') }}
              <code>sh /data/mi-lumruri/mitt-boot.sh auth reset-totp</code>{{ t(', отсканируйте QR-код приложением, затем') }}
              <code>sh /data/mi-lumruri/mitt-boot.sh auth confirm</code>{{ t('. Подробнее — в инструкции, раздел «Второй фактор».') }}</span>
          </template>
        </span>
        <span :class="['badge', totp ? 'badge--ok' : 'badge--idle']">{{ totp ? t('Пароль и код') : t('Только пароль') }}</span>
      </div>
    </div>

  </section>
</template>
