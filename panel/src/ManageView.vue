<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import Button from 'primevue/button'
import Checkbox from 'primevue/checkbox'
import InputText from 'primevue/inputtext'
import Message from 'primevue/message'
import Password from 'primevue/password'
import Select from 'primevue/select'
import Skeleton from 'primevue/skeleton'
import Tag from 'primevue/tag'
import Textarea from 'primevue/textarea'
import ToggleSwitch from 'primevue/toggleswitch'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { manage, type ApiResult, type Category, type Config, type Device, type Lease, type ManageResponse, type ZapretConfig } from './api'
import {
  DEFAULT_TUNNEL_RESOLVER, deviceFromLease, dnsToForm, emptyNetworkForm, emptyProfileForm, formToDns, formToNetwork, formToProfile, formToSecret,
  networkToForm, profileToForm, type DnsForm, type NetworkForm, type ProfileForm,
} from './manage'
import { destShort, plural, routeKind, routeLabel, sourceShort, type ServiceStatus } from './route'
import RouteBadge from './RouteBadge.vue'
import RouteLine from './RouteLine.vue'

type Tab = 'rules' | 'devices' | 'profiles' | 'categories' | 'dns' | 'status'
const props = defineProps<{ config: Config; revision: string; tab: Tab; status: ManageResponse | null }>()
const emit = defineEmits<{ changed: [config: Config, revision: string]; reload: []; status: [s: ManageResponse]; navigate: [tab: 'edit' | Tab] }>()

const toast = useToast()
const confirm = useConfirm()

const msg = ref<{ kind: 'ok' | 'bad'; text: string } | null>(null)
const busy = ref(false)
const secrets = ref<Record<string, boolean>>({})

async function run(p: Promise<ApiResult<ManageResponse>>, ok: string): Promise<ApiResult<ManageResponse>> {
  busy.value = true
  msg.value = null
  try {
    const r = await p
    if (r.status >= 200 && r.status < 300 && r.body.ok) {
      msg.value = { kind: 'ok', text: ok }
      toast.add({ severity: 'success', summary: ok, life: 4000 })
      if (r.body.config && r.body.revision) emit('changed', r.body.config, r.body.revision)
    } else if (r.status === 409 && r.body.error?.code === 'revision_conflict') {
      msg.value = { kind: 'bad', text: 'Настройки изменились в другом окне. Обновите их и повторите.' }
    } else {
      const details = r.body.issues.map((i) => `${i.path}: ${i.message}`).join('; ')
      msg.value = { kind: 'bad', text: `${r.body.error?.message ?? `Ошибка ${r.status}`}${details ? ` — ${details}` : ''}` }
    }
    return r
  } finally {
    busy.value = false
  }
}

/** Ошибка формы до отправки: сообщение показывается тем же блоком, что и ответ контроллера. */
function fail(text: string) { msg.value = { kind: 'bad', text } }

/** Подтверждение удаления в окне панели вместо системного confirm(). */
function ask(message: string, accept: () => void) {
  confirm.require({
    header: 'Удалить?', message, acceptLabel: 'Удалить', rejectLabel: 'Отмена',
    acceptProps: { severity: 'danger' }, rejectProps: { severity: 'secondary', variant: 'text' }, accept,
  })
}

async function focusForm(id: string) {
  await nextTick()
  const el = document.getElementById(id)
  el?.scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' })
  el?.querySelector<HTMLElement>('input, textarea')?.focus({ preventScroll: true })
}

// ---- правила ----
const rules = computed(() => props.config.rules)
function move(id: string, to: number) { void run(manage.moveRule(props.revision, id, to), 'Порядок правил изменён.') }
function del(id: string) { ask(`Правило «${id}» будет удалено из настроек.`, () => void run(manage.deleteRule(props.revision, id), `Правило «${id}» удалено.`)) }

// ---- профиль TrustTunnel (контроллер принимает только один) ----
const pf = ref<ProfileForm>(emptyProfileForm())
const editing = ref(false)
const canAddProfile = computed(() => props.config.profiles.length === 0)
function editProfile(id: string) { const p = props.config.profiles.find((x) => x.id === id); if (p) { pf.value = profileToForm(p); editing.value = true; void focusForm('profile-form') } }
function newProfile() { pf.value = emptyProfileForm(); editing.value = true; void focusForm('profile-form') }
async function saveProfile() {
  const p = formToProfile(pf.value)
  if (typeof p === 'string') { fail(p); return }
  const r = await run(manage.saveProfile(props.revision, p), `Профиль «${p.name}» сохранён.`)
  const s = formToSecret(pf.value)
  if (r.status === 200 && s) {
    const sr = await run(manage.setSecret(p.id, s), `Профиль «${p.name}» сохранён, пароль записан.`)
    if (sr.status === 200) pf.value.password = ''
  }
  if (r.status === 200) { editing.value = false; await loadSecrets() }
}
function delProfile(id: string) { ask(`Профиль «${id}» будет удалён. Правила с действием «через туннель» перестанут проходить проверку.`, () => void run(manage.deleteProfile(props.revision, id), `Профиль «${id}» удалён.`)) }
async function loadSecrets() { const r = await manage.secrets(); if (r.status === 200 && r.body.profiles) secrets.value = r.body.profiles }
const onFailureOptions = [{ value: 'block', label: 'Блокировать трафик правила' }, { value: 'direct', label: 'Пускать напрямую в обход туннеля' }]

// ---- категории ----
const cat = ref<Category>({ id: '', name: '', kind: 'domain', source: '' })
const catList = ref('')
const catTarget = ref('')
const kindOptions = [{ value: 'domain', label: 'Домены' }, { value: 'ip', label: 'IP-префиксы' }]
async function saveCategory() {
  const c: Category = { id: cat.value.id.trim(), name: cat.value.name.trim(), kind: cat.value.kind, ...(cat.value.source?.trim() ? { source: cat.value.source.trim() } : {}) }
  const r = await run(manage.saveCategory(props.revision, c), `Категория «${c.name}» сохранена.`)
  if (r.status === 200) { catTarget.value = c.id; cat.value = { id: '', name: '', kind: 'domain', source: '' } }
}
function pickCategory(id: string) { catTarget.value = id; void focusForm('cat-list-form') }
function uploadCategory() { void run(manage.categoryList(catTarget.value, catList.value), 'Список категории проверен и заменён.') }
function delCategory(id: string) { ask(`Категория «${id}» и её список будут удалены.`, () => void run(manage.deleteCategory(props.revision, id), `Категория «${id}» удалена.`)) }

// ---- сети (SSID) и устройства ----
const nf = ref<NetworkForm>(emptyNetworkForm())
const nfExisting = computed(() => props.config.networks.some((n) => n.id === nf.value.id.trim()))
function editNetwork(id: string) { const n = props.config.networks.find((x) => x.id === id); if (n) { nf.value = networkToForm(n); void focusForm('network-form') } }
async function saveNetwork() {
  const n = formToNetwork(nf.value)
  if (typeof n === 'string') { fail(n); return }
  const r = await run(manage.saveNetwork(props.revision, n), `Сеть «${n.name}» сохранена.`)
  if (r.status === 200) nf.value = emptyNetworkForm()
}
function delNetwork(id: string) { ask(`Сеть «${id}» будет удалена из настроек.`, () => void run(manage.deleteNetwork(props.revision, id), `Сеть «${id}» удалена.`)) }
const dv = ref<Device>({ id: '', name: '', mac: '', network: props.config.networks[0]?.id ?? '' })
const dvExisting = computed(() => props.config.devices.some((d) => d.id === dv.value.id.trim()))
const leases = ref<Lease[]>([])
const leasesLoaded = ref(false)
async function loadLeases() { const r = await manage.leases(); if (r.status === 200) leases.value = r.body.leases ?? []; leasesLoaded.value = true }
function pickLease(l: Lease) { dv.value = deviceFromLease(l, dv.value.network || props.config.networks[0]?.id || ''); void focusForm('device-form') }
function editDevice(id: string) { const d = props.config.devices.find((x) => x.id === id); if (d) { dv.value = { ...d }; void focusForm('device-form') } }
async function saveDevice() {
  const d: Device = { id: dv.value.id.trim(), name: dv.value.name.trim(), mac: dv.value.mac.trim(), network: dv.value.network }
  const r = await run(manage.saveDevice(props.revision, d), `Устройство «${d.name}» сохранено.`)
  if (r.status === 200) { dv.value = { id: '', name: '', mac: '', network: d.network }; await loadLeases() }
}
function delDevice(id: string) { ask(`Устройство «${id}» будет удалено. Правила для него перестанут проходить проверку.`, () => void run(manage.deleteDevice(props.revision, id), `Устройство «${id}» удалено.`)) }
const netName = (id: string) => props.config.networks.find((n) => n.id === id)?.name ?? id
const networkOptions = computed(() => props.config.networks.map((n) => ({ value: n.id, label: n.name })))

// ---- Zapret ----
const zOn = ref(!!props.config.zapret)
const z = ref<ZapretConfig>({ strategy: props.config.zapret?.strategy ?? 'multisplit', pos: props.config.zapret?.pos ?? 2, tcp_ports: props.config.zapret?.tcp_ports ?? [80, 443] })
const zPorts = ref((z.value.tcp_ports ?? [80, 443]).join(' '))
// позиция разреза — строка поля ввода, как и порты; число собирается при сохранении
const zPos = ref(String(z.value.pos ?? ''))
const strategyOptions = [{ value: 'multisplit', label: 'multisplit' }, { value: 'multidisorder', label: 'multidisorder' }]
function saveZapret() {
  if (!zOn.value) { void run(manage.saveZapret(props.revision, null), 'Zapret выключен.'); return }
  const ports = zPorts.value.split(/[\s,]+/).filter(Boolean).map(Number)
  void run(manage.saveZapret(props.revision, { strategy: z.value.strategy, pos: Number(zPos.value), tcp_ports: ports }), 'Настройки Zapret сохранены.')
}

// ---- DNS ----
const dns = ref<DnsForm>(dnsToForm(props.config.dns))
const adText = ref('')
function saveDns() { void run(manage.saveDns(props.revision, formToDns(dns.value)), 'Настройки DNS сохранены.') }
function uploadAdblock() { void run(manage.adblockList(adText.value), 'Список рекламы проверен и заменён.') }

// ---- состояние ----
const statusLoading = ref(false)
async function loadStatus() {
  statusLoading.value = true
  try { const r = await manage.status(); emit('status', r.body) } finally { statusLoading.value = false }
}
async function applyNow() { await run(manage.applyRequest(), 'Заявка на применение принята; служба роутера применит текущие настройки.'); await loadStatus() }
const service = computed(() => (props.status?.service ?? null) as ServiceStatus | null)
const ENGINES: [string, string][] = [['service', 'Служба mi-tt-admin'], ['trusttunnel', 'Клиент TrustTunnel'], ['nfqws2', 'Zapret (nfqws2)'], ['nginx', 'Веб-сервер панели (nginx)'], ['uhttpd', 'CGI контроллера (uhttpd)']]
const PROTECTION: Record<string, string> = {
  full: 'Правила применены полностью',
  guard: 'Только защита: трафик правил туннеля блокируется, пока туннель не поднимется',
  none: 'Правила не применены',
}
function when(sec?: number): string {
  if (!sec) return '—'
  return new Date(sec * 1000).toLocaleString('ru-RU', { day: 'numeric', month: 'long', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

onMounted(() => { void loadSecrets(); if (props.tab === 'status') void loadStatus(); if (props.tab === 'devices') void loadLeases() })
</script>

<template>
  <section class="sect mg">
    <div aria-live="polite">
      <Message v-if="msg?.kind === 'bad'" severity="error" closable class="mg__msg" @close="msg = null">
        {{ msg.text }}
        <Button v-if="msg.text.startsWith('Настройки изменились')" label="Обновить настройки" size="small" severity="secondary" class="save__reload" @click="emit('reload')" />
      </Message>
    </div>

    <!-- ===== правила ===== -->
    <template v-if="tab === 'rules'">
      <div class="sect__head">
        <h1 class="sect__title">Правила</h1>
        <Button label="Новое правило" size="small" @click="emit('navigate', 'edit')" />
      </div>
      <p class="sect__lead">Сначала проверяются правила устройств, затем сетей, затем всей LAN; внутри уровня срабатывает первое совпадение в этом порядке.</p>

      <div v-if="!rules.length" class="empty">
        <p>Правил пока нет: весь трафик идёт по маршруту по умолчанию. Создайте первое правило — выберите устройство или сеть и решите, куда пустить их трафик.</p>
        <Button label="Создать правило" @click="emit('navigate', 'edit')" />
      </div>
      <ol v-else class="rules">
        <li v-for="(r, i) in rules" :key="r.id" :class="['rules__row', `bar--${routeKind(r.action)}`, { 'rules__row--off': !r.enabled }]">
          <span class="rules__pos num">{{ i + 1 }}</span>
          <span class="rules__body">
            <RouteLine :source="sourceShort(r.source, config)" :destination="destShort(r.destination, config)" :kind="routeKind(r.action)"
              :action="routeLabel(r.action, config)" />
            <span class="rules__meta">
              <span class="rules__id">{{ r.id }}</span>
              <Tag v-if="!r.enabled" value="Выключено" severity="secondary" />
            </span>
          </span>
          <span class="rules__actions">
            <Button severity="secondary" variant="text" size="small" :disabled="busy || i === 0" :aria-label="`Поднять правило ${r.id} выше`" title="Выше" @click="move(r.id, i - 1)">
              <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="M8 13V3M4 7l4-4 4 4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" /></svg>
            </Button>
            <Button severity="secondary" variant="text" size="small" :disabled="busy || i === rules.length - 1" :aria-label="`Опустить правило ${r.id} ниже`" title="Ниже" @click="move(r.id, i + 1)">
              <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true"><path d="M8 3v10M4 9l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" /></svg>
            </Button>
            <Button label="Удалить" severity="danger" variant="text" size="small" :disabled="busy" :aria-label="`Удалить правило ${r.id}`" @click="del(r.id)" />
          </span>
        </li>
      </ol>
      <p :class="['rules__default', `bar--${routeKind(config.default_action)}`]">
        <span>Остальной трафик</span>
        <span class="route__arrow" aria-hidden="true">→</span>
        <RouteBadge :kind="routeKind(config.default_action)" :label="routeLabel(config.default_action, config)" />
      </p>
    </template>

    <!-- ===== устройства и сети ===== -->
    <template v-else-if="tab === 'devices'">
      <h1 class="sect__title">Устройства и сети</h1>

      <h2 class="sect__h2">Сети Wi‑Fi</h2>
      <p class="sect__lead">Правило сети применяется по порту моста — интерфейсу SSID (например <code>wl0</code>, <code>wl1</code>), а не по IP-адресу.</p>
      <div class="scroll">
        <table class="tbl tbl--stack">
          <thead><tr><th scope="col">Сеть</th><th scope="col">SSID</th><th scope="col">Мост и порты</th><th scope="col">Подсеть</th><th scope="col"><span class="sr-only">Действия</span></th></tr></thead>
          <tbody>
            <tr v-for="n in config.networks" :key="n.id">
              <td data-label="Сеть"><span class="tbl__name">{{ n.name }}</span> <span class="tbl__id">{{ n.id }}</span></td>
              <td data-label="SSID">{{ n.ssid }}</td>
              <td data-label="Мост и порты">{{ n.bridge ?? '—' }}{{ n.ports?.length ? `: ${n.ports.join(', ')}` : '' }}</td>
              <td data-label="Подсеть" class="num">{{ n.subnet ?? '—' }}</td>
              <td class="tbl__actions">
                <Button label="Изменить" severity="secondary" variant="text" size="small" @click="editNetwork(n.id)" />
                <Button label="Удалить" severity="danger" variant="text" size="small" :disabled="busy" @click="delNetwork(n.id)" />
              </td>
            </tr>
            <tr v-if="!config.networks.length"><td colspan="5" class="tbl__empty">Сетей нет. Добавьте сеть формой ниже, чтобы задавать правила для её клиентов.</td></tr>
          </tbody>
        </table>
      </div>
      <form id="network-form" class="box form" @submit.prevent="saveNetwork">
        <h3 class="box__title">{{ nfExisting ? `Изменение сети «${nf.id.trim()}»` : 'Новая сеть' }}</h3>
        <div class="form__grid">
          <div class="field"><label for="nf-id" class="field__label">Идентификатор</label><InputText id="nf-id" v-model="nf.id" required pattern="[a-z0-9][a-z0-9_-]*" fluid /></div>
          <div class="field"><label for="nf-name" class="field__label">Название</label><InputText id="nf-name" v-model="nf.name" required fluid /></div>
          <div class="field"><label for="nf-ssid" class="field__label">SSID</label><InputText id="nf-ssid" v-model="nf.ssid" required fluid /></div>
          <div class="field"><label for="nf-bridge" class="field__label">Мост</label><InputText id="nf-bridge" v-model="nf.bridge" placeholder="br-lan" fluid /></div>
          <div class="field"><label for="nf-ports" class="field__label">Порты SSID (через пробел)</label><InputText id="nf-ports" v-model="nf.ports" placeholder="wl0 wl1" fluid /></div>
          <div class="field"><label for="nf-subnet" class="field__label">Подсеть клиентов</label><InputText id="nf-subnet" v-model="nf.subnet" class="num" placeholder="192.168.31.0/24" fluid /></div>
        </div>
        <div class="form__actions"><Button type="submit" label="Сохранить сеть" :disabled="busy" /></div>
      </form>

      <h2 class="sect__h2">Устройства</h2>
      <p class="sect__lead">Устройство определяется по MAC на входе моста; смена его IPv4 в аренде не выводит его из-под правила.</p>
      <div class="scroll">
        <table class="tbl tbl--stack">
          <thead><tr><th scope="col">Устройство</th><th scope="col">MAC</th><th scope="col">Сеть</th><th scope="col"><span class="sr-only">Действия</span></th></tr></thead>
          <tbody>
            <tr v-for="d in config.devices" :key="d.id">
              <td data-label="Устройство"><span class="tbl__name">{{ d.name }}</span> <span class="tbl__id">{{ d.id }}</span></td>
              <td data-label="MAC" class="num">{{ d.mac }}</td>
              <td data-label="Сеть">{{ netName(d.network) }}</td>
              <td class="tbl__actions">
                <Button label="Изменить" severity="secondary" variant="text" size="small" @click="editDevice(d.id)" />
                <Button label="Удалить" severity="danger" variant="text" size="small" :disabled="busy" @click="delDevice(d.id)" />
              </td>
            </tr>
            <tr v-if="!config.devices.length"><td colspan="4" class="tbl__empty">Устройств нет. Выберите клиента из аренд DHCP ниже или заполните форму вручную.</td></tr>
          </tbody>
        </table>
      </div>
      <form id="device-form" class="box form" @submit.prevent="saveDevice">
        <h3 class="box__title">{{ dvExisting ? `Изменение устройства «${dv.id.trim()}»` : 'Новое устройство' }}</h3>
        <div class="form__grid">
          <div class="field"><label for="dv-id" class="field__label">Идентификатор</label><InputText id="dv-id" v-model="dv.id" required pattern="[a-z0-9][a-z0-9_-]*" fluid /></div>
          <div class="field"><label for="dv-name" class="field__label">Название</label><InputText id="dv-name" v-model="dv.name" required fluid /></div>
          <div class="field"><label for="dv-mac" class="field__label">MAC</label><InputText id="dv-mac" v-model="dv.mac" class="num" required placeholder="aa:bb:cc:dd:ee:ff" fluid /></div>
          <div class="field"><label for="dv-net" class="field__label">Сеть</label>
            <Select v-model="dv.network" input-id="dv-net" :options="networkOptions" option-label="label" option-value="value" fluid placeholder="Выберите сеть" />
          </div>
        </div>
        <div class="form__actions"><Button type="submit" label="Сохранить устройство" :disabled="busy" /></div>
      </form>

      <div class="sect__head">
        <h3 class="sect__h3">Клиенты из аренд DHCP</h3>
        <Button label="Обновить список" severity="secondary" variant="outlined" size="small" @click="loadLeases" />
      </div>
      <div v-if="!leasesLoaded" class="loading"><Skeleton height="2rem" /><Skeleton height="2rem" /></div>
      <div v-else class="scroll">
        <table class="tbl tbl--stack">
          <thead><tr><th scope="col">Имя</th><th scope="col">MAC</th><th scope="col">IPv4</th><th scope="col"><span class="sr-only">Действия</span></th></tr></thead>
          <tbody>
            <tr v-for="l in leases" :key="l.mac">
              <td data-label="Имя">{{ l.hostname || '—' }}</td>
              <td data-label="MAC" class="num">{{ l.mac }}</td>
              <td data-label="IPv4" class="num">{{ l.ip }}</td>
              <td class="tbl__actions">
                <span v-if="l.device" class="tbl__meta">Устройство <span class="tbl__id">{{ l.device }}</span></span>
                <Button v-else label="Заполнить форму" severity="secondary" variant="outlined" size="small" @click="pickLease(l)" />
              </td>
            </tr>
            <tr v-if="!leases.length"><td colspan="4" class="tbl__empty">Аренд нет: роутер ещё не выдавал адреса или список недоступен.</td></tr>
          </tbody>
        </table>
      </div>
    </template>

    <!-- ===== профиль ===== -->
    <template v-else-if="tab === 'profiles'">
      <h1 class="sect__title">Профиль TrustTunnel</h1>
      <p class="sect__lead">VPN-выход один — сервер TrustTunnel (официальный клиент). Остальные действия правил: напрямую, напрямую с Zapret и блокировка.</p>

      <div v-if="!config.profiles.length && !editing" class="empty">
        <p>Добавьте сервер TrustTunnel, чтобы правила могли вести трафик в туннель.</p>
        <Button label="Добавить сервер" @click="newProfile" />
      </div>

      <article v-for="p in config.profiles" :key="p.id" class="box profile bar--tunnel">
        <div class="profile__head">
          <div>
            <h2 class="box__title">{{ p.name }} <span class="tbl__id">{{ p.id }}</span></h2>
            <Tag v-if="!p.endpoint" value="Сервер не указан" severity="warn" />
          </div>
          <div class="profile__actions">
            <Button label="Изменить" severity="secondary" variant="outlined" size="small" @click="editProfile(p.id)" />
            <Button label="Удалить" severity="danger" variant="text" size="small" :disabled="busy" @click="delProfile(p.id)" />
          </div>
        </div>
        <dl class="kv">
          <div><dt>Сервер</dt><dd class="num">{{ p.endpoint ? `${p.endpoint.server}:${p.endpoint.port}` : '—' }}<template v-if="p.endpoint?.sni"> ({{ p.endpoint.sni }})</template></dd></div>
          <div><dt>Протокол</dt><dd>{{ p.endpoint ? (p.endpoint.quic ? 'HTTP/3' : 'HTTP/2') : '—' }}{{ p.endpoint?.anti_dpi ? ', анти-DPI' : '' }}</dd></div>
          <div><dt>Если туннель недоступен</dt><dd>{{ p.on_failure === 'direct' ? 'Напрямую' : 'Блокировать' }}</dd></div>
          <div><dt>Пароль</dt><dd>{{ secrets[p.id] ? 'Задан' : 'Не задан' }}</dd></div>
        </dl>
      </article>

      <p v-if="!editing && !canAddProfile" class="sect__note">Поддерживается один сервер TrustTunnel: чтобы сменить сервер, измените существующий профиль.</p>

      <form v-if="editing" id="profile-form" class="box form" @submit.prevent="saveProfile">
        <h3 class="box__title">{{ canAddProfile ? 'Новый сервер TrustTunnel' : 'Изменение профиля' }}</h3>
        <div class="form__grid">
          <div class="field"><label for="pf-id" class="field__label">Идентификатор</label><InputText id="pf-id" v-model="pf.id" required pattern="[a-z0-9][a-z0-9_-]*" fluid /></div>
          <div class="field"><label for="pf-name" class="field__label">Название</label><InputText id="pf-name" v-model="pf.name" required fluid /></div>
          <div class="field"><label for="pf-server" class="field__label">IP-адрес сервера</label>
            <InputText id="pf-server" v-model="pf.server" class="num" required inputmode="decimal" placeholder="203.0.113.10" spellcheck="false" fluid /></div>
          <div class="field"><label for="pf-port" class="field__label">Порт</label><InputText id="pf-port" v-model="pf.port" class="num" inputmode="numeric" required fluid /></div>
          <div class="field field--wide"><label for="pf-sni" class="field__label">Имя сервера для TLS (SNI)</label>
            <InputText id="pf-sni" v-model="pf.sni" placeholder="vpn.example.com" spellcheck="false" fluid aria-describedby="pf-sni-hint" />
            <small id="pf-sni-hint" class="field__hint">Клиент подключается по IP-адресу; доменное имя сервера укажите в SNI. Без SNI для TLS используется адрес.</small></div>
          <div class="field"><label for="pf-user" class="field__label">Имя пользователя</label><InputText id="pf-user" v-model="pf.username" required autocomplete="off" spellcheck="false" fluid /></div>
          <div class="field"><label for="pf-pass" class="field__label">Пароль</label>
            <Password v-model="pf.password" input-id="pf-pass" :feedback="false" toggle-mask fluid :input-props="{ autocomplete: 'new-password' }" aria-describedby="pf-pass-hint" />
            <small id="pf-pass-hint" class="field__hint">Только запись: сохранённый пароль не показывается. Оставьте пустым, чтобы не менять.</small></div>
          <div class="field field--wide checks">
            <div class="check"><Checkbox v-model="pf.quic" input-id="pf-quic" binary /><label for="pf-quic">HTTP/3 (QUIC) вместо HTTP/2</label></div>
            <div class="check"><Checkbox v-model="pf.antiDpi" input-id="pf-dpi" binary /><label for="pf-dpi">Защита от DPI (anti-DPI)</label></div>
          </div>
          <div class="field field--wide"><label for="pf-fail" class="field__label">Если туннель недоступен</label>
            <Select v-model="pf.onFailure" input-id="pf-fail" :options="onFailureOptions" option-label="label" option-value="value" fluid /></div>
          <div class="field field--wide"><label for="pf-cert" class="field__label">Сертификат сервера, PEM (необязательно: только для самоподписанного сервера)</label>
            <Textarea id="pf-cert" v-model="pf.certificate" rows="5" spellcheck="false" class="num" fluid
              placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----" /></div>
        </div>
        <div class="form__actions">
          <Button type="submit" label="Сохранить профиль" :disabled="busy" />
          <Button type="button" label="Отмена" severity="secondary" variant="text" @click="editing = false" />
        </div>
      </form>
    </template>

    <!-- ===== категории ===== -->
    <template v-else-if="tab === 'categories'">
      <h1 class="sect__title">Категории назначений</h1>
      <p class="sect__lead">Геокатегории и списки доменов или IP-префиксов хранятся на роутере и используются в правилах как назначение «категория».</p>
      <div class="scroll">
        <table class="tbl tbl--stack">
          <thead><tr><th scope="col">Категория</th><th scope="col">Вид</th><th scope="col">Источник</th><th scope="col"><span class="sr-only">Действия</span></th></tr></thead>
          <tbody>
            <tr v-for="c in config.categories ?? []" :key="c.id" :class="{ 'tbl__row--on': catTarget === c.id }">
              <td data-label="Категория"><span class="tbl__name">{{ c.name }}</span> <span class="tbl__id">{{ c.id }}</span></td>
              <td data-label="Вид">{{ c.kind === 'domain' ? 'Домены' : 'IP-префиксы' }}</td>
              <td data-label="Источник">{{ c.source ?? '—' }}</td>
              <td class="tbl__actions">
                <Button label="Загрузить список" severity="secondary" variant="outlined" size="small" @click="pickCategory(c.id)" />
                <Button label="Удалить" severity="danger" variant="text" size="small" :disabled="busy" @click="delCategory(c.id)" />
              </td>
            </tr>
            <tr v-if="!(config.categories ?? []).length"><td colspan="4" class="tbl__empty">Категорий нет. Создайте категорию, затем загрузите в неё список доменов или подсетей.</td></tr>
          </tbody>
        </table>
      </div>
      <form class="box form" @submit.prevent="saveCategory">
        <h3 class="box__title">Новая категория</h3>
        <div class="form__grid">
          <div class="field"><label for="cat-id" class="field__label">Идентификатор</label><InputText id="cat-id" v-model="cat.id" required fluid /></div>
          <div class="field"><label for="cat-name" class="field__label">Название</label><InputText id="cat-name" v-model="cat.name" required fluid /></div>
          <div class="field"><label for="cat-kind" class="field__label">Вид</label>
            <Select v-model="cat.kind" input-id="cat-kind" :options="kindOptions" option-label="label" option-value="value" fluid /></div>
          <div class="field"><label for="cat-src" class="field__label">Источник (необязательно)</label><InputText id="cat-src" v-model="cat.source" placeholder="geosite:youtube" fluid /></div>
        </div>
        <div class="form__actions"><Button type="submit" label="Сохранить категорию" :disabled="busy" /></div>
      </form>
      <form v-if="catTarget" id="cat-list-form" class="box form" @submit.prevent="uploadCategory">
        <h3 class="box__title">Список категории <span class="tbl__id">{{ catTarget }}</span></h3>
        <div class="field"><label for="cat-list" class="field__label">Записи, по одной в строке</label>
          <Textarea id="cat-list" v-model="catList" rows="6" class="num" fluid /></div>
        <div class="form__actions"><Button type="submit" label="Проверить и заменить список" :disabled="busy || !catList.trim()" /></div>
      </form>
    </template>

    <!-- ===== DNS, реклама, Zapret ===== -->
    <template v-else-if="tab === 'dns'">
      <h1 class="sect__title">DNS, реклама, Zapret</h1>
      <p class="sect__lead">
        Доменные правила работают через DNS роутера: dnsmasq записывает адреса доменов в наборы правил. Устройство со своим DoH/DoT
        спрашивает DNS мимо роутера, и такие правила к нему не применяются.
      </p>
      <form class="box form" @submit.prevent="saveDns">
        <h2 class="box__title">DNS и блокировка рекламы</h2>
        <div class="field"><label for="dns-res" class="field__label">DNS-сервер для доменов через TrustTunnel</label>
          <InputText id="dns-res" v-model="dns.resolver" class="num field__short" inputmode="decimal" :placeholder="DEFAULT_TUNNEL_RESOLVER" spellcheck="false"
            aria-describedby="dns-res-hint" />
          <small id="dns-res-hint" class="field__hint">Публичный IPv4-адрес; запросы к нему идут через туннель. Пусто — {{ DEFAULT_TUNNEL_RESOLVER }}. Остальные домены роутер разрешает как обычно.</small></div>
        <div class="check"><ToggleSwitch v-model="dns.adblock" input-id="dns-ad" /><label for="dns-ad">Блокировать рекламу</label></div>
        <div class="field"><label for="dns-exc" class="field__label">Исключения из блокировки (по домену в строке)</label>
          <Textarea id="dns-exc" v-model="dns.exceptions" rows="3" spellcheck="false" fluid /></div>
        <div class="form__actions"><Button type="submit" label="Сохранить DNS" :disabled="busy" /></div>
      </form>
      <form class="box form" @submit.prevent="uploadAdblock">
        <h2 class="box__title">Список рекламы</h2>
        <div class="field"><label for="ad-list" class="field__label">Новый список (домены или строки hosts)</label>
          <Textarea id="ad-list" v-model="adText" rows="6" fluid aria-describedby="ad-hint" />
          <small id="ad-hint" class="field__hint">Ошибочный список не применяется; действует предыдущий.</small></div>
        <div class="form__actions"><Button type="submit" label="Проверить и заменить список" :disabled="busy || !adText.trim()" /></div>
      </form>
      <form class="box form bar--zapret" @submit.prevent="saveZapret">
        <h2 class="box__title">Обход блокировок (Zapret)</h2>
        <div class="check"><ToggleSwitch v-model="zOn" input-id="z-on" /><label for="z-on">Включить nfqws2 для действия «Напрямую с Zapret»</label></div>
        <div v-if="zOn" class="form__grid">
          <div class="field"><label for="z-strat" class="field__label">Стратегия</label>
            <Select v-model="z.strategy" input-id="z-strat" :options="strategyOptions" option-label="label" option-value="value" fluid /></div>
          <div class="field"><label for="z-pos" class="field__label">Позиция разреза</label>
            <InputText id="z-pos" v-model="zPos" class="num" inputmode="numeric" fluid /></div>
        </div>
        <div class="form__actions"><Button type="submit" label="Сохранить Zapret" :disabled="busy" /></div>
      </form>
    </template>

    <!-- ===== состояние ===== -->
    <template v-else-if="tab === 'status'">
      <div class="sect__head">
        <h1 class="sect__title">Состояние</h1>
        <Button label="Обновить" severity="secondary" variant="outlined" size="small" :loading="statusLoading" @click="loadStatus" />
      </div>
      <p class="sect__lead">Панель только сохраняет настройки. Применяет их к сети служба роутера (mi-tt-admin) — по заявке ниже, а также при перезагрузке, смене аренды и перезагрузке firewall.</p>

      <div class="box apply">
        <div>
          <h2 class="box__title">Применение настроек</h2>
          <p class="apply__state" aria-live="polite">
            <template v-if="!status">Состояние ещё не получено.</template>
            <template v-else-if="status.apply_pending">Заявка отправлена и ждёт службу роутера.</template>
            <template v-else>Заявок в очереди нет.</template>
          </p>
        </div>
        <Button label="Применить на роутере" :loading="busy" :disabled="busy" @click="applyNow" />
      </div>

      <div v-if="!status" class="loading"><Skeleton height="2rem" /><Skeleton height="2rem" /><Skeleton height="2rem" /></div>
      <template v-else>
        <Message v-if="!service" severity="warn" :closable="false">Служба ещё не сообщала состояние: она не запущена или ещё не завершила первый цикл.</Message>
        <div v-else class="box">
          <h2 class="box__title">Служба роутера</h2>
          <dl class="kv">
            <div v-for="[k, label] in ENGINES" :key="k">
              <dt>{{ label }}</dt>
              <dd>
                <span v-if="service.engines?.[k] === true" class="state state--ok"><span class="state__dot" aria-hidden="true" />Работает</span>
                <span v-else-if="service.engines?.[k] === false" class="state state--bad"><span class="state__dot" aria-hidden="true" />Не работает</span>
                <span v-else class="state state--idle"><span class="state__dot" aria-hidden="true" />Не требуется</span>
              </dd>
            </div>
            <div><dt>Маршрутизация</dt><dd>{{ PROTECTION[service.protection ?? 'none'] ?? service.protection }}</dd></div>
            <div v-if="service.last_apply"><dt>Последнее применение</dt>
              <dd>{{ when(service.last_apply.at) }}, {{ service.last_apply.exit === 0 ? 'успешно' : `с ошибкой (код ${service.last_apply.exit})` }}<span v-if="service.last_apply.tag" class="tbl__meta"> {{ service.last_apply.tag }}</span></dd></div>
            <div v-if="service.release"><dt>Выпуск</dt><dd class="num">{{ service.release }}</dd></div>
            <div><dt>Состояние записано</dt><dd>{{ when(service.at) }}</dd></div>
          </dl>
          <details class="more">
            <summary>Технические подробности</summary>
            <pre class="pre">{{ JSON.stringify(status.service, null, 2) }}</pre>
          </details>
        </div>
      </template>

      <div class="box">
        <h2 class="box__title">Сохранённые настройки</h2>
        <dl class="kv">
          <div><dt>Версия схемы</dt><dd class="num">{{ config.version }}</dd></div>
          <div><dt>Ревизия</dt><dd class="num">{{ revision.slice(0, 12) }}</dd></div>
          <div><dt>Состав</dt><dd>
            {{ plural(config.profiles.length, 'VPN-профиль', 'VPN-профиля', 'VPN-профилей') }}, {{ plural(config.networks.length, 'сеть', 'сети', 'сетей') }},
            {{ plural(config.devices.length, 'устройство', 'устройства', 'устройств') }}, {{ plural(config.groups.length, 'группа', 'группы', 'групп') }},
            {{ plural(config.rules.length, 'правило', 'правила', 'правил') }}
          </dd></div>
        </dl>
      </div>
    </template>
  </section>
</template>
