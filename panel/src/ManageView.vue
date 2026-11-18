<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { manage, type ApiResult, type Category, type Config, type Device, type DnsConfig, type Lease, type ManageResponse, type ZapretConfig } from './api'
import {
  actionText, destinationText, deviceFromLease, dnsDefault, emptyNetworkForm, emptyProfileForm, formToNetwork, formToProfile, formToSecret, networkToForm, profileToForm,
  secretLabels, sourceText, type NetworkForm, type ProfileForm,
} from './manage'

const props = defineProps<{ config: Config; revision: string; tab: 'rules' | 'devices' | 'profiles' | 'categories' | 'dns' | 'status' }>()
const emit = defineEmits<{ changed: [config: Config, revision: string]; reload: [] }>()

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

// ---- правила ----
const rules = computed(() => props.config.rules)
function move(id: string, to: number) { void run(manage.moveRule(props.revision, id, to), 'Порядок правил изменён.') }
function del(id: string) { if (confirm(`Удалить правило «${id}»?`)) void run(manage.deleteRule(props.revision, id), `Правило «${id}» удалено.`) }

// ---- профили ----
const pf = ref<ProfileForm>(emptyProfileForm())
const editing = ref(false)
const labels = computed(() => secretLabels(pf.value))
function editProfile(id: string) { const p = props.config.profiles.find((x) => x.id === id); if (p) { pf.value = profileToForm(p); editing.value = true } }
function newProfile() { pf.value = emptyProfileForm(); editing.value = true }
async function saveProfile() {
  const p = formToProfile(pf.value)
  if (typeof p === 'string') { msg.value = { kind: 'bad', text: p }; return }
  const r = await run(manage.saveProfile(props.revision, p), `Профиль «${p.name}» сохранён.`)
  const s = formToSecret(pf.value)
  if (r.status === 200 && s) {
    const sr = await run(manage.setSecret(p.id, s), `Профиль «${p.name}» сохранён, секрет записан.`)
    if (sr.status === 200) { pf.value.secret1 = ''; pf.value.secret2 = '' }
  }
  if (r.status === 200) { editing.value = false; await loadSecrets() }
}
function delProfile(id: string) { if (confirm(`Удалить профиль «${id}»?`)) void run(manage.deleteProfile(props.revision, id), `Профиль «${id}» удалён.`) }
async function loadSecrets() { const r = await manage.secrets(); if (r.status === 200 && r.body.profiles) secrets.value = r.body.profiles }

// ---- категории ----
const cat = ref<Category>({ id: '', name: '', kind: 'domain', source: '' })
const catList = ref('')
const catTarget = ref('')
async function saveCategory() {
  const c: Category = { id: cat.value.id.trim(), name: cat.value.name.trim(), kind: cat.value.kind, ...(cat.value.source?.trim() ? { source: cat.value.source.trim() } : {}) }
  const r = await run(manage.saveCategory(props.revision, c), `Категория «${c.name}» сохранена.`)
  if (r.status === 200) { catTarget.value = c.id; cat.value = { id: '', name: '', kind: 'domain', source: '' } }
}
function uploadCategory() { void run(manage.categoryList(catTarget.value, catList.value), 'Список категории проверен и заменён.') }
function delCategory(id: string) { if (confirm(`Удалить категорию «${id}»?`)) void run(manage.deleteCategory(props.revision, id), `Категория «${id}» удалена.`) }

// ---- сети (SSID) и устройства ----
const nf = ref<NetworkForm>(emptyNetworkForm())
function editNetwork(id: string) { const n = props.config.networks.find((x) => x.id === id); if (n) nf.value = networkToForm(n) }
async function saveNetwork() {
  const n = formToNetwork(nf.value)
  if (typeof n === 'string') { msg.value = { kind: 'bad', text: n }; return }
  const r = await run(manage.saveNetwork(props.revision, n), `Сеть «${n.name}» сохранена.`)
  if (r.status === 200) nf.value = emptyNetworkForm()
}
function delNetwork(id: string) { if (confirm(`Удалить сеть «${id}»?`)) void run(manage.deleteNetwork(props.revision, id), `Сеть «${id}» удалена.`) }
const dv = ref<Device>({ id: '', name: '', mac: '', network: props.config.networks[0]?.id ?? '' })
const leases = ref<Lease[]>([])
async function loadLeases() { const r = await manage.leases(); if (r.status === 200) leases.value = r.body.leases ?? [] }
function pickLease(l: Lease) { dv.value = deviceFromLease(l, dv.value.network || props.config.networks[0]?.id || '') }
function editDevice(id: string) { const d = props.config.devices.find((x) => x.id === id); if (d) dv.value = { ...d } }
async function saveDevice() {
  const d: Device = { id: dv.value.id.trim(), name: dv.value.name.trim(), mac: dv.value.mac.trim(), network: dv.value.network }
  const r = await run(manage.saveDevice(props.revision, d), `Устройство «${d.name}» сохранено.`)
  if (r.status === 200) { dv.value = { id: '', name: '', mac: '', network: d.network }; await loadLeases() }
}
function delDevice(id: string) { if (confirm(`Удалить устройство «${id}»?`)) void run(manage.deleteDevice(props.revision, id), `Устройство «${id}» удалено.`) }
const netName = (id: string) => props.config.networks.find((n) => n.id === id)?.name ?? id

// ---- Zapret ----
const zOn = ref(!!props.config.zapret)
const z = ref<ZapretConfig>({ strategy: props.config.zapret?.strategy ?? 'multisplit', pos: props.config.zapret?.pos ?? 2, tcp_ports: props.config.zapret?.tcp_ports ?? [80, 443] })
const zPorts = ref((z.value.tcp_ports ?? [80, 443]).join(' '))
function saveZapret() {
  if (!zOn.value) { void run(manage.saveZapret(props.revision, null), 'Zapret выключен.'); return }
  const ports = zPorts.value.split(/[\s,]+/).filter(Boolean).map(Number)
  void run(manage.saveZapret(props.revision, { strategy: z.value.strategy, pos: Number(z.value.pos), tcp_ports: ports }), 'Настройки Zapret сохранены.')
}

// ---- DNS ----
const dns = ref<DnsConfig>(JSON.parse(JSON.stringify(props.config.dns ?? dnsDefault())))
const dnsOn = ref(!!props.config.dns)
const exceptionsText = ref((props.config.dns?.adblock?.exceptions ?? []).join('\n'))
const adText = ref('')
function ensureOdoh() {
  if (dns.value.transport === 'odoh' && !dns.value.odoh) dns.value.odoh = { target: { host: '', ip: '', path: '/dns-query' }, relays: [{ host: '', ip: '', path: '/proxy' }] }
  if (dns.value.transport !== 'odoh' && !dns.value.servers?.length) dns.value.servers = [{ host: '', ip: '' }]
}
function saveDns() {
  if (!dnsOn.value) { void run(manage.saveDns(props.revision, null), 'Шифрованный DNS выключен.'); return }
  const d: DnsConfig = { transport: dns.value.transport }
  if (d.transport === 'odoh') d.odoh = dns.value.odoh
  else d.servers = (dns.value.servers ?? []).filter((s) => s.host || s.ip)
  const ex = exceptionsText.value.split(/\s+/).filter(Boolean)
  d.adblock = { enabled: !!dns.value.adblock?.enabled, ...(ex.length ? { exceptions: ex } : {}) }
  void run(manage.saveDns(props.revision, d), 'Настройки DNS сохранены.')
}
function uploadAdblock() { void run(manage.adblockList(adText.value), 'Список рекламы проверен и заменён.') }

// ---- состояние ----
const status = ref<ManageResponse | null>(null)
async function loadStatus() { const r = await manage.status(); status.value = r.body }
async function applyNow() { await run(manage.applyRequest(), 'Заявка на применение принята; служба роутера применит текущие настройки.'); await loadStatus() }

onMounted(() => { void loadSecrets(); void loadStatus(); if (props.tab === 'devices') void loadLeases() })
</script>

<template>
  <section class="mg">
    <p v-if="msg" :class="`mg__msg mg__msg--${msg.kind}`" role="status">{{ msg.text }}</p>

    <div v-if="tab === 'rules'">
      <h2>Правила по порядку</h2>
      <p class="mg__hint">Сначала правила устройств, затем сетей, затем всей LAN; внутри уровня — первое совпадение по этому порядку.</p>
      <table class="mg__table">
        <thead><tr><th>#</th><th>Правило</th><th>Источник</th><th>Назначение</th><th>Выход</th><th></th></tr></thead>
        <tbody>
          <tr v-for="(r, i) in rules" :key="r.id">
            <td>{{ i + 1 }}</td><td><code>{{ r.id }}</code></td><td>{{ sourceText(r, config) }}</td>
            <td>{{ destinationText(r.destination, config) }}</td><td>{{ actionText(r.action, config) }}</td>
            <td class="mg__actions">
              <button type="button" :disabled="busy || i === 0" title="Выше" @click="move(r.id, i - 1)">↑</button>
              <button type="button" :disabled="busy || i === rules.length - 1" title="Ниже" @click="move(r.id, i + 1)">↓</button>
              <button type="button" :disabled="busy" @click="del(r.id)">Удалить</button>
            </td>
          </tr>
          <tr v-if="!rules.length"><td colspan="6">Правил нет.</td></tr>
        </tbody>
      </table>
    </div>

    <div v-else-if="tab === 'devices'">
      <h2>Сети (SSID)</h2>
      <p class="mg__hint">Политика сети применяется по порту моста — интерфейсу SSID (например <code>wl0</code>, <code>wl1</code>), а не по IP-адресу.</p>
      <table class="mg__table">
        <thead><tr><th>Сеть</th><th>SSID</th><th>Мост и порты</th><th>Подсеть</th><th></th></tr></thead>
        <tbody>
          <tr v-for="n in config.networks" :key="n.id">
            <td>{{ n.name }} <code>{{ n.id }}</code></td><td>{{ n.ssid }}</td><td>{{ n.bridge ?? '—' }}{{ n.ports?.length ? `: ${n.ports.join(', ')}` : '' }}</td><td>{{ n.subnet ?? '—' }}</td>
            <td class="mg__actions"><button type="button" @click="editNetwork(n.id)">Изменить</button><button type="button" :disabled="busy" @click="delNetwork(n.id)">Удалить</button></td>
          </tr>
        </tbody>
      </table>
      <form class="mg__form" @submit.prevent="saveNetwork">
        <label>Идентификатор <input v-model="nf.id" required pattern="[a-z0-9][a-z0-9_-]*" /></label>
        <label>Название <input v-model="nf.name" required /></label>
        <label>SSID <input v-model="nf.ssid" required /></label>
        <label>Мост <input v-model="nf.bridge" placeholder="br-lan" /></label>
        <label>Порты SSID (через пробел) <input v-model="nf.ports" placeholder="wl0 wl1" /></label>
        <label>Подсеть клиентов <input v-model="nf.subnet" placeholder="192.168.31.0/24" /></label>
        <button type="submit" :disabled="busy">Сохранить сеть</button>
      </form>

      <h2>Устройства</h2>
      <p class="mg__hint">Устройство определяется по MAC на входе моста; смена его IPv4 в аренде не выводит его из-под правила.</p>
      <table class="mg__table">
        <thead><tr><th>Устройство</th><th>MAC</th><th>Сеть</th><th></th></tr></thead>
        <tbody>
          <tr v-for="d in config.devices" :key="d.id">
            <td>{{ d.name }} <code>{{ d.id }}</code></td><td><code>{{ d.mac }}</code></td><td>{{ netName(d.network) }}</td>
            <td class="mg__actions"><button type="button" @click="editDevice(d.id)">Изменить</button><button type="button" :disabled="busy" @click="delDevice(d.id)">Удалить</button></td>
          </tr>
        </tbody>
      </table>
      <form class="mg__form" @submit.prevent="saveDevice">
        <label>Идентификатор <input v-model="dv.id" required pattern="[a-z0-9][a-z0-9_-]*" /></label>
        <label>Название <input v-model="dv.name" required /></label>
        <label>MAC <input v-model="dv.mac" required placeholder="aa:bb:cc:dd:ee:ff" /></label>
        <label>Сеть <select v-model="dv.network" required><option v-for="n in config.networks" :key="n.id" :value="n.id">{{ n.name }}</option></select></label>
        <button type="submit" :disabled="busy">Сохранить устройство</button>
      </form>
      <h3>Клиенты из аренд DHCP</h3>
      <table class="mg__table">
        <thead><tr><th>Имя</th><th>MAC</th><th>IPv4</th><th></th></tr></thead>
        <tbody>
          <tr v-for="l in leases" :key="l.mac">
            <td>{{ l.hostname || '—' }}</td><td><code>{{ l.mac }}</code></td><td>{{ l.ip }}</td>
            <td class="mg__actions"><span v-if="l.device">устройство <code>{{ l.device }}</code></span><button v-else type="button" @click="pickLease(l)">Заполнить форму</button></td>
          </tr>
          <tr v-if="!leases.length"><td colspan="4">Аренд нет.</td></tr>
        </tbody>
      </table>
      <button type="button" @click="loadLeases">Обновить список</button>
    </div>

    <div v-else-if="tab === 'profiles'">
      <h2>VPN-профили</h2>
      <table class="mg__table">
        <thead><tr><th>Профиль</th><th>Вид</th><th>Сервер</th><th>Секрет</th><th></th></tr></thead>
        <tbody>
          <tr v-for="p in config.profiles" :key="p.id">
            <td>{{ p.name }} <code>{{ p.id }}</code></td><td>{{ p.kind }}</td><td>{{ p.endpoint ? `${p.endpoint.server}:${p.endpoint.port}` : '—' }}</td>
            <td>{{ secrets[p.id] ? 'задан' : 'нет' }}</td>
            <td class="mg__actions"><button type="button" @click="editProfile(p.id)">Изменить</button><button type="button" :disabled="busy" @click="delProfile(p.id)">Удалить</button></td>
          </tr>
        </tbody>
      </table>
      <button v-if="!editing" type="button" @click="newProfile">Добавить профиль</button>
      <form v-else class="mg__form" @submit.prevent="saveProfile">
        <label>Идентификатор <input v-model="pf.id" required pattern="[a-z0-9][a-z0-9_-]*" /></label>
        <label>Название <input v-model="pf.name" required /></label>
        <label>Вид
          <select v-model="pf.kind">
            <option value="trusttunnel">TrustTunnel</option><option value="hysteria2">Hysteria2</option><option value="vless">VLESS</option><option value="wireguard">WireGuard / AmneziaWG</option>
          </select>
        </label>
        <label>При отказе <select v-model="pf.onFailure"><option value="block">блокировать</option><option value="direct">напрямую (обход)</option></select></label>
        <label>Сервер <input v-model="pf.server" required /></label>
        <label>Порт <input v-model="pf.port" inputmode="numeric" required /></label>
        <template v-if="pf.kind !== 'wireguard'">
          <label>SNI (имя в сертификате) <input v-model="pf.sni" /></label>
          <label v-if="!(pf.kind === 'vless' && pf.security === 'reality')">SHA-256 сертификата (закрепление) <input v-model="pf.certSha256" /></label>
        </template>
        <label v-if="pf.kind === 'trusttunnel'">Имя пользователя <input v-model="pf.username" required /></label>
        <label v-if="pf.kind === 'trusttunnel'" class="mg__check"><input v-model="pf.quic" type="checkbox" /> HTTP/3 (QUIC)</label>
        <label v-if="pf.kind === 'hysteria2'" class="mg__check"><input v-model="pf.obfs" type="checkbox" /> Обфускация salamander</label>
        <template v-if="pf.kind === 'vless'">
          <label>Защита <select v-model="pf.security"><option value="tls">TLS</option><option value="reality">REALITY</option></select></label>
          <label class="mg__check"><input v-model="pf.vision" type="checkbox" /> XTLS vision</label>
          <template v-if="pf.security === 'reality'">
            <label>Открытый ключ REALITY <input v-model="pf.realityKey" required /></label>
            <label>Short ID <input v-model="pf.realityShortId" /></label>
            <p class="mg__warn">REALITY клиента Mihomo v1.19.34 не работает с серверами Xray ≥ v26.9.30; для них используйте TLS.</p>
          </template>
        </template>
        <template v-if="pf.kind === 'wireguard'">
          <label>Открытый ключ сервера <input v-model="pf.publicKey" required /></label>
          <label>Адрес клиента (IPv4/32) <input v-model="pf.address" required placeholder="10.66.66.2/32" /></label>
          <label>MTU <input v-model="pf.mtu" inputmode="numeric" placeholder="1408" /></label>
          <label class="mg__check"><input v-model="pf.awg" type="checkbox" /> AmneziaWG</label>
          <label v-if="pf.awg">Параметры AmneziaWG <input v-model="pf.awgText" /></label>
        </template>
        <fieldset class="mg__secret">
          <legend>Секрет (только запись; сохранённое значение не показывается)</legend>
          <label>{{ labels[0] }} <input v-model="pf.secret1" type="password" autocomplete="off" /></label>
          <label v-if="labels[1]">{{ labels[1] }} <input v-model="pf.secret2" type="password" autocomplete="off" /></label>
        </fieldset>
        <div class="mg__row"><button type="submit" :disabled="busy">Сохранить профиль</button><button type="button" @click="editing = false">Отмена</button></div>
      </form>
    </div>

    <div v-else-if="tab === 'categories'">
      <h2>Категории назначений</h2>
      <p class="mg__hint">Геокатегории и списки доменов или IP-префиксов хранятся локально и используются в правилах как назначение «категория».</p>
      <table class="mg__table">
        <thead><tr><th>Категория</th><th>Вид</th><th>Источник</th><th></th></tr></thead>
        <tbody>
          <tr v-for="c in config.categories ?? []" :key="c.id">
            <td>{{ c.name }} <code>{{ c.id }}</code></td><td>{{ c.kind === 'domain' ? 'домены' : 'IP-префиксы' }}</td><td>{{ c.source ?? '—' }}</td>
            <td class="mg__actions"><button type="button" @click="catTarget = c.id">Загрузить список</button><button type="button" :disabled="busy" @click="delCategory(c.id)">Удалить</button></td>
          </tr>
        </tbody>
      </table>
      <form class="mg__form" @submit.prevent="saveCategory">
        <label>Идентификатор <input v-model="cat.id" required /></label>
        <label>Название <input v-model="cat.name" required /></label>
        <label>Вид <select v-model="cat.kind"><option value="domain">домены</option><option value="ip">IP-префиксы</option></select></label>
        <label>Источник (необязательно) <input v-model="cat.source" placeholder="geosite:youtube" /></label>
        <button type="submit" :disabled="busy">Сохранить категорию</button>
      </form>
      <form v-if="catTarget" class="mg__form" @submit.prevent="uploadCategory">
        <label>Список категории <code>{{ catTarget }}</code> (по записи в строке)<textarea v-model="catList" rows="6" /></label>
        <button type="submit" :disabled="busy || !catList.trim()">Проверить и заменить список</button>
      </form>
    </div>

    <div v-else-if="tab === 'dns'">
      <h2>DNS и блокировка рекламы</h2>
      <form class="mg__form" @submit.prevent="saveDns">
        <label class="mg__check"><input v-model="dnsOn" type="checkbox" /> Шифрованный DNS для всей сети (открытого DNS наружу не будет)</label>
        <template v-if="dnsOn">
          <label>Транспорт
            <select v-model="dns.transport" @change="ensureOdoh">
              <option value="doh">DoH</option><option value="dot">DoT</option><option value="doq">DoQ</option><option value="doh3">DoH3</option><option value="odoh">ODoH через relay</option>
            </select>
          </label>
          <template v-if="dns.transport !== 'odoh'">
            <div v-for="(s, i) in dns.servers" :key="i" class="mg__row">
              <label>Имя сервера <input v-model="s.host" required /></label><label>IP <input v-model="s.ip" required /></label>
            </div>
          </template>
          <template v-else-if="dns.odoh">
            <div class="mg__row"><label>Target <input v-model="dns.odoh.target.host" required /></label><label>IP <input v-model="dns.odoh.target.ip" required /></label></div>
            <div v-for="(r, i) in dns.odoh.relays" :key="i" class="mg__row"><label>Relay <input v-model="r.host" required /></label><label>IP <input v-model="r.ip" required /></label></div>
            <p class="mg__warn">Если все relay недоступны, клиенты получают ошибку DNS: обхода через target нет.</p>
          </template>
          <label class="mg__check"><input v-model="dns.adblock!.enabled" type="checkbox" /> Блокировать рекламу</label>
          <label>Исключения (по домену в строке)<textarea v-model="exceptionsText" rows="3" /></label>
        </template>
        <button type="submit" :disabled="busy">Сохранить DNS</button>
      </form>
      <form class="mg__form" @submit.prevent="uploadAdblock">
        <label>Новый список рекламы (домены или строки hosts)<textarea v-model="adText" rows="6" /></label>
        <button type="submit" :disabled="busy || !adText.trim()">Проверить и заменить список</button>
        <p class="mg__hint">Ошибочный список не применяется; действует предыдущий.</p>
      </form>
      <h2>Обход блокировок (Zapret)</h2>
      <form class="mg__form" @submit.prevent="saveZapret">
        <label class="mg__check"><input v-model="zOn" type="checkbox" /> Включить nfqws2 для действия «напрямую с Zapret»</label>
        <template v-if="zOn">
          <label>Стратегия <select v-model="z.strategy"><option value="multisplit">multisplit</option><option value="multidisorder">multidisorder</option></select></label>
          <label>Позиция разреза <input v-model="z.pos" inputmode="numeric" /></label>
          <label>TCP-порты <input v-model="zPorts" placeholder="80 443" /></label>
        </template>
        <button type="submit" :disabled="busy">Сохранить Zapret</button>
      </form>
    </div>

    <div v-else-if="tab === 'status'">
      <h2>Состояние</h2>
      <p>Панель только сохраняет настройки. Применяет их к сети служба роутера (mi-tt-admin) — по заявке или при перезагрузке, смене аренды и перезагрузке firewall.</p>
      <p v-if="status">Заявка на применение: {{ status.apply_pending ? 'ожидает службу' : 'нет' }}</p>
      <pre v-if="status?.service" class="mg__pre">{{ JSON.stringify(status.service, null, 2) }}</pre>
      <p v-else-if="status">Служба ещё не сообщала состояние.</p>
      <div class="mg__row"><button type="button" :disabled="busy" @click="applyNow">Применить настройки</button><button type="button" @click="loadStatus">Обновить</button></div>
    </div>
  </section>
</template>
