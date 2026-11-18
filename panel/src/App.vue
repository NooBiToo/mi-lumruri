<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { api, type ApiResult, type ConfigResponse, type PreviewResponse, type SaveResponse } from './api'
import { defaultForm, fieldForIssue, ruleKey, saveOutcome, toRequest, type DraftForm, type Field, type SaveOutcome } from './draft'
import RuleForm from './RuleForm.vue'
import PreviewView from './PreviewView.vue'

const cfg = ref<ApiResult<ConfigResponse> | null>(null)
const form = ref<DraftForm | null>(null)
const result = ref<ApiResult<PreviewResponse> | null>(null)
const busy = ref(false)
const stale = ref(false)
const checkedKey = ref<string | null>(null)
const saving = ref(false)
const saveRes = ref<ApiResult<SaveResponse> | null>(null)
const outcome = ref<SaveOutcome | null>(null)

async function load(keepForm = false) {
  cfg.value = await api.config()
  const c = cfg.value.body.config
  if (!keepForm || !form.value) form.value = c && cfg.value.body.ok ? defaultForm(c) : null
  result.value = null
  checkedKey.value = null
  saveRes.value = null
  outcome.value = null
}

async function check() {
  if (!form.value) return
  busy.value = true
  try {
    const key = ruleKey(form.value)
    result.value = await api.preview(toRequest(form.value))
    stale.value = false
    checkedKey.value = result.value.status === 200 ? key : null
    saveRes.value = null
    outcome.value = null
  } finally {
    busy.value = false
  }
}

const canSave = computed(
  () => !!form.value && !!cfg.value?.body.revision && checkedKey.value !== null && checkedKey.value === ruleKey(form.value) && !saving.value,
)

async function save() {
  if (!form.value || !cfg.value?.body.revision || !canSave.value) return
  saving.value = true
  try {
    saveRes.value = await api.saveRule(cfg.value.body.revision, toRequest(form.value).rule)
    outcome.value = saveOutcome(saveRes.value)
    const b = saveRes.value.body
    if (outcome.value.kind === 'saved' && b.config && b.revision) {
      cfg.value = { status: 200, body: { ...cfg.value.body, ok: true, config: b.config, revision: b.revision, issues: [] } }
      checkedKey.value = null
    } else if (outcome.value.kind === 'conflict') {
      checkedKey.value = null
    }
  } finally {
    saving.value = false
  }
}

watch(form, () => { if (result.value) stale.value = true }, { deep: true })

const errors = computed(() => {
  const out: Partial<Record<Field, string[]>> = {}
  const src = saveRes.value?.status === 422 ? saveRes.value.body.issues : result.value?.status === 422 ? result.value.body.issues : []
  for (const i of src) {
    const f = fieldForIssue(i.path)
    if (f) (out[f] ??= []).push(i.message)
  }
  return out
})

function count(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10
  const m100 = n % 100
  const w = m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many
  return `${n} ${w}`
}

onMounted(() => load())
</script>

<template>
  <div class="app">
    <header class="app__head">
      <div>
        <h1>Правило устройства или сети</h1>
        <p class="app__sub">mi-trusttunnel · BE7000 · сценарий TrustTunnel</p>
      </div>
      <span class="app__mode" title="Стенд слушает только 127.0.0.1; входа по паролю пока нет">Стенд · только loopback</span>
    </header>

    <section v-if="!cfg" class="app__status">Читаю настройки…</section>
    <section v-else-if="!cfg.body.ok || !cfg.body.config" class="app__status app__status--bad" role="alert">
      <strong>Настройки не загружены.</strong>
      <span v-if="cfg.body.error"> {{ cfg.body.error.message }}</span>
      <ul>
        <li v-for="i in cfg.body.issues" :key="i.path + i.code"><code>{{ i.path }}</code> {{ i.message }}</li>
      </ul>
      <button type="button" @click="load()">Повторить</button>
    </section>
    <section v-else class="app__status">
      Настройки v{{ cfg.body.config.version }}: {{ count(cfg.body.config.profiles.length, 'VPN-профиль', 'VPN-профиля', 'VPN-профилей') }},
      {{ count(cfg.body.config.networks.length, 'сеть', 'сети', 'сетей') }}, {{ count(cfg.body.config.devices.length, 'устройство', 'устройства', 'устройств') }},
      {{ count(cfg.body.config.groups.length, 'группа', 'группы', 'групп') }}, {{ count(cfg.body.config.rules.length, 'правило', 'правила', 'правил') }}.
      <span v-if="cfg.body.revision" class="app__rev">Ревизия {{ cfg.body.revision.slice(0, 12) }}</span>
      <span v-if="cfg.body.config.rules.length" class="app__rules">
        Сохранены: <code v-for="r in cfg.body.config.rules" :key="r.id">{{ r.id }}</code>
      </span>
    </section>

    <main v-if="form && cfg?.body.config" class="app__grid">
      <RuleForm v-model="form" :config="cfg.body.config" :errors="errors" :busy="busy" @submit="check" />
      <div class="app__right">
        <PreviewView :result="result" :stale="stale" />
        <div class="save">
          <button type="button" class="save__btn" :disabled="!canSave" @click="save">
            {{ saving ? 'Сохраняю…' : 'Сохранить правило' }}
          </button>
          <span v-if="!outcome" class="save__hint">Сохранить можно только правило, прошедшее проверку и не изменённое после неё.</span>
          <span v-else :class="`save__msg save__msg--${outcome.kind}`" role="status">{{ outcome.message }}</span>
          <button v-if="outcome?.kind === 'conflict'" type="button" class="save__reload" @click="load(true)">Обновить настройки</button>
        </div>
      </div>
    </main>

    <footer class="app__foot">
      Локальный стенд на 127.0.0.1: контроллер вызывается как CGI и сохраняет правило атомарно, только по запросу с этой
      страницы. Входа по паролю пока нет. Применение к сети выполняется отдельно (mi-tt-ctl render) и из панели не запускается.
    </footer>
  </div>
</template>
