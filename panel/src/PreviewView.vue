<script setup lang="ts">
import { computed } from 'vue'
import type { ApiResult, PreviewResponse } from './api'

const props = defineProps<{ result: ApiResult<PreviewResponse> | null; stale: boolean }>()

const p = computed(() => (props.result?.status === 200 ? props.result.body.preview ?? null : null))
const failed = computed(() => (props.result && !p.value ? props.result : null))
const title = computed(() => {
  const s = failed.value?.status
  if (s === 422) return 'Правило не прошло проверку'
  if (s === 409) return 'Сохранённые настройки не проходят проверку'
  if (s === 0) return 'Нет связи с контроллером'
  return `Ошибка запроса (${s})`
})
</script>

<template>
  <section class="preview" :class="{ 'preview--stale': stale }" aria-live="polite">
    <p v-if="!result" class="preview__empty">Заполните правило и нажмите «Проверить и показать». Контроллер проверит его и покажет, как изменится выбор маршрута.</p>

    <div v-else-if="failed" class="preview__error" role="alert">
      <h2>{{ title }}</h2>
      <p v-if="failed.body.error && failed.body.error.message.toLowerCase() !== title.toLowerCase()">{{ failed.body.error.message }}</p>
      <ul>
        <li v-for="i in failed.body.issues" :key="i.path + i.code"><code>{{ i.path }}</code> {{ i.message }}</li>
      </ul>
    </div>

    <template v-else-if="p">
      <p v-if="stale" class="preview__stale">Форма изменилась после проверки — нажмите «Проверить» ещё раз.</p>
      <div class="preview__summary">
        <div>
          <span class="preview__k">Позиция</span>
          <strong>{{ p.position }} из {{ p.order.length }}</strong>
          <span class="preview__muted">{{ p.level_label }} · {{ p.mode === 'add' ? 'новое правило' : 'замена существующего' }}</span>
        </div>
        <div>
          <span class="preview__k">Выход</span>
          <strong>{{ p.exit }}</strong>
          <span v-if="p.on_failure" class="preview__muted">при отказе профиля: {{ p.on_failure }}</span>
        </div>
        <div>
          <span class="preview__k">Касается</span>
          <strong v-if="p.affected_devices.length">{{ p.affected_devices.map((d) => d.name).join(', ') }}</strong>
          <strong v-else>нет известных устройств</strong>
          <span v-if="p.affects_unknown_clients" class="preview__muted">и новых клиентов источника</span>
        </div>
      </div>

      <ul class="preview__findings">
        <li v-for="f in p.findings" :key="f.code + f.message" :class="`preview__finding preview__finding--${f.severity}`">
          <span class="preview__badge">{{ f.severity === 'warning' ? 'внимание' : 'инфо' }}</span>{{ f.message }}
        </li>
      </ul>

      <h3 v-if="p.probes.length">Пробные запросы</h3>
      <div v-if="p.probes.length" class="preview__scroll">
        <table class="preview__table">
          <thead><tr><th>Кто</th><th>Куда</th><th>Сейчас</th><th>После правила</th></tr></thead>
          <tbody>
            <tr v-for="(r, i) in p.probes" :key="i" :class="{ 'preview__row--changed': r.changed }">
              <td>{{ r.subject }}</td>
              <td><code>{{ r.host }}</code></td>
              <td>{{ r.before.exit }}<small v-if="r.before.rule_id"> · {{ r.before.rule_id }}</small></td>
              <td>{{ r.after.exit }}<small v-if="r.after.rule_id"> · {{ r.after.rule_id }}</small></td>
            </tr>
          </tbody>
        </table>
      </div>

      <h3>Порядок вычисления</h3>
      <div class="preview__scroll">
        <table class="preview__table">
          <thead><tr><th>#</th><th>Правило</th><th>Источник</th><th>Назначение</th><th>Выход</th></tr></thead>
          <tbody>
            <tr v-for="o in p.order" :key="o.rule_id" :class="{ 'preview__row--draft': o.draft }">
              <td>{{ o.position }}</td>
              <td><code>{{ o.rule_id }}</code></td>
              <td>{{ o.source }}</td>
              <td>{{ o.destination }}</td>
              <td>{{ o.exit }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <details class="preview__details">
        <summary>Развёрнутые записи сопоставления ({{ p.match_entries.length }})</summary>
        <ul>
          <li v-for="(m, i) in p.match_entries" :key="i">{{ m.source }} → {{ m.destination }} → {{ m.exit }}</li>
        </ul>
      </details>
      <p class="preview__muted">Это предпросмотр: сохранение — кнопкой ниже; к сети правило применяется отдельно, не из панели.</p>
    </template>
  </section>
</template>
