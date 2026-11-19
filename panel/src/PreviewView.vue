<script setup lang="ts">
import { computed } from 'vue'
import Message from 'primevue/message'
import type { ApiResult, PreviewResponse } from './api'
import { exitKind, exitShort } from './route'
import RouteBadge from './RouteBadge.vue'

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

const isDefault = (exit: string) => exit.startsWith('маршрут по умолчанию')
</script>

<template>
  <section :class="['preview', { 'preview--stale': stale }]" aria-live="polite" aria-labelledby="preview-title">
    <h2 id="preview-title" class="preview__title">Проверка</h2>
    <p v-if="!result" class="preview__empty">
      Заполните правило и нажмите «Проверить правило». Контроллер проверит его и покажет, как изменится выбор маршрута.
    </p>

    <Message v-else-if="failed" severity="error" :closable="false" role="alert">
      <strong>{{ title }}.</strong>
      <span v-if="failed.body.error && failed.body.error.message.toLowerCase() !== title.toLowerCase()"> {{ failed.body.error.message }}.</span>
      <ul v-if="failed.body.issues.length" class="issues">
        <li v-for="i in failed.body.issues" :key="i.path + i.code"><code>{{ i.path }}</code> {{ i.message }}</li>
      </ul>
    </Message>

    <template v-else-if="p">
      <Message v-if="stale" severity="warn" :closable="false" size="small">Форма изменилась после проверки — нажмите «Проверить правило» ещё раз.</Message>
      <dl class="facts">
        <div class="facts__item">
          <dt>Позиция</dt>
          <dd><span class="facts__big num">{{ p.position }} из {{ p.order.length }}</span></dd>
          <dd class="facts__note">{{ p.level_label }}, {{ p.mode === 'add' ? 'новое правило' : 'замена существующего' }}</dd>
        </div>
        <div class="facts__item">
          <dt>Выход</dt>
          <dd><RouteBadge :kind="exitKind(p.exit)" :label="exitShort(p.exit)" :title="p.exit" /></dd>
          <dd v-if="p.on_failure" class="facts__note">При отказе туннеля: {{ p.on_failure }}</dd>
        </div>
        <div class="facts__item">
          <dt>Касается</dt>
          <dd>{{ p.affected_devices.length ? p.affected_devices.map((d) => d.name).join(', ') : 'Нет известных устройств' }}</dd>
          <dd v-if="p.affects_unknown_clients" class="facts__note">и новых клиентов источника</dd>
        </div>
      </dl>

      <div v-if="p.findings.length" class="findings">
        <Message v-for="f in p.findings" :key="f.code + f.message" :severity="f.severity === 'warning' ? 'warn' : 'secondary'" size="small" :closable="false">
          <span class="sr-only">{{ f.severity === 'warning' ? 'Внимание: ' : 'Для сведения: ' }}</span>{{ f.message }}
        </Message>
      </div>

      <template v-if="p.probes.length">
        <h3 class="preview__sub">Пробные запросы</h3>
        <ul class="probes">
          <li v-for="(r, i) in p.probes" :key="i" :class="['probes__row', { 'probes__row--changed': r.changed }]">
            <span class="probes__who">{{ r.subject }} <span class="route__arrow" aria-hidden="true">→</span><span class="sr-only">, адрес</span> <span class="num">{{ r.host }}</span></span>
            <span class="probes__exit">
              <span class="probes__k">Сейчас</span>
              <RouteBadge :kind="exitKind(r.before.exit)" :label="exitShort(r.before.exit)" :title="r.before.exit" />
              <small class="tbl__meta">{{ r.before.rule_id ?? (isDefault(r.before.exit) ? 'по умолчанию' : '') }}</small>
            </span>
            <span class="probes__exit">
              <span class="probes__k">После правила<span v-if="r.changed" class="tbl__changed">, изменится</span></span>
              <RouteBadge :kind="exitKind(r.after.exit)" :label="exitShort(r.after.exit)" :title="r.after.exit" />
              <small class="tbl__meta">{{ r.after.rule_id ?? (isDefault(r.after.exit) ? 'по умолчанию' : '') }}</small>
            </span>
          </li>
        </ul>
      </template>

      <h3 class="preview__sub">Порядок вычисления</h3>
      <ol class="order">
        <li v-for="o in p.order" :key="o.rule_id" :class="['order__row', `bar--${exitKind(o.exit) ?? 'none'}`, { 'order__row--draft': o.draft }]">
          <span class="order__pos num">{{ o.position }}</span>
          <span class="order__body">
            <span class="order__id">{{ o.rule_id }}<span v-if="o.draft" class="order__draft">это правило</span></span>
            <span class="order__route">{{ o.source }} → {{ o.destination }}</span>
          </span>
          <RouteBadge :kind="exitKind(o.exit)" :label="exitShort(o.exit)" />
        </li>
      </ol>

      <details class="more">
        <summary>Развёрнутые записи сопоставления ({{ p.match_entries.length }})</summary>
        <ul>
          <li v-for="(m, i) in p.match_entries" :key="i">{{ m.source }} → {{ m.destination }} → {{ m.exit }}</li>
        </ul>
      </details>
      <p class="preview__note">Это предпросмотр. Сохраните правило кнопкой ниже; к сети его применяет служба роутера по заявке из раздела «Состояние».</p>
    </template>
  </section>
</template>
