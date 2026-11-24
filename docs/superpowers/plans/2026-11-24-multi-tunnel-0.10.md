# Несколько туннелей и накопители (0.10.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** До 16 серверов TrustTunnel одновременно, каждый со своим TUN и таблицей; правила выбирают сервер; пакет
видит накопители; страница «Модули» показывает их (установка модулей — 0.11.0 вместе с sing-box).

**Architecture:** Номер туннеля кодируется в поле метки (`0xf0`, запасное `0x0f00`) рядом с битом `0x4000`; при одном
туннеле план не меняется ни в одной записи. mi-tt-admin выбирает свободное поле по живому состоянию и при занятости
обоих полей сужает план до туннеля 0. Рендер пишет файлы туннеля 0 по прежним путям, туннелей n>0 — в `tun<n>/`;
служба обходит туннели из `tunnels.list`.

**Tech Stack:** Rust (controller, mi-tt-admin), BusyBox ash, Vue 3 + TS (panel), qemu-user лаборатория.

**Spec:** `docs/superpowers/specs/2026-11-24-modules-multi-tunnel-design.md`

## Global Constraints

- Один туннель ⇒ план (`build_plan`) байт-в-байт как сейчас: маска `0x4000/0x4000`, таблица 3100, `mitt0`.
- Поле номера: основное `0xf0` (shift 4), запасное `0x0f00` (shift 8); маска правил N>1: `0x4000 | field`.
- Туннель n: таблица `3100+n`, интерфейс `mitt<n>`, метка `0x4000 | n<<shift`; n ∈ 0..15.
- Чужие биты не делим: занятое поле не используется; оба заняты ⇒ только туннель 0, правила n>0 по политике отказа.
- Зона `ip rule` 3000–3199, таблицы 3100–3115.
- Файлы туннеля 0 — прежние пути (`$RENDER/client.toml`, `$STATE/endpoint`, `$LOG/trusttunnel.log`, pid `trusttunnel`).
  Туннель n>0: `$RENDER/tun<n>/…`, `$STATE/tun<n>/…`, `$LOG/trusttunnel<n>.log`, pid `trusttunnel<n>`.
- Старое состояние mi-tt-admin (`state.json` без новых полей) читается: новые поля с `serde(default)`.
- i18n ru/en/zh полностью (i18n.test); shellcheck и secret-scan чистые; лаборатория — только qemu-user.

## Review Focus

1. Обновление с 0.9.x при одном сервере: ни одной записи `ip rule`/iptables не меняется (переприменение — noop).
2. Удаление сервера с индексом 0 при оставшемся сервере 1: план переходит на «один туннель» с индексом 1 — метка
   должна оставаться полевой (n≠0 требует поле), а не `0x4000/0x4000` с таблицей 3101 без поля. Решение: если
   единственный туннель имеет n>0, используется поле (тест в Task 1).
3. Поле занято во время работы (UU включили): тик переприменяет на запасном поле без потери туннеля 0.
4. Правило «Сайтов» ссылается на удалённый сервер — проверка настроек отклоняет (validate), панель не даёт удалить
   сервер, пока на него есть правила (переназначает на сервер по умолчанию).
5. Флешки с пробелами/юникодом в пути монтирования и FAT без exec — `storage` их показывает, путь экранируется в JSON.

---

### Task 1: План меток и таблиц на N туннелей (plan.rs)

**Files:**
- Modify: `controller/src/plan.rs` (PolicySpec, PolicyRule, Entry::Route, build_plan, our_mark_mask, reconcile, tests)

**Interfaces:**
- Produces:
  - `pub struct TunSpec { pub index: u8, pub dev: String, pub fail_open: bool }` (serde, deny_unknown_fields)
  - `PolicySpec.extra: Vec<TunSpec>` (`#[serde(default, skip_serializing_if = "Vec::is_empty")]`) — туннели n≥1 и
    туннель 0, если его нет (тогда `tun` пуст — см. ниже); `PolicySpec.field: MarkField` (`serde(default)`)
  - `pub enum MarkField { #[default] Uu, Wan }` with `fn mask(self) -> u32` (0xf0 / 0x0f00), `fn shift(self) -> u32`
  - `PolicyRule.tun: u8` (`serde(default)`, skip if 0)
  - `PolicySpec.dns_tun: u8` (`serde(default)`, skip if 0)
  - `Entry::Route { v6, table: u32 (serde default = TABLE), dev, metric }`
  - `pub fn tun_mark(spec: &PolicySpec, n: u8) -> (u32, u32)` — (значение, маска): один туннель с n=0 ⇒
    `(0x4000, 0x4000)`, иначе `(0x4000 | n<<shift, 0x4000 | field.mask())`
  - `pub fn tunnels(spec: &PolicySpec) -> Vec<TunSpec>` — все туннели (0 из `tun`/`fail_open`, если `tun` не пуст)
  - `pub fn degrade(spec: &PolicySpec) -> PolicySpec` — оставить туннель с наименьшим индексом; правила других
    туннелей → `Act::Block` (fail_open=false) или удаляются (fail_open=true, т. е. «напрямую»: правило без метки).
  - `pub fn field_users(ipt_save: &str, ip_rules: &str, field: MarkField) -> Vec<String>` — чужие записи, задевающие поле.

- [ ] **Step 1: Тесты**
  - `single_tunnel_plan_unchanged`: снимок записей `build_plan(&spec())` до изменений (скопировать текущий вывод
    в ожидание) совпадает после.
  - `two_tunnels_use_uu_field`: туннели 0 и 1 ⇒ правила `fwmark 0x4000/0x40f0 lookup 3100` и
    `fwmark 0x4010/0x40f0 lookup 3101`, маршруты `table 3101 dev mitt1`, лист-цепочки `--set-xmark 0x4010/0x40f0`.
  - `wan_field`: то же с `field: Wan` ⇒ `0x4100/0x4f00`.
  - `lone_nonzero_tunnel_uses_field`: только туннель 3 ⇒ `0x4030/0x40f0`, таблица 3103.
  - `degrade_blocks_or_drops`: правило tun=1 с fail_open=false ⇒ Act::Block; с true ⇒ правило исчезает.
  - `field_users_finds_uu`: `-A X -j MARK --set-xmark 0x20/0xf0` ⇒ найдено для Uu, не для Wan.
  - `old_state_policy_parses`: JSON PolicySpec без новых полей разбирается.
- [ ] **Step 2:** `bash tools/cargo.sh test -p mi-tt-controller plan::` — новые тесты падают.
- [ ] **Step 3:** Реализация. Каждый туннель: свой guard-маршрут (если !fail_open) и tun-маршрут в своей таблице,
  `ip rule` приоритета `PRIO_MARK + n` с его меткой; классификация `C` переходит в лист `T<n>` по `rule.tun`;
  FORWARD accept для каждого `mitt<n>`; DNS-цепочка `O` ставит метку `dns_tun`; IPv6-ветка идёт в туннель
  `v6_tun: u8` (новое поле рядом с `v6_tunnel`, рендер берёт туннель правил «всё через VPN» сервера по умолчанию). `reconcile`/`read_live` учитывают таблицы 3100..=3115 (`Entry::Route.table`).
- [ ] **Step 4:** тесты plan:: проходят; весь `cargo test` проходит.
- [ ] **Step 5:** commit `feat(plan): метки и таблицы на несколько туннелей`.

### Task 2: Выбор поля и сужение в mi-tt-admin

**Files:**
- Modify: `controller/src/admin/main.rs` (table_routes по всем таблицам туннелей, change, status, State)
- Modify: `controller/src/plan.rs` (`pub fn choose_field`)

**Interfaces:**
- Consumes: Task 1.
- Produces: `pub fn choose_field(spec: &PolicySpec, ipt_save: &str, ip_rules: &str) -> (PolicySpec, Option<MarkField>, Vec<String>)`
  — если туннелей ≤1 и он n=0 ⇒ spec как есть, None; иначе Uu, если свободно, затем Wan; иначе `degrade` + причина.
  `State.mark_field: Option<String>` (`"uu"|"wan"`), `State.degraded: bool`; выводятся в `status` и `apply`.
- [ ] Тесты `choose_field_prefers_uu`, `choose_field_falls_back_to_wan`, `choose_field_degrades_when_both_busy`
  (тексты iptables-save/ip rule как в выводе роутера пользователя + `--set-mark 0x20` и `0x100/0x3f00`).
- [ ] Реализация: `change()` читает `iptables-save` и `ip rule` до `build`, применяет `choose_field`; предупреждение
  в `warnings`; поле в state. `read_live` собирает маршруты таблиц 3100..=3115 (`ip route show table N` —
  отсутствие таблицы = пусто, как `table_missing`).
- [ ] `cargo test`; commit `feat(admin): поле номера туннеля по живому состоянию и сужение до одного туннеля`.

### Task 3: Модель и проверка нескольких серверов

**Files:**
- Modify: `controller/src/model.rs` (`Profile.tunnel: u8`, `DnsConfig.tunnel_profile: Option<String>`)
- Modify: `controller/src/validate.rs` (снять `too_many_profiles`, лимит 16, уникальность и диапазон `tunnel`,
  ссылка `tunnel_profile`), `fixtures/` при необходимости, `panel/src/api.ts` (типы)

**Interfaces:**
- Produces: `Profile.tunnel` (`serde(default)`, skip if 0), `DnsConfig.tunnel_profile`.
- [ ] Тесты validate: два профиля с tunnel 0 и 1 — ок; одинаковый tunnel — `duplicate_tunnel`; tunnel 16 —
  `bad_tunnel`; 17 профилей — лимит; `tunnel_profile` на несуществующий — `unknown_profile`.
- [ ] Реализация; `cargo test`; commit `feat(model): несколько серверов с номерами туннелей`.

### Task 4: Рендер по туннелям

**Files:**
- Modify: `controller/src/render.rs` (Rendered.tunnels, PolicySpec.extra/rule.tun/dns_tun, tunnels.list)
- Modify: `controller/src/main.rs` (запись файлов: туннель 0 — прежние пути, n>0 — `tun<n>/`; `tunnels.list`;
  удаление каталогов `tun<n>` исчезнувших туннелей; `dns-tunnel.args` с `--device mitt<dns_tun>`)

**Interfaces:**
- Produces: `pub struct TunRender { index: u8, dev: String, client_toml, client_backup_toml, primary_addr, servers_addr, fastest }`;
  `$RENDER/tunnels.list` строки `«<n> mitt<n> <profile id>»` по возрастанию n (пусто/нет — туннелей нет).
- [ ] Тесты render: два профиля и правила на оба ⇒ `policy.extra` с mitt1, `rules[..].tun` по профилю, два
  `TunRender`; один профиль ⇒ `extra` пуст и `policy` как раньше (снимок); `dns.tunnel_profile` ⇒ `dns_tun`.
- [ ] Реализация; `cargo test`; commit `feat(render): файлы и политика на каждый туннель`.

### Task 5: Служба на несколько туннелей

**Files:**
- Modify: `package/scripts/mitt-lib.sh` (`tun_ctx <n>` → TR/TS/TL/TP/TD; tt_config, tunnel_probe, tun_ready,
  tunnel_tick, tunnel_track, server_addr_learn, primary_reachable — через контекст; stats — сумма `mitt*`)
- Modify: `package/scripts/mitt-service.sh` (запуск/останов/ожидание по `tunnels.list`), `mitt-boot.sh`
  (останов `trusttunnel*`), `mitt-diag.sh` (по туннелям), `mitt-speed.sh` (`--tunnel <n>`), `mitt-notify.sh`
  (через `mitt<dns_tun>`), `controller/src/tunnel.rs` (без изменений логики: `--dir` уже параметр)
- Test: `tools/lab/test-multi.sh` (новый), существующие лабораторные тесты

**Interfaces:**
- Produces: `tun_ctx <n>` выставляет `TR` (каталог рендера), `TS` (состояние), `TL` (журнал клиента), `TP` (имя pid),
  `TD` (интерфейс); для n=0 — прежние значения. Уведомления про туннель n>0 содержат имя профиля.
- [ ] Лабораторный тест test-multi: рендер двух профилей, служба запускает два клиента-заглушки (`MITT_TT_WRAP`),
  ждёт `mitt0` и `mitt1`, сторож перезапускает только упавший, остановка гасит оба; одиночный профиль — прежние пути.
- [ ] Реализация; все лабораторные тесты (`tools/lab/*.sh`), shellcheck; commit `feat(service): несколько клиентов TrustTunnel`.

### Task 6: Накопители

**Files:**
- Create: `controller/src/storage.rs` (`parse_mounts`, `Storage`)
- Modify: `controller/src/main.rs` (`mi-tt-ctl storage`), `controller/src/manage.rs` (`GET /storage`), `lib.rs`
- Test: unit-тесты в storage.rs, `tools/lab/test-storage.sh`

**Interfaces:**
- Produces: `pub struct Storage { path: String, device: String, fs: String, total: u64, free: u64, writable: bool, exec: bool, label: Option<String>, model: Option<String> }`;
  `pub fn parse_mounts(mounts: &str) -> Vec<(String /*dev*/, String /*path*/, String /*fs*/, String /*opts*/)>` —
  только `/dev/sd*` под `/mnt/` или `/extdisks/`, `\040` → пробел; размер — `statvfs` (libc) в `storage_list(root)`;
  `GET /storage` → `{ "data": Storage /data, "usb": [Storage] }`. `MI_TT_PROC_MOUNTS` — путь для лаборатории.
- [ ] Тесты: строки `/proc/mounts` с vfat/ntfs/ext4, `\040`, `ro`, `noexec`; не-USB пропускаются.
- [ ] Реализация; commit `feat(storage): подключённые накопители и их место`.

### Task 7: Панель — серверы, выбор сервера в правилах, «Модули»

**Files:**
- Modify: `panel/src/simple.ts` (+ test): `Simple.siteServer?: Record<string, string>` (ключ — id сервиса или
  домен, значение — id профиля), `Simple.deviceServer?: Record<string, string>` (MAC → профиль), группы
  `vpn-sites` (сервер по умолчанию = `profiles` с наименьшим `tunnel`) и `vpn-sites--<pid>` для остальных, правила
  `vpn-<src>@<pid>`; `fromConfig` разбирает обратно (несколько профилей больше не «ручные»).
- Modify: `panel/src/views/ServerView.vue` (список серверов, «Добавить сервер», удаление с переназначением
  правил на сервер по умолчанию), `SitesView.vue`/`DevicesView.vue` (выбор сервера, если серверов >1),
  `MoreView.vue` (DNS-туннель в «Сеть и DNS», если серверов >1), `App.vue` (пункт «Модули»).
- Create: `panel/src/views/ModulesView.vue` (накопители: путь/модель, свободно/всего, ФС; «Модули появятся в
  следующем обновлении»), `panel/src/i18n/{en,zh}/modules.ts`, `api.ts` (`storage()`), store/status правки
  `profile` → `profiles`.
- Test: `simple.test.ts` (круговой toConfig/fromConfig с двумя серверами), `panel/e2e/servers.e2e.ts`
  (добавить второй сервер, назначить сайту, увидеть «Модули» с накопителем стенда), `stand/server.mjs` (`/storage`).
- [ ] Тесты → реализация → `npm test`, `npm run e2e`; commit `feat(panel): несколько серверов и страница «Модули»`.

### Task 8: Документы, версия, выпуск 0.10.0

- [ ] Руководство RU/EN/ZH (серверы, выбор сервера, «Модули», биты UU/mwan3), README ×3, ARCHITECTURE (метки),
  версия 0.10.0, полная лаборатория (`tools/check-all.sh`), ARM64 сборка, shellcheck, secret-scan, push, CI,
  релиз по обычной схеме, `install-from-github.sh`.
