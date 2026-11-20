> **Исторический документ.** План реализации на 2026-11-19, реализован в версиях 0.3.x; дальше код менялся без правки этого текста. Текущее поведение — в [руководстве](../../guide.md) и [ARCHITECTURE.md](../../../ARCHITECTURE.md).

# Простая панель, списки сайтов и Zapret одной кнопкой — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Панель из пяти простых экранов (Состояние, Сайты, Устройства, Сервер, Дополнительно), готовые списки сайтов itdoginfo с ежедневным обновлением и Zapret, который работает сразу (круговой режим zapret2) и подбирает стратегию одной кнопкой.

**Architecture:** Модель правил контроллера остаётся движком; панель пишет конфигурацию канонического вида целиком через новый `POST /config` и сразу ставит заявку на применение. Стратегии Zapret — встроенный в контроллер каталог (JSON, `include_str!`), из которого рендер собирает профили nfqws2 и очередь NFQUEUE (TCP и UDP, первые пакеты через `connbytes`). Списки сайтов — снимок в пакете, синхронизируемый в `etc/categories/` службой, и ежедневное обновление с GitHub; подбор стратегии — сценарий службы на `curl` стока с отдельной очередью для проверочного трафика.

**Tech Stack:** Rust (controller), BusyBox ash (package/scripts), Vue 3 + TypeScript + PrimeVue 4.5.5 (panel), Node (tools/package.mjs), WSL-лаборатории.

**Spec:** `docs/superpowers/specs/2026-11-19-simple-panel-design.md`

## Global Constraints

- Сток RC06 1.1.38: BusyBox ash 1.25.1, iptables 1.6.2, ipset, `curl` с TLS (`/usr/bin/curl`), модули `xt_connbytes`, `xt_owner`, `xt_NFQUEUE` есть; свободен только бит метки `0x4000`; nfqws2 помечает свои пакеты `0x40000000`.
- Тексты интерфейса и комментарии — по-русски, sentence case, без ALL-CAPS; кнопки называют действие.
- PrimeVue 4.5.5 (последний MIT); новые зависимости — точные версии, опубликованные не позже чем 2 недели назад.
- Стратегии из Zapret-Manager (Apache-2.0) — с указанием авторства в `NOTICE` репозитория и пакета.
- Источник списков: `https://raw.githubusercontent.com/itdoginfo/allow-domains/main/<путь>`; снимок закреплён по коммиту.
- Каждое сохранение в панели ставит заявку на применение; отдельной кнопки «Применить» нет.
- Существующие тесты (`bash tools/cargo.sh test --locked`, `npm test` в panel, `node --test stand/stand.test.mjs`, лаборатории `run-lab-install.sh`, `run-lab-boot.sh`) остаются зелёными.

## Review Focus

- Каталог стратегий ссылается на blob или hostlist, которого нет в пакете → nfqws2 не стартует, Zapret молча не работает. Тест в Task 1 сверяет каждую ссылку с каталогом блобов; Task 2 проверяет, что пакет содержит все файлы каталога; Task 10 запускает nfqws2 с отрендеренными аргументами (`--dry-run`).
- Обновление списков вернуло мусор (HTML-заглушку, пустой файл, обрыв) → прежний список должен остаться. Тест в Task 6.
- Подбор прерван (перезагрузка, падение) или лучше контроля ничего нет → настройка не меняется. Тесты в Task 4.
- Конфигурация на роутере не канонического вида (правлена через CLI) → панель не затирает её молча, а предлагает привести к простому виду. Тест в Task 8.
- Пользователь выключил VPN и включил снова → отмеченные сайты и устройства сохраняются. Тест в Task 8.

---

### Task 1: Каталог стратегий Zapret и профили nfqws2

**Files:**
- Create: `controller/data/zapret-strategies.json`, `controller/src/zapret.rs`, `NOTICE`
- Modify: `controller/src/lib.rs`, `controller/src/model.rs` (ZapretConfig), `controller/src/validate.rs:353-362`, `controller/src/render.rs` (`nfqws2_args_for` → `zapret::nfqws2_args`), `controller/src/manage.rs` (без изменения маршрута `/zapret`)
- Test: `controller/src/zapret.rs` (модульные), `controller/tests/stage9.rs`

**Interfaces:**
- Produces:
  - `model::ZapretConfig { #[serde(default = "auto")] strategy: String, #[serde(default = "auto")] youtube: String }` — `"auto"` или `id` стратегии каталога соответствующего вида; прежние поля `strategy: multisplit|multidisorder`, `pos`, `tcp_ports` удаляются.
  - `zapret::Catalog { blobs: BTreeMap<String, String> /* имя → файл */, hostlists: BTreeMap<String, String> /* youtube|discord → файл */, strategies: Vec<Strategy> }`, `Strategy { id: String, name: String, kind: Kind /* general|youtube */, profiles: Vec<ZProfile> }`, `ZProfile { proto: Proto /* tcp|udp */, ports: String, l7: Vec<String>, hostlist: Option<String>, hostlist_exclude: Vec<String>, args: Vec<String> }`.
  - `zapret::catalog() -> &'static Catalog` (разбор `include_str!("../data/zapret-strategies.json")` один раз).
  - `zapret::selected(cfg: &ZapretConfig) -> Vec<&'static ZProfile>` — профили общей стратегии + YouTube-стратегии + постоянные профили Discord и YouTube QUIC.
  - `zapret::nfqws2_args(cfg: &ZapretConfig, qnum: u16) -> Vec<String>` — `--qnum`, `--fwmark=0x40000000`, `--chdir`, `--lua-init=@zapret-lib.lua.gz`, `--lua-init=@zapret-antidpi.lua.gz`, `--lua-init=@zapret-auto.lua.gz`, `--blob=<имя>:@<файл>` для каждого используемого блоба, затем профили через `--new` (`--filter-tcp|--filter-udp=<ports>`, `--filter-l7=…`, `--hostlist=<файл>`, `--hostlist-exclude=<файл>`, аргументы профиля).
  - `zapret::queue(cfg) -> Vec<(Proto, String)>` — объединённые порты по протоколу для очереди.

- [ ] **Step 1:** Составить `zapret-strategies.json` из `files/Zapret2/zapret2` репозитория StressOzz/Zapret-Manager (ветка `main`): `auto` (general) = профили `V_circular`; `auto` (youtube) = `Youtube_circular`; постоянные профили — `Youtube_UDP`, `Discord_circular`, `discord_media`, `discord_udp`; отдельные стратегии для подбора — каждая группа `strategy=N` из `V_circular` как `v1`…`v10` и из `Youtube_circular` как `yv1`…`yvN` (без `circular`, `strategy=N` и `final`). Имена блобов — как в исходнике; блоб `fake_default_*` встроен в nfqws2 и в `blobs` не нужен. Записать авторство в `NOTICE`.
- [ ] **Step 2:** Тесты `catalog_is_consistent` (каждый `blob=`/`seqovl_pattern=`/`pattern=` в аргументах есть в `blobs` или начинается с `fake_default_`/`0x`; каждый `hostlist` есть в `hostlists`; id уникальны; есть `auto` обоих видов и минимум 8 стратегий general), `auto_args_have_circular_and_profiles` (в `nfqws2_args(&Default)` есть `--lua-init=@zapret-auto.lua.gz`, `circular`, ≥4 `--new`, нет `strategy=` у не-auto выбора `v3`), `unknown_strategy_rejected` (validate: `zapret.strategy = "nope"` → issue `unknown_strategy`; стратегия YouTube в поле `strategy` → `wrong_kind`). Запустить — FAIL.
- [ ] **Step 3:** Реализовать `zapret.rs`, поменять модель и проверки, `render` берёт аргументы из `zapret::nfqws2_args(&zcfg, ZAPRET_QNUM)`; обновить `stage9.rs` под новые аргументы.
- [ ] **Step 4:** `bash tools/cargo.sh test --locked` — PASS.
- [ ] **Step 5:** Commit `feat(zapret): каталог стратегий zapret2 и профили nfqws2`.

### Task 2: Файлы Zapret в пакете

**Files:**
- Modify: `tools/package.mjs`, `tools/lab/fetch-zapret.sh` (если нужны файлы, которых нет в кэше), `package/install.sh:82` (проверка запуска не меняется)
- Create: `package/zapret/zapret-hosts-youtube.txt`, `package/zapret/zapret-hosts-discord.txt` (YouTube — из itdoginfo `Services/youtube.lst`, Discord — из Zapret-Manager `files/Zapret2/zapret_hosts_discord.txt`)

**Interfaces:**
- Consumes: `zapret-strategies.json` (Task 1) — списки `blobs`, `hostlists`.
- Produces: в `payload/engines/` все Lua zapret2 (`zapret-lib`, `zapret-antidpi`, `zapret-auto`), блобы каталога и hostlist-файлы; после распаковки они лежат рядом с `nfqws2` (`--chdir`).

- [ ] **Step 1:** `package.mjs` читает `controller/data/zapret-strategies.json` и копирует (plain) каждый файл `blobs`/`hostlists` из `.tools/lab/zapret2/zapret2-v1.0.7/files/fake/` или `package/zapret/`, падает с понятной ошибкой, если файла нет; `zapret-auto.lua.gz` добавляется к Lua. `NOTICE` кладётся в пакет.
- [ ] **Step 2:** Проверить: `node tools/package.mjs` проходит, `tar tf out/package/mi-trusttunnel-0.2.0.tar | grep -c 'payload/engines/'` растёт на число файлов каталога; рост пакета ≤ 300 КБ.
- [ ] **Step 3:** Commit `feat(package): Lua, блобы и списки хостов zapret2`.

### Task 3: Очередь NFQUEUE для TCP и UDP, первые пакеты и проверочный трафик

**Files:**
- Modify: `controller/src/plan.rs` (PolicySpec, build_plan, тесты), `controller/src/render.rs`, `controller/src/caps.rs` (NF_QUEUE + `NETFILTER_XT_MATCH_CONNBYTES`/`xt_connbytes`), `controller/src/admin/main.rs` (проверка `iptables -m connbytes`)

**Interfaces:**
- Consumes: `zapret::queue(cfg)` (Task 1).
- Produces: `PolicySpec.zapret_queue: Vec<QueueRule { proto: String /* tcp|udp */, ports: String }>` вместо `zapret_ports`; константы `ZAPRET_TEST_QNUM: u16 = 201`, `ZAPRET_TEST_SPORTS: &str = "49100:49199"`.
- Цепочка-лист Q (mangle): на каждый `QueueRule` строка `-p <proto> -m multiport --dports <ports> -m connbytes --connbytes 1:<N> --connbytes-dir original --connbytes-mode packets -j NFQUEUE --queue-num 200 --queue-bypass`, N = 25 для tcp и 5 для udp (как в Zapret-Manager).
- Цепочка P (mangle OUTPUT, только если Zapret используется и не guard-only): `-p tcp -m tcp --sport 49100:49199 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 201 --queue-bypass` и то же для udp — проверочный трафик подбора.

- [ ] **Step 1:** Тесты в `plan.rs`: `zapret_queue_tcp_udp_with_connbytes` (точные строки выше для `tcp 80,443` и `udp 443`), `test_queue_only_router_sports` (строка P присутствует, nfqws2-метка исключена), `guard_only_has_no_queues`. Проверить точный вид `-S` для `connbytes` на iptables лаборатории (`--connbytes 1:25 --connbytes-dir original --connbytes-mode packets`) и подогнать порядок слов в строках под него. FAIL.
- [ ] **Step 2:** Реализовать, обновить caps и admin (капабилити `iptables -m connbytes -h` содержит `--connbytes`).
- [ ] **Step 3:** `bash tools/cargo.sh test --locked` — PASS; лаборатория загрузки `run-lab-boot.sh` 25/25 (WSL; перед прогоном загрузить модули, в т. ч. `xt_connbytes`).
- [ ] **Step 4:** Commit `feat(plan): очередь Zapret для TCP/UDP по первым пакетам и проверочная очередь`.

### Task 4: Подбор стратегии одной кнопкой

**Files:**
- Create: `package/scripts/mitt-zapret-test.sh`, `controller/data/zapret-targets.txt`, `tools/lab/test-zapret-test.sh` (тест сценария с заглушками)
- Modify: `package/scripts/mitt-service.sh` (заявка `zapret-test.request`), `controller/src/manage.rs` (`POST /zapret/test`, `GET /zapret/test`), `controller/src/main.rs` (`mi-tt-ctl zapret-args <config.json> <strategy-id>` — печатает аргументы nfqws2 для проверки одной стратегии на очереди 201; `mi-tt-ctl zapret-set <config.json> <general|youtube> <id>` — атомарно меняет выбор через `store::update_config`)

**Interfaces:**
- Consumes: `zapret::catalog()`, `ZAPRET_TEST_QNUM`, `ZAPRET_TEST_SPORTS` (Tasks 1, 3).
- Produces: файл состояния `$STATE/zapret-test.json`: `{ "state": "idle|running|done|failed", "started": <unix>, "finished": <unix|null>, "progress": {"done": n, "total": m, "current": "<id>"}, "control": {"opened": n, "total": m}, "best": {"id": "...", "opened": n} | null, "applied": bool, "message": "<по-русски>" }`; API `GET /zapret/test` отдаёт его; `POST /zapret/test {"mode":"quick"}` пишет `$STATE/zapret-test.request` (409, если уже идёт).
- Цели (`zapret-targets.txt`): строки `required|optional <url>` — YouTube (сайт, `youtubei.googleapis.com`, видеоузел `redirector.googlevideo.com`), Discord (`discord.com`, `gateway.discord.gg`, `updates.discord.com`), набор CDN/хостингов (Hetzner, Cloudflare, CDN77, Akamai, AWS, Fastly, OVH — адреса из dpi-detector).
- Алгоритм сценария: контроль (без nfqws2 на 201) → каждая стратегия `v*` (nfqws2 `--qnum=201` с аргументами `mi-tt-ctl zapret-args`) → по 4 цели параллельно, `curl -s -o /dev/null --local-port 49100-49199 --max-time 8 -w '%{http_code} %{size_download}'`; открыта = код не `000`/`451` и curl завершился без ошибки; оборванный на 16–20 КБ ответ — закрыт. Победитель = максимум открытых `required`, затем `optional`; применяется (`zapret-set` + `apply.request`), только если больше контроля; затем повторная проверка текущей настройки на основной очереди (через клиентский путь не проверить — проверяется стратегией на 201 ещё раз); хуже прежнего — откат к прежнему id. Если после общего подбора YouTube-цели не открыты — тот же проход по `yv*` для поля `youtube`. Флаг прерывания: файл `$STATE/zapret-test.stop`; при прерывании ничего не применяется.

- [ ] **Step 1:** `tools/lab/test-zapret-test.sh`: запускает `mitt-zapret-test.sh` под BusyBox стока (qemu, как в лаборатории установщика) с `MITT_CURL`/`MITT_NFQWS`-заглушками: (а) контроль 2/10, `v3` 9/10, остальные 4/10 → `best.id = v3`, `applied = true`, в config `zapret.strategy = v3`; (б) все ≤ контроля → `applied = false`, config не изменён, `message` «Подходящей стратегии лучше, чем без Zapret, не нашлось»; (в) `zapret-test.stop` посреди → `state = failed`, config не изменён. FAIL.
- [ ] **Step 2:** Тесты Rust: `zapret_test_api` (POST пишет заявку, повторный POST при `running` → 409, GET отдаёт файл состояния или `idle`), `zapret_set_cli` (меняет только выбранное поле, неизвестный id — отказ).
- [ ] **Step 3:** Реализовать сценарий, CLI, API, обработку заявки в цикле службы (запуск в фоне, одна одновременно).
- [ ] **Step 4:** Все тесты — PASS.
- [ ] **Step 5:** Commit `feat(zapret): подбор стратегии на роутере одной кнопкой`.

### Task 5: Снимок списков сайтов itdoginfo в пакете

**Files:**
- Create: `tools/fetch-lists.sh`, `package/lists/catalog.json`, `package/lists/*.lst` (снимок)
- Modify: `tools/package.mjs` (копирует `package/lists/` в `payload/lists/`)

**Interfaces:**
- Produces: `catalog.json`: `{ "source": "itdoginfo/allow-domains", "commit": "<sha>", "date": "YYYY-MM-DD", "services": [ { "id": "youtube", "name": "YouTube", "group": "Сервисы|Категории|Россия", "domains": "Services/youtube.lst", "ipv4": "Subnets/IPv4/…lst" | null } ] }`; файлы лежат в `package/lists/` под тем же относительным путём.
- Набор: все `Services/*.lst` (человеческие названия: YouTube, Instagram и Facebook (`meta`), Discord, Telegram, ChatGPT и Google AI (`google_ai`), TikTok, X (`twitter`), Google Play, Google Meet, Roblox, HDRezka, Cloudflare, CloudFront, DigitalOcean, Hetzner, OVH), `Categories/*.lst` кроме `porn` (Аниме, Новости, Заблокированное (`block`), Геоблок, Ходячие и др.), `Russia/inside-raw.lst` («Заблокированное в России»); `ipv4` — соответствующий `Subnets/IPv4/<имя>.lst` (регистр как в репозитории, предпочесть нижний).

- [ ] **Step 1:** `fetch-lists.sh <commit>` скачивает файлы, проверяет каждый через `mi-tt-ctl category-check domain|ip <file>` (новая подкоманда в Task 6 — до неё временно через Rust-тест), пишет `catalog.json`.
- [ ] **Step 2:** Запустить на текущем `main` itdoginfo, закоммитить снимок; размер `package/lists` ≤ 300 КБ.
- [ ] **Step 3:** Commit `feat(lists): снимок списков itdoginfo`.

### Task 6: Синхронизация и ежедневное обновление списков

**Files:**
- Create: `package/scripts/mitt-lists.sh`
- Modify: `package/scripts/mitt-service.sh`, `package/scripts/mitt-lib.sh` (экспорт пути каталога в CGI: `MI_TT_LISTS_DIR`), `controller/src/main.rs` (`category-check <domain|ip> <file>`), `controller/src/manage.rs` (`GET /lists`, `POST /lists/update`), `controller/src/api.rs` при необходимости
- Test: `tools/lab/test-lists.sh`, Rust-тест `lists_api`

**Interfaces:**
- Consumes: `catalog.json` (Task 5), `render::parse_category_list`.
- Produces:
  - `mitt-lists.sh sync`: для каждой записи каталога — `$ETC/categories/svc-<id>.list` (домены) и `svc-<id>-ip.list` (IPv4) из `$DATA/lists/<путь>` (обновлённый), иначе из `$REL/payload/lists/<путь>`; пишет только при изменении (cmp).
  - `mitt-lists.sh update`: `curl -fsS --max-time 30` каждого файла во временный, `mi-tt-ctl category-check`, затем атомарно в `$DATA/lists/`; любая ошибка файла — прежний файл остаётся; пишет `$STATE/lists.json { "snapshot": "<date>", "updated": <unix|null>, "checked": <unix>, "ok": bool, "errors": ["<файл>: <причина>"] }`; если что-то изменилось — `sync` и `apply.request`.
  - Служба: `sync` перед каждым `render`; `update` — в фоне раз в 24 часа после старта (метка `$DATA/lists/.checked`) и по заявке `$STATE/lists-update.request`.
  - API `GET /lists`: `{ ok, catalog: <catalog.json>, status: <lists.json|null> }`; `POST /lists/update` → 202 и заявка.

- [ ] **Step 1:** `tools/lab/test-lists.sh` (BusyBox стока под qemu, `MITT_CURL`-заглушка): сначала sync из пакета создаёт `svc-youtube.list`; update с корректным ответом заменяет; ответ-HTML (`<html>`) и пустой файл — отказ, прежний файл на месте, `ok=false`, ошибка с именем файла; без сети — `ok=false`, списки из пакета работают. FAIL.
- [ ] **Step 2:** Rust: `category_check_cli` (корректный → 0, HTML → 1), `lists_api` (GET с `MI_TT_LISTS_DIR` на фикстуру, POST пишет заявку).
- [ ] **Step 3:** Реализовать. **Step 4:** тесты и `run-lab-boot.sh` — PASS. **Step 5:** Commit `feat(lists): синхронизация и ежедневное обновление списков`.

### Task 7: API для простой панели: сеть роутера и замена конфигурации целиком

**Files:**
- Modify: `controller/src/manage.rs` (`GET /router`, `POST /config`), `package/scripts/mitt-lib.sh` (в CGI: `MI_TT_UCI_NETWORK=/etc/config/network`)
- Test: `controller/tests/simple_api.rs`

**Interfaces:**
- Produces:
  - `GET /router` → `{ ok, lan: { bridge: "br-lan", subnet: "192.168.31.0/24", address: "192.168.31.1" } }` из uci-файла `network` (секция `config interface 'lan'`: `ipaddr`, `netmask`, `device`/`ifname`; мост по умолчанию `br-lan`).
  - `POST /config { base_revision, config }` → полная проверка (`validate_config`) и атомарная замена через `store::update_config`; при успехе сразу пишет `apply.request` (как `/apply-request`); ответ как у сохранения правила (`revision`, `config`). 409 при чужой ревизии, 422 при ошибках проверки.

- [ ] **Step 1:** Тесты: `router_reads_uci_lan` (фикстура uci с `option ipaddr '192.168.31.1'`, `option netmask '255.255.255.0'` → subnet `192.168.31.0/24`), `config_replace_validates_and_queues_apply`, `config_replace_revision_conflict`, `config_replace_requires_session_and_csrf` (через CGI как в `stage11.rs`). FAIL.
- [ ] **Step 2:** Реализовать. **Step 3:** PASS. **Step 4:** Commit `feat(api): сеть LAN роутера и замена конфигурации целиком`.

### Task 8: Модель простых настроек в панели

**Files:**
- Create: `panel/src/simple.ts`, `panel/src/simple.test.ts`, `panel/src/serverConfig.ts`, `panel/src/serverConfig.test.ts`
- Modify: `panel/src/api.ts` (типы и вызовы `/router`, `/config`, `/lists`, `/lists/update`, `/zapret/test`)

**Interfaces:**
- Consumes: API Tasks 4, 6, 7.
- Produces:
  - `type Simple = { enabled: boolean; mode: 'selected' | 'all'; services: string[]; customDomains: string[]; exceptions: string[]; rest: 'direct' | 'zapret'; devices: 'all' | string[] /* MAC */ }`.
  - `fromConfig(cfg: Config): { simple: Simple; canonical: true } | { canonical: false; reason: string }`.
  - `toConfig(base: Config, s: Simple, lan: Lan, catalog: ListCatalog, known: KnownDevice[]): Config` — канонический вид: сеть `home` (мост, подсеть из `lan`, `ssid` — «Домашняя сеть»), категории `svc-<id>`/`svc-<id>-ip`, группы `vpn-sites` и `vpn-except`, устройства `dev-<mac без двоеточий>`, правила `vpn-<устройство|lan>` и `except-<…>` по спецификации, `default_action`; профиль, `dns`, `zapret` из `base` не трогаются.
  - `parseClientToml(text: string): { endpoint: Partial<Endpoint>; password?: string } | { error: string }` — поля `hostname`, `addresses[0]`, `username`, `password`, `custom_sni`, `upstream_protocol`, `anti_dpi`, `certificate` формата `client.toml`.

- [ ] **Step 1:** Тесты: `round_trip_selected_all_devices`, `round_trip_all_mode_with_exceptions`, `selected_devices_rules_per_device`, `disable_keeps_selection` (enabled=false → все правила `enabled: false`, `default_action` direct, `fromConfig` возвращает прежние сервисы и устройства), `zapret_rest` (`rest: 'zapret'` → `default_action: direct_zapret` в режиме selected), `non_canonical_detected` (фикстура `fixtures/config.valid.json` → `canonical: false`), `parse_client_toml_export` (пример из `trusttunnel_endpoint … --format toml`: адрес `203.0.113.10:443`, hostname, сертификат PEM в `'''`), `parse_client_toml_garbage` → `error`. FAIL.
- [ ] **Step 2:** Реализовать. **Step 3:** `npm test` — PASS. **Step 4:** Commit `feat(panel): модель простых настроек и разбор конфига сервера`.

### Task 9: Экраны простой панели

**Files:**
- Create: `panel/src/views/StatusView.vue`, `SitesView.vue`, `DevicesView.vue`, `ServerView.vue`, `MoreView.vue`
- Modify: `panel/src/App.vue` (оболочка: строка состояния, меню из пяти пунктов, на телефоне — выпадающий список), `panel/src/style.css`, `panel/src/theme.ts`
- Delete: `panel/src/RuleForm.vue`, `PreviewView.vue`, `ManageView.vue`, `RouteBadge.vue`, `RouteLine.vue`, `route.ts`, `route.test.ts`, неиспользуемые части `draft.ts`/`manage.ts` и их тестов

**Interfaces:**
- Consumes: `simple.ts`, `serverConfig.ts`, API (Task 8).
- Экраны — по спецификации, раздел «Экраны» и «Zapret». Без конфигурации канонического вида Сайты/Устройства показывают «Настройки изменены вручную» и кнопку «Привести к простому виду» (подтверждение в диалоге). Без профиля — Сервер первым экраном после входа. Подбор: кнопка «Подобрать», пока `running` — прогресс «Проверяю v4: 5 из 11», опрос `GET /zapret/test` раз в 2 с; итог «Открылось 47 из 54, без Zapret — 12» и «Применена стратегия v4» / сообщение.
- Сохранение любого экрана: `POST /config` → тост «Сохранено, применяю на роутере».

- [ ] **Step 1:** Реализовать экраны; удалить старые представления; `npm run typecheck`, `npm test`, `npm run build` — PASS; `node --test stand/stand.test.mjs` — PASS (обновить проверки разметки, если есть).
- [ ] **Step 2:** Скриншоты стенда (светлая и тёмная тема, 1280 и 390 px) в `out/panel-simple/`, самопроверка: на каждом экране не больше одного основного действия, нет технических терминов (мост, порт, MAC крупно, id).
- [ ] **Step 3:** Commit `feat(panel): простой интерфейс на пяти экранах`.

### Task 10: Лаборатория, пакет и документация

**Files:**
- Modify: `tools/lab/lab-boot-inner.sh`, `tools/lab/check-boot.py` (nfqws2 x86 из кэша zapret2 запускается с отрендеренными аргументами `--dry-run`; служба запускает nfqws2 с профилями; списки синхронизированы в `etc/categories`), `docs/guide.md`, `README.md`, `ARCHITECTURE.md`

- [ ] **Step 1:** Добавить проверки в лабораторию; `run-lab-install.sh` и `run-lab-boot.sh` — ИТОГ: ПРОЙДЕНО; `tools/check-all.sh` — успешно.
- [ ] **Step 2:** Руководство: экраны панели, подбор Zapret, обновление списков; удалить описание старых экранов правил.
- [ ] **Step 3:** Commit `docs: простая панель, списки и подбор Zapret`.
