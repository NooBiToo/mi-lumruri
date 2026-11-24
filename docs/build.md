# Сборка и проверка

## Сборка на GitHub

Workflow **BE7000 ARM64** (`.github/workflows/build.yml`) запускается при отправке изменений в `main` или кнопкой **Run workflow**. Работает только для `main`: для других веток задание пропускается. Шаги на `ubuntu-24.04` с Node.js 24:

1. Проверка сценариев роутера (`package/install.sh`, `package/scripts/*.sh`, `tools/device/*.sh`): `sh -n`, `tools/lint-sh.py` — конструкции, которых нет в штатном BusyBox ash 1.25.1 или которые ведут себя в нём иначе (например, дробный `sleep`, `[[ … ]]`, `echo -e`), и `shellcheck -s sh -S error`. Строку можно разрешить комментарием `# lint-sh: allow <причина>`.
2. Тесты и сборка контроллера: `cargo test --locked`, `cargo build --locked --release --target aarch64-unknown-linux-musl` (Rust 1.100.0 из `controller/rust-toolchain.toml`).
3. Тесты и сборка панели: `npm ci`, `npm test`, `npm run build`; затем сквозные тесты `npx playwright test` — собранная панель на HTTPS-стенде с настоящим контроллером (вход, настройки, языки, резервная копия).
4. Загрузка zapret2 v1.0.7: `tools/lab/fetch-zapret.sh`.
5. Пакет с подписью: `node tools/package.mjs --version ci-<первые 12 символов коммита> --key <ключ>`. Клиент TrustTunnel v1.3.0 для aarch64 скрипт скачивает сам.
6. Проверка: `tools/test-install.py`, `mi-tt-admin release verify` для собранного пакета, `SHA256SUMS` в сводке запуска.

В успешном запуске в **Artifacts** лежит `mi-lumruri-be7000`. Внутри ZIP — установочный TAR `mi-lumruri-ci-<коммит>.tar`, `SHA256SUMS` и `install.py`. На Linux командой `sha256sum -c SHA256SUMS` можно проверить архив. В PowerShell выполните `Get-FileHash *.tar` и сравните результат с SHA-256 в сводке запуска. `install.py` берёт `mi-lumruri-ci-*.tar` из своего каталога или файл из `--package`, а если пакета рядом нет, скачивает последнюю успешную сборку `main` через `gh`. TAR из CI выкладывается и в GitHub Releases, например релиз v0.3.3 — `mi-lumruri-ci-6a03e250723f.tar`. `tools/device/install-from-github.sh` ставит релиз, адрес которого записан в нём. Обновление из панели (с 0.4.0) берёт последний релиз через API GitHub и ищет в нём `mi-lumruri-*.tar` и `SHA256SUMS`, поэтому оба файла должны лежать в релизе.

Для подписи используется постоянный секрет Actions `BE7000_SIGNING_KEY` (закрытый ключ Ed25519 в формате PEM). При его отсутствии сборка останавливается.

## Ключ подписи

Роутер закрепляет открытый ключ при первой установке (`/data/mi-lumruri/keys/release.pub`). Дальше установщик принимает только пакеты, подписанные тем же ключом. У сборок CI ключ из секрета `BE7000_SIGNING_KEY`, у локальных — `.tools/keys/release-ed25519.pem`, который `tools/package.mjs` создаёт при первом запуске. Это разные ключи: роутер, установленный из CI, не примет локальную сборку, и наоборот. Отпечаток ключа (`key_fingerprint`) печатают сборщик и установщик. Если собираете сами, сохраните закрытый ключ из `.tools/keys/` в защищённом месте: без него установленный роутер обновится только со сменой ключа. Сменить ключ можно явно: `install.py --trust-key <отпечаток>` или `sh install.sh install --trust-key=<отпечаток>` (16 знаков hex). Отпечаток закреплённого ключа показывает `mi-tt-admin release key-fingerprint /data/mi-lumruri/keys/release.pub`. Обновление из панели переходит только на ключ релизов GitHub `e4a271890e5643ab`.

## Локальная сборка

Собирайте на компьютере. Для команд ниже подойдёт Ubuntu x86_64 с Bash, Node.js 22.12 или новее, npm, Python 3.12+, curl, компилятором для хоста и утилитами apt. Понадобится интернет для первой загрузки зависимостей. Команды выполняются из корня проекта.

`tools/setup-tools.sh` ставит в `.tools/` проекта Rust 1.100.0 с целью `aarch64-unknown-linux-musl` (линковка rust-lld, внешний C-тулчейн не нужен), распаковывает qemu-aarch64 из пакета `qemu-user` и скачивает сервер TrustTunnel для лабораторий. PATH и профиль пользователя не меняются, `tools/cargo.sh` запускает cargo из этого тулчейна.

## Установочный пакет

```sh
tools/setup-tools.sh
tools/lab/fetch-zapret.sh
tools/cargo.sh build --release --locked --target aarch64-unknown-linux-musl
(cd panel && npm ci && npm run build)
node tools/package.mjs
```

`cargo build` собирает программы `mi-tt-ctl`, `mi-tt-admin` и `mi-tt-dns` для разработки и тестов, а для пакета — `mi-tt`: те же три программы в одной, выбор по имени ссылки. Клиент TrustTunnel для ARM64 (v1.3.0, архив закреплён по SHA-256) `tools/package.mjs` скачивает сам в `.tools/lab/dl`. По умолчанию пакет получает версию 0.13.1, другую задаёт `--version`, другой ключ — `--key`. В `out/package/` появляются `mi-lumruri-<версия>.tar`, совместимая копия `mi-trusttunnel-<версия>.tar` (для обновления из панели 0.4), `SHA256SUMS` и отчёт `report-<версия>.json` с размерами файлов и SHA-256. Сборка воспроизводима: XZ и tar без времени и владельцев, подпись Ed25519 детерминирована. На роутер переносится **TAR**. [Инструкция для роутера](guide.md)

## Тесты

```sh
tools/cargo.sh test --locked
(cd panel && npm ci && npm test && npm run build)
(cd panel && npx playwright install chromium && npx playwright test)   # сквозные: нужны controller/target/release/mi-tt-ctl и mi-tt-admin (или MITT_BIN_DIR)
python3 -B tools/test-install.py
```

Полный прогон на подготовленном стенде запускается командой `bash tools/check-all.sh`. Он включает сканер секретов, сравнение ответов `mi-tt-ctl` на x86_64 и ARM64 под qemu, HTTPS-стенд, сборку ARM64, проверку пакета и сетевые лаборатории. Проверяйте также сообщения о пропусках: без QEMU или сервера TrustTunnel (`tools/lab/fetch.sh`) часть проверок пропускается.

Лаборатории можно запустить и по отдельности в Linux (подходит WSL2) после сборки пакета: `tools/lab/run-lab-install.sh` — установка, обновление, откат, внешнее хранилище и удаление на штатном BusyBox под qemu; `tools/lab/run-lab-boot.sh` — автозагрузка, служба и правила с настоящим сервером `trusttunnel_endpoint` v1.1.0, официальным клиентом v1.3.0 для x86_64, dnsmasq с ipset и штатными BusyBox, nginx, uhttpd и curl прошивки под qemu; Zapret с nfqws2 x86_64 на настоящем ядре, обновление списков и подбор стратегии по кнопкам панели. Результаты этих двух лабораторий сохраняются в `out/lab/`. Отдельные сценарии службы проверяются на штатном BusyBox ash под qemu без сети: `tools/lab/test-update.sh` — обновление из релизов GitHub (заглушки curl и `install.sh`), `tools/lab/test-watch.sh` — сторож туннеля, `tools/lab/test-failover.sh` — переключение на запасной сервер и возврат, `tools/lab/test-sub.sh` — подписка TrustTunnel; так же устроены `test-lists.sh`, `test-zapret-test.sh`, `test-notify.sh` (уведомления в Telegram), `test-stats.sh` (статистика трафика) и `test-speed.sh` (замер скорости и выбор сервера по задержке), `test-devices.sh` (таблица производителей прошивки и поиск имён в сети mDNS/SSDP в отдельном сетевом пространстве). Решения сторожа, запасного сервера и выбора по задержке принимает `mi-tt-ctl tunnel` (controller/src/tunnel.rs, юнит-тесты), сценарий службы делает только пробы и действия. `test-update.sh`, `test-sub.sh`, `test-lists.sh`, `test-watch.sh`, `test-failover.sh`, `test-notify.sh`, `test-stats.sh` и `test-speed.sh` берут собранные программы контроллера для ARM64, поэтому сначала выполните `cargo build` для `aarch64-unknown-linux-musl`. История этапов описана в [журнале](../VERTICAL-SLICE.md).

| Каталог | Содержимое |
| --- | --- |
| `controller/` | Rust-контроллер: `mi-tt-ctl`, `mi-tt-admin`, `mi-tt-dns` и общая программа `mi-tt` для пакета; каталог стратегий Zapret в `controller/data/` |
| `panel/`, `stand/` | Веб-панель и локальный HTTPS-стенд |
| `package/` | Установщик, сценарии службы, начальные настройки, снимок списков сайтов, файлы Zapret |
| `tools/` | Сборка пакета, тулчейн, сканер секретов, сценарии для устройства (`tools/device/`) |
| `tools/lab/` | Изолированные сетевые сценарии |
| `fixtures/` | Настройки и данные для тестов |

[К обзору проекта](../README.md)
