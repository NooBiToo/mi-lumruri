# Сборка и проверка

## Сборка на GitHub

Workflow **BE7000 ARM64** (`.github/workflows/build.yml`) запускается при отправке изменений в `main` или кнопкой **Run workflow**. Работает только для `main`: для других веток задание пропускается. Шаги на `ubuntu-24.04` с Node.js 24:

1. Тесты и сборка контроллера: `cargo test --locked`, `cargo build --locked --release --target aarch64-unknown-linux-musl` (Rust 1.100.0 из `controller/rust-toolchain.toml`).
2. Тесты и сборка панели: `npm ci`, `npm test`, `npm run build`.
3. Загрузка zapret2 v1.0.7: `tools/lab/fetch-zapret.sh`.
4. Пакет с подписью: `node tools/package.mjs --version ci-<первые 12 символов коммита> --key <ключ>`. Клиент TrustTunnel v1.3.0 для aarch64 скрипт скачивает сам.
5. Проверка: `tools/test-install.py`, `mi-tt-admin release verify` для собранного пакета, `SHA256SUMS` в сводке запуска.

В успешном запуске в **Artifacts** лежит `mi-trusttunnel-be7000`. Внутри ZIP — установочный TAR `mi-trusttunnel-ci-<коммит>.tar`, `SHA256SUMS` и `install.py`. На Linux командой `sha256sum -c SHA256SUMS` можно проверить архив. В PowerShell выполните `Get-FileHash *.tar` и сравните результат с SHA-256 в сводке запуска. `install.py` берёт `mi-trusttunnel-ci-*.tar` из своего каталога или файл из `--package`, а если пакета рядом нет, скачивает последнюю успешную сборку `main` через `gh`. TAR из CI выкладывается и в GitHub Releases, например релиз v0.3.3 — `mi-trusttunnel-ci-6a03e250723f.tar` (его ставит `tools/device/install-from-github.sh`).

Для подписи используется постоянный секрет Actions `BE7000_SIGNING_KEY` (закрытый ключ Ed25519 в формате PEM). При его отсутствии сборка останавливается.

## Ключ подписи

Роутер закрепляет открытый ключ при первой установке (`/data/mi-trusttunnel/keys/release.pub`). Дальше установщик принимает только пакеты, подписанные тем же ключом. У сборок CI ключ из секрета `BE7000_SIGNING_KEY`, у локальных — `.tools/keys/release-ed25519.pem`, который `tools/package.mjs` создаёт при первом запуске. Это разные ключи: роутер, установленный из CI, не примет локальную сборку, и наоборот. Отпечаток ключа (`key_fingerprint`) печатают сборщик и установщик. Если собираете сами, сохраните закрытый ключ из `.tools/keys/` в защищённом месте: без него установленный роутер не обновить.

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

`cargo build` собирает программы `mi-tt-ctl`, `mi-tt-admin` и `mi-tt-dns` для разработки и тестов, а для пакета — `mi-tt`: те же три программы в одной, выбор по имени ссылки. Клиент TrustTunnel для ARM64 (v1.3.0, архив закреплён по SHA-256) `tools/package.mjs` скачивает сам в `.tools/lab/dl`. По умолчанию пакет получает версию 0.3.3, другую задаёт `--version`, другой ключ — `--key`. В `out/package/` появляются `mi-trusttunnel-<версия>.tar`, `SHA256SUMS` и отчёт `report-<версия>.json` с размерами файлов и SHA-256. Сборка воспроизводима: XZ и tar без времени и владельцев, подпись Ed25519 детерминирована. На роутер переносится **TAR**. [Инструкция для роутера](guide.md)

## Тесты

```sh
tools/cargo.sh test --locked
(cd panel && npm ci && npm test && npm run build)
python3 -B tools/test-install.py
```

Полный прогон на подготовленном стенде запускается командой `bash tools/check-all.sh`. Он включает сканер секретов, сравнение ответов `mi-tt-ctl` на x86_64 и ARM64 под qemu, HTTPS-стенд, сборку ARM64, проверку пакета и сетевые лаборатории. Проверяйте также сообщения о пропусках: без QEMU или сервера TrustTunnel (`tools/lab/fetch.sh`) часть проверок пропускается.

Лаборатории можно запустить и по отдельности в Linux (подходит WSL2) после сборки пакета: `tools/lab/run-lab-install.sh` — установка, обновление, откат, внешнее хранилище и удаление на штатном BusyBox под qemu; `tools/lab/run-lab-boot.sh` — автозагрузка, служба и правила с настоящим сервером `trusttunnel_endpoint` v1.1.0, официальным клиентом v1.3.0 для x86_64, dnsmasq с ipset и штатными BusyBox, nginx, uhttpd и curl прошивки под qemu; Zapret с nfqws2 x86_64 на настоящем ядре, обновление списков и подбор стратегии по кнопкам панели. Результаты сохраняются в `out/lab/`. История этапов описана в [журнале](../VERTICAL-SLICE.md).

| Каталог | Содержимое |
| --- | --- |
| `controller/` | Rust-контроллер: `mi-tt-ctl`, `mi-tt-admin`, `mi-tt-dns`; каталог стратегий Zapret в `controller/data/` |
| `panel/`, `stand/` | Веб-панель и локальный HTTPS-стенд |
| `package/` | Установщик, сценарии службы, начальные настройки, снимок списков сайтов, файлы Zapret |
| `tools/` | Сборка пакета, тулчейн, сканер секретов, сценарии для устройства (`tools/device/`) |
| `tools/lab/` | Изолированные сетевые сценарии |
| `fixtures/` | Настройки и данные для тестов |

[К обзору проекта](../README.md)
