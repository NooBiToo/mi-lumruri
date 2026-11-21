#!/usr/bin/env bash
# Полная локальная проверка среза. Ничего не отправляет на роутер и не меняет хост.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
step() { printf '\n== %s\n' "$*"; }

step "0. секреты: тест сканера и сканирование рабочего дерева (закрытые ключи, литералы паролей и ключей; значения не печатаются)"
python -I -X utf8 tools/secret-scan.test.py | tail -1
python -I -X utf8 tools/secret-scan.py tree

step "1. контроллер: модульные и сквозные тесты этапов 1–12 (x86_64 хоста)"
tools/cargo.sh test --locked -q 2>&1 | grep -E '^test result|FAILED|panicked' || true
tools/cargo.sh test --locked -q >/dev/null 2>&1

step "2. контроллер: сборки release для хоста (стенд) и ARM64 musl (комплект)"
tools/cargo.sh build --release --locked -q
tools/cargo.sh build --release --locked -q --target aarch64-unknown-linux-musl
file controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl

step "3. одинаковые ответы на хосте и на ARM64 под qemu-user (если есть WSL и .tools/qemu)"
rm -rf out/cases
HOSTBIN=controller/target/release/mi-tt-ctl; [ -f "$HOSTBIN.exe" ] && HOSTBIN="$HOSTBIN.exe"
tools/run-cases.sh out/cases/native "$HOSTBIN" >/dev/null
QEMU=.tools/qemu/root/usr/bin/qemu-aarch64
if [ -f "$QEMU" ] && command -v wsl >/dev/null; then
  WROOT="/mnt/$(echo "${ROOT:1:1}" | tr 'A-Z' 'a-z')${ROOT:2}"
  MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$WROOT/tools/run-cases.sh" "$WROOT/out/cases/arm64-qemu" \
    "$WROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl" "$WROOT/$QEMU"
  diff -r out/cases/native out/cases/arm64-qemu && echo "ответы x86_64 и ARM64 совпадают побайтно ($(ls out/cases/native | wc -l) случаев)"
elif [ -f "$QEMU" ]; then
  tools/run-cases.sh out/cases/arm64-qemu controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl "$QEMU"
  diff -r out/cases/native out/cases/arm64-qemu && echo "ответы x86_64 и ARM64 совпадают"
else
  echo "ПРОПУЩЕНО: qemu-aarch64 не найден, ARM64-бинарник не запускался"
fi

step "4. панель: тесты, проверка типов, сборка"
(cd panel && npm ci --no-audit --no-fund --loglevel=error && npm test --silent 2>&1 | grep -E 'Tests|FAIL' && npm run build --silent 2>&1 | grep -E 'dist/|error')

step "5. стенд: HTTPS → CGI → контроллер, вход паролем и TOTP, запись с проверкой Origin/Host/CSRF, перезапуск"
node --test stand/stand.test.mjs 2>&1 | grep -E '^ℹ (tests|pass|fail)|✖'

step "6. подписанный установочный пакет ARM64 (контроллер, панель, trusttunnel_client, nfqws2) и бюджет flash"
# release-сборка не должна содержать отладочную подмену времени для тестов входа
# («! grep» под set -e не останавливает сценарий, поэтому явные if)
if grep -q MI_TT_TEST_NOW controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl controller/target/aarch64-unknown-linux-musl/release/mi-tt-admin; then
  echo "ОШИБКА: в release найдена отладочная подмена времени MI_TT_TEST_NOW"; exit 1
fi
echo "отладочная подмена времени (MI_TT_TEST_NOW) в release: отсутствует"
node tools/package.mjs >out/package-build.txt
# версия пакета по умолчанию — из tools/package.mjs
VER=$(sed -n "s/.*: '\([0-9][0-9.]*\)'$/\1/p" tools/package.mjs | head -n 1)
head -3 out/package-build.txt
VER="$VER" node -e 'const r=JSON.parse(require("fs").readFileSync(`out/package/report-${process.env.VER}.json`,"utf8")); if (r.headroom < 0) { console.error("ОШИБКА: пакет не помещается в бюджет flash"); process.exit(1) }'
# архив: закрытых ключей (PEM) быть не должно; прочие совпадения — в отчёт (без значений)
python -I -X utf8 tools/secret-scan.py archive out/package/mi-lumruri-$VER.tar | tee out/secret-scan-archives.txt | tail -1
if grep -q private_key_pem out/secret-scan-archives.txt; then echo "ОШИБКА: закрытый ключ в архиве пакета"; exit 1; fi
tools/lab/install-packages.sh >/dev/null   # v1, v2, v5, подменённый, чужой ключ — для лаборатории установщика
node tools/package.mjs >/dev/null           # вернуть в out/package пакет текущей версии (install-packages.sh собирает 0.1.0-stage12)

step "7. изолированные лаборатории (Linux/WSL): установка/обновление/откат/внешнее хранилище и автозагрузка без WAN с настоящими TrustTunnel, dnsmasq и ipset"
if [ -f .tools/lab/bin/trusttunnel_endpoint ]; then
  if command -v unshare >/dev/null && [ "$(uname -s)" = Linux ]; then
    tools/lab/run-lab-install.sh | grep -E "ИТОГ|артефакты|НЕТ|проверок"
    tools/lab/run-lab-boot.sh | grep -E "ИТОГ|артефакты|НЕТ|проверок"
  elif command -v wsl >/dev/null; then
    WROOT="/mnt/$(echo "${ROOT:1:1}" | tr 'A-Z' 'a-z')${ROOT:2}"
    MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$WROOT/tools/lab/run-lab-install.sh" | grep -E "ИТОГ|артефакты|НЕТ|проверок"
    MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$WROOT/tools/lab/run-lab-boot.sh" | grep -E "ИТОГ|артефакты|НЕТ|проверок"
  else
    echo "ПРОПУЩЕНО: нет Linux/WSL"
  fi
else
  echo "ПРОПУЩЕНО: нет сервера TrustTunnel (tools/lab/fetch.sh)"
fi
