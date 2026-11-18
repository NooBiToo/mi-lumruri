#!/usr/bin/env bash
# Полная локальная проверка среза. Ничего не отправляет на роутер и не меняет хост.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
step() { printf '\n== %s\n' "$*"; }

step "1. контроллер: модульные и сквозные тесты этапов 1–4 (x86_64 хоста)"
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

step "5. стенд: HTTP → CGI → контроллер, запись с проверкой Origin/Host, перезапуск"
node --test stand/stand.test.mjs 2>&1 | grep -E '^ℹ (tests|pass|fail)|✖'

step "6. комплект ARM64 и бюджет flash"
node tools/bundle.mjs

step "7. изолированная лаборатория: метки по MAC/порту моста (tc), mi-tt-admin, TrustTunnel, Mihomo, смена адресов без apply (Linux/WSL)"
if [ -f .tools/lab/bin/mihomo ] && [ -f .tools/lab/bin/trusttunnel_endpoint ]; then
  if command -v unshare >/dev/null && [ "$(uname -s)" = Linux ]; then
    tools/lab/run-lab.sh | grep -E "ИТОГ|артефакты|НЕТ"
  elif command -v wsl >/dev/null; then
    WROOT="/mnt/$(echo "${ROOT:1:1}" | tr 'A-Z' 'a-z')${ROOT:2}"
    MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$WROOT/tools/lab/run-lab.sh" | grep -E "ИТОГ|артефакты|НЕТ"
  else
    echo "ПРОПУЩЕНО: нет Linux/WSL"
  fi
else
  echo "ПРОПУЩЕНО: нет движков (tools/lab/fetch.sh)"
fi
