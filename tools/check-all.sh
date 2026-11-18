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

step "6. комплект ARM64 и бюджет flash; подписанный установочный пакет (этап 12)"
node tools/bundle.mjs
node tools/package.mjs
# архивы: закрытых ключей (PEM) быть не должно; прочие совпадения — в отчёт (без значений)
python -I -X utf8 tools/secret-scan.py archive out/bundle/mi-trusttunnel-0.1.0-stage12.tar out/package/mi-trusttunnel-0.1.0-stage12.tar | tee out/secret-scan-archives.txt | tail -1
! grep -q private_key_pem out/secret-scan-archives.txt
tools/lab/install-packages.sh >/dev/null   # v1, v2, v5, подменённый, чужой ключ — для лаборатории установщика

step "7. изолированная лаборатория: механизмы tc (этап 4) и netfilter (сток), Hysteria2 по QUIC (этап 7), Zapret (этап 9) и категории (этап 11), VLESS и AmneziaWG одновременно (этап 8), DNS/ODoH/реклама (этап 10), установка/обновление/откат и автозагрузка без WAN (этап 12), возможности, preflight ARM64 BusyBox, TrustTunnel, смена адресов (Linux/WSL)"
if [ -f .tools/lab/bin/mihomo ] && [ -f .tools/lab/bin/trusttunnel_endpoint ]; then
  if command -v unshare >/dev/null && [ "$(uname -s)" = Linux ]; then
    for m in tc netfilter; do MARKER=$m tools/lab/run-lab.sh | grep -E "ИТОГ|артефакты|НЕТ"; done
    tools/lab/run-lab-hy2.sh | grep -E "ИТОГ|артефакты|НЕТ|проверок"
    for v in tls reality; do VLESS_MODE=$v tools/lab/run-lab-multi.sh | grep -E "ИТОГ|артефакты|НЕТ|проверок"; done
    tools/lab/run-lab-dns.sh | grep -E "ИТОГ|артефакты|НЕТ|проверок"
    tools/lab/run-lab-install.sh | grep -E "ИТОГ|артефакты|НЕТ|проверок"
    tools/lab/run-lab-boot.sh | grep -E "ИТОГ|артефакты|НЕТ|проверок"
  elif command -v wsl >/dev/null; then
    WROOT="/mnt/$(echo "${ROOT:1:1}" | tr 'A-Z' 'a-z')${ROOT:2}"
    for m in tc netfilter; do MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- env MARKER=$m bash "$WROOT/tools/lab/run-lab.sh" | grep -E "ИТОГ|артефакты|НЕТ"; done
    MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$WROOT/tools/lab/run-lab-hy2.sh" | grep -E "ИТОГ|артефакты|НЕТ|проверок"
    for v in tls reality; do MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- env VLESS_MODE=$v bash "$WROOT/tools/lab/run-lab-multi.sh" | grep -E "ИТОГ|артефакты|НЕТ|проверок"; done
    MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$WROOT/tools/lab/run-lab-dns.sh" | grep -E "ИТОГ|артефакты|НЕТ|проверок"
    MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$WROOT/tools/lab/run-lab-install.sh" | grep -E "ИТОГ|артефакты|НЕТ|проверок"
    MSYS_NO_PATHCONV=1 wsl -d Ubuntu -- bash "$WROOT/tools/lab/run-lab-boot.sh" | grep -E "ИТОГ|артефакты|НЕТ|проверок"
  else
    echo "ПРОПУЩЕНО: нет Linux/WSL"
  fi
else
  echo "ПРОПУЩЕНО: нет движков (tools/lab/fetch.sh)"
fi
