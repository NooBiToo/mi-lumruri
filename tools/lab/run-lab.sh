#!/usr/bin/env bash
# Одноразовая изолированная лаборатория (Linux/WSL, без root): unshare создаёт user+net+mount+pid namespace,
# внутри поднимаются отдельные сетевые пространства клиентов, роутера, «интернета» и сервера TrustTunnel.
# Хостовая сеть, маршруты и firewall не меняются; по завершении всё уничтожается ядром.
# Использование: tools/lab/run-lab.sh [--config <config.json, сохранённый панелью>] [--native]
#   по умолчанию контроллер — ARM64-бинарник комплекта под qemu-aarch64 (.tools/qemu), --native — x86_64 musl, если собран.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_IN=""; MODE=arm64
while [ $# -gt 0 ]; do case "$1" in --config) CONFIG_IN="$(realpath "$2")"; shift 2;; --native) MODE=native; shift;; *) echo "неизвестный аргумент $1"; exit 2;; esac; done
for c in unshare nsenter ip curl python3 ping; do command -v "$c" >/dev/null || { echo "нужен $c"; exit 2; }; done
B="$ROOT/.tools/lab/bin"
[ -x "$B/mihomo" ] && [ -x "$B/trusttunnel_endpoint" ] || { echo "нет движков: запустите tools/lab/fetch.sh"; exit 2; }
if [ "$MODE" = arm64 ]; then
  CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"; RUNCTL="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
  ADM="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-admin"
  [ -f "$RUNCTL" ] || { echo "нет qemu-aarch64: tools/setup-tools.sh"; exit 2; }
else
  CTL="$ROOT/controller/target/x86_64-unknown-linux-musl/release/mi-tt-ctl"; RUNCTL=""
  ADM="$ROOT/controller/target/x86_64-unknown-linux-musl/release/mi-tt-admin"
fi
[ -f "$CTL" ] && [ -f "$ADM" ] || { echo "нет контроллера $CTL / $ADM"; exit 2; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/out/lab/$STAMP"; W="$(mktemp -d /tmp/mitt-lab.XXXXXX)"
mkdir -p "$OUT"; : >"$OUT/probes.jsonl"
# движки и контроллер копируются в каталог Linux-ФС: блокировки и rename проверяются на настоящей файловой системе
mkdir -p "$W/bin"; cp "$B/mihomo" "$B/trusttunnel_endpoint" "$CTL" "$ADM" "$W/bin/"; chmod +x "$W/bin/"*
{ echo "controller=$MODE $(sha256sum "$CTL" | cut -d' ' -f1)"; echo "admin=$MODE $(sha256sum "$ADM" | cut -d' ' -f1)"; "$W/bin/mihomo" -v | head -1; "$W/bin/trusttunnel_endpoint" --version 2>&1 | head -1; uname -r; } >"$OUT/versions.txt"
set +e
ROOT="$ROOT" W="$W" OUT="$OUT" CTL="$W/bin/mi-tt-ctl" ADMIN="$W/bin/mi-tt-admin" RUNCTL="$RUNCTL" MIHOMO="$W/bin/mihomo" TTBIN="$W/bin/trusttunnel_endpoint" CONFIG_IN="$CONFIG_IN" \
  unshare --user --map-root-user --net --mount --propagation private --pid --fork --mount-proc bash "$ROOT/tools/lab/lab-inner.sh"
RC=$?
set -e
rm -rf "$W"
python3 -I -X utf8 "$ROOT/tools/lab/check.py" "$OUT"; CRC=$?
echo "артефакты: $OUT"
[ $RC -eq 0 ] && [ $CRC -eq 0 ]
