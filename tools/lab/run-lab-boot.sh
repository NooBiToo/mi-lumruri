#!/usr/bin/env bash
# Лаборатория автозагрузки и службы (этап 12): одноразовые user+net+mount+pid namespace; сценарии пакета на штатном
# BusyBox ARM64, панель на штатных nginx и uhttpd прошивки (qemu-user), контроллер ARM64 (qemu), Mihomo x86_64,
# настоящий сервер Hysteria2. Пакет — out/package/mi-trusttunnel (node tools/package.mjs).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG="${1:-$ROOT/out/package/mi-trusttunnel}"
"$ROOT/tools/fw/prepare.sh" >/dev/null
"$ROOT/tools/lab/fetch-iptables.sh" >/dev/null
"$ROOT/tools/lab/fetch-hysteria.sh" >/dev/null
B="$ROOT/.tools/lab/bin"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; OUT="$ROOT/out/lab/$STAMP-boot"; W="$(mktemp -d /tmp/mitt-boot.XXXXXX)"
mkdir -p "$OUT" "$W/bin"; cp "$B/mihomo" "$B/hysteria" "$W/bin/"; chmod +x "$W/bin/"*
set +e
ROOT="$ROOT" W="$W" OUT="$OUT" PKG="$PKG" MIHOMO="$W/bin/mihomo" HYBIN="$W/bin/hysteria" \
  unshare --user --map-root-user --net --mount --propagation private --pid --fork --mount-proc bash "$ROOT/tools/lab/lab-boot-inner.sh"
RC=$?
set -e
rm -rf "$W"
python3 -I -X utf8 "$ROOT/tools/lab/check-boot.py" "$OUT"; CRC=$?
echo "артефакты: $OUT"
[ $RC -eq 0 ] && [ $CRC -eq 0 ]
