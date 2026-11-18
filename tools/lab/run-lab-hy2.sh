#!/usr/bin/env bash
# Лаборатория этапа 7 (Hysteria2, netfilter-путь стока): одноразовые user+net+mount+pid namespace, без root и без
# изменений хоста. Контроллер — ARM64 из комплекта под qemu-aarch64; сервер — настоящий hysteria (apernet) по QUIC.
# Использование: tools/lab/run-lab-hy2.sh [--config <config.json, сохранённый панелью>]
set -euo pipefail
CONFIG_IN=""; [ "${1:-}" = --config ] && CONFIG_IN="$(realpath "$2")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/lab/fetch-iptables.sh" >/dev/null
"$ROOT/tools/lab/fetch-hysteria.sh" >/dev/null
"$ROOT/tools/lab/fetch-zapret.sh" >/dev/null
ZAP="$ROOT/.tools/lab/zapret2/zapret2-v1.0.7"
for c in unshare nsenter ip python3 ping; do command -v "$c" >/dev/null || { echo "нужен $c"; exit 2; }; done
B="$ROOT/.tools/lab/bin"
[ -x "$B/mihomo" ] && [ -x "$B/hysteria" ] || { echo "нет движков: tools/lab/fetch.sh и tools/lab/fetch-hysteria.sh"; exit 2; }
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"; ADM="${CTL%/*}/mi-tt-admin"
RUNCTL="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
[ -f "$CTL" ] && [ -f "$ADM" ] && [ -f "$RUNCTL" ] || { echo "нет ARM64-контроллера или qemu-aarch64"; exit 2; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/out/lab/$STAMP-hy2"; W="$(mktemp -d /tmp/mitt-hy2.XXXXXX)"
mkdir -p "$OUT" "$W/bin"; cp "$B/mihomo" "$B/hysteria" "$ZAP/binaries/linux-x86_64/nfqws2" "$CTL" "$ADM" "$W/bin/"; chmod +x "$W/bin/"*
{ echo "controller=arm64 $(sha256sum "$CTL" | cut -d' ' -f1)"; echo "admin=arm64 $(sha256sum "$ADM" | cut -d' ' -f1)"
  "$W/bin/mihomo" -v | head -1; "$W/bin/hysteria" version 2>/dev/null | grep -E '^Version|^BuildDate' | tr '\n' ' '; echo; "$W/bin/nfqws2" --version 2>&1 | head -1; uname -r; } >"$OUT/versions.txt"
set +e
ROOT="$ROOT" W="$W" OUT="$OUT" CTL="$W/bin/mi-tt-ctl" ADMIN="$W/bin/mi-tt-admin" RUNCTL="$RUNCTL" MIHOMO="$W/bin/mihomo" HYBIN="$W/bin/hysteria" NFQWS="$W/bin/nfqws2" NFQWS_LUA="$ZAP/lua" CONFIG_IN="$CONFIG_IN" \
  unshare --user --map-root-user --net --mount --propagation private --pid --fork --mount-proc bash "$ROOT/tools/lab/lab-hy2-inner.sh"
RC=$?
set -e
rm -rf "$W"
python3 -I -X utf8 "$ROOT/tools/lab/check-hy2.py" "$OUT"; CRC=$?
echo "артефакты: $OUT"
[ $RC -eq 0 ] && [ $CRC -eq 0 ]
