#!/usr/bin/env bash
# Лаборатория этапа 8 (VLESS-REALITY и AmneziaWG одновременно, netfilter-путь стока): одноразовые user+net+mount+pid
# namespace, без root и без изменений хоста. Контроллер — ARM64 из комплекта под qemu-aarch64;
# серверы — настоящие Xray-core (VLESS) и amneziawg-go (peer AmneziaWG).
# Использование: VLESS_MODE=tls|reality tools/lab/run-lab-multi.sh
#   tls (по умолчанию) — VLESS+TLS+vision на актуальном Xray v26.10.31 (сертификат закреплён);
#   reality — VLESS+REALITY+vision на Xray v26.6.1: REALITY клиента Mihomo v1.19.34 несовместим с серверами Xray ≥ v26.9.30.
set -euo pipefail
VLESS_MODE="${VLESS_MODE:-tls}"
case "$VLESS_MODE" in tls) XRAY_VERSION="${XRAY_VERSION:-v26.10.31}";; reality) XRAY_VERSION="${XRAY_VERSION:-v26.6.1}";; *) echo "VLESS_MODE: tls или reality"; exit 2;; esac
export XRAY_VERSION
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/lab/fetch-iptables.sh" >/dev/null
"$ROOT/tools/lab/fetch-xray.sh" >/dev/null
for c in unshare nsenter ip python3 ping; do command -v "$c" >/dev/null || { echo "нужен $c"; exit 2; }; done
B="$ROOT/.tools/lab/bin"
[ -x "$B/mihomo" ] && [ -x "$B/xray-$XRAY_VERSION" ] && [ -f "$B/amneziawg-go" ] || { echo "нет движков: tools/lab/fetch.sh, tools/lab/fetch-xray.sh, tools/lab/build-awg.sh (Go на хосте)"; exit 2; }
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"; ADM="${CTL%/*}/mi-tt-admin"
RUNCTL="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
[ -f "$CTL" ] && [ -f "$ADM" ] && [ -f "$RUNCTL" ] || { echo "нет ARM64-контроллера или qemu-aarch64"; exit 2; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/out/lab/$STAMP-multi-$VLESS_MODE"; W="$(mktemp -d /tmp/mitt-multi.XXXXXX)"
mkdir -p "$OUT" "$W/bin"; cp "$B/mihomo" "$B/xray-$XRAY_VERSION" "$B/amneziawg-go" "$CTL" "$ADM" "$W/bin/"; chmod +x "$W/bin/"*
{ echo "controller=arm64 $(sha256sum "$CTL" | cut -d' ' -f1)"; echo "admin=arm64 $(sha256sum "$ADM" | cut -d' ' -f1)"
  "$W/bin/mihomo" -v | head -1; "$W/bin/xray-$XRAY_VERSION" version | head -1; echo "vless_mode=$VLESS_MODE"; echo "amneziawg-go v0.2.19 $(sha256sum "$W/bin/amneziawg-go" | cut -d' ' -f1)"; uname -r; } >"$OUT/versions.txt"
set +e
ROOT="$ROOT" W="$W" OUT="$OUT" CTL="$W/bin/mi-tt-ctl" ADMIN="$W/bin/mi-tt-admin" RUNCTL="$RUNCTL" MIHOMO="$W/bin/mihomo" XRAY="$W/bin/xray-$XRAY_VERSION" VLESS_MODE="$VLESS_MODE" AWG="$W/bin/amneziawg-go" \
  unshare --user --map-root-user --net --mount --propagation private --pid --fork --mount-proc bash "$ROOT/tools/lab/lab-multi-inner.sh"
RC=$?
set -e
rm -rf "$W"
VLESS_MODE="$VLESS_MODE" python3 -I -X utf8 "$ROOT/tools/lab/check-multi.py" "$OUT"; CRC=$?
echo "артефакты: $OUT"
[ $RC -eq 0 ] && [ $CRC -eq 0 ]
