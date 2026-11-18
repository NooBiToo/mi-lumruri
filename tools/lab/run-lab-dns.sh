#!/usr/bin/env bash
# Лаборатория этапа 10 (шифрованный DNS, ODoH, блокировка рекламы): одноразовые user+net+mount+pid namespace,
# без root и без изменений хоста. Контроллер — ARM64 под qemu-aarch64; Mihomo, dnscrypt-proxy, dnsmasq — x86_64;
# серверы DoH/DoT/DoQ/DoH3 (AdGuard dnsproxy) и ODoH target/relay (odoh-server-go) — настоящие.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/lab/fetch-dns.sh" >/dev/null
for c in unshare nsenter ip python3 openssl; do command -v "$c" >/dev/null || { echo "нужен $c"; exit 2; }; done
B="$ROOT/.tools/lab/bin"
[ -x "$B/mihomo" ] && [ -x "$B/dnsproxy" ] && [ -x "$B/dnscrypt-proxy" ] && [ -f "$B/odoh-server" ] || { echo "нет инструментов: tools/lab/fetch.sh, fetch-dns.sh, build-odoh.sh"; exit 2; }
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"; RUNCTL="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
[ -f "$CTL" ] && [ -f "$RUNCTL" ] || { echo "нет ARM64-контроллера или qemu-aarch64"; exit 2; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; OUT="$ROOT/out/lab/$STAMP-dns"; W="$(mktemp -d /tmp/mitt-dns.XXXXXX)"
mkdir -p "$OUT" "$W/bin"; cp "$B/mihomo" "$B/dnsproxy" "$B/dnscrypt-proxy" "$B/odoh-server" "$CTL" "$W/bin/"; chmod +x "$W/bin/"*
DM="$ROOT/.tools/lab/dnsmasq/root"
printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s/usr/lib/x86_64-linux-gnu\nexec %s/usr/sbin/dnsmasq "$@"\n' "$DM" "$DM" >"$W/bin/dnsmasq"; chmod +x "$W/bin/dnsmasq"
{ echo "controller=arm64 $(sha256sum "$CTL" | cut -d' ' -f1)"; "$W/bin/mihomo" -v | head -1; "$W/bin/dnsproxy" --version 2>&1 | head -1
  echo "dnscrypt-proxy $("$W/bin/dnscrypt-proxy" -version)"; "$W/bin/dnsmasq" --version | head -1; echo "odoh-server-go v0.1.4"; uname -r; } >"$OUT/versions.txt"
set +e
ROOT="$ROOT" W="$W" OUT="$OUT" CTL="$W/bin/mi-tt-ctl" RUNCTL="$RUNCTL" MIHOMO="$W/bin/mihomo" DNSPROXY="$W/bin/dnsproxy" DNSCRYPT="$W/bin/dnscrypt-proxy" \
  ODOH="$W/bin/odoh-server" DNSMASQ="$W/bin/dnsmasq" \
  unshare --user --map-root-user --net --mount --propagation private --pid --fork --mount-proc bash "$ROOT/tools/lab/lab-dns-inner.sh"
RC=$?
set -e
rm -rf "$W"
python3 -I -X utf8 "$ROOT/tools/lab/check-dns.py" "$OUT"; CRC=$?
echo "артефакты: $OUT"
[ $RC -eq 0 ] && [ $CRC -eq 0 ]
