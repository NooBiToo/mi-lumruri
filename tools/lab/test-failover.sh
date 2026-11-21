#!/usr/bin/env bash
# Запасной сервер (failover_check, tt_config в package/scripts/mitt-lib.sh) на штатном BusyBox ash 1.25.1 (ARM64 из
# образа RC06 1.1.38 под qemu-user): состояние клиента — строки журнала, «клиент» — процесс sleep, заглушка curl —
# код выхода проверки основного сервера (7 — не подключиться, 35 — ошибка TLS, то есть порт открыт).
# Запуск — в WSL: bash tools/lab/test-failover.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
W="$(mktemp -d /tmp/mitt-fo.XXXXXX)"; CLIENT=""
[ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"; [ -n "$CLIENT" ] && kill "$CLIENT" 2>/dev/null' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr usleep; do
  if [ -e "$F/bin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
    printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  else echo "нет апплета $a в образе"; exit 2; fi
done
printf '#!/bin/sh\necho "$*" >>"$LT/curl.log"\nexit "$(cat "$LT/rc")"\n' >"$SB/curl"
chmod +x "$SB"/*

R="$W/root"; LT="$W/lt"; S="$R/tmp/mi-lumruri/run"; L="$R/tmp/mi-lumruri/log"; RD="$R/tmp/mi-lumruri/render"
mkdir -p "$S" "$L" "$RD" "$R/data/mi-lumruri" "$LT"
: >"$RD/client.toml"; : >"$RD/client-backup.toml"; echo "203.0.113.10 443" >"$RD/primary.addr"; echo 7 >"$LT/rc"
newclient() { [ -n "$CLIENT" ] && kill "$CLIENT" 2>/dev/null; sleep 1000 & CLIENT=$!; echo "$CLIENT" >"$S/trusttunnel.pid"; }
state() { echo "x VPNCORE raise_state: [0] $1" >>"$L/trusttunnel.log"; }
fo() {
  timeout 120 env -i PATH="$SB" MITT_ROOT="$R" MITT_QUIET=1 LT="$LT" LIB="$ROOT/package/scripts/mitt-lib.sh" \
    MITT_FAILOVER_AFTER="${AFTER:-0}" MITT_FAILBACK_EVERY=0 "$Q" -L "$F" "$F/bin/busybox" ash -c ". \"\$LIB\"; ${1:-failover_check}" 2>>"$W/err"
}
alive() { kill -0 "$CLIENT" 2>/dev/null; }
ep() { cat "$S/endpoint" 2>/dev/null || echo "-"; }

echo "(а) основной подключён — без переключений, клиент с client.toml"
newclient; state VPN_SS_CONNECTED; fo
alive && [ "$(ep)" = "-" ] && ok "a: на основном" || bad "a: endpoint=$(ep)"
[ "$(fo tt_config)" = "$RD/client.toml" ] && ok "a: tt_config — client.toml" || bad "a: tt_config=$(fo tt_config)"

echo "(б) связи нет дольше порога — на запасной, клиент перезапускается с client-backup.toml"
state VPN_SS_RECOVERING; AFTER=600 fo
alive && [ "$(ep)" = "-" ] && ok "b: до порога — ждём" || bad "b: рано переключился: $(ep)"
fo; sleep 1
! alive && [ "$(ep)" = backup ] && grep -q "переключение на запасной" "$L/mitt.log" && ok "b: переключение на запасной" || bad "b: endpoint=$(ep) alive=$(alive && echo да)"
[ "$(fo tt_config)" = "$RD/client-backup.toml" ] && ok "b: tt_config — client-backup.toml" || bad "b: tt_config=$(fo tt_config)"

echo "(в) на запасном: основной не отвечает — остаёмся"
newclient; state VPN_SS_CONNECTED; echo 7 >"$LT/rc"; fo; fo
alive && [ "$(ep)" = backup ] && ok "c: основной не отвечает — на запасном" || bad "c: endpoint=$(ep)"
grep -q "https://203.0.113.10:443/" "$LT/curl.log" && ok "c: проверка основного напрямую по адресу и порту" || bad "c: curl: $(cat "$LT/curl.log")"

echo "(г) основной ответил дважды подряд — возврат"
echo 35 >"$LT/rc"; fo
alive && [ "$(ep)" = backup ] && ok "d: один ответ — ещё на запасном" || bad "d: endpoint=$(ep)"
fo; sleep 1
! alive && [ "$(ep)" = primary ] && grep -q "возврат на основной" "$L/mitt.log" && ok "d: второй ответ — возврат на основной" || bad "d: endpoint=$(ep)"

echo "(д) запасной убран из настроек — состояние снято"
newclient; rm -f "$RD/client-backup.toml"; echo backup >"$S/endpoint"; fo
[ "$(ep)" = "-" ] && [ "$(fo tt_config)" = "$RD/client.toml" ] && ok "e: без запасного — основной" || bad "e: endpoint=$(ep)"

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; cat "$W/err" | tail -5; exit 1; }
