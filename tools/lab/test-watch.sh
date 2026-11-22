#!/usr/bin/env bash
# Сторож туннеля (tunnel_watch в package/scripts/mitt-lib.sh) на штатном BusyBox ash 1.25.1 (ARM64 из образа RC06
# 1.1.38 под qemu-user): заглушки curl (ответ через mitt0 есть/нет) и ip (mitt0 поднят), «клиент» — процесс sleep.
# Запуск — в WSL: bash tools/lab/test-watch.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"
[ -f "$CTL" ] || { echo "нет $CTL: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
W="$(mktemp -d /tmp/mitt-watch.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"; kill "$CLIENT" 2>/dev/null' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr usleep; do
  if [ -e "$F/bin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
    printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  else echo "нет апплета $a в образе"; exit 2; fi
done
cat >"$SB/ip" <<'EOF'
#!/bin/sh
case "$*" in
  "link show mitt0") echo '9: mitt0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1350';;
  "-4 addr show dev mitt0") echo '    inet 172.16.219.2/32 scope global mitt0';;
  *) exit 1;;
esac
EOF
cat >"$SB/curl" <<'EOF'
#!/bin/sh
echo "$*" >>"$LT/curl.log"
[ "$(cat "$LT/net")" = ok ]
EOF
chmod +x "$SB"/*

R="$W/root"; LT="$W/lt"; mkdir -p "$R/tmp/mi-lumruri/run" "$R/tmp/mi-lumruri/log" "$R/tmp/mi-lumruri/bin" "$R/data/mi-lumruri" "$LT"
printf '#!/bin/sh\nexec %s %s "$@"\n' "$Q" "$CTL" >"$R/tmp/mi-lumruri/bin/mi-tt-ctl"; chmod +x "$R/tmp/mi-lumruri/bin/mi-tt-ctl"
S="$R/tmp/mi-lumruri/run"; L="$R/tmp/mi-lumruri/log"
sleep 1000 & CLIENT=$!
echo "$CLIENT" >"$S/trusttunnel.pid"
echo "x VPNCORE raise_state: [0] VPN_SS_CONNECTED" >"$L/trusttunnel.log"
# mitt-lib.sh — из репозитория (путь внутри qemu совпадает с путём хоста)
watch() {
  timeout 120 env -i PATH="$SB" MITT_ROOT="$R" MITT_QUIET=1 LT="$LT" MITT_WATCH_INTERVAL=0 MITT_WATCH_GAP="${GAP:-300}" LIB="$ROOT/package/scripts/mitt-lib.sh" \
    "$Q" -L "$F" "$F/bin/busybox" ash -c '. "$LIB"; tunnel_tick' >>"$W/out" 2>&1
}
alive() { kill -0 "$CLIENT" 2>/dev/null; }
js() { cat "$S/watch.json" 2>/dev/null; }

echo "(а) трафик идёт — сбоев нет, клиент жив"
echo ok >"$LT/net"; watch
alive && grep -q '"ok":true' "$S/watch.json" && ok "a: ok, клиент жив" || bad "a: $(js)"
grep -q -- '--interface mitt0' "$LT/curl.log" && ok "a: проверка через mitt0" || bad "a: curl: $(cat "$LT/curl.log")"

echo "(б) две неудачи — ещё не перезапуск; третья — перезапуск клиента"
echo fail >"$LT/net"; watch; watch
alive && grep -q '"fails":2' "$S/watch.json" && ok "b: 2 неудачи, клиент жив" || bad "b: $(js)"
watch; sleep 2
! alive && grep -q 'сторож:' "$L/mitt.log" && ok "b: третья неудача — клиент остановлен, запись в журнале" || bad "b: alive=$(alive && echo да || echo нет) $(js)"
[ "$(grep -c 'https://' "$LT/curl.log")" -ge 7 ] && ok "b: при неудаче пробуется и второй адрес" || bad "b: curl.log: $(wc -l <"$LT/curl.log")"

echo "(в) повторный сбой раньше 5 минут — без перезапуска"
sleep 1000 & CLIENT=$!; echo "$CLIENT" >"$S/trusttunnel.pid"
watch; watch; watch; sleep 1
alive && ok "c: новый клиент не перезапускается чаще раза в 5 минут" || bad "c: перезапущен: $(js)"

echo "(г) клиент сам переподключается (не CONNECTED) — сторож не вмешивается"
echo "y VPNCORE raise_state: [0] VPN_SS_RECOVERING" >>"$L/trusttunnel.log"; rm -f "$S/tunnel.json"
watch; watch; watch; sleep 1
alive && grep -q '"watch_fails":0' "$S/tunnel.json" && ok "d: при восстановлении проверок нет" || bad "d: $(cat "$S/tunnel.json")"

echo "(д) интервал: между проверками не меньше MITT_WATCH_INTERVAL"
echo "z VPNCORE raise_state: [0] VPN_SS_CONNECTED" >>"$L/trusttunnel.log"; : >"$LT/curl.log"; echo ok >"$LT/net"; rm -f "$S/tunnel.json"
timeout 60 env -i PATH="$SB" MITT_ROOT="$R" MITT_QUIET=1 LT="$LT" LIB="$ROOT/package/scripts/mitt-lib.sh" \
  "$Q" -L "$F" "$F/bin/busybox" ash -c '. "$LIB"; tunnel_tick; tunnel_tick; tunnel_tick' >>"$W/out" 2>&1
[ "$(grep -c 'https://' "$LT/curl.log")" = 1 ] && ok "e: три вызова подряд — одна проверка" || bad "e: проверок $(grep -c 'https://' "$LT/curl.log")"

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
