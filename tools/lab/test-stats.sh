#!/usr/bin/env bash
# Статистика трафика (stats_sample в mitt-lib.sh и mi-tt-ctl stats-sample) на штатном BusyBox ash 1.25.1 (ARM64 из
# образа RC06 1.1.38 под qemu-user): счётчики интерфейсов — поддельный /sys (MITT_SYS), trafficd — заглушка ubus,
# маршрут по умолчанию — заглушка ip, аренды DHCP — файл. Настоящий mi-tt-ctl ARM64.
# Нужен `bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl`. Запуск — в WSL.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"
[ -f "$CTL" ] || { echo "нет $CTL: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
W="$(mktemp -d /tmp/mitt-stats.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr; do
  printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
done
printf '#!/bin/sh\necho "default via 100.64.0.1 dev eth4 proto static"\n' >"$SB/ip"
# trafficd: ответ из $W/trafficd.json (нет файла — trafficd нет)
printf '#!/bin/sh\n[ "$1 $2 $3" = "call trafficd ip" ] && [ -f "%s/trafficd.json" ] && exec cat "%s/trafficd.json"\nexit 4\n' "$W" "$W" >"$SB/ubus"
chmod +x "$SB"/*

R="$W/root"; L="$R/tmp/mi-lumruri"
mkdir -p "$R/data/mi-lumruri/etc" "$L/bin" "$L/scripts" "$L/run" "$L/log" "$W/sys/class/net/mitt0/statistics" "$W/sys/class/net/eth4/statistics"
cp "$ROOT"/package/scripts/*.sh "$L/scripts/"
printf '#!/bin/sh\nexec %s %s "$@"\n' "$Q" "$CTL" >"$L/bin/mi-tt-ctl"; chmod +x "$L/bin/mi-tt-ctl"
printf '1800000000 aa:bb:cc:dd:ee:01 192.168.31.10 tv *\n1800000000 aa:bb:cc:dd:ee:02 192.168.31.11 phone *\n' >"$W/leases"
cnt() { echo "$2" >"$W/sys/class/net/$1/statistics/rx_bytes"; echo "$3" >"$W/sys/class/net/$1/statistics/tx_bytes"; }
tdj() { printf '{"192.168.31.10":{"hw":"AA:BB:CC:DD:EE:01","rx_bytes":%s,"tx_bytes":0},"192.168.31.11":{"rx_bytes":%s,"tx_bytes":0},"192.168.31.99":{"rx_bytes":%s,"tx_bytes":0}}' "$1" "$2" "$3" >"$W/trafficd.json"; }
sample() { timeout 120 env -i PATH="$SB" MITT_ROOT="$R" MITT_QUIET=1 MITT_SYS="$W/sys" MITT_STATS_EVERY=0 MITT_LEASES="$W/leases" \
  "$Q" -L "$F" "$F/bin/busybox" ash -c ". \"$L/scripts/mitt-lib.sh\"; stats_sample" >>"$W/out" 2>&1; }
js() { python3 -I -c 'import json,sys
s=json.load(open(sys.argv[1])); h=s["hours"]; print(eval(sys.argv[2]))' "$L/run/stats.json" "$1" 2>&1; }
chk() { local r; r="$(js "$2")"; [ "$r" = True ] && ok "$1" || bad "$1 → $r; $(cat "$L/run/stats.json" 2>/dev/null | head -c 600); вывод: $(tail -3 "$W/out")"; }

echo "(а) первое показание запоминается; второе — приращения туннеля, WAN и устройств (по MAC из аренд)"
cnt mitt0 1000 1000; cnt eth4 10000 0; tdj 100 50 7; sample
chk "a: часов нет, показания сохранены" 'h == [] and s["last"]["vpn"] == 2000 and s["last"]["wan"] == 10000'
cnt mitt0 1500 2000; cnt eth4 14000 1000; tdj 400 80 7; sample
chk "a: vpn +1500, wan +5000" 'len(h) == 1 and h[0]["vpn"] == 1500 and h[0]["wan"] == 5000'
chk "a: устройства по MAC: ТВ +300, телефон +30; без аренды — по IP" 'h[0]["dev"]["aa:bb:cc:dd:ee:01"] == 300 and h[0]["dev"]["aa:bb:cc:dd:ee:02"] == 30 and h[0]["dev"]["192.168.31.99"] == 0'
[ -f "$R/data/mi-lumruri/etc/stats.json" ] && ok "a: копия в /data" || bad "a: копии в /data нет"

echo "(б) клиент перезапущен: счётчик mitt0 обнулился — приращение равно новому значению"
cnt mitt0 100 100; cnt eth4 15000 1000; sample
chk "b: vpn +200 после сброса, wan +1000" 'h[-1]["vpn"] == 1700 and h[-1]["wan"] == 6000'

echo "(в) туннеля нет (mitt0 не существует) и trafficd нет — WAN считается дальше"
rm -rf "$W/sys/class/net/mitt0" "$W/trafficd.json"; cnt eth4 16000 1000; sample
chk "c: wan +1000, vpn без изменений" 'h[-1]["vpn"] == 1700 and h[-1]["wan"] == 7000 and s["last"].get("vpn") is None'

echo "(г) после «перезагрузки» (RAM пуста) статистика берётся из копии в /data"
rm -f "$L/run/stats.json" "$L/run/stats.last"; cnt eth4 17000 1000; sample
chk "d: часы сохранились, wan +1000" 'h[-1]["wan"] == 8000'

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
