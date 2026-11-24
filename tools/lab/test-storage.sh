#!/usr/bin/env bash
# Накопители (storage_scan в mitt-lib.sh и mi-tt-ctl storage-scan) на штатном BusyBox ash 1.25.1 (ARM64 из образа RC06
# 1.1.38 под qemu-user): /proc/mounts — поддельный (MITT_PROC), df — заглушка с выводом BusyBox, sysfs — поддельный
# (MI_TT_SYS). Настоящий mi-tt-ctl ARM64. Запуск — в WSL: bash tools/lab/test-storage.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"
[ -f "$CTL" ] || { echo "нет $CTL: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
W="$(mktemp -d /tmp/mitt-storage.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr; do
  printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
done
printf '#!/bin/sh\ncat "%s/df.txt"\n' "$W" >"$SB/df"
chmod +x "$SB"/*

R="$W/root"; L="$R/tmp/mi-lumruri"
mkdir -p "$R/data/mi-lumruri/etc" "$L/bin" "$L/run" "$L/log" "$W/proc" "$W/sys/block/sda/device"
printf '#!/bin/sh\nexec %s %s "$@"\n' "$Q" "$CTL" >"$L/bin/mi-tt-ctl"; chmod +x "$L/bin/mi-tt-ctl"
printf 'ubi0_1 /data ubifs rw,relatime 0 0\n/dev/sda1 /mnt/usb-5f2a vfat rw,relatime 0 0\ntmpfs /tmp tmpfs rw 0 0\n' >"$W/proc/mounts"
printf 'Filesystem           1K-blocks      Used Available Use%% Mounted on\nubi0_1                   40000     22000     18000  55%% /data\n/dev/sda1             15000000   1000000  14000000   7%% /mnt/usb-5f2a\n' >"$W/df.txt"
echo "Kingston" >"$W/sys/block/sda/device/vendor"; echo "DataTraveler" >"$W/sys/block/sda/device/model"
scan() { timeout 120 env -i PATH="$SB" MITT_ROOT="$R" MITT_QUIET=1 MITT_PROC="$W/proc" MI_TT_SYS="$W/sys" MITT_STORAGE_EVERY="${EVERY:-0}" \
  "$Q" -L "$F" "$F/bin/busybox" ash -c ". \"$ROOT/package/scripts/mitt-lib.sh\"; storage_scan" >>"$W/out" 2>&1; }
js() { python3 -I -c 'import json,sys
v=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$L/run/storage.json" "$1" 2>&1; }
chk() { local r; r="$(js "$2")"; [ "$r" = True ] && ok "$1" || bad "$1 → $r; $(head -c 600 "$L/run/storage.json" 2>/dev/null); вывод: $(tail -3 "$W/out")"; }

echo "(а) флешка видна: путь, ФС, место, производитель и модель; внутренняя память — по /data"
scan
chk "a: флешка" 'v["usb"][0]["path"]=="/mnt/usb-5f2a" and v["usb"][0]["fs"]=="vfat" and v["usb"][0]["free"]==14000000*1024 and v["usb"][0]["vendor"]=="Kingston" and v["usb"][0]["model"]=="DataTraveler"'
chk "a: /data" 'v["data"]["free"]==18000*1024 and v["data"]["path"].startswith("/data")'

echo "(б) флешку вынули — список пуст"
printf 'ubi0_1 /data ubifs rw,relatime 0 0\n' >"$W/proc/mounts"; scan
chk "b: пусто" 'v["usb"]==[]'

echo "(в) повтор раньше минуты — без нового сканирования"
printf 'ubi0_1 /data ubifs rw 0 0\n/dev/sda1 /mnt/usb-5f2a vfat rw 0 0\n' >"$W/proc/mounts"; EVERY=60 scan
chk "c: прежний итог" 'v["usb"]==[]'

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
