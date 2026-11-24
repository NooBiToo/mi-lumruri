#!/usr/bin/env bash
# Модуль sing-box (mitt-module.sh, modules_prepare, modules_watch в mitt-lib.sh) на штатном BusyBox ash 1.25.1 (ARM64 из
# образа RC06 1.1.38 под qemu-user): настоящий подписанный модуль ARM64 из out/package (node tools/package.mjs),
# настоящие mi-tt-ctl и mi-tt-admin ARM64, «флешка» — каталог. Установка, отказ при чужом SHA-256, пропажа и возврат
# накопителя с уведомлениями, удаление, запуск без накопителя. Запуск — в WSL: bash tools/lab/test-module.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
T="$ROOT/controller/target/aarch64-unknown-linux-musl/release"
PKGD="$ROOT/out/package"
[ -f "$T/mi-tt" ] || { echo "нет $T/mi-tt: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
MOD="$(ls "$PKGD"/mitt-mod-sing-box-*.tar 2>/dev/null | head -n 1)"
[ -n "$MOD" ] && [ -f "$PKGD/mi-lumruri/payload/scripts/modules.json" ] || { echo "нет модуля в $PKGD: node tools/package.mjs"; exit 2; }
W="$(mktemp -d /tmp/mitt-module.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir rmdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr tar unxz ls; do
  printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
done
chmod +x "$SB"/*

R="$W/root"; L="$R/tmp/mi-lumruri"; DATA="$R/data/mi-lumruri"; USB="$R/mnt/usb-lab"
mkdir -p "$DATA/etc" "$DATA/keys" "$L/bin" "$L/scripts" "$L/run" "$L/log" "$L/render" "$USB"
cp "$ROOT"/package/scripts/*.sh "$PKGD/mi-lumruri/payload/scripts/modules.json" "$L/scripts/"
cp "$T/mi-tt" "$L/bin/mi-tt.arm64"
for n in mi-tt-ctl mi-tt-admin; do printf '#!/bin/sh\nexec %s -0 %s %s/mi-tt.arm64 "$@"\n' "$Q" "$n" "$L/bin" >"$L/bin/$n"; chmod +x "$L/bin/$n"; done
python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["pubkey"])' "$PKGD/module-sing-box/module/manifest.json" >"$DATA/keys/release.pub"
S="$L/run"
run() { timeout 600 env -i PATH="$SB" MITT_ROOT="$R" MITT_QUIET=1 MITT_MODULE_SRC="${SRC:-$MOD}" MITT_MODULE_WATCH=0 \
  "$Q" -L "$F" "$F/bin/busybox" ash -c ". \"$L/scripts/mitt-lib.sh\"; $1" >>"$W/out" 2>&1; }
req() { printf '%s\n' "$1" >"$S/module.request.run"; run "sh \"$L/scripts/mitt-module.sh\""; }
st() { cat "$S/module.json" 2>/dev/null; }

echo "(а) установка на «флешку»: проверка SHA-256 и подписи, запись, распаковка в RAM, заявка на применение"
run modules_prepare
[ -f "$S/modules-catalog.json" ] && ok "a: каталог модулей для панели" || bad "a: нет modules-catalog.json"
req "{\"action\":\"install\",\"name\":\"sing-box\",\"dir\":\"/mnt/usb-lab/mi-lumruri-modules/sing-box\"}"
grep -q '"state":"done"' "$S/module.json" && ok "a: $(st | sed -n 's/.*"message":"\([^"]*\)".*/\1/p')" || bad "a: $(st); $(tail -5 "$W/out")"
[ -f "$USB/mi-lumruri-modules/sing-box/manifest.json" ] && ok "a: модуль на флешке" || bad "a: нет файлов модуля на флешке"
grep -q '"sing-box"' "$DATA/etc/modules.json" 2>/dev/null && ok "a: etc/modules.json" || bad "a: $(cat "$DATA/etc/modules.json" 2>&1)"
v="$("$Q" "$L/mod/sing-box/sing-box" version 2>&1 | head -n 1)"
case "$v" in "sing-box version 1.14"*) ok "a: в RAM запускается: $v";; *) bad "a: sing-box из RAM: $v";; esac
[ -f "$S/apply.request" ] && ok "a: заявка на применение" || bad "a: нет apply.request"
grep -q '"sing-box":{"state":"ok","ram":true}' "$S/modules-state.json" && ok "a: состояние ok" || bad "a: $(cat "$S/modules-state.json")"
ls "$USB/mi-lumruri-modules" | grep -q part && bad "a: остался .part" || ok "a: временных файлов нет"

echo "(б) чужой tar (SHA-256 не из каталога) — отказ, установленный модуль не тронут"
head -c 4096 "$MOD" >"$W/bad.tar"
SRC="$W/bad.tar" req "{\"action\":\"install\",\"name\":\"sing-box\",\"dir\":\"/mnt/usb-lab/mi-lumruri-modules/sing-box\"}"
grep -q '"state":"failed"' "$S/module.json" && grep -q 'SHA-256' "$S/module.json" && ok "b: отказ — SHA-256" || bad "b: $(st)"
[ -f "$USB/mi-lumruri-modules/sing-box/manifest.json" ] && ok "b: прежний модуль на месте" || bad "b: модуль пропал"

echo "(в) флешка пропала при работающем сервере модуля: одно уведомление, программа в RAM остаётся"
echo "1 mitt1 vl sing-box" >"$L/render/tunnels.list"
mv "$USB" "$W/usb-away"
run modules_watch; run modules_watch
[ "$(grep -c 'module_missing' "$S/notify.queue" 2>/dev/null)" = 1 ] && ok "c: одно уведомление module_missing" || bad "c: $(cat "$S/notify.queue" 2>&1)"
grep -q '"sing-box":{"state":"missing","ram":true}' "$S/modules-state.json" && ok "c: missing, в RAM" || bad "c: $(cat "$S/modules-state.json")"

echo "(г) флешка вернулась: уведомление, состояние ok"
mv "$W/usb-away" "$USB"; rm -f "$S/apply.request"
run modules_watch
grep -q 'module_back' "$S/notify.queue" && ok "d: уведомление module_back" || bad "d: $(cat "$S/notify.queue")"
grep -q '"state":"ok"' "$S/modules-state.json" && ok "d: ok" || bad "d: $(cat "$S/modules-state.json")"

echo "(д) перезагрузка без флешки: в RAM ничего, missing; уведомление «не работают»"
rm -rf "$L/mod" "$S/mod-sing-box.missing" "$S/notify.queue"; mv "$USB" "$W/usb-away"
run modules_prepare; run modules_watch
grep -q '"sing-box":{"state":"missing","ram":false}' "$S/modules-state.json" && ok "e: missing, в RAM нет" || bad "e: $(cat "$S/modules-state.json")"
grep -q 'module_missing_off' "$S/notify.queue" && ok "e: уведомление module_missing_off" || bad "e: $(cat "$S/notify.queue" 2>&1)"
mv "$W/usb-away" "$USB"; run modules_watch
[ -x "$L/mod/sing-box/sing-box" ] && [ -f "$S/apply.request" ] && ok "e: вернулась — распакован, заявка на применение" || bad "e: $(ls "$L/mod" 2>&1)"

echo "(е) удаление"
req '{"action":"remove","name":"sing-box"}'
grep -q '"state":"done"' "$S/module.json" && [ ! -d "$USB/mi-lumruri-modules/sing-box" ] && [ ! -d "$L/mod/sing-box" ] && ok "f: удалён с флешки и из RAM" || bad "f: $(st)"
grep -q 'sing-box' "$DATA/etc/modules.json" && bad "f: запись осталась" || ok "f: запись удалена"

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; tail -20 "$W/out"; exit 1; }
