#!/usr/bin/env bash
# Этап 12: установщик на штатном BusyBox ash 1.25.1 (ARM64 из образа RC06 1.1.38 под qemu-user) в эмулированной
# файловой системе роутера (MITT_ROOT). uci, openssl, unxz, df, uname — программы и апплеты прошивки.
# Выполняется в одноразовом user+mount namespace (см. run-lab-install.sh): сеть и файлы хоста не меняются.
set -uo pipefail
: "${ROOT:?}" "${W:?}" "${OUT:?}" "${PKGS:?}"
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
log() { printf '[install] %s\n' "$*" | tee -a "$OUT/lab.log"; }

# апплеты BusyBox и программы стока через qemu-user
SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv ln rm mkdir chmod readlink sed awk grep head tail wc tr cut sort cmp df uname date sleep kill sync basename dirname unxz xzcat mktemp touch printf echo test expr id ls md5sum cksum; do
  # только апплеты, которые действительно есть в образе 1.1.38: недостающий — ошибка «not found» в сценарии, как на роутере
  if [ -e "$F/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
  printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  else echo "$a" >>"$OUT/stock-missing-applets.txt"; fi
done
printf '#!/bin/sh\nexec %s -L %s %s/sbin/uci "$@"\n' "$Q" "$F" "$F" >"$SB/uci"
printf '#!/bin/sh\nexec %s -L %s %s/usr/bin/openssl "$@"\n' "$Q" "$F" "$F" >"$SB/openssl"
chmod +x "$SB"/*
# ARM64-программы пакета — через qemu (обёртки вместо распакованных файлов, только при MITT_ROOT)
LB="$W/labbin"; mkdir -p "$LB"
for n in mi-tt-ctl mi-tt-admin mi-tt-dns trusttunnel_client nfqws2; do printf '#!/bin/sh\nexec %s "$0.arm64" "$@"\n' "$Q" >"$LB/$n"; done; chmod +x "$LB"/*

newroot() { # newroot <каталог>: файловая система роутера из образа (только нужное)
  local r="$1"; rm -rf "$r"; mkdir -p "$r/data" "$r/tmp" "$r/etc/config" "$r/usr/share/xiaoqiang"
  cp "$F/usr/share/xiaoqiang/xiaoqiang_version" "$r/usr/share/xiaoqiang/"; cp "$F/etc/config/firewall" "$F/etc/config/network" "$r/etc/config/"; }
inst() { # inst <id> <каталог пакета> <команда> [аргументы]
  local id="$1" pkg="$2"; shift 2
  env -i PATH="$SB" MITT_ROOT="$RR" MITT_LAB_BIN="$LB" MITT_UCI_CONF="$RR/etc/config" MITT_QUIET=1 ${EXTRA:-} \
    "$Q" -L "$F" "$F/bin/busybox" ash "$pkg/install.sh" "$@" >"$OUT/$id.out" 2>&1
  local rc=$?
  "$PY" -c 'import json,os,sys;r=sys.argv[2];rd=lambda n: open(r+"/data/mi-trusttunnel/"+n).read().strip() if os.path.exists(r+"/data/mi-trusttunnel/"+n) else None
cur=rd("current.ver"); prev=rd("previous.ver")
rel=sorted(os.listdir(r+"/data/mi-trusttunnel/releases")) if os.path.isdir(r+"/data/mi-trusttunnel/releases") else []
fw=open(r+"/etc/config/firewall").read()
print(json.dumps({"id":sys.argv[1],"exit":int(sys.argv[3]),"current":cur,"previous":prev,"releases":rel,"include":"config include '"'"'mitt'"'"'" in fw,"out":open(sys.argv[4],errors="replace").read()[-600:]}))' \
    "$id" "$RR" "$rc" "$OUT/$id.out" >>"$OUT/steps.jsonl"
  log "$id ($*): код $rc, $(tail -1 "$OUT/$id.out")"
}
PY=python3

RR="$W/root"; newroot "$RR"
inst I1-fresh "$PKGS/v1" install --no-start
EXTRA="" inst I2-repeat "$PKGS/v1" install --no-start
inst I3-update "$PKGS/v2" install --no-start
inst I4-tampered "$PKGS/v3-tampered" install --no-start
inst I5-foreign-key "$PKGS/v4-foreign" install --no-start
EXTRA="MITT_LAB_FAIL_AT=copy" inst I6-interrupted "$PKGS/v5" install --no-start
inst I7-after-interrupt "$PKGS/v5" install --no-start
inst I8-rollback "$PKGS/v5" rollback --no-start
# проверка файлов установки после всех шагов
"$PY" -c 'import json,os,stat,sys;r=sys.argv[1]+"/data/mi-trusttunnel"
m=lambda p: oct(stat.S_IMODE(os.stat(p).st_mode))[2:] if os.path.exists(p) else None
fw=open(sys.argv[1]+"/etc/config/firewall").read(); i=fw.find("config include '"'"'mitt'"'"'")
print(json.dumps({"data":m(r),"etc":m(r+"/etc"),"auth":m(r+"/etc/auth"),"tls_key":m(r+"/etc/tls/key.pem"),"secrets":m(r+"/etc/secrets.json"),
 "pinned":open(r+"/keys/release.pub").read().strip()[:16],"cert":open(r+"/etc/tls/cert.pem").read()[:27],"fw_include":fw[i:i+220] if i>=0 else None}))' "$RR" >"$OUT/layout.json"
# настройки пользователя не перезаписываются обновлением
printf '{"marker":"user"}\n' >>"$RR/data/mi-trusttunnel/etc/config.json.user-test"
inst I9-uninstall "$PKGS/v5" uninstall
ls "$RR/data/mi-trusttunnel" >"$OUT/after-uninstall.txt" 2>&1

# неверная модель и нехватка места — на чистых корнях
RM="$W/root-model"; newroot "$RM"; sed -i "s/option HARDWARE 'RC06'/option HARDWARE 'RA70'/" "$RM/usr/share/xiaoqiang/xiaoqiang_version"
RR="$RM" inst I10-wrong-model "$PKGS/v1" install --no-start
RS="$W/root-small"; newroot "$RS"; mount -t tmpfs -o size=4m tmpfs "$RS/data"
RR="$RS" inst I11-no-space "$PKGS/v1" install --no-start
ls -A "$RS/data" >"$OUT/no-space-data.txt"

# внешнее хранилище релизов (--store): свежая установка, обновление, перенос из /data, накопитель не подключён
storestate() { # storestate <id> <корень> <каталог хранилища>
  "$PY" -c 'import json,os,sys;d=sys.argv[2]+"/data/mi-trusttunnel";s=sys.argv[3]
ls=lambda p: sorted(os.listdir(p)) if os.path.isdir(p) else None
rd=lambda n: open(d+"/"+n).read().strip() if os.path.exists(d+"/"+n) else None
print(json.dumps({"id":sys.argv[1],"store":rd("store"),"current":rd("current.ver"),"previous":rd("previous.ver"),"data_releases":ls(d+"/releases"),"store_releases":ls(s+"/releases"),
 "stub_waits":"MITT_STORE_WAIT" in open(d+"/mitt-boot.sh").read() if os.path.exists(d+"/mitt-boot.sh") else None}))' "$1" "$2" "$3" >>"$OUT/store.jsonl"
}
: >"$OUT/store.jsonl"
RE="$W/root-ext"; newroot "$RE"; mkdir -p "$RE/mnt/usb"; ST="$RE/mnt/usb/mi-trusttunnel"
RR="$RE" inst S1-store-fresh "$PKGS/v1" install --no-start "--store=$ST"; storestate S1-store-fresh "$RE" "$ST"
RR="$RE" inst S2-store-update "$PKGS/v2" install --no-start; storestate S2-store-update "$RE" "$ST"
RR="$RE" inst S3-store-rollback "$PKGS/v2" rollback --no-start; storestate S3-store-rollback "$RE" "$ST"
RR="$RE" inst S4-store-uninstall "$PKGS/v2" uninstall; storestate S4-store-uninstall "$RE" "$ST"
RV="$W/root-move"; newroot "$RV"; mkdir -p "$RV/mnt/usb"; SV="$RV/mnt/usb/mi-trusttunnel"
RR="$RV" inst S5-move-base "$PKGS/v1" install --no-start
RR="$RV" inst S6-move "$PKGS/v2" install --no-start "--store=$SV"; storestate S6-move "$RV" "$SV"
RN="$W/root-nousb"; newroot "$RN"
RR="$RN" inst S7-store-absent "$PKGS/v1" install --no-start "--store=$RN/mnt/usb/mi-trusttunnel"; storestate S7-store-absent "$RN" "$RN/mnt/usb/mi-trusttunnel"
ls -A "$RN/data" >"$OUT/store-absent-data.txt"
log "готово"
