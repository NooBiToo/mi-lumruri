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
  "$PY" -c 'import json,os,sys;r=sys.argv[2];rd=lambda n: open(r+"/data/mi-lumruri/"+n).read().strip() if os.path.exists(r+"/data/mi-lumruri/"+n) else None
cur=rd("current.ver"); prev=rd("previous.ver")
rel=sorted(os.listdir(r+"/data/mi-lumruri/releases")) if os.path.isdir(r+"/data/mi-lumruri/releases") else []
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
"$PY" -c 'import json,os,stat,sys;r=sys.argv[1]+"/data/mi-lumruri"
m=lambda p: oct(stat.S_IMODE(os.stat(p).st_mode))[2:] if os.path.exists(p) else None
fw=open(sys.argv[1]+"/etc/config/firewall").read(); i=fw.find("config include '"'"'mitt'"'"'")
print(json.dumps({"data":m(r),"etc":m(r+"/etc"),"auth":m(r+"/etc/auth"),"tls_key":m(r+"/etc/tls/key.pem"),"secrets":m(r+"/etc/secrets.json"),
 "pinned":open(r+"/keys/release.pub").read().strip()[:16],"cert":open(r+"/etc/tls/cert.pem").read()[:27],"fw_include":fw[i:i+220] if i>=0 else None}))' "$RR" >"$OUT/layout.json"
# настройки пользователя не перезаписываются обновлением
printf '{"marker":"user"}\n' >>"$RR/data/mi-lumruri/etc/config.json.user-test"
inst I9-uninstall "$PKGS/v5" uninstall
ls "$RR/data/mi-lumruri" >"$OUT/after-uninstall.txt" 2>&1

# неверная модель и нехватка места — на чистых корнях
RM="$W/root-model"; newroot "$RM"; sed -i "s/option HARDWARE 'RC06'/option HARDWARE 'RA70'/" "$RM/usr/share/xiaoqiang/xiaoqiang_version"
RR="$RM" inst I10-wrong-model "$PKGS/v1" install --no-start
RS="$W/root-small"; newroot "$RS"; mount -t tmpfs -o size=4m tmpfs "$RS/data"
RR="$RS" inst I11-no-space "$PKGS/v1" install --no-start
ls -A "$RS/data" >"$OUT/no-space-data.txt"

# смена ключа подписи (--trust-key): без флага — отказ с отпечатками, с чужим отпечатком — отказ, с верным — установка
# и закрепление нового ключа; после этого пакет со старым ключом уже не принимается
RK="$W/root-key"; newroot "$RK"
RR="$RK" inst K1-fresh "$PKGS/v1" install --no-start
RR="$RK" inst K2-foreign-no-flag "$PKGS/v4-foreign" install --no-start
FFP="$(sed -n 's/.*у пакета \([0-9a-f]\{16\}\).*/\1/p' "$OUT/K2-foreign-no-flag.out" | head -n 1)"
echo "$FFP" >"$OUT/foreign-fp.txt"
RR="$RK" inst K3-foreign-wrong-fp "$PKGS/v4-foreign" install --no-start --trust-key=0123456789abcdef
RR="$RK" inst K4-foreign-trusted "$PKGS/v4-foreign" install --no-start "--trust-key=${FFP:-none}"
head -c 16 "$RK/data/mi-lumruri/keys/release.pub" >"$OUT/key-after-trust.txt"
RR="$RK" inst K5-old-key-refused "$PKGS/v2" install --no-start

# внешнее хранилище релизов (--store): свежая установка, обновление, перенос из /data, накопитель не подключён
storestate() { # storestate <id> <корень> <каталог хранилища>
  "$PY" -c 'import json,os,sys;d=sys.argv[2]+"/data/mi-lumruri";s=sys.argv[3]
ls=lambda p: sorted(os.listdir(p)) if os.path.isdir(p) else None
rd=lambda n: open(d+"/"+n).read().strip() if os.path.exists(d+"/"+n) else None
print(json.dumps({"id":sys.argv[1],"store":rd("store"),"current":rd("current.ver"),"previous":rd("previous.ver"),"data_releases":ls(d+"/releases"),"store_releases":ls(s+"/releases"),
 "stub_waits":"MITT_STORE_WAIT" in open(d+"/mitt-boot.sh").read() if os.path.exists(d+"/mitt-boot.sh") else None}))' "$1" "$2" "$3" >>"$OUT/store.jsonl"
}
: >"$OUT/store.jsonl"
RE="$W/root-ext"; newroot "$RE"; mkdir -p "$RE/mnt/usb"; ST="$RE/mnt/usb/mi-lumruri"
RR="$RE" inst S1-store-fresh "$PKGS/v1" install --no-start "--store=$ST"; storestate S1-store-fresh "$RE" "$ST"
RR="$RE" inst S2-store-update "$PKGS/v2" install --no-start; storestate S2-store-update "$RE" "$ST"
RR="$RE" inst S3-store-rollback "$PKGS/v2" rollback --no-start; storestate S3-store-rollback "$RE" "$ST"
RR="$RE" inst S4-store-uninstall "$PKGS/v2" uninstall; storestate S4-store-uninstall "$RE" "$ST"
RV="$W/root-move"; newroot "$RV"; mkdir -p "$RV/mnt/usb"; SV="$RV/mnt/usb/mi-lumruri"
RR="$RV" inst S5-move-base "$PKGS/v1" install --no-start
RR="$RV" inst S6-move "$PKGS/v2" install --no-start "--store=$SV"; storestate S6-move "$RV" "$SV"
RN="$W/root-nousb"; newroot "$RN"
RR="$RN" inst S7-store-absent "$PKGS/v1" install --no-start "--store=$RN/mnt/usb/mi-lumruri"; storestate S7-store-absent "$RN" "$RN/mnt/usb/mi-lumruri"
ls -A "$RN/data" >"$OUT/store-absent-data.txt"

# переименование 0.5.0: установленный 0.4.0 (/data/mi-trusttunnel) → установка новой версии переносит настройки
# в /data/mi-lumruri, оставляет ссылку, перерегистрирует автозапуск; откат на 0.4.0 работает через ссылку
if [ -d "$PKGS/old040" ]; then
  migstate() { # migstate <id> <корень>
    "$PY" -c 'import json,os,sys;r=sys.argv[2];n=r+"/data/mi-lumruri";o=r+"/data/mi-trusttunnel"
rd=lambda p: open(p).read().strip() if os.path.isfile(p) else None
fw=open(r+"/etc/config/firewall").read(); i=fw.find("config include '"'"'mitt'"'"'")
print(json.dumps({"id":sys.argv[1],"new_dir":os.path.isdir(n) and not os.path.islink(n),"old_link":os.readlink(o) if os.path.islink(o) else ("dir" if os.path.isdir(o) else None),
 "current":rd(n+"/current.ver") or rd(o+"/current.ver"),"previous":rd(n+"/previous.ver") or rd(o+"/previous.ver"),"marker":rd(n+"/etc/marker.txt"),"auth":os.path.isfile(n+"/etc/auth/auth.json"),
 "pinned":(rd(n+"/keys/release.pub") or "")[:16],"tmp_old":os.path.exists(r+"/tmp/mi-trusttunnel"),"fw":fw[i:i+260] if i>=0 else None,
 "stub_new":"/data/mi-lumruri" in (rd(n+"/mitt-boot.sh") or "")}))' "$1" "$2" >>"$OUT/migrate.jsonl"
  }
  : >"$OUT/migrate.jsonl"
  RG="$W/root-migrate"; newroot "$RG"
  RR="$RG" inst M1-old040 "$PKGS/old040" install --no-start
  mkdir -p "$RG/data/mi-trusttunnel/etc/auth"; echo user-settings >"$RG/data/mi-trusttunnel/etc/marker.txt"
  printf '{"lab":1}\n' >"$RG/data/mi-trusttunnel/etc/auth/auth.json"; mkdir -p "$RG/tmp/mi-trusttunnel/run"
  migstate M1-old040 "$RG"
  RR="$RG" inst M2-migrate-refused "$PKGS/v2" install --no-start; migstate M2-migrate-refused "$RG"
  LKEY="$(sed -n 's/.*у пакета \([0-9a-f]\{16\}\).*/\1/p' "$OUT/M2-migrate-refused.out" | head -n 1)"
  RR="$RG" inst M3-migrate "$PKGS/v2" install --no-start "--trust-key=${LKEY:-none}"; migstate M3-migrate "$RG"
  RR="$RG" inst M4-repeat "$PKGS/v2" install --no-start; migstate M4-repeat "$RG"
  RR="$RG" inst M5-rollback-040 "$PKGS/v2" rollback --no-start; migstate M5-rollback-040 "$RG"
  # служба 0.4 после отката работает из /tmp/mi-trusttunnel: новая установка останавливает её её же загрузчиком
  mkdir -p "$RG/tmp/mi-trusttunnel/scripts"; printf 'echo "$1" >>%s/old-boot.log\n' "$OUT" >"$RG/tmp/mi-trusttunnel/scripts/mitt-boot.sh"
  RR="$RG" inst M5b-reinstall "$PKGS/v2" install --no-start; migstate M5b-reinstall "$RG"
  RR="$RG" inst M6-uninstall "$PKGS/v2" uninstall; migstate M6-uninstall "$RG"
fi
log "готово"
