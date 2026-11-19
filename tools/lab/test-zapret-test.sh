#!/usr/bin/env bash
# Подбор стратегии Zapret (package/scripts/mitt-zapret-test.sh) на штатном BusyBox ash 1.25.1 (ARM64 из образа RC06 1.1.38
# под qemu-user) с заглушками curl, nfqws2 и mi-tt-ctl. Сеть и очереди не нужны: заглушка curl «открывает» первые K целей,
# K зависит от стратегии, которую сейчас «запустила» заглушка nfqws2. Запуск — в WSL: bash tools/lab/test-zapret-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
W="$(mktemp -d /tmp/mitt-zt.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

# апплеты BusyBox стока через qemu-user: недостающий в образе апплет — «not found», как на роутере
SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut sort date sleep usleep kill basename dirname touch printf echo test expr seq; do
  if [ -e "$F/bin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
    printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  fi
done
chmod +x "$SB"/*

# заглушки (обычные сценарии хоста)
ST="$W/stub"; mkdir -p "$ST"
cat >"$ST/mi-tt-ctl" <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
case "$1" in
  zapret-list) if [ "$2" = general ]; then printf 'v%s\n' 1 2 3 4 5 6 7 8 9 10; else printf 'yv%s\n' 1 2 3; fi;;
  zapret-args) printf -- '--qnum=201\n--fwmark=0x40000000\n--zt-id=%s\n' "$2";;
  zapret-set)
    k=strategy; [ "$3" = youtube ] && k=youtube
    prev="$(sed -n "s/.*\"$k\": *\"\([^\"]*\)\".*/\1/p" "$2")"
    sed -i "s/\"$k\": *\"[^\"]*\"/\"$k\": \"$4\"/" "$2"
    echo "zapret-set $3 $4" >>"$ZT/calls"
    printf '{\n  "ok": true,\n  "field": "%s",\n  "previous": "%s",\n  "id": "%s"\n}\n' "$3" "$prev" "$4";;
  *) echo "неожиданный вызов mi-tt-ctl $*" >>"$ZT/errors"; exit 2;;
esac
EOF
cat >"$ST/nfqws2" <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
for a; do case "$a" in --zt-id=*) id="${a#--zt-id=}";; esac; done
case " $* " in *" --qnum=201 "*) ;; *) echo "nfqws2 не на проверочной очереди: $*" >>"$ZT/errors";; esac
echo "$id" >"$ZT/current"
trap 'rm -f "$ZT/current"; exit 0' TERM INT
while :; do sleep 0.1; done
EOF
cat >"$ST/curl" <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
for a; do url="$a"; done
cur="$(cat "$ZT/current" 2>/dev/null)"; [ -n "$cur" ] || cur=control
case " $* " in *" --local-port 61000-61099 "*) ;; *) echo "curl без проверочных портов: $*" >>"$ZT/errors";; esac
echo "$cur $url" >>"$ZT/curl.log"
. "$ZT/scenario"
k="$(lim "$cur" "$url")"
n="${url#https://t}"; n="${n%%.*}"
case "$url" in https://t*) ;; *) n=1;; esac
if [ "$n" -le "$k" ]; then printf '200 1024'; exit 0; fi
printf '000 0'; exit 28
EOF
chmod +x "$ST"/*

TEN='required https://t1.test/
required https://t2.test/
required https://t3.test/
required https://t4.test/
required https://t5.test/
optional https://t6.test/
optional https://t7.test/
optional https://t8.test/
optional https://t9.test/
optional https://t10.test/'

# run <имя> <цели> <сценарий (функция lim)>: свежий корень, запуск под BusyBox; результат в $W/<имя>
run() {
  local n="$1" d="$W/$1"
  local RR="$d/root" ZT="$d/zt"
  mkdir -p "$ZT" "$RR/data/mi-trusttunnel/etc" "$RR/tmp/mi-trusttunnel/bin" "$RR/tmp/mi-trusttunnel/scripts"
  cp "$ROOT"/package/scripts/*.sh "$RR/tmp/mi-trusttunnel/scripts/"
  cp "$ST/mi-tt-ctl" "$RR/tmp/mi-trusttunnel/bin/"
  [ -n "${NOZAP:-}" ] || { mkdir -p "$RR/tmp/mi-trusttunnel/render"; echo --qnum=200 >"$RR/tmp/mi-trusttunnel/render/nfqws2.args"; }
  printf '%s\n' "$2" >"$d/targets.txt"
  printf '%s\n' "$3" >"$ZT/scenario"
  printf '{\n  "version": 1,\n  "zapret": {\n    "strategy": "auto",\n    "youtube": "auto"\n  }\n}\n' >"$RR/data/mi-trusttunnel/etc/config.json"
  cp "$RR/data/mi-trusttunnel/etc/config.json" "$d/config.before"
  local t0=$(date +%s)
  timeout 300 env -i PATH="$SB" MITT_ROOT="$RR" MITT_QUIET=1 MITT_CURL="$ST/curl" MITT_NFQWS="$ST/nfqws2" MITT_ZAPRET_TARGETS="$d/targets.txt" \
    MITT_ZT_SETTLE=0 ZT="$ZT" ZSTATE="$RR/tmp/mi-trusttunnel/run" \
    "$Q" -L "$F" "$F/bin/busybox" ash "$RR/tmp/mi-trusttunnel/scripts/mitt-zapret-test.sh" >"$d/out" 2>&1
  echo "$?" >"$d/rc"
  echo "[$n] код $(cat "$d/rc"), $(( $(date +%s) - t0 )) с"
  [ -s "$ZT/errors" ] && bad "$n: $(cat "$ZT/errors")"
  [ -f "$RR/tmp/mi-trusttunnel/run/zapret-nfqws.pid" ] && bad "$n: проверочный nfqws2 не остановлен"
  pgrep -f "$ST/nfqws2" >/dev/null && { bad "$n: процесс заглушки nfqws2 жив"; pkill -f "$ST/nfqws2"; }
  return 0
}
# j <имя> <выражение python над s (состояние) и c (настройки)>
j() {
  local d="$W/$1"
  python3 -I -c 'import json,sys
d=sys.argv[1]; s=json.load(open(d+"/root/tmp/mi-trusttunnel/run/zapret-test.json")); c=json.load(open(d+"/root/data/mi-trusttunnel/etc/config.json"))
import os; areq=os.path.exists(d+"/root/tmp/mi-trusttunnel/run/apply.request")
r=eval(sys.argv[2]); print(r)' "$d" "$2" 2>&1
}
check() { # check <имя> <описание> <выражение>
  local r; r="$(j "$1" "$3")"
  if [ "$r" = True ]; then ok "$1: $2"; else bad "$1: $2 → $r; состояние: $(cat "$W/$1/root/tmp/mi-trusttunnel/run/zapret-test.json" 2>/dev/null); вывод: $(tail -5 "$W/$1/out")"; fi
}

echo "(а) контроль 2/10, v3 9/10, остальные 4/10"
run a "$TEN" 'lim() { case "$1" in control) echo 2;; v3) echo 9;; *) echo 4;; esac; }'
check a "готово, победитель v3, применено" 's["state"]=="done" and s["best"]["id"]=="v3" and s["best"]["opened"]==9 and s["applied"] is True'
check a "контроль 2 из 10" 's["control"]=={"opened":2,"total":10}'
check a "в настройках strategy = v3, youtube прежний" 'c["zapret"]=={"strategy":"v3","youtube":"auto"}'
check a "заявка на применение" 'areq'
check a "прогресс: все стратегии пройдены" 's["progress"]["done"]==s["progress"]["total"]==11 and s["finished"]>=s["started"]'
check a "итог по-русски" '"9 из 10" in s["message"] and "без Zapret — 2" in s["message"]'
grep -q 'v3 https://t1.test/' "$W/a/zt/curl.log" && [ "$(grep -c '^v3 ' "$W/a/zt/curl.log")" = 20 ] && ok "a: v3 проверена дважды (повторная проверка)" || bad "a: повторной проверки v3 нет"

echo "(б) все стратегии не лучше контроля"
run b "$TEN" 'lim() { case "$1" in control) echo 4;; *) echo 4;; esac; }'
check b "готово, не применено" 's["state"]=="done" and s["applied"] is False'
check b "сообщение" 's["message"]=="Подходящей стратегии лучше, чем без Zapret, не нашлось"'
cmp -s "$W/b/config.before" "$W/b/root/data/mi-trusttunnel/etc/config.json" && ok "b: настройки не изменены" || bad "b: настройки изменены"
check b "без заявки на применение" 'not areq'

echo "(в) прерывание посреди подбора"
run c "$TEN" 'lim() { [ "$1" = v4 ] && touch "$ZSTATE/zapret-test.stop"; case "$1" in control) echo 2;; v3) echo 9;; *) echo 4;; esac; }'
check c "прервано" 's["state"]=="failed" and s["applied"] is False and s["finished"] is not None'
cmp -s "$W/c/config.before" "$W/c/root/data/mi-trusttunnel/etc/config.json" && ok "c: настройки не изменены" || bad "c: настройки изменены"
check c "без заявки на применение" 'not areq'
grep -q '^v5 ' "$W/c/zt/curl.log" && bad "c: после прерывания проверка продолжилась" || ok "c: после прерывания стратегии не проверялись"

echo "(г) повторная проверка хуже — откат"
run d "$TEN" 'lim() { case "$1" in control) echo 2;; v3) if [ "$(grep -c "^v3 " "$ZT/curl.log")" -gt 10 ]; then echo 1; else echo 9; fi;; *) echo 4;; esac; }'
check d "готово, откат" 's["state"]=="done" and s["applied"] is False and c["zapret"]["strategy"]=="auto"'
grep -q 'zapret-set general auto' "$W/d/zt/calls" && ok "d: возврат к прежней стратегии" || bad "d: возврата нет: $(cat "$W/d/zt/calls" 2>/dev/null)"

echo "(д) YouTube не открылся — проход по yv*"
run e "required https://t1.test/
required https://t2.test/
optional https://t3.test/
required https://www.youtube.com/
required https://redirector.googlevideo.com/report_mapping" \
  'lim() { case "$2" in *youtube*|*googlevideo*) [ "$1" = yv2 ] && echo 1 || echo 0;; *) echo 2;; esac; }'
check e "готово, YouTube — yv2" 's["state"]=="done" and s["applied"] is True and c["zapret"]=={"strategy":"auto","youtube":"yv2"}'
check e "результат YouTube" 's["youtube"]=={"id":"yv2","opened":2,"total":2}'
check e "прогресс включает yv*" 's["progress"]["total"]==14 and s["progress"]["done"]==14'
grep -q '^yv1 https://t1.test/' "$W/e/zt/curl.log" && bad "e: в проходе YouTube проверялись другие цели" || ok "e: в проходе YouTube — только цели YouTube"

echo "(е) Zapret не включён — подбор не начинается"
NOZAP=1 run f "$TEN" 'lim() { echo 9; }'
check f "отказ с объяснением" 's["state"]=="failed" and "Zapret не включён" in s["message"] and not areq'
[ -f "$W/f/zt/curl.log" ] && bad "f: проверочные запросы были" || ok "f: проверочных запросов не было"

[ $FAIL -eq 0 ] && echo "PASS" || echo "FAIL"
exit $FAIL
