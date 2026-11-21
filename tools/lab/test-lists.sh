#!/usr/bin/env bash
# Готовые списки сайтов (package/scripts/mitt-lists.sh) на штатном BusyBox ash 1.25.1 (ARM64 из образа RC06 1.1.38 под
# qemu-user): sync из снимка релиза, update с заглушкой curl (MITT_CURL) и настоящим mi-tt-ctl ARM64 (category-check).
# Нужен `bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl`.
# Запуск — в WSL: bash tools/lab/test-lists.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"
[ -f "$CTL" ] || { echo "нет $CTL: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
"$Q" "$CTL" category-check domain "$ROOT/package/lists/Services/youtube.lst" >/dev/null 2>&1 || { echo "$CTL устарел (нет category-check): пересоберите"; exit 2; }
W="$(mktemp -d /tmp/mitt-lists.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }
t() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr; do
  if [ -e "$F/bin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
    printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  fi
done
chmod +x "$SB"/*

# заглушка curl: ответ по сценарию resp <путь> → ok | html | empty | 404 | offline; файлы «сервера» — $LT/remote
ST="$W/stub"; mkdir -p "$ST"
cat >"$ST/curl" <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
echo "$*" >>"$LT/curl.log"
out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift;; *) url="$1";; esac; shift; done
p="${url#https://lists.test/main/}"
. "$LT/scenario"
case "$(resp "$p")" in
  offline) echo "curl: (6) Could not resolve host: lists.test" >&2; exit 6;;
  404) echo "curl: (22) The requested URL returned error: 404" >&2; exit 22;;
  html) printf '<!DOCTYPE html>\n<html><body>Rate limit exceeded</body></html>\n' >"$out";;
  empty) : >"$out";;
  cert) echo "curl: (60) SSL certificate problem: certificate is not yet valid" >&2; exit 60;;
  short) printf 'youtube.com\nytimg.com\ngooglevideo.com\n' >"$out";;
  *) cat "$LT/remote/$p" >"$out";;
esac
EOF
chmod +x "$ST/curl"

# root <имя>: свежий корень «роутера» с релизом 0.9.0 (снимок списков из package/lists)
root() {
  local d="$W/$1/root"
  mkdir -p "$d/data/mi-lumruri/etc" "$d/data/mi-lumruri/releases/0.9.0/payload" "$d/tmp/mi-lumruri/bin" "$d/tmp/mi-lumruri/scripts" "$W/$1/lt"
  echo 0.9.0 >"$d/data/mi-lumruri/current.ver"
  cp -r "$ROOT/package/lists" "$d/data/mi-lumruri/releases/0.9.0/payload/lists"
  cp "$ROOT"/package/scripts/*.sh "$d/tmp/mi-lumruri/scripts/"
  printf '#!/bin/sh\nexec %s %s "$@"\n' "$Q" "$CTL" >"$d/tmp/mi-lumruri/bin/mi-tt-ctl"; chmod +x "$d/tmp/mi-lumruri/bin/mi-tt-ctl"
  cp -r "$ROOT/package/lists" "$W/$1/lt/remote"
  echo 'resp() { echo ok; }' >"$W/$1/lt/scenario"
}
# bb <имя> <аргументы ash…>: BusyBox стока с окружением
bb() {
  local n="$1"; shift
  timeout 600 env -i PATH="$SB" MITT_ROOT="$W/$n/root" MITT_QUIET=1 MITT_CURL="$ST/curl" MITT_LISTS_URL=https://lists.test/main LT="$W/$n/lt" \
    "$Q" -L "$F" "$F/bin/busybox" ash "$@"
}
lists() { bb "$1" "$W/$1/root/tmp/mi-lumruri/scripts/mitt-lists.sh" "$2" >>"$W/$1/out" 2>&1; echo "[$1] $2: код $?"; }
due() { bb "$1" -c '. "$MITT_ROOT/tmp/mi-lumruri/scripts/mitt-lib.sh"; lists_due'; }
j() { python3 -I -c 'import json,sys
s=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$W/$1/root/tmp/mi-lumruri/run/lists.json" "$2" 2>&1; }
check() { local r; r="$(j "$1" "$3")"; if [ "$r" = True ]; then ok "$1: $2"; else bad "$1: $2 → $r; lists.json: $(cat "$W/$1/root/tmp/mi-lumruri/run/lists.json" 2>/dev/null); вывод: $(tail -5 "$W/$1/out")"; fi; }
ino() { stat -c %i "$1" 2>/dev/null; }

NFILES="$(python3 -I -c 'import json,sys;c=json.load(open(sys.argv[1]));print(len(c["services"])+sum(1 for s in c["services"] if s["ipv4"]))' "$ROOT/package/lists/catalog.json")"
COMMIT="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["commit"])' "$ROOT/package/lists/catalog.json")"
SNAPDATE="$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["date"])' "$ROOT/package/lists/catalog.json")"
A="$W/a/root"; CATD="$A/data/mi-lumruri/etc/categories"; UPD="$A/data/mi-lumruri/lists"; RUNS="$A/tmp/mi-lumruri/run"

echo "(а) sync из пакета"
root a; lists a sync
t "a: svc-youtube.list — из снимка релиза" 'cmp -s "$CATD/svc-youtube.list" "$ROOT/package/lists/Services/youtube.lst"'
t "a: svc-meta-ip.list — подсети IPv4 из снимка" 'cmp -s "$CATD/svc-meta-ip.list" "$ROOT/package/lists/Subnets/IPv4/meta.lst"'
t "a: у YouTube подсетей в каталоге нет — svc-youtube-ip.list не создан" '[ ! -e "$CATD/svc-youtube-ip.list" ]'
t "a: все $NFILES файлов каталога разложены" '[ "$(ls "$CATD" | grep -c "^svc-.*\.list$")" = "$NFILES" ]'
I0="$(ino "$CATD/svc-youtube.list")"; lists a sync
t "a: повторный sync без изменений файл не переписывает" '[ "$(ino "$CATD/svc-youtube.list")" = "$I0" ]'

echo "(б) update: корректный ответ заменяет список"
printf '\nlab-new.example.com\n' >>"$W/a/lt/remote/Services/youtube.lst"
IM="$(ino "$CATD/svc-meta.list")"; lists a update
t "b: в /data — новая версия YouTube" 'grep -qx lab-new.example.com "$UPD/Services/youtube.lst"'
t "b: svc-youtube.list обновлён" 'grep -qx lab-new.example.com "$CATD/svc-youtube.list"'
t "b: неизменившийся svc-meta.list не переписан" '[ "$(ino "$CATD/svc-meta.list")" = "$IM" ]'
check a "ok, без ошибок, снимок $SNAPDATE, updated = checked" 's["ok"] is True and s["errors"]==[] and s["snapshot"]=="'"$SNAPDATE"'" and s["updated"]==s["checked"]>0'
t "b: заявка на применение от списков" 'grep -q "\"by\":\"lists\"" "$RUNS/apply.request"'
t "b: curl -fsS --max-time 30 для каждого из $NFILES файлов" '[ "$(grep -c -- "-fsS --max-time 30 -o " "$W/a/lt/curl.log")" = "$NFILES" ]'
t "b: метка .checked и копия состояния в /data" '[ -s "$UPD/.checked" ] && cmp -s "$UPD/.status" "$RUNS/lists.json"'
t "b: метка свежая — проверка не нужна" '! due a'
UPD1="$(j a 's["updated"]')"

echo "(в) update: HTML вместо списка, пустой файл, 404 — отказ, прежние файлы на месте"
rm -f "$RUNS/apply.request"; : >"$W/a/lt/curl.log"
cat >"$W/a/lt/scenario" <<'EOF'
resp() { case "$1" in Services/youtube.lst) echo html;; Services/meta.lst) echo empty;; Services/discord.lst) echo 404;; *) echo ok;; esac; }
EOF
lists a update
t "c: svc-youtube.list прежний (обновлённый в б)" 'grep -qx lab-new.example.com "$CATD/svc-youtube.list" && cmp -s "$CATD/svc-youtube.list" "$UPD/Services/youtube.lst"'
t "c: svc-meta.list прежний" 'cmp -s "$CATD/svc-meta.list" "$ROOT/package/lists/Services/meta.lst"'
check a "ok=false, три ошибки с именами файлов" 'not s["ok"] and len(s["errors"])==3 and s["errors"][0].startswith("Services/youtube.lst: ") and s["errors"][1].startswith("Services/meta.lst: ") and s["errors"][2].startswith("Services/discord.lst: ")'
check a "причины: проверка формата, пустой ответ, ошибка curl" '"проверка формата" in s["errors"][0] and "пустой" in s["errors"][1] and "404" in s["errors"][2]'
check a "updated не изменился" 's["updated"]=='"$UPD1"
t "c: после ошибки одного файла остальные проверены" '[ "$(wc -l <"$W/a/lt/curl.log")" = "$NFILES" ]'
t "c: ничего не изменилось — заявки на применение нет" '[ ! -e "$RUNS/apply.request" ]'
t "c: временных файлов не осталось" '[ -z "$(find "$UPD" -name "*.t*")" ] && [ ! -e "$A/tmp/mi-lumruri/lists-dl" ]'

echo "(г) без сети: ok=false, списки из пакета работают"
B="$W/g/root"; root g
echo 'resp() { echo offline; }' >"$W/g/lt/scenario"
t "g: без метки .checked проверка нужна сразу" 'due g'
lists g sync; lists g update
check g "ok=false, одна ошибка «нет связи», updated null" 'not s["ok"] and len(s["errors"])==1 and "нет связи" in s["errors"][0] and "Could not resolve host" in s["errors"][0] and s["updated"] is None'
t "g: после первой неудачи связи остальные файлы не запрашивались" '[ "$(wc -l <"$W/g/lt/curl.log")" = 1 ]'
t "g: svc-youtube.list — из пакета" 'cmp -s "$B/data/mi-lumruri/etc/categories/svc-youtube.list" "$ROOT/package/lists/Services/youtube.lst"'
t "g: в /data списков нет" '[ -z "$(find "$B/data/mi-lumruri/lists" -name "*.lst")" ]'
t "g: повтор не раньше чем через час (метка сдвинута)" '! due g && [ "$(( $(date +%s) - $(cut -d " " -f 1 "$B/data/mi-lumruri/lists/.checked") ))" -ge 82700 ]'
t "g: отсрочка в RAM (lists-next) — через час, снимок тот же" '[ "$(cut -d " " -f 2 "$B/tmp/mi-lumruri/run/lists-next")" = "$COMMIT" ] && [ "$(( $(cut -d " " -f 1 "$B/tmp/mi-lumruri/run/lists-next") - $(date +%s) ))" -ge 3500 ]'
# дальше проверяется метка .checked: отсрочки в RAM нет (как после перезагрузки)
rm -f "$B/tmp/mi-lumruri/run/lists-next"
t "g: метка из будущего (часы ушли назад) — проверка нужна" 'echo "$(( $(date +%s) + 999 )) $COMMIT" >"$B/data/mi-lumruri/lists/.checked"; due g'
t "g: прошли сутки — проверка нужна" 'echo "$(( $(date +%s) - 86401 )) $COMMIT" >"$B/data/mi-lumruri/lists/.checked"; due g'
t "g: метка свежая, коммит снимка тот же — проверка не нужна" 'echo "$(date +%s) $COMMIT" >"$B/data/mi-lumruri/lists/.checked"; ! due g'
t "g: отсрочка в RAM действует без метки .checked" 'rm -f "$B/data/mi-lumruri/lists/.checked"; echo "$(( $(date +%s) + 600 )) $COMMIT" >"$B/tmp/mi-lumruri/run/lists-next"; ! due g'
t "g: отсрочка дальше суток (часы ушли назад) не в счёт" 'echo "$(( $(date +%s) + 90000 )) $COMMIT" >"$B/tmp/mi-lumruri/run/lists-next"; due g'
t "g: истёкшая отсрочка — решает метка (её нет — проверка нужна)" 'echo "$(( $(date +%s) - 1 )) $COMMIT" >"$B/tmp/mi-lumruri/run/lists-next"; due g'

echo "(д) после перезагрузки (RAM пуста) состояние проверки восстанавливается из /data"
rm -f "$RUNS/lists.json"; lists a sync
t "d: lists.json восстановлен" 'cmp -s "$UPD/.status" "$RUNS/lists.json"'

echo "(е) повторное обновление: новая версия другого списка"
echo 'resp() { echo ok; }' >"$W/a/lt/scenario"; printf '\nlab-new2.example.com\n' >>"$W/a/lt/remote/Services/meta.lst"
lists a update
t "e: svc-meta.list обновлён (из /data)" 'grep -qx lab-new2.example.com "$CATD/svc-meta.list"'
check a "ok=true, updated новее" 's["ok"] is True and s["updated"]>='"$UPD1"

echo "(ж) пустая копия в /data — берётся снимок"
: >"$UPD/Services/meta.lst"; lists a sync
t "f: svc-meta.list — из снимка" 'cmp -s "$CATD/svc-meta.list" "$ROOT/package/lists/Services/meta.lst"'

echo "(з) обрезанный ответ (меньше половины записей) и ошибка сертификата"
cp "$CATD/svc-youtube.list" "$W/yt.before"
echo 'resp() { case "$1" in Services/youtube.lst) echo short;; *) echo ok;; esac; }' >"$W/a/lt/scenario"
lists a update
check a "ok=false, ошибка «меньше половины» у YouTube" 'not s["ok"] and len(s["errors"])==1 and s["errors"][0].startswith("Services/youtube.lst: ") and "меньше половины" in s["errors"][0]'
t "h: svc-youtube.list прежний" 'cmp -s "$CATD/svc-youtube.list" "$W/yt.before"'
: >"$W/a/lt/curl.log"; echo 'resp() { echo cert; }' >"$W/a/lt/scenario"
lists a update
check a "сертификат (код 60) — «нет связи», одна ошибка" 'not s["ok"] and len(s["errors"])==1 and "нет связи" in s["errors"][0] and "(60)" in s["errors"][0]'
t "h: после ошибки сертификата остальные не запрашивались, повтор через час" '[ "$(wc -l <"$W/a/lt/curl.log")" = 1 ] && ! due a && [ "$(( $(date +%s) - $(cut -d " " -f 1 "$UPD/.checked") ))" -ge 82700 ]'

echo "(и) новый релиз с другим снимком: старая копия в /data не используется"
REL2="$A/data/mi-lumruri/releases/0.9.0/payload/lists"
sed -i "s/$COMMIT/$(printf 'f%.0s' $(seq 40))/" "$REL2/catalog.json"
printf '\nsnap-new.example.com\n' >>"$REL2/Services/youtube.lst"
t "i: в /data старая копия YouTube (lab-new)" 'grep -qx lab-new.example.com "$UPD/Services/youtube.lst"'
lists a sync
t "i: svc-youtube.list — из нового снимка" 'cmp -s "$CATD/svc-youtube.list" "$REL2/Services/youtube.lst"'
t "i: сменился коммит снимка — проверка нужна сразу (метка и отсрочка свежие)" '[ -s "$RUNS/lists-next" ] && due a'
t "i: до проверки в /data — метки прежнего снимка (.updated, .status)" '[ -s "$UPD/.updated" ] && [ -s "$UPD/.status" ]'
echo 'resp() { echo offline; }' >"$W/a/lt/scenario"; lists a update
t "i: смена снимка убрала и скрытые .updated/.status: updated null" '[ ! -e "$UPD/.updated" ] && [ -z "$(ls "$UPD" | grep -v "^$")" ]'
check a "updated null после смены снимка" 's["updated"] is None and not s["ok"]'
rm -f "$RUNS/lists-next"
echo 'resp() { echo ok; }' >"$W/a/lt/scenario"; lists a update
t "i: после проверки .base — коммит нового снимка, YouTube снова из /data" '[ "$(cat "$UPD/.base")" = "$(printf "f%.0s" $(seq 40))" ] && grep -qx lab-new.example.com "$CATD/svc-youtube.list" && ! due a'

echo "(к) нет каталога: проверка не нужна, журнал — не чаще раза в час"
Z="$W/k/root"; root k; rm -f "$Z/data/mi-lumruri/releases/0.9.0/payload/lists/catalog.json"
t "k: без каталога проверка не нужна" '! due k'
lists k update; lists k update; lists k sync
t "k: «нет каталога» в журнале один раз" '[ "$(grep -c "нет каталога" "$Z/tmp/mi-lumruri/log/mitt.log")" = 1 ]'
t "k: метка повтора через час, curl не вызывался" '[ "$(( $(date +%s) - $(cut -d " " -f 1 "$Z/data/mi-lumruri/lists/.checked") ))" -ge 82700 ] && [ ! -e "$W/k/lt/curl.log" ]'

echo "(л) /data только для чтения: проверка не повторяется каждые 5 с, состояние видно"
if [ "$(id -u)" = 0 ]; then echo "  skip под root права каталога не действуют"
else
  L="$W/l/root"; root l; lists l sync
  mkdir -p "$L/data/mi-lumruri/lists"; chmod 555 "$L/data/mi-lumruri/lists"
  t "l: проверка нужна (метки нет)" 'due l'
  # служба проверяет lists_due каждые 5 с: десять «тиков» — один прогон update
  for i in 1 2 3 4 5 6 7 8 9 10; do due l && lists l update; done
  t "l: за 10 тиков curl прошёл по списку один раз" '[ "$(wc -l <"$W/l/lt/curl.log")" = "$NFILES" ]'
  check l "состояние в RAM: ok=false, ошибка про /data" 'not s["ok"] and any(e.startswith("/data: ") for e in s["errors"]) and s["checked"]>0'
  t "l: отсрочка в RAM — через час" '[ "$(( $(cut -d " " -f 1 "$L/tmp/mi-lumruri/run/lists-next") - $(date +%s) ))" -ge 3500 ] && ! due l'
  t "l: метки .checked нет, временных файлов нет" '[ ! -e "$L/data/mi-lumruri/lists/.checked" ] && [ -z "$(ls -A "$L/data/mi-lumruri/lists")" ]'
  t "l: списки из снимка работают" 'cmp -s "$L/data/mi-lumruri/etc/categories/svc-youtube.list" "$ROOT/package/lists/Services/youtube.lst"'
  chmod 755 "$L/data/mi-lumruri/lists"
fi

echo "(м) служба: итог рендера и полного применения — в status.json (mitt-lib.sh, BusyBox awk)"
M="$W/m/root"; root m; ME="$M/data/mi-lumruri/etc"; MS="$M/tmp/mi-lumruri/run"
echo '{"version": 1, "profiles": []}' >"$ME/config.json"; echo '{"version": 1}' >"$ME/secrets.json"
# заглушка mi-tt-admin: защитный вызов проходит, полный — сбой с сообщением (в нём кавычки и «\»)
cat >"$M/tmp/mi-lumruri/bin/mi-tt-admin" <<'STUB'
#!/bin/sh
case " $* " in *" --guard-only "*) echo '{ "ok": true }'; exit 0;; esac
echo '{'
echo '  "ok": false,'
echo '  "error": { "code": "apply_failed", "message": "iptables-restore: строка 3 \"x\" не принята" }'
echo '}'
exit 3
STUB
chmod +x "$M/tmp/mi-lumruri/bin/mi-tt-admin"
svc() { bb m -c '. "$MITT_ROOT/tmp/mi-lumruri/scripts/mitt-lib.sh"; mkdir -p "$STATE" "$LOG"; '"$1" >>"$W/m/out" 2>&1; }
sj() { python3 -I -c 'import json,sys
s=json.load(open(sys.argv[1])); r=s["render"]; a=s["apply"]; print(eval(sys.argv[2]))' "$MS/status.json" "$1" 2>&1; }
svc 'render_now; echo "render $?"; admin_apply panel-request; admin_apply panel-request-guard --guard-only; status_write'
cp "$MS/status.json" "$W/m/status.1.json" 2>/dev/null
t "m: render_now вернул 1" 'grep -q "^render 1" "$W/m/out"'
t "m: status.json разбирается; рендер не прошёл — причина из вывода mi-tt-ctl" '[ "$(sj '\''r["ok"] is False and "не разобраны" in r["error"] and r["at"] > 0'\'')" = True ]'
t "m: полное применение — код 3 и причина; защитный вызов после него её не скрыл" '[ "$(sj '\''a["exit"] == 3 and a["tag"] == "panel-request" and a["error"].endswith("строка 3 " + chr(39) + "x" + chr(39) + " не принята") and s["last_apply"]["exit"] == 0'\'')" = True ]'
echo '{"version": 1, "default_action": {"type": "direct"}}' >"$ME/config.json"
echo '#!/bin/sh
echo "{ \"ok\": true }"' >"$M/tmp/mi-lumruri/bin/mi-tt-admin"
svc 'render_now; admin_apply panel-request; status_write'
t "m: удачные рендер и применение — ok, exit 0, без ошибки" '[ "$(sj '\''r == {"ok": True, "at": r["at"]} and a["exit"] == 0 and a["error"] is None'\'')" = True ]'
[ "$FAIL" -eq 0 ] || echo "  вывод (м): $(tail -5 "$W/m/out"); status.json после сбоя: $(cat "$W/m/status.1.json" 2>/dev/null)"

[ $FAIL -eq 0 ] && echo "PASS" || echo "FAIL"
exit $FAIL
