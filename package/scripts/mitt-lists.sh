#!/bin/sh
# mi-lumruri: готовые списки сайтов (снимок itdoginfo/allow-domains в релизе, обновления — в /data).
#   mitt-lists.sh sync   — $ETC/categories/svc-<id>.list (домены) и svc-<id>-ip.list (IPv4) по каталогу релиза: из $DATA/lists
#                          (обновлённый файл), иначе из payload/lists релиза; файл переписывается только при изменении.
#                          Служба вызывает перед каждым render.
#   mitt-lists.sh update — загрузка свежих файлов (curl стока, обычный маршрут роутера), проверка mi-tt-ctl category-check,
#                          атомарная замена в $DATA/lists; файл с ошибкой не применяется, прежний остаётся. Итог —
#                          $STATE/lists.json (копия — $DATA/lists/.status); если что-то изменилось — sync и заявка на
#                          применение. Служба запускает в фоне раз в сутки (метка $DATA/lists/.checked, отсрочка в RAM
#                          $STATE/lists-next — см. lists_due) и по заявке панели (lists-update.request).
# Обновления в /data привязаны к коммиту снимка, на котором они сделаны ($DATA/lists/.base): после установки релиза
# с другим снимком они не используются, пока следующая проверка (она нужна сразу, см. lists_due) не загрузит свежие.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
CURL="${MITT_CURL:-curl}"
URL="${MITT_LISTS_URL:-https://raw.githubusercontent.com/itdoginfo/allow-domains/main}"
SNAP="$REL/payload/lists"; UPD="$DATA/lists"; CAT="$LISTS_CAT"

# строки «<id> <файл доменов> <файл IPv4|->» из каталога (JSON с отступами, его пишет tools/fetch-lists.sh);
# запись с недопустимым id или путём пропускается
rows() {
  awk 'function v(k,  s) { s = $0; sub(".*\"" k "\": *\"", "", s); sub("\".*", "", s); return s }
    function okp(p) { return p ~ /^[A-Za-z0-9_][A-Za-z0-9_.\/-]*$/ && p !~ /\.\./ }
    /"id":/ { id = v("id") } /"domains":/ { dm = v("domains") }
    /"ipv4":/ { ip = ($0 ~ /"ipv4": *null/) ? "-" : v("ipv4") }
    /}/ { if (id ~ /^[a-z0-9][a-z0-9_-]*$/ && okp(dm) && (ip == "-" || okp(ip))) print id, dm, ip; id = ""; dm = ""; ip = "-" }
    BEGIN { ip = "-" }' "$CAT"
}
snapshot() { sed -n 's/^ *"date": *"\([0-9-]*\)".*/\1/p' "$CAT" | head -n 1; }
# обновления из /data — только сделанные на снимке текущего релиза; пустой файл не в счёт
USE_UPD=""; [ -f "$CAT" ] && [ "$(cat "$UPD/.base" 2>/dev/null)" = "$(lists_commit)" ] && USE_UPD=1
src() { if [ -n "$USE_UPD" ] && [ -s "$UPD/$1" ]; then echo "$UPD/$1"; else echo "$SNAP/$1"; fi; }
entries() { awk 'NF && $1 !~ /^#/ { n++ } END { print n + 0 }' "$1"; }
# нет каталога (релиз на неподключённом накопителе?) — в журнал не чаще раза в час
nocat() {
  local l now; now="$(date +%s)"; l="$(cat "$STATE/lists-nocat" 2>/dev/null)"
  case "$l" in ''|*[!0-9]*) l=0;; esac
  [ $((now - l)) -ge "$LISTS_RETRY" ] || [ "$l" -gt "$now" ] || return 0
  mkdir -p "$STATE"; echo "$now" >"$STATE/lists-nocat"; mlog "списки: нет каталога $CAT — действуют прежние"
}

put() { # put <источник> <цель>: запись только при изменении (атомарно)
  [ -f "$1" ] || { mlog "списки: нет файла $1"; return 1; }
  cmp -s "$1" "$2" && return 0
  { cp "$1" "$2.t$$" && mv -f "$2.t$$" "$2"; } || { rm -f "$2.t$$"; mlog "списки: не записан $2"; return 1; }
  SYNCED="$SYNCED $(basename "$2" .list)"
}

lists_sync() {
  local id dm ip
  SYNCED=""
  # состояние последней проверки переживает перезагрузку: копия в /data
  [ -f "$STATE/lists.json" ] || [ ! -f "$UPD/.status" ] || { mkdir -p "$STATE"; cp "$UPD/.status" "$STATE/lists.json"; }
  [ -f "$CAT" ] || { nocat; return 0; }
  mkdir -p "$ETC/categories"
  lock_take lists-sync 30 || { mlog "списки: синхронизация занята"; return 1; }
  while read -r id dm ip; do
    [ -n "$id" ] || continue
    put "$(src "$dm")" "$ETC/categories/svc-$id.list"
    [ "$ip" = - ] || put "$(src "$ip")" "$ETC/categories/svc-$id-ip.list"
  done <<EOF
$(rows)
EOF
  lock_drop lists-sync
  [ -z "$SYNCED" ] || mlog "списки: обновлены категории$SYNCED"
  return 0
}

lists_update() {
  local now t f k p rc why cur n0 n1 base x ok_n=0 errs="" changed="" upd=null ok=true
  now="$(date +%s)"; mkdir -p "$UPD" "$STATE"
  if [ ! -f "$CAT" ]; then
    echo "$((now - LISTS_PERIOD + LISTS_RETRY)) -" >"$UPD/.checked.t" && mv -f "$UPD/.checked.t" "$UPD/.checked"
    echo "$((now + LISTS_RETRY)) -" >"$STATE/lists-next"
    nocat; return 0
  fi
  lock_take lists-update 1 || { mlog "списки: обновление уже идёт"; return 0; }
  base="$(lists_commit)"
  if [ -z "$USE_UPD" ]; then
    # релиз с другим снимком: прежние обновления не используются — убрать и начать от снимка этого релиза
    for x in "$UPD"/* "$UPD/.updated" "$UPD/.status"; do [ -e "$x" ] && rm -rf "$x"; done
    echo "$base" >"$UPD/.base.t" && mv -f "$UPD/.base.t" "$UPD/.base" && USE_UPD=1
  fi
  t="$RUN/lists-dl"; rm -rf "$t"; mkdir -p "$t"; f="$t/file"
  err() { errs="$errs,\"$1: $2\""; }
  while read -r k p; do
    [ -n "$p" ] || continue
    rm -f "$f"
    "$CURL" -fsS --max-time 30 -o "$f" "$URL/$p" 2>"$t/err" </dev/null; rc=$?
    if [ "$rc" -ne 0 ]; then
      why="$(head -n 1 "$t/err" | tr -cd ' -~' | sed 's/["\\]//g' | cut -c 1-160)"
      # нет связи (имя, соединение, таймаут, TLS, сертификат, нет curl) и ничего ещё не скачано — остальное не пробовать
      case "$rc" in 6|7|28|35|60|127) [ "$ok_n" -gt 0 ] || { err "$p" "нет связи ($why); остальные файлы не проверялись"; break; };; esac
      err "$p" "загрузка не удалась ($why)"; continue
    fi
    [ -s "$f" ] || { err "$p" "пустой ответ"; continue; }
    ctl category-check "$k" "$f" >"$t/check" 2>&1 </dev/null || { err "$p" "ответ не похож на список (проверка формата не прошла)"; continue; }
    ok_n=$((ok_n + 1))
    cur="$(src "$p")"
    # обрезанный ответ: меньше половины записей действующего списка — не применять
    n1="$(entries "$f")"; n0=0; [ ! -s "$cur" ] || n0="$(entries "$cur")"
    [ $((n1 * 2)) -ge "$n0" ] || { err "$p" "в ответе $n1 записей против $n0 в действующем списке (меньше половины)"; continue; }
    cmp -s "$f" "$cur" || changed="$changed $p"
    # в /data — всегда последняя проверенная версия
    cmp -s "$f" "$UPD/$p" && continue
    { mkdir -p "$(dirname "$UPD/$p")" && cp "$f" "$UPD/$p.t" && mv -f "$UPD/$p.t" "$UPD/$p"; } || { err "$p" "запись в /data не удалась"; rm -f "$UPD/$p.t"; }
  done <<EOF
$(rows | awk '{ print "domain", $2; if ($3 != "-") print "ip", $3 }')
EOF
  [ -z "$changed" ] || echo "$now" >"$UPD/.updated"
  k="$(cat "$UPD/.updated" 2>/dev/null)"; case "$k" in ''|*[!0-9]*) ;; *) upd="$k";; esac
  # метка — после загрузок; ни одного файла не получено (нет связи) — следующая попытка через час, а не через сутки
  k="$now"; [ "$ok_n" -gt 0 ] || k=$((now - LISTS_PERIOD + LISTS_RETRY))
  { echo "$k $base" >"$UPD/.checked.t" && mv -f "$UPD/.checked.t" "$UPD/.checked"; } 2>/dev/null || { rm -f "$UPD/.checked.t"; err "/data" "метка проверки не записана (нет места или раздел только для чтения)"; k=$((now - LISTS_PERIOD + LISTS_RETRY)); }
  # отсрочка в RAM — всегда: при незаписываемом /data без неё служба запускала бы проверку каждые 5 с
  echo "$((k + LISTS_PERIOD)) $base" >"$STATE/lists-next"
  [ -z "$errs" ] || ok=false
  # состояние для панели — прямо в RAM, копия в /data (переживает перезагрузку) — если получится
  printf '{"snapshot":"%s","updated":%s,"checked":%s,"ok":%s,"errors":[%s]}\n' "$(snapshot)" "$upd" "$now" "$ok" "${errs#,}" >"$STATE/lists.json.t" \
    && mv -f "$STATE/lists.json.t" "$STATE/lists.json" && { cp "$STATE/lists.json" "$UPD/.status.t" && mv -f "$UPD/.status.t" "$UPD/.status"; } 2>/dev/null
  rm -f "$UPD/.status.t" 2>/dev/null
  rm -rf "$t"
  if [ -n "$changed" ]; then
    lists_sync
    printf '{"requested_unix":%s,"by":"lists"}\n' "$now" >"$STATE/apply.request"
    mlog "списки: загружены новые версии:$changed"
  fi
  [ "$ok" = true ] && mlog "списки: проверка обновлений — без ошибок" || mlog "списки: проверка обновлений — ошибки: ${errs#,}"
  lock_drop lists-update
}

case "${1:-}" in
  sync) lists_sync;;
  update) lists_update;;
  *) echo "использование: mitt-lists.sh sync|update" >&2; exit 2;;
esac
