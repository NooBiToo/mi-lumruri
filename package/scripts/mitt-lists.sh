#!/bin/sh
# mi-trusttunnel: готовые списки сайтов (снимок itdoginfo/allow-domains в релизе, обновления — в /data).
#   mitt-lists.sh sync   — $ETC/categories/svc-<id>.list (домены) и svc-<id>-ip.list (IPv4) по каталогу релиза: из $DATA/lists
#                          (обновлённый файл), иначе из payload/lists релиза; файл переписывается только при изменении.
#                          Служба вызывает перед каждым render.
#   mitt-lists.sh update — загрузка свежих файлов (curl стока, обычный маршрут роутера), проверка mi-tt-ctl category-check,
#                          атомарная замена в $DATA/lists; файл с ошибкой не применяется, прежний остаётся. Итог —
#                          $STATE/lists.json; если что-то изменилось — sync и заявка на применение. Служба запускает в фоне
#                          раз в сутки (метка $DATA/lists/.checked) и по заявке панели (lists-update.request).
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
CURL="${MITT_CURL:-curl}"
URL="${MITT_LISTS_URL:-https://raw.githubusercontent.com/itdoginfo/allow-domains/main}"
SNAP="$REL/payload/lists"; UPD="$DATA/lists"; CAT="$SNAP/catalog.json"

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
src() { if [ -f "$UPD/$1" ]; then echo "$UPD/$1"; else echo "$SNAP/$1"; fi; }

put() { # put <источник> <цель>: запись только при изменении (атомарно)
  [ -f "$1" ] || { mlog "списки: нет файла $1"; return 1; }
  cmp -s "$1" "$2" && return 0
  cp "$1" "$2.t$$" && mv -f "$2.t$$" "$2" && SYNCED="$SYNCED $(basename "$2" .list)"
}

lists_sync() {
  local id dm ip
  SYNCED=""
  # состояние последней проверки переживает перезагрузку: копия в /data
  [ -f "$STATE/lists.json" ] || [ ! -f "$UPD/.status" ] || { mkdir -p "$STATE"; cp "$UPD/.status" "$STATE/lists.json"; }
  [ -f "$CAT" ] || { mlog "списки: нет каталога $CAT — оставлены прежние"; return 1; }
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
  local now t f k p rc why ok_n=0 errs="" changed="" upd=null ok=true
  [ -f "$CAT" ] || { mlog "списки: нет каталога $CAT"; return 1; }
  lock_take lists-update 1 || { mlog "списки: обновление уже идёт"; return 0; }
  now="$(date +%s)"; mkdir -p "$UPD" "$STATE"; echo "$now" >"$UPD/.checked"
  t="$RUN/lists-dl"; rm -rf "$t"; mkdir -p "$t"; f="$t/file"
  err() { errs="$errs,\"$1: $2\""; }
  while read -r k p; do
    [ -n "$p" ] || continue
    rm -f "$f"
    "$CURL" -fsS --max-time 30 -o "$f" "$URL/$p" 2>"$t/err" </dev/null; rc=$?
    if [ "$rc" -ne 0 ]; then
      why="$(head -n 1 "$t/err" | tr -cd ' -~' | sed 's/["\\]//g' | cut -c 1-160)"
      # нет связи (имя не разрешилось, соединение, таймаут, TLS, нет curl) и ничего ещё не скачано — остальное не пробовать
      case "$rc" in 6|7|28|35|127) [ "$ok_n" -gt 0 ] || { err "$p" "нет связи ($why); остальные файлы не проверялись"; break; };; esac
      err "$p" "загрузка не удалась ($why)"; continue
    fi
    [ -s "$f" ] || { err "$p" "пустой ответ"; continue; }
    ctl category-check "$k" "$f" >"$t/check" 2>&1 </dev/null || { err "$p" "ответ не похож на список (проверка формата не прошла)"; continue; }
    ok_n=$((ok_n + 1))
    cmp -s "$f" "$(src "$p")" || changed="$changed $p"
    # в /data — всегда последняя проверенная версия (свежее снимка нового релиза)
    cmp -s "$f" "$UPD/$p" && continue
    mkdir -p "$(dirname "$UPD/$p")" && cp "$f" "$UPD/$p.t" && mv -f "$UPD/$p.t" "$UPD/$p" || { err "$p" "запись в /data не удалась"; rm -f "$UPD/$p.t"; }
  done <<EOF
$(rows | awk '{ print "domain", $2; if ($3 != "-") print "ip", $3 }')
EOF
  [ -z "$changed" ] || echo "$now" >"$UPD/.updated"
  k="$(cat "$UPD/.updated" 2>/dev/null)"; case "$k" in ''|*[!0-9]*) ;; *) upd="$k";; esac
  [ -z "$errs" ] || ok=false
  # ни одного файла не получено (нет связи) — следующая попытка через час, а не через сутки
  [ "$ok_n" -gt 0 ] || echo $((now - LISTS_PERIOD + LISTS_RETRY)) >"$UPD/.checked"
  printf '{"snapshot":"%s","updated":%s,"checked":%s,"ok":%s,"errors":[%s]}\n' "$(snapshot)" "$upd" "$now" "$ok" "${errs#,}" >"$UPD/.status.t" \
    && cp "$UPD/.status.t" "$STATE/lists.json.t" && mv -f "$STATE/lists.json.t" "$STATE/lists.json" && mv -f "$UPD/.status.t" "$UPD/.status"
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
