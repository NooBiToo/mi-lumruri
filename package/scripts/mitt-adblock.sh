#!/bin/sh
# mi-trusttunnel: загрузка списка блокировки рекламы. Ссылку выбирает панель (рендер пишет $RENDER/adblock.url);
# список проверяет mi-tt-ctl adblock-check (HTML, пусто, много мусора — отказ, единичные кривые строки пропускаются).
# Рабочая копия — в RAM ($RUN/adblock.list), сжатая — в /data ($DATA/adblock.list.gz): после перезагрузки блокировка
# работает сразу, до новой загрузки. Итог — $STATE/adblock.json для панели; новый список применяется заявкой apply.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
URL_FILE="$RENDER/adblock.url"
[ -f "$URL_FILE" ] || exit 0
url="$(head -n 1 "$URL_FILE")"
now="$(date +%s)"
period="$LISTS_PERIOD"

state() { # state <ok:true|false> <доменов> <ошибка>
  local err; err="$(printf '%s' "$3" | tr '"\\\n' "' " | cut -c1-200)"
  printf '{"ok":%s,"checked":%s,"updated":%s,"domains":%s,"url":"%s","error":%s}\n' "$1" "$now" \
    "$(cat "$RUN/adblock.updated" 2>/dev/null || echo null)" "${2:-null}" "$url" "$( [ -n "$err" ] && printf '"%s"' "$err" || echo null)" \
    >"$STATE/adblock.json.t" && mv -f "$STATE/adblock.json.t" "$STATE/adblock.json"
}
fail() { state false "" "$1"; echo "$((now + LISTS_RETRY)) $url" >"$STATE/adblock-next"; mlog "реклама: $1"; exit 1; }

tmp="$RUN/adblock.dl"
curl -sSfL --proto '=https' --max-time 120 --max-filesize 12582912 -o "$tmp" "$url" 2>"$LOG/adblock-curl.log" \
  || { rm -f "$tmp"; fail "список не скачан: $(tail -n 1 "$LOG/adblock-curl.log")"; }
res="$(ctl adblock-check "$tmp" 2>&1)" || { rm -f "$tmp"; fail "список не прошёл проверку: $(printf '%s' "$res" | sed -n 's/.*"message": *"\([^"]*\)".*/\1/p' | tail -n 1)"; }
n="$(printf '%s' "$res" | sed -n 's/.*"domains": *\([0-9]*\).*/\1/p' | head -n 1)"

changed=1
if [ -f "$RUN/adblock.list" ] && cmp -s "$tmp" "$RUN/adblock.list" && [ "$(cat "$RUN/adblock.src" 2>/dev/null)" = "$url" ]; then changed=0; fi
mv -f "$tmp" "$RUN/adblock.list"; echo "$url" >"$RUN/adblock.src"
if [ "$changed" = 1 ]; then
  echo "$now" >"$RUN/adblock.updated"
  # копия для загрузки роутера: сжатая, чтобы не занимать /data (нет места — блокировка работает до перезагрузки)
  if gzip -c "$RUN/adblock.list" >"$DATA/adblock.list.gz.t" 2>/dev/null && mv -f "$DATA/adblock.list.gz.t" "$DATA/adblock.list.gz"; then
    echo "$url" >"$DATA/adblock.src"
  else
    rm -f "$DATA/adblock.list.gz.t"; mlog "реклама: копия списка в /data не записана (нет места?)"
  fi
  touch "$STATE/apply.request"
  mlog "реклама: список обновлён (${n:-?} доменов)"
fi
state true "$n" ""
echo "$((now + period)) $url" >"$STATE/adblock-next"
