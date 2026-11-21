#!/bin/sh
# mi-trusttunnel: подписка TrustTunnel 1.3. По ссылке из secrets.json (https://user:pass@host/path, секрет) скачивает
# JSON с параметрами подключения и переносит его в настройки профиля (mi-tt-ctl subscription-import): адрес, имя
# сервера, логин, пароль, HTTP/3, anti-DPI, сертификат, префикс client_random. Изменилось — заявка на применение.
# Запускает служба: по расписанию списков сайтов и по кнопке панели (sub-update.request). Итог — $STATE/subscription.json.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
CURL="${MITT_CURL:-curl}"
P="${MITT_SUB_PROFILE:-tt}"
OUT="$STATE/subscription.json"
mkdir -p "$STATE" "$LOG"
rm -f "$STATE/sub-update.request.run"
url="$(ctl subscription-url "$ETC/config.json" "$P" 2>/dev/null)" || { rm -f "$OUT"; exit 0; }
tmp="$R/tmp/mitt-sub.$$.json"
now=$(date +%s)
prev_upd="$(sed -n 's/.*"updated":\([0-9]*\).*/\1/p' "$OUT" 2>/dev/null)"
js() { printf '%s' "$1" | tr -d '"\\' | tr '\n\r\t' '   ' | cut -c1-300; }
put() { # put <ok true|false> <updated|null> [ошибка]
  printf '{"ok":%s,"checked":%s,"updated":%s,"error":%s}\n' "$1" "$now" "$2" "$([ -n "${3:-}" ] && printf '"%s"' "$(js "$3")" || echo null)" >"$OUT.t" && mv -f "$OUT.t" "$OUT"
}
# ошибки curl без ссылки: в ней логин и пароль подписки
if ! "$CURL" -sSfL --proto '=https' --max-time 30 --max-filesize 262144 -o "$tmp" "$url" 2>"$LOG/sub-curl.log"; then
  e="$(tail -n 1 "$LOG/sub-curl.log" | sed 's#https://[^ ]*#<ссылка>#g')"
  rm -f "$tmp"; put false "${prev_upd:-null}" "сервер подписки не ответил: $e"; mlog "подписка: не скачана ($e)"; exit 1
fi
r="$(ctl subscription-import "$ETC/config.json" "$P" "$tmp" 2>&1)"; rc=$?
rm -f "$tmp"
if [ $rc -ne 0 ]; then
  e="$(printf '%s' "$r" | sed -n 's/.*"message": *"\([^"]*\)".*/\1/p' | head -n 1)"
  put false "${prev_upd:-null}" "ответ подписки не принят: ${e:-код $rc}"; mlog "подписка: не принята (${e:-код $rc})"; exit 1
fi
if printf '%s' "$r" | grep -q '"changed": *true'; then
  put true "$now"; mlog "подписка: параметры сервера обновлены, применяю"
else
  put true "${prev_upd:-null}"
fi
exit 0
