#!/bin/sh
# mi-lumruri: подписки серверов. Для каждого сервера со ссылкой-подпиской в secrets.json (секрет: в ней логин и пароль):
#  - TrustTunnel 1.3 — JSON с параметрами подключения → mi-tt-ctl subscription-import (адрес, имя сервера, логин,
#    пароль, HTTP/3, anti-DPI, сертификат, префикс client_random);
#  - модуль sing-box — список ссылок vless://, hysteria2://, trojan://, ss:// (обычно base64) → mi-tt-ctl proxy-sub-import
#    (список в etc/sub/<id>.json, выбранный сервер — в настройки и секрет link).
# Изменилось — заявка на применение (её ставит mi-tt-ctl). Запускает служба: по расписанию списков сайтов и по кнопке
# панели (sub-update.request). Итог по серверу — $STATE/sub/<id>.json; серверов с подпиской нет — каталог очищается.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
CURL="${MITT_CURL:-curl}"
mkdir -p "$STATE/sub" "$LOG"
rm -f "$STATE/sub-update.request.run"
LIST="$R/tmp/mitt-sub.$$.list"
ctl subscription-list "$ETC/config.json" >"$LIST" 2>/dev/null || : >"$LIST"
# состояние серверов, у которых подписки больше нет
for f in "$STATE"/sub/*.json; do
  [ -f "$f" ] || continue; id="$(basename "$f" .json)"
  grep -q "^$id " "$LIST" || rm -f "$f" "$STATE/sub/$id.ping"
done
js() { printf '%s' "$1" | tr -d '"\\' | tr '\n\r\t' '   ' | cut -c1-300; }
# задержка до серверов последнего списка подписки (TCP-подключение с роутера, по 8 сразу) → $STATE/sub/<id>.ping:
# «хост порт мс|-»; Hysteria2 работает по UDP — TCP-замер к нему ничего не скажет, «-»
sub_ping() {
  local id="$1" h p k n=0 t="$R/tmp/mitt-sub.$$.ping"
  rm -f "$t".*
  ctl proxy-sub-hosts "$ETC/config.json" "$id" >"$t.list" 2>/dev/null
  while read -r h p k; do
    [ -n "$p" ] || continue
    n=$((n + 1))
    if [ "$k" = hysteria2 ]; then echo "$h $p -" >"$t.$n"
    else ( v="$(ping_ms "$h" "$p")"; echo "$h $p ${v:--}" >"$t.$n" ) & fi
    [ $((n % 8)) -eq 0 ] && wait
  done <"$t.list"
  wait
  rm -f "$t.list"
  cat "$t".* 2>/dev/null >"$STATE/sub/$id.ping.t"; mv -f "$STATE/sub/$id.ping.t" "$STATE/sub/$id.ping"; rm -f "$t".*
}
rc_all=0
while read -r id kind; do
  [ -n "$id" ] || continue
  OUT="$STATE/sub/$id.json"; now=$(date +%s)
  prev_upd="$(sed -n 's/.*"updated":\([0-9]*\).*/\1/p' "$OUT" 2>/dev/null)"
  # сбой подписки — уведомление один раз, пока она снова не обновится
  prev_ok="$(sed -n 's/^{"ok":\([a-z]*\),.*/\1/p' "$OUT" 2>/dev/null)"
  put() { # put <ok true|false> <updated|null> [ошибка] [count]
    printf '{"ok":%s,"checked":%s,"updated":%s,"error":%s,"count":%s}\n' "$1" "$now" "$2" \
      "$([ -n "${3:-}" ] && printf '"%s"' "$(js "$3")" || echo null)" "${4:-null}" >"$OUT.t" && mv -f "$OUT.t" "$OUT"
  }
  url="$(ctl subscription-url "$ETC/config.json" "$id" 2>/dev/null)" || continue
  tmp="$R/tmp/mitt-sub.$$.body"
  # ошибки curl без ссылки: в ней логин и пароль подписки
  # панели VPN-провайдеров (Remnawave, Marzban, 3x-ui) выбирают формат подписки по User-Agent: для v2rayN — список
  # ссылок в base64; на «curl» часть из них отвечает страницей для браузера или настройками другой программы
  ua="mi-lumruri"; [ "$kind" = trusttunnel ] || ua="v2rayN/7.13.2"
  if ! "$CURL" -sSfL --proto '=https' --max-time 30 --max-filesize 1048576 -A "$ua" -o "$tmp" "$url" 2>"$LOG/sub-curl.log"; then
    e="$(tail -n 1 "$LOG/sub-curl.log" | sed 's#https://[^ ]*#<ссылка>#g')"
    rm -f "$tmp"; put false "${prev_upd:-null}" "сервер подписки не ответил: $e"; mlog "подписка $id: не скачана ($e)"
    [ "$prev_ok" = false ] || notify subscription sub_failed "$e"; rc_all=1; continue
  fi
  if [ "$kind" = trusttunnel ]; then r="$(ctl subscription-import "$ETC/config.json" "$id" "$tmp" 2>&1)"; rc=$?
  else r="$(ctl proxy-sub-import "$ETC/config.json" "$id" "$tmp" 2>&1)"; rc=$?; fi
  rm -f "$tmp"
  cnt="$(printf '%s' "$r" | sed -n 's/.*"count": *\([0-9]*\).*/\1/p' | head -n 1)"
  if [ $rc -ne 0 ]; then
    e="$(printf '%s' "$r" | sed -n 's/.*"message": *"\([^"]*\)".*/\1/p' | head -n 1)"
    put false "${prev_upd:-null}" "ответ подписки не принят: ${e:-код $rc}"; mlog "подписка $id: не принята (${e:-код $rc})"
    [ "$prev_ok" = false ] || notify subscription sub_failed "${e:-код $rc}"; rc_all=1; continue
  fi
  # сервер модуля sing-box: замер задержки списка и автовыбор (если включён) — переход на заметно более быстрый
  if [ "$kind" != trusttunnel ]; then
    sub_ping "$id"
    ra="$(ctl proxy-sub-auto "$ETC/config.json" "$id" "$STATE/sub/$id.ping" 2>&1)"
    if printf '%s' "$ra" | grep -q '"changed": *true'; then mlog "подписка $id: автовыбор — сервер с меньшей задержкой"; r="$r \"changed\": true"; fi
  fi
  if printf '%s' "$r" | grep -q '"changed": *true'; then
    put true "$now" "" "$cnt"; mlog "подписка $id: параметры сервера обновлены, применяю"; notify subscription sub_changed
  else
    put true "${prev_upd:-null}" "" "$cnt"
  fi
done <"$LIST"
rm -f "$LIST"
exit "$rc_all"
