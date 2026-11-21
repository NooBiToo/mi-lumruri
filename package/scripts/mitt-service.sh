#!/bin/sh
# mi-trusttunnel: служба (цикл). Запускает и перезапускает клиент TrustTunnel и nfqws2, применяет полную политику после их
# готовности, выполняет заявки панели (apply.request, restart.request, diag.request, zapret-test.request, lists-update.request), раз в сутки проверяет
# обновления готовых списков сайтов. Работает без WAN: туннель подключится сам, когда появится связь;
# до этого трафик «через TrustTunnel» блокируется (unreachable) или идёт напрямую, если так выбрано в профиле.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
INTERVAL="${MITT_INTERVAL:-5}"

engines_stop() {
  for n in trusttunnel nfqws2 dnsproxy dnstunnel; do rm -f "$STATE/$n.wanted"; pid_stop "$n"; done
  # прежний TUN удаляется ядром не сразу: новый клиент и ожидание ниже не должны застать старый mitt0
  local i=0; while [ $i -lt 50 ] && ip link show mitt0 >/dev/null 2>&1; do nap; i=$((i + 1)); done
}
engines_start() {
  # защищённый DNS — первым: dnsmasq стока (а через него и клиент TrustTunnel, разрешающий имя сервера) уже
  # отправляет вопросы в этот прокси; запущенный после клиента, он оставлял того без адреса сервера
  if [ -f "$RENDER/dns-proxy.args" ]; then
    touch "$STATE/dnsproxy.wanted"
    # shellcheck disable=SC2046 — аргументы по одному в строке, без пробелов (формирует рендер)
    pid_alive dnsproxy || start_bg dnsproxy "$BIN/mi-tt-dns" $(cat "$RENDER/dns-proxy.args") --fallback "$(resolv_file)" --status "$STATE/dns-proxy.json"
    local j=0; while [ $j -lt 10 ] && ! "$BIN/mi-tt-dns" --probe 127.0.0.1:5453 example.com >/dev/null 2>&1; do nap; j=$((j + 1)); done
  fi
  # DoH/DoT для доменов туннеля: сокеты привязаны к mitt0 (до появления TUN вопросы не уходят); запасного пути нет
  if [ -f "$RENDER/dns-tunnel.args" ]; then
    touch "$STATE/dnstunnel.wanted"
    # shellcheck disable=SC2046
    pid_alive dnstunnel || start_bg dnstunnel "$BIN/mi-tt-dns" $(cat "$RENDER/dns-tunnel.args") --status "$STATE/dns-tunnel.json"
  fi
  if [ -f "$RENDER/client.toml" ]; then
    touch "$STATE/trusttunnel.wanted"
    pid_alive trusttunnel || start_bg trusttunnel ${MITT_TT_WRAP:-} "$BIN/trusttunnel_client" -c "$RENDER/client.toml"
    # TUN должен быть поднят и с адресом до apply: маршрут таблицы 3100 ссылается на него
    local i=0; while [ $i -lt 75 ] && ! tun_ready; do nap; i=$((i + 1)); done
  fi
  if [ -f "$RENDER/nfqws2.args" ]; then
    touch "$STATE/nfqws2.wanted"
    # shellcheck disable=SC2046 — аргументы по одному в строке, без пробелов (формирует рендер)
    pid_alive nfqws2 || { zapret_readable; start_bg nfqws2 ${MITT_NFQWS_WRAP:-} "$BIN/nfqws2" $(cat "$RENDER/nfqws2.args"); }
  fi
  return 0
}
dns_sync() { # dnsmasq: наш файл в активном conf-dir стока (/tmp/dnsmasq.d), перезапуск только при изменении
  local d="$R/tmp/dnsmasq.d" want="$RENDER/dnsmasq-mitt.conf"
  mkdir -p "$d"
  if [ -f "$want" ]; then
    cmp -s "$want" "$d/mitt.conf" && return 0
    cp "$want" "$d/mitt.conf.t" && mv -f "$d/mitt.conf.t" "$d/mitt.conf"
  else
    [ -f "$d/mitt.conf" ] || return 0
    rm -f "$d/mitt.conf"
  fi
  ${MITT_DNSMASQ_RESTART:-/etc/init.d/dnsmasq restart} >>"$LOG/dnsmasq-restart.log" 2>&1
  mlog "dnsmasq: файл mi-trusttunnel обновлён, служба перезапущена"
}
full_cycle() { # full_cycle <причина>
  if render_now; then
    engines_stop; engines_start
    if admin_apply "$1"; then echo full >"$STATE/protection"; else admin_apply "$1-guard" --guard-only && echo guard >"$STATE/protection"; fi
    # dnsmasq — после применения: наборы ipset, в которые он заносит адреса доменов, к этому моменту уже созданы
    dns_sync
  else
    mlog "$1: render не прошёл, действует прежняя политика"
  fi
  status_write
}

# подбор Zapret, оборванный остановкой или перезагрузкой: прежние стратегии — до первого рендера (попытка при запуске
# всегда; в цикле — не больше трёх)
rm -f "$ZT_RETRY"; zt_recover
full_cycle start
while [ -f "$STATE/service.wanted" ]; do
  sleep "$INTERVAL"
  if [ -f "$STATE/apply.request" ]; then
    rm -f "$STATE/apply.request"; full_cycle panel-request; continue
  fi
  if [ -f "$STATE/restart.request" ]; then
    rm -f "$STATE/restart.request"; mlog "перезапуск по заявке панели"; full_cycle panel-restart; continue
  fi
  # диагностика — в фоне, одна одновременно: только чтение и пробные запросы, итог в $STATE/diag
  if [ -f "$STATE/diag.request" ] && ! pid_alive diag; then
    mv -f "$STATE/diag.request" "$STATE/diag.request.run"; start_bg diag sh "$SCR/mitt-diag.sh"
  fi
  # обновление из релизов GitHub — в фоне, одно одновременно (проверка или установка; итог в $STATE/update.json)
  if [ -f "$STATE/update.request" ] && ! pid_alive update; then
    mv -f "$STATE/update.request" "$STATE/update.request.run"; start_bg update sh "$SCR/mitt-update.sh"
  fi
  # подбор стратегии Zapret — в фоне, один одновременно (заявку повторного нажатия панель не ставит, пока идёт подбор);
  # сценарий умер без итога (KILL, сбой) — вернуть прежние стратегии и пометить подбор failed
  pid_alive zapret-test || zt_service_recover
  if [ -f "$STATE/zapret-test.request" ]; then
    rm -f "$STATE/zapret-test.request"
    pid_alive zapret-test || { start_bg zapret-test sh "$SCR/mitt-zapret-test.sh"; mlog "подбор стратегии Zapret запущен"; }
  elif ! pid_alive zapret-test && zt_check_due; then
    # автопроверка: тот же подбор, новый способ применяется, только если он лучше действующего
    date +%s >"$ETC/zapret-check.last" 2>/dev/null
    start_bg zapret-test sh "$SCR/mitt-zapret-test.sh"; mlog "автопроверка способа Zapret запущена"
  fi
  # готовые списки: проверка обновлений в фоне — раз в сутки и по заявке панели (цикл службы не ждёт загрузку)
  if [ -f "$STATE/lists-update.request" ] || lists_due; then
    # идущая проверка: заявка остаётся до следующего прохода
    # кнопка «Обновить» обновляет и список рекламы: сброс его отсрочки
    pid_alive lists-update || { [ -f "$STATE/lists-update.request" ] && rm -f "$STATE/adblock-next"; rm -f "$STATE/lists-update.request"
      start_bg lists-update sh "$SCR/mitt-lists.sh" update; mlog "проверка обновлений списков запущена"; }
  fi
  # список рекламы: по расписанию списков сайтов, по кнопке «Обновить» и при смене ссылки — в фоне
  if ! pid_alive adblock-update && adblock_due; then
    start_bg adblock-update sh "$SCR/mitt-adblock.sh"
  fi
  for e in trusttunnel nfqws2 dnsproxy dnstunnel; do
    if [ -f "$STATE/$e.wanted" ] && ! pid_alive "$e"; then
      mlog "движок $e завершился — перезапуск"
      # время перезапусков — для диагностики (падения по кругу за последние минуты), последние 50
      echo "$(date +%s) $e" >>"$STATE/restarts"; tail -n 50 "$STATE/restarts" >"$STATE/restarts.t" && mv -f "$STATE/restarts.t" "$STATE/restarts"
      engines_start; admin_apply "$e-restart" && echo full >"$STATE/protection"; status_write; break
    fi
  done
  # полное применение не прошло (туннель не успел подняться) и действует только защита: повтор, когда mitt0 готов,
  # не чаще раза в минуту
  if [ "$(cat "$STATE/protection" 2>/dev/null)" = guard ] && [ -f "$STATE/trusttunnel.wanted" ] && tun_ready; then
    now=$(date +%s); last=$(cat "$STATE/guard-retry" 2>/dev/null || echo 0)
    if [ $((now - last)) -ge 60 ] || [ "$now" -lt "$last" ]; then
      echo "$now" >"$STATE/guard-retry"
      admin_apply tun-ready && echo full >"$STATE/protection"
    fi
  fi
  status_write
done
mlog "служба остановлена"
