#!/bin/sh
# mi-trusttunnel: служба (цикл). Запускает и перезапускает клиент TrustTunnel и nfqws2, применяет полную политику после их
# готовности, выполняет заявки панели (apply.request, zapret-test.request, lists-update.request), раз в сутки проверяет
# обновления готовых списков сайтов. Работает без WAN: туннель подключится сам, когда появится связь;
# до этого трафик «через TrustTunnel» блокируется (unreachable) или идёт напрямую, если так выбрано в профиле.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
INTERVAL="${MITT_INTERVAL:-5}"

engines_stop() { for n in trusttunnel nfqws2; do rm -f "$STATE/$n.wanted"; pid_stop "$n"; done; }
engines_start() {
  if [ -f "$RENDER/client.toml" ]; then
    touch "$STATE/trusttunnel.wanted"
    pid_alive trusttunnel || start_bg trusttunnel ${MITT_TT_WRAP:-} "$BIN/trusttunnel_client" -c "$RENDER/client.toml"
    # TUN должен появиться до apply: маршрут таблицы 3100 ссылается на него
    local i=0; while [ $i -lt 50 ] && ! ip link show mitt0 >/dev/null 2>&1; do sleep 0.2; i=$((i + 1)); done
  fi
  if [ -f "$RENDER/nfqws2.args" ]; then
    touch "$STATE/nfqws2.wanted"
    # shellcheck disable=SC2046 — аргументы по одному в строке, без пробелов (формирует рендер)
    pid_alive nfqws2 || start_bg nfqws2 ${MITT_NFQWS_WRAP:-} "$BIN/nfqws2" $(cat "$RENDER/nfqws2.args")
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
  # подбор стратегии Zapret — в фоне, один одновременно (заявку повторного нажатия панель не ставит, пока идёт подбор);
  # сценарий умер без итога (KILL, сбой) — вернуть прежние стратегии и пометить подбор failed
  pid_alive zapret-test || zt_service_recover
  if [ -f "$STATE/zapret-test.request" ]; then
    rm -f "$STATE/zapret-test.request"
    pid_alive zapret-test || { start_bg zapret-test sh "$SCR/mitt-zapret-test.sh"; mlog "подбор стратегии Zapret запущен"; }
  fi
  # готовые списки: проверка обновлений в фоне — раз в сутки и по заявке панели (цикл службы не ждёт загрузку)
  if [ -f "$STATE/lists-update.request" ] || lists_due; then
    rm -f "$STATE/lists-update.request"
    pid_alive lists-update || { start_bg lists-update sh "$SCR/mitt-lists.sh" update; mlog "проверка обновлений списков запущена"; }
  fi
  for e in trusttunnel nfqws2; do
    if [ -f "$STATE/$e.wanted" ] && ! pid_alive "$e"; then
      mlog "движок $e завершился — перезапуск"; engines_start; admin_apply "$e-restart"; status_write; break
    fi
  done
  status_write
done
mlog "служба остановлена"
