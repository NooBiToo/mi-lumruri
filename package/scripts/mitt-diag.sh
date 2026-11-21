#!/bin/sh
# mi-trusttunnel: диагностика по заявке панели (diag.request). Только чтение состояния и пробные запросы:
# ничего не меняет. Итог — каталог $STATE/diag: checks.tsv (id, итог, подробность), site.tsv (проверка сайта),
# хвосты журналов log-*.txt, отметки started/finished. Его читает контроллер (GET /diag) и разбирает маршрут сайта.
# Итоги: ok — работает, warn — работает с оговоркой, bad — не работает, skip — не используется.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
REQ="$STATE/diag.request.run"
OUT="$STATE/diag"; T="$OUT.new"
rm -rf "$T"; mkdir -p "$T"
date +%s >"$T/started"
# сайт — только [a-z0-9.-] (контроллер проверил домен до записи заявки)
site="$(sed -n 's/.*"site": *"\([a-z0-9.-]*\)".*/\1/p' "$REQ" 2>/dev/null)"

ch() { printf '%s\t%s\t%s\n' "$1" "$2" "$(printf '%s' "$3" | tr '\t\n' '  ' | cut -c1-300)" >>"$T/checks.tsv"; }
has_tun() { ip link show mitt0 >/dev/null 2>&1; }
# внешний адрес: ответ Cloudflare по IP, без DNS
trace() { curl -s --max-time 8 "$@" https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p'; }

pid_alive service && ch service ok "работает" || ch service bad "не запущена: перезапустите службу"

if [ -f "$RENDER/client.toml" ]; then
  if pid_alive trusttunnel; then
    st="$(grep -o 'VPN_SS_[A-Z_]*' "$LOG/trusttunnel.log" 2>/dev/null | tail -n 1)"
    ping="$(grep -o 'ping=[0-9]*ms' "$LOG/trusttunnel.log" 2>/dev/null | tail -n 1 | sed 's/ping=\([0-9]*\)ms/\1 мс/')"
    ver="$("$BIN/trusttunnel_client" --version 2>/dev/null | sed -n 's/^trusttunnel_client //p' | head -n 1)"
    # на связи с последнего VPN_SS_CONNECTED: время журнала клиента — UTC, «дд.мм.гггг чч:мм:сс.мкс»
    since=""; t="$(grep 'VPN_SS_CONNECTED' "$LOG/trusttunnel.log" 2>/dev/null | tail -n 1 | cut -c1-19)"
    if [ -n "$t" ] && s="$(date -u -D '%d.%m.%Y %H:%M:%S' -d "$t" +%s 2>/dev/null)"; then
      m=$(( ($(date +%s) - s) / 60 )); [ "$m" -ge 0 ] && since="$( [ $m -ge 1440 ] && echo "$((m / 1440)) д $(((m % 1440) / 60)) ч" || { [ $m -ge 60 ] && echo "$((m / 60)) ч $((m % 60)) мин" || echo "$m мин"; })"
    fi
    case "$st" in
      VPN_SS_CONNECTED) ch client ok "подключён к серверу${ping:+, задержка $ping}${since:+, на связи $since}${ver:+, клиент $ver}" ;;
      VPN_SS_CONNECTING|VPN_SS_RECOVERING*|VPN_SS_WAITING*) ch client warn "подключается к серверу" ;;
      *) ch client bad "нет связи с сервером${st:+ ($st)}" ;;
    esac
  else
    ch client bad "клиент TrustTunnel не запущен"
  fi
  if has_tun; then
    tip="$(trace --interface mitt0)"; dip="$(trace)"
    if [ -z "$tip" ]; then ch exit bad "через туннель интернет не отвечает${dip:+; напрямую — $dip}"
    elif [ "$tip" = "$dip" ]; then ch exit warn "через туннель тот же адрес, что и напрямую: $tip"
    else ch exit ok "выход через туннель $tip, напрямую ${dip:-нет ответа}"; fi
  else
    ch exit bad "интерфейс туннеля mitt0 не создан"
  fi
  r=$(ip rule 2>/dev/null | grep -c 'lookup 3100'); t=$(ip route show table 3100 2>/dev/null | grep -c 'dev mitt0')
  if [ "$r" -gt 0 ] && [ "$t" -gt 0 ]; then ch route ok "трафик сайтов из списка уходит в туннель"
  else ch route bad "нет правила или маршрута в туннель (правил: $r, маршрутов: $t)"; fi
  # сторож туннеля (tunnel_watch): последняя проверка и перезапуски клиента за последний час
  w="$(cat "$STATE/watch.json" 2>/dev/null)"
  if [ -n "$w" ]; then
    wc_="$(echo "$w" | sed -n 's/.*"checked":\([0-9]*\).*/\1/p')"; wr="$(echo "$w" | sed -n 's/.*"restarted":\([0-9]*\).*/\1/p')"
    wf="$(echo "$w" | sed -n 's/.*"fails":\([0-9]*\).*/\1/p')"; now=$(date +%s)
    if [ "${wr:-0}" -gt 0 ] && [ $((now - wr)) -lt 3600 ]; then ch watch warn "перезапускал клиент $((  (now - wr) / 60 )) мин назад: трафик через туннель не шёл"
    elif [ "${wf:-0}" -gt 0 ]; then ch watch warn "последние проверки через туннель не прошли ($wf подряд)"
    else ch watch ok "трафик через туннель идёт, проверка $(( (now - ${wc_:-$now}) / 60 )) мин назад"; fi
  else
    ch watch skip "проверок ещё не было"
  fi
else
  ch client skip "VPN выключен или сервер не настроен"
fi

if grep -q '"rules": *\[\]' "$RENDER/policy.json" 2>/dev/null; then
  ch firewall skip "правил маршрутизации нет: сайты не выбраны"
elif [ "$(iptables -w -t mangle -S PREROUTING 2>/dev/null | grep -c MITT_C)" -gt 0 ]; then
  sets="$(ipset list -t 2>/dev/null | awk '/^Name: mitt/{n++; f=1; next} /^Name:/{f=0} f && /^Number of entries/{s+=$4} END{printf "наборов %d, адресов %d", n, s}')"
  ch firewall ok "трафик устройств сортируется: $sets"
else
  ch firewall bad "правила сортировки трафика не подключены"
fi

if [ -f "$RENDER/dnsmasq-mitt.conf" ]; then
  if [ ! -f "$R/tmp/dnsmasq.d/mitt.conf" ]; then ch dns bad "настройки DNS пакета не подключены к dnsmasq"
  elif ! pidof dnsmasq >/dev/null 2>&1; then ch dns bad "dnsmasq не запущен"
  else
    d=$(grep -m1 '^ipset=/' "$R/tmp/dnsmasq.d/mitt.conf" | cut -d/ -f2)
    if [ -z "$d" ] || nslookup "$d" 127.0.0.1 >/dev/null 2>&1; then ch dns ok "DNS роутера отвечает${d:+, $d разрешается}"
    else ch dns warn "DNS роутера не разрешает $d"; fi
  fi
else
  ch dns skip "свои настройки DNS не нужны"
fi

if [ -f "$RENDER/dns-proxy.args" ]; then
  if ! pid_alive dnsproxy; then ch secure bad "прокси DoH/DoT не запущен"
  elif "$BIN/mi-tt-dns" --probe 127.0.0.1:5453 example.com >/dev/null 2>&1; then
    fb="$(sed -n 's/.*"fallback":\([0-9]*\).*/\1/p' "$STATE/dns-proxy.json" 2>/dev/null)"; ok="$(sed -n 's/.*"upstream_ok":\([0-9]*\).*/\1/p' "$STATE/dns-proxy.json" 2>/dev/null)"
    err="$(sed -n 's/.*"last_error":"\([^"]*\)".*/\1/p' "$STATE/dns-proxy.json" 2>/dev/null)"
    if [ "${ok:-0}" -eq 0 ] && [ "${fb:-0}" -gt 0 ]; then ch secure warn "сервер недоступен, ответы идут через DNS провайдера${err:+: $err}"
    elif [ $(( ${fb:-0} * 20 )) -gt $(( ${ok:-0} + ${fb:-0} )) ]; then ch secure warn "работает, но заметная часть ответов ($fb) шла через DNS провайдера${err:+, последняя ошибка: $err}"
    else ch secure ok "ответов через защищённый сервер: ${ok:-0}$( [ "${fb:-0}" -gt 0 ] && echo ", через провайдера при сбоях: $fb")"; fi
  else ch secure bad "прокси DoH/DoT не отвечает"; fi
else
  ch secure skip "защищённый DNS выключен"
fi

if [ -f "$RENDER/dns-tunnel.args" ]; then
  if ! pid_alive dnstunnel; then ch tunnelsecure bad "прокси DoH/DoT для сайтов через VPN не запущен"
  elif "$BIN/mi-tt-dns" --probe 127.0.0.1:5454 example.com >/dev/null 2>&1; then
    ok="$(sed -n 's/.*"upstream_ok":\([0-9]*\).*/\1/p' "$STATE/dns-tunnel.json" 2>/dev/null)"
    ch tunnelsecure ok "шифрованные ответы через туннель: ${ok:-0}"
  else
    err="$(sed -n 's/.*"last_error":"\([^"]*\)".*/\1/p' "$STATE/dns-tunnel.json" 2>/dev/null)"
    ch tunnelsecure bad "сервер не отвечает через туннель${err:+: $err}"
  fi
fi

if [ -f "$RENDER/nfqws2.args" ]; then
  pid_alive nfqws2 && ch zapret ok "nfqws2 работает" || ch zapret bad "nfqws2 не запущен"
else
  ch zapret skip "обход блокировок не используется"
fi

# программы, которые падают и перезапускаются по кругу (служба проверяет их раз в несколько секунд)
# считаются только перезапуски за последние 10 минут (служба пишет их время в $STATE/restarts)
since=$(( $(date +%s) - 600 )); loop=""; recent=""
for e in trusttunnel nfqws2 dnsproxy dnstunnel; do
  c=$(awk -v s="$since" -v e="$e" '$1 >= s && $2 == e' "$STATE/restarts" 2>/dev/null | wc -l)
  if [ "$c" -ge 3 ]; then
    last="$(tail -n 1 "$LOG/$e.log" 2>/dev/null | cut -c1-120)"
    loop="$loop $e (перезапусков за 10 минут: $c${last:+; последняя запись: $last})"
  elif [ "$c" -gt 0 ]; then recent="$recent $e ($c)"; fi
done
if [ -n "$loop" ]; then ch restarts bad "перезапускаются по кругу:$loop"
elif [ -n "$recent" ]; then ch restarts warn "перезапускались за последние 10 минут:$recent"
else ch restarts ok "за последние 10 минут программы не падали"; fi

if [ -n "$site" ]; then
  ip4="$(nslookup "$site" 127.0.0.1 2>/dev/null | awk '/^Name:/{f=1} f && /^Address [0-9]+: /{if ($3 ~ /^[0-9.]+$/) {print $3; exit}}')"
  sets=""
  if [ -n "$ip4" ]; then for s in $(ipset list -n 2>/dev/null | grep '^mitt'); do ipset test "$s" "$ip4" >/dev/null 2>&1 && sets="$sets $s"; done; fi
  http() { curl -s -o /dev/null --max-time 10 -w '%{http_code} %{time_total}' "$@" "https://$site/" 2>/dev/null; }
  direct="$(http)"; tunnel=""; has_tun && tunnel="$(http --interface mitt0)"
  printf 'domain\t%s\nip\t%s\nsets\t%s\ndirect\t%s\ntunnel\t%s\n' "$site" "$ip4" "${sets# }" "$direct" "$tunnel" >"$T/site.tsv"
fi

tail -n 60 "$LOG/mitt.log" >"$T/log-service.txt" 2>/dev/null
tail -n 60 "$LOG/trusttunnel.log" >"$T/log-trusttunnel.txt" 2>/dev/null
tail -n 30 "$LOG/nfqws2.log" >"$T/log-nfqws2.txt" 2>/dev/null
date +%s >"$T/finished"
rm -rf "$OUT"; mv "$T" "$OUT"
rm -f "$REQ"
