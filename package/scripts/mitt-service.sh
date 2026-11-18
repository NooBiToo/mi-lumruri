#!/bin/sh
# mi-trusttunnel: служба (цикл). Запускает и перезапускает движки, применяет полную политику после их готовности,
# выполняет заявки панели (apply.request), следит за арендами DHCP и перезапуском движков. Работает без WAN:
# VPN и DNS подключатся сами, когда появится связь; до этого защищённые источники заблокированы (guard/unreachable).
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
INTERVAL="${MITT_INTERVAL:-5}"

# md5sum — есть в BusyBox стока 1.1.38 (cksum нет)
lease_sig() { [ -f "$LEASES" ] && md5sum <"$LEASES" || echo none; }

engines_stop() { for n in mihomo dnscrypt nfqws2; do rm -f "$STATE/$n.wanted"; pid_stop "$n"; done; }
engines_start() {
  [ -f "$RENDER/config.yaml" ] || return 1
  if [ -f "$RENDER/dnscrypt-proxy.toml" ]; then touch "$STATE/dnscrypt.wanted"; pid_alive dnscrypt || start_bg dnscrypt "$BIN/dnscrypt-proxy" -config "$RENDER/dnscrypt-proxy.toml"; fi
  touch "$STATE/mihomo.wanted"; pid_alive mihomo || start_bg mihomo "$BIN/mihomo" -d "$RENDER" -f "$RENDER/config.yaml"
  if [ -f "$RENDER/nfqws2.args" ]; then
    touch "$STATE/nfqws2.wanted"
    # shellcheck disable=SC2046 — аргументы по одному в строке, без пробелов (формирует рендер)
    pid_alive nfqws2 || start_bg nfqws2 ${MITT_NFQWS_WRAP:-} "$BIN/nfqws2" $(cat "$RENDER/nfqws2.args")
  fi
  # TUN должен появиться до apply: маршрут таблицы 3100 ссылается на него
  local i=0; while [ $i -lt 50 ] && ! ip link show mitt0 >/dev/null 2>&1; do sleep 0.2; i=$((i + 1)); done
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
    engines_stop; engines_start; dns_sync
    if admin_apply "$1"; then echo full >"$STATE/protection"; else admin_apply "$1-guard" --guard-only && echo guard >"$STATE/protection"; fi
  else
    mlog "$1: render не прошёл, действует прежняя политика"
  fi
  status_write
}

full_cycle start
LS="$(lease_sig)"
while [ -f "$STATE/service.wanted" ]; do
  sleep "$INTERVAL"
  if [ -f "$STATE/apply.request" ]; then
    rm -f "$STATE/apply.request"; full_cycle panel-request; LS="$(lease_sig)"; continue
  fi
  n="$(lease_sig)"; if [ "$n" != "$LS" ]; then LS="$n"; mlog "аренды DHCP изменились"; full_cycle lease-change; continue; fi
  for e in mihomo dnscrypt nfqws2; do
    if [ -f "$STATE/$e.wanted" ] && ! pid_alive "$e"; then
      mlog "движок $e завершился — перезапуск"; engines_start; admin_apply "$e-restart"; status_write; break
    fi
  done
  status_write
done
mlog "служба остановлена"
