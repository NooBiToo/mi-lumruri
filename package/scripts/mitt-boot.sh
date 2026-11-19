#!/bin/sh
# mi-trusttunnel: загрузчик. Регистрируется установщиком как `config include 'mitt'` firewall (fw3 вызывает его
# при загрузке и при каждой перезагрузке firewall). Без WAN: всё локально из /data, сеть не нужна.
#   холодный старт: распаковка в RAM, render, apply --guard-only (защита до движков и клиентов), панель, служба;
#   перезагрузка firewall: служба уже работает — восстановить свои правила (apply), fw3 мог их снять;
#   mitt-boot.sh stop — остановить всё и снять свои правила.
#   mitt-boot.sh auth <init|confirm|reset-password|…> — mi-tt-admin auth с каталогами пакета (вход в панель);
#   mitt-boot.sh status — состояние службы (JSON).
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
case "${1:-}" in
  auth)
    shift; [ -x "$BIN/mi-tt-admin" ] || { echo "mi-trusttunnel: служба не запущена (нет $BIN/mi-tt-admin): sh install.sh install" >&2; exit 1; }
    MI_TT_AUTH_DIR="$ETC/auth" MI_TT_SESSION_DIR="$RUN/sessions" exec "$BIN/mi-tt-admin" auth "$@";;
  status) cat "$STATE/status.json" 2>/dev/null || echo '{"protection":"none"}'; exit 0;;
esac
mkdir -p "$STATE" "$LOG"
lock_take boot 30 || die "загрузчик уже выполняется"
trap 'lock_drop boot' EXIT

case "${1:-auto}" in
  stop)
    # mihomo и dnscrypt — движки версий до 0.2: при обновлении их останавливает уже новый загрузчик
    for n in service trusttunnel nfqws2 mihomo dnscrypt nginx uhttpd zapret-test zapret-nfqws; do rm -f "$STATE/$n.wanted"; pid_stop "$n"; done
    [ -x "$BIN/mi-tt-admin" ] && adm revert --state-dir "$RUN/admin" >"$STATE/revert.json" 2>&1
    # без своего файла dnsmasq перестаёт заносить адреса в снятые наборы и спрашивать резолвер туннеля
    if [ -f "$R/tmp/dnsmasq.d/mitt.conf" ]; then rm -f "$R/tmp/dnsmasq.d/mitt.conf"; ${MITT_DNSMASQ_RESTART:-/etc/init.d/dnsmasq restart} >/dev/null 2>&1; fi
    echo none >"$STATE/protection"; status_write; mlog "остановлено"; exit 0;;
esac

if pid_alive service; then
  # перезагрузка firewall: наши цепочки и переходы могли быть сняты — apply восстанавливает недостающее
  admin_apply fw-reload; status_write; exit 0
fi

unpack_runtime
render_now || mlog "render не прошёл: защита по предыдущей сохранённой конфигурации невозможна, движки не запускаются"
# защита до запуска движков и до появления клиентов: guard-only не требует WAN и движков
if admin_apply boot-guard --guard-only; then echo guard >"$STATE/protection"; else echo none >"$STATE/protection"; fi
start_panel
touch "$STATE/service.wanted"
start_bg service sh "$SCR/mitt-service.sh"
status_write
mlog "холодный старт выполнен; служба запущена"
exit 0
