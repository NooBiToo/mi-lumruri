#!/bin/sh
# mi-lumruri: замер по заявке панели (speed.request): задержка до основного и запасного серверов (время TCP-подключения
# с роутера), скорость скачивания напрямую и через туннель (тот же файл, до MITT_SPEED_TIME секунд на каждый путь).
# Итог — $STATE/speed.json. Трафик: до ~2 × MITT_SPEED_BYTES (по умолчанию 25 МБ).
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
CURL="${MITT_SPEED_CURL:-curl}"
PING_CURL="$CURL"
BYTES="${MITT_SPEED_BYTES:-25000000}"
URL="${MITT_SPEED_URL:-https://speed.cloudflare.com/__down?bytes=$BYTES}"
TIME="${MITT_SPEED_TIME:-12}"
OUT="$STATE/speed.json"
mkdir -p "$STATE" "$LOG"
started=$(date +%s)
js() { printf '%s' "$1" | tr -d '"\\' | tr '\n\r\t' '   ' | cut -c1-200; }
num_or_null() { case "$1" in ''|*[!0-9.]*) echo null;; *) echo "$1";; esac; }
put() { # put <state> <ping_primary> <ping_backup> <direct> <tunnel>
  printf '{"state":"%s","started":%s,"at":%s,"ping":{"primary":%s,"backup":%s},"direct":%s,"tunnel":%s}\n' \
    "$1" "$started" "$(date +%s)" "$2" "$3" "$4" "$5" >"$OUT.t" && mv -f "$OUT.t" "$OUT"
}
# speed <tunnel|direct>: {"mbps":…,"bytes":…} или {"error":"…"}
speed() {
  local opt="" r rc sp by code
  [ "$1" = tunnel ] && opt="--interface mitt0"
  # shellcheck disable=SC2086
  r="$("$CURL" -s -o /dev/null $opt --connect-timeout 8 --max-time "$TIME" -w '%{speed_download} %{size_download} %{http_code}' "$URL" 2>&1)"; rc=$?
  sp="${r%% *}"; code="${r##* }"; by="$(echo "$r" | cut -d' ' -f2)"
  # тайм-аут при скачивании — норма: скорость по скачанному за отведённое время
  if { [ "$rc" -eq 0 ] || [ "$rc" -eq 28 ]; } && [ "${by:-0}" -gt 0 ] 2>/dev/null; then
    awk -v s="$sp" -v b="$by" 'BEGIN { printf "{\"mbps\":%.1f,\"bytes\":%d}", s * 8 / 1000000, b }'
  else
    printf '{"error":"%s"}' "$(js "$( [ "$rc" -ne 0 ] && echo "curl код $rc" || echo "HTTP $code")")"
  fi
}

pp=null; pb=null
if [ -f "$RENDER/servers.addr" ]; then
  while read -r role h p; do
    [ -n "$h" ] && [ -n "$p" ] || continue
    v="$(ping_ms "$h" "$p")"
    case "$role" in primary) pp="$(num_or_null "$v")";; backup) pb="$(num_or_null "$v")";; esac
  done <"$RENDER/servers.addr"
fi
put running "$pp" "$pb" null null
dr="$(speed direct)"
put running "$pp" "$pb" "$dr" null
if tun_ready; then tr_="$(speed tunnel)"; else tr_='{"error":"туннель не поднят"}'; fi
put done "$pp" "$pb" "$dr" "$tr_"
mlog "замер: напрямую $dr, через туннель $tr_, задержка основной ${pp} мс, запасной ${pb} мс"
rm -f "$STATE/speed.request.run"
exit 0
