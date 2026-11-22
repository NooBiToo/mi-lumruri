#!/usr/bin/env bash
# Замер скорости и задержки (package/scripts/mitt-speed.sh) на штатном BusyBox ash 1.25.1 (ARM64 из образа RC06 1.1.38
# под qemu-user): заглушка curl (время подключения, скорость и объём скачивания), заглушка ip (туннель поднят или нет).
# Запуск — в WSL: bash tools/lab/test-speed.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
W="$(mktemp -d /tmp/mitt-speed.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr; do
  printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
done
cat >"$SB/ip" <<'EOF'
#!/bin/sh
[ "$(cat "$LT/tun" 2>/dev/null)" = up ] || exit 1
case "$*" in *addr*) echo "    inet 172.16.0.2/32 scope global mitt0";; *) echo "9: mitt0: <POINTOPOINT,UP,LOWER_UP> mtu 1350";; esac
EOF
# curl: задержка — по хосту ($LT/ping.<хост>, нет файла — не отвечает); скорость — по пути ($LT/direct, $LT/tunnel)
cat >"$SB/curl" <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
echo "$*" >>"$LT/curl.log"
case "$*" in
  *time_connect*)
    h="$(echo "$*" | sed -n 's#.*https://\[*\([^]/:]*\).*#\1#p')"
    [ -f "$LT/ping.$h" ] && { printf '%s' "$(cat "$LT/ping.$h")"; exit 0; }
    printf '0.000000'; exit 28;;
  *speed_download*)
    via=direct; case "$*" in *"--interface mitt0"*) via=tunnel;; esac
    case "$(cat "$LT/$via")" in
      fast) printf '12500000.000 25000000 200'; exit 0;;
      timeout) printf '2500000.000 30000000 200'; exit 28;;
      fail) printf '0.000 0 000'; exit 7;;
      http) printf '0.000 0 503'; exit 0;;
    esac;;
esac
EOF
chmod +x "$SB"/*

case_() { # case_ <имя> <direct> <tunnel> <туннель up|down> <servers.addr>
  local d="$W/$1/root" lt="$W/$1/lt"; local L="$d/tmp/mi-lumruri"
  mkdir -p "$d/data/mi-lumruri/etc" "$L/scripts" "$L/render" "$L/run" "$L/log" "$lt"
  cp "$ROOT"/package/scripts/*.sh "$L/scripts/"
  echo "$2" >"$lt/direct"; echo "$3" >"$lt/tunnel"; echo "$4" >"$lt/tun"; printf '%b' "$5" >"$L/render/servers.addr"
  echo 0.0421 >"$lt/ping.vpn.example.com"; echo 0.120 >"$lt/ping.203.0.113.9"
  touch "$L/run/speed.request.run"
  timeout 120 env -i PATH="$SB" MITT_ROOT="$d" MITT_QUIET=1 LT="$lt" "$Q" -L "$F" "$F/bin/busybox" ash "$L/scripts/mitt-speed.sh" >"$W/$1/out" 2>&1
}
j() { python3 -I -c 'import json,sys
s=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$W/$1/root/tmp/mi-lumruri/run/speed.json" "$2" 2>&1; }
chk() { local r; r="$(j "$1" "$3")"; [ "$r" = True ] && ok "$1: $2" || bad "$1: $2 → $r; $(cat "$W/$1/root/tmp/mi-lumruri/run/speed.json" 2>/dev/null); $(tail -3 "$W/$1/out")"; }

echo "(а) оба пути работают, два сервера: задержки в мс, скорость в Мбит/с, заявка снята"
case_ a fast timeout up 'primary vpn.example.com 443\nbackup 203.0.113.9 8443\n'
chk a "done, задержка основного 42 мс, запасного 120 мс" 's["state"]=="done" and s["ping"]=={"primary":42,"backup":120}'
chk a "напрямую 100 Мбит/с, через туннель 20 Мбит/с (тайм-аут — по скачанному)" 's["direct"]["mbps"]==100.0 and s["tunnel"]["mbps"]==20.0 and s["tunnel"]["bytes"]==30000000'
[ ! -e "$W/a/root/tmp/mi-lumruri/run/speed.request.run" ] && ok "a: заявка снята" || bad "a: заявка осталась"
grep -q -- '--interface mitt0' "$W/a/lt/curl.log" && ok "a: через туннель — --interface mitt0" || bad "a: $(cat "$W/a/lt/curl.log")"

echo "(б) туннель не поднят, запасного нет, основной не отвечает: понятные ошибки, без замера через туннель"
case_ b fast fast down 'primary dead.example.com 443\n'
chk b "ping primary null, backup null; tunnel — «туннель не поднят»" 's["ping"]=={"primary":None,"backup":None} and s["tunnel"]=={"error":"туннель не поднят"} and s["direct"]["mbps"]==100.0'
[ "$(grep -c -- '--interface mitt0' "$W/b/lt/curl.log")" = 0 ] && ok "b: через туннель не скачивали" || bad "b: $(cat "$W/b/lt/curl.log")"

echo "(в) сбой сети и ответ 503"
case_ c fail http up ''
chk c "direct: curl код 7; tunnel: HTTP 503" 's["direct"]=={"error":"curl код 7"} and s["tunnel"]=={"error":"HTTP 503"}'

# выбор сервера по задержке (fastest_check в mitt-lib.sh)
fast() { # fast <имя> <ping основного, с> <ping запасного, с> <сколько раз вызвать>
  local d="$W/$1/root" lt="$W/$1/lt"; local L="$d/tmp/mi-lumruri"
  mkdir -p "$d/data/mi-lumruri/etc" "$L/scripts" "$L/render" "$L/run" "$L/log" "$lt"
  cp "$ROOT"/package/scripts/*.sh "$L/scripts/"
  printf 'primary vpn.example.com 443\nbackup 203.0.113.9 8443\n' >"$L/render/servers.addr"; echo 1 >"$L/render/fastest"
  echo "$2" >"$lt/ping.vpn.example.com"; echo "$3" >"$lt/ping.203.0.113.9"
  local i=0 cmd=""; while [ $i -lt "$4" ]; do cmd="$cmd fastest_check;"; i=$((i + 1)); done
  timeout 120 env -i PATH="$SB" MITT_ROOT="$d" MITT_QUIET=1 LT="$lt" MITT_FASTEST_EVERY=0 "$Q" -L "$F" "$F/bin/busybox" ash -c \
    ". \"$L/scripts/mitt-lib.sh\"; $cmd" >>"$W/$1/out" 2>&1
}
ep() { cat "$W/$1/root/tmp/mi-lumruri/run/endpoint" 2>/dev/null || echo primary; }

echo "(г) запасной заметно быстрее: после одного замера — ещё нет, после двух подряд — переключение и уведомление"
fast g 0.120 0.040 1
[ "$(ep g)" = primary ] && ok "g: один замер — без переключения" || bad "g: endpoint $(ep g)"
fast g 0.120 0.040 1
[ "$(ep g)" = backup ] && ok "g: два замера подряд — запасной" || bad "g: endpoint $(ep g)"
grep -q 'failover_backup' "$W/g/root/tmp/mi-lumruri/run/notify.queue" && ok "g: уведомление о переключении" || bad "g: очереди нет"
python3 -I -c 'import json,sys; s=json.load(open(sys.argv[1])); sys.exit(0 if s["primary"]==120 and s["backup"]==40 else 1)' "$W/g/root/tmp/mi-lumruri/run/fastest.json" \
  && ok "g: итог замера в fastest.json" || bad "g: $(cat "$W/g/root/tmp/mi-lumruri/run/fastest.json")"

echo "(д) разница меньше порога (50 против 40 мс) — остаётся на основном"
fast h 0.050 0.040 3
[ "$(ep h)" = primary ] && ok "h: без переключения" || bad "h: endpoint $(ep h)"

echo "(е) на запасном, основной снова быстрее — возврат; без признака fastest — ничего не делает"
fast k 0.030 0.200 0; echo backup >"$W/k/root/tmp/mi-lumruri/run/endpoint"; fast k 0.030 0.200 2
[ "$(ep k)" = primary ] && ok "k: возврат на более быстрый основной" || bad "k: endpoint $(ep k)"
fast m 0.200 0.030 0; rm -f "$W/m/root/tmp/mi-lumruri/render/fastest"
timeout 60 env -i PATH="$SB" MITT_ROOT="$W/m/root" MITT_QUIET=1 LT="$W/m/lt" MITT_FASTEST_EVERY=0 "$Q" -L "$F" "$F/bin/busybox" ash -c \
  ". \"$W/m/root/tmp/mi-lumruri/scripts/mitt-lib.sh\"; fastest_check; fastest_check" >>"$W/m/out" 2>&1
[ "$(ep m)" = primary ] && [ ! -e "$W/m/root/tmp/mi-lumruri/run/fastest.json" ] && ok "m: выключено — замеров и переключений нет" || bad "m: endpoint $(ep m)"

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
