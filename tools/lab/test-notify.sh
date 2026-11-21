#!/usr/bin/env bash
# Уведомления в Telegram (package/scripts/mitt-notify.sh и notify/tunnel_track в mitt-lib.sh) на штатном BusyBox ash
# 1.25.1 (ARM64 из образа RC06 1.1.38 под qemu-user): заглушка curl вместо api.telegram.org, заглушка ip (туннель
# поднят или нет), настоящий mi-tt-ctl ARM64 (notify-conf из secrets.json).
# Нужен `bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl`. Запуск — в WSL.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"
[ -f "$CTL" ] || { echo "нет $CTL: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
W="$(mktemp -d /tmp/mitt-notify.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"; kill $SLP 2>/dev/null' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }
TOKEN="123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw" # secret-scan: allow тестовый токен

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr; do
  if [ -e "$F/bin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
    printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  else echo "нет апплета $a в образе"; exit 2; fi
done
# ip: туннель mitt0 поднят, если в $LT/tun «up»
cat >"$SB/ip" <<'EOF'
#!/bin/sh
[ "$(cat "$LT/tun" 2>/dev/null)" = up ] || exit 1
case "$*" in *addr*) echo "    inet 172.16.0.2/32 scope global mitt0";; *) echo "9: mitt0: <POINTOPOINT,UP,LOWER_UP> mtu 1350";; esac
EOF
# «Telegram»: адрес из конфигурации на stdin (-K -), ответ по $LT/tg: ok | unauthorized | down | tunnel-only | direct-only
cat >"$SB/curl" <<'EOF'
#!/bin/sh
PATH=/usr/bin:/bin
cfg="$(cat)"; via=direct
case "$*" in *"--interface mitt0"*) via=tunnel;; esac
printf '%s | %s | %s\n' "$via" "$cfg" "$*" >>"$LT/curl.log"
case "$(cat "$LT/tg")" in
  ok) echo '{"ok":true,"result":{}}';;
  unauthorized) echo '{"ok":false,"error_code":401,"description":"Unauthorized"}';;
  down) echo "curl: (7) Failed to connect to api.telegram.org port 443" >&2; exit 7;;
  tunnel-only) [ $via = tunnel ] && echo '{"ok":true}' || { echo "curl: (28) Connection timed out" >&2; exit 28; };;
  direct-only) [ $via = direct ] && echo '{"ok":true}' || { echo "curl: (28) Connection timed out" >&2; exit 28; };;
esac
EOF
chmod +x "$SB"/*
sleep 600 & SLP=$!

root() { # root <имя> <notify-json|"">
  local d="$W/$1/root" lt="$W/$1/lt"
  mkdir -p "$d/data/mi-lumruri/etc" "$d/tmp/mi-lumruri/bin" "$d/tmp/mi-lumruri/scripts" "$d/tmp/mi-lumruri/run" "$d/tmp/mi-lumruri/log" "$lt"
  cp "$ROOT"/package/scripts/*.sh "$d/tmp/mi-lumruri/scripts/"
  printf '#!/bin/sh\nexec %s %s "$@"\n' "$Q" "$CTL" >"$d/tmp/mi-lumruri/bin/mi-tt-ctl"; chmod +x "$d/tmp/mi-lumruri/bin/mi-tt-ctl"
  if [ -n "$2" ]; then printf '{"version":1,"profiles":{},"notify":%s}\n' "$2" >"$d/data/mi-lumruri/etc/secrets.json"
  else printf '{"version":1,"profiles":{}}\n' >"$d/data/mi-lumruri/etc/secrets.json"; fi
  echo ok >"$lt/tg"; echo down >"$lt/tun"
}
nj() { printf '{"telegram_token":"%s","chat_id":"123456789","events":[%s],"lang":"%s"}' "$TOKEN" "$1" "${2:-ru}"; }
q() { # q <имя> <событие> <ключ> [параметр] [возраст_с]
  local t; t=$(( $(date +%s) - ${5:-0} ))
  printf '%s\t%s\t%s\t%s\n' "$2" "$t" "$3" "${4:-}" >>"$W/$1/root/tmp/mi-lumruri/run/notify.queue"
}
run() { # run <имя> <сценарий ash>
  timeout 120 env -i PATH="$SB" MITT_ROOT="$W/$1/root" MITT_QUIET=1 LT="$W/$1/lt" \
    "$Q" -L "$F" "$F/bin/busybox" ash -c ". \"$W/$1/root/tmp/mi-lumruri/scripts/mitt-lib.sh\"; $2" >>"$W/$1/out" 2>&1
}
send() { timeout 120 env -i PATH="$SB" MITT_ROOT="$W/$1/root" MITT_QUIET=1 LT="$W/$1/lt" \
  "$Q" -L "$F" "$F/bin/busybox" ash "$W/$1/root/tmp/mi-lumruri/scripts/mitt-notify.sh" >>"$W/$1/out" 2>&1; }
log() { cat "$W/$1/lt/curl.log" 2>/dev/null; }
res() { cat "$W/$1/root/tmp/mi-lumruri/run/notify.json" 2>/dev/null; }
queue() { cat "$W/$1/root/tmp/mi-lumruri/run/notify.queue" 2>/dev/null; }

echo "(а) уведомления не настроены: очередь сброшена, Telegram не вызывается"
root a ""; q a tunnel tunnel_down 200; send a
[ -z "$(log a)" ] && [ -z "$(queue a)" ] && ok "a: ничего не отправлено, очередь пуста" || bad "a: curl: $(log a); очередь: $(queue a)"

echo "(б) выбраны только события туннеля: туннель и проверка отправлены напрямую, обновление — нет"
root b "$(nj '"tunnel"')"; q b tunnel tunnel_down 200; q b update update_done 0.7.0; q b test test; send b
n=$(log b | wc -l); [ "$n" -eq 2 ] && ok "b: два сообщения" || bad "b: сообщений $n: $(log b)"
log b | grep -q 'text=Mi Lumruri: VPN-туннель упал: нет связи с сервером 200 с' && ok "b: текст по-русски с параметром" || bad "b: $(log b)"
log b | grep -q 'Обновлено до' && bad "b: отправлено невыбранное событие" || ok "b: невыбранное событие не отправлено"
log b | grep -q '^direct ' && ! log b | grep -q '^tunnel ' && ok "b: туннель не поднят — напрямую" || bad "b: путь: $(log b)"
log b | grep -q -- "$TOKEN | " && bad "b: токен в аргументах curl" || ok "b: токен только в конфигурации на stdin, не в аргументах"
log b | grep -q "url = \"https://api.telegram.org/bot$TOKEN/sendMessage\"" && ok "b: адрес API с токеном — в конфигурации curl" || bad "b: $(log b)"
log b | grep -q 'chat_id=123456789' && ok "b: чат" || bad "b: чат: $(log b)"
res b | grep -q '"ok":true' && [ -z "$(queue b)" ] && ok "b: итог ok, очередь пуста" || bad "b: итог $(res b); очередь $(queue b)"

echo "(в) язык панели — английский"
root c "$(nj '"failover","update"' en)"; q c failover failover_backup; q c update update_available 0.7.0; send c
log c | grep -q 'text=Mi Lumruri: The primary server is not responding: switched to the backup server' && log c | grep -q 'Version 0.7.0 is available' \
  && ok "c: тексты по-английски" || bad "c: $(log c)"

echo "(г) туннель поднят — через туннель (--interface mitt0)"
root d "$(nj '"tunnel"')"; echo up >"$W/d/lt/tun"; q d tunnel tunnel_up; send d
log d | grep -q '^tunnel ' && ok "d: через туннель" || bad "d: $(log d)"

echo "(д) туннель поднят, но через него Telegram недоступен — повтор напрямую"
root e "$(nj '"tunnel"')"; echo up >"$W/e/lt/tun"; echo direct-only >"$W/e/lt/tg"; q e tunnel watch_restart; send e
[ "$(log e | cut -d' ' -f1 | tr '\n' ' ')" = "tunnel direct " ] && res e | grep -q '"via":"direct"' && ok "e: сначала туннель, затем напрямую — отправлено" || bad "e: $(log e); $(res e)"

echo "(е) Telegram отказал (неверный токен): очередь сохранена, ошибка в итоге; потом — отправлено"
root f "$(nj '"tunnel"')"; echo unauthorized >"$W/f/lt/tg"; q f tunnel tunnel_down 300; send f
res f | grep -q '"ok":false' && res f | grep -q 'Unauthorized' && [ "$(queue f | wc -l)" -eq 1 ] && ok "f: ошибка Unauthorized, сообщение осталось в очереди" || bad "f: $(res f); очередь $(queue f)"
echo ok >"$W/f/lt/tg"; send f
res f | grep -q '"ok":true' && [ -z "$(queue f)" ] && ok "f: повтор отправил сообщение" || bad "f: $(res f); очередь $(queue f)"

echo "(ж) туннель не поднят и Telegram напрямую недоступен: не теряется"
root g "$(nj '"tunnel"')"; echo down >"$W/g/lt/tg"; q g tunnel tunnel_down 300; send g
[ "$(queue g | wc -l)" -eq 1 ] && [ "$(log g | wc -l)" -eq 1 ] && ok "g: одна попытка напрямую, сообщение ждёт" || bad "g: $(log g); очередь $(queue g)"

echo "(з) сообщения старше суток отбрасываются"
root h "$(nj '"tunnel"')"; q h tunnel tunnel_down 60 90000; send h
[ -z "$(log h)" ] && [ -z "$(queue h)" ] && ok "h: старое не отправлено и удалено" || bad "h: $(log h); очередь $(queue h)"

echo "(и) tunnel_track: клиент не подключён дольше порога — «упал» один раз; подключился — «работает»"
root i "$(nj '"tunnel"')"; L="$W/i/root/tmp/mi-lumruri"
touch "$L/run/trusttunnel.wanted"; echo "VPN_SS_CONNECTING" >"$L/log/trusttunnel.log"
run i 'MITT_NOTIFY_DOWN_AFTER=0; tunnel_track; tunnel_track; tunnel_track'
[ "$(grep -c tunnel_down "$L/run/notify.queue")" -eq 1 ] && ok "i: «упал» — одно сообщение за три прохода" || bad "i: очередь $(queue i)"
echo "$SLP" >"$L/run/trusttunnel.pid"; echo "VPN_SS_CONNECTED" >>"$L/log/trusttunnel.log"; echo up >"$W/i/lt/tun"
run i 'tunnel_track; tunnel_track'
[ "$(grep -c tunnel_up "$L/run/notify.queue")" -eq 1 ] && ok "i: «снова работает» — одно сообщение" || bad "i: очередь $(queue i)"

echo "(к) notify_flush: заявка панели на проверку ставит сообщение test; после неудачи — пауза до повтора"
root k "$(nj '')"; L="$W/k/root/tmp/mi-lumruri"; touch "$L/run/notify-test.request"
run k 'SCR="$RUN/scripts"; notify_flush; i=0; while pid_alive notify && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done'
log k | grep -q 'Проверка уведомлений' && [ ! -e "$L/run/notify-test.request" ] && ok "k: проверочное сообщение отправлено (событие test — всегда)" || bad "k: $(log k); $(cat "$W/k/out")"
printf '{"ok":false,"at":%s,"sent":0,"via":"","error":"x"}\n' "$(date +%s)" >"$L/run/notify.json"; q k tunnel tunnel_up; : >"$W/k/lt/curl.log"
run k 'SCR="$RUN/scripts"; notify_flush; sleep 2'
[ -z "$(log k)" ] && ok "k: сразу после неудачи повтора нет" || bad "k: $(log k)"

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
