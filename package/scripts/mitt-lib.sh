# mi-lumruri: общие функции установщика, загрузчика и службы (BusyBox ash 1.25.1 стока RC06 1.1.38).
# Все пути строятся от MITT_ROOT: на роутере он пуст; в лаборатории — каталог эмуляции файловой системы роутера.
# Лабораторные переопределения (MITT_LAB_*) учитываются только при непустом MITT_ROOT и в работе на роутере не действуют.

R="${MITT_ROOT:-}"
DATA="$R/data/mi-lumruri"
ETC="$DATA/etc"
# Текущий релиз — файл-указатель current.ver (замена обычного файла через mv атомарна; BusyBox 1.25 не умеет mv -T
# для символических ссылок на каталоги). Релиз: releases/<версия>/{manifest.json,manifest.sig,payload/}.
CURV="$(cat "$DATA/current.ver" 2>/dev/null)"
# Хранилище релизов: по умолчанию /data. Файл store (install.sh --store=<каталог>) переносит releases/ на внешний
# накопитель; настройки, ключи и точка автозапуска остаются в /data. Пока идёт перенос, релиз ищется и в /data.
STORE="$(cat "$DATA/store" 2>/dev/null)"; [ -n "$STORE" ] || STORE="$DATA"
REL="$STORE/releases/$CURV"
[ -d "$REL" ] || [ ! -d "$DATA/releases/$CURV" ] || REL="$DATA/releases/$CURV"
RUN="$R/tmp/mi-lumruri"
# Сценарии работают из копии в RAM: после холодного старта служба не зависит от накопителя с релизами.
SCR="$RUN/scripts"
BIN="$RUN/bin"
RENDER="$RUN/render"
STATE="$RUN/run"
LOG="$RUN/log"
LEASES="${MITT_LEASES:-$R/tmp/dhcp.leases}"
PANEL_PORT="${MITT_PANEL_PORT:-8443}"
CGI_PORT=18081

mlog() { mkdir -p "$LOG"; printf '%s %s\n' "$(date +%Y-%m-%dT%H:%M:%S)" "$*" >>"$LOG/mitt.log"; [ -n "${MITT_QUIET:-}" ] || echo "mi-lumruri: $*" >&2
  # журнал ограниченного размера (RAM): оставляем последние 400 строк
  if [ "$(wc -l <"$LOG/mitt.log")" -gt 800 ]; then tail -n 400 "$LOG/mitt.log" >"$LOG/mitt.log.t" && mv -f "$LOG/mitt.log.t" "$LOG/mitt.log"; fi; }
die() { mlog "ОШИБКА: $*"; exit 1; }

lab() { [ -n "$R" ]; }

# Эксклюзивная блокировка каталогом (mkdir атомарен); снимается trap'ом.
lock_take() { # lock_take <имя> <секунд>
  local d="$STATE/$1.lock" n=0
  mkdir -p "$STATE"
  while ! mkdir "$d" 2>/dev/null; do
    if [ -f "$d/pid" ] && ! kill -0 "$(cat "$d/pid" 2>/dev/null)" 2>/dev/null; then rm -rf "$d"; continue; fi
    n=$((n + 1)); [ "$n" -ge "$2" ] && return 1; sleep 1
  done
  echo $$ >"$d/pid"
}
lock_drop() { rm -rf "$STATE/$1.lock"; }

ctl() { "$BIN/mi-tt-ctl" "$@"; }
adm() { "$BIN/mi-tt-admin" "$@"; }

# Распаковка пакета (каталог с payload/) в каталог: программы и движки, Lua zapret2, панель (www, assets/).
unpack_payload() { # unpack_payload <каталог релиза> <куда>
  local rel="$1" to="$2" f
  mkdir -p "$to/www/assets"
  for f in "$rel"/payload/bin/*.xz "$rel"/payload/engines/*.xz; do
    [ -f "$f" ] || continue
    unxz -c "$f" >"$to/$(basename "$f" .xz)" || return 1; chmod 700 "$to/$(basename "$f" .xz)"
  done
  # mi-tt — одна программа на три имени (выбор по имени ссылки); пакеты до 0.4 содержат отдельные программы
  if [ -f "$to/mi-tt" ]; then for f in mi-tt-ctl mi-tt-admin mi-tt-dns; do rm -f "$to/$f"; ln -s mi-tt "$to/$f" || return 1; done; fi
  # Lua, блобы и списки хостов zapret2 — обычные файлы рядом с nfqws2 (--chdir)
  for f in "$rel"/payload/engines/*.lua.gz "$rel"/payload/engines/*.bin "$rel"/payload/engines/*.txt; do [ -f "$f" ] && { cp "$f" "$to/" || return 1; }; done
  for f in "$rel"/payload/www/*.xz; do
    [ -f "$f" ] || continue
    case "$(basename "$f" .xz)" in assets__*) unxz -c "$f" >"$to/www/assets/$(basename "$f" .xz | sed 's/^assets__//')" || return 1;; *) unxz -c "$f" >"$to/www/$(basename "$f" .xz)" || return 1;; esac
  done
}

# Распаковка текущего релиза в RAM с проверкой хэшей по манифесту.
unpack_runtime() {
  local rel tmp f
  [ -n "$CURV" ] && [ -d "$REL/payload" ] || die "нет текущего релиза '$CURV' в $STORE/releases (накопитель не подключён?)"
  rel="$REL"
  if [ -f "$RUN/.release" ] && [ "$(cat "$RUN/.release")" = "$rel" ] && [ -x "$BIN/mi-tt-admin" ]; then return 0; fi
  tmp="$RUN/bin.new"; rm -rf "$tmp"; mkdir -p "$tmp"
  unpack_payload "$rel" "$tmp" || { rm -rf "$tmp"; die "распаковка релиза"; }
  # проверка распакованного против манифеста (без sha256sum на стоке — средствами самого mi-tt-admin)
  local v="$tmp/mi-tt-admin"
  if lab && [ -n "${MITT_LAB_BIN:-}" ] && [ -f "$MITT_LAB_BIN/mi-tt-admin" ]; then
    v="$RUN/verify-admin"; cp "$MITT_LAB_BIN/mi-tt-admin" "$v"; cp "$tmp/mi-tt-admin" "$v.arm64"; chmod 700 "$v" "$v.arm64"
  fi
  "$v" release verify "$rel" --pinned "$DATA/keys/release.pub" --unpacked "$tmp" >"$LOG/unpack.json" 2>&1     || { cat "$LOG/unpack.json" >&2; rm -rf "$tmp"; die "распакованные файлы не совпали с манифестом"; }
  rm -f "$RUN/verify-admin" "$RUN/verify-admin.arm64"
  lab_override "$tmp"
  rm -rf "$SCR.new"; cp -r "$rel/payload/scripts" "$SCR.new" || { rm -rf "$tmp" "$SCR.new"; die "копирование сценариев в RAM"; }
  rm -rf "$SCR"; mv "$SCR.new" "$SCR"
  rm -rf "$BIN"; mv "$tmp" "$BIN"; echo "$rel" >"$RUN/.release"
  mlog "распакован релиз $(basename "$rel") в RAM"
}

# Только лаборатория (MITT_ROOT непуст): ARM64-программы запускаются через qemu-user — распакованный файл
# переименовывается в <имя>.arm64, на его место ставится обёртка из MITT_LAB_BIN. На роутере не действует.
lab_override() {
  lab && [ -n "${MITT_LAB_BIN:-}" ] || return 0
  local f n
  for f in "$MITT_LAB_BIN"/*; do n="$(basename "$f")"; [ -f "$1/$n" ] && mv "$1/$n" "$1/$n.arm64"; cp "$f" "$1/$n"; chmod 700 "$1/$n"; done
}

# Короткая причина сбоя из JSON-вывода mi-tt-ctl или mi-tt-admin: первые два «message» через «; », кавычки \" — как ',
# без «\» и табуляций (строка идёт в status.json как есть); сообщений нет — пусто.
short_err() {
  [ -f "$1" ] || return 0
  awk '{ gsub(/\\"/, "\047"); n = split($0, a, /"message": *"/)
    for (i = 2; i <= n && k < 2; i++) { m = a[i]; sub(/".*/, "", m); gsub(/[\\\t]/, "", m); printf "%s%s", (k++ ? "; " : ""), m } }' "$1"
}

# Итог последнего рендера для панели: $STATE/last-render.json {"ok":…,"at":…[,"error":"…"]}.
render_now() {
  # готовые списки сайтов (svc-*.list) — до рендера: настройки панели ссылаются на эти категории
  [ ! -f "$SCR/mitt-lists.sh" ] || sh "$SCR/mitt-lists.sh" sync >>"$LOG/lists.log" 2>&1 || mlog "списки: синхронизация не прошла, действуют прежние"
  # client.toml содержит пароль TrustTunnel: каталог рендера доступен только root
  rm -rf "$RENDER.new"; mkdir -p "$RENDER.new"; chmod 700 "$RENDER.new"
  # список рекламы: рабочая копия в RAM; после загрузки роутера — из сжатой копии в /data (mitt-adblock.sh)
  if [ ! -f "$RUN/adblock.list" ] && [ -f "$DATA/adblock.list.gz" ]; then
    gzip -dc "$DATA/adblock.list.gz" >"$RUN/adblock.list.t" 2>/dev/null && mv -f "$RUN/adblock.list.t" "$RUN/adblock.list"       && cp -f "$DATA/adblock.src" "$RUN/adblock.src" 2>/dev/null || rm -f "$RUN/adblock.list.t"
  fi
  if MI_TT_ADBLOCK_LIST="$RUN/adblock.list" MI_TT_SERVER_ADDRS="$ETC/server-addrs" ctl render "$ETC/config.json" "$ETC/secrets.json" "$RENDER.new" >"$STATE/render.json" 2>&1; then
    rm -rf "$RENDER.prev"; [ -d "$RENDER" ] && mv "$RENDER" "$RENDER.prev"; mv "$RENDER.new" "$RENDER"
    printf '{"ok":true,"at":%s}\n' "$(date +%s)" >"$STATE/last-render.json"; return 0
  fi
  local e; e="$(short_err "$STATE/render.json")"
  printf '{"ok":false,"at":%s,"error":"%s"}\n' "$(date +%s)" "${e:-настройки не сформированы}" >"$STATE/last-render.json"
  rm -rf "$RENDER.new"; mlog "render не прошёл: $(head -c 300 "$STATE/render.json")"; return 1
}

# last-apply.json — последний вызов (и защитный); full-apply.json — последнее полное применение с причиной сбоя:
# защитный вызов после сбоя полного не должен скрыть от панели, что настройки не применены.
admin_apply() { # admin_apply <метка> [--guard-only]
  local tag="$1" e=""; shift
  adm apply --state-dir "$RUN/admin" --config "$ETC/config.json" --secrets "$ETC/secrets.json" "$@" >"$STATE/apply.$tag.json" 2>&1
  local rc=$?; [ "$rc" -eq 0 ] || cp -f "$STATE/apply.$tag.json" "$STATE/apply.$tag.fail.json" 2>/dev/null
  printf '{"tag":"%s","exit":%s,"at":%s}\n' "$tag" "$rc" "$(date +%s)" >"$STATE/last-apply.json"
  if [ "${1:-}" != --guard-only ]; then
    [ "$rc" -eq 0 ] || { e="$(short_err "$STATE/apply.$tag.json")"; [ -n "$e" ] || e="код $rc"; }
    printf '{"tag":"%s","exit":%s,"at":%s,"error":%s}\n' "$tag" "$rc" "$(date +%s)" "$([ -n "$e" ] && printf '"%s"' "$e" || echo null)" >"$STATE/full-apply.json"
  fi
  mlog "apply $tag $*: код $rc"; return $rc
}

# пауза 0,2 с: sleep в BusyBox стока не понимает дробные секунды (сразу выходит с ошибкой), usleep — понимает
nap() { usleep 200000 2>/dev/null || sleep 1; }
# Запасной адрес сервера: после удачного подключения клиент пишет «Using endpoint: name=<имя>, address=<IP>:<порт>».
# Последние адреса (до трёх, свежий первым) — в $ETC/server-addrs «имя IP»: рендер добавляет их в addresses за доменом,
# и при сбое DNS на старте клиент подключается по IP, а не завершается. Файл переписывается, только если адрес новый.
server_addr_learn() {
  local l name ip f="$ETC/server-addrs"
  l="$(tail -n 60 "$LOG/trusttunnel.log" 2>/dev/null | grep 'Using endpoint: name=' | tail -n 1)"
  [ -n "$l" ] || return 0
  name="$(echo "$l" | sed -n 's/.*Using endpoint: name=\([^,]*\), address=.*/\1/p')"
  ip="$(echo "$l" | sed -n 's/.*, address=\([^,]*\),.*/\1/p' | sed 's/:[0-9]*$//; s/^\[//; s/\]$//')"
  [ -n "$name" ] && [ -n "$ip" ] || return 0
  [ "$(head -n 1 "$f" 2>/dev/null)" = "$name $ip" ] && return 0
  { echo "$name $ip"; grep -v "^$name $ip\$" "$f" 2>/dev/null; } | head -n 3 >"$f.t" && mv -f "$f.t" "$f"
}
# Проба сторожа туннеля: короткий HTTPS-запрос через mitt0 к 1.1.1.1, при неудаче — к 8.8.8.8 (решение — tunnel_tick).
WATCH_CURL="${MITT_WATCH_CURL:-curl}"
tunnel_probe() {
  local u
  for u in https://1.1.1.1/cdn-cgi/trace https://8.8.8.8/; do
    "$WATCH_CURL" -sk --interface mitt0 --max-time 6 -o /dev/null "$u" 2>/dev/null && return 0
  done
  return 1
}
# ping_ms <хост> <порт>: мс до установки TCP-соединения (с роутера, мимо туннеля) или пусто
ping_ms() {
  local h="$1" p="$2" u t
  case "$h" in *:*) u="https://[$h]:$p/";; *) u="https://$h:$p/";; esac
  t="$("${PING_CURL:-$WATCH_CURL}" -sk -o /dev/null --connect-timeout 5 --max-time 8 -w '%{time_connect}' "$u" 2>/dev/null)"
  awk -v t="$t" 'BEGIN { if (t + 0 > 0) printf "%d", t * 1000 + 0.5 }'
}
# Запасной сервер (client-backup.toml от рендера): какой файл отдать клиенту — $STATE/endpoint (primary|backup).
tt_config() { [ "$(cat "$STATE/endpoint" 2>/dev/null)" = backup ] && [ -f "$RENDER/client-backup.toml" ] && echo "$RENDER/client-backup.toml" || echo "$RENDER/client.toml"; }
# Основной сервер отвечает на TCP (проверка возврата с запасного): любой ответ или ошибка TLS — порт открыт;
# «не подключиться», тайм-аут, не разрешилось имя — нет.
primary_reachable() {
  local h p u rc
  read -r h p <"$RENDER/primary.addr" 2>/dev/null || return 1
  case "$h" in *:*) u="https://[$h]:$p/";; *) u="https://$h:$p/";; esac
  "$WATCH_CURL" -sk --connect-timeout 5 --max-time 8 -o /dev/null "$u" 2>/dev/null; rc=$?
  case "$rc" in 6|7|28) return 1;; *) return 0;; esac
}
# Решения о клиенте — mi-tt-ctl tunnel (controller/src/tunnel.rs): сторож (три неудачи проверки через mitt0 подряд —
# перезапуск клиента, не чаще раза в 5 мин), запасной сервер (нет связи дольше 2 мин — на другой; на запасном раз в
# 5 мин проверка основного, два ответа подряд — возврат) и выбор по задержке (рендер: fastest). Сценарий делает только
# пробы и действия: остановить клиент (цикл службы запустит его с файлом tt_config), уведомление, журнал.
tunnel_tick() {
  local st con=0 tun=0 bk=0 fa=0 due w="" fb="" pp="" pb="" hp hb cfg a rest
  st="$(tail -n 200 "$LOG/trusttunnel.log" 2>/dev/null | grep -o 'VPN_SS_[A-Z_]*' | tail -n 1)"
  [ "$st" = VPN_SS_CONNECTED ] && con=1
  tun_ready && tun=1
  [ -f "$RENDER/client-backup.toml" ] && bk=1
  [ -f "$RENDER/fastest" ] && fa=1
  cfg="watch_interval=${MITT_WATCH_INTERVAL:-60} watch_fails=${MITT_WATCH_FAILS:-3} watch_gap=${MITT_WATCH_GAP:-300}"
  cfg="$cfg failover_after=${MITT_FAILOVER_AFTER:-120} failback_every=${MITT_FAILBACK_EVERY:-300}"
  cfg="$cfg fastest_every=${MITT_FASTEST_EVERY:-1800} fastest_margin=${MITT_FASTEST_MARGIN:-20}"
  # shellcheck disable=SC2086
  due="$(ctl tunnel due --dir "$STATE" connected=$con tun=$tun backup=$bk fastest=$fa $cfg 2>>"$LOG/service.log")" || return 0
  case " $(echo $due) " in *" watch "*) if tunnel_probe; then w=ok; else w=fail; fi;; esac
  case " $(echo $due) " in *" failback "*) if primary_reachable; then fb=ok; else fb=fail; fi;; esac
  case " $(echo $due) " in *" fastest "*)
    hp="$(sed -n 's/^primary //p' "$RENDER/servers.addr" 2>/dev/null)"; hb="$(sed -n 's/^backup //p' "$RENDER/servers.addr" 2>/dev/null)"
    if [ -n "$hp" ] && [ -n "$hb" ]; then
      # shellcheck disable=SC2086
      pp="$(ping_ms $hp)"; pb="$(ping_ms $hb)"; pp="${pp:--}"; pb="${pb:--}"
    fi;;
  esac
  # shellcheck disable=SC2086
  ctl tunnel step --dir "$STATE" connected=$con tun=$tun backup=$bk fastest=$fa $cfg ${w:+watch=$w} ${fb:+failback=$fb} \
    ${pp:+ping_primary=$pp} ${pb:+ping_backup=$pb} 2>>"$LOG/service.log" >"$STATE/tunnel.actions"
  while read -r a rest; do
    case "$a" in
      restart) pid_stop trusttunnel;;
      log) mlog "$rest";;
      notify)
        # shellcheck disable=SC2086
        notify $rest;;
    esac
  done <"$STATE/tunnel.actions"
  rm -f "$STATE/tunnel.actions"
}
# TUN клиента готов: есть, поднят и с IPv4-адресом (клиент настраивает его не сразу после создания)
tun_ready() { ip link show mitt0 2>/dev/null | grep -q '[<,]UP[,>]' && ip -4 addr show dev mitt0 2>/dev/null | grep -q 'inet '; }
pid_alive() { [ -f "$STATE/$1.pid" ] && kill -0 "$(cat "$STATE/$1.pid")" 2>/dev/null; }
pid_stop() { if pid_alive "$1"; then kill "$(cat "$STATE/$1.pid")" 2>/dev/null; sleep 1; kill -9 "$(cat "$STATE/$1.pid")" 2>/dev/null; fi; rm -f "$STATE/$1.pid"; }
# nfqws2 после запуска сбрасывает права (UID 2147483647) и перечитывает списки хостов уже без root: данным Zapret
# нужно чтение для всех, каталогу $BIN — проход (распаковка идёт под umask 077). Секретов в этих файлах нет.
zapret_readable() {
  chmod 711 "$RUN" "$BIN"
  for f in "$BIN"/zapret-hosts-*.txt "$BIN"/*.lua.gz "$BIN"/*.bin; do [ -f "$f" ] && chmod 644 "$f"; done
  return 0
}
start_bg() { # start_bg <имя> <команда…>
  local n="$1"; shift
  "$@" >>"$LOG/$n.log" 2>&1 &
  echo $! >"$STATE/$n.pid"
}

panel_origins() {
  local ip
  ip="$( (uci ${MITT_UCI_CONF:+-c "$MITT_UCI_CONF"} -q get network.lan.ipaddr) 2>/dev/null)"; [ -n "$ip" ] || ip="192.168.31.1"
  printf 'https://%s:%s,https://miwifi.com:%s,https://router.miwifi.com:%s' "$ip" "$PANEL_PORT" "$PANEL_PORT" "$PANEL_PORT"
  [ -f "$ETC/panel.origins" ] && printf ',%s' "$(tr '\n' ',' <"$ETC/panel.origins" | sed 's/,$//')"
}

start_panel() {
  mkdir -p "$RUN/cgi/cgi-bin" "$STATE"
  # рабочие процессы nginx работают от nobody: статике панели нужно чтение для всех, каталогам выше — только проход
  # (распаковка идёт под umask 077 установщика). Программы в $BIN остаются 700, сессии и состояние — в своих каталогах.
  chmod 711 "$RUN" "$BIN"
  chmod 755 "$BIN/www" "$BIN/www/assets"
  chmod 644 "$BIN"/www/*.* "$BIN"/www/assets/*
  # CGI-обёртка: окружение контроллера; uhttpd слушает только 127.0.0.1 и доступен лишь локальному nginx (TLS)
  cat >"$RUN/cgi/cgi-bin/api" <<EOF
#!/bin/sh
export MI_TT_CONFIG='$ETC/config.json' MI_TT_AUTH_DIR='$ETC/auth' MI_TT_SESSION_DIR='$RUN/sessions' MI_TT_RUN_DIR='$STATE'
export MI_TT_SECRETS='$ETC/secrets.json' MI_TT_LEASES='$LEASES' MI_TT_ALLOWED_ORIGINS='$(panel_origins)' MI_TT_TRUST_PROXY=1
export MI_TT_LISTS_DIR='$REL/payload/lists' MI_TT_UCI_NETWORK='$R/etc/config/network'
exec '$BIN/mi-tt-ctl' cgi
EOF
  # uhttpd исполняет CGI только при бите x для прочих (S_IXOTH); секретов в обёртке нет
  chmod 755 "$RUN/cgi/cgi-bin/api"
  sed -e "s#@WWW@#$BIN/www#g" -e "s#@TLS@#$ETC/tls#g" -e "s#@PORT@#$PANEL_PORT#g" -e "s#@CGI@#$CGI_PORT#g" -e "s#@RUN@#$RUN#g" \
    "$SCR/nginx-mitt.conf" >"$RUN/nginx.conf"
  pid_alive uhttpd || start_bg uhttpd ${MITT_UHTTPD:-uhttpd} -f -p "127.0.0.1:$CGI_PORT" -h "$RUN/cgi" -x /cgi-bin -t 30 -T 30
  pid_alive nginx || start_bg nginx ${MITT_NGINX:-nginx} -c "$RUN/nginx.conf" -g "daemon off; pid $STATE/nginx.master.pid;"
  mlog "панель: https порт $PANEL_PORT (nginx), CGI на 127.0.0.1:$CGI_PORT (uhttpd)"
}

# проверка новой версии: период из расписания (update_check, сутки по умолчанию; 0 — вручную); первая — через
# MITT_UPDATE_FIRST (10 мин) после запуска службы, чтобы не мешать загрузке
update_check_due() {
  local p last now; p="${MITT_UPDATE_PERIOD:-$(sched update_check)}"; case "$p" in ''|*[!0-9]*) p=86400;; esac
  [ "$p" -gt 0 ] || return 1
  now=$(date +%s); last="$(cat "$ETC/update-check.last" 2>/dev/null)"
  [ -n "$last" ] || { last=$((now - p + ${MITT_UPDATE_FIRST:-600})); echo "$last" >"$ETC/update-check.last" 2>/dev/null; }
  [ $((now - last)) -ge "$p" ] || [ "$now" -lt "$last" ]
}

# --- статистика трафика (mi-tt-ctl stats-sample, GET /stats) ---
# раз в MITT_STATS_EVERY (5 мин): байты туннеля (mitt0), WAN (интерфейс маршрута по умолчанию) и по устройствам
# (штатный trafficd: ubus call trafficd ip). Копия в /data — раз в час (переживает перезагрузку, флеш не изнашивается).
SYS="${MITT_SYS:-/sys}"
if_bytes() { local d="$SYS/class/net/$1/statistics"; [ -r "$d/rx_bytes" ] || { echo -; return; }; echo $(( $(cat "$d/rx_bytes") + $(cat "$d/tx_bytes") )); }
wan_dev() { ip -4 route show default 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1; }
stats_sample() {
  local now last w
  now=$(date +%s); last="$(cat "$STATE/stats.last" 2>/dev/null || echo 0)"
  [ $((now - last)) -ge "${MITT_STATS_EVERY:-300}" ] || [ "$now" -lt "$last" ] || return 0
  echo "$now" >"$STATE/stats.last"
  [ -f "$STATE/stats.json" ] || { [ -f "$ETC/stats.json" ] && cp -f "$ETC/stats.json" "$STATE/stats.json"; }
  w="$(wan_dev)"
  ${MITT_UBUS:-ubus} call trafficd ip >"$STATE/trafficd.json" 2>/dev/null || rm -f "$STATE/trafficd.json"
  # подключение устройств (Wi‑Fi, сигнал) для экрана «Устройства»
  ${MITT_UBUS:-ubus} call trafficd hw >"$STATE/trafficd-hw.json.t" 2>/dev/null && mv -f "$STATE/trafficd-hw.json.t" "$STATE/trafficd-hw.json"; rm -f "$STATE/trafficd-hw.json.t"
  if [ -f "$STATE/trafficd.json" ]; then
    MI_TT_LEASES="$LEASES" "$BIN/mi-tt-ctl" stats-sample "$STATE/stats.json" "$(if_bytes mitt0)" "$( [ -n "$w" ] && if_bytes "$w" || echo -)" "$STATE/trafficd.json" 2>>"$LOG/service.log"
  else
    MI_TT_LEASES="$LEASES" "$BIN/mi-tt-ctl" stats-sample "$STATE/stats.json" "$(if_bytes mitt0)" "$( [ -n "$w" ] && if_bytes "$w" || echo -)" 2>>"$LOG/service.log"
  fi
  rm -f "$STATE/trafficd.json"
  # раз в час — копия в /data
  if [ $((now / 3600)) != "$(cat "$STATE/stats.saved" 2>/dev/null)" ] && [ -f "$STATE/stats.json" ]; then
    cp -f "$STATE/stats.json" "$ETC/stats.json.t" 2>/dev/null && mv -f "$ETC/stats.json.t" "$ETC/stats.json" && echo $((now / 3600)) >"$STATE/stats.saved"
  fi
}

# --- сведения об устройствах (экран «Устройства», controller/src/devices.rs и discover.rs) ---
# таблица производителей по MAC из прошивки (oui.tar.gz) — один раз в RAM; имена, объявленные в сети (mDNS, SSDP), —
# раз в MITT_NAMES_EVERY (10 мин) и по кнопке панели; копия в /data — раз в час (переживает перезагрузку)
OUI_TGZ="${MITT_OUI_TGZ:-$R/usr/share/xiaoqiang/oui.tar.gz}"
lan_ip() { local ip; ip="$( (uci ${MITT_UCI_CONF:+-c "$MITT_UCI_CONF"} -q get network.lan.ipaddr) 2>/dev/null)"; echo "${ip:-192.168.31.1}"; }
devices_prepare() {
  [ -s "$STATE/oui.txt" ] || { [ -f "$OUI_TGZ" ] && tar -xzOf "$OUI_TGZ" >"$STATE/oui.txt.t" 2>/dev/null && mv -f "$STATE/oui.txt.t" "$STATE/oui.txt"; rm -f "$STATE/oui.txt.t"; }
  [ -f "$STATE/names.json" ] || { [ -f "$ETC/names.json" ] && cp -f "$ETC/names.json" "$STATE/names.json"; }
  return 0
}
names_scan() {
  local now last
  now=$(date +%s); last="$(cat "$STATE/names.last" 2>/dev/null || echo 0)"
  if [ -f "$STATE/discover.request" ]; then rm -f "$STATE/discover.request"
  elif [ $((now - last)) -lt "${MITT_NAMES_EVERY:-600}" ] && [ "$now" -ge "$last" ]; then return 0; fi
  pid_alive names && return 0
  echo "$now" >"$STATE/names.last"
  start_bg names env MI_TT_LEASES="$LEASES" "$BIN/mi-tt-ctl" names-scan --from "$(lan_ip)" --out "$STATE/names.json" --wait "${MITT_NAMES_WAIT:-3000}"
  if [ $((now / 3600)) != "$(cat "$STATE/names.saved" 2>/dev/null)" ] && [ -f "$STATE/names.json" ]; then
    cp -f "$STATE/names.json" "$ETC/names.json.t" 2>/dev/null && mv -f "$ETC/names.json.t" "$ETC/names.json" && echo $((now / 3600)) >"$STATE/names.saved"
  fi
}

# --- уведомления в Telegram (mitt-notify.sh) ---
# notify <событие> <ключ сообщения> [параметр]: в очередь; mitt-notify.sh отправит, если событие выбрано в панели
notify() {
  mkdir -p "$STATE" 2>/dev/null
  printf '%s\t%s\t%s\t%s\n' "$1" "$(date +%s)" "$2" "$(printf '%s' "${3:-}" | tr '\t\n' '  ' | cut -c1-300)" >>"$STATE/notify.queue"
  tail -n 50 "$STATE/notify.queue" >"$STATE/notify.queue.t" && mv -f "$STATE/notify.queue.t" "$STATE/notify.queue"
}
# проход службы: пробное сообщение по заявке панели; очередь не пуста — отправка в фоне (одна одновременно)
notify_flush() {
  [ -f "$STATE/notify-test.request" ] && { rm -f "$STATE/notify-test.request"; notify test test; }
  { [ -s "$STATE/notify.queue" ] || [ -s "$STATE/notify.queue.sending" ]; } || return 0
  pid_alive notify && return 0
  # после неудачи — не чаще раза в MITT_NOTIFY_RETRY (2 мин)
  local now last; now=$(date +%s); last="$(sed -n 's/.*"ok":false,"at":\([0-9]*\).*/\1/p' "$STATE/notify.json" 2>/dev/null)"
  [ -z "$last" ] || [ $((now - last)) -ge "${MITT_NOTIFY_RETRY:-120}" ] || [ "$now" -lt "$last" ] || return 0
  start_bg notify sh "$SCR/mitt-notify.sh"
}
# туннель упал (клиент не подключён дольше MITT_NOTIFY_DOWN_AFTER, 3 мин) и поднялся снова — по одному сообщению
tunnel_track() {
  [ -f "$STATE/trusttunnel.wanted" ] || { rm -f "$STATE/tun-notified" "$STATE/tun-bad-since"; return 0; }
  local st now since
  st="$(tail -n 200 "$LOG/trusttunnel.log" 2>/dev/null | grep -o 'VPN_SS_[A-Z_]*' | tail -n 1)"; now=$(date +%s)
  if pid_alive trusttunnel && [ "$st" = VPN_SS_CONNECTED ] && tun_ready; then
    rm -f "$STATE/tun-bad-since"
    [ "$(cat "$STATE/tun-notified" 2>/dev/null)" = down ] && { notify tunnel tunnel_up; echo up >"$STATE/tun-notified"; }
    return 0
  fi
  since="$(cat "$STATE/tun-bad-since" 2>/dev/null)"; [ -n "$since" ] || { echo "$now" >"$STATE/tun-bad-since"; return 0; }
  if [ $((now - since)) -ge "${MITT_NOTIFY_DOWN_AFTER:-180}" ] && [ "$(cat "$STATE/tun-notified" 2>/dev/null)" != down ]; then
    notify tunnel tunnel_down "$((now - since))"; echo down >"$STATE/tun-notified"
  fi
}

# --- автозапуск и прошивка ---
# Запись `config include 'mitt'` в firewall может пропасть: обновление прошивки, сброс или правка настроек firewall
# штатным интерфейсом. Служба раз в 10 минут проверяет её и восстанавливает; `mitt-boot.sh repair` — то же вручную.
UCI="uci ${MITT_UCI_CONF:+-c $MITT_UCI_CONF}"
autostart_ok() {
  [ "$($UCI -q get firewall.mitt)" = include ] && [ "$($UCI -q get firewall.mitt.path)" = "$DATA/mitt-boot.sh" ] \
    && [ "$($UCI -q get firewall.mitt.enabled)" != 0 ]
}
autostart_set() {
  $UCI -q delete firewall.mitt
  $UCI set firewall.mitt=include && $UCI set firewall.mitt.type=script && $UCI set firewall.mitt.path="$DATA/mitt-boot.sh" \
    && $UCI set firewall.mitt.reload=1 && $UCI set firewall.mitt.enabled=1 && $UCI commit firewall
}
# точки входа нет (пакет удалён) — восстанавливать нечего
autostart_heal() {
  [ -f "$DATA/mitt-boot.sh" ] || return 0
  autostart_ok && return 0
  if autostart_set; then mlog "автозапуск: запись в настройках firewall пропала — восстановлена"; date +%s >"$STATE/autostart-healed"
  else mlog "автозапуск: запись в настройках firewall пропала, восстановить не удалось"; return 1; fi
}
rom_now() { sed -n "s/.*option ROM '\(.*\)'.*/\1/p" "$R/usr/share/xiaoqiang/xiaoqiang_version" 2>/dev/null; }
ROM_TESTED=1.1.38
# смена прошивки с прошлого запуска: «<было> <стало> <unix>» в $ETC/rom.changed (для диагностики)
rom_track() {
  local rom seen; rom="$(rom_now)"; seen="$(cat "$ETC/rom.seen" 2>/dev/null)"
  [ -n "$rom" ] && [ "$rom" != "$seen" ] || return 0
  if [ -n "$seen" ]; then mlog "прошивка изменилась: $seen → $rom"; echo "$seen $rom $(date +%s)" >"$ETC/rom.changed"; fi
  echo "$rom" >"$ETC/rom.seen"
}

status_write() {
  local e="" n
  for n in trusttunnel nfqws2 nginx uhttpd service; do
    if pid_alive "$n"; then e="$e\"$n\":true,"; elif [ -f "$STATE/$n.wanted" ]; then e="$e\"$n\":false,"; fi
  done
  # render — итог последнего рендера (ok, error), apply — последнего полного применения (exit, error)
  # endpoint — к какому серверу подключён клиент: primary или backup (запасной задан и связи с основным нет)
  local ep; ep="$(cat "$STATE/endpoint" 2>/dev/null)"; [ -f "$RENDER/client-backup.toml" ] || ep=""; [ -n "$ep" ] || ep=primary
  printf '{"at":%s,"release":"%s","protection":"%s","endpoint":"%s","engines":{%s},"last_apply":%s,"render":%s,"apply":%s}\n' "$(date +%s)" "$(basename "$(cat "$RUN/.release" 2>/dev/null)")" \
    "$(cat "$STATE/protection" 2>/dev/null || echo none)" "$ep" "${e%,}" "$(cat "$STATE/last-apply.json" 2>/dev/null || echo null)" \
    "$(cat "$STATE/last-render.json" 2>/dev/null || echo null)" "$(cat "$STATE/full-apply.json" 2>/dev/null || echo null)" >"$STATE/status.json.t" && mv -f "$STATE/status.json.t" "$STATE/status.json"
}

# --- готовые списки сайтов (mitt-lists.sh) ---
# частоты из настроек: рендер пишет $RENDER/schedule («lists=<секунд>», «zapret_check=<секунд>»; 0 — только вручную)
sched() { sed -n "s/^$1=//p" "$RENDER/schedule" 2>/dev/null | head -n 1; }
lists_period() { local v; v="${MITT_LISTS_PERIOD:-$(sched lists)}"; case "$v" in ''|*[!0-9]*) echo 86400;; *) echo "$v";; esac; }
# для отсрочек после прогона: «только вручную» считается как сутки (сама служба тогда не проверяет, см. lists_due)
LISTS_PERIOD="$(lists_period)"; [ "$LISTS_PERIOD" -gt 0 ] || LISTS_PERIOD=86400
LISTS_RETRY="${MITT_LISTS_RETRY:-3600}"      # без связи или без каталога — повтор через час
LISTS_CAT="$REL/payload/lists/catalog.json"
lists_commit() { sed -n 's/^ *"commit": *"\([0-9a-f]*\)".*/\1/p' "$LISTS_CAT" 2>/dev/null | head -n 1; }
# пора проверять обновления. Метка .checked: «<unix> <коммит каталога>». Каталога нет — нет (повтор только по заявке);
# метки нет, сменился релиз (другой коммит снимка), прошли сутки или часы роутера ушли назад — да.
# Сначала — отсрочка в RAM $STATE/lists-next «<не раньше unix> <коммит>»: её пишет каждый прогон update (успех — сутки,
# сбой — час). Она действует, даже если /data не записывается (нет .checked): иначе проверка шла бы каждые 5 с.
# Отсрочка другого снимка или дальше суток вперёд (часы ушли назад) не в счёт.
lists_due() {
  local c cm now LISTS_PERIOD
  [ -f "$LISTS_CAT" ] || return 1
  # частота могла смениться после запуска службы; 0 — проверка только по кнопке
  LISTS_PERIOD="$(lists_period)"; [ "$LISTS_PERIOD" -gt 0 ] || return 1
  now="$(date +%s)"
  { read -r c cm <"$STATE/lists-next"; } 2>/dev/null
  case "$c" in ''|*[!0-9]*) ;; *) [ "$cm" != "$(lists_commit)" ] || [ "$c" -le "$now" ] || [ $((c - now)) -gt "$LISTS_PERIOD" ] || return 1;; esac
  c=""; cm=""
  { read -r c cm <"$DATA/lists/.checked"; } 2>/dev/null
  case "$c" in ''|*[!0-9]*) return 0;; esac
  [ "$cm" = "$(lists_commit)" ] || return 0
  [ "$c" -gt "$now" ] || [ $((now - c)) -ge "$LISTS_PERIOD" ]
}

# --- защищённый DNS (mi-tt-dns) ---
# DNS провайдера для запасного пути прокси: resolv-файл штатного dnsmasq (uci), иначе обычные места OpenWrt
resolv_file() {
  local f
  for f in "$( (uci ${MITT_UCI_CONF:+-c "$MITT_UCI_CONF"} -q get dhcp.@dnsmasq[0].resolvfile) 2>/dev/null)" \
    "$R/tmp/resolv.conf.d/resolv.conf.auto" "$R/tmp/resolv.conf.auto"; do
    [ -n "$f" ] && [ -f "$f" ] && { echo "$f"; return 0; }
  done
  echo "$R/tmp/resolv.conf.auto"
}

# --- список рекламы (mitt-adblock.sh) ---
# пора скачивать, если блокировка включена (есть adblock.url) и: в этой загрузке роутера ещё не скачивали или нажата
# «Обновить» (нет $STATE/adblock-next), сменилась ссылка, подошёл срок отсрочки (успех — период списков, сбой — час)
# и при этом списка нет или он от другой ссылки; при «только вручную» служба сама не обновляет
adblock_due() {
  local n u now want
  [ -f "$RENDER/adblock.url" ] || return 1
  want="$(head -n 1 "$RENDER/adblock.url")"; now="$(date +%s)"
  { read -r n u <"$STATE/adblock-next"; } 2>/dev/null
  case "$n" in ''|*[!0-9]*) return 0;; esac
  [ "$u" = "$want" ] || return 0
  [ "$n" -le "$now" ] || return 1
  [ -f "$RUN/adblock.list" ] && [ "$(cat "$RUN/adblock.src" 2>/dev/null)" = "$want" ] || return 0
  [ "$(lists_period)" -gt 0 ]
}

# --- подбор стратегии Zapret (mitt-zapret-test.sh) ---
# автопроверка способа по расписанию: Zapret используется, прошёл период с прошлой проверки ($ETC/zapret-check.last,
# переживает перезагрузку) и роутер работает больше 10 минут — сеть и часы успели подняться
zt_check_due() {
  local p last now up
  p="$(sched zapret_check)"; case "$p" in ''|0|*[!0-9]*) return 1;; esac
  [ -f "$RENDER/nfqws2.args" ] || return 1
  up="$(cut -d. -f1 /proc/uptime 2>/dev/null)"; [ "${up:-0}" -ge "${MITT_ZT_CHECK_UPTIME:-600}" ] || return 1
  last="$(cat "$ETC/zapret-check.last" 2>/dev/null)"; case "$last" in ''|*[!0-9]*) last=0;; esac
  now="$(date +%s)"
  [ "$last" -gt "$now" ] || [ $((now - last)) -ge "$p" ]
}
# Метка отката в /data (переживает перезагрузку): строки «<general|youtube> <прежний id> <применённый id>» пишутся до смены
# стратегии и снимаются, только когда подбор закончился (стратегия подтверждена или возвращена). Оставшуюся метку — подбор
# убит сигналом, KILL или перезагрузкой — разбирают служба (zt_recover, zt_service_recover) и следующий подбор.
# Если стратегию после подбора уже сменили (в настройках не применённый id), прежняя не возвращается — строка снимается.
ZT_ROLLBACK="$ETC/zapret-test.rollback"
ZT_RETRY="$STATE/zapret-test.retry"   # повторы службы: «<попыток> <не раньше unix>» (RAM)
zt_apply_request() { printf '{"requested_unix":%s,"by":"zapret-test"}\n' "$(date +%s)" >"$STATE/apply.request"; }
zt_set() { # zt_set <general|youtube> <id>: вывод mi-tt-ctl zapret-set; занятые настройки (busy) — до 5 попыток
  local n=0 o
  while :; do
    o="$(ctl zapret-set "$ETC/config.json" "$1" "$2" </dev/null)" && { echo "$o"; return 0; }
    n=$((n + 1))
    if [ "$n" -ge 5 ] || ! echo "$o" | grep -q '"busy"'; then echo "$o"; return 1; fi
    sleep 1
  done
}
# Вернуть всё из метки отката. ZT_LEFT — что вернуть не удалось («вид=id …», для журнала; тогда в метке остаются только
# эти строки), ZT_LEFT_TXT — то же словами для панели, без id стратегий; ZT_RESTORED — что-то возвращено.
zt_undo() {
  local k id new cur now left=""
  ZT_LEFT=""; ZT_LEFT_TXT=""; ZT_RESTORED=""
  [ -f "$ZT_ROLLBACK" ] || return 0
  now="$(ctl zapret-get "$ETC/config.json" </dev/null)" || { ZT_LEFT=" (настройки не прочитаны)"; ZT_LEFT_TXT="настройки не прочитаны"; mlog "подбор Zapret: настройки не прочитаны, откат отложен"; return 1; }
  while read -r k id new; do
    [ -n "$k" ] || continue
    cur="$(echo "$now" | sed -n "s/^$k //p")"
    if [ -n "$new" ] && [ "$cur" != "$new" ]; then
      [ "$cur" = "$id" ] || mlog "подбор Zapret: $k = $cur выбрана после подбора — прежняя ($id) не возвращается"
      continue
    fi
    if zt_set "$k" "$id" >/dev/null; then mlog "подбор Zapret: возвращена стратегия $k = $id"; ZT_RESTORED=1
    else
      ZT_LEFT="$ZT_LEFT $k=$id"; left="$left$k $id $new
"
      case "$k" in general) k="для всех сайтов";; *) k="для YouTube";; esac
      ZT_LEFT_TXT="${ZT_LEFT_TXT:+$ZT_LEFT_TXT, }$k"
    fi
  done <"$ZT_ROLLBACK"
  [ -z "$ZT_RESTORED" ] || zt_apply_request
  if [ -n "$ZT_LEFT" ]; then
    printf '%s' "$left" >"$ZT_ROLLBACK.t" && mv -f "$ZT_ROLLBACK.t" "$ZT_ROLLBACK"
    mlog "подбор Zapret: не удалось вернуть$ZT_LEFT"; return 1
  fi
  rm -f "$ZT_ROLLBACK"
}
zt_fail_state() { # zt_fail_state <сообщение> <true|false: применено>
  local f="$STATE/zapret-test.json" now; now="$(date +%s)"
  if [ -f "$f" ]; then
    sed -e 's|"state":"[a-z]*"|"state":"failed"|' -e "s|\"finished\":null|\"finished\":$now|" -e 's|"current":"[^"]*"|"current":""|' \
      -e "s|\"applied\":[a-z]*|\"applied\":$2|" -e "s|\"message\":\"[^\"]*\"|\"message\":\"$1\"|" "$f" >"$f.t" && mv -f "$f.t" "$f"
  else
    printf '{"state":"failed","started":%s,"finished":%s,"progress":{"done":0,"total":0,"current":""},"control":{"opened":0,"total":0},"best":null,"youtube":null,"applied":%s,"message":"%s"}\n' \
      "$now" "$now" "$2" "$1" >"$f"
  fi
}
# Подбор, завершившийся без итога: вернуть прежние стратегии, состояние — failed. Не трогает идущий сценарий.
zt_recover() {
  local had="" lp
  # сценарий подбора идёт (держит блокировку) — не мешать; сам сценарий вызывает разбор под своей блокировкой
  lp="$(cat "$STATE/zapret-test.lock/pid" 2>/dev/null)"
  [ -n "$lp" ] && [ "$lp" != "$$" ] && kill -0 "$lp" 2>/dev/null && return 0
  pid_alive zapret-nfqws && pid_stop zapret-nfqws   # проверочный nfqws2 убитого сценария
  [ -f "$ZT_ROLLBACK" ] && had=1
  [ -n "$had" ] || grep -q '"state":"running"' "$STATE/zapret-test.json" 2>/dev/null || return 0
  if zt_undo; then
    rm -f "$ZT_RETRY"
    if [ -n "$ZT_RESTORED" ]; then zt_fail_state "Подбор прервался; прежний способ восстановлен" false
    elif [ -n "$had" ]; then zt_fail_state "Подбор прервался; способ уже сменили вручную — он оставлен" false
    else zt_fail_state "Подбор прервался; настройки не изменены" false; fi
    mlog "подбор Zapret: незавершённый подбор разобран"
  else
    zt_fail_state "Подбор прервался; не удалось вернуть прежний способ ($ZT_LEFT_TXT)" true; return 1
  fi
}
# Служба в цикле: не больше 3 попыток (сразу, через 1 мин, через 5 мин); затем метка и failed остаются до запуска
# службы или следующего подбора — без повторов в журнале.
zt_service_recover() {
  local n=0 next=0 now d
  [ -f "$ZT_ROLLBACK" ] || { grep -q '"state":"running"' "$STATE/zapret-test.json" 2>/dev/null && zt_recover; return 0; }
  [ -f "$ZT_RETRY" ] && read -r n next <"$ZT_RETRY"
  [ "$n" -lt 3 ] || return 0
  now="$(date +%s)"; [ "$now" -ge "$next" ] || return 0
  n=$((n + 1)); set -- ${MITT_ZT_RETRY_DELAYS:-60 300}
  case "$n" in 1) d="$1";; *) d="$2";; esac
  echo "$n $((now + d))" >"$ZT_RETRY"
  zt_recover && return 0
  [ "$n" -lt 3 ] || mlog "подбор Zapret: служба прекращает попытки вернуть прежнюю стратегию (3 неудачи); метка отката оставлена"
}
