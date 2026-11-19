# mi-trusttunnel: общие функции установщика, загрузчика и службы (BusyBox ash 1.25.1 стока RC06 1.1.38).
# Все пути строятся от MITT_ROOT: на роутере он пуст; в лаборатории — каталог эмуляции файловой системы роутера.
# Лабораторные переопределения (MITT_LAB_*) учитываются только при непустом MITT_ROOT и в работе на роутере не действуют.

R="${MITT_ROOT:-}"
DATA="$R/data/mi-trusttunnel"
ETC="$DATA/etc"
# Текущий релиз — файл-указатель current.ver (замена обычного файла через mv атомарна; BusyBox 1.25 не умеет mv -T
# для символических ссылок на каталоги). Релиз: releases/<версия>/{manifest.json,manifest.sig,payload/}.
CURV="$(cat "$DATA/current.ver" 2>/dev/null)"
# Хранилище релизов: по умолчанию /data. Файл store (install.sh --store=<каталог>) переносит releases/ на внешний
# накопитель; настройки, ключи и точка автозапуска остаются в /data. Пока идёт перенос, релиз ищется и в /data.
STORE="$(cat "$DATA/store" 2>/dev/null)"; [ -n "$STORE" ] || STORE="$DATA"
REL="$STORE/releases/$CURV"
[ -d "$REL" ] || [ ! -d "$DATA/releases/$CURV" ] || REL="$DATA/releases/$CURV"
RUN="$R/tmp/mi-trusttunnel"
# Сценарии работают из копии в RAM: после холодного старта служба не зависит от накопителя с релизами.
SCR="$RUN/scripts"
BIN="$RUN/bin"
RENDER="$RUN/render"
STATE="$RUN/run"
LOG="$RUN/log"
LEASES="${MITT_LEASES:-$R/tmp/dhcp.leases}"
PANEL_PORT="${MITT_PANEL_PORT:-8443}"
CGI_PORT=18081

mlog() { mkdir -p "$LOG"; printf '%s %s\n' "$(date +%Y-%m-%dT%H:%M:%S)" "$*" >>"$LOG/mitt.log"; [ -n "${MITT_QUIET:-}" ] || echo "mi-trusttunnel: $*" >&2
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

render_now() {
  # client.toml содержит пароль TrustTunnel: каталог рендера доступен только root
  rm -rf "$RENDER.new"; mkdir -p "$RENDER.new"; chmod 700 "$RENDER.new"
  if ctl render "$ETC/config.json" "$ETC/secrets.json" "$RENDER.new" >"$STATE/render.json" 2>&1; then
    rm -rf "$RENDER.prev"; [ -d "$RENDER" ] && mv "$RENDER" "$RENDER.prev"; mv "$RENDER.new" "$RENDER"; return 0
  fi
  rm -rf "$RENDER.new"; mlog "render не прошёл: $(head -c 300 "$STATE/render.json")"; return 1
}

admin_apply() { # admin_apply <метка> [--guard-only]
  local tag="$1"; shift
  adm apply --state-dir "$RUN/admin" --config "$ETC/config.json" --secrets "$ETC/secrets.json" "$@" >"$STATE/apply.$tag.json" 2>&1
  local rc=$?; printf '{"tag":"%s","exit":%s,"at":%s}\n' "$tag" "$rc" "$(date +%s)" >"$STATE/last-apply.json"
  mlog "apply $tag $*: код $rc"; return $rc
}

pid_alive() { [ -f "$STATE/$1.pid" ] && kill -0 "$(cat "$STATE/$1.pid")" 2>/dev/null; }
pid_stop() { if pid_alive "$1"; then kill "$(cat "$STATE/$1.pid")" 2>/dev/null; sleep 1; kill -9 "$(cat "$STATE/$1.pid")" 2>/dev/null; fi; rm -f "$STATE/$1.pid"; }
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

status_write() {
  local e="" n
  for n in trusttunnel nfqws2 nginx uhttpd service; do
    if pid_alive "$n"; then e="$e\"$n\":true,"; elif [ -f "$STATE/$n.wanted" ]; then e="$e\"$n\":false,"; fi
  done
  printf '{"at":%s,"release":"%s","protection":"%s","engines":{%s},"last_apply":%s}\n' "$(date +%s)" "$(basename "$(cat "$RUN/.release" 2>/dev/null)")" \
    "$(cat "$STATE/protection" 2>/dev/null || echo none)" "${e%,}" "$(cat "$STATE/last-apply.json" 2>/dev/null || echo null)" >"$STATE/status.json.t" && mv -f "$STATE/status.json.t" "$STATE/status.json"
}
