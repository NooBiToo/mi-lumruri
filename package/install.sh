#!/bin/sh
# mi-trusttunnel: установка и обновление по SSH во внутреннюю память (/data), без USB и без сети.
# Запуск на роутере из распакованного пакета:  sh install.sh [install|rollback|uninstall [--purge]|status] [--no-start]
#   install   — проверки (модель, ARM64, прошивка, место на /data и в /tmp, исполнение в /tmp), проверка подписи
#               и хэшей, пробный запуск всех программ в RAM, затем атомарное переключение current; прежний релиз — previous.
#   rollback  — current ← previous (атомарно), перезапуск.
#   uninstall — остановка, снятие своих правил, удаление автозапуска; --purge удаляет и настройки.
# Ничего не меняется, пока все проверки не пройдены. Прерывание (питание, обрыв SSH) оставляет прежний current.
set -u
PKG="$(cd "$(dirname "$0")" && pwd)"
. "$PKG/payload/scripts/mitt-lib.sh"
CMD="${1:-install}"; [ $# -gt 0 ] && shift
NOSTART=""; PURGE=""
for a in "$@"; do case "$a" in --no-start) NOSTART=1;; --purge) PURGE=1;; *) echo "неизвестный аргумент $a"; exit 2;; esac; done
RESERVE_DATA=$((2 * 1024 * 1024))   # оставить штатной прошивке на /data
RESERVE_TMP=$((16 * 1024 * 1024))   # RAM для работы движков сверх распакованных файлов
UCI="uci ${MITT_UCI_CONF:+-c $MITT_UCI_CONF}"
say() { echo "mi-trusttunnel: $*"; }
fail() { say "ОТКАЗ: $*"; exit 3; }
fault() { lab && [ "${MITT_LAB_FAIL_AT:-}" = "$1" ] && { say "лаборатория: прерывание на шаге $1"; kill -9 $$; }; return 0; }

jget() { sed -n "s/.*\"$1\": *\"\{0,1\}\([^\",}]*\)\"\{0,1\}.*/\1/p" "$PKG/manifest.json" | head -1; }
avail_kb() { df -k "$1" 2>/dev/null | awk 'NR>1 {v=$4} END {print v+0}'; }

checks() {
  local ver hw rom arch need_d need_t have_d have_t t
  ver="$R/usr/share/xiaoqiang/xiaoqiang_version"
  [ -f "$ver" ] || fail "не найден $ver: это не роутер Xiaomi на штатной прошивке"
  hw="$(sed -n "s/.*option HARDWARE '\(.*\)'.*/\1/p" "$ver")"; rom="$(sed -n "s/.*option ROM '\(.*\)'.*/\1/p" "$ver")"
  [ "$hw" = "RC06" ] || fail "модель $hw, а пакет собран для RC06 (BE7000)"
  [ "$rom" = "1.1.38" ] || say "ВНИМАНИЕ: прошивка $rom; проверено для 1.1.38 — возможности ядра проверит mi-tt-admin caps"
  arch="$(uname -m)"; [ "$arch" = "aarch64" ] || fail "архитектура $arch, нужна aarch64"
  command -v unxz >/dev/null || fail "нет unxz (BusyBox)"
  need_d="$(jget data_bytes)"; need_t="$(jget tmp_bytes)"
  [ -d "$R/data" ] || fail "нет раздела /data"
  have_d=$(( $(avail_kb "$R/data") * 1024 )); have_t=$(( $(avail_kb "$R/tmp") * 1024 ))
  # при обновлении прежний релиз остаётся для отката: нужен объём ещё одного релиза
  [ "$have_d" -ge $((need_d + RESERVE_DATA)) ] || fail "на /data свободно $have_d байт, нужно $need_d + резерв $RESERVE_DATA"
  [ "$have_t" -ge $((need_t + RESERVE_TMP)) ] || fail "в /tmp свободно $have_t байт, нужно $need_t + резерв $RESERVE_TMP"
  t="$R/tmp/.mitt-exec.$$"; printf '#!/bin/sh\nexit 0\n' >"$t" && chmod 700 "$t" && "$t" || { rm -f "$t"; fail "в /tmp нельзя исполнять файлы"; }
  rm -f "$t"
  say "проверки: RC06 $rom, $arch; /data свободно $have_d (нужно $need_d), /tmp свободно $have_t (нужно $need_t)"
}

verify_and_try() { # подпись и хэши; пробный запуск всех программ из RAM
  local st="$R/tmp/mi-trusttunnel.check.$$" f pinned=""
  rm -rf "$st"; mkdir -p "$st"
  mkdir -p "$st/pre"
  unxz -c "$PKG/payload/bin/mi-tt-admin.xz" >"$st/pre/mi-tt-admin" && chmod 700 "$st/pre/mi-tt-admin" || fail "распаковка mi-tt-admin"
  lab_override "$st/pre"
  cp "$st/pre/mi-tt-admin" "$st/mi-tt-admin.run"; [ -f "$st/pre/mi-tt-admin.arm64" ] && cp "$st/pre/mi-tt-admin.arm64" "$st/mi-tt-admin.run.arm64"
  [ -f "$DATA/keys/release.pub" ] && pinned="--pinned $DATA/keys/release.pub"
  # при обновлении пакет проверяет уже установленный mi-tt-admin закреплённым ключом
  local verifier="$st/mi-tt-admin.run"; [ -n "$pinned" ] && [ -x "$BIN/mi-tt-admin" ] && verifier="$BIN/mi-tt-admin"
  # shellcheck disable=SC2086
  "$verifier" release verify "$PKG" $pinned >"$st/verify.json" 2>&1 || { cat "$st/verify.json"; rm -rf "$st"; fail "подпись или хэши пакета не прошли проверку"; }
  unpack_payload "$PKG" "$st" || fail "распаковка пакета в RAM"
  "$st/mi-tt-admin.run" release verify "$PKG" --unpacked "$st" >"$st/unpacked.json" 2>&1 || { cat "$st/unpacked.json"; rm -rf "$st"; fail "распакованные файлы не совпали с манифестом"; }
  lab_override "$st"
  "$st/mi-tt-ctl" --version >/dev/null 2>&1 || fail "mi-tt-ctl не запускается"
  "$st/mi-tt-admin" sha256 "$PKG/manifest.json" >/dev/null 2>&1 || fail "mi-tt-admin не запускается"
  "$st/mihomo" -v >/dev/null 2>&1 || fail "mihomo не запускается"
  "$st/dnscrypt-proxy" -version >/dev/null 2>&1 || fail "dnscrypt-proxy не запускается"
  "$st/nfqws2" --version >/dev/null 2>&1; [ $? -le 1 ] || fail "nfqws2 не запускается"
  say "подпись: $(sed -n 's/.*"key_fingerprint": *"\([0-9a-f]*\)".*/\1/p' "$st/verify.json") ($( [ -n "$pinned" ] && echo "закреплённый ключ" || echo "первая установка: сверьте отпечаток"))"
  rm -rf "$st"
}

# постоянная точка входа для fw3: находит текущий релиз по current.ver (сама не меняется при обновлениях)
write_stub() {
  printf '#!/bin/sh\n# mi-trusttunnel: вход автозапуска (fw3 include)\nD="${MITT_ROOT:-}/data/mi-trusttunnel"\nV="$(cat "$D/current.ver" 2>/dev/null)" || exit 0\n[ -f "$D/releases/$V/payload/scripts/mitt-boot.sh" ] || exit 0\nexec sh "$D/releases/$V/payload/scripts/mitt-boot.sh" "$@"\n' >"$DATA/mitt-boot.sh.new" \
    && chmod 755 "$DATA/mitt-boot.sh.new" && mv -f "$DATA/mitt-boot.sh.new" "$DATA/mitt-boot.sh" || fail "запись точки входа"
}
autostart_on() {
  write_stub
  $UCI -q delete firewall.mitt
  $UCI set firewall.mitt=include && $UCI set firewall.mitt.type=script && $UCI set firewall.mitt.path="$DATA/mitt-boot.sh" \
    && $UCI set firewall.mitt.reload=1 && $UCI set firewall.mitt.enabled=1 && $UCI commit firewall || fail "не удалось зарегистрировать автозапуск"
}
autostart_off() { $UCI -q delete firewall.mitt; $UCI commit firewall; }
setver() { # setver <current|previous> <версия>: атомарная замена файла-указателя
  printf '%s\n' "$2" >"$DATA/$1.ver.new" && sync && mv -f "$DATA/$1.ver.new" "$DATA/$1.ver" || fail "запись $1.ver"
}
boot_sh() { sh "$DATA/mitt-boot.sh" "$@"; }

first_setup() {
  mkdir -p "$ETC/auth" "$ETC/tls" "$ETC/categories" "$DATA/keys" "$DATA/releases"
  chmod 700 "$DATA" "$ETC" "$ETC/auth" "$ETC/tls" "$DATA/keys"
  [ -f "$ETC/config.json" ] || cp "$PKG/payload/defaults/config.json" "$ETC/config.json"
  [ -f "$ETC/secrets.json" ] || { printf '{"version":1,"profiles":{}}\n' >"$ETC/secrets.json"; chmod 600 "$ETC/secrets.json"; }
  [ -f "$DATA/keys/release.pub" ] || jget pubkey >"$DATA/keys/release.pub"
  if [ ! -f "$ETC/tls/key.pem" ]; then
    # свой ключ и сертификат панели для этого устройства (штатный сертификат прошивки общий для всех роутеров)
    ${MITT_OPENSSL:-openssl} req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=mi-trusttunnel" \
      -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" >/dev/null 2>&1 || fail "не удалось выпустить сертификат панели (openssl)"
    chmod 600 "$ETC/tls/key.pem"
  fi
}

install_release() {
  local ver dst old
  ver="$(jget version)"; dst="$DATA/releases/$ver"
  checks; verify_and_try
  first_setup
  if [ -d "$dst" ] && cmp -s "$dst/manifest.json" "$PKG/manifest.json"; then
    say "релиз $ver уже установлен"
  else
    rm -rf "$dst.tmp"; mkdir -p "$dst.tmp"
    cp -r "$PKG/manifest.json" "$PKG/manifest.sig" "$PKG/payload" "$dst.tmp/" || fail "копирование в /data"
    fault copy
    sync
    rm -rf "$dst"; mv "$dst.tmp" "$dst" || fail "переименование релиза"
  fi
  fault switch
  old="$(cat "$DATA/current.ver" 2>/dev/null)"
  if [ "$old" != "$ver" ]; then
    [ -n "$old" ] && setver previous "$old"
    setver current "$ver"
  fi
  # старые релизы, кроме current и previous, удаляются (место на /data)
  local keep_c keep_p
  keep_c="$(cat "$DATA/current.ver")"; keep_p="$(cat "$DATA/previous.ver" 2>/dev/null)"
  for d in "$DATA"/releases/*; do
    [ -e "$d" ] || continue
    case "$(basename "$d")" in "$keep_c"|"$keep_p") ;; *) rm -rf "$d";; esac
  done
  autostart_on
  rm -f "$RUN/.release"   # загрузчик распакует новый релиз
  say "установлен релиз $ver (current), предыдущий: ${old:-нет}"
  if [ -z "$NOSTART" ]; then boot_sh stop >/dev/null 2>&1; boot_sh start; fi
}

case "$CMD" in
  install) install_release;;
  rollback)
    p="$(cat "$DATA/previous.ver" 2>/dev/null)"; [ -n "$p" ] && [ -d "$DATA/releases/$p" ] || fail "нет предыдущего релиза для отката"
    c="$(cat "$DATA/current.ver")"
    setver current "$p"; setver previous "$c"
    autostart_on; rm -f "$RUN/.release"; say "откат: current → $p, previous → $c"
    [ -n "$NOSTART" ] || { boot_sh stop >/dev/null 2>&1; boot_sh start; };;
  uninstall)
    [ -f "$DATA/mitt-boot.sh" ] && boot_sh stop
    autostart_off; rm -rf "$RUN"
    if [ -n "$PURGE" ]; then rm -rf "$DATA"; say "удалено вместе с настройками"; else rm -rf "$DATA/releases" "$DATA/current.ver" "$DATA/previous.ver" "$DATA/mitt-boot.sh"; say "удалено; настройки сохранены в $ETC"; fi;;
  status)
    echo "current: $(cat "$DATA/current.ver" 2>/dev/null)"; echo "previous: $(cat "$DATA/previous.ver" 2>/dev/null)"
    cat "$STATE/status.json" 2>/dev/null;;
  *) echo "использование: sh install.sh [install|rollback|uninstall [--purge]|status] [--no-start]"; exit 2;;
esac
