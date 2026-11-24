#!/bin/sh
# mi-lumruri: установка и удаление модуля (заявка панели run/module.request.run, итог — run/module.json).
# Установка: tar модуля с GitHub (последний релиз, затем поиск по списку релизов) — SHA-256 по каталогу из подписанного
# пакета — распаковка на выбранный накопитель — подпись манифеста закреплённым ключом — запись в etc/modules.json —
# распаковка в RAM и заявка на применение (серверы модуля запускаются). Удаление — каталог и запись (сервер модуля
# панель удалить не даст, пока он используется).
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
CURL="${MITT_CURL:-curl}"
REPO="${MITT_MODULE_REPO:-NooBiToo/mi-lumruri}"
OUT="$STATE/module.json"
REQ="$STATE/module.request.run"
mkdir -p "$STATE" "$LOG"
req="$(cat "$REQ" 2>/dev/null)"
action="$(echo "$req" | sed -n 's/.*"action": *"\([a-z]*\)".*/\1/p')"
name="$(echo "$req" | sed -n 's/.*"name": *"\([a-z0-9-]*\)".*/\1/p')"
dir="$(echo "$req" | sed -n 's/.*"dir": *"\([^"]*\)".*/\1/p')"
# путь на роутере (запись в etc/modules.json); файлы — через корень эмуляции (в лаборатории)
md="$R$dir"
W="$R/tmp/mitt-module.$$"

js() { printf '%s' "$1" | tr -d '"\\' | tr '\n\r\t' '   ' | cut -c1-300; }
put() { # put <состояние> [сообщение]
  printf '{"state":"%s","action":"%s","name":"%s","at":%s,"message":%s}\n' "$1" "$action" "$name" "$(date +%s)" \
    "$([ -n "${2:-}" ] && printf '"%s"' "$(js "$2")" || echo null)" >"$OUT.t" && mv -f "$OUT.t" "$OUT"
}
finish() { rm -rf "$W" "$REQ"; exit "${1:-0}"; }
fail() { mlog "модуль $name: $1"; put failed "$1"; [ -n "$dir" ] && rm -rf "$md.tmp"; finish 1; }

[ -n "$name" ] || fail "заявка не разобрана"

case "$action" in
  install)
    case "$dir" in /*) ;; *) fail "каталог модуля не задан";; esac
    info="$(ctl module-info "$STATE/modules-catalog.json" "$name" 2>&1)" || fail "$info"
    set -- $info; asset="$1"; want="$2"; ver="$3"
    put running "скачиваю $asset"; mlog "модуль $name: установка $ver в $dir"
    mkdir -p "$W" || fail "временный каталог"
    tarf="$(dirname "$md")/.$asset.part"
    mkdir -p "$(dirname "$md")" 2>/dev/null || fail "накопитель недоступен для записи: $(dirname "$dir")"
    if [ -n "${MITT_MODULE_DIR:-}" ] && lab; then
      cp "$MITT_MODULE_DIR/$asset" "$tarf" || fail "лаборатория: нет $MITT_MODULE_DIR/$asset"
    elif [ -n "${MITT_MODULE_SRC:-}" ] && lab; then
      cp "$MITT_MODULE_SRC" "$tarf" || fail "лаборатория: нет $MITT_MODULE_SRC"
    elif ! "$CURL" -sSfL --proto '=https' --max-time 900 -o "$tarf" "https://github.com/$REPO/releases/latest/download/$asset" 2>"$W/curl.log"; then
      # в последнем релизе другой версии модуля нет — ищем ассет с этим именем в недавних релизах
      "$CURL" -sSfL --proto '=https' --max-time 30 -H 'Accept: application/vnd.github+json' -o "$W/list.json" "https://api.github.com/repos/$REPO/releases?per_page=20" 2>>"$W/curl.log" \
        || { rm -f "$tarf"; fail "GitHub не ответил: $(tail -n 1 "$W/curl.log")"; }
      url="$(tr ',' '\n' <"$W/list.json" | sed -n "s|.*\"browser_download_url\": *\"\(https:[^\"]*/$asset\)\".*|\1|p" | head -n 1)"
      [ -n "$url" ] || { rm -f "$tarf"; fail "в релизах нет $asset"; }
      "$CURL" -sSfL --proto '=https' --max-time 900 -o "$tarf" "$url" 2>>"$W/curl.log" || { rm -f "$tarf"; fail "не скачался $asset: $(tail -n 1 "$W/curl.log")"; }
    fi
    put running "проверяю"
    got="$(adm sha256 "$tarf" 2>/dev/null | sed -n '1s/^\([0-9a-f]\{64\}\).*/\1/p')"
    [ "$got" = "$want" ] || { rm -f "$tarf"; fail "SHA-256 модуля не совпал с каталогом пакета"; }
    rm -rf "$md.tmp"; mkdir -p "$md.tmp" || { rm -f "$tarf"; fail "нет места или прав на накопителе"; }
    tar -xf "$tarf" -C "$md.tmp" 2>"$W/tar.log" || { rm -f "$tarf"; fail "распаковка: $(tail -n 1 "$W/tar.log")"; }
    rm -f "$tarf"
    adm release verify "$md.tmp/module" --pinned "$DATA/keys/release.pub" >"$W/verify.json" 2>&1 || fail "подпись модуля не прошла проверку"
    rm -rf "$md.old"; [ -d "$md" ] && mv "$md" "$md.old"
    mv "$md.tmp/module" "$md" && rmdir "$md.tmp" 2>/dev/null
    [ -d "$md" ] || fail "не удалось переместить модуль в $dir"
    rm -rf "$md.old" "$RUN/mod/$name"
    ctl module-record "$ETC/modules.json" set "$name" "$ver" "$dir" || fail "не записан etc/modules.json"
    put running "распаковываю в память"
    modules_prepare
    [ "$(module_state "$name")" = ok ] || fail "модуль установлен, но не распаковался в память"
    put done "установлен $name $ver"; mlog "модуль $name $ver установлен в $dir"
    # серверы модуля запускаются при полном применении
    printf '{"requested_unix":%s,"by":"module"}\n' "$(date +%s)" >"$STATE/apply.request"
    finish 0;;
  remove)
    old="$(ctl module-list "$ETC/modules.json" | sed -n "s/^$name [^ ]* //p")"
    ctl module-record "$ETC/modules.json" del "$name" || fail "не записан etc/modules.json"
    case "$old" in /*/modules/"$name"|/*/mi-lumruri-modules/"$name") rm -rf "$R$old";; esac
    rm -rf "$RUN/mod/$name"; modules_prepare
    put done "удалён $name"; mlog "модуль $name удалён"
    printf '{"requested_unix":%s,"by":"module"}\n' "$(date +%s)" >"$STATE/apply.request"
    finish 0;;
  *) fail "неизвестное действие «$action»";;
esac
