#!/bin/sh
# mi-lumruri: обновление из релизов GitHub по заявке панели ($STATE/update.request.run, JSON от mi-tt-ctl):
#   {"action":"check"}  — узнать последний релиз и сравнить с установленным;
#   {"action":"install","trust_official":true|false} — скачать пакет, сверить SHA-256 по SHA256SUMS релиза и поставить
#   штатным install.sh (подпись проверяется закреплённым ключом). trust_official — разрешить смену ключа только на
#   ключ релизов GitHub (отпечаток ниже), например после локальных сборок.
# Итог — $STATE/update.json. После установки служба перезапускается отдельным процессом (stop останавливает и этот сценарий).
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
API="${MITT_UPDATE_API:-https://api.github.com/repos/NooBiToo/mi-lumruri/releases/latest}"
OFFICIAL_FP="${MITT_OFFICIAL_KEY:-e4a271890e5643ab}"
CURL="${MITT_CURL:-curl}"
OUT="$STATE/update.json"
mkdir -p "$STATE" "$LOG"
req="$(cat "$STATE/update.request.run" 2>/dev/null)"
action="$(echo "$req" | sed -n 's/.*"action": *"\([a-z]*\)".*/\1/p')"
trust=""; echo "$req" | grep -q '"trust_official": *true' && trust=1
W="$R/tmp/mitt-update.$$"
installed="$(cat "$DATA/current.ver" 2>/dev/null)"
tag=""; asset=""; sums=""; page=""; published=""; newer=false; avail=""

js() { printf '%s' "$1" | tr -d '"\\' | tr '\n\r\t' '   '; }
put() { # put <состояние> [ошибка] [ключ_пакета]: итог для панели
  printf '{"state":"%s","at":%s,"installed":"%s","latest":"%s","available":"%s","newer":%s,"page":"%s","published":"%s","error":%s,"package_key":%s,"official_key":"%s"}\n' \
    "$1" "$(date +%s)" "$(js "$installed")" "$(js "$tag")" "$(js "$avail")" "$newer" "$(js "$page")" "$(js "$published")" \
    "$([ -n "${2:-}" ] && printf '"%s"' "$(js "$2")" || echo null)" "$([ -n "${3:-}" ] && printf '"%s"' "$(js "$3")" || echo null)" "$OFFICIAL_FP" \
    >"$OUT.t" && mv -f "$OUT.t" "$OUT"
}
done_() { rm -rf "$W" "$STATE/update.request.run"; exit "${1:-0}"; }
fail() { mlog "обновление: $1"; put error "$1" "${2:-}"; done_ 1; }

# версия: 0.4.1 → 000000000004000001 (для сравнения строкой); «ci-…» и прочее — пусто
vkey() { echo "$1" | sed -n 's/^v\{0,1\}\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2 \3/p' | awk '{printf "%06d%06d%06d", $1, $2, $3}'; }

check() {
  mkdir -p "$W"
  "$CURL" -sSfL --proto '=https' --max-time 30 -H 'Accept: application/vnd.github+json' -o "$W/latest.json" "$API" 2>"$W/curl.log" \
    || fail "GitHub не ответил: $(tail -n 1 "$W/curl.log")"
  tr ',' '\n' <"$W/latest.json" >"$W/latest.txt"
  tag="$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$W/latest.txt" | head -n 1)"
  published="$(sed -n 's/.*"published_at": *"\([^"]*\)".*/\1/p' "$W/latest.txt" | head -n 1)"
  page="$(sed -n 's/.*"html_url": *"\(https:[^"]*\/releases\/tag\/[^"]*\)".*/\1/p' "$W/latest.txt" | head -n 1)"
  asset="$(sed -n 's/.*"browser_download_url": *"\(https:[^"]*\/mi-lumruri-[^"\/]*\.tar\)".*/\1/p' "$W/latest.txt" | head -n 1)"
  # релизы до 0.5 — пакет под прежним именем
  [ -n "$asset" ] || asset="$(sed -n 's/.*"browser_download_url": *"\(https:[^"]*\/mi-trusttunnel-[^"\/]*\.tar\)".*/\1/p' "$W/latest.txt" | head -n 1)"
  sums="$(sed -n 's/.*"browser_download_url": *"\(https:[^"]*\/SHA256SUMS\)".*/\1/p' "$W/latest.txt" | head -n 1)"
  [ -n "$tag" ] && [ -n "$asset" ] && [ -n "$sums" ] || fail "в последнем релизе нет пакета или SHA256SUMS"
  avail="$(basename "$asset" .tar | sed 's/^mi-lumruri-//; s/^mi-trusttunnel-//')"
  # новее: та же сборка — нет; установлена сборка CI (ci-…) другая — да (релизы идут только вперёд);
  # установлена версия x.y.z — сравнение с тегом релиза
  if [ "$avail" = "$installed" ]; then newer=false
  elif [ -z "$(vkey "$installed")" ]; then newer=true
  elif [ -n "$(vkey "$tag")" ] && awk -v a="$(vkey "$tag")" -v b="$(vkey "$installed")" 'BEGIN { exit !(a "" > b "") }'; then newer=true
  else newer=false; fi
}

case "$action" in
  check)
    put checking; check; put ready; mlog "обновление: последний релиз $tag ($avail), установлен $installed"; done_ 0;;
  install)
    put checking; check
    [ "$avail" = "$installed" ] && { put ready "эта версия уже установлена"; done_ 0; }
    put downloading
    "$CURL" -sSfL --proto '=https' --max-time 300 --max-filesize 33554432 -o "$W/package.tar" "$asset" 2>"$W/curl.log" \
      || fail "пакет не скачан: $(tail -n 1 "$W/curl.log")"
    "$CURL" -sSfL --proto '=https' --max-time 30 -o "$W/SHA256SUMS" "$sums" 2>"$W/curl.log" || fail "SHA256SUMS не скачан: $(tail -n 1 "$W/curl.log")"
    want="$(grep " [ *]\{0,1\}$(basename "$asset")\$" "$W/SHA256SUMS" | head -n 1 | cut -d' ' -f1)"
    have="$("$BIN/mi-tt-admin" sha256 "$W/package.tar" 2>/dev/null | cut -d' ' -f1)"
    [ -n "$want" ] && [ "$want" = "$have" ] || fail "SHA-256 пакета не совпал с SHA256SUMS релиза"
    put installing
    mkdir -p "$W/x" && tar -xf "$W/package.tar" -C "$W/x" || fail "пакет не распакован"
    pd="$W/x/mi-lumruri"; [ -f "$pd/install.sh" ] || pd="$W/x/mi-trusttunnel"
    [ -f "$pd/install.sh" ] || fail "пакет не распакован"
    rm -f "$W/package.tar"
    set -- install --no-start
    [ -n "$trust" ] && set -- "$@" "--trust-key=$OFFICIAL_FP"
    if ! sh "$pd/install.sh" "$@" >"$LOG/update-install.log" 2>&1; then
      pk="$(sed -n 's/.*у пакета \([0-9a-f]\{16\}\).*/\1/p' "$LOG/update-install.log" | head -n 1)"
      [ -n "$pk" ] && fail "пакет подписан другим ключом, чем установленный" "$pk"
      fail "установщик отказал: $(grep 'ОТКАЗ' "$LOG/update-install.log" | tail -n 1 | sed 's/^mi-[a-z]*: ОТКАЗ: //')"
    fi
    installed="$(cat "$DATA/current.ver" 2>/dev/null)"
    put restarting
    mlog "обновление: установлен $installed, перезапуск службы"
    rm -rf "$W" "$STATE/update.request.run"
    # отдельный процесс: stop останавливает службу и этот сценарий; после start панель увидит новую версию
    ( sleep 2; sh "$DATA/mitt-boot.sh" stop; sh "$DATA/mitt-boot.sh" start; installed="$(cat "$DATA/current.ver" 2>/dev/null)"; put done ) \
      </dev/null >>"$LOG/update-install.log" 2>&1 &
    exit 0;;
  *) fail "неизвестное действие «$action»";;
esac
