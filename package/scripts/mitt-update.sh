#!/bin/sh
# mi-lumruri: обновление из релизов GitHub по заявке панели ($STATE/update.request.run, JSON от mi-tt-ctl):
#   {"action":"check"}  — узнать последний релиз и сравнить с установленным;
#   {"action":"install","trust_official":true|false} — скачать пакет, сверить SHA-256 по SHA256SUMS релиза и поставить
#   штатным install.sh (подпись проверяется закреплённым ключом). trust_official — разрешить смену ключа только на
#   ключ релизов GitHub (отпечаток ниже), например после локальных сборок.
# Итог — $STATE/update.json. После установки служба перезапускается отдельным процессом (stop останавливает и этот сценарий),
# затем до MITT_UPDATE_HEALTH_WAIT секунд (5 минут) проверяется, что новая версия работает: служба, панель и — если до
# обновления настройки применялись — применение без ошибок. Не заработала — откат на прежний релиз (install.sh rollback).
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
tag=""; asset=""; sums=""; page=""; published=""; newer=false; avail=""; rolled=false; failed_ver=""
HEALTH_WAIT="${MITT_UPDATE_HEALTH_WAIT:-300}"

js() { printf '%s' "$1" | tr -d '"\\' | tr '\n\r\t' '   '; }
put() { # put <состояние> [ошибка] [ключ_пакета]: итог для панели
  printf '{"state":"%s","at":%s,"installed":"%s","latest":"%s","available":"%s","newer":%s,"page":"%s","published":"%s","error":%s,"package_key":%s,"official_key":"%s","rolled_back":%s,"failed":"%s"}\n' \
    "$1" "$(date +%s)" "$(js "$installed")" "$(js "$tag")" "$(js "$avail")" "$newer" "$(js "$page")" "$(js "$published")" \
    "$([ -n "${2:-}" ] && printf '"%s"' "$(js "$2")" || echo null)" "$([ -n "${3:-}" ] && printf '"%s"' "$(js "$3")" || echo null)" "$OFFICIAL_FP" "$rolled" "$(js "$failed_ver")" \
    >"$OUT.t" && mv -f "$OUT.t" "$OUT"
}
done_() { rm -rf "$W" "$STATE/update.request.run"; exit "${1:-0}"; }
fail() { mlog "обновление: $1"; put error "$1" "${2:-}"; done_ 1; }

# состояние службы из status.json (одна строка): поле apply — последнее полное применение
st_apply() { sed -n 's/.*"apply":{"tag":"[^"]*","exit":\([0-9]*\),"at":\([0-9]*\).*/\1 \2/p' "$STATE/status.json" 2>/dev/null; }
st_field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" "$STATE/status.json" 2>/dev/null; }
st_at() { sed -n 's/^{"at":\([0-9]*\),.*/\1/p' "$STATE/status.json" 2>/dev/null; }
# health <t0> <нужно применение>: новая версия работает? Причина отказа — в WHY
health() {
  local a ex at e
  WHY="служба не запустилась"
  at="$(st_at)"; [ -n "$at" ] && [ "$at" -ge "$1" ] || return 1
  WHY="запущена не новая версия"; [ "$(st_field release)" = "$installed" ] || return 1
  for e in service nginx uhttpd; do
    grep -q "\"$e\":true" "$STATE/status.json" 2>/dev/null || { WHY="не работает $e"; return 1; }
  done
  [ "$2" = 1 ] || return 0
  a="$(st_apply)"; ex="${a% *}"; at="${a#* }"
  WHY="настройки ещё не применены"; [ -n "$a" ] && [ "$at" -ge "$1" ] || return 1
  [ "$ex" = 0 ] || { WHY="настройки не применились: $(sed -n 's/.*"apply":{[^}]*"error":"\([^"]*\)".*/\1/p' "$STATE/status.json")"; return 1; }
  return 0
}

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
    prev="$installed"; installed="$(cat "$DATA/current.ver" 2>/dev/null)"
    # до перезапуска: применялись ли настройки без ошибок (тогда и новая версия обязана их применить)
    need=0; [ "$(st_apply | cut -d' ' -f1)" = 0 ] && need=1
    put restarting
    mlog "обновление: установлен $installed, перезапуск службы"
    rm -f "$STATE/update.request.run"
    # отдельный процесс: stop останавливает службу и этот сценарий; после start панель увидит новую версию.
    # Распакованный пакет ($pd) нужен до конца проверки: его install.sh выполняет откат.
    ( sleep 2; t0="$(date +%s)"; sh "$DATA/mitt-boot.sh" stop; sh "$DATA/mitt-boot.sh" start
      installed="$(cat "$DATA/current.ver" 2>/dev/null)"; put verifying
      n=0; ok=""
      while [ "$n" -lt "$HEALTH_WAIT" ]; do health "$t0" "$need" && { ok=1; break; }; sleep 5; n=$((n + 5)); done
      if [ -n "$ok" ]; then put done; mlog "обновление: $installed работает"
      else
        failed_ver="$installed"; why="$WHY"
        mlog "обновление: $installed не заработал за $HEALTH_WAIT с ($why) — откат на $prev"
        if [ -n "$prev" ] && sh "$pd/install.sh" rollback >>"$LOG/update-install.log" 2>&1; then
          rolled=true; installed="$(cat "$DATA/current.ver" 2>/dev/null)"; put error "$why"
        else
          put error "$why; откат не удался — подробности в журнале обновления"
        fi
      fi
      rm -rf "$W" ) </dev/null >>"$LOG/update-install.log" 2>&1 &
    exit 0;;
  *) fail "неизвестное действие «$action»";;
esac
