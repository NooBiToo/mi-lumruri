#!/bin/sh
# mi-trusttunnel: подбор стратегии Zapret одной кнопкой (заявка панели zapret-test.request, запускает служба в фоне).
# Проверка идёт в стороне от клиентов: отдельный nfqws2 на очереди 201, запросы curl стока с портов 61000–61099
# (план mi-tt-admin отправляет в очередь 201 только TCP с этих портов к портам 80 и 443). Сначала контроль без Zapret,
# затем каждая стратегия; лучшая применяется, только если открыла больше контроля, и перепроверяется (хуже — откат).
# Флаг $STATE/zapret-test.stop прерывает подбор; при прерывании настройки не меняются. Итог — $STATE/zapret-test.json.
D="$(cd "$(dirname "$0")" && pwd)"
. "$D/mitt-lib.sh"
CURL="${MITT_CURL:-curl}"
NFQ="${MITT_NFQWS:-$BIN/nfqws2}"
TARGETS="${MITT_ZAPRET_TARGETS:-$D/zapret-targets.txt}"
SETTLE="${MITT_ZT_SETTLE:-1}"     # секунд на запуск nfqws2 до первых запросов
SPORTS=61000-61099                # = plan::ZAPRET_TEST_SPORTS
OUT="$STATE/zapret-test.json"; STOP="$STATE/zapret-test.stop"; W="$RUN/zapret-test"; CFG="$ETC/config.json"

mkdir -p "$STATE" "$LOG"
lock_take zapret-test 1 || { mlog "подбор Zapret уже идёт"; exit 0; }
STARTED="$(date +%s)"; DONE=0; TOTAL=0; CUR=""; CTRL_N=0; NT=0; BEST_ID=""; BEST_N=0; APPLIED=false; YT=null; FINAL=""
rm -f "$STOP"; rm -rf "$W"; mkdir -p "$W"

st() { # st <running|done|failed> <сообщение>
  local fin=null best=null
  [ "$1" = running ] || fin="$(date +%s)"
  [ -n "$BEST_ID" ] && best="{\"id\":\"$BEST_ID\",\"opened\":$BEST_N}"
  printf '{"state":"%s","started":%s,"finished":%s,"progress":{"done":%s,"total":%s,"current":"%s"},"control":{"opened":%s,"total":%s},"best":%s,"youtube":%s,"applied":%s,"message":"%s"}\n' \
    "$1" "$STARTED" "$fin" "$DONE" "$TOTAL" "$CUR" "$CTRL_N" "$NT" "$best" "$YT" "$APPLIED" "$2" >"$OUT.t" && mv -f "$OUT.t" "$OUT"
  [ "$1" = running ] || FINAL="$1"
}
nfq_stop() {
  [ -f "$STATE/zapret-nfqws.pid" ] || return 0
  local p; p="$(cat "$STATE/zapret-nfqws.pid")"
  kill "$p" 2>/dev/null; usleep 200000; kill -9 "$p" 2>/dev/null; rm -f "$STATE/zapret-nfqws.pid"
}
# аварийное завершение: проверочный nfqws2 не остаётся, состояние не залипает в running
trap 'nfq_stop; [ -n "$FINAL" ] || st failed "Подбор завершился с ошибкой"; rm -rf "$W"; lock_drop zapret-test' EXIT
trap 'exit 1' INT TERM

is_yt() { case "$1" in *youtube*|*googlevideo*) return 0;; esac; return 1; }

# Одна цель → «1» (открыта) или «0». Открыта: curl завершился без ошибки и код ответа не 000 и не 451.
# Ответ, оборванный на 16–20 КБ (блокировка по объёму), — ошибка curl (сброс или тайм-аут), то есть закрыта.
probe() {
  local r rc n=0
  while :; do
    r="$("$CURL" -k -s -o /dev/null --local-port "$SPORTS" --max-time 8 -w '%{http_code} %{size_download}' "$1" 2>/dev/null)"; rc=$?
    # 45 — не удалось занять порт диапазона (все в TIME_WAIT): подождать и повторить
    [ "$rc" -eq 45 ] && [ "$n" -lt 5 ] || break
    n=$((n + 1)); sleep 2
  done
  set -- $r
  if [ "$rc" -eq 0 ] && [ "${1:-000}" != 000 ] && [ "$1" != 451 ]; then echo 1; else echo 0; fi
}

# Проверка целей по 4 параллельно. measure <all|yt>: RES="<открыто required> <открыто optional>", NM — число целей.
# Код 1 — прерывание (флаг stop).
measure() {
  local i=0 kind url pids="" f rq=0 op=0 ok
  rm -rf "$W/p"; mkdir -p "$W/p"
  while read -r kind url; do
    case "$kind" in required|optional) ;; *) continue;; esac
    [ "$1" = yt ] && ! is_yt "$url" && continue
    i=$((i + 1))
    (trap - EXIT; echo "$kind $(probe "$url")" >"$W/p/$i") &
    pids="$pids $!"
    if [ $((i % 4)) -eq 0 ]; then wait $pids; pids=""; [ -f "$STOP" ] && return 1; fi
  done <"$TARGETS"
  [ -z "$pids" ] || wait $pids
  [ -f "$STOP" ] && return 1
  for f in "$W"/p/*; do
    [ -f "$f" ] || continue
    read -r kind ok <"$f"; [ "$ok" = 1 ] || continue
    if [ "$kind" = required ]; then rq=$((rq + 1)); else op=$((op + 1)); fi
  done
  RES="$rq $op"; NM=$i
}
score() { echo $(($1 * 1000 + $2)); }   # больше required важнее любого числа optional
opened() { echo $(($1 + $2)); }

# Стратегия на очереди 201: RES как у measure; пусто — nfqws2 не запустился. Код 1 — прерывание.
try() { # try <id> <all|yt>
  local args
  RES=""
  args="$(ctl zapret-args "$1")" || { mlog "подбор Zapret: нет аргументов для $1"; return 0; }
  # shellcheck disable=SC2086 — аргументы по одному в строке, без пробелов (каталог стратегий)
  start_bg zapret-nfqws ${MITT_NFQWS_WRAP:-} "$NFQ" $args
  sleep "$SETTLE"
  if ! pid_alive zapret-nfqws; then mlog "подбор Zapret: nfqws2 со стратегией $1 не запустился"; nfq_stop; return 0; fi
  measure "$2"; local rc=$?
  nfq_stop
  return $rc
}

stopped() {
  nfq_stop
  local r
  for r in $ROLLS; do set_choice "${r%%=*}" "${r#*=}"; done
  APPLIED=false; st failed "Подбор прерван; настройки не изменены"; mlog "подбор Zapret прерван"; exit 0
}

# set_choice <general|youtube> <id>: PREV — прежний id; затем заявка на применение
set_choice() {
  local o
  o="$(ctl zapret-set "$CFG" "$1" "$2")" || { mlog "подбор Zapret: zapret-set $1 $2 не прошёл: $(echo "$o" | head -c 300)"; return 1; }
  PREV="$(echo "$o" | sed -n 's/.*"previous": *"\([^"]*\)".*/\1/p')"
  printf '{"requested_unix":%s,"by":"zapret-test"}\n' "$(date +%s)" >"$STATE/apply.request"
  mlog "подбор Zapret: $1 = $2 (было $PREV)"
}
ROLLS=""   # применённые в этом подборе изменения «вид=прежний id», последнее — первым

# pass <general|youtube> <all|yt> <контроль: score> → BEST_P, BEST_PS, BEST_PN; оценки — S_<id>
pass() {
  local id s
  BEST_P=""; BEST_PS=-1; BEST_PN=0
  for id in $IDS; do
    CUR="$id"; st running "Проверка стратегии $id"
    try "$id" "$2" || stopped
    DONE=$((DONE + 1))
    [ -n "$RES" ] || continue
    s="$(score $RES)"; eval "S_$id=$s"
    if [ "$s" -gt "$BEST_PS" ]; then BEST_P="$id"; BEST_PS="$s"; BEST_PN="$(opened $RES)"; fi
  done
}

# apply_best <general|youtube> <all|yt> <контроль score>: применить BEST_P, перепроверить, при ухудшении — откат.
# Код 0 — применено и подтверждено.
apply_best() {
  local s prev_s
  [ -n "$BEST_P" ] && [ "$BEST_PS" -gt "$3" ] || return 1
  set_choice "$1" "$BEST_P" || return 1
  ROLLS="$1=$PREV $ROLLS"; APPLIED=true
  CUR="$BEST_P"; st running "Повторная проверка стратегии $BEST_P"
  try "$BEST_P" "$2" || stopped
  s=-1; [ -n "$RES" ] && s="$(score $RES)"
  prev_s="$(eval "echo \${S_$PREV:-}")"
  if [ "$s" -le "$3" ] || { [ -n "$prev_s" ] && [ "$s" -lt "$prev_s" ]; }; then
    mlog "подбор Zapret: $BEST_P при повторной проверке хуже — возврат к $PREV"
    ROLLS="${ROLLS#* }"; set_choice "$1" "$PREV"; APPLIED=false; return 1
  fi
  return 0
}

# проверочная очередь есть в плане, только когда Zapret используется (рендер тогда пишет nfqws2.args)
[ -f "$RENDER/nfqws2.args" ] || { st failed "Zapret не включён: подбор работает при «Напрямую с обходом блокировок (Zapret)»"; exit 0; }
NT=0; NY=0
while read -r kind url; do
  case "$kind" in required|optional) NT=$((NT + 1)); is_yt "$url" && NY=$((NY + 1));; esac
done <"$TARGETS"
[ "$NT" -gt 0 ] || { st failed "Нет целей проверки"; exit 1; }
IDS="$(ctl zapret-list general)"
TOTAL=$((1 + $(echo $IDS | wc -w)))
mlog "подбор Zapret: начат, целей $NT"

# контроль: без nfqws2 на очереди 201 (пакеты проходят как есть — очередь с --queue-bypass)
CUR=control; st running "Проверка без Zapret"
measure all || stopped
CTRL_S="$(score $RES)"; CTRL_N="$(opened $RES)"; DONE=1
# YouTube-цели контроля: общий профиль их не касается (исключены списком хостов), их судьба решается отдельно
measure yt || stopped
YT_CTRL_S="$(score $RES)"; YT_CTRL_N="$(opened $RES)"

pass general all
BEST_ID="$BEST_P"; BEST_N="$BEST_PN"
GEN=""; apply_best general all "$CTRL_S" && GEN="$BEST_P"

YT_MSG=""
if [ "$NY" -gt 0 ] && [ "$YT_CTRL_N" -lt "$NY" ]; then
  IDS="$(ctl zapret-list youtube)"
  TOTAL=$((TOTAL + $(echo $IDS | wc -w)))
  KEEP_APPLIED="$APPLIED"
  pass youtube yt
  if apply_best youtube yt "$YT_CTRL_S"; then
    YT="{\"id\":\"$BEST_P\",\"opened\":$BEST_PN,\"total\":$NY}"; YT_MSG="; YouTube — стратегия $BEST_P: $BEST_PN из $NY"
  fi
  [ "$KEEP_APPLIED" = true ] && APPLIED=true
fi
CUR=""

if [ -n "$GEN" ]; then
  st done "Применена стратегия $GEN: открылось $BEST_N из $NT, без Zapret — $CTRL_N$YT_MSG"
elif [ -n "$YT_MSG" ]; then
  st done "Для всех сайтов стратегия не изменена (без Zapret открылось $CTRL_N из $NT)$YT_MSG"
else
  st done "Подходящей стратегии лучше, чем без Zapret, не нашлось"
fi
mlog "подбор Zapret: $(sed -n 's/.*"message":"\([^"]*\)".*/\1/p' "$OUT")"
