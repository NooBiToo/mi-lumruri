#!/usr/bin/env bash
# Этап 7: Hysteria2 в одноразовых user+net+mount+pid namespace (см. run-lab-hy2.sh). Сеть хоста не видна и не меняется.
#
#   tv     10.10.1.2 fd00:10::2 (02:..:0a:02) ─┬─ br-lan 10.10.1.1  [router: Mihomo TUN mitt0, netfilter стока]
#   phone  10.10.1.3 fd00:10::3 (02:..:0b:02) ─┘                    10.20.0.2 ── [inet] ── 10.30.0.2 [vpn: hysteria server, QUIC/UDP 443]
#   эхо-цели в inet (TCP и UDP 7007): 10.99.0.10 (группа «Видео»), 10.98.0.10 (вне группы), fd00:99::10 (IPv6)
#   сниффер в inet на i-r (всё, что вышло с роутера) и i-v (транспорт к серверу)
#
# Правило: ТВ (устройство) → группа «Видео» → профиль Hysteria2 (obfs salamander, закреплённый сертификат).
# Телефон — контрольное устройство без правила (напрямую).
set -uo pipefail
: "${ROOT:?}" "${W:?}" "${OUT:?}" "${CTL:?}" "${ADMIN:?}" "${MIHOMO:?}" "${HYBIN:?}" "${NFQWS:?}"
export PATH="/usr/sbin:/sbin:$PATH"
RUNCTL=(${RUNCTL:-})
PY=(python3 -I -X utf8)
ORIGIN="https://127.0.0.1:8787"
log() { printf '[hy2] %s\n' "$*" | tee -a "$OUT/lab.log"; }
die() { log "ОШИБКА: $*"; exit 1; }
nsx() { local n="$1"; shift; nsenter --net="/run/netns/$n" -- "$@"; }
now() { "${PY[@]}" -c 'import time;print(round(time.time(),3))'; }

# x86 iptables для netfilter-пути (как в лаборатории этапа 5)
NFBIN="$W/nfbin"; mkdir -p "$NFBIN"; IPTD="$ROOT/.tools/lab/iptables/root"; L="$IPTD/usr/lib/x86_64-linux-gnu"
for t in iptables iptables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s/xtables\nexec %s %s "$@"\n' "$L" "$L" "$IPTD/usr/sbin/xtables-legacy-multi" "$t" >"$NFBIN/$t"; done
for t in ip6tables ip6tables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s/xtables\nexec %s %s "$@"\n' "$L" "$L" "$IPTD/usr/sbin/xtables-nft-multi" "$t" >"$NFBIN/$t"; done
chmod +x "$NFBIN"/*; export PATH="$NFBIN:$PATH"

# --- топология ---
mount -t tmpfs tmpfs /run || die "tmpfs /run"
for n in router tv phone inet vpn; do ip netns add "$n" || die "netns $n"; ip -n "$n" link set lo up; done
ip link add r-tv netns router type veth peer name eth0 netns tv
ip link add r-ph netns router type veth peer name eth0 netns phone
ip link add r-wan netns router type veth peer name i-r netns inet
ip link add i-v netns inet type veth peer name v-i netns vpn
ip -n tv link set eth0 address 02:00:00:00:0a:02
ip -n phone link set eth0 address 02:00:00:00:0b:02
ip -n router link add br-lan type bridge
ip -n router link set r-tv master br-lan; ip -n router link set r-ph master br-lan
for l in br-lan r-tv r-ph r-wan; do ip -n router link set "$l" up; done
ip -n router addr add 10.10.1.1/24 dev br-lan; ip -n router addr add fd00:10::1/64 dev br-lan nodad
ip -n router addr add 10.20.0.2/30 dev r-wan; ip -n router addr add fd00:20::2/64 dev r-wan nodad
ip -n router route add default via 10.20.0.1; ip -n router -6 route add default via fd00:20::1
client() { ip -n "$1" addr add "$2" dev eth0; ip -n "$1" addr add "$3" dev eth0 nodad; ip -n "$1" link set eth0 up
  ip -n "$1" route add default via 10.10.1.1; ip -n "$1" -6 route add default via fd00:10::1; }
client tv 10.10.1.2/24 fd00:10::2/64
client phone 10.10.1.3/24 fd00:10::3/64
ip -n inet addr add 10.20.0.1/30 dev i-r; ip -n inet addr add fd00:20::1/64 dev i-r nodad; ip -n inet addr add 10.30.0.1/30 dev i-v
ip -n inet link set i-r up; ip -n inet link set i-v up
ip -n inet addr add 10.99.0.10/32 dev lo; ip -n inet addr add 10.98.0.10/32 dev lo; ip -n inet addr add fd00:99::10/128 dev lo
ip -n inet addr add 10.97.0.10/32 dev lo   # этап 9: цель группы «Zapret» (HTTP :80)
ip -n inet addr add 10.95.0.10/32 dev lo; ip -n inet addr add 10.94.0.10/32 dev lo   # этап 11: IP-категория и доменная категория
ip -n inet route add 10.10.1.0/24 via 10.20.0.2; ip -n inet -6 route add fd00:10::/64 via fd00:20::2   # без NAT
ip -n vpn addr add 10.30.0.2/30 dev v-i; ip -n vpn link set v-i up; ip -n vpn route add default via 10.30.0.1
for n in router inet; do nsx "$n" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'; done
log "топология: br-lan (ТВ, телефон), роутер, «интернет», сервер Hysteria2"

# --- сниффер и эхо-цели ---
nsx inet "${PY[@]}" "$ROOT/tools/lab/sniff.py" i-r "$OUT/sniff-wan.jsonl" & SN1=$!
nsx inet "${PY[@]}" "$ROOT/tools/lab/sniff.py" i-v "$OUT/sniff-vpn.jsonl" & SN2=$!
for a in 10.99.0.10 10.98.0.10 fd00:99::10; do nsx inet "${PY[@]}" "$ROOT/tools/lab/echo.py" serve "$a" 7007 "$OUT/echo.jsonl" "echo-$a" & done
nsx inet "${PY[@]}" "$ROOT/tools/lab/target.py" 80 "$OUT/zapret-target.log" 10.97.0.10 zapret &
nsx inet "${PY[@]}" "$ROOT/tools/lab/echo.py" serve 10.95.0.10 7007 "$OUT/echo.jsonl" "echo-10.95.0.10" &
nsx inet "${PY[@]}" "$ROOT/tools/lab/target.py" 80 "$OUT/category-target.log" 10.94.0.10 category &
sleep 0.5

# --- сервер Hysteria2: QUIC (UDP 443), пароль и obfs — случайные на прогон, сертификат лаборатории ---
HYPASS="$("${PY[@]}" -c 'import secrets;print(secrets.token_urlsafe(18))')"
OBFS="$("${PY[@]}" -c 'import secrets;print(secrets.token_urlsafe(18))')"
mkdir -p "$W/hy" && chmod 700 "$W/hy"
# эфемерный ключ и сертификат TLS этого прогона (в $W, удаляется с ним); отпечаток привязывается к профилям динамически
TLSFP="$("$ROOT/tools/lab/ephemeral-tls.sh" "$W/tls")" || die "эфемерный TLS"
cat >"$W/hy/server.yaml" <<EOF
listen: 10.30.0.2:443
tls:
  cert: $W/tls/cert.pem
  key: $W/tls/key.pem
auth:
  type: password
  password: "$HYPASS"
obfs:
  type: salamander
  salamander:
    password: "$OBFS"
EOF
chmod 600 "$W/hy/server.yaml"
start_hy() { nsx vpn "$HYBIN" server -c "$W/hy/server.yaml" --log-level debug >>"$OUT/hysteria.log" 2>&1 & HY_PID=$!
  for i in $(seq 50); do nsx vpn sh -c 'cat /proc/net/udp' | grep -q ':01BB ' && break; sleep 0.1; done; }
start_hy
log "hysteria server (pid $HY_PID) слушает UDP 443: $(nsx vpn sh -c 'cat /proc/net/udp /proc/net/tcp' | grep -c ':01BB ') сокет(ов) на 443"
nsx vpn sh -c 'cat /proc/net/tcp' | grep -q ':01BB .* 0A' && echo '{"tcp_listen_443":true}' >"$OUT/hy-tcp.json" || echo '{"tcp_listen_443":false}' >"$OUT/hy-tcp.json"
for n in tv phone; do nsx "$n" ping -c1 -W1 10.10.1.1 >/dev/null; nsx "$n" ping -6 -c1 -W1 fd00:10::1 >/dev/null; done

# --- контроллер ARM64: вход (пароль + TOTP), сохранение правила через CGI ---
CFG="$W/state/config.json"; mkdir -p "$W/state"; chmod 700 "$W/state"
# этап 9: группа «Zapret» и настройка стратегии (как их задаёт администратор); правило — через API
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]))
d["groups"].append({"id":"zapret","name":"Zapret (стенд)","destinations":[{"type":"cidr","value":"10.97.0.0/24"}]})
d["zapret"]={"strategy":"multisplit","pos":2,"tcp_ports":[80,443]}
d["categories"]=[{"id":"geo-ip","name":"Геокатегория IP (стенд)","kind":"ip","source":"geoip:lab"},{"id":"geo-dom","name":"Геокатегория доменов (стенд)","kind":"domain","source":"geosite:lab"}]
json.dump(d,open(sys.argv[2],"w"),ensure_ascii=False,indent=2)' "$ROOT/fixtures/lab/config.hy2.json" "$CFG"
"${PY[@]}" "$ROOT/tools/lab/pin-config.py" "$CFG" "$TLSFP" >/dev/null || die "привязка отпечатка"
AUTHD="$W/auth"; SESSD="$W/sessions"
AUTHENV=(MI_TT_AUTH_DIR="$AUTHD" MI_TT_SESSION_DIR="$SESSD" HTTPS=on MI_TT_ALLOWED_ORIGINS="$ORIGIN")
SESSENV=()
cgi() { local m="$1" p="$2" b="$3"; shift 3
  if [ "$b" = "-" ]; then env -i MI_TT_CONFIG="$CFG" REQUEST_METHOD="$m" PATH_INFO="$p" "${AUTHENV[@]}" "${SESSENV[@]}" "$@" "${RUNCTL[@]}" "$CTL" cgi </dev/null
  else env -i MI_TT_CONFIG="$CFG" REQUEST_METHOD="$m" PATH_INFO="$p" CONTENT_TYPE=application/json CONTENT_LENGTH="$(wc -c <"$b")" "${AUTHENV[@]}" "${SESSENV[@]}" "$@" "${RUNCTL[@]}" "$CTL" cgi <"$b"; fi; }
body_of() { sed '1,/^\r$/d'; }
status_of() { head -1 | cut -d' ' -f2; }
jget() { "${PY[@]}" -c 'import json,sys;d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k] if not k.isdigit() else d[int(k)]
print(d)' "$1"; }
totp() { "${PY[@]}" -c 'import base64,hashlib,hmac,os,struct,sys,time
s=os.environ["TOTP_SECRET"];k=base64.b32decode(s+"="*(-len(s)%8));c=struct.pack(">Q",int((time.time()+int(sys.argv[1]))//30))
h=hmac.new(k,c,hashlib.sha1).digest();o=h[-1]&15;print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "${1:-0}"; }
PW="$("${PY[@]}" -c 'import secrets;print(secrets.token_urlsafe(18))')"
adm_auth() { env -i PATH="$PATH" "${AUTHENV[@]}" "${RUNCTL[@]}" "$ADMIN" auth "$@"; }
printf '%s\n%s\n' "$PW" "$PW" | adm_auth init --stdin >"$W/auth-init.json" || die "auth init"
export TOTP_SECRET; TOTP_SECRET="$(jget totp_secret_base32 <"$W/auth-init.json")"
totp 0 | adm_auth confirm --stdin >/dev/null || die "auth confirm"
printf '{"password":"%s"}' "$PW" >"$W/login.json"; chmod 600 "$W/login.json"
cgi POST /auth/login "$W/login.json" HTTP_ORIGIN="$ORIGIN" HTTP_SEC_FETCH_SITE=same-origin >"$W/a-login.out"
PRE="$(grep -o '__Host-mitt_pre=[0-9a-f]*' "$W/a-login.out" | cut -d= -f2)"
printf '{"totp":"%s"}' "$(totp 30)" >"$W/second.json"
cgi POST /auth/second "$W/second.json" HTTP_ORIGIN="$ORIGIN" HTTP_COOKIE="__Host-mitt_pre=$PRE" >"$W/a-second.out"
[ "$(status_of <"$W/a-second.out")" = 200 ] || die "вход не выполнен"
SESSENV=(HTTP_COOKIE="__Host-mitt_sess=$(grep -o '__Host-mitt_sess=[0-9a-f]*' "$W/a-second.out" | cut -d= -f2)" HTTP_X_MITT_CSRF="$(body_of <"$W/a-second.out" | jget csrf)")
# API без сессии закрыт и для нового вида профиля
SAVEDENV=("${SESSENV[@]}"); SESSENV=(); cgi GET /config - >"$W/a-noauth.out"; SESSENV=("${SAVEDENV[@]}")
cgi GET /config - >"$W/cfg.out"; body_of <"$W/cfg.out" >"$OUT/api-config.json"
REV="$(jget revision <"$OUT/api-config.json")"
RULE='{"id":"r-tv-video-hy2","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"video"},"action":{"type":"profile","id":"hy2-lab"}}'
if [ -n "${CONFIG_IN:-}" ]; then
  # правило уже сохранено панелью (браузер → HTTPS-стенд → CGI): берём его файл и повторно сохраняем то же правило через API
  RULE="$("${PY[@]}" -c 'import json,sys;print(json.dumps(json.load(open(sys.argv[1]))["rules"][0]))' "$CONFIG_IN")"
  log "правило взято из настроек, сохранённых панелью: $CONFIG_IN"
fi
printf '{"rule":%s,"probes":[{"device":"tv","host":"10.99.0.10"},{"device":"phone","host":"10.99.0.10"}]}' "$RULE" >"$W/preview.json"
cgi POST /preview "$W/preview.json" HTTP_ORIGIN="$ORIGIN" HTTP_SEC_FETCH_SITE=same-origin >"$W/preview.out"; body_of <"$W/preview.out" >"$OUT/api-preview.json"
printf '{"base_revision":"%s","rule":%s}' "$REV" "$RULE" >"$W/save.json"
cgi POST /rules "$W/save.json" HTTP_ORIGIN="$ORIGIN" HTTP_SEC_FETCH_SITE=same-origin >"$W/save.out"; body_of <"$W/save.out" >"$OUT/api-save.json"
[ "$(status_of <"$W/save.out")" = 200 ] || { cat "$W/save.out"; die "сохранение не прошло"; }
# этап 11: списки категорий (проверка и атомарная замена ARM64-контроллером) и правила с назначением «категория»
printf '10.95.0.0/24\n' >"$W/geo-ip.txt"; printf 'cat.lab.test\n' >"$W/geo-dom.txt"
"${RUNCTL[@]}" "$CTL" category-update "$CFG" geo-ip "$W/geo-ip.txt" >"$OUT/category-update-ip.json"; echo "exit=$?" >>"$OUT/category-update-ip.json"
"${RUNCTL[@]}" "$CTL" category-update "$CFG" geo-dom "$W/geo-dom.txt" >"$OUT/category-update-dom.json"; echo "exit=$?" >>"$OUT/category-update-dom.json"
for c in geo-ip geo-dom; do
  cgi GET /config - >"$W/cfgc.out"; REVC="$(body_of <"$W/cfgc.out" | jget revision)"
  printf '{"base_revision":"%s","rule":{"id":"r-tv-%s","source":{"type":"device","id":"tv"},"destination":{"type":"category","id":"%s"},"action":{"type":"profile","id":"hy2-lab"}}}' "$REVC" "$c" "$c" >"$W/savec.json"
  cgi POST /rules "$W/savec.json" HTTP_ORIGIN="$ORIGIN" HTTP_SEC_FETCH_SITE=same-origin >"$W/savec.out"
  printf '{"category":"%s","status":%s}\n' "$c" "$(status_of <"$W/savec.out")" >>"$OUT/api-categories.jsonl"
done
cgi GET /config - >"$W/cfg2.out"; REV2="$(body_of <"$W/cfg2.out" | jget revision)"
printf '{"base_revision":"%s","rule":{"id":"r-tv-zapret","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"zapret"},"action":{"type":"direct_zapret"}}}' "$REV2" >"$W/save2.json"
cgi POST /rules "$W/save2.json" HTTP_ORIGIN="$ORIGIN" HTTP_SEC_FETCH_SITE=same-origin >"$W/save2.out"
[ "$(status_of <"$W/save2.out")" = 200 ] || { cat "$W/save2.out"; die "сохранение правила Zapret не прошло"; }
"${PY[@]}" -c 'import json,sys;print(json.dumps({"noauth":open(sys.argv[1]).readline().split()[1],"preview":open(sys.argv[2]).readline().split()[1],"save":open(sys.argv[3]).readline().split()[1],"save_zapret":open(sys.argv[4]).readline().split()[1]}))' \
  "$W/a-noauth.out" "$W/preview.out" "$W/save.out" "$W/save2.out" >"$OUT/api-status.json"
log "правило ТВ → Hysteria2 сохранено через CGI после входа: $(cat "$OUT/api-status.json")"

# --- рендер (ARM64), Mihomo, apply через netfilter-путь стока ---
ip -n router -4 neigh show | awk '{for(i=2;i<NF;i++) if($i=="lladdr") print 1999999999, $(i+1), $1, "lab", "*"}' | grep -v ' 10\.20\.' >"$W/dhcp.leases"
printf '{"version":1,"profiles":{"hy2-lab":{"password":"%s","obfs_password":"%s"}}}\n' "$HYPASS" "$OBFS" >"$W/secrets.json"; chmod 600 "$W/secrets.json"
"${RUNCTL[@]}" "$CTL" render "$CFG" "$W/secrets.json" "$W/dhcp.leases" "$W/mihomo" >"$OUT/render.json" || { cat "$OUT/render.json"; die "render"; }
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]));[p.update({k:"<скрыт>" for k in ("password","obfs-password") if k in p}) for p in d.get("proxies",[])];json.dump(d,open(sys.argv[2],"w"),indent=2,ensure_ascii=False)' "$W/mihomo/config.yaml" "$OUT/mihomo.config.redacted.json"
nsx router "$MIHOMO" -t -d "$W/mihomo" -f "$W/mihomo/config.yaml" >"$OUT/mihomo.test.log" 2>&1 || { cat "$OUT/mihomo.test.log"; die "mihomo -t"; }
start_mh() { nsx router "$MIHOMO" -d "$1" -f "$1/config.yaml" >>"$OUT/mihomo.log" 2>&1 & MH_PID=$!
  for i in $(seq 100); do ip -n router link show mitt0 >/dev/null 2>&1 && break; sleep 0.1; done; sleep 1; }
AST="$W/admin-state"
admin() { local step="$1"; shift
  nsx router env "${RUNCTL[@]}" "$ADMIN" "$@" --state-dir "$AST" >"$W/admin.out" 2>"$W/admin.err"; local rc=$?
  "${PY[@]}" -c 'import json,sys
try: out=json.load(open(sys.argv[3],encoding="utf-8"))
except Exception: out={"raw":open(sys.argv[3],encoding="utf-8").read()}
print(json.dumps({"step":sys.argv[1],"cmd":sys.argv[2],"exit":int(sys.argv[4]),"out":out}))' "$step" "$*" "$W/admin.out" "$rc" >>"$OUT/admin.jsonl"
  log "admin $step ($*): exit=$rc"; return $rc; }
APPLY=(apply --config "$CFG" --secrets "$W/secrets.json" --leases "$W/dhcp.leases" --marker netfilter)
admin G0-guard "${APPLY[@]}" --guard-only
start_mh "$W/mihomo"
admin A1-apply "${APPLY[@]}"
admin A2-status status
nsx router iptables -w -t mangle -S MITT_ZQ >"$OUT/zapret-chain.txt" 2>&1
cp "$W/mihomo/nfqws2.args" "$OUT/nfqws2.args" 2>/dev/null
# nfqws2 (zapret2) с аргументами, сформированными рендером; Lua-библиотеки рядом с программой
ZQ="$W/zapret"; mkdir -p "$ZQ"; cp "$NFQWS" "$ZQ/nfqws2"; cp "$NFQWS_LUA"/zapret-lib.lua.gz "$NFQWS_LUA"/zapret-antidpi.lua.gz "$ZQ/"
# В user namespace лаборатории setgroups запрещён ядром, и сброс привилегий nfqws2 завершил бы процесс: только здесь
# nfqws2 запускается через seccomp-обёртку (setgroups → 0) и с --uid=0:0 (в namespace отображён только uid/gid 0).
# На роутере — аргументы рендера без обёртки и без --uid: nfqws2 сбрасывает привилегии сам.
start_nfq() { mapfile -t NARGS <"$W/mihomo/nfqws2.args"; nsx router "${PY[@]}" "$ROOT/tools/lab/nosetgroups.py" "$ZQ/nfqws2" "${NARGS[@]}" --uid=0:0 --debug=@"$W/nfqws2.log" >>"$OUT/nfqws2.out" 2>&1 & NFQ_PID=$!; sleep 1; }
start_nfq
zq_count() { nsx router iptables -w -t mangle -L MITT_ZQ -v -x -n 2>/dev/null | awk '/NFQUEUE/ {print $1; exit}'; }
http_probe() { # http_probe <id> <ns>
  local id="$1" ns="$2" t0 t1 code
  t0="$(now)"; code="$(nsx "$ns" curl -sS -m 6 -o "$W/http.body" -w '%{http_code}' -H "X-Probe: $id" http://10.97.0.10/ 2>"$W/curl.err")"; local rc=$?; t1="$(now)"
  "${PY[@]}" -c 'import json,sys
a=sys.argv
try: b=json.load(open(a[6]))
except Exception: b={}
print(json.dumps({"probe":a[1],"ns":a[2],"proto":"http","addr":"10.97.0.10","rc":int(a[3]),"t0":float(a[4]),"t1":float(a[5]),"http":a[7],"reply":{"seen_client":b.get("seen_client")}}))' \
    "$id" "$ns" "$rc" "$t0" "$t1" "$W/http.body" "$code" >>"$OUT/probes.jsonl"
  log "проба $id ($ns HTTP → 10.97.0.10): rc=$rc http=$code"; }
# --- пробы ---
: >"$OUT/probes.jsonl"; : >"$OUT/phases.jsonl"
probe() { # probe <id> <ns> <tcp|udp> <адрес>
  local id="$1" ns="$2" proto="$3" addr="$4" t0 t1 out rc
  t0="$(now)"; out="$(nsx "$ns" "${PY[@]}" "$ROOT/tools/lab/echo.py" probe "$proto" "$addr" 7007 "$id" 2>&1)"; rc=$?; t1="$(now)"
  "${PY[@]}" -c 'import json,sys
a=sys.argv
try: r=json.loads(a[7])
except Exception: r={"raw":a[7]}
print(json.dumps({"probe":a[1],"ns":a[2],"proto":a[3],"addr":a[4],"rc":int(a[5]),"t0":float(a[6]),"t1":float(a[8]),"reply":r}))' \
    "$id" "$ns" "$proto" "$addr" "$rc" "$t0" "$out" "$t1" >>"$OUT/probes.jsonl"
  log "проба $id ($ns $proto → $addr): rc=$rc $out"; }
phase() { printf '{"phase":"%s","t":%s}\n' "$1" "$(now)" >>"$OUT/phases.jsonl"; log "== фаза $1"; }
set_of() { probe "$1-tv-tcp" tv tcp 10.99.0.10; probe "$1-tv-udp" tv udp 10.99.0.10; probe "$1-tv-v6" tv tcp fd00:99::10
  probe "$1-phone-tcp" phone tcp 10.99.0.10; probe "$1-phone-udp" phone udp 10.99.0.10; }

phase tunnel
set_of T
probe T-tv-outside-tcp tv tcp 10.98.0.10
probe T-tv-outside-udp tv udp 10.98.0.10

# этап 9: Zapret — прямой выход движка с меткой сокета через NFQUEUE и nfqws2 (multisplit:pos=2)
phase zapret
ZQ0="$(zq_count)"
http_probe Z-tv-http tv
http_probe Z-phone-http phone
probe Z-tv-tcp tv tcp 10.99.0.10
probe Z-tv-udp tv udp 10.99.0.10
ZQ1="$(zq_count)"
phase zapret_nfqws_stopped
kill "$NFQ_PID"; wait "$NFQ_PID" 2>/dev/null
http_probe Y-tv-http tv
ZQ2="$(zq_count)"
start_nfq
printf '{"before":%s,"after_zapret":%s,"after_stopped":%s}\n' "${ZQ0:-null}" "${ZQ1:-null}" "${ZQ2:-null}" >"$OUT/zapret-queue.json"

# этап 11: назначения-категории
phase categories
probe C-tv-ip-tcp tv tcp 10.95.0.10; probe C-tv-ip-udp tv udp 10.95.0.10; probe C-phone-ip-tcp phone tcp 10.95.0.10
host_probe() { # host_probe <id> <ns> <Host>
  local t0 code; t0="$(now)"; code="$(nsx "$2" curl -sS -m 6 -o "$W/hb" -w '%{http_code}' -H "Host: $3" -H "X-Probe: $1" http://10.94.0.10/ 2>/dev/null)"; local rc=$?
  "${PY[@]}" -c 'import json,sys
a=sys.argv
try: b=json.load(open(a[5]))
except Exception: b={}
print(json.dumps({"probe":a[1],"ns":a[2],"proto":"http","addr":"10.94.0.10","host":a[6],"rc":int(a[3]),"t0":float(a[4]),"t1":float(a[4]),"http":a[7],"reply":{"seen_client":b.get("seen_client")}}))' "$1" "$2" "$rc" "$t0" "$W/hb" "$3" "$code" >>"$OUT/probes.jsonl"
  log "проба $1 ($2 HTTP Host $3 → 10.94.0.10): rc=$rc http=$code"; }
host_probe C-tv-dom tv cat.lab.test; host_probe C-tv-sub tv www.cat.lab.test; host_probe C-tv-other tv other.lab.test

phase server_down
kill "$HY_PID"; wait "$HY_PID" 2>/dev/null; sleep 0.5
set_of S
admin S-status status

phase recovered
start_hy; T_UP="$(now)"
# клиент Mihomo держит прежнее QUIC-соединение до истечения простоя; измеряем фактическое время восстановления
for i in $(seq 40); do
  nsx tv "${PY[@]}" "$ROOT/tools/lab/echo.py" probe tcp 10.99.0.10 7007 "R-wait-$i" >/dev/null 2>&1 && break; sleep 2
done
"${PY[@]}" -c 'import json,sys,time;print(json.dumps({"server_restarted":float(sys.argv[1]),"recovered_after_s":round(time.time()-float(sys.argv[1]),1),"attempts":int(sys.argv[2])}))' "$T_UP" "$i" >"$OUT/recovery.json"
log "восстановление после рестарта сервера: $(cat "$OUT/recovery.json")"
set_of R

phase engine_down
kill "$MH_PID"; wait "$MH_PID" 2>/dev/null; sleep 0.5
set_of E
admin E-status status

# неверный закреплённый сертификат: TLS не проходит, прямых пакетов нет
phase bad_pin
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]));[p["endpoint"].update({"cert_sha256":"00"*32}) for p in d["profiles"] if p["id"]=="hy2-lab"];json.dump(d,open(sys.argv[2],"w"))' "$CFG" "$W/state/config-badpin.json"
"${RUNCTL[@]}" "$CTL" render "$W/state/config-badpin.json" "$W/secrets.json" "$W/dhcp.leases" "$W/mihomo-badpin" >"$OUT/render-badpin.json" || die "render badpin"
start_mh "$W/mihomo-badpin"
set_of B
kill "$MH_PID"; wait "$MH_PID" 2>/dev/null

phase restored
start_mh "$W/mihomo"
admin X0-apply "${APPLY[@]}"
set_of X
phase revert
admin X1-revert revert
kill "$MH_PID" "$HY_PID" "$NFQ_PID" 2>/dev/null; wait "$MH_PID" "$HY_PID" "$NFQ_PID" 2>/dev/null
cp "$W/nfqws2.log" "$OUT/nfqws2.log" 2>/dev/null
phase end
sleep 0.5; kill "$SN1" "$SN2" 2>/dev/null

# секреты (пароль панели, пароль и obfs Hysteria2) не должны попасть в артефакты
MITT_TLSKEY="$W/tls/key.pem" MITT_PW="$PW" MITT_HY="$HYPASS" MITT_OBFS="$OBFS" "${PY[@]}" -c 'import json,os,sys
from pathlib import Path
out=Path(sys.argv[1]);sec={"panel_password":os.environ["MITT_PW"],"totp_secret":os.environ["TOTP_SECRET"],"hy2_password":os.environ["MITT_HY"],"hy2_obfs":os.environ["MITT_OBFS"]}
sec["tls_key"]=[l for l in open(os.environ["MITT_TLSKEY"]).read().splitlines() if l and not l.startswith("-----")][0]  # эфемерный ключ TLS прогона
found=sorted({f"{k}:{f.relative_to(out)}" for f in out.rglob("*") if f.is_file() for k,v in sec.items() if v.encode() in f.read_bytes()})
json.dump({"scanned":sum(1 for f in out.rglob("*") if f.is_file()),"found":found},open(out/"secret-leak.json","w"))' "$OUT"
log "готово"
