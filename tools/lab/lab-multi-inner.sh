#!/usr/bin/env bash
# Этап 8: VLESS (Xray; VLESS_MODE=tls — TLS с закреплённым сертификатом, reality — REALITY; оба с XTLS vision)
# и AmneziaWG (amneziawg-go) одновременно, netfilter-путь стока.
#
#   tv     10.10.1.2 (02:..:0a:02) ─┬─ br-lan   10.10.1.1                 10.20.0.2 ── [inet] ── 10.30.0.2 [vpn: Xray VLESS-REALITY tcp/443,
#   phone  10.10.1.3 (02:..:0b:02) ─┘                                                                       amneziawg-go udp/51820 (туннель 10.66.66.1/24),
#   laptop 10.10.2.2 (02:..:0c:02) ─── br-guest 10.10.2.1 (SSID «гостевая»)                                 TLS-сайт для REALITY :8443]
#   эхо-цели TCP+UDP 7007 в inet: 10.99.0.10 (группа «Видео»), 10.98.0.10 (группа «Широкая», пересекается с «Видео»), fd00:99::10
#
# Правила (порядок): r1 ТВ → «Видео» → VLESS; r2 ТВ → «Широкая» → блок; r3 гостевая сеть (SSID) → «Видео» → AmneziaWG.
# Телефон — контрольное устройство без правил. Эхо видит: VLESS → 10.30.0.2, AmneziaWG → 10.66.66.2, напрямую → адрес клиента.
set -uo pipefail
: "${ROOT:?}" "${W:?}" "${OUT:?}" "${CTL:?}" "${ADMIN:?}" "${MIHOMO:?}" "${XRAY:?}" "${AWG:?}"
export PATH="/usr/sbin:/sbin:$PATH"
RUNCTL=(${RUNCTL:-})
PY=(python3 -I -X utf8)
ORIGIN="https://127.0.0.1:8787"
log() { printf '[multi] %s\n' "$*" | tee -a "$OUT/lab.log"; }
die() { log "ОШИБКА: $*"; exit 1; }
nsx() { local n="$1"; shift; nsenter --net="/run/netns/$n" -- "$@"; }
now() { "${PY[@]}" -c 'import time;print(round(time.time(),3))'; }

NFBIN="$W/nfbin"; mkdir -p "$NFBIN"; IPTD="$ROOT/.tools/lab/iptables/root"; L="$IPTD/usr/lib/x86_64-linux-gnu"
for t in iptables iptables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s/xtables\nexec %s %s "$@"\n' "$L" "$L" "$IPTD/usr/sbin/xtables-legacy-multi" "$t" >"$NFBIN/$t"; done
for t in ip6tables ip6tables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s/xtables\nexec %s %s "$@"\n' "$L" "$L" "$IPTD/usr/sbin/xtables-nft-multi" "$t" >"$NFBIN/$t"; done
chmod +x "$NFBIN"/*; export PATH="$NFBIN:$PATH"

# --- топология ---
mount -t tmpfs tmpfs /run || die "tmpfs /run"
for n in router tv phone laptop inet vpn; do ip netns add "$n" || die "netns $n"; ip -n "$n" link set lo up; done
ip link add r-tv netns router type veth peer name eth0 netns tv
ip link add r-ph netns router type veth peer name eth0 netns phone
ip link add r-gst netns router type veth peer name eth0 netns laptop
ip link add r-wan netns router type veth peer name i-r netns inet
ip link add i-v netns inet type veth peer name v-i netns vpn
ip -n tv link set eth0 address 02:00:00:00:0a:02; ip -n phone link set eth0 address 02:00:00:00:0b:02; ip -n laptop link set eth0 address 02:00:00:00:0c:02
ip -n router link add br-lan type bridge; ip -n router link add br-guest type bridge
ip -n router link set r-tv master br-lan; ip -n router link set r-ph master br-lan; ip -n router link set r-gst master br-guest
for l in br-lan br-guest r-tv r-ph r-gst r-wan; do ip -n router link set "$l" up; done
ip -n router addr add 10.10.1.1/24 dev br-lan; ip -n router addr add fd00:10::1/64 dev br-lan nodad
ip -n router addr add 10.10.2.1/24 dev br-guest; ip -n router addr add fd00:11::1/64 dev br-guest nodad
ip -n router addr add 10.20.0.2/30 dev r-wan; ip -n router addr add fd00:20::2/64 dev r-wan nodad
ip -n router route add default via 10.20.0.1; ip -n router -6 route add default via fd00:20::1
client() { ip -n "$1" addr add "$2" dev eth0; ip -n "$1" addr add "$3" dev eth0 nodad; ip -n "$1" link set eth0 up
  ip -n "$1" route add default via "$4"; ip -n "$1" -6 route add default via "$5"; }
client tv 10.10.1.2/24 fd00:10::2/64 10.10.1.1 fd00:10::1
client phone 10.10.1.3/24 fd00:10::3/64 10.10.1.1 fd00:10::1
client laptop 10.10.2.2/24 fd00:11::2/64 10.10.2.1 fd00:11::1
ip -n inet addr add 10.20.0.1/30 dev i-r; ip -n inet addr add fd00:20::1/64 dev i-r nodad; ip -n inet addr add 10.30.0.1/30 dev i-v
ip -n inet link set i-r up; ip -n inet link set i-v up
ip -n inet addr add 10.99.0.10/32 dev lo; ip -n inet addr add 10.98.0.10/32 dev lo; ip -n inet addr add fd00:99::10/128 dev lo
for s in 10.10.1.0/24 10.10.2.0/24; do ip -n inet route add "$s" via 10.20.0.2; done
for s in fd00:10::/64 fd00:11::/64; do ip -n inet -6 route add "$s" via fd00:20::2; done
ip -n inet route add 10.66.66.0/24 via 10.30.0.2   # адреса туннеля AmneziaWG — без NAT
ip -n vpn addr add 10.30.0.2/30 dev v-i; ip -n vpn link set v-i up; ip -n vpn route add default via 10.30.0.1
for n in router inet vpn; do nsx "$n" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'; done
log "топология: br-lan (ТВ, телефон), br-guest (ноутбук), «интернет», сервер VLESS и peer AmneziaWG"

nsx inet "${PY[@]}" "$ROOT/tools/lab/sniff.py" i-r "$OUT/sniff-wan.jsonl" & SN1=$!
nsx inet "${PY[@]}" "$ROOT/tools/lab/sniff.py" i-v "$OUT/sniff-vpn.jsonl" & SN2=$!
for a in 10.99.0.10 10.98.0.10 fd00:99::10; do nsx inet "${PY[@]}" "$ROOT/tools/lab/echo.py" serve "$a" 7007 "$OUT/echo.jsonl" "echo-$a" & done

# --- сервер VLESS: Xray, REALITY (маскировка под TLS-сайт лаборатории) + XTLS vision; ключи и UUID — на прогон ---
mkdir -p "$W/srv" && chmod 700 "$W/srv"
kv() { awk -F': ' -v k="$1" '$1==k {print $2}'; }
VLESS_MODE="${VLESS_MODE:-tls}"
# эфемерный ключ и сертификат TLS этого прогона (в $W, удаляется с ним); отпечаток привязывается к профилю динамически
PIN="$("$ROOT/tools/lab/ephemeral-tls.sh" "$W/tls")" || die "эфемерный TLS"
"$XRAY" x25519 >"$W/srv/reality.txt"; RPRIV="$(kv PrivateKey <"$W/srv/reality.txt")"; RPUB="$(kv 'Password (PublicKey)' <"$W/srv/reality.txt")"
VUUID="$("$XRAY" uuid)"; SID="$("${PY[@]}" -c 'import secrets;print(secrets.token_hex(8))')"
nsx vpn "${PY[@]}" -c 'import http.server,ssl,sys
h=http.server.HTTPServer(("10.30.0.2",8443),http.server.SimpleHTTPRequestHandler)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(sys.argv[1],sys.argv[2]);h.socket=c.wrap_socket(h.socket,server_side=True);h.serve_forever()' \
  "$W/tls/cert.pem" "$W/tls/key.pem" >/dev/null 2>&1 &
"${PY[@]}" -c 'import json,sys
a=sys.argv
json.dump({"log":{"loglevel":"info","access":a[6]},"inbounds":[{"listen":"10.30.0.2","port":443,"protocol":"vless",
 "settings":{"clients":[{"id":a[1],"flow":"xtls-rprx-vision"}],"decryption":"none"},
 "streamSettings":({"network":"tcp","security":"reality","realitySettings":{"target":"10.30.0.2:8443","serverNames":["vpn.lab.test"],"privateKey":a[2],"shortIds":[a[3]]}}
   if a[5]=="reality" else {"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":a[7],"keyFile":a[8]}]}})}],
 "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["10.96.0.0/14"]}]}}]},open(a[4],"w"),indent=1)' \
  "$VUUID" "$RPRIV" "$SID" "$W/srv/xray.json" "$VLESS_MODE" "$W/srv/xray-access.log" "$W/tls/cert.pem" "$W/tls/key.pem"
start_xray() { nsx vpn "$XRAY" run -c "$W/srv/xray.json" >>"$OUT/xray.log" 2>&1 & XR_PID=$!
  for i in $(seq 50); do nsx vpn sh -c 'cat /proc/net/tcp' | grep -q ':01BB 00000000:0000 0A' && break; sleep 0.1; done; }
start_xray

# --- peer AmneziaWG: amneziawg-go (userspace), конфигурация через UAPI; ключи на прогон ---
"$XRAY" wg >"$W/srv/wg-srv.txt"; "$XRAY" wg >"$W/srv/wg-cli.txt"
WS_PRIV="$(kv PrivateKey <"$W/srv/wg-srv.txt")"; WS_PUB="$(kv 'Password (PublicKey)' <"$W/srv/wg-srv.txt")"
WC_PRIV="$(kv PrivateKey <"$W/srv/wg-cli.txt")"; WC_PUB="$(kv 'Password (PublicKey)' <"$W/srv/wg-cli.txt")"
AWG_PARAMS='{"jc":4,"jmin":40,"jmax":70,"s1":37,"s2":61,"h1":1361409513,"h2":2016328541,"h3":726101713,"h4":1919296617}'
start_awg() {
  nsx vpn env WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 LOG_LEVEL=verbose "$AWG" -f awg0 >>"$OUT/amneziawg.log" 2>&1 & AWG_PID=$!
  for i in $(seq 50); do [ -S /run/amneziawg/awg0.sock ] && break; sleep 0.1; done
  nsx vpn ip addr add 10.66.66.1/24 dev awg0; nsx vpn ip link set awg0 up
  "${PY[@]}" -c 'import base64,json,socket,sys
a=sys.argv;p=json.loads(a[4]);hx=lambda k: base64.b64decode(k).hex()
cfg="set=1\nprivate_key=%s\nlisten_port=51820\n"%hx(a[2])+"".join("%s=%s\n"%(k,p[k]) for k in ("jc","jmin","jmax","s1","s2","h1","h2","h3","h4"))
cfg+="public_key=%s\nallowed_ip=10.66.66.2/32\n\n"%hx(a[3])
s=socket.socket(socket.AF_UNIX);s.connect(a[1]);s.sendall(cfg.encode());r=s.recv(4096).decode();print(r.strip());sys.exit(0 if "errno=0" in r else 1)' \
    /run/amneziawg/awg0.sock "$WS_PRIV" "$WC_PUB" "$AWG_PARAMS" >>"$OUT/amneziawg.log" || die "UAPI amneziawg"; }
start_awg
awg_stat() { "${PY[@]}" -c 'import socket,sys
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(b"get=1\n\n");d=b""
while not d.endswith(b"\n\n"):
  c=s.recv(65536)
  if not c: break
  d+=c
kv=dict(l.split("=",1) for l in d.decode().splitlines() if "=" in l)
import json;print(json.dumps({k:kv.get(k) for k in ("last_handshake_time_sec","rx_bytes","tx_bytes","jc","h1")}))' /run/amneziawg/awg0.sock 2>/dev/null; }
log "Xray (pid $XR_PID) и amneziawg-go (pid $AWG_PID) запущены"
for n in tv:10.10.1.1 phone:10.10.1.1 laptop:10.10.2.1; do nsx "${n%%:*}" ping -c1 -W1 "${n#*:}" >/dev/null; done

# --- настройки: профили VLESS и AmneziaWG (как их задаёт администратор), правила — через защищённый API ---
CFG="$W/state/config.json"; mkdir -p "$W/state"; chmod 700 "$W/state"
"${PY[@]}" -c 'import json,sys
a=sys.argv;d=json.load(open(a[1]))
vl={"server":"10.30.0.2","port":443,"sni":"vpn.lab.test","flow":"xtls-rprx-vision","client_fingerprint":"chrome"}
vl.update({"security":"reality","reality":{"public_key":a[2],"short_id":a[3]}} if a[7]=="reality" else {"security":"tls","cert_sha256":a[8]})
d["profiles"]=[{"id":"vless-lab","name":"VLESS стенд","kind":"vless","on_failure":"block","endpoint":vl},
 {"id":"awg-lab","name":"AmneziaWG стенд","kind":"wireguard","on_failure":"block","endpoint":{"server":"10.30.0.2","port":51820,"public_key":a[4],
  "address":"10.66.66.2/32","mtu":1380,"awg":json.loads(a[5])}}]
d["groups"].append({"id":"wide","name":"Широкая (стенд)","destinations":[{"type":"cidr","value":"10.96.0.0/14"}]})
json.dump(d,open(a[6],"w"),ensure_ascii=False,indent=2)' "$ROOT/fixtures/lab/config.json" "$RPUB" "$SID" "$WS_PUB" "$AWG_PARAMS" "$CFG" "$VLESS_MODE" "$PIN"
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
cgi POST /auth/login "$W/login.json" HTTP_ORIGIN="$ORIGIN" >"$W/a-login.out"
PRE="$(grep -o '__Host-mitt_pre=[0-9a-f]*' "$W/a-login.out" | cut -d= -f2)"
printf '{"totp":"%s"}' "$(totp 30)" >"$W/second.json"
cgi POST /auth/second "$W/second.json" HTTP_ORIGIN="$ORIGIN" HTTP_COOKIE="__Host-mitt_pre=$PRE" >"$W/a-second.out"
[ "$(status_of <"$W/a-second.out")" = 200 ] || die "вход не выполнен"
SESSENV=(HTTP_COOKIE="__Host-mitt_sess=$(grep -o '__Host-mitt_sess=[0-9a-f]*' "$W/a-second.out" | cut -d= -f2)" HTTP_X_MITT_CSRF="$(body_of <"$W/a-second.out" | jget csrf)")
: >"$OUT/api.jsonl"
save_rule() { local rev; cgi GET /config - >"$W/cfg.out"; rev="$(body_of <"$W/cfg.out" | jget revision)"
  printf '{"base_revision":"%s","rule":%s}' "$rev" "$1" >"$W/save.json"
  cgi POST /rules "$W/save.json" HTTP_ORIGIN="$ORIGIN" HTTP_SEC_FETCH_SITE=same-origin >"$W/save.out"
  printf '{"rule":%s,"status":%s}\n' "$1" "$(status_of <"$W/save.out")" >>"$OUT/api.jsonl"
  [ "$(status_of <"$W/save.out")" = 200 ] || { cat "$W/save.out"; die "сохранение не прошло"; }; }
save_rule '{"id":"r-tv-video-vless","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"video"},"action":{"type":"profile","id":"vless-lab"}}'
save_rule '{"id":"r-tv-wide-block","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"wide"},"action":{"type":"block"}}'
save_rule '{"id":"r-guest-video-awg","source":{"type":"network","id":"guest"},"destination":{"type":"group","id":"video"},"action":{"type":"profile","id":"awg-lab"}}'
log "три правила сохранены через CGI после входа"

# --- рендер, Mihomo, apply (netfilter) ---
ip -n router -4 neigh show | awk '{for(i=2;i<NF;i++) if($i=="lladdr") print 1999999999, $(i+1), $1, "lab", "*"}' | grep -v ' 10\.20\.' >"$W/dhcp.leases"
"${PY[@]}" -c 'import json,sys;a=sys.argv;json.dump({"version":1,"profiles":{"vless-lab":{"uuid":a[1]},"awg-lab":{"private_key":a[2]}}},open(a[3],"w"))' "$VUUID" "$WC_PRIV" "$W/secrets.json"; chmod 600 "$W/secrets.json"
render() { "${RUNCTL[@]}" "$CTL" render "$1" "$W/secrets.json" "$W/dhcp.leases" "$2" >"$3" || { cat "$3"; die "render $1"; }; }
render "$CFG" "$W/mihomo" "$OUT/render.json"
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]));[p.update({k:"<скрыт>" for k in ("uuid","private-key","pre-shared-key") if k in p}) for p in d.get("proxies",[])];json.dump(d,open(sys.argv[2],"w"),indent=2,ensure_ascii=False)' "$W/mihomo/config.yaml" "$OUT/mihomo.config.redacted.json"
nsx router "$MIHOMO" -t -d "$W/mihomo" -f "$W/mihomo/config.yaml" >"$OUT/mihomo.test.log" 2>&1 || { cat "$OUT/mihomo.test.log"; die "mihomo -t"; }
start_mh() { nsx router "$MIHOMO" -d "$1" -f "$1/config.yaml" >>"$OUT/mihomo.log" 2>&1 & MH_PID=$!
  for i in $(seq 100); do ip -n router link show mitt0 >/dev/null 2>&1 && break; sleep 0.1; done; sleep 1; }
stop_mh() { kill "$MH_PID" 2>/dev/null; wait "$MH_PID" 2>/dev/null; }
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

: >"$OUT/probes.jsonl"; : >"$OUT/phases.jsonl"
probe() { local id="$1" ns="$2" proto="$3" addr="$4" t0 t1 out rc
  t0="$(now)"; out="$(nsx "$ns" "${PY[@]}" "$ROOT/tools/lab/echo.py" probe "$proto" "$addr" 7007 "$id" 2>&1)"; rc=$?; t1="$(now)"
  "${PY[@]}" -c 'import json,sys
a=sys.argv
try: r=json.loads(a[7])
except Exception: r={"raw":a[7]}
print(json.dumps({"probe":a[1],"ns":a[2],"proto":a[3],"addr":a[4],"rc":int(a[5]),"t0":float(a[6]),"t1":float(a[8]),"reply":r}))' \
    "$id" "$ns" "$proto" "$addr" "$rc" "$t0" "$out" "$t1" >>"$OUT/probes.jsonl"
  log "проба $id ($ns $proto → $addr): rc=$rc $out"; }
phase() { printf '{"phase":"%s","t":%s}\n' "$1" "$(now)" >>"$OUT/phases.jsonl"; log "== фаза $1"; }
set_of() { local p="$1"
  probe "$p-tv-tcp" tv tcp 10.99.0.10; probe "$p-tv-udp" tv udp 10.99.0.10; probe "$p-tv-wide" tv tcp 10.98.0.10; probe "$p-tv-v6" tv tcp fd00:99::10
  probe "$p-lap-tcp" laptop tcp 10.99.0.10; probe "$p-lap-udp" laptop udp 10.99.0.10; probe "$p-lap-other" laptop tcp 10.98.0.10
  probe "$p-phone-tcp" phone tcp 10.99.0.10; probe "$p-phone-udp" phone udp 10.99.0.10; }
retry_ok() { for i in $(seq 30); do nsx "$1" "${PY[@]}" "$ROOT/tools/lab/echo.py" probe tcp 10.99.0.10 7007 "warm-$1-$i" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

phase both
retry_ok tv; retry_ok laptop
set_of P
log "AmneziaWG peer: $(awg_stat)"; awg_stat >"$OUT/awg-peer-stats.txt"

phase vless_down
kill "$XR_PID"; wait "$XR_PID" 2>/dev/null; sleep 0.5
set_of V
start_xray; retry_ok tv

phase awg_down
kill "$AWG_PID"; wait "$AWG_PID" 2>/dev/null; sleep 0.5
set_of A
start_awg; retry_ok laptop

phase engine_down
stop_mh; sleep 0.5
set_of E

# несовместимые параметры AmneziaWG (h1 не совпадает с peer) и чужая проверка VLESS (другой закреплённый сертификат
# в режиме TLS, другой открытый ключ в режиме REALITY): связи нет, обхода нет
phase bad_params
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]))
for p in d["profiles"]:
  if p["id"]=="awg-lab": p["endpoint"]["awg"]["h1"]=p["endpoint"]["awg"]["h1"]+1
  if p["id"]=="vless-lab" and "reality" in p["endpoint"]: p["endpoint"]["reality"]["public_key"]=sys.argv[3]
  if p["id"]=="vless-lab" and "cert_sha256" in p["endpoint"]: p["endpoint"]["cert_sha256"]="00"*32
json.dump(d,open(sys.argv[2],"w"))' "$CFG" "$W/cfg-bad.json" "$(kv 'Password (PublicKey)' < <("$XRAY" x25519))"
render "$W/cfg-bad.json" "$W/mihomo-bad" "$OUT/render-bad.json"
HS_BEFORE="$(awg_stat)"
start_mh "$W/mihomo-bad"
admin B0-apply-bad-params apply --config "$W/cfg-bad.json" --secrets "$W/secrets.json" --leases "$W/dhcp.leases" --marker netfilter
set_of B
log "AmneziaWG peer после неверных параметров: $(awg_stat)"
printf '{"before":%s,"after":%s}\n' "${HS_BEFORE:-null}" "$(awg_stat || echo null)" >"$OUT/awg-bad-params.json"
stop_mh

# «перезагрузка роутера»: все наши записи ядра сняты, Mihomo не запущен; загрузка — guard до Mihomo, затем apply
phase reboot
admin R0-revert revert
admin R1-guard-at-boot "${APPLY[@]}" --guard-only
set_of G
start_mh "$W/mihomo"
admin R2-apply-after-boot "${APPLY[@]}"
retry_ok tv; retry_ok laptop
phase after_reboot
set_of Z

phase end
# журнал доступа Xray содержит идентификаторы клиента; в артефакты — только число принятых соединений к целям
grep -cE 'accepted (tcp|udp):10\.9[89]\.0\.10' "$W/srv/xray-access.log" >"$OUT/xray-accepted.count" 2>/dev/null
admin X1-revert revert
stop_mh; kill "$XR_PID" "$AWG_PID" 2>/dev/null; wait "$XR_PID" "$AWG_PID" 2>/dev/null
sleep 0.5; kill "$SN1" "$SN2" 2>/dev/null

MITT_TLSKEY="$W/tls/key.pem" MITT_PW="$PW" MITT_UUID="$VUUID" MITT_WC="$WC_PRIV" MITT_WS="$WS_PRIV" MITT_RP="$RPRIV" "${PY[@]}" -c 'import json,os,sys
from pathlib import Path
out=Path(sys.argv[1]);sec={k:os.environ[v] for k,v in {"panel_password":"MITT_PW","totp_secret":"TOTP_SECRET","vless_uuid":"MITT_UUID","awg_client_private":"MITT_WC","awg_server_private":"MITT_WS","reality_private":"MITT_RP"}.items()}
sec["tls_key"]=[l for l in open(os.environ["MITT_TLSKEY"]).read().splitlines() if l and not l.startswith("-----")][0]  # эфемерный ключ TLS прогона
found=sorted({f"{k}:{f.relative_to(out)}" for f in out.rglob("*") if f.is_file() for k,v in sec.items() if v.encode() in f.read_bytes()})
json.dump({"scanned":sum(1 for f in out.rglob("*") if f.is_file()),"found":found},open(out/"secret-leak.json","w"))' "$OUT"
log "готово"
