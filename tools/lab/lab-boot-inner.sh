#!/usr/bin/env bash
# Автозагрузка и служба на «роутере» в одноразовых namespace. Сценарии пакета выполняет штатный BusyBox ash 1.25.1
# (ARM64 под qemu); панель — штатные nginx (TLS) и uhttpd (CGI) прошивки под qemu; контроллер — ARM64 под qemu;
# клиент TrustTunnel — официальный x86_64 той же версии, что aarch64 в пакете (TUN под qemu-user не проверяется);
# сервер TrustTunnel (trusttunnel_endpoint) — настоящий.
#   tv 10.10.1.2 ─ br-lan 10.10.1.1 [router] 10.20.0.2 ─ [inet] ─ 10.30.0.2 [trusttunnel server]
set -uo pipefail
: "${ROOT:?}" "${W:?}" "${OUT:?}" "${PKG:?}" "${TTCLIENT:?}" "${TTBIN:?}"
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
PY=(python3 -I -X utf8)
log() { printf '[boot] %s\n' "$*" | tee -a "$OUT/lab.log"; }
die() { log "ОШИБКА: $*"; exit 1; }
nsx() { local n="$1"; shift; nsenter --net="/run/netns/$n" -- "$@"; }
now() { "${PY[@]}" -c 'import time;print(round(time.time(),3))'; }

mount -t tmpfs tmpfs /run || die "tmpfs /run"
# --- программы «роутера»: апплеты BusyBox стока, uci/nginx/uhttpd/openssl стока (qemu), ip, iptables и ipset хоста
SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv ln rm mkdir chmod readlink sed awk grep head tail wc tr cut sort cmp df uname date sleep kill sync basename dirname unxz xzcat zcat gzip mktemp touch printf echo test expr id ls md5sum cksum pwd logger; do
  # только апплеты, которые действительно есть в образе 1.1.38: недостающий — ошибка «not found» в сценарии, как на роутере
  if [ -e "$F/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
  printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  else echo "$a" >>"$OUT/stock-missing-applets.txt"; fi
done
for p in sbin/uci usr/bin/openssl usr/sbin/uhttpd usr/bin/curl; do printf '#!/bin/sh\nexec %s -L %s %s/%s "$@"\n' "$Q" "$F" "$F" "$p" >"$SB/$(basename "$p")"; done
# nginx стока: в user namespace отображён только uid 0 — рабочий процесс от root, setgroups — через seccomp-обёртку (только лаборатория)
cat >"$SB/nginx" <<PYEOF
#!/usr/bin/python3
import os, sys
a, out, i = sys.argv[1:], [], 0
while i < len(a):
    if a[i] == "-g":
        out += ["-g", "user root root; " + a[i + 1]]; i += 2
    else:
        out.append(a[i]); i += 1
os.execv(sys.executable, [sys.executable, "-I", "$ROOT/tools/lab/nosetgroups.py", "$Q", "-L", "$F", "$F/usr/sbin/nginx"] + out)
PYEOF
NFBIN="$W/nfbin"; mkdir -p "$NFBIN"
# iptables распаковывается в каталог Linux: на диске Windows libxt_MARK.so и libxt_mark.so — один файл (регистр не различается)
IPTD="$W/iptables-root"; for d in "$ROOT"/.tools/lab/iptables/*.deb; do dpkg-deb -x "$d" "$IPTD"; done
L="$IPTD/usr/lib/x86_64-linux-gnu"; XT="$L/xtables"
for t in iptables iptables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s\nexec %s %s "$@"\n' "$L" "$XT" "$IPTD/usr/sbin/xtables-legacy-multi" "$t" >"$NFBIN/$t"; done
for t in ip6tables ip6tables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s\nexec %s %s "$@"\n' "$L" "$XT" "$IPTD/usr/sbin/xtables-nft-multi" "$t" >"$NFBIN/$t"; done
ISD="$ROOT/.tools/lab/ipset/root"
printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s\nexec %s "$@"\n' "$ISD/usr/lib/x86_64-linux-gnu" "$ISD/usr/sbin/ipset" >"$NFBIN/ipset"
ln -sf "$(command -v ip)" "$NFBIN/ip"
chmod +x "$SB"/* "$NFBIN"/*
LB="$W/labbin"; mkdir -p "$LB"
for n in mi-tt-ctl mi-tt-admin mi-tt-dns; do printf '#!/bin/sh\nexec %s "$0.arm64" "$@"\n' "$Q" >"$LB/$n"; done
# nfqws2 — x86_64 той же версии zapret2, что aarch64 в пакете (очередь NFQUEUE под qemu-user не проверяется); файл лежит
# рядом с Lua, блобами и списками хостов пакета, поэтому --chdir (каталог программы) — тот же, что на роутере.
# В namespace отображён только uid/gid 0: сброс привилегий — к --uid=0:0, setgroups — через seccomp-обёртку (только лаборатория)
cp "$ROOT/.tools/lab/zapret2/zapret2-v1.0.7/binaries/linux-x86_64/nfqws2" "$LB/nfqws2.x86"
printf '#!/bin/sh\nexec %s -I %s "${0%%/*}/nfqws2.x86" "$@" --uid=0:0\n' "$(command -v python3)" "$ROOT/tools/lab/nosetgroups.py" >"$LB/nfqws2"
printf '#!/bin/sh\nexec %s "$@"\n' "$TTCLIENT" >"$LB/trusttunnel_client"
chmod +x "$LB"/*
RR="$W/root"; mkdir -p "$RR/data" "$RR/tmp" "$RR/etc/config" "$RR/usr/share/xiaoqiang"
cp "$F/usr/share/xiaoqiang/xiaoqiang_version" "$RR/usr/share/xiaoqiang/"; cp "$F/etc/config/firewall" "$F/etc/config/network" "$RR/etc/config/"
# адрес LAN в uci network — по нему панель строит допустимые Origin
sed -i "s/option ipaddr '192.168.31.1'/option ipaddr '10.10.1.1'/" "$RR/etc/config/network"
DMQ="$ROOT/.tools/lab/dnsmasq/root"; mkdir -p "$RR/tmp/dnsmasq.d"
cat >"$W/dnsmasq-restart" <<EOF
#!/bin/sh
# штатный dnsmasq роутера в лаборатории: провайдерский DNS — 198.51.100.53, conf-dir стока /tmp/dnsmasq.d
PATH=/usr/sbin:/usr/bin:/sbin:/bin
[ -f "$W/dnsmasq.pid" ] && kill "\$(cat "$W/dnsmasq.pid")" 2>/dev/null; sleep 0.3
exec env LD_LIBRARY_PATH="$DMQ/usr/lib/x86_64-linux-gnu" python3 -I "$ROOT/tools/lab/nosetgroups.py" "$DMQ/usr/sbin/dnsmasq" --conf-file=/dev/null --user=root --group=root \
  --listen-address=10.10.1.1 --bind-interfaces --no-resolv --server=198.51.100.53 --conf-dir="$RR/tmp/dnsmasq.d" \
  --pid-file="$W/dnsmasq.pid" --log-queries --log-facility="$OUT/dnsmasq.log"
EOF
chmod +x "$W/dnsmasq-restart"
ENVR=(PATH="$SB:$NFBIN" MITT_ROOT="$RR" MITT_LAB_BIN="$LB" MITT_UCI_CONF="$RR/etc/config" MITT_INTERVAL=2 MITT_LEASES="$RR/tmp/dhcp.leases"
  MITT_DNSMASQ_RESTART="$W/dnsmasq-restart" MITT_LISTS_URL="http://10.99.0.20:8080" MITT_ZAPRET_TARGETS="$W/zapret-targets.txt" MI_TT_IPTABLES="$NFBIN/iptables" MI_TT_IP6TABLES="$NFBIN/ip6tables" MI_TT_IPTABLES_SAVE="$NFBIN/iptables-save" MI_TT_IPSET="$NFBIN/ipset")

# --- топология ---
for n in router tv phone inet vpn; do ip netns add "$n" || die "netns $n"; ip -n "$n" link set lo up; done
ip link add r-tv netns router type veth peer name eth0 netns tv
ip link add r-ph netns router type veth peer name eth0 netns phone
ip link add r-wan netns router type veth peer name i-r netns inet
ip link add i-v netns inet type veth peer name v-i netns vpn
ip -n tv link set eth0 address 02:00:00:00:0a:02; ip -n phone link set eth0 address 02:00:00:00:0b:02
ip -n router link add br-lan type bridge; ip -n router link set r-tv master br-lan; ip -n router link set r-ph master br-lan
for l in br-lan r-tv r-ph r-wan; do ip -n router link set "$l" up; done
ip -n router addr add 10.10.1.1/24 dev br-lan; ip -n router addr add fd00:10::1/64 dev br-lan nodad
ip -n router addr add 10.20.0.2/30 dev r-wan; ip -n router route add default via 10.20.0.1
for c in tv:10.10.1.2 phone:10.10.1.3; do ip -n "${c%%:*}" addr add "${c#*:}/24" dev eth0; ip -n "${c%%:*}" link set eth0 up; ip -n "${c%%:*}" route add default via 10.10.1.1; done
ip -n inet addr add 10.20.0.1/30 dev i-r; ip -n inet addr add 10.30.0.1/30 dev i-v; ip -n inet link set i-r up; ip -n inet link set i-v up
for a in 10.99.0.10 10.99.0.11 10.99.0.12 10.99.0.13 10.99.0.20; do ip -n inet addr add "$a/32" dev lo; done; ip -n inet addr add 198.51.100.53/32 dev lo; ip -n inet addr add 198.51.100.54/32 dev lo
ip -n inet route add 10.10.1.0/24 via 10.20.0.2
ip -n vpn addr add 10.30.0.2/30 dev v-i; ip -n vpn link set v-i up; ip -n vpn route add default via 10.30.0.1
for n in router inet; do nsx "$n" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; done
nsx inet "${PY[@]}" "$ROOT/tools/lab/sniff.py" i-r "$OUT/sniff-wan.jsonl" &
nsx inet "${PY[@]}" "$ROOT/tools/lab/echo.py" serve 10.99.0.10 7007 "$OUT/echo.jsonl" echo &
nsx inet "${PY[@]}" "$ROOT/tools/lab/echo.py" serve 10.99.0.11 7007 "$OUT/echo2.jsonl" echo2 &
nsx inet "${PY[@]}" "$ROOT/tools/lab/dnsauth.py" 198.51.100.53 53 "$OUT/dnsauth.jsonl" internet &
nsx inet "${PY[@]}" "$ROOT/tools/lab/dnsauth.py" 198.51.100.54 53 "$OUT/dnsauth.jsonl" tunnel-resolver &

# --- сервер TrustTunnel с эфемерным сертификатом этого прогона ---
TTPASS="$("${PY[@]}" -c 'import secrets;print(secrets.token_urlsafe(18))')"
"$ROOT/tools/lab/ephemeral-tls.sh" "$W/tls" >/dev/null || die "эфемерный TLS"
mkdir -p "$W/tt" && chmod 700 "$W/tt"
cat >"$W/tt/vpn.toml" <<EOF
listen_address = "10.30.0.2:443"
ipv6_available = false
allow_private_network_connections = true
credentials_file = "$W/tt/credentials.toml"

[listen_protocols]

[listen_protocols.http1]

[listen_protocols.http2]

[forward_protocol]
direct = {}
EOF
printf '[[main_hosts]]\nhostname = "vpn.lab.test"\ncert_chain_path = "%s"\nprivate_key_path = "%s"\n' "$W/tls/cert.pem" "$W/tls/key.pem" >"$W/tt/hosts.toml"
printf '[[client]]\nusername = "tv-user"\npassword = "%s"\n' "$TTPASS" >"$W/tt/credentials.toml"
nsx vpn "$TTBIN" "$W/tt/vpn.toml" "$W/tt/hosts.toml" >>"$OUT/trusttunnel-server.log" 2>&1 &
# Zapret: эхо на порту 443 (TCP и UDP) — трафик телефона идёт через очередь nfqws2; веб-цели подбора стратегии
nsx inet "${PY[@]}" "$ROOT/tools/lab/echo.py" serve 10.99.0.12 443 "$OUT/echo-zapret.jsonl" echo-zapret &
WS="$W/web"; mkdir -p "$WS"; printf 'mi-lumruri lab\n' >"$WS/index.html"
printf 'required https://10.99.0.13/\nrequired http://10.99.0.13/\noptional https://10.99.0.13/index.html\n' >"$W/zapret-targets.txt"
nsx inet "${PY[@]}" "$ROOT/tools/lab/web.py" 10.99.0.13 80 "$WS" "$OUT/web-zapret.jsonl" &
nsx inet "${PY[@]}" "$ROOT/tools/lab/web.py" 10.99.0.13 443 "$WS" "$OUT/web-zapret.jsonl" "$W/tls/cert.pem" "$W/tls/key.pem" &
# готовые списки: «репозиторий itdoginfo» — копия снимка пакета; один список позже изменится
LS="$W/lists-srv"; cp -r "$PKG/payload/lists" "$LS"
nsx inet "${PY[@]}" "$ROOT/tools/lab/web.py" 10.99.0.20 8080 "$LS" "$OUT/web-lists.jsonl" &
nsx router "$W/dnsmasq-restart" || die "dnsmasq"

# --- установка пакета (штатный BusyBox, без запуска) и настройки владельца ---
bb() { env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$@"; }
bb "$PKG/install.sh" install --no-start >"$OUT/install.out" 2>&1 || { cat "$OUT/install.out"; die "установка"; }
E="$RR/data/mi-lumruri/etc"
"${PY[@]}" -c 'import json,sys
cert=open(sys.argv[2]).read()
d={"version":1,
 "profiles":[{"id":"tt-lab","name":"TrustTunnel стенд","kind":"trusttunnel","on_failure":"block",
   "endpoint":{"server":"10.30.0.2","port":443,"sni":"vpn.lab.test","username":"tv-user","certificate":cert}}],
 "networks":[{"id":"home","name":"Дом","ssid":"Home","subnet":"10.10.1.0/24","bridge":"br-lan","ports":["r-tv","r-ph"]}],
 "devices":[{"id":"tv","name":"Телевизор","mac":"02:00:00:00:0a:02","network":"home"},{"id":"phone","name":"Телефон","mac":"02:00:00:00:0b:02","network":"home"}],
 "groups":[{"id":"video","name":"Видео (стенд)","destinations":[{"type":"domain_suffix","value":"video.lab.test"},{"type":"cidr","value":"10.99.0.10/32"}]},
   {"id":"dnsgrp","name":"Домен (стенд)","destinations":[{"type":"domain_suffix","value":"ok2.lab.test"}]},
   {"id":"lists","name":"Готовый список","destinations":[{"type":"category","id":"svc-cloudflare"}]}],
 "categories":[{"id":"svc-cloudflare","name":"Cloudflare","kind":"domain","source":"itdoginfo:Services/cloudflare.lst"}],
 "rules":[{"id":"r-tv-video","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"video"},"action":{"type":"profile","id":"tt-lab"}},
   {"id":"r-tv-dns","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"dnsgrp"},"action":{"type":"profile","id":"tt-lab"}},
   {"id":"r-tv-lists","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"lists"},"action":{"type":"profile","id":"tt-lab"}}],
 "dns":{"tunnel_resolver":"198.51.100.54"},
 "zapret":{"strategy":"auto","youtube":"auto"},
 "default_action":{"type":"direct_zapret"}}
json.dump(d,open(sys.argv[1],"w"),ensure_ascii=False,indent=2)' "$E/config.json" "$W/tls/cert.pem" || die "настройки"
printf '{"version":1,"profiles":{"tt-lab":{"password":"%s"}}}\n' "$TTPASS" >"$E/secrets.json"
for c in tv:10.10.1.2 phone:10.10.1.3; do nsx "${c%%:*}" ping -c1 -W1 10.10.1.1 >/dev/null; done
ip -n router -4 neigh show | awk '{for(i=2;i<NF;i++) if($i=="lladdr") print 1999999999, $(i+1), $1, "lab", "*"}' >"$RR/tmp/dhcp.leases"
# вход в панель: пароль и TOTP (секреты — только в этом прогоне)
PW="$("${PY[@]}" -c 'import secrets;print(secrets.token_urlsafe(18))')"
ADM="$W/admin.arm64"; "$Q" -L "$F" "$F/bin/busybox" unxz -c "$PKG/payload/bin/mi-tt.xz" >"$ADM"; chmod +x "$ADM"
printf '%s\n%s\n' "$PW" "$PW" | env -i MI_TT_AUTH_DIR="$E/auth" MI_TT_SESSION_DIR="$RR/tmp/mi-lumruri/sessions" "$Q" "$ADM" auth init --stdin --with-totp >"$W/auth.json" || die "auth init"
export TOTP_SECRET; TOTP_SECRET="$("${PY[@]}" -c 'import json,sys;print(json.load(open(sys.argv[1]))["totp_secret_base32"])' "$W/auth.json")"
totp() { "${PY[@]}" -c 'import base64,hashlib,hmac,os,struct,sys,time
s=os.environ["TOTP_SECRET"];k=base64.b32decode(s+"="*(-len(s)%8));c=struct.pack(">Q",int((time.time()+int(sys.argv[1]))//30))
h=hmac.new(k,c,hashlib.sha1).digest();o=h[-1]&15;print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "${1:-0}"; }
totp 0 | env -i MI_TT_AUTH_DIR="$E/auth" MI_TT_SESSION_DIR="$RR/tmp/mi-lumruri/sessions" "$Q" "$ADM" auth confirm --stdin >/dev/null || die "auth confirm"

: >"$OUT/probes.jsonl"; : >"$OUT/phases.jsonl"
probe() { local id="$1" ns="$2" host="${3:-10.99.0.10}" port="${4:-7007}" t0 out rc; t0="$(now)"; out="$(nsx "$ns" "${PY[@]}" "$ROOT/tools/lab/echo.py" probe tcp "$host" "$port" "$id" 2>&1)"; rc=$?
  "${PY[@]}" -c 'import json,sys
a=sys.argv
try: r=json.loads(a[5])
except Exception: r={"raw":a[5]}
print(json.dumps({"probe":a[1],"ns":a[2],"rc":int(a[3]),"t0":float(a[4]),"reply":r}))' "$id" "$ns" "$rc" "$t0" "$out" >>"$OUT/probes.jsonl"; log "проба $id ($ns): rc=$rc $out"; }
phase() { printf '{"phase":"%s","t":%s}\n' "$1" "$(now)" >>"$OUT/phases.jsonl"; log "== фаза $1"; }
ipt() { nsx router "$NFBIN/iptables" -w "$@"; }
snapz() { { nsx router ip rule show | awk -F: '$1>=3000 && $1<=3199'; nsx router ip route show table 3100 2>/dev/null; ipt -t mangle -S | grep MITT; ipt -S | grep MITT; nsx router "$NFBIN/ipset" list -n | grep mitt; } >"$OUT/zone.$1.txt" 2>/dev/null; }
# WAN поднялся: на роутере netifd/DHCP возвращает маршрут по умолчанию (ядро сняло его при link down)
wan_on() { ip -n router link set r-wan up; ip -n router route replace default via 10.20.0.1; }
wait_tunnel() { for i in $(seq 60); do nsx tv "${PY[@]}" "$ROOT/tools/lab/echo.py" probe tcp 10.99.0.10 7007 "wait" 2>/dev/null | grep -q 10.30.0.2 && return 0; sleep 1; done; return 1; }
RN="$RR/tmp/mi-lumruri/run"
cp_status() { cp "$RN/status.json" "$OUT/status.$1.json" 2>/dev/null; cp "$RN/last-apply.json" "$OUT/last-apply.$1.json" 2>/dev/null; }
boot() { nsx router env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$RR/data/mi-lumruri/mitt-boot.sh" "$@"; }

# 1) холодный старт без WAN (как fw3 при загрузке): защита сразу, панель локально
phase cold_boot_no_wan
ip -n router link set r-wan down
T0="$(now)"; boot >"$OUT/boot1.out" 2>&1; echo "exit=$?" >>"$OUT/boot1.out"
T1="$(now)"; snapz boot-guard; cp_status boot; cp "$RR/tmp/mi-lumruri/log/mitt.log" "$OUT/mitt.boot1.log" 2>/dev/null; cp "$RN/apply.boot-guard.json" "$RN/render.json" "$OUT/" 2>/dev/null
printf '{"boot_seconds":%s}\n' "$("${PY[@]}" -c "print(round($T1-$T0,1))")" >"$OUT/boot-time.json"
probe B-tv-no-wan tv; probe B-phone-no-wan phone
boot auth status >"$OUT/auth-status.json" 2>&1
ls "$RR/tmp/mi-lumruri/bin" >"$OUT/engines.ls" 2>&1
# панель: https через штатный nginx стока → uhttpd стока → CGI ARM64; вход паролем и TOTP из сети LAN
sleep 2
CJ="$W/cookies"; cu() { nsx tv curl -sk -m 20 -c "$CJ" -b "$CJ" "$@"; }
cu -o "$W/index.html" -w '%{http_code}' https://10.10.1.1:8443/ >"$OUT/panel-index.code"
cu -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/auth/session >"$OUT/panel-session.out"
cu -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/config >"$OUT/panel-config-noauth.out"
cu -X POST -H 'Content-Type: application/json' -H 'Origin: https://10.10.1.1:8443' -H 'Sec-Fetch-Site: same-origin' -d "{\"password\":\"$PW\"}" -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/auth/login >"$W/login.out"
tail -1 "$W/login.out" >"$OUT/panel-login.code"
cu -X POST -H 'Content-Type: application/json' -H 'Origin: https://10.10.1.1:8443' -d "{\"totp\":\"$(totp 30)\"}" -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/auth/second >"$W/second.out"
tail -1 "$W/second.out" >"$OUT/panel-second.code"
CSRF="$(head -1 "$W/second.out" | "${PY[@]}" -c 'import json,sys;print(json.load(sys.stdin).get("csrf",""))')"
cu -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/config | tail -1 >"$OUT/panel-config-auth.code"
grep -c "__Host-mitt_sess" "$CJ" >"$OUT/panel-cookie.count"
# готовые списки: категории svc-* разложены из снимка релиза до первого рендера; каталог — через API панели
cu -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/lists >"$OUT/panel-lists.out"
cu -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/router >"$OUT/panel-router.out"
ls "$E/categories" >"$OUT/categories.ls" 2>&1
nsx tv curl -sk -m 10 -D - -o /dev/null https://10.10.1.1:8443/ | tr -d '\r' >"$OUT/panel-headers.txt"
# первая проверка обновлений списков (служба, curl стока) без WAN: «нет связи», прежние списки остаются
for i in $(seq 60); do [ -f "$RN/lists.json" ] && break; sleep 1; done; cp "$RN/lists.json" "$OUT/lists.boot.json" 2>/dev/null

# 2) WAN появился: служба сама подключает туннель
phase wan_up
wan_on
if wait_tunnel; then echo '{"tunnel":true}' >"$OUT/wan-up.json"; else echo '{"tunnel":false}' >"$OUT/wan-up.json"; fi
probe W-tv tv; probe W-phone phone; cp_status wan; snapz full
nsx router ip route show >"$OUT/routes.main.txt"; nsx router ip rule show >"$OUT/rules.all.txt"; nsx router ip link show >"$OUT/links.txt"

# 2б) Zapret на настоящем ядре: остальной трафик LAN — «напрямую с Zapret»; план mi-tt-admin (цепочки Q, Z, P) применён
# и сверен, nfqws2 x86_64 работает с аргументами рендера (каталог стратегий пакета), трафик телефона к порту 443 проходит
# через очередь 200
phase zapret
TAG="$(sed -n 's/.*"tag":"\([^"]*\)".*/\1/p' "$RN/last-apply.json")"; cp "$RN/apply.$TAG.json" "$OUT/apply.wan.json" 2>/dev/null
RD="$RR/tmp/mi-lumruri/render"; cp "$RD/nfqws2.args" "$OUT/nfqws2.args" 2>/dev/null
nsx router "$RR/tmp/mi-lumruri/bin/nfqws2" --dry-run $(cat "$RD/nfqws2.args") >"$OUT/nfqws2-dry-run.out" 2>&1; echo "exit=$?" >>"$OUT/nfqws2-dry-run.out"
probe Z-phone-443 phone 10.99.0.12 443
nsx phone "${PY[@]}" "$ROOT/tools/lab/echo.py" probe udp 10.99.0.12 443 Z-phone-udp443 >"$OUT/zapret-udp.json" 2>&1
nsx router cat /proc/net/netfilter/nfnetlink_queue >"$OUT/nfqueue.wan.txt" 2>&1
ipt -t mangle -S >"$OUT/mangle.wan.txt"; ipt -t mangle -L -v -x -n >"$OUT/mangle-counters.wan.txt"
kill -0 "$(cat "$RN/nfqws2.pid")" 2>/dev/null && echo alive >"$OUT/nfqws2.wan.alive"
cp "$RR/tmp/mi-lumruri/log/nfqws2.log" "$OUT/nfqws2.wan.log" 2>/dev/null

# 2a) домен из правила: до вопроса DNS адрес не в наборе (напрямую), вопрос ТВ к dnsmasq роутера уходит к резолверу
# через туннель, ответ попадает в ipset — и трафик ТВ к этому адресу идёт в туннель; телефон без правила — напрямую
phase dns_domain
cp "$RR/tmp/dnsmasq.d/mitt.conf" "$OUT/dnsmasq-mitt.conf" 2>/dev/null
probe D-tv-before-dns tv 10.99.0.11
nsx tv "${PY[@]}" "$ROOT/tools/lab/dnsq.py" 10.10.1.1 ok2.lab.test A >"$OUT/dns-tv.json" 2>&1
phase dns_answered
nsx router "$NFBIN/ipset" list >"$OUT/ipset.after-dns.txt" 2>&1
probe D-tv-after-dns tv 10.99.0.11
nsx phone "${PY[@]}" "$ROOT/tools/lab/dnsq.py" 10.10.1.1 ok2.lab.test A >"$OUT/dns-phone.json" 2>&1
probe D-phone-after-dns phone 10.99.0.11
nsx tv "${PY[@]}" "$ROOT/tools/lab/dnsq.py" 10.10.1.1 ok.lab.test A >"$OUT/dns-tv-other.json" 2>&1

# 3) перезагрузка firewall: fw3 снимает цепочки — include вызывает mitt-boot.sh, правила восстанавливаются
phase fw_reload
for t in filter mangle; do
  ipt -t "$t" -S | awk '/^-A (FORWARD|PREROUTING|OUTPUT) .*-j MITT_/ {sub(/^-A /,""); print}' | while read -r spec; do ipt -t "$t" -D $spec; done
  for c in $(ipt -t "$t" -S | awk '/^-N MITT_/ {print $2}'); do ipt -t "$t" -F "$c"; done
  for c in $(ipt -t "$t" -S | awk '/^-N MITT_/ {print $2}'); do ipt -t "$t" -X "$c"; done
done
snapz flushed
phase fw_flushed
probe F-tv-flushed tv
boot >"$OUT/boot-reload.out" 2>&1
phase fw_restored
snapz restored; cp_status fw
probe F-tv tv

# 4) ТВ сменил адрес (новая аренда): правило устройства по MAC действует сразу, без применения политики
phase new_address
nsx tv ip addr del 10.10.1.2/24 dev eth0; nsx tv ip addr add 10.10.1.50/24 dev eth0; nsx tv ip route add default via 10.10.1.1
nsx tv ping -c1 -W1 10.10.1.1 >/dev/null
probe N-tv-new-ip tv

# 5) падение клиента TrustTunnel: TUN исчезает, трафик правила упирается в unreachable; служба перезапускает клиент
phase engine_crash
kill -9 "$(cat "$RN/trusttunnel.pid")"; sleep 0.5; probe E-tv-down tv
for i in $(seq 30); do grep -q '"trusttunnel-restart' "$RN/last-apply.json" 2>/dev/null && break; sleep 1; done
wait_tunnel; probe E-tv-restored tv; cp_status crash

# 6) заявка на применение из панели (сессия 2FA) — служба выполняет
phase panel_apply
cu -X POST -H 'Content-Type: application/json' -H 'Origin: https://10.10.1.1:8443' -H 'Sec-Fetch-Site: same-origin' -H "X-MITT-CSRF: $CSRF" -d '{}' -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/apply-request >"$OUT/panel-apply.out"; tail -1 "$OUT/panel-apply.out" >"$OUT/panel-apply.code"
for i in $(seq 30); do grep -q '"panel-request' "$RN/last-apply.json" 2>/dev/null && break; sleep 1; done
cu -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/status >"$OUT/panel-status.out"; cp_status panel
kill -0 "$(cat "$RN/nfqws2.pid")" 2>/dev/null && echo alive >"$OUT/nfqws2.panel.alive"
post() { cu -X POST -H 'Content-Type: application/json' -H 'Origin: https://10.10.1.1:8443' -H 'Sec-Fetch-Site: same-origin' -H "X-MITT-CSRF: $CSRF" -d "$2" -w '\n%{http_code}' "https://10.10.1.1:8443/cgi-bin/api/$1"; }
at_of() { sed -n 's/.*"at":\([0-9]*\).*/\1/p' "$RN/last-apply.json" 2>/dev/null; }

# 6а) обновление готовых списков по кнопке панели: в «репозитории» изменился один список — служба (mitt-lists.sh update,
# curl стока) загружает и проверяет файлы, синхронизирует категории и применяет политику заново; новый домен — в dnsmasq
phase lists_update
LT="$(date +%s)"; A0="$(at_of)"
f="$LS/Services/cloudflare.lst"; [ -z "$(tail -c1 "$f")" ] || echo >>"$f"; echo lab-new.lab.test >>"$f"
post lists/update '{}' >"$OUT/panel-lists-update.out"
for i in $(seq 300); do c="$(sed -n 's/.*"checked":\([0-9]*\).*/\1/p' "$RN/lists.json" 2>/dev/null)"; [ "${c:-0}" -ge "$LT" ] && break; sleep 1; done
cp "$RN/lists.json" "$OUT/lists.update.json" 2>/dev/null
for i in $(seq 60); do [ "$(at_of)" -gt "${A0:-0}" ] 2>/dev/null && grep -q '"panel-request' "$RN/last-apply.json" && break; sleep 1; done
# файл dnsmasq служба обновляет сразу после применения (dns_sync идёт после apply) — дождаться его
for i in $(seq 30); do grep -q 'lab-new.lab.test' "$RR/tmp/dnsmasq.d/mitt.conf" 2>/dev/null && break; sleep 1; done
cp "$RN/last-apply.json" "$OUT/last-apply.lists.json"; cp "$RR/tmp/dnsmasq.d/mitt.conf" "$OUT/dnsmasq-mitt.lists.conf" 2>/dev/null
cp "$E/categories/svc-cloudflare.list" "$OUT/svc-cloudflare.after.list" 2>/dev/null
# после применения служба перезапускает dnsmasq (новый файл): вопрос — когда он снова отвечает
for i in $(seq 10); do nsx tv "${PY[@]}" "$ROOT/tools/lab/dnsq.py" 10.10.1.1 lab-new.lab.test A >"$OUT/dns-tv-lists.json" 2>&1 && ! grep -q '"error"' "$OUT/dns-tv-lists.json" && break; sleep 1; done

# 6б) подбор стратегии Zapret по кнопке панели: настоящие nfqws2 и curl стока, проверочная очередь 201 (цепочка P), свой
# nfqws2 на каждую стратегию. DPI в лаборатории нет: контроль открывает все цели, стратегии лучше него нет
phase zapret_test
ZP="$(ipt -t mangle -S | awk '/^-N MITT_P/ {print $2}')"
ipt -t mangle -L "$ZP" -v -x -n >"$OUT/zapret-test.P.before.txt" 2>&1
post zapret/test '{"mode":"quick"}' >"$OUT/panel-zapret-test.out"
( while :; do nsx router cat /proc/net/netfilter/nfnetlink_queue; echo --; sleep 0.3; done ) >"$OUT/nfqueue.zapret-test.txt" 2>&1 & SAMP=$!
for i in $(seq 900); do grep -qE '"state":"(done|failed)"' "$RN/zapret-test.json" 2>/dev/null && break; sleep 1; done
kill "$SAMP" 2>/dev/null
cp "$RN/zapret-test.json" "$OUT/zapret-test.json" 2>/dev/null
ipt -t mangle -L "$ZP" -v -x -n >"$OUT/zapret-test.P.after.txt" 2>&1
grep 'подбор Zapret' "$RR/tmp/mi-lumruri/log/mitt.log" >"$OUT/zapret-test.log" 2>/dev/null
cp "$RR/tmp/mi-lumruri/log/zapret-nfqws.log" "$OUT/zapret-nfqws.log" 2>/dev/null
kill -0 "$(cat "$RN/nfqws2.pid")" 2>/dev/null && echo alive >"$OUT/nfqws2.after-test.alive"
probe Z-phone-after-test phone 10.99.0.12 443

# 6в) IPv6 через VPN при «всё через VPN» для ТВ: правило ТВ → весь интернет IPv4 через туннель, ipv6_via_vpn —
# применение проходит, появляются ip -6 rule (метка → 3100), маршрут IPv6 через mitt0 и цепочки ip6tables; затем возврат
phase ipv6_via_vpn
cp "$E/config.json" "$W/config.before-ipv6.json"
"${PY[@]}" -c 'import json,sys
p=sys.argv[1]; c=json.load(open(p))
c["groups"].append({"id":"all-net","name":"Весь интернет","destinations":[{"type":"cidr","value":"0.0.0.0/1"},{"type":"cidr","value":"128.0.0.0/1"}]})
c["rules"].insert(0,{"id":"tv-all","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"all-net"},"action":{"type":"profile","id":c["profiles"][0]["id"]}})
c["ipv6_via_vpn"]=True
json.dump(c,open(p,"w"),ensure_ascii=False,indent=2)' "$E/config.json"
A0="$(at_of)"; post apply-request '{}' >/dev/null
for i in $(seq 60); do [ "$(at_of)" -gt "${A0:-0}" ] 2>/dev/null && grep -q '"panel-request' "$RN/last-apply.json" && break; sleep 1; done
cp "$RN/last-apply.json" "$OUT/last-apply.ipv6.json"
{ nsx router ip -6 rule show | awk -F: '$1>=3000 && $1<=3199'; echo "--- route"; nsx router ip -6 route show table 3100 2>/dev/null
  echo "--- mangle"; nsx router "$NFBIN/ip6tables" -w -t mangle -S | grep MITT; echo "--- filter"; nsx router "$NFBIN/ip6tables" -w -S | grep MITT; } >"$OUT/zone.ipv6.txt" 2>&1
grep -o 'has_ipv6 = [a-z]*' "$RR/tmp/mi-lumruri/render/client.toml" >"$OUT/client.ipv6.txt" 2>/dev/null
cp "$W/config.before-ipv6.json" "$E/config.json"
A0="$(at_of)"; post apply-request '{}' >/dev/null
for i in $(seq 60); do [ "$(at_of)" -gt "${A0:-0}" ] 2>/dev/null && grep -q '"panel-request' "$RN/last-apply.json" && break; sleep 1; done
nsx router ip -6 rule show | awk -F: '$1>=3000 && $1<=3199' >"$OUT/zone.ipv6-off.txt" 2>&1
wait_tunnel

# 7) «перезагрузка роутера»: RAM очищена, правила ядра сняты; снова холодный старт без WAN
phase reboot
boot stop >"$OUT/stop.out" 2>&1
pkill -f "$TTCLIENT" 2>/dev/null; pkill -f "usr/sbin/nginx" 2>/dev/null; pkill -f "usr/sbin/uhttpd" 2>/dev/null; sleep 1
rm -rf "$RR/tmp/mi-lumruri"; ip -n router link set r-wan down
snapz after-reboot
boot >"$OUT/boot2.out" 2>&1; echo "exit=$?" >>"$OUT/boot2.out"
snapz boot2; probe R-tv-no-wan tv
wan_on; wait_tunnel; probe R-tv-wan tv; cp_status reboot
phase end
cp "$RN/lists.json" "$OUT/lists.json" 2>/dev/null
boot stop >>"$OUT/stop.out" 2>&1
pkill -f "$TTCLIENT" 2>/dev/null; pkill -f "usr/sbin/nginx" 2>/dev/null; pkill -f "usr/sbin/uhttpd" 2>/dev/null
[ -f "$W/dnsmasq.pid" ] && kill "$(cat "$W/dnsmasq.pid")" 2>/dev/null
cp "$RR/tmp/mi-lumruri/log/mitt.log" "$OUT/mitt.log" 2>/dev/null
cp "$RR/tmp/mi-lumruri/log/trusttunnel.log" "$OUT/trusttunnel-client.log" 2>/dev/null
MITT_TLSKEY="$W/tls/key.pem" MITT_PW="$PW" MITT_TT="$TTPASS" "${PY[@]}" -c 'import json,os,sys
from pathlib import Path
out=Path(sys.argv[1]);sec={"panel_password":os.environ["MITT_PW"],"totp":os.environ["TOTP_SECRET"],"trusttunnel":os.environ["MITT_TT"]}
sec["tls_key"]=[l for l in open(os.environ["MITT_TLSKEY"]).read().splitlines() if l and not l.startswith("-----")][0]  # эфемерный ключ TLS прогона
found=sorted({f"{k}:{f.relative_to(out)}" for f in out.rglob("*") if f.is_file() for k,v in sec.items() if v.encode() in f.read_bytes()})
json.dump({"found":found},open(out/"secret-leak.json","w"))' "$OUT"
log "готово"
