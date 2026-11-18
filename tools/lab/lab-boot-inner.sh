#!/usr/bin/env bash
# Этап 12: автозагрузка и служба на «роутере» в одноразовых namespace. Сценарии пакета выполняет штатный BusyBox ash
# 1.25.1 (ARM64 под qemu); панель — штатные nginx (TLS) и uhttpd (CGI) прошивки под qemu; контроллер — ARM64 под qemu;
# Mihomo — x86_64 (TUN под qemu-user не проверялся), сервер Hysteria2 — настоящий.
#   tv 10.10.1.2 ─ br-lan 10.10.1.1 [router] 10.20.0.2 ─ [inet] ─ 10.30.0.2 [hysteria server]
set -uo pipefail
: "${ROOT:?}" "${W:?}" "${OUT:?}" "${PKG:?}" "${MIHOMO:?}" "${HYBIN:?}"
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
PY=(python3 -I -X utf8)
log() { printf '[boot] %s\n' "$*" | tee -a "$OUT/lab.log"; }
die() { log "ОШИБКА: $*"; exit 1; }
nsx() { local n="$1"; shift; nsenter --net="/run/netns/$n" -- "$@"; }
now() { "${PY[@]}" -c 'import time;print(round(time.time(),3))'; }

mount -t tmpfs tmpfs /run || die "tmpfs /run"
# --- программы «роутера»: апплеты BusyBox стока, uci/nginx/uhttpd/openssl стока (qemu), ip и iptables хоста (как в этапе 5)
SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv ln rm mkdir chmod readlink sed awk grep head tail wc tr cut sort cmp df uname date sleep kill sync basename dirname unxz xzcat zcat gzip mktemp touch printf echo test expr id ls md5sum cksum pwd; do
  # только апплеты, которые действительно есть в образе 1.1.38: недостающий — ошибка «not found» в сценарии, как на роутере
  if [ -e "$F/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/usr/sbin/$a" ]; then
  printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
  else echo "$a" >>"$OUT/stock-missing-applets.txt"; fi
done
for p in sbin/uci usr/bin/openssl usr/sbin/uhttpd; do printf '#!/bin/sh\nexec %s -L %s %s/%s "$@"\n' "$Q" "$F" "$F" "$p" >"$SB/$(basename "$p")"; done
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
NFBIN="$W/nfbin"; mkdir -p "$NFBIN"; IPTD="$ROOT/.tools/lab/iptables/root"; L="$IPTD/usr/lib/x86_64-linux-gnu"
for t in iptables iptables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s/xtables\nexec %s %s "$@"\n' "$L" "$L" "$IPTD/usr/sbin/xtables-legacy-multi" "$t" >"$NFBIN/$t"; done
for t in ip6tables ip6tables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s/xtables\nexec %s %s "$@"\n' "$L" "$L" "$IPTD/usr/sbin/xtables-nft-multi" "$t" >"$NFBIN/$t"; done
ln -sf "$(command -v ip)" "$NFBIN/ip"
chmod +x "$SB"/* "$NFBIN"/*
LB="$W/labbin"; mkdir -p "$LB"
for n in mi-tt-ctl mi-tt-admin; do printf '#!/bin/sh\nexec %s "$0.arm64" "$@"\n' "$Q" >"$LB/$n"; done
printf '#!/bin/sh\nexec %s "$@"\n' "$MIHOMO" >"$LB/mihomo"
for n in dnscrypt-proxy nfqws2; do printf '#!/bin/sh\nexec %s "$0.arm64" "$@"\n' "$Q" >"$LB/$n"; done
chmod +x "$LB"/*
RR="$W/root"; mkdir -p "$RR/data" "$RR/tmp" "$RR/etc/config" "$RR/usr/share/xiaoqiang"
cp "$F/usr/share/xiaoqiang/xiaoqiang_version" "$RR/usr/share/xiaoqiang/"; cp "$F/etc/config/firewall" "$F/etc/config/network" "$RR/etc/config/"
# адрес LAN в uci network — по нему панель строит допустимые Origin
sed -i "s/option ipaddr '192.168.31.1'/option ipaddr '10.10.1.1'/" "$RR/etc/config/network"
ENVR=(PATH="$SB:$NFBIN" MITT_ROOT="$RR" MITT_LAB_BIN="$LB" MITT_UCI_CONF="$RR/etc/config" MITT_INTERVAL=2 MITT_LEASES="$RR/tmp/dhcp.leases"
  MITT_DNSMASQ_RESTART=true MI_TT_IPTABLES="$NFBIN/iptables" MI_TT_IP6TABLES="$NFBIN/ip6tables" MI_TT_IPTABLES_SAVE="$NFBIN/iptables-save")
bb() { env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$@"; }

# --- топология (как в лаборатории Hysteria2) ---
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
ip -n inet addr add 10.99.0.10/32 dev lo; ip -n inet route add 10.10.1.0/24 via 10.20.0.2
ip -n vpn addr add 10.30.0.2/30 dev v-i; ip -n vpn link set v-i up; ip -n vpn route add default via 10.30.0.1
for n in router inet; do nsx "$n" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; done
nsx inet "${PY[@]}" "$ROOT/tools/lab/sniff.py" i-r "$OUT/sniff-wan.jsonl" &
nsx inet "${PY[@]}" "$ROOT/tools/lab/echo.py" serve 10.99.0.10 7007 "$OUT/echo.jsonl" echo &
HYPASS="$("${PY[@]}" -c 'import secrets;print(secrets.token_urlsafe(18))')"
# эфемерный ключ и сертификат TLS этого прогона (в $W, удаляется с ним); отпечаток привязывается к профилям динамически
TLSFP="$("$ROOT/tools/lab/ephemeral-tls.sh" "$W/tls")" || die "эфемерный TLS"
printf 'listen: 10.30.0.2:443\ntls:\n  cert: %s\n  key: %s\nauth:\n  type: password\n  password: "%s"\n' "$W/tls/cert.pem" "$W/tls/key.pem" "$HYPASS" >"$W/hy.yaml"
nsx vpn "$HYBIN" server -c "$W/hy.yaml" >>"$OUT/hysteria.log" 2>&1 &

# --- установка пакета (штатный BusyBox, без запуска) и настройки владельца ---
bb "$PKG/install.sh" install --no-start >"$OUT/install.out" 2>&1 || { cat "$OUT/install.out"; die "установка"; }
E="$RR/data/mi-trusttunnel/etc"
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]));[p["endpoint"].pop("obfs",None) for p in d["profiles"] if p["id"]=="hy2-lab"]
d["rules"]=[{"id":"r-tv-video","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"video"},"action":{"type":"profile","id":"hy2-lab"}}]
d["networks"]=[n for n in d["networks"] if n["id"]=="home"]; d["networks"][0]["ports"]=["r-tv","r-ph"]
d["devices"]=[x for x in d["devices"] if x["network"]=="home"]
json.dump(d,open(sys.argv[2],"w"),ensure_ascii=False,indent=2)' "$ROOT/fixtures/lab/config.hy2.json" "$E/config.json"
"${PY[@]}" "$ROOT/tools/lab/pin-config.py" "$E/config.json" "$TLSFP" >/dev/null || die "привязка отпечатка"
printf '{"version":1,"profiles":{"hy2-lab":{"password":"%s"}}}\n' "$HYPASS" >"$E/secrets.json"
for c in tv:10.10.1.2 phone:10.10.1.3; do nsx "${c%%:*}" ping -c1 -W1 10.10.1.1 >/dev/null; done
ip -n router -4 neigh show | awk '{for(i=2;i<NF;i++) if($i=="lladdr") print 1999999999, $(i+1), $1, "lab", "*"}' >"$RR/tmp/dhcp.leases"
# вход в панель: пароль и TOTP (секреты — только в этом прогоне)
PW="$("${PY[@]}" -c 'import secrets;print(secrets.token_urlsafe(18))')"
ADM="$W/admin.arm64"; "$Q" -L "$F" "$F/bin/busybox" unxz -c "$PKG/payload/bin/mi-tt-admin.xz" >"$ADM"; chmod +x "$ADM"
printf '%s\n%s\n' "$PW" "$PW" | env -i MI_TT_AUTH_DIR="$E/auth" MI_TT_SESSION_DIR="$RR/tmp/mi-trusttunnel/sessions" "$Q" "$ADM" auth init --stdin >"$W/auth.json" || die "auth init"
export TOTP_SECRET; TOTP_SECRET="$("${PY[@]}" -c 'import json,sys;print(json.load(open(sys.argv[1]))["totp_secret_base32"])' "$W/auth.json")"
totp() { "${PY[@]}" -c 'import base64,hashlib,hmac,os,struct,sys,time
s=os.environ["TOTP_SECRET"];k=base64.b32decode(s+"="*(-len(s)%8));c=struct.pack(">Q",int((time.time()+int(sys.argv[1]))//30))
h=hmac.new(k,c,hashlib.sha1).digest();o=h[-1]&15;print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "${1:-0}"; }
totp 0 | env -i MI_TT_AUTH_DIR="$E/auth" MI_TT_SESSION_DIR="$RR/tmp/mi-trusttunnel/sessions" "$Q" "$ADM" auth confirm --stdin >/dev/null || die "auth confirm"

: >"$OUT/probes.jsonl"; : >"$OUT/phases.jsonl"
probe() { local id="$1" ns="$2" t0 out rc; t0="$(now)"; out="$(nsx "$ns" "${PY[@]}" "$ROOT/tools/lab/echo.py" probe tcp 10.99.0.10 7007 "$id" 2>&1)"; rc=$?
  "${PY[@]}" -c 'import json,sys
a=sys.argv
try: r=json.loads(a[5])
except Exception: r={"raw":a[5]}
print(json.dumps({"probe":a[1],"ns":a[2],"rc":int(a[3]),"t0":float(a[4]),"reply":r}))' "$id" "$ns" "$rc" "$t0" "$out" >>"$OUT/probes.jsonl"; log "проба $id ($ns): rc=$rc $out"; }
phase() { printf '{"phase":"%s","t":%s}\n' "$1" "$(now)" >>"$OUT/phases.jsonl"; log "== фаза $1"; }
snapz() { { nsx router ip rule show | awk -F: '$1>=3000 && $1<=3199'; nsx router "$NFBIN/iptables" -w -S FORWARD | grep MITT; nsx router "$NFBIN/iptables" -w -S MITT_FWD 2>/dev/null; } >"$OUT/zone.$1.txt"; }
# WAN поднялся: на роутере netifd/DHCP возвращает маршрут по умолчанию (ядро сняло его при link down)
wan_on() { ip -n router link set r-wan up; ip -n router route replace default via 10.20.0.1; }
wait_tunnel() { for i in $(seq 40); do nsx tv "${PY[@]}" "$ROOT/tools/lab/echo.py" probe tcp 10.99.0.10 7007 "wait" 2>/dev/null | grep -q 10.30.0.2 && return 0; sleep 1; done; return 1; }
RN="$RR/tmp/mi-trusttunnel/run"
cp_status() { cp "$RN/status.json" "$OUT/status.$1.json" 2>/dev/null; cp "$RN/last-apply.json" "$OUT/last-apply.$1.json" 2>/dev/null; }

# 1) холодный старт без WAN (как fw3 при загрузке): защита сразу, панель локально
phase cold_boot_no_wan
ip -n router link set r-wan down
T0="$(now)"; nsx router env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$RR/data/mi-trusttunnel/mitt-boot.sh" >"$OUT/boot1.out" 2>&1; echo "exit=$?" >>"$OUT/boot1.out"
T1="$(now)"; snapz boot-guard; cp_status boot; cp "$RR/tmp/mi-trusttunnel/log/mitt.log" "$OUT/mitt.boot1.log" 2>/dev/null; cp "$RN/apply.boot-guard.json" "$RN/render.json" "$OUT/" 2>/dev/null
printf '{"boot_seconds":%s}\n' "$("${PY[@]}" -c "print(round($T1-$T0,1))")" >"$OUT/boot-time.json"
probe B-tv-no-wan tv; probe B-phone-no-wan phone
# служебный вход оператора по SSH: mitt-boot.sh auth status — каталоги пакета без ручных переменных
nsx router env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$RR/data/mi-trusttunnel/mitt-boot.sh" auth status >"$OUT/auth-status.json" 2>&1
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
nsx tv curl -sk -m 10 -D - -o /dev/null https://10.10.1.1:8443/ | tr -d '\r' >"$OUT/panel-headers.txt"

# 2) WAN появился: служба сама подключает туннель
phase wan_up
wan_on
if wait_tunnel; then echo '{"tunnel":true}' >"$OUT/wan-up.json"; else echo '{"tunnel":false}' >"$OUT/wan-up.json"; fi
probe W-tv tv; probe W-phone phone; cp_status wan; snapz full

# 3) перезагрузка firewall: fw3 снимает цепочки — include вызывает mitt-boot.sh, правила восстанавливаются
phase fw_reload
nsx router "$NFBIN/iptables" -w -D FORWARD -m comment --comment mi-trusttunnel -j MITT_FWD; nsx router "$NFBIN/iptables" -w -F MITT_FWD; nsx router "$NFBIN/iptables" -w -X MITT_FWD
snapz flushed
nsx router env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$RR/data/mi-trusttunnel/mitt-boot.sh" >"$OUT/boot-reload.out" 2>&1
snapz restored; cp_status fw
probe F-tv tv

# 4) смена аренды: ТВ получил новый адрес; служба замечает изменение файла аренд и применяет политику заново
phase lease_change
nsx tv ip addr del 10.10.1.2/24 dev eth0; nsx tv ip addr add 10.10.1.50/24 dev eth0; nsx tv ip route add default via 10.10.1.1
nsx tv ping -c1 -W1 10.10.1.1 >/dev/null
"${PY[@]}" -c 'import sys;p=sys.argv[1];t=open(p).read().replace(" 10.10.1.2 "," 10.10.1.50 ");open(p,"w").write(t)' "$RR/tmp/dhcp.leases"
for i in $(seq 30); do grep -q '"lease-change' "$RN/last-apply.json" 2>/dev/null && break; sleep 1; done
wait_tunnel; probe L-tv-new-ip tv; cp_status lease

# 5) падение движка: служба перезапускает Mihomo и применяет политику; в это время прямых пакетов нет
phase engine_crash
kill -9 "$(cat "$RN/mihomo.pid")"; sleep 0.5; probe E-tv-down tv
for i in $(seq 30); do grep -q '"mihomo-restart' "$RN/last-apply.json" 2>/dev/null && break; sleep 1; done
wait_tunnel; probe E-tv-restored tv; cp_status crash

# 6) заявка на применение из панели (сессия 2FA) — служба выполняет
phase panel_apply
cu -X POST -H 'Content-Type: application/json' -H 'Origin: https://10.10.1.1:8443' -H 'Sec-Fetch-Site: same-origin' -H "X-MITT-CSRF: $CSRF" -d '{}' -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/apply-request >"$OUT/panel-apply.out"; tail -1 "$OUT/panel-apply.out" >"$OUT/panel-apply.code"
for i in $(seq 30); do grep -q '"panel-request' "$RN/last-apply.json" 2>/dev/null && break; sleep 1; done
cu -w '\n%{http_code}' https://10.10.1.1:8443/cgi-bin/api/status >"$OUT/panel-status.out"; cp_status panel

# 7) «перезагрузка роутера»: RAM очищена, правила ядра сняты; снова холодный старт без WAN
phase reboot
nsx router env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$RR/data/mi-trusttunnel/mitt-boot.sh" stop >"$OUT/stop.out" 2>&1
pkill -f "$MIHOMO" 2>/dev/null; pkill -f "usr/sbin/nginx" 2>/dev/null; pkill -f "usr/sbin/uhttpd" 2>/dev/null; sleep 1
rm -rf "$RR/tmp/mi-trusttunnel"; ip -n router link set r-wan down
snapz after-reboot
nsx router env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$RR/data/mi-trusttunnel/mitt-boot.sh" >"$OUT/boot2.out" 2>&1; echo "exit=$?" >>"$OUT/boot2.out"
snapz boot2; probe R-tv-no-wan tv
wan_on; wait_tunnel; probe R-tv-wan tv; cp_status reboot
phase end
nsx router env -i "${ENVR[@]}" "$Q" -L "$F" "$F/bin/busybox" ash "$RR/data/mi-trusttunnel/mitt-boot.sh" stop >>"$OUT/stop.out" 2>&1
pkill -f "$MIHOMO" 2>/dev/null; pkill -f "usr/sbin/nginx" 2>/dev/null; pkill -f "usr/sbin/uhttpd" 2>/dev/null
cp "$RR/tmp/mi-trusttunnel/log/mitt.log" "$OUT/mitt.log" 2>/dev/null
MITT_TLSKEY="$W/tls/key.pem" MITT_PW="$PW" MITT_HY="$HYPASS" "${PY[@]}" -c 'import json,os,sys
from pathlib import Path
out=Path(sys.argv[1]);sec={"panel_password":os.environ["MITT_PW"],"totp":os.environ["TOTP_SECRET"],"hy2":os.environ["MITT_HY"]}
sec["tls_key"]=[l for l in open(os.environ["MITT_TLSKEY"]).read().splitlines() if l and not l.startswith("-----")][0]  # эфемерный ключ TLS прогона
found=sorted({f"{k}:{f.relative_to(out)}" for f in out.rglob("*") if f.is_file() for k,v in sec.items() if v.encode() in f.read_bytes()})
json.dump({"found":found},open(out/"secret-leak.json","w"))' "$OUT"
log "готово"
