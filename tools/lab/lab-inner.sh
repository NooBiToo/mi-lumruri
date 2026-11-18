#!/usr/bin/env bash
# Выполняется ВНУТРИ одноразовых user+net+mount+pid namespace (см. run-lab.sh). Сеть хоста не видна и не меняется.
#
#   tv     10.10.1.2 fd00:10::2 (02:..:0a:02) ─┬─ br-lan   10.10.1.1 fd00:10::1   [router: Mihomo TUN mitt0,
#   phone  10.10.1.3 fd00:10::3 (02:..:0b:02) ─┘                                    управление :9090]
#   laptop 10.10.2.2 fd00:11::2 (02:..:0c:02) ─── br-guest 10.10.2.1 fd00:11::1     10.20.0.2 ── [inet] ── [vpn: trusttunnel]
#   цели в inet: 10.99.0.10:8080 (группа), 10.98.0.10:8080 (вне группы), [fd00:99::10]:8080 (IPv6)
#
# Этап 4: защита привязана к наблюдаемому на входе источнику — MAC телевизора на входе br-lan (политика устройства)
# и порт r-gst моста br-guest (политика гостевой сети). Проверяется смена DHCP-адреса и новый IPv6 без повторного apply.
set -uo pipefail
: "${ROOT:?}" "${W:?}" "${OUT:?}" "${CTL:?}" "${ADMIN:?}" "${MIHOMO:?}" "${TTBIN:?}"
export PATH="/usr/sbin:/sbin:$PATH"
RUNCTL=(${RUNCTL:-})
ORIGIN="https://127.0.0.1:8787"
log() { printf '[lab] %s\n' "$*" | tee -a "$OUT/lab.log"; }
die() { log "ОШИБКА: $*"; exit 1; }
nsx() { local n="$1"; shift; nsenter --net="/run/netns/$n" -- "$@"; }
PY=(python3 -I -X utf8)
MARKER="${MARKER:-tc}"
FWROOT=/tmp/mitt-fw/rootfs
if [ "$MARKER" = netfilter ]; then
  # x86 iptables для netfilter лаборатории: ARM64 iptables прошивки под qemu-user не может говорить с netfilter
  # (qemu не транслирует IPT_SO_*). IPv4 — legacy (как на стоке), IPv6 — nft-совместимый: модуль ip6_tables ядра WSL
  # из user namespace не загружается, а nf_tables + xt_compat подгружает само ядро.
  NFBIN="$W/nfbin"; mkdir -p "$NFBIN"; IPTD="$ROOT/.tools/lab/iptables/root"; L="$IPTD/usr/lib/x86_64-linux-gnu"
  for t in iptables iptables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s/xtables\nexec %s %s "$@"\n' "$L" "$L" "$IPTD/usr/sbin/xtables-legacy-multi" "$t" >"$NFBIN/$t"; done
  for t in ip6tables ip6tables-save; do printf '#!/bin/sh\nexport LD_LIBRARY_PATH=%s XTABLES_LIBDIR=%s/xtables\nexec %s %s "$@"\n' "$L" "$L" "$IPTD/usr/sbin/xtables-nft-multi" "$t" >"$NFBIN/$t"; done
  chmod +x "$NFBIN"/*; export PATH="$NFBIN:$PATH"
fi

mount -t tmpfs tmpfs /run || die "tmpfs /run"
for n in router tv phone laptop inet vpn; do ip netns add "$n" || die "netns $n"; ip -n "$n" link set lo up; done
ip link add r-tv netns router type veth peer name eth0 netns tv
ip link add r-ph netns router type veth peer name eth0 netns phone
ip link add r-gst netns router type veth peer name eth0 netns laptop
ip link add r-wan netns router type veth peer name i-r netns inet
ip link add i-v netns inet type veth peer name v-i netns vpn
ip -n tv link set eth0 address 02:00:00:00:0a:02
ip -n phone link set eth0 address 02:00:00:00:0b:02
ip -n laptop link set eth0 address 02:00:00:00:0c:02
ip -n router link add br-lan type bridge; ip -n router link add br-guest type bridge
ip -n router link set r-tv master br-lan; ip -n router link set r-ph master br-lan; ip -n router link set r-gst master br-guest
ip -n router link add r-loose type dummy   # интерфейс вне мостов — для проверки отказа до применения
ip -n router link add r-kid type dummy; ip -n router link set r-kid master br-lan   # второй «SSID» на br-lan (часть моста)
for l in br-lan br-guest r-tv r-ph r-gst r-wan r-loose r-kid; do ip -n router link set "$l" up; done
ip -n router addr add 10.10.1.1/24 dev br-lan; ip -n router addr add fd00:10::1/64 dev br-lan nodad
ip -n router addr add 10.10.2.1/24 dev br-guest; ip -n router addr add fd00:11::1/64 dev br-guest nodad
ip -n router addr add 10.20.0.2/30 dev r-wan; ip -n router addr add fd00:20::2/64 dev r-wan nodad
ip -n router route add default via 10.20.0.1; ip -n router -6 route add default via fd00:20::1
client() { # client <ns> <v4/len> <v6/len> <gw4> <gw6>
  ip -n "$1" addr add "$2" dev eth0; ip -n "$1" addr add "$3" dev eth0 nodad; ip -n "$1" link set eth0 up
  ip -n "$1" route add default via "$4"; ip -n "$1" -6 route add default via "$5"
}
client tv 10.10.1.2/24 fd00:10::2/64 10.10.1.1 fd00:10::1
client phone 10.10.1.3/24 fd00:10::3/64 10.10.1.1 fd00:10::1
client laptop 10.10.2.2/24 fd00:11::2/64 10.10.2.1 fd00:11::1
ip -n inet addr add 10.20.0.1/30 dev i-r; ip -n inet addr add fd00:20::1/64 dev i-r nodad; ip -n inet addr add 10.30.0.1/30 dev i-v
ip -n inet link set i-r up; ip -n inet link set i-v up
ip -n inet addr add 10.99.0.10/32 dev lo; ip -n inet addr add 10.98.0.10/32 dev lo; ip -n inet addr add fd00:99::10/128 dev lo
for s in 10.10.1.0/24 10.10.2.0/24 10.10.9.0/24; do ip -n inet route add "$s" via 10.20.0.2; done   # без NAT
for s in fd00:10::/64 fd00:11::/64; do ip -n inet -6 route add "$s" via fd00:20::2; done
ip -n vpn addr add 10.30.0.2/30 dev v-i; ip -n vpn link set v-i up; ip -n vpn route add default via 10.30.0.1
for n in router inet; do nsx "$n" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward; echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'; done
log "топология поднята: br-lan (ТВ, телефон), br-guest (ноутбук), IPv4 + IPv6"

# --- чужие правила, маршруты и tc роутера, которые mi-tt-admin не должен трогать ---
ip -n router route add 10.77.0.0/24 via 10.20.0.1 table 200
ip -n router rule add from 10.10.1.3 to 10.77.0.0/24 lookup 200 priority 2000
ip -n router rule add fwmark 0x77/0xff lookup 201 priority 5000          # чужая метка в младших битах — не пересекается
ip -n router route add 10.66.0.0/24 via 10.20.0.1
ip -n router -6 route add fd00:66::/64 via fd00:20::1
ip -n router -6 rule add from fd00:10::3 lookup 202 priority 2500
tc -n router qdisc add dev br-lan clsact                                   # чужой хук на мосту ТВ
tc -n router filter add dev br-lan ingress pref 2000 protocol all matchall action pass
if [ "$MARKER" = netfilter ]; then   # чужие правила firewall
  nsx router iptables -w -t filter -A FORWARD -i br-guest -o br-lan -j ACCEPT
  nsx router iptables -w -t mangle -A PREROUTING -i br-guest -j RETURN
  nsx router ip6tables -w -t filter -A FORWARD -i br-guest -o br-lan -j ACCEPT
fi
nfs() { [ "$MARKER" = netfilter ] || return 0; for t in iptables ip6tables; do for tb in filter mangle; do nsx router "$t" -w -t "$tb" -S 2>/dev/null | sed "s/^/$t $tb: /"; done; done; }
zone() { { nsx router ip rule show; nsx router ip -6 rule show; } | awk -F: '$1>=3000 && $1<=3199'; nsx router ip route show table 3100 2>/dev/null
         for d in br-lan br-guest r-gst r-tv r-ph; do tc -n router filter show dev "$d" ingress 2>/dev/null | grep -E 'pref 1[0-3][0-9]{2} ' | grep handle | sed "s/^/$d: /"; done
         tc -n router qdisc show dev r-gst | grep clsact | sed 's/^/r-gst: /'; nfs | grep MITT; }
foreign_tc() { tc -n router qdisc show dev br-lan | grep -E 'clsact|ingress'; tc -n router filter show dev br-lan ingress | grep -E '^filter' | grep -v -E 'pref 1[0-3][0-9]{2} '; }
foreign_rules() { { nsx router ip rule show; echo ---; nsx router ip -6 rule show; } | awk -F: '!($1>=3000 && $1<=3199)'; }
routing_all() { { nsx router ip route show table all; nsx router ip -6 route show table all; } | grep -v 'fe80::'; }
foreign_nf() { nfs | grep -v MITT; }
outside() { foreign_rules; routing_all | grep -v 'table 3100'; echo "## tc"; foreign_tc; echo "## nf"; foreign_nf; }
snap() { foreign_rules >"$OUT/snap/foreign-rules.$1.txt"; zone >"$OUT/snap/zone.$1.txt"; foreign_tc >"$OUT/snap/foreign-tc.$1.txt"; foreign_nf >"$OUT/snap/foreign-nf.$1.txt"; }
mkdir -p "$OUT/snap"

# --- сервисы ---
nsx inet "${PY[@]}" "$ROOT/tools/lab/target.py" 8080 "$OUT/target.log" 0.0.0.0 target &
nsx inet "${PY[@]}" "$ROOT/tools/lab/target.py" 8080 "$OUT/target6.log" :: target6 &
nsx router "${PY[@]}" "$ROOT/tools/lab/target.py" 9090 "$OUT/mgmt.log" 0.0.0.0 mgmt &
nsx router "${PY[@]}" "$ROOT/tools/lab/target.py" 9090 "$OUT/mgmt6.log" :: mgmt6 &
PASS="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
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
# эфемерный ключ и сертификат TLS этого прогона (в $W, удаляется с ним); отпечаток привязывается к профилям динамически
TLSFP="$("$ROOT/tools/lab/ephemeral-tls.sh" "$W/tls")" || die "эфемерный TLS"
cat >"$W/tt/hosts.toml" <<EOF
[[main_hosts]]
hostname = "vpn.lab.test"
cert_chain_path = "$W/tls/cert.pem"
private_key_path = "$W/tls/key.pem"
EOF
cat >"$W/tt/credentials.toml" <<EOF
[[client]]
username = "tv-user"
password = "$PASS"
EOF
start_tt() { nsx vpn "$TTBIN" "$W/tt/vpn.toml" "$W/tt/hosts.toml" --loglvl debug >>"$OUT/trusttunnel.log" 2>&1 & TT_PID=$!; }
start_tt
for i in $(seq 50); do nsx vpn sh -c 'cat /proc/net/tcp' | grep -q ':01BB 00000000:0000 0A' && break; sleep 0.1; done
sleep 0.5
for c in tv:10.10.1.1:fd00:10::1 phone:10.10.1.1:fd00:10::1 laptop:10.10.2.1:fd00:11::1; do
  IFS=: read -r n g4 rest <<<"$c"; nsx "$n" ping -c1 -W1 "$g4" >/dev/null; nsx "$n" ping -6 -c1 -W1 "${c#*:*:}" >/dev/null
done
log "цели, управление роутера и trusttunnel_endpoint (pid $TT_PID) запущены"
sleep 1; snap 00-initial; routing_all >"$OUT/snap/routing.00-initial.txt"

probe() { # probe <id> <ns> <url> [curl-args...]
  local id="$1" ns="$2" url="$3"; shift 3
  local body code rc
  body="$(nsx "$ns" curl -sS -m 6 -H "X-Probe: $id" "$@" -o - -w '\n%{http_code}' "$url" 2>"$W/curl.err")"; rc=$?
  code="$(printf '%s' "$body" | tail -1)"; body="$(printf '%s' "$body" | head -n -1)"
  "${PY[@]}" -c 'import json,sys;print(json.dumps({"probe":sys.argv[1],"client_ns":sys.argv[2],"url":sys.argv[3],"curl_exit":int(sys.argv[4]),"http":sys.argv[5],"body":sys.argv[6],"error":open(sys.argv[7]).read().strip()}))' \
    "$id" "$ns" "$url" "$rc" "$code" "$body" "$W/curl.err" >>"$OUT/probes.jsonl"
  log "проба $id ($ns → $url $*): curl=$rc http=$code $body"
}
GROUP=http://10.99.0.10:8080/; OUTSIDE=http://10.98.0.10:8080/; V6=http://[fd00:99::10]:8080/
MGMT=http://10.10.1.1:9090/; MGMT6=http://[fd00:10::1]:9090/; GMGMT=http://10.10.2.1:9090/

probe B1-tv-group tv "$GROUP"
probe B2-tv-v6 tv "$V6"
probe B3-laptop-group laptop "$GROUP"
probe B4-laptop-v6 laptop "$V6"

# --- контроллер (ARM64 под qemu-user): сохранение двух правил через CGI, как это делает панель ---
CFG="$W/state/config.json"; mkdir -p "$W/state"; chmod 700 "$W/state"
# Этап 6: CGI как за uhttpd с TLS (HTTPS=on); каталоги входа — в рабочем каталоге лаборатории.
AUTHD="$W/auth"; SESSD="$W/sessions"
AUTHENV=(MI_TT_AUTH_DIR="$AUTHD" MI_TT_SESSION_DIR="$SESSD" HTTPS=on MI_TT_ALLOWED_ORIGINS="$ORIGIN")
SESSENV=()
cgi() { # cgi <METHOD> <PATH> <body-file|-> [extra env...]
  local m="$1" p="$2" b="$3"; shift 3
  if [ "$b" = "-" ]; then
    env -i MI_TT_CONFIG="$CFG" REQUEST_METHOD="$m" PATH_INFO="$p" "${AUTHENV[@]}" "${SESSENV[@]}" "$@" "${RUNCTL[@]}" "$CTL" cgi </dev/null
  else
    env -i MI_TT_CONFIG="$CFG" REQUEST_METHOD="$m" PATH_INFO="$p" CONTENT_TYPE=application/json CONTENT_LENGTH="$(wc -c <"$b")" "${AUTHENV[@]}" "${SESSENV[@]}" "$@" "${RUNCTL[@]}" "$CTL" cgi <"$b"
  fi
}
body_of() { sed '1,/^\r$/d'; }
status_of() { head -1 | cut -d' ' -f2; }
jget() { "${PY[@]}" -c 'import json,sys;d=json.load(sys.stdin)
for k in sys.argv[1].split("."): d=d[k] if not k.isdigit() else d[int(k)]
print(d)' "$1"; }
# TOTP (RFC 6238) третьей, независимой реализацией (Python hmac); секрет — из окружения, не из argv
totp() { "${PY[@]}" -c 'import base64,hashlib,hmac,os,struct,sys,time
s=os.environ["TOTP_SECRET"];k=base64.b32decode(s+"="*(-len(s)%8));c=struct.pack(">Q",int((time.time()+int(sys.argv[1]))//30))
h=hmac.new(k,c,hashlib.sha1).digest();o=h[-1]&15;print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "${1:-0}"; }
ms() { "${PY[@]}" -c 'import time;print(int(time.monotonic()*1000))'; }

# --- вход в панель (ARM64 под qemu-user): настройка mi-tt-admin auth, затем пароль и TOTP через CGI ---
PW="$("${PY[@]}" -c 'import secrets;print(secrets.token_urlsafe(18))')"
adm_auth() { env -i PATH="$PATH" "${AUTHENV[@]}" "${RUNCTL[@]}" "$ADMIN" auth "$@"; }
t0=$(ms); printf '%s\n%s\n' "$PW" "$PW" | adm_auth init --stdin >"$W/auth-init.json" || { cat "$W/auth-init.json"; die "auth init"; }; t1=$(ms)
export TOTP_SECRET; TOTP_SECRET="$(jget totp_secret_base32 <"$W/auth-init.json")"
RC1="$(jget recovery_codes.0 <"$W/auth-init.json")"
cgi GET /config - >"$W/a-unconfirmed.out"
totp 0 | adm_auth confirm --stdin >"$W/auth-confirm.json" || { cat "$W/auth-confirm.json"; die "auth confirm"; }
adm_auth status >"$OUT/auth-status.json"
cgi GET /config - >"$W/a-noauth.out"
printf '{"password":"%s"}' "$PW" >"$W/login.json"; chmod 600 "$W/login.json"
login1() { cgi POST /auth/login "$W/login.json" HTTP_ORIGIN="$ORIGIN" HTTP_SEC_FETCH_SITE=same-origin; }
t2=$(ms); login1 >"$W/a-login.out"; t3=$(ms)
PRE="$(grep -o '__Host-mitt_pre=[0-9a-f]*' "$W/a-login.out" | cut -d= -f2)"
cgi GET /config - HTTP_COOKIE="__Host-mitt_pre=$PRE" >"$W/a-pending-only.out"
cgi GET /config - HTTP_COOKIE="__Host-mitt_sess=$PRE" >"$W/a-pending-as-sess.out"
CODE="$(totp 30)"; printf '{"totp":"%s"}' "$CODE" >"$W/second.json"
cgi POST /auth/second "$W/second.json" HTTP_ORIGIN="$ORIGIN" HTTP_COOKIE="__Host-mitt_pre=$PRE" >"$W/a-second.out"
SESS="$(grep -o '__Host-mitt_sess=[0-9a-f]*' "$W/a-second.out" | cut -d= -f2)"
CSRF="$(body_of <"$W/a-second.out" | jget csrf)"
# повтор того же кода из новой предварительной сессии
login1 >"$W/a-login2.out"; PRE2="$(grep -o '__Host-mitt_pre=[0-9a-f]*' "$W/a-login2.out" | cut -d= -f2)"
cgi POST /auth/second "$W/second.json" HTTP_ORIGIN="$ORIGIN" HTTP_COOKIE="__Host-mitt_pre=$PRE2" >"$W/a-replay.out"
printf '{"recovery_code":"%s"}' "$RC1" >"$W/rc.json"
cgi POST /auth/second "$W/rc.json" HTTP_ORIGIN="$ORIGIN" HTTP_COOKIE="__Host-mitt_pre=$PRE2" >"$W/a-recovery.out"
login1 >"$W/a-login3.out"; PRE3="$(grep -o '__Host-mitt_pre=[0-9a-f]*' "$W/a-login3.out" | cut -d= -f2)"
cgi POST /auth/second "$W/rc.json" HTTP_ORIGIN="$ORIGIN" HTTP_COOKIE="__Host-mitt_pre=$PRE3" >"$W/a-recovery-again.out"
SESSENV=(HTTP_COOKIE="__Host-mitt_sess=$SESS" HTTP_X_MITT_CSRF="$CSRF")
cgi POST /preview "$ROOT/fixtures/request.tv-video-trusttunnel.json" HTTP_ORIGIN="$ORIGIN" HTTP_X_MITT_CSRF= >"$W/a-nocsrf.out"
st() { status_of <"$W/$1.out"; }
code() { body_of <"$W/$1.out" | "${PY[@]}" -c 'import json,sys;print((json.load(sys.stdin).get("error") or {}).get("code",""))'; }
"${PY[@]}" -c 'import json,sys;a=sys.argv[1:];print(json.dumps(dict(zip(a[::2],a[1::2])),ensure_ascii=False))' \
  init_ms $((t1-t0)) login_password_ms $((t3-t2)) \
  unconfirmed "$(st a-unconfirmed) $(code a-unconfirmed)" noauth "$(st a-noauth) $(code a-noauth)" \
  login "$(st a-login)" pending_only "$(st a-pending-only) $(code a-pending-only)" pending_as_sess "$(st a-pending-as-sess) $(code a-pending-as-sess)" \
  second "$(st a-second)" replay "$(st a-replay) $(code a-replay)" recovery "$(st a-recovery)" recovery_again "$(st a-recovery-again) $(code a-recovery-again)" \
  nocsrf "$(st a-nocsrf) $(code a-nocsrf)" \
  cookie_attrs "$(grep -o '__Host-mitt_sess=[0-9a-f]*;.*' "$W/a-second.out" | sed 's/=[0-9a-f]*;/=<токен>;/' | tr -d '\r')" \
  perm_auth_dir "$(stat -c %a "$AUTHD")" perm_auth_json "$(stat -c %a "$AUTHD/auth.json")" perm_session_dir "$(stat -c %a "$SESSD")" \
  >"$OUT/auth.json"
log "вход (ARM64): $(cat "$OUT/auth.json")"
save_rule() { # save_rule <json правила>
  local rev; rev="$(cgi GET /config - | body_of | "${PY[@]}" -c 'import json,sys;print(json.load(sys.stdin)["revision"])')"
  printf '{"base_revision":"%s","rule":%s}' "$rev" "$1" >"$W/save.json"
  cgi POST /rules "$W/save.json" MI_TT_ALLOWED_ORIGINS="$ORIGIN" HTTP_ORIGIN="$ORIGIN" HTTP_SEC_FETCH_SITE=same-origin >"$W/save.out"
  [ "$(status_of <"$W/save.out")" = 200 ] || { cat "$W/save.out"; die "сохранение не прошло"; }
}
if [ -n "${CONFIG_IN:-}" ]; then
  cp "$CONFIG_IN" "$CFG"; "${PY[@]}" "$ROOT/tools/lab/pin-config.py" "$CFG" "$TLSFP" >/dev/null || die "привязка отпечатка"
  log "настройки взяты из $CONFIG_IN (сохранены панелью), отпечаток — эфемерного сертификата"
else
  cp "$ROOT/fixtures/lab/config.json" "$CFG"; "${PY[@]}" "$ROOT/tools/lab/pin-config.py" "$CFG" "$TLSFP" >/dev/null || die "привязка отпечатка"
  save_rule '{"id":"r-tv-video","source":{"type":"device","id":"tv"},"destination":{"type":"group","id":"video"},"action":{"type":"profile","id":"tt-lab"}}'
  save_rule '{"id":"r-guest-video","source":{"type":"network","id":"guest"},"destination":{"type":"group","id":"video"},"action":{"type":"profile","id":"tt-lab"}}'
  log "сохранены правило устройства (ТВ) и правило гостевой сети через CGI"
fi
leases() { ip -n router -4 neigh show | awk '{for(i=2;i<NF;i++) if($i=="lladdr") print 1999999999, $(i+1), $1, "lab", "*"}' | grep -v -E ' 10\.20\.' >"$W/dhcp.leases"; }
leases; cp "$W/dhcp.leases" "$OUT/dhcp.leases"
printf '{"version":1,"profiles":{"tt-lab":{"password":"%s"}}}\n' "$PASS" >"$W/secrets.json"; chmod 600 "$W/secrets.json"
render() { "${RUNCTL[@]}" "$CTL" render "$CFG" "$W/secrets.json" "$W/dhcp.leases" "$W/mihomo" >"$OUT/render.json" || { cat "$OUT/render.json"; die "render"; }; }
render; cp "$CFG" "$OUT/config.saved.json"
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]));[p.__setitem__("password","<скрыт>") for p in d.get("proxies",[])];json.dump(d,open(sys.argv[2],"w"),indent=2,ensure_ascii=False)' "$W/mihomo/config.yaml" "$OUT/mihomo.config.redacted.json"
log "Mihomo: $("${PY[@]}" -c 'import json,sys;print(" | ".join(json.load(open(sys.argv[1]))["rules"]))' "$OUT/render.json")"

# --- mi-tt-admin ---
AST="$W/admin-state"
admin() { # admin <шаг> <команда> [аргументы...]; журнал вызовов → admin.jsonl (+ было ли изменение вне зоны)
  local step="$1" cmd="$2"; shift 2
  local cfg="$CFG" extra=()
  if [ "${ADMIN_CFG:-}" ]; then cfg="$ADMIN_CFG"; fi
  case "$cmd" in plan|apply) extra=(--config "$cfg" --secrets "$W/secrets.json" --leases "$W/dhcp.leases" --marker "$MARKER");; esac
  outside >"$W/outside.before"
  nsx router env ${ADMIN_ENV:-} "${RUNCTL[@]}" "$ADMIN" "$cmd" --state-dir "$AST" "${extra[@]}" "$@" >"$W/admin.out" 2>"$W/admin.err"
  local rc=$?
  outside >"$W/outside.after"
  local same=false; cmp -s "$W/outside.before" "$W/outside.after" && same=true
  "${PY[@]}" -c 'import json,sys
try: out=json.load(open(sys.argv[3],encoding="utf-8"))
except Exception: out={"raw":open(sys.argv[3],encoding="utf-8").read()}
print(json.dumps({"step":sys.argv[1],"cmd":sys.argv[2],"exit":int(sys.argv[4]),"outside_unchanged":sys.argv[5]=="true","out":out}))' "$step" "$cmd $*" "$W/admin.out" "$rc" "$same" >>"$OUT/admin.jsonl"
  log "admin $step ($cmd $*): exit=$rc $("${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1],encoding="utf-8"));e=d.get("error") or {};print(d.get("phase",""), e.get("code","") if isinstance(e,dict) else "", "noop" if d.get("noop") else "", d.get("protection",""))' "$W/admin.out" 2>/dev/null)"
  return $rc
}
env REQUEST_METHOD=POST GATEWAY_INTERFACE=CGI/1.1 "${RUNCTL[@]}" "$ADMIN" revert --state-dir "$AST" >"$W/cgi-admin.out"; echo "{\"exit\":$?}" >"$OUT/admin-under-cgi.json"

admin A0-plan plan; cp "$W/admin.out" "$OUT/admin-plan.json"

# --- возможности: нормальный, отсутствующий и конфликтный наборы (до любых изменений) ---
if [ "$MARKER" = netfilter ]; then
STOCK_ENV="MI_TT_KCONFIG=$ROOT/.tools/fw/kernel/config MI_TT_MODULES_DIR=$FWROOT/lib/modules/5.4.164 MI_TT_KERNEL_RELEASE=5.4.164"
admin N0-caps-lab caps; cp "$W/admin.out" "$OUT/caps.lab.json"
ADMIN_ENV="$STOCK_ENV" admin N1-caps-stock caps; cp "$W/admin.out" "$OUT/caps.stock.json"
sed 's/^CONFIG_NETFILTER_XT_MATCH_MAC=m/# CONFIG_NETFILTER_XT_MATCH_MAC is not set/' "$ROOT/.tools/fw/kernel/config" >"$W/kconfig.nomac"
ADMIN_ENV="MI_TT_KCONFIG=$W/kconfig.nomac MI_TT_MODULES_DIR=$FWROOT/lib/modules/5.4.164 MI_TT_KERNEL_RELEASE=5.4.164" admin N2-apply-stock-without-xt_mac apply --marker auto; snap 00b-nomac
ADMIN_ENV="$STOCK_ENV" admin N3-apply-tc-on-stock apply --marker tc
ADMIN_ENV="$STOCK_ENV" admin N4-plan-stock-auto plan --marker auto; cp "$W/admin.out" "$OUT/admin-plan.stock.json"
  # сеть на части моста (порт r-kid на br-lan) требует physdev + MARK; в ядре WSL ревизия 2 MARK недоступна → отказ без изменений
  "${PY[@]}" -c 'import json,sys
d=json.load(open(sys.argv[1]))
d["networks"].append({"id":"kids","name":"Дети (стенд)","ssid":"Lab-Kids","subnet":"10.10.3.0/24","bridge":"br-lan","ports":["r-kid"]})
d["rules"].append({"id":"r-kids-video","source":{"type":"network","id":"kids"},"destination":{"type":"group","id":"video"},"action":{"type":"profile","id":"tt-lab"},"enabled":True})
json.dump(d,open(sys.argv[2],"w"))' "$CFG" "$W/cfg-kids.json"
  ADMIN_CFG="$W/cfg-kids.json" admin N5-partial-bridge-without-mark apply; snap 00c-kids
fi

# 0) проверка интерфейсов до применения: несуществующий порт и порт не того моста — отказ, ничего не меняется
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]));d["networks"][1]["ports"]=["r-gst","r-nope"];json.dump(d,open(sys.argv[2],"w"))' "$CFG" "$W/cfg-badport.json"
"${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]));d["networks"][1]["ports"]=["r-gst","r-loose"];json.dump(d,open(sys.argv[2],"w"))' "$CFG" "$W/cfg-loose.json"
ADMIN_CFG="$W/cfg-badport.json" admin I1-missing-port apply; snap 00a-badport
ADMIN_CFG="$W/cfg-loose.json" admin I2-port-outside-bridge apply

# 1) старт без Mihomo: метки и запреты (как при загрузке до запуска движков)
admin A1-guard apply --guard-only; snap 01-guard
probe G1-tv-group tv "$GROUP"
probe G2-tv-mgmt tv "$MGMT"
probe G3-tv-mgmt6 tv "$MGMT6"
probe G4-tv-v6 tv "$V6"
probe G5-phone-group phone "$GROUP"
probe G6-phone-v6 phone "$V6"
probe G7-laptop-group laptop "$GROUP"
probe G8-laptop-mgmt laptop "$GMGMT"
probe G9-laptop-v6 laptop "$V6"

# 2) частичный отказ: с чистого состояния полный apply без TUN — шаг TUN падает, выполненные шаги откатываются
admin A2-revert-before-partial revert; snap 02-reverted
admin A3-partial-failure apply; snap 03-after-partial
admin A3s-status-after-partial status

# 3) блокировка параллельного изменения
admin A4-guard-again apply --guard-only
( "${PY[@]}" -c 'import fcntl,sys,time;f=open(sys.argv[1],"a");fcntl.flock(f,fcntl.LOCK_EX);open(sys.argv[2],"w").close();time.sleep(6)' "$AST/apply.lock" "$W/locked" ) &
LOCK_PID=$!; for i in $(seq 50); do [ -f "$W/locked" ] && break; sleep 0.1; done
admin A5-locked apply
wait "$LOCK_PID"

# 4) Mihomo и полное применение; повтор; сбой посреди apply
nsx router "$MIHOMO" -t -d "$W/mihomo" -f "$W/mihomo/config.yaml" >"$OUT/mihomo.test.log" 2>&1 || { cat "$OUT/mihomo.test.log"; die "mihomo -t"; }
start_mh() { nsx router "$MIHOMO" -d "$W/mihomo" -f "$W/mihomo/config.yaml" >>"$OUT/mihomo.log" 2>&1 & MH_PID=$!; for i in $(seq 100); do ip -n router link show mitt0 >/dev/null 2>&1 && break; sleep 0.1; done; }
snap 05-before-mihomo
start_mh; sleep 1; snap 05-mihomo-started
admin A6-apply apply; snap 06-applied
admin A7-repeat apply
if [ "$MARKER" = netfilter ] && [ -x "$FWROOT/bin/busybox" ]; then
  # preflight выполняет ARM64 BusyBox 1.25.1 прошивки (под qemu): каждый апплет и ip/tc/iptables прошивки — через обёртки
  Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"; FWB="$W/fwbin"; mkdir -p "$FWB"
  for a in $("$Q" -L "$FWROOT" "$FWROOT/bin/busybox" --list); do
    printf '#!/bin/sh\nexec %s -L %s -0 %s %s "$@"\n' "$Q" "$FWROOT" "$a" "$FWROOT/bin/busybox" >"$FWB/$a"
  done
  for a in ip tc; do printf '#!/bin/sh\nexec %s -L %s -0 %s %s "$@"\n' "$Q" "$FWROOT" "$a" "$FWROOT/usr/libexec/$a-full" >"$FWB/$a"; done
  for a in iptables ip6tables iptables-save ip6tables-save; do printf '#!/bin/sh\nexec %s -L %s -0 %s %s "$@"\n' "$Q" "$FWROOT" "$a" "$FWROOT/usr/sbin/xtables-multi" >"$FWB/$a"; done
  chmod +x "$FWB"/*
  outside >"$W/pf.before"; zone >"$W/pf.zone.before"
  # 1) полностью стоковое окружение пользователя (ARM64 BusyBox + ip/tc/iptables прошивки), /sys — свой для netns роутера
  nsx router unshare -m --propagation private sh -c "mount -t sysfs sysfs /sys; MITT_PREFLIGHT_KEEP_PATH=1 PATH=$FWB exec $Q -L $FWROOT $FWROOT/bin/busybox sh $ROOT/tools/device/preflight.sh" >"$OUT/preflight.stock-userland.txt" 2>"$OUT/preflight.stock-userland.err"
  echo "{\"exit\": $?}" >"$OUT/preflight.stock-userland.exit.json"
  # 2) та же оболочка и апплеты прошивки, но iptables лаборатории (чтобы видеть реальные правила в netns)
  nsx router unshare -m --propagation private sh -c "mount -t sysfs sysfs /sys; MITT_PREFLIGHT_KEEP_PATH=1 PATH=$NFBIN:$FWB exec $Q -L $FWROOT $FWROOT/bin/busybox sh $ROOT/tools/device/preflight.sh" >"$OUT/preflight.lab-iptables.txt" 2>"$OUT/preflight.lab-iptables.err"
  echo "{\"exit\": $?}" >"$OUT/preflight.lab-iptables.exit.json"
  "$Q" -L "$FWROOT" "$FWROOT/bin/busybox" sh -n "$ROOT/tools/device/preflight.sh"; echo "{\"exit\": $?}" >"$OUT/preflight.syntax.json"
  outside >"$W/pf.after"; zone >"$W/pf.zone.after"
  cmp -s "$W/pf.before" "$W/pf.after" && cmp -s "$W/pf.zone.before" "$W/pf.zone.after" && echo '{"unchanged": true}' >"$OUT/preflight.mutation.json" || echo '{"unchanged": false}' >"$OUT/preflight.mutation.json"
  log "preflight: $(grep -c . "$OUT/preflight.stock-userland.txt") строк (стоковая среда), $(grep '^verdict' "$OUT/preflight.lab-iptables.txt" | tr '\n' ' ')"
fi
"${PY[@]}" -c 'import json,sys
p=sys.argv[1]; s=json.load(open(p,encoding="utf-8"))
f=[e for e in s["owned"] if e.get("kind") in ("filter","ipt")][:1]
s["owned"]=[e for e in s["owned"] if e not in f]; s["pending"]=f; s["phase"]="pending"
json.dump(s,open(p,"w",encoding="utf-8"))' "$AST/applied.json"
admin A7c-status-after-crash status
admin A7d-apply-after-crash apply
{ echo "## ip rule"; ip -n router rule; echo "## ip -6 rule"; ip -n router -6 rule; echo "## table 3100"; ip -n router route show table 3100
  for d in br-lan r-gst; do echo "## tc $d"; tc -n router qdisc show dev "$d"; tc -n router filter show dev "$d" ingress; done; } >"$OUT/router-routing.txt"
sleep 1
probe P1-tv-group tv "$GROUP"
probe P2-tv-domain tv http://video.lab.test:8080/ --resolve video.lab.test:8080:10.98.0.10
probe P3-tv-outside tv "$OUTSIDE"
probe P4-phone-group phone "$GROUP"
probe P5-laptop-group laptop "$GROUP"
probe P6-laptop-outside laptop "$OUTSIDE"
probe P7-tv-mgmt tv "$MGMT"
probe P8-tv-mgmt6 tv "$MGMT6"
probe P9-tv-v6 tv "$V6"
probe P10-phone-v6 phone "$V6"
probe P11-laptop-v6 laptop "$V6"

# 5) смена адресов БЕЗ повторного apply: новые соединения
log "ТВ получает новый IPv4 10.10.1.50 (смена DHCP-аренды) и новый IPv6 fd00:10::99 (временный адрес)"
ip -n tv addr del 10.10.1.2/24 dev eth0; ip -n tv addr add 10.10.1.50/24 dev eth0; ip -n tv route add default via 10.10.1.1 2>/dev/null
ip -n tv addr add fd00:10::99/64 dev eth0 nodad
nsx tv ping -c1 -W1 10.10.1.1 >/dev/null; nsx tv ping -6 -c1 -W1 -I fd00:10::99 fd00:10::1 >/dev/null; echo "{\"ndp_ping_router_from_new_v6\": $?}" >"$OUT/ndp.json"
probe C1-tv-newip-group tv "$GROUP"
probe C2-tv-newip-outside tv "$OUTSIDE"
probe C3-tv-newip-mgmt tv "$MGMT"
probe C4-tv-newv6-external tv "$V6" --interface fd00:10::99
probe C5-tv-newv6-mgmt6 tv "$MGMT6" --interface fd00:10::99
log "ноутбук: новый IPv4 внутри гостевой подсети (10.10.2.77) и адрес вне её (10.10.9.9)"
ip -n laptop addr del 10.10.2.2/24 dev eth0; ip -n laptop addr add 10.10.2.77/24 dev eth0; ip -n laptop route add default via 10.10.2.1 2>/dev/null
ip -n laptop addr add 10.10.9.9/24 dev eth0
probe C6-laptop-newip-group laptop "$GROUP"
probe C7-laptop-outsidesubnet-group laptop "$GROUP" --interface 10.10.9.9
admin A8-status-addr-changed status
probe C8-phone-group-unaffected phone "$GROUP"
# новый адрес ТВ попадает в аренды → повторный apply возвращает туннель
ip -n router neigh del 10.10.1.2 dev br-lan 2>/dev/null   # как обновление файла аренд dnsmasq: старая аренда ушла
nsx tv ping -c1 -W1 10.10.1.1 >/dev/null; leases; cp "$W/dhcp.leases" "$OUT/dhcp.leases.after-change"; render
admin A9-apply-new-lease apply
# Mihomo ещё работает со старой конфигурацией (не знает 10.10.1.50): новый адрес уже допущен в TUN — должен быть отказ, не DIRECT
probe C9a-tv-newip-group-stale-mihomo tv "$GROUP"
log "перезапуск Mihomo с конфигурацией для новой аренды, затем apply (маршрут TUN пересоздаётся)"
kill "$MH_PID"; wait "$MH_PID" 2>/dev/null; start_mh
admin A9b-apply-after-mihomo-reload apply
sleep 1
probe C9-tv-newip-group-after-apply tv "$GROUP"

# 6) коллизии и чужие записи — отказ без изменений
ip -n router rule add from 10.10.1.99 lookup 300 priority 3150
admin K1-foreign-rule-in-zone apply; snap 07-k1
ip -n router rule del from 10.10.1.99 lookup 300 priority 3150
ip -n router rule add fwmark 0x10000/0xff0000 lookup 205 priority 2600
admin K2-foreign-mark-overlap apply
ip -n router rule del fwmark 0x10000/0xff0000 lookup 205 priority 2600
if [ "$MARKER" = tc ]; then
  tc -n router filter add dev br-lan ingress pref 1100 protocol all matchall action pass
  admin K3-foreign-tc-in-zone apply
  tc -n router filter del dev br-lan ingress pref 1100
  tc -n router filter add dev r-gst ingress pref 10 protocol all matchall action pass
  admin K4-foreign-tc-before-ours apply
  tc -n router filter del dev r-gst ingress pref 10
  printf '#!/bin/sh\necho "*mangle"\necho "-A PREROUTING -i br-lan -j MARK --set-xmark 0x20000/0xff0000"\necho COMMIT\n' >"$W/fake-iptables-save"; chmod +x "$W/fake-iptables-save"
  ADMIN_ENV="MI_TT_IPTABLES_SAVE=$W/fake-iptables-save" admin K5-firewall-mark-overlap apply
else
  nsx router iptables -w -t filter -A MITT_FWD -j ACCEPT          # чужое правило внутри нашей цепочки
  admin K3-foreign-rule-in-our-chain apply
  nsx router iptables -w -t filter -D MITT_FWD -j ACCEPT
  nsx router ip6tables -w -t filter -N MITT_OLD                   # неучтённая цепочка с нашим префиксом
  admin K4-untracked-mitt-chain apply
  nsx router ip6tables -w -t filter -X MITT_OLD
  nsx router iptables -w -t filter -I INPUT 1 -j MITT_FWD         # неучтённый переход в нашу цепочку
  admin K5-untracked-jump apply
  nsx router iptables -w -t filter -D INPUT -j MITT_FWD
fi
admin K6-clean-after-conflicts apply

# 7) дрейф и «перезагрузка»: ядро потеряло записи, журнал остался
if [ "$MARKER" = tc ]; then
  tc -n router filter del dev br-lan ingress pref 1001
  ip -n router rule del priority 3105 fwmark 0xa000000/0xf800000 unreachable
else
  nsx router iptables -w -t filter -D MITT_FWD ! -s 10.10.1.50/32 -i br-lan -m mac --mac-source 02:00:00:00:0a:02 -j REJECT --reject-with icmp-port-unreachable
  ip -n router rule del priority 3100 from 10.10.1.50 lookup 3100
fi
admin D1-status-drift status
probe D2-tv-group-during-drift tv "$GROUP"
admin D3-restore apply
probe D4-tv-group-restored tv "$GROUP"
log "имитация перезагрузки: все наши записи и tc сняты не через admin, Mihomo остановлен"
kill "$MH_PID"; wait "$MH_PID" 2>/dev/null
for p in $(ip -n router rule show | awk -F: '$1>=3000 && $1<=3199{print $1}' | sort -u); do while ip -n router rule del priority "$p" 2>/dev/null; do :; done; done
for p in $(ip -n router -6 rule show | awk -F: '$1>=3000 && $1<=3199{print $1}' | sort -u); do while ip -n router -6 rule del priority "$p" 2>/dev/null; do :; done; done
ip -n router route flush table 3100 2>/dev/null
tc -n router qdisc del dev r-gst clsact 2>/dev/null; tc -n router filter del dev br-lan ingress pref 1001 2>/dev/null
if [ "$MARKER" = netfilter ]; then
  for t in iptables ip6tables; do
    nsx router "$t" -w -t filter -D FORWARD -m comment --comment mi-trusttunnel -j MITT_FWD 2>/dev/null
    nsx router "$t" -w -t filter -F MITT_FWD 2>/dev/null; nsx router "$t" -w -t filter -X MITT_FWD 2>/dev/null
  done
fi
admin R1-status-after-reboot status
probe R2-tv-group-unprotected-before-boot-apply tv "$GROUP"
admin R3-boot-guard apply --guard-only
probe R4-tv-group-boot-guard tv "$GROUP"
probe R5-laptop-group-boot-guard laptop "$GROUP"
start_mh
admin R6-apply-after-engine apply
sleep 1
probe R7-tv-group-after-boot tv "$GROUP"

# 8) отказ туннеля и движка: защищённые потоки не уходят напрямую
log "остановка туннеля"
kill "$TT_PID"; wait "$TT_PID" 2>/dev/null; sleep 1
probe T1-tv-group-tunnel-down tv "$GROUP"
probe T2-laptop-group-tunnel-down laptop "$GROUP"
probe T3-phone-group-tunnel-down phone "$GROUP"
probe T4-tv-outside-tunnel-down tv "$OUTSIDE"
log "остановка Mihomo"
kill "$MH_PID"; wait "$MH_PID" 2>/dev/null; sleep 1
admin E1-status-engine-down status
probe E2-tv-group-engine-down tv "$GROUP"
probe E3-laptop-group-engine-down laptop "$GROUP"
probe E4-tv-mgmt-engine-down tv "$MGMT"
probe E5-phone-group-engine-down phone "$GROUP"
start_tt; sleep 1; start_mh
admin E6-reapply apply
sleep 1
probe E7-tv-group-restored tv "$GROUP"
probe E8-laptop-group-restored laptop "$GROUP"

# 9) явное снятие
admin X1-revert revert; snap 14-reverted
admin X2-status status
probe X3-tv-group-after-revert tv "$GROUP"
probe X4-tv-v6-after-revert tv "$V6"
probe X5-laptop-group-after-revert laptop "$GROUP"
snap 15-mihomo-running
kill "$MH_PID" 2>/dev/null; wait "$MH_PID" 2>/dev/null; sleep 0.5
snap 16-final
routing_all >"$OUT/snap/routing.16-final.txt"
cp "$AST/applied.json" "$OUT/admin-state.final.json" 2>/dev/null
log "готово"
# этап 6: секреты входа не должны попадать в артефакты и журналы
MITT_TLSKEY="$W/tls/key.pem" MITT_PW="$PW" "${PY[@]}" -c 'import json,os,sys
from pathlib import Path
out=Path(sys.argv[1]);init=json.load(open(sys.argv[2],encoding="utf-8"))
secrets={"password":os.environ["MITT_PW"],"totp_secret":os.environ["TOTP_SECRET"]}
secrets["tls_key"]=[l for l in open(os.environ["MITT_TLSKEY"]).read().splitlines() if l and not l.startswith("-----")][0]  # эфемерный ключ TLS прогона
for i,c in enumerate(init["recovery_codes"]): secrets[f"recovery_{i}"]=c; secrets[f"recovery_{i}_raw"]=c.replace("-","")
found=sorted({f"{k}:{f.relative_to(out)}" for f in out.rglob("*") if f.is_file() for k,v in secrets.items() if v.encode() in f.read_bytes()})
json.dump({"scanned":sum(1 for f in out.rglob("*") if f.is_file()),"found":found},open(out/"secret-leak.json","w"))' "$OUT" "$W/auth-init.json"
