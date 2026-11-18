#!/usr/bin/env bash
# Этап 10: шифрованный DNS роутера в одноразовых user+net+mount+pid namespace (см. run-lab-dns.sh).
#
#   tv 10.10.1.2, phone 10.10.1.3 ─ br-lan 10.10.1.1 [router: dnsmasq :53 → Mihomo DNS 127.0.0.1:1053 → (DoH|DoT|DoQ|DoH3)
#                                                      или dnscrypt-proxy 127.0.0.1:5300 → ODoH relay]   10.20.0.2 ── [inet]
#   [inet] ── doh    10.30.2.2  dnsproxy: DoH tcp/443, DoH3 udp/443, DoT tcp/853, DoQ udp/853 → «публичный» резолвер 1.1.1.1 (свой netns)
#          ── target 10.30.3.2  ODoH target (odoh-server-go) → 1.1.1.1 (свой netns)
#          ── relay  10.30.4.2  ODoH relay (odoh-server-go /proxy)
#   Сниффер в inet на линке роутера: любой DNS (порт 53) или пакет к target от роутера — утечка.
set -uo pipefail
: "${ROOT:?}" "${W:?}" "${OUT:?}" "${CTL:?}" "${MIHOMO:?}" "${DNSPROXY:?}" "${DNSCRYPT:?}" "${ODOH:?}" "${DNSMASQ:?}"
export PATH="/usr/sbin:/sbin:$PATH"
RUNCTL=(${RUNCTL:-})
PY=(python3 -I -X utf8)
log() { printf '[dns] %s\n' "$*" | tee -a "$OUT/lab.log"; }
die() { log "ОШИБКА: $*"; exit 1; }
nsx() { local n="$1"; shift; nsenter --net="/run/netns/$n" -- "$@"; }
now() { "${PY[@]}" -c 'import time;print(round(time.time(),3))'; }

mount -t tmpfs tmpfs /run || die "tmpfs /run"
# имена ODoH target для relay — только в этом mount namespace (как запись DNS у настоящего relay)
printf '127.0.0.1 localhost\n10.30.3.2 odoh-target.lab.test\n' >"$W/hosts"; mount --bind "$W/hosts" /etc/hosts || die "hosts"
for n in router tv phone inet doh target relay; do ip netns add "$n" || die "netns $n"; ip -n "$n" link set lo up; done
ip link add r-tv netns router type veth peer name eth0 netns tv
ip link add r-ph netns router type veth peer name eth0 netns phone
ip link add r-wan netns router type veth peer name i-r netns inet
ip -n router link add br-lan type bridge
ip -n router link set r-tv master br-lan; ip -n router link set r-ph master br-lan
for l in br-lan r-tv r-ph r-wan; do ip -n router link set "$l" up; done
ip -n router addr add 10.10.1.1/24 dev br-lan; ip -n router addr add 10.20.0.2/30 dev r-wan; ip -n router route add default via 10.20.0.1
for c in tv:10.10.1.2 phone:10.10.1.3; do ip -n "${c%%:*}" addr add "${c#*:}/24" dev eth0; ip -n "${c%%:*}" link set eth0 up; ip -n "${c%%:*}" route add default via 10.10.1.1; done
ip -n inet addr add 10.20.0.1/30 dev i-r; ip -n inet link set i-r up; ip -n inet route add 10.10.1.0/24 via 10.20.0.2
k=2; for n in doh target relay; do
  ip link add "i-$n" netns inet type veth peer name eth0 netns "$n"
  ip -n inet addr add "10.30.$k.1/24" dev "i-$n"; ip -n inet link set "i-$n" up
  ip -n "$n" addr add "10.30.$k.2/24" dev eth0; ip -n "$n" link set eth0 up; ip -n "$n" route add default via "10.30.$k.1"
  k=$((k+1)); done
for n in router inet; do nsx "$n" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'; done

# --- сертификаты: временный УЦ лаборатории; доверие к нему — только у процессов лаборатории (SSL_CERT_FILE) ---
C="$W/ca"; mkdir -p "$C"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=mitt-lab-ca -keyout "$C/ca.key" -out "$C/ca.pem" 2>/dev/null
leaf() { openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$C/$1.key" -out "$C/$1.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s\n' "$1" >"$C/$1.ext"
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -days 1 -extfile "$C/$1.ext" -out "$C/$1.pem" 2>/dev/null; }
for h in doh.lab.test odoh-target.lab.test odoh-relay.lab.test; do leaf "$h"; done
export SSL_CERT_FILE="$C/ca.pem"

# --- «интернет»: сниффер, «публичные» резолверы, серверы ---
nsx inet "${PY[@]}" "$ROOT/tools/lab/sniff.py" i-r "$OUT/sniff-wan.jsonl" & SN=$!
nsx inet "${PY[@]}" "$ROOT/tools/lab/sniff.py" i-target "$OUT/sniff-target.jsonl" & SN2=$!
# «публичные» резолверы: target odoh-server-go выбирает случайно из 1.1.1.1, 8.8.8.8, 9.9.9.9 (по TCP)
for n in doh target; do for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
  nsx "$n" ip addr add "$r/32" dev lo
  nsx "$n" "${PY[@]}" "$ROOT/tools/lab/dnsauth.py" "$r" 53 "$OUT/auth.jsonl" "auth-$n" &
done; done
start_dnsproxy() { nsx doh "$DNSPROXY" -l 10.30.2.2 -p 0 --https-port=443 --tls-port=853 --quic-port=853 --http3 \
    --tls-crt="$C/doh.lab.test.pem" --tls-key="$C/doh.lab.test.key" -u 1.1.1.1:53 -v >>"$OUT/dnsproxy.log" 2>&1 & DP_PID=$!; sleep 1; }
start_dnsproxy
nsx target env PORT=443 CERT="$C/odoh-target.lab.test.pem" KEY="$C/odoh-target.lab.test.key" TARGET_INSTANCE_NAME=lab "$ODOH" >>"$OUT/odoh-target.log" 2>&1 &
start_relay() { nsx relay env PORT=443 CERT="$C/odoh-relay.lab.test.pem" KEY="$C/odoh-relay.lab.test.key" "$ODOH" >>"$OUT/odoh-relay.log" 2>&1 & RL_PID=$!; sleep 1; }
start_relay
sleep 1
log "серверы: dnsproxy (pid $DP_PID), ODoH target и relay (pid $RL_PID); «публичный» резолвер 1.1.1.1 — в их netns"

# --- роутер: настройки, рендер (ARM64), dnsmasq и Mihomo ---
CFG="$W/state/config.json"; mkdir -p "$W/state" "$W/dnsmasq.d"
printf 'ads.lab.test\n0.0.0.0 tracker.lab.test\n# комментарий\n' >"$W/list1.txt"
"${RUNCTL[@]}" "$CTL" adblock-update "$CFG" "$W/list1.txt" >"$OUT/adblock-update-1.json"; echo "exit=$?" >>"$OUT/adblock-update-1.json"
setcfg() { # setcfg <transport>
  "${PY[@]}" -c 'import json,sys
d=json.load(open(sys.argv[1]));t=sys.argv[2]
dns={"transport":t,"adblock":{"enabled":True,"exceptions":["good.ads.lab.test"]}}
if t=="odoh":
  dns["odoh"]={"target":{"host":"odoh-target.lab.test","ip":"10.30.3.2","path":"/dns-query"},"relays":[{"host":"odoh-relay.lab.test","ip":"10.30.4.2","path":"/proxy"}]}
else:
  dns["servers"]=[{"host":"doh.lab.test","ip":"10.30.2.2"}]
d["dns"]=dns
json.dump(d,open(sys.argv[3],"w"),ensure_ascii=False,indent=2)' "$ROOT/fixtures/lab/config.json" "$1" "$CFG"; }
printf '{"version":1,"profiles":{}}\n' >"$W/secrets.json"; : >"$W/dhcp.leases"
render() { "${RUNCTL[@]}" "$CTL" render "$CFG" "$W/secrets.json" "$W/dhcp.leases" "$W/mh" >"$OUT/render-$1.json" || { cat "$OUT/render-$1.json"; die "render $1"; }
  cp "$W/mh/dnsmasq-mitt.conf" "$W/dnsmasq.d/"; cp "$W/mh/dnsmasq-mitt.conf" "$OUT/dnsmasq-mitt.$1.conf"
  "${PY[@]}" -c 'import json,sys;d=json.load(open(sys.argv[1]));print(json.dumps(d.get("dns"),indent=1))' "$W/mh/config.yaml" >"$OUT/mihomo-dns.$1.json"; }
start_dnsmasq() { # как штатный dnsmasq: DHCP и локальные имена не трогаем, наш файл — в conf-dir
  nsx router "${PY[@]}" "$ROOT/tools/lab/nosetgroups.py" "$DNSMASQ" -k --conf-file=/dev/null --listen-address=10.10.1.1 --bind-interfaces \
    --conf-dir="$W/dnsmasq.d" --pid-file= --user=root --group=root --cache-size=0 --log-queries --log-facility="$OUT/dnsmasq.log" >>"$OUT/dnsmasq.out" 2>&1 & DM_PID=$!; sleep 0.7; }
stop_dnsmasq() { kill "$DM_PID" 2>/dev/null; wait "$DM_PID" 2>/dev/null; }
start_mh() { nsx router "$MIHOMO" -d "$W/mh" -f "$W/mh/config.yaml" >>"$OUT/mihomo.log" 2>&1 & MH_PID=$!; sleep 2; }
stop_mh() { kill "$MH_PID" 2>/dev/null; wait "$MH_PID" 2>/dev/null; }
start_dc() { nsx router "$DNSCRYPT" -config "$W/mh/dnscrypt-proxy.toml" >>"$OUT/dnscrypt.log" 2>&1 & DC_PID=$!; sleep 3; }
stop_dc() { kill "${DC_PID:-0}" 2>/dev/null; wait "${DC_PID:-0}" 2>/dev/null; }

: >"$OUT/queries.jsonl"; : >"$OUT/phases.jsonl"
q() { # q <id> <ns> <имя> <A|AAAA>
  local t0 out; t0="$(now)"; out="$(nsx "$2" "${PY[@]}" "$ROOT/tools/lab/dnsq.py" 10.10.1.1 "$3" "$4" 6 2>&1)"
  "${PY[@]}" -c 'import json,sys
a=sys.argv
try: r=json.loads(a[6])
except Exception: r={"raw":a[6]}
r.update({"id":a[1],"ns":a[2],"name":a[3],"type":a[4],"t0":float(a[5])});print(json.dumps(r))' "$1" "$2" "$3" "$4" "$t0" "$out" >>"$OUT/queries.jsonl"
  log "запрос $1 ($2 $3 $4): $out"; }
phase() { printf '{"phase":"%s","t":%s}\n' "$1" "$(now)" >>"$OUT/phases.jsonl"; log "== фаза $1"; }

for t in doh dot doq doh3; do
  setcfg "$t"; render "$t"; start_dnsmasq; start_mh
  phase "$t"
  q "$t-A" tv ok.lab.test A; q "$t-AAAA" tv ok.lab.test AAAA; q "$t-phone" phone ok2.lab.test A
  q "$t-ads-A" tv ads.lab.test A; q "$t-ads-AAAA" tv ads.lab.test AAAA; q "$t-tracker" tv tracker.lab.test A
  q "$t-good" tv good.ads.lab.test A; q "$t-nx" tv missing.lab.test A
  stop_mh; stop_dnsmasq
done

# обновление списка: корректный новый список применяется, ошибочный — отклоняется, действующий сохраняется
setcfg doh
printf 'ads.lab.test\nblocked2.lab.test\n' >"$W/list2.txt"
"${RUNCTL[@]}" "$CTL" adblock-update "$CFG" "$W/list2.txt" >"$OUT/adblock-update-2.json"; echo "exit=$?" >>"$OUT/adblock-update-2.json"
cp "$W/state/adblock.list" "$W/list-before-bad.txt"
printf 'ads.lab.test\nthis is not a domain\n' >"$W/list3.txt"
"${RUNCTL[@]}" "$CTL" adblock-update "$CFG" "$W/list3.txt" >"$OUT/adblock-update-3.json"; echo "exit=$?" >>"$OUT/adblock-update-3.json"
cmp -s "$W/list-before-bad.txt" "$W/state/adblock.list" && echo '{"kept":true}' >"$OUT/adblock-kept.json" || echo '{"kept":false}' >"$OUT/adblock-kept.json"
render update; start_dnsmasq; start_mh
phase adblock_update
q U-blocked2 tv blocked2.lab.test A; q U-tracker tv tracker.lab.test A; q U-ads tv ads.lab.test A; q U-ok tv ok.lab.test A

# отказ сервера DoH: ошибка у клиента, открытого DNS наружу нет
phase doh_down
kill "$DP_PID"; wait "$DP_PID" 2>/dev/null; sleep 0.5
q F-A tv ok3.lab.test A; q F-phone phone ok3.lab.test A
stop_mh; stop_dnsmasq; start_dnsproxy

# ODoH через relay
phase odoh_start
setcfg odoh; render odoh; cp "$W/mh/dnscrypt-proxy.toml" "$OUT/dnscrypt-proxy.toml"
start_dnsmasq; start_mh; start_dc
for i in $(seq 40); do grep -q "dnscrypt-proxy is ready" "$OUT/dnscrypt.log" && break; sleep 0.5; done; sleep 1
phase odoh
q O-A tv ok.lab.test A; q O-AAAA tv ok.lab.test AAAA; q O-ads tv ads.lab.test A; q O-good tv good.ads.lab.test A
phase relay_down
kill "$RL_PID"; wait "$RL_PID" 2>/dev/null; sleep 0.5
q R-A tv ok4.lab.test A
phase end
stop_mh; stop_dnsmasq; stop_dc
kill "$SN" "$SN2" 2>/dev/null
log "готово"
