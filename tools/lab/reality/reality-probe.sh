#!/usr/bin/env bash
# Мини-стенд в одноразовом netns: совместимость REALITY Mihomo ↔ Xray. Только loopback.
set -u
# корень проекта — от каталога самого скрипта; другой бинарник Xray — параметром XRAY=<путь> (reality-bisect.sh)
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"; B=$R/.tools/lab/bin; W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT   # эфемерный ключ TLS прогона удаляется вместе с каталогом
ip link set lo up
X="${XRAY:-$B/xray}"
$X x25519 > $W/k; PRIV=$(awk -F': ' '$1=="PrivateKey"{print $2}' $W/k); PUB=$(awk -F': ' '$1=="Password (PublicKey)"{print $2}' $W/k)
U=$($X uuid); SID=$(python3 -I -c 'import secrets;print(secrets.token_hex(8))')
# эфемерный ключ и сертификат TLS прогона (в $W)
"$R/tools/lab/ephemeral-tls.sh" "$W/tls" >/dev/null || exit 1
TARGET="${TARGET:-go}"
if [ "$TARGET" = go ]; then
  printf '{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":8443,"protocol":"vless","settings":{"clients":[{"id":"%s"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"certificates":[{"certificateFile":"%s","keyFile":"%s"}]}}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}' \
    "$($X uuid)" "$W/tls/cert.pem" "$W/tls/key.pem" > $W/t.json
  $X run -c $W/t.json > $W/t.log 2>&1 &
else
  python3 -c 'import http.server,ssl,sys
h=http.server.HTTPServer(("127.0.0.1",8443),http.server.SimpleHTTPRequestHandler)
c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain(sys.argv[1],sys.argv[2]);h.socket=c.wrap_socket(h.socket,server_side=True);h.serve_forever()' "$W/tls/cert.pem" "$W/tls/key.pem" >/dev/null 2>&1 &
fi
python3 -m http.server 9000 --bind 127.0.0.1 >/dev/null 2>&1 &
printf '{"log":{"loglevel":"debug"},"inbounds":[{"listen":"127.0.0.1","port":443,"protocol":"vless","settings":{"clients":[{"id":"%s","flow":"xtls-rprx-vision"}],"decryption":"none"},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"target":"127.0.0.1:8443","serverNames":["vpn.lab.test"],"privateKey":"%s","shortIds":["%s"]%s}}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.0/8"]}]}}]}' \
  "$U" "$PRIV" "$SID" "${MINVER:+,\"minClientVer\":\"$MINVER\"}" > $W/s.json
$X run -c $W/s.json > $W/srv.log 2>&1 &
sleep 1
for fp in chrome firefox; do
  printf 'mixed-port: 7890\nlog-level: debug\nproxies:\n  - {name: v, type: vless, server: 127.0.0.1, port: 443, uuid: "%s", network: tcp, tls: true, udp: true, flow: xtls-rprx-vision, servername: vpn.lab.test, client-fingerprint: %s, reality-opts: {public-key: "%s", short-id: "%s"}}\nrules: ["MATCH,v"]\n' \
    "$U" "$fp" "$PUB" "$SID" > $W/m.yaml
  $B/mihomo -d $W -f $W/m.yaml > $W/m-$fp.log 2>&1 & M=$!
  sleep 1.5
  echo "target=$TARGET mihomo fp=$fp → http=$(curl -s -m 5 -x socks5h://127.0.0.1:7890 http://127.0.0.1:9000/ -o /dev/null -w '%{http_code}')"
  grep -m1 -iE "error" $W/m-$fp.log | cut -c1-200
  kill $M; wait $M 2>/dev/null
done
printf '{"inbounds":[{"listen":"127.0.0.1","port":7891,"protocol":"socks"}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"%s","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"vpn.lab.test","fingerprint":"chrome","password":"%s","shortId":"%s"}}}]}' \
  "$U" "$PUB" "$SID" > $W/c.json
$X run -c $W/c.json > $W/c.log 2>&1 & C=$!; sleep 1
echo "target=$TARGET xray client → http=$(curl -s -m 5 -x socks5h://127.0.0.1:7891 http://127.0.0.1:9000/ -o /dev/null -w '%{http_code}')"
kill $C; grep -v "^$" $W/srv.log | tail -25 | cut -c1-260; cat $W/k
