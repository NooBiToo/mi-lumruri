#!/usr/bin/env bash
# Сведения об устройствах: (1) таблица производителей из настоящего oui.tar.gz прошивки RC06 1.1.38 распаковывается
# штатным BusyBox ash/tar под qemu-user (devices_prepare); (2) mi-tt-ctl names-scan (ARM64 под qemu) в отдельном сетевом
# пространстве находит имена: «Chromecast» отвечает на mDNS (legacy unicast), «телевизор» — на SSDP с описанием UPnP.
# Нужен `bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl`. Запуск — в WSL.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null
F=/tmp/mitt-fw/rootfs; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
CTL="$ROOT/controller/target/aarch64-unknown-linux-musl/release/mi-tt-ctl"
[ -f "$CTL" ] || { echo "нет $CTL: bash tools/cargo.sh build --locked --release --target aarch64-unknown-linux-musl"; exit 2; }
W="$(mktemp -d /tmp/mitt-devices.XXXXXX)"; [ -n "${KEEP:-}" ] && echo "каталог: $W" || trap 'rm -rf "$W"' EXIT
FAIL=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; FAIL=1; }

SB="$W/stockbin"; mkdir -p "$SB"
for a in sh ash cat cp mv rm mkdir chmod sed awk grep head tail wc tr cut cmp date sleep kill basename dirname touch printf echo test expr tar gzip env; do
  [ -e "$F/bin/$a" ] || [ -e "$F/usr/bin/$a" ] || [ -e "$F/sbin/$a" ] || [ -e "$F/usr/sbin/$a" ] || { echo "нет апплета $a в образе"; exit 2; }
  printf '#!/bin/sh\nexec %s -L %s %s/bin/busybox %s "$@"\n' "$Q" "$F" "$F" "$a" >"$SB/$a"
done
chmod +x "$SB"/*
R="$W/root"; L="$R/tmp/mi-lumruri"; mkdir -p "$R/data/mi-lumruri/etc" "$L/run" "$L/log" "$L/bin" "$L/scripts"
cp "$ROOT"/package/scripts/*.sh "$L/scripts/"

echo "(а) таблица производителей: штатный tar распаковывает oui.tar.gz прошивки"
timeout 120 env -i PATH="$SB" MITT_ROOT="$R" MITT_QUIET=1 MITT_OUI_TGZ="$F/usr/share/xiaoqiang/oui.tar.gz" \
  "$Q" -L "$F" "$F/bin/busybox" ash -c ". \"$L/scripts/mitt-lib.sh\"; devices_prepare" >"$W/out" 2>&1
n=$(wc -l <"$L/run/oui.txt" 2>/dev/null || echo 0)
[ "$n" -gt 3000 ] && grep -q '^3C-D9-2B Hewlett Packard' "$L/run/oui.txt" && ok "a: $n строк, формат «XX-XX-XX Производитель ICON:…»" || bad "a: строк $n; $(cat "$W/out")"

echo "(б) поиск имён: mDNS (Chromecast, legacy unicast) и SSDP с описанием UPnP (телевизор) в отдельной сети"
cat >"$W/responder.py" <<'EOF'
import socket, struct, sys, threading, http.server
def name(s):
    return b"".join(bytes([len(l)]) + l.encode() for l in s.split(".")) + b"\0"
def rr(n, t, data):
    return name(n) + struct.pack(">HHIH", t, 0x8001, 120, len(data)) + data
inst = "Chromecast-1a2b._googlecast._tcp.local"
txt = b"".join(bytes([len(x.encode())]) + x.encode() for x in ["md=Chromecast", "fn=Гостиная"])
answer = struct.pack(">HHHHHH", 0, 0x8400, 0, 3, 0, 0) + rr("_googlecast._tcp.local", 12, name(inst)) + rr(inst, 16, txt) + rr("1a2b.local", 1, bytes([127, 0, 0, 20]))
m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); m.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
m.bind(("224.0.0.251", 5353)); m.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("224.0.0.251") + socket.inet_aton("127.0.0.20"))
m.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("239.255.255.250", 1900)); s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("239.255.255.250") + socket.inet_aton("127.0.0.30"))
XML = b"<root><device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>[TV] Samsung</friendlyName><manufacturer>Samsung Electronics</manufacturer><modelName>UE55</modelName></device></root>"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(XML)
    def log_message(self, *a): pass
httpd = http.server.HTTPServer(("127.0.0.30", 9197), H)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
def mdns():
    out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); out.bind(("127.0.0.20", 5353 if False else 0))
    while True:
        data, src = m.recvfrom(9000)
        if src[0] != "127.0.0.20":
            o = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); o.bind(("127.0.0.20", 5353)); o.sendto(answer, src); o.close()
def ssdp():
    while True:
        data, src = s.recvfrom(9000)
        if b"M-SEARCH" in data:
            o = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); o.bind(("127.0.0.30", 1900))
            o.sendto(b"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.30:9197/dmr.xml\r\nST: upnp:rootdevice\r\n\r\n", src); o.close()
threading.Thread(target=mdns, daemon=True).start(); threading.Thread(target=ssdp, daemon=True).start()
print("ready", flush=True); threading.Event().wait(60)
EOF
printf '1800000000 aa:bb:cc:dd:ee:20 127.0.0.20 cast *\n1800000000 aa:bb:cc:dd:ee:30 127.0.0.30 tv *\n' >"$W/leases"
cat >"$W/ns.sh" <<EOF
ip link set lo up; ip route add 224.0.0.0/4 dev lo
python3 -I "$W/responder.py" >"$W/responder.log" 2>&1 & sleep 1
MI_TT_LEASES="$W/leases" timeout 60 "$Q" "$CTL" names-scan --from 127.0.0.1 --out "$L/run/names.json" --wait 2500 >"$W/scan.out" 2>&1
EOF
unshare -rn bash "$W/ns.sh"
js() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1]))["devices"]; print(eval(sys.argv[2]))' "$L/run/names.json" "$1" 2>&1; }
[ "$(js 'd["aa:bb:cc:dd:ee:20"]["name"]=="Гостиная" and d["aa:bb:cc:dd:ee:20"]["kind"]=="tv" and d["aa:bb:cc:dd:ee:20"]["model"]=="Chromecast"')" = True ] \
  && ok "b: mDNS — «Гостиная», тип tv, модель Chromecast (по MAC из аренд)" || bad "b: $(cat "$L/run/names.json" 2>/dev/null) $(cat "$W/scan.out" "$W/responder.log")"
[ "$(js 'd["aa:bb:cc:dd:ee:30"]["name"]=="[TV] Samsung" and d["aa:bb:cc:dd:ee:30"]["source"]=="ssdp" and "UE55" in d["aa:bb:cc:dd:ee:30"]["model"]')" = True ] \
  && ok "b: SSDP + UPnP — «[TV] Samsung», модель Samsung Electronics UE55" || bad "b: $(cat "$L/run/names.json" 2>/dev/null)"

[ $FAIL -eq 0 ] && echo "ИТОГ: ПРОЙДЕНО" || { echo "ИТОГ: ЕСТЬ ОШИБКИ"; exit 1; }
