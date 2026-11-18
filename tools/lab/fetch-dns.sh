#!/usr/bin/env bash
# Инструменты лаборатории DNS (этап 10), кэш .tools/lab; повторно не качает. Хэши архивов — из API релизов (поле digest).
#   dnsproxy v0.86.0 (AdGuard, Apache-2.0) — сервер DoH/DoT/DoQ/DoH3 в «интернете» лаборатории;
#   dnscrypt-proxy 2.1.20 (ISC) — клиент ODoH на роутере (x86_64 для лаборатории, arm64 — для комплекта);
#   dnsmasq-base (Ubuntu, apt-get download без установки) — как штатный dnsmasq роутера.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dl"; B="$ROOT/.tools/lab/bin"; mkdir -p "$D" "$B"
get() { # get <url> <sha256>
  local f="$D/$(basename "$1")"
  [ -s "$f" ] || { curl -sSfL --proto '=https' -o "$f.part" "$1" && mv "$f.part" "$f"; }
  echo "$2  $f" | sha256sum -c --quiet || { echo "хэш не совпал: $f"; rm -f "$f"; exit 1; }
}
DP=https://github.com/AdguardTeam/dnsproxy/releases/download/v0.86.0/dnsproxy-linux-amd64-v0.86.0.tar.gz
DC=https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.20
get "$DP" 17ac43f76ebfcedf547c663f6f31aa70e68b8eb6fc41d2fc37d3bfe21a2ced66
get "$DC/dnscrypt-proxy-linux_x86_64-2.1.20.tar.gz" 71ba1165f006a682463aa30b120ac33bb3b3d0942b41d7cac8ab105e2dc98464
get "$DC/dnscrypt-proxy-linux_arm64-2.1.20.tar.gz" def151a7f7b3bf62129a975e48875861908e05a1e0effb74929c66b8a50c6527
[ -x "$B/dnsproxy" ] || { tar -xzf "$D/$(basename "$DP")" -C "$D" && cp "$D/linux-amd64/dnsproxy" "$B/dnsproxy"; }
[ -x "$B/dnscrypt-proxy" ] || { tar -xzf "$D/dnscrypt-proxy-linux_x86_64-2.1.20.tar.gz" -C "$D" && cp "$D/linux-x86_64/dnscrypt-proxy" "$B/dnscrypt-proxy"; }
if [ ! -x "$ROOT/.tools/lab/dnsmasq/root/usr/sbin/dnsmasq" ]; then
  mkdir -p "$ROOT/.tools/lab/dnsmasq" && (cd "$ROOT/.tools/lab/dnsmasq" && apt-get download dnsmasq-base libnetfilter-conntrack3 libnfnetlink0 libnftables1 libnftnl11 libjansson4 libxtables12 libmnl0 >/dev/null 2>&1 && for d in *.deb; do dpkg-deb -x "$d" root; done && sha256sum *.deb >SHA256SUMS.txt)
fi
chmod +x "$B"/*
"$B/dnsproxy" --version 2>&1 | head -1; "$B/dnscrypt-proxy" -version; LD_LIBRARY_PATH="$ROOT/.tools/lab/dnsmasq/root/usr/lib/x86_64-linux-gnu" "$ROOT/.tools/lab/dnsmasq/root/usr/sbin/dnsmasq" --version | head -1
