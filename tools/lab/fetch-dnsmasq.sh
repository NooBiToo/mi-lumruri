#!/usr/bin/env bash
# x86_64 dnsmasq (с ipset) для лаборатории DNS-сопоставления: dnsmasq прошивки ARM64 под qemu-user не получает
# netlink netfilter. Конфигурация (ipset=, server=, address=) — та же, что пишет пакет для dnsmasq стока.
# Пакеты Ubuntu распаковываются в кэш без установки; dnsmasq запускается с LD_LIBRARY_PATH кэша.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/dnsmasq"; mkdir -p "$D"; cd "$D"
if [ ! -x root/usr/sbin/dnsmasq ]; then
  apt-get download dnsmasq-base libnetfilter-conntrack3 libnfnetlink0 libnftables1 libnftnl11 libjansson4 libxtables12 >/dev/null
  for d in *.deb; do dpkg-deb -x "$d" root; done
fi
sha256sum *.deb > SHA256SUMS.txt
LD_LIBRARY_PATH="$D/root/usr/lib/x86_64-linux-gnu" "$D/root/usr/sbin/dnsmasq" --version | head -2
