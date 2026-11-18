#!/usr/bin/env bash
# x86_64 iptables-legacy для лаборатории (ARM64 iptables прошивки под qemu-user не работает с netfilter:
# qemu не транслирует setsockopt/getsockopt IPT_SO_*). Пакеты Ubuntu распаковываются в кэш без установки.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/iptables"; mkdir -p "$D"; cd "$D"
if [ ! -x root/usr/sbin/xtables-legacy-multi ]; then
  apt-get download iptables libxtables12 libip4tc2 libip6tc2 >/dev/null
  for d in *.deb; do dpkg-deb -x "$d" root; done
fi
sha256sum *.deb > SHA256SUMS.txt
LD_LIBRARY_PATH="$D/root/usr/lib/x86_64-linux-gnu" "$D/root/usr/sbin/xtables-legacy-multi" iptables -V
