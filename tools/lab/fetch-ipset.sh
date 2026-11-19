#!/usr/bin/env bash
# x86_64 ipset для лаборатории (ARM64 ipset прошивки под qemu-user не работает с netlink netfilter).
# Пакеты Ubuntu распаковываются в кэш без установки.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="$ROOT/.tools/lab/ipset"; mkdir -p "$D"; cd "$D"
if [ ! -x root/usr/sbin/ipset ]; then
  apt-get download ipset "$(apt-cache depends ipset | awk '/Depends: libipset/ {print $2; exit}')" >/dev/null
  for d in *.deb; do dpkg-deb -x "$d" root; done
fi
sha256sum *.deb > SHA256SUMS.txt
# версию не спрашиваем: вне своего namespace ядро отвечает EPERM
ls -l "$D/root/usr/sbin/ipset"
