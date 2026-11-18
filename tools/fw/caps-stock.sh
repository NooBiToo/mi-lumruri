#!/usr/bin/env bash
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"; F=/tmp/mitt-fw/rootfs; Q=$R/.tools/qemu/root/usr/bin/qemu-aarch64
mkdir -p /tmp/stockbin
for t in iptables ip6tables; do printf '#!/bin/sh\nexec %s -L %s -E XTABLES_LIBDIR=/usr/lib/iptables %s/usr/sbin/xtables-multi %s "$@"\n' "$Q" "$F" "$F" "$t" > /tmp/stockbin/$t; chmod +x /tmp/stockbin/$t; done
printf '#!/bin/sh\nexec %s -L %s %s/usr/sbin/tc "$@"\n' "$Q" "$F" "$F" > /tmp/stockbin/tc; chmod +x /tmp/stockbin/tc
env -i PATH=/usr/bin:/bin MI_TT_IPTABLES=/tmp/stockbin/iptables MI_TT_IP6TABLES=/tmp/stockbin/ip6tables MI_TT_TC=/tmp/stockbin/tc \
  MI_TT_KCONFIG=$R/.tools/fw/kernel/config MI_TT_MODULES_DIR=$F/lib/modules/5.4.164 MI_TT_KERNEL_RELEASE=5.4.164 \
  $Q $R/controller/target/aarch64-unknown-linux-musl/release/mi-tt-admin caps
