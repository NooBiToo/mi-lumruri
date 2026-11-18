#!/usr/bin/env bash
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
tools/fw/prepare.sh >/tmp/prep.log 2>&1; echo "prepare rc=$?"
F=/tmp/mitt-fw/rootfs
ls "$F" | head -3
find "$F/lib/modules" -name "*.ko" | grep -iE "nfqueue|multiport|xt_mark|nfnetlink_queue|iptable_mangle" | sed "s#.*/##"
ls "$F/usr/lib/iptables" 2>/dev/null | grep -iE "NFQUEUE|multiport|mark" | tr "\n" " "; echo
