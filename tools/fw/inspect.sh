#!/usr/bin/env bash
# Статическая проверка образа стока RC06 1.1.38 (только чтение файлов образа; ничего из него не запускается,
# кроме --version/-V ARM64-утилит под qemu-user без доступа к сети хоста). Отчёт: out/fw/rc06-1.1.38.txt
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
"$ROOT/tools/fw/prepare.sh" >/dev/null || exit 1
R=/tmp/mitt-fw/rootfs; K="$ROOT/.tools/fw/kernel/config"; Q="$ROOT/.tools/qemu/root/usr/bin/qemu-aarch64"
O="$ROOT/out/fw"; mkdir -p "$O"; F="$O/rc06-1.1.38.txt"
{
  echo "# RC06 1.1.38 — статическая проверка (образ SHA-256 77d8bd587418310c12c32922f8af63994079baa12c3a4772891494631bd84d8e)"
  echo "## версия"; grep -o "ROM '[^']*'" "$R/usr/share/xiaoqiang/xiaoqiang_version"; grep DISTRIB_ "$R/etc/openwrt_release"
  echo "## конфигурация ядра (IKCONFIG из FIT, ядро $(ls "$R/lib/modules"))"
  for o in IKCONFIG_PROC IP_MULTIPLE_TABLES IPV6_MULTIPLE_TABLES TUN NET_SCH_INGRESS NET_CLS_ACT NET_CLS_FLOWER NET_CLS_MATCHALL NET_ACT_SKBEDIT NET_CLS_U32 NET_CLS_FW \
           IP_NF_IPTABLES IP_NF_FILTER IP_NF_MANGLE IP_NF_TARGET_REJECT IP6_NF_IPTABLES IP6_NF_FILTER IP6_NF_MANGLE IP6_NF_TARGET_REJECT \
           NETFILTER_XT_MATCH_MAC NETFILTER_XT_MATCH_COMMENT NETFILTER_XT_MARK NETFILTER_XT_MATCH_MARK NETFILTER_XT_TARGET_MARK NETFILTER_XT_MATCH_PHYSDEV BRIDGE_NETFILTER NF_TABLES; do
    printf '%-30s %s\n' "$o" "$(grep -E "^(# )?CONFIG_$o[= ]" "$K" | head -1 || true)"
  done
  echo "## модули"; for m in tun sch_ingress cls_flower cls_matchall act_skbedit cls_u32 cls_fw ip_tables iptable_filter iptable_mangle ipt_REJECT ip6_tables ip6table_filter ip6table_mangle ip6t_REJECT xt_mac xt_comment xt_mark xt_physdev br_netfilter nf_tables; do
    [ -f "$R/lib/modules/5.4.164/$m.ko" ] && echo "$m.ko: есть" || echo "$m.ko: нет"; done
  echo "## утилиты"; for b in usr/sbin/ip sbin/tc usr/sbin/iptables usr/sbin/ip6tables usr/sbin/iptables-save usr/sbin/ipset usr/sbin/brctl usr/sbin/nft usr/sbin/ebtables usr/sbin/bridge; do
    printf '%-24s %s\n' "$b" "$(readlink "$R/$b" 2>/dev/null || ([ -e "$R/$b" ] && echo файл) || echo нет)"; done
  "$Q" -L "$R" -0 ip "$R/usr/libexec/ip-full" -V; "$Q" -L "$R" -0 tc "$R/usr/libexec/tc-full" -V; "$Q" -L "$R" -0 iptables "$R/usr/sbin/xtables-multi" -V; "$Q" -L "$R" "$R/bin/busybox" | head -1
  echo "## встроенные расширения iptables (libiptext*.so)"; strings "$R"/usr/lib/libiptext*.so | grep -E "^lib(xt|ipt|ip6t)_[A-Za-z0-9_]+_init$" | sort -u | tr '\n' ' '; echo
  echo "## отдельные расширения iptables"; ls "$R/usr/lib/iptables" | tr '\n' ' '; echo
  echo "## BusyBox: нужные апплеты"; L=$("$Q" -L "$R" "$R/bin/busybox" --list); for a in sh awk sed grep zcat flock timeout unxz xzcat sha256sum md5sum sysctl df; do echo "$L" | grep -qx "$a" && echo "$a: есть" || echo "$a: нет"; done
  echo "## bridge netfilter: включается ECM"; grep -n "bridge-nf-call" "$R/etc/init.d/qca-nss-ecm"; cat "$R/etc/modules.d/br-netfilter"
  echo "## распределение битов skb mark (miqosd_init.sh)"; grep -n "skb mark\|mark_[A-Z_]*=" "$R/usr/sbin/miqosd_init.sh" | head -12
  echo "## маски mark/MARK в скриптах прошивки"; grep -rhoE -e '--(set-xmark|set-mark|mark) +0x[0-9a-fA-F]+(/0x[0-9a-fA-F]+)?' "$R/etc" "$R/usr/sbin" "$R/lib" 2>/dev/null | sort | uniq -c
  grep -n "mmx_mask" "$R/etc/config/mwan3"
} >"$F" 2>&1
echo "$F"
