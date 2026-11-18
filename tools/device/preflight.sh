#!/bin/sh
# mi-trusttunnel preflight для BE7000 (RC06) — ТОЛЬКО ЧТЕНИЕ. Совместим с BusyBox ash (1.25.1 стока).
# Запуск по уже доступному SSH:   ssh root@<роутер> 'sh -s' < preflight.sh > preflight.txt
# Ничего не меняет: не пишет файлы, не трогает правила, маршруты, sysctl, firewall, не загружает модули явно.
# Не выводит секреты и персональные данные: ни паролей, ни ключей Wi-Fi, ни MAC и IP клиентов (только счётчики и маски).
# Примечание: `iptables -j MARK -h` при выгруженном xt_mark может заставить iptables загрузить модуль (так ведёт себя
# сам iptables); сеть и правила при этом не меняются. Выключите MITT_PREFLIGHT_HELP=0, чтобы пропустить такие проверки.
# Формат: строки key=value; итог — строки verdict.*.

[ "${MITT_PREFLIGHT_KEEP_PATH:-0}" = 1 ] || PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"   # для стенда: оставить PATH как есть
LC_ALL=C
export PATH LC_ALL
HELP="${MITT_PREFLIGHT_HELP:-1}"
EXT_NF_OK=yes
EXT_MARK_OK=yes

kv() { printf '%s=%s\n' "$1" "$2"; }
has() { command -v "$1" >/dev/null 2>&1; }
first() { head -n 1 2>/dev/null | tr -d '\r' | cut -c1-120; }

kv preflight.version 1
kv preflight.readonly yes

# --- устройство и ядро ---
rom=""; [ -r /usr/share/xiaoqiang/xiaoqiang_version ] && rom=$(grep -o "ROM '[^']*'" /usr/share/xiaoqiang/xiaoqiang_version | cut -d"'" -f2)
kv device.rom "${rom:-unknown}"
model=""; [ -r /proc/device-tree/model ] && model=$(tr -d '\000' </proc/device-tree/model)
kv device.model "${model:-unknown}"
hw=""; has uci && hw=$(uci -q get misc.hardware.model 2>/dev/null)
kv device.hardware "${hw:-unknown}"
rel=$(uname -r); kv kernel.release "$rel"; kv kernel.arch "$(uname -m)"
[ -r /etc/openwrt_release ] && kv os.openwrt "$(grep DISTRIB_RELEASE /etc/openwrt_release | cut -d"'" -f2)"

# --- конфигурация ядра ---
KC=""
if [ -r /proc/config.gz ] && has zcat; then
  KC=$(zcat /proc/config.gz 2>/dev/null)
  kv kconfig.source /proc/config.gz
else
  kv kconfig.source unavailable
fi
for o in IP_MULTIPLE_TABLES IPV6_MULTIPLE_TABLES TUN NET_SCH_INGRESS NET_CLS_ACT NET_CLS_FLOWER NET_CLS_MATCHALL NET_ACT_SKBEDIT \
         IP_NF_IPTABLES IP_NF_FILTER IP_NF_MANGLE IP_NF_TARGET_REJECT IP6_NF_IPTABLES IP6_NF_FILTER IP6_NF_MANGLE IP6_NF_TARGET_REJECT \
         NETFILTER_XT_MATCH_MAC NETFILTER_XT_MATCH_COMMENT NETFILTER_XT_MARK NETFILTER_XT_MATCH_PHYSDEV BRIDGE_NETFILTER; do
  v=""
  if [ -n "$KC" ]; then
    v=$(printf '%s\n' "$KC" | grep -E "^CONFIG_$o=" | cut -d= -f2)
    [ -z "$v" ] && printf '%s\n' "$KC" | grep -q "^# CONFIG_$o is not set" && v=n
  fi
  kv "kconfig.$o" "${v:-absent}"
done

# --- модули (файл и загружен ли) ---
MD="/lib/modules/$rel"
for m in tun sch_ingress cls_flower cls_matchall act_skbedit ip_tables iptable_filter iptable_mangle ipt_REJECT \
         ip6_tables ip6table_filter ip6table_mangle ip6t_REJECT xt_mac xt_comment xt_mark xt_physdev br_netfilter; do
  f=no; [ -f "$MD/$m.ko" ] && f=yes
  l=no; [ -d "/sys/module/$m" ] && l=yes
  kv "module.$m" "file=$f loaded=$l"
done

# --- утилиты ---
for t in ip tc iptables ip6tables iptables-save ip6tables-save brctl zcat flock unxz xzcat sha256sum md5sum; do
  if has "$t"; then kv "tool.$t" "$(command -v "$t")"; else kv "tool.$t" missing; fi
done
has ip && kv tool.ip.version "$(ip -V 2>&1 | first)"
has tc && kv tool.tc.version "$(tc -V 2>&1 | first)"
has iptables && kv tool.iptables.version "$(iptables -V 2>&1 | first)"
if [ "$HELP" = 1 ]; then
  for t in iptables ip6tables; do
    has "$t" || continue
    $t -m mac -h 2>&1 | grep -q -- '--mac-source' && kv "ext.$t.mac" yes || kv "ext.$t.mac" no
    $t -m comment -h 2>&1 | grep -q -- '--comment' && kv "ext.$t.comment" yes || kv "ext.$t.comment" no
    $t -j REJECT -h 2>&1 | grep -q -- '--reject-with' && kv "ext.$t.REJECT" yes || kv "ext.$t.REJECT" no
    if $t -m physdev -h 2>&1 | grep -q -- '--physdev-in'; then kv "ext.$t.physdev" yes; else kv "ext.$t.physdev" no; EXT_MARK_OK=no; fi
    if $t -j MARK -h 2>&1 | grep -q -- '--set-xmark'; then kv "ext.$t.MARK_xmark" yes; else kv "ext.$t.MARK_xmark" no; EXT_MARK_OK=no; fi
    for x in mac comment; do $t -m $x -h 2>&1 | grep -q -- "--$( [ $x = mac ] && echo mac-source || echo comment)" || EXT_NF_OK=no; done
    $t -j REJECT -h 2>&1 | grep -q -- '--reject-with' || EXT_NF_OK=no
  done
fi

# --- мосты и порты (имена интерфейсов, без MAC) ---
for b in /sys/class/net/*/bridge; do
  [ -d "$b" ] || continue
  br=$(basename "$(dirname "$b")")
  ports=""; for p in /sys/class/net/"$br"/brif/*; do [ -e "$p" ] && ports="$ports $(basename "$p")"; done
  kv "bridge.$br.ports" "${ports# }"
done
for f in bridge-nf-call-iptables bridge-nf-call-ip6tables; do
  v=""; [ -r "/proc/sys/net/bridge/$f" ] && v=$(cat "/proc/sys/net/bridge/$f")
  kv "sysctl.net.bridge.$f" "${v:-absent}"
done
kv sysctl.ipv4.ip_forward "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"

# --- правила маршрутизации: только приоритеты и маски, без адресов ---
if has ip; then
  for fam in 4 6; do
    z=$(ip -"$fam" rule show 2>/dev/null | awk -F: '$1>=3000 && $1<=3199' | wc -l)
    kv "rules.v$fam.zone_3000_3199" "$z"
    kv "rules.v$fam.lookup_3100" "$(ip -"$fam" rule show 2>/dev/null | grep -c 'lookup 3100')"
    kv "rules.v$fam.fwmark_masks" "$(ip -"$fam" rule show 2>/dev/null | grep -o 'fwmark [0-9a-fx/]*' | sed 's/.*\///' | sort -u | tr '\n' ' ')"
  done
  kv routes.table_3100 "$(ip route show table 3100 2>/dev/null | wc -l)"
fi

# --- firewall: маски меток, наши цепочки, политика FORWARD (без адресов и MAC) ---
for t in iptables ip6tables; do
  has "$t-save" || continue
  S=$($t-save 2>/dev/null)
  kv "fw.$t.mark_masks" "$(printf '%s\n' "$S" | grep -oE -- '--(set-xmark|set-mark|mark|or-mark|and-mark|xor-mark) [0-9a-fx]+(/[0-9a-fx]+)?' | awk '{n=split($2,a,"/"); print (n>1)?a[2]:"0xffffffff"}' | sort | uniq -c | awk '{printf "%s:%s ", $2, $1}')"
  kv "fw.$t.mitt_chains" "$(printf '%s\n' "$S" | grep -c '^:MITT_')"
  kv "fw.$t.forward_policy" "$(printf '%s\n' "$S" | grep '^:FORWARD' | head -n 1 | awk '{print $2}')"
  kv "fw.$t.forward_rules" "$(printf '%s\n' "$S" | grep -c '^-A FORWARD')"
done
[ -r /etc/config/firewall ] && kv fw.fw3_includes "$(grep -c '^config include' /etc/config/firewall)"

# --- ускорение и сеть ---
for m in ecm qca_nss_drv qca_ovsmgr ecm_sfe_l2 shortcut_fe; do [ -d "/sys/module/$m" ] && kv "accel.$m" loaded || kv "accel.$m" absent; done
has uci && kv accel.ecm_bridge "$(uci -q get ecm.global.acceleration_engine 2>/dev/null || echo unknown)"
[ -c /dev/net/tun ] && kv dev.net_tun yes || kv dev.net_tun no

# --- место ---
df -k /data /tmp 2>/dev/null | awk 'NR>1{print "storage."$6".avail_kb="$4}'
grep -E ' /tmp | /data ' /proc/mounts 2>/dev/null | awk '{print "mount."$2".opts="$4}'

# --- итог ---
yn() { [ "$1" = y ] || [ "$1" = m ] && echo yes || echo no; }
kc() { printf '%s\n' "$KC" | grep -E "^CONFIG_$1=" | cut -d= -f2; }
if [ -n "$KC" ]; then
  tc_ok=yes
  for o in NET_SCH_INGRESS NET_CLS_ACT NET_CLS_FLOWER NET_CLS_MATCHALL NET_ACT_SKBEDIT; do [ "$(yn "$(kc $o)")" = yes ] || tc_ok=no; done
  nf_ok=yes
  for o in IP_NF_IPTABLES IP_NF_FILTER IP_NF_TARGET_REJECT IP6_NF_IPTABLES IP6_NF_FILTER IP6_NF_TARGET_REJECT NETFILTER_XT_MATCH_MAC NETFILTER_XT_MATCH_COMMENT; do
    [ "$(yn "$(kc $o)")" = yes ] || nf_ok=no
  done
  has iptables && has ip6tables || nf_ok=no
  [ "$HELP" = 1 ] && [ "$EXT_NF_OK" = no ] && nf_ok=no
  mk_ok=$nf_ok
  [ "$HELP" = 1 ] && [ "$EXT_MARK_OK" = no ] && mk_ok=no
  for o in IP_NF_MANGLE IP6_NF_MANGLE NETFILTER_XT_MARK NETFILTER_XT_MATCH_PHYSDEV BRIDGE_NETFILTER; do [ "$(yn "$(kc $o)")" = yes ] || mk_ok=no; done
  [ "$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null)" = 1 ] || mk_ok=no
  kv verdict.marker_tc "$tc_ok"
  kv verdict.marker_netfilter "$nf_ok"
  kv verdict.netfilter_partial_bridge_ports "$mk_ok"
else
  kv verdict.marker_tc unknown
  kv verdict.marker_netfilter unknown
  kv verdict.netfilter_partial_bridge_ports unknown
fi
kv verdict.note "сверьте с mi-tt-admin caps; при partial_bridge_ports=no политика сети допустима только для сети на отдельном мосту"
exit 0
