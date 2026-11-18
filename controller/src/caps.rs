//! Возможности ядра и утилит для механизмов определения источника. Только разбор и сопоставление:
//! данные собирает mi-tt-admin (или preflight на устройстве) без изменения сети.
//!
//! Факты по стоку RC06 1.1.38 (статическая проверка образа, SHA-256 77d8bd58…): CONFIG_NET_CLS_ACT, NET_CLS_FLOWER,
//! NET_CLS_MATCHALL не включены, sch_ingress нет → tc-механизм недоступен; iptables/ip6tables 1.6.2 с mac, mark/MARK,
//! comment, REJECT, physdev; модули xt_mac, xt_mark, xt_physdev, ipt/ip6t_REJECT, ip(6)table_filter/mangle есть;
//! BRIDGE_NETFILTER=y; IKCONFIG_PROC=y.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::plan::Marker;

/// Требование к ядру: опция и модуль, который должен существовать, если опция =m.
#[derive(Debug, Clone, Copy)]
pub struct Req {
    pub option: &'static str,
    pub module: Option<&'static str>,
}

const fn r(option: &'static str, module: Option<&'static str>) -> Req {
    Req { option, module }
}

pub const COMMON: &[Req] = &[r("IP_MULTIPLE_TABLES", None), r("IPV6_MULTIPLE_TABLES", None), r("TUN", Some("tun"))];
pub const TC: &[Req] = &[
    r("NET_SCH_INGRESS", Some("sch_ingress")),
    r("NET_CLS_ACT", None),
    r("NET_CLS_FLOWER", Some("cls_flower")),
    r("NET_CLS_MATCHALL", Some("cls_matchall")),
    r("NET_ACT_SKBEDIT", Some("act_skbedit")),
];
pub const NF: &[Req] = &[
    r("IP_NF_IPTABLES", Some("ip_tables")),
    r("IP_NF_FILTER", Some("iptable_filter")),
    r("IP_NF_TARGET_REJECT", Some("ipt_REJECT")),
    r("IP6_NF_IPTABLES", Some("ip6_tables")),
    r("IP6_NF_FILTER", Some("ip6table_filter")),
    r("IP6_NF_TARGET_REJECT", Some("ip6t_REJECT")),
    r("NETFILTER_XT_MATCH_MAC", Some("xt_mac")),
    r("NETFILTER_XT_MATCH_COMMENT", Some("xt_comment")),
];
/// Дополнительно для политики сети на части моста (physdev + MARK).
pub const NF_MARK: &[Req] = &[
    r("IP_NF_MANGLE", Some("iptable_mangle")),
    r("IP6_NF_MANGLE", Some("ip6table_mangle")),
    r("NETFILTER_XT_MARK", Some("xt_mark")),
    r("NETFILTER_XT_MATCH_PHYSDEV", Some("xt_physdev")),
    r("BRIDGE_NETFILTER", Some("br_netfilter")),
];

/// Дополнительно для Zapret (NFQUEUE в mangle OUTPUT с отбором по метке и портам).
pub const NF_QUEUE: &[Req] = &[
    r("IP_NF_MANGLE", Some("iptable_mangle")),
    r("NETFILTER_NETLINK_QUEUE", Some("nfnetlink_queue")),
    r("NETFILTER_XT_TARGET_NFQUEUE", Some("xt_NFQUEUE")),
    r("NETFILTER_XT_MATCH_MULTIPORT", Some("xt_multiport")),
    r("NETFILTER_XT_MATCH_MARK", Some("xt_mark")),
];

/// CONFIG_X=y|m|"..." → значение; «# CONFIG_X is not set» → "n".
pub fn parse_kconfig(text: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("CONFIG_") {
            if let Some((k, v)) = rest.split_once('=') {
                m.insert(k.to_string(), v.trim_matches('"').to_string());
            }
        } else if let Some(rest) = line.strip_prefix("# CONFIG_") {
            if let Some(k) = rest.strip_suffix(" is not set") {
                m.insert(k.to_string(), "n".into());
            }
        }
    }
    m
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Item {
    pub what: String,
    pub ok: bool,
    pub detail: String,
}

/// Проверка требований к ядру. `kconfig = None` — конфигурация недоступна: решаем по наличию файлов модулей
/// и помечаем это в detail (встроенное в ядро без конфигурации не видно).
pub fn check_kernel(reqs: &[Req], kconfig: Option<&BTreeMap<String, String>>, modules: &BTreeSet<String>) -> Vec<Item> {
    reqs.iter()
        .map(|q| {
            let what = format!("CONFIG_{}", q.option);
            match (kconfig.and_then(|k| k.get(q.option)).map(String::as_str), q.module) {
                (Some("y"), _) => Item { what, ok: true, detail: "встроено".into() },
                (Some("m"), Some(m)) if modules.contains(m) => Item { what, ok: true, detail: format!("модуль {m}.ko") },
                (Some("m"), Some(m)) => Item { what, ok: false, detail: format!("=m, но файла {m}.ko нет") },
                (Some("m"), None) => Item { what, ok: true, detail: "модуль".into() },
                (Some(v), _) if kconfig.is_some() => Item { what, ok: false, detail: format!("не включено ({v})") },
                (None, Some(m)) if kconfig.is_none() => Item { what, ok: modules.contains(m), detail: format!("конфигурация ядра недоступна; модуль {m}.ko {}", if modules.contains(m) { "есть" } else { "не найден" }) },
                (None, None) if kconfig.is_none() => Item { what, ok: false, detail: "конфигурация ядра недоступна".into() },
                _ => Item { what, ok: false, detail: "нет в конфигурации ядра".into() },
            }
        })
        .collect()
}

/// Справка расширения iptables показывает опцию, только если расширение есть (а для MARK rev2 — если ядро его отдаёт).
pub fn help_has(text: &str, option: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || c == '[' || c == ']' || c == ',').any(|w| w == option)
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Caps {
    pub kconfig_source: String,
    pub kernel_release: String,
    pub common: Vec<Item>,
    pub tc: Vec<Item>,
    pub netfilter: Vec<Item>,
    pub netfilter_mark: Vec<Item>,
    #[serde(default)]
    pub netfilter_queue: Vec<Item>,
    pub tc_ok: bool,
    pub netfilter_ok: bool,
    pub netfilter_mark_ok: bool,
    #[serde(default)]
    pub netfilter_queue_ok: bool,
}

impl Caps {
    pub fn finish(mut self) -> Self {
        let all = |v: &[Item]| !v.is_empty() && v.iter().all(|i| i.ok);
        let common = all(&self.common);
        self.tc_ok = common && all(&self.tc);
        self.netfilter_ok = common && all(&self.netfilter);
        self.netfilter_mark_ok = self.netfilter_ok && all(&self.netfilter_mark);
        self.netfilter_queue_ok = self.netfilter_ok && all(&self.netfilter_queue);
        self
    }
    pub fn missing(items: &[Item]) -> Vec<String> {
        items.iter().filter(|i| !i.ok).map(|i| format!("{}: {}", i.what, i.detail)).collect()
    }
    /// Выбор механизма: явный запрос или auto (tc, если доступен, иначе netfilter).
    pub fn choose(&self, requested: Option<Marker>) -> Result<Marker, Vec<String>> {
        let common = Self::missing(&self.common);
        match requested {
            Some(Marker::Tc) if self.tc_ok => Ok(Marker::Tc),
            Some(Marker::Tc) => Err([common, Self::missing(&self.tc)].concat()),
            Some(Marker::Netfilter) if self.netfilter_ok => Ok(Marker::Netfilter),
            Some(Marker::Netfilter) => Err([common, Self::missing(&self.netfilter)].concat()),
            None if self.tc_ok => Ok(Marker::Tc),
            None if self.netfilter_ok => Ok(Marker::Netfilter),
            None => Err([common, Self::missing(&self.tc), Self::missing(&self.netfilter)].concat()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Фрагмент реальной конфигурации ядра RC06 1.1.38 (IKCONFIG из образа).
    const STOCK: &str = "CONFIG_IP_MULTIPLE_TABLES=y\nCONFIG_IPV6_MULTIPLE_TABLES=y\nCONFIG_TUN=m\n# CONFIG_NET_CLS_ACT is not set\n# CONFIG_NET_CLS_FLOWER is not set\n# CONFIG_NET_CLS_MATCHALL is not set\nCONFIG_IP_NF_IPTABLES=m\nCONFIG_IP_NF_FILTER=m\nCONFIG_IP_NF_TARGET_REJECT=m\nCONFIG_IP6_NF_IPTABLES=m\nCONFIG_IP6_NF_FILTER=m\nCONFIG_IP6_NF_TARGET_REJECT=m\nCONFIG_NETFILTER_XT_MATCH_MAC=m\nCONFIG_NETFILTER_XT_MATCH_COMMENT=m\nCONFIG_IP_NF_MANGLE=m\nCONFIG_IP6_NF_MANGLE=m\nCONFIG_NETFILTER_XT_MARK=m\nCONFIG_NETFILTER_XT_MATCH_PHYSDEV=m\nCONFIG_BRIDGE_NETFILTER=y\n";
    const STOCK_MODULES: &[&str] = &["tun", "ip_tables", "iptable_filter", "ipt_REJECT", "ip6_tables", "ip6table_filter", "ip6t_REJECT", "xt_mac", "xt_comment", "iptable_mangle", "ip6table_mangle", "xt_mark", "xt_physdev"];

    fn caps(cfg: &str, mods: &[&str]) -> Caps {
        let k = parse_kconfig(cfg);
        let m: BTreeSet<String> = mods.iter().map(|s| s.to_string()).collect();
        Caps {
            common: check_kernel(COMMON, Some(&k), &m),
            tc: check_kernel(TC, Some(&k), &m),
            netfilter: check_kernel(NF, Some(&k), &m),
            netfilter_mark: check_kernel(NF_MARK, Some(&k), &m),
            ..Default::default()
        }
        .finish()
    }

    #[test]
    fn stock_has_no_tc_but_netfilter() {
        let c = caps(STOCK, STOCK_MODULES);
        assert!(!c.tc_ok && c.netfilter_ok && c.netfilter_mark_ok);
        assert_eq!(c.choose(None), Ok(Marker::Netfilter));
        let e = c.choose(Some(Marker::Tc)).unwrap_err();
        assert!(e.iter().any(|x| x.contains("NET_CLS_ACT")), "{e:?}");
        assert!(e.iter().any(|x| x.contains("NET_SCH_INGRESS")), "{e:?}");
    }

    #[test]
    fn missing_module_file_or_option_is_reported() {
        let mods: Vec<&str> = STOCK_MODULES.iter().copied().filter(|m| *m != "xt_mac").collect();
        let c = caps(STOCK, &mods);
        assert!(!c.netfilter_ok);
        let e = c.choose(None).unwrap_err();
        assert!(e.iter().any(|x| x.contains("xt_mac.ko")), "{e:?}");
        let c2 = caps(&STOCK.replace("CONFIG_IP6_NF_FILTER=m", "# CONFIG_IP6_NF_FILTER is not set"), STOCK_MODULES);
        assert!(!c2.netfilter_ok);
    }

    #[test]
    fn help_detection() {
        assert!(help_has("MARK target options:\n  --set-xmark value[/mask]  Clear bits", "--set-xmark"));
        assert!(!help_has("MARK target options:\n  --set-mark value  Set nfmark value", "--set-xmark"));
    }
}
