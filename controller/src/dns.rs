//! DNS роутера для выборочной маршрутизации.
//!
//! Штатный dnsmasq сохраняет DHCP и локальные имена. Для доменов из правил он заносит адреса ответа в ipset правила
//! (`ipset=/домен/набор`): по этим наборам ядро выбирает маршрут. Домены правил «через TrustTunnel» разрешаются через
//! резолвер туннеля (`server=/домен/IP`), а вопросы роутера к этому резолверу ядро отправляет в туннель —
//! провайдер не видит и не подменяет ответ. Блокировка рекламы — `address=/домен/` (NXDOMAIN, вопрос наружу не уходит).

use std::collections::{BTreeMap, BTreeSet};

use crate::model::AdblockConfig;
use crate::validate::{Issue, normalize_domain};

pub const ADBLOCK_MAX_ENTRIES: usize = 200_000;
pub const ADBLOCK_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Разбор списка блокировки: по домену в строке, `#` — комментарий, допускаются строки hosts (`0.0.0.0 домен`).
/// Ошибочная строка — отказ всего списка (действующий список остаётся прежним).
pub fn parse_adblock_list(text: &str) -> Result<Vec<String>, Vec<Issue>> {
    let mut issues = Vec::new();
    let mut out = BTreeSet::new();
    if text.len() > ADBLOCK_MAX_BYTES {
        return Err(vec![Issue::new("adblock", "too_large", format!("список больше {ADBLOCK_MAX_BYTES} байт"))]);
    }
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut f = line.split_whitespace();
        let first = f.next().unwrap_or_default();
        let dom = if matches!(first, "0.0.0.0" | "127.0.0.1" | "::" | "::1") { f.next().unwrap_or_default() } else { first };
        if f.next().is_some() {
            issues.push(Issue::new(format!("adblock[{}]", n + 1), "bad_line", "в строке больше одного домена"));
            continue;
        }
        match normalize_domain(dom, 2) {
            Ok(d) => {
                out.insert(d);
            }
            Err(m) => issues.push(Issue::new(format!("adblock[{}]", n + 1), "bad_domain", m)),
        }
        if issues.len() > 20 {
            break;
        }
    }
    if out.len() > ADBLOCK_MAX_ENTRIES {
        issues.push(Issue::new("adblock", "too_many", format!("больше {ADBLOCK_MAX_ENTRIES} доменов")));
    }
    if issues.is_empty() { Ok(out.into_iter().collect()) } else { Err(issues) }
}

/// Что нужно dnsmasq от правил: в какие наборы заносить адреса доменов и какие домены разрешать через туннель.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DnsPlan {
    /// домен → наборы ipset (dnsmasq сопоставляет домен вместе с поддоменами).
    pub sets: BTreeMap<String, BTreeSet<String>>,
    /// Домены правил «через TrustTunnel»: их вопросы идут к резолверу туннеля.
    pub tunnel_domains: BTreeSet<String>,
    /// IPv4 резолвера туннеля.
    pub resolver: String,
}

/// Файл для каталога conf-dir dnsmasq. Пустая строка — файл не нужен.
pub fn dnsmasq_conf(plan: &DnsPlan, adblock: Option<&AdblockConfig>, blocked: &[String]) -> String {
    let mut s = String::new();
    if !plan.sets.is_empty() {
        s.push_str(&format!("# mi-trusttunnel: адреса доменов правил → ipset ({} доменов)\n", plan.sets.len()));
        for (d, sets) in &plan.sets {
            s.push_str(&format!("ipset=/{d}/{}\n", sets.iter().cloned().collect::<Vec<_>>().join(",")));
        }
    }
    if !plan.tunnel_domains.is_empty() {
        s.push_str(&format!("# домены «через TrustTunnel» разрешаются через {} в туннеле\n", plan.resolver));
        for d in &plan.tunnel_domains {
            s.push_str(&format!("server=/{d}/{}\n", plan.resolver));
        }
    }
    if let Some(AdblockConfig { enabled: true, exceptions }) = adblock {
        s.push_str(&format!("# блокировка рекламы: {} доменов (NXDOMAIN для A и AAAA, вопрос наружу не уходит)\n", blocked.len()));
        for b in blocked {
            s.push_str(&format!("address=/{b}/\n"));
        }
        for e in exceptions {
            // `#` — обычные вышестоящие серверы dnsmasq: исключение снимает блокировку родительского домена
            let up = if plan.tunnel_domains.iter().any(|t| e == t || e.ends_with(&format!(".{t}"))) { plan.resolver.clone() } else { "#".into() };
            s.push_str(&format!("server=/{e}/{up}\n"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adblock_list_strict() {
        assert_eq!(parse_adblock_list("# c\nads.example\n0.0.0.0 tracker.example # x\n\nADS.example\n").unwrap(), ["ads.example", "tracker.example"]);
        assert!(parse_adblock_list("ok.example\nbad domain here\n").is_err());
        assert!(parse_adblock_list("ok.example\n-bad-.example\n").is_err());
    }

    #[test]
    fn conf_has_ipsets_tunnel_servers_and_adblock() {
        let mut p = DnsPlan { resolver: "1.1.1.1".into(), ..Default::default() };
        p.sets.insert("youtube.com".into(), ["mitt1d".to_string(), "mitt2d".to_string()].into());
        p.tunnel_domains.insert("youtube.com".into());
        let a = AdblockConfig { enabled: true, exceptions: vec!["ok.ads.example".into()] };
        let c = dnsmasq_conf(&p, Some(&a), &["ads.example".into()]);
        assert!(c.contains("ipset=/youtube.com/mitt1d,mitt2d\n"), "{c}");
        assert!(c.contains("server=/youtube.com/1.1.1.1\n"), "{c}");
        assert!(c.contains("address=/ads.example/\n") && c.contains("server=/ok.ads.example/#\n"), "{c}");
        assert!(!c.contains("no-resolv"), "провайдерский DNS остаётся для остальных доменов");
        assert_eq!(dnsmasq_conf(&DnsPlan::default(), None, &[]), "");
    }
}
