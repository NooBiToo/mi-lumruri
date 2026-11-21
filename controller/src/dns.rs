//! DNS роутера для выборочной маршрутизации.
//!
//! Штатный dnsmasq сохраняет DHCP и локальные имена. Для доменов из правил он заносит адреса ответа в ipset правила
//! (`ipset=/домен/набор`): по этим наборам ядро выбирает маршрут. Домены правил «через TrustTunnel» разрешаются через
//! резолвер туннеля (`server=/домен/IP`), а вопросы роутера к этому резолверу ядро отправляет в туннель —
//! провайдер не видит и не подменяет ответ. Блокировка рекламы — `address=/домен/` (NXDOMAIN, вопрос наружу не уходит).

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{AdblockConfig, DNS_PROXY_PORT, HostRecord};
use crate::validate::{Issue, normalize_domain};

pub const ADBLOCK_MAX_ENTRIES: usize = 300_000;
pub const ADBLOCK_MAX_BYTES: usize = 12 * 1024 * 1024;

/// Разбор списка блокировки: по домену в строке, `#` и `!` — комментарии, допускаются строки hosts (`0.0.0.0 домен`).
/// Строки, которые не разобрать, пропускаются (их число — `skipped`): один кривой домен в скачанном списке не должен
/// останавливать обновление. Отказ — если это не список (HTML, пусто) или ошибочных строк больше 5 % (и больше 20).
pub fn parse_adblock_list(text: &str) -> Result<(Vec<String>, usize), Vec<Issue>> {
    let mut out = BTreeSet::new();
    let mut skipped = 0usize;
    let mut first_bad: Option<Issue> = None;
    if text.len() > ADBLOCK_MAX_BYTES {
        return Err(vec![Issue::new("adblock", "too_large", format!("список больше {ADBLOCK_MAX_BYTES} байт"))]);
    }
    if text.trim_start().starts_with('<') {
        return Err(vec![Issue::new("adblock", "not_a_list", "это не список доменов (похоже на страницу HTML)")]);
    }
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with('!') {
            continue;
        }
        let mut f = line.split_whitespace();
        let first = f.next().unwrap_or_default();
        let dom = if matches!(first, "0.0.0.0" | "127.0.0.1" | "::" | "::1") { f.next().unwrap_or_default() } else { first };
        let parsed = if f.next().is_some() { Err("в строке больше одного домена".to_string()) } else { normalize_domain(dom, 2) };
        match parsed {
            Ok(d) => {
                out.insert(d);
            }
            Err(m) => {
                skipped += 1;
                first_bad.get_or_insert_with(|| Issue::new(format!("adblock[{}]", n + 1), "bad_domain", m));
            }
        }
    }
    if skipped > 20 && skipped * 20 > out.len() + skipped {
        return Err(vec![first_bad.unwrap_or_else(|| Issue::new("adblock", "bad_list", "много строк не разобрано")),
            Issue::new("adblock", "too_many_bad", format!("не разобрано строк: {skipped} — это не похоже на список доменов"))]);
    }
    if out.is_empty() {
        return Err(vec![Issue::new("adblock", "empty", "в списке нет ни одного домена")]);
    }
    if out.len() > ADBLOCK_MAX_ENTRIES {
        return Err(vec![Issue::new("adblock", "too_many", format!("больше {ADBLOCK_MAX_ENTRIES} доменов"))]);
    }
    Ok((out.into_iter().collect(), skipped))
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
pub fn dnsmasq_conf(plan: &DnsPlan, adblock: Option<&AdblockConfig>, blocked: &[String], hosts: &[HostRecord], secure: bool) -> String {
    let mut s = String::new();
    if secure {
        // остальные домены — через mi-tt-dns (DoH/DoT); DNS провайдера dnsmasq больше не спрашивает (no-resolv), его
        // как запасной путь использует сам прокси. Домены туннеля и свои записи ниже — точнее этого правила и важнее.
        s.push_str(&format!("# защищённый DNS: остальные домены — через mi-tt-dns (DoH/DoT)\nno-resolv\nserver=127.0.0.1#{DNS_PROXY_PORT}\n"));
    }
    if !hosts.is_empty() {
        s.push_str("# свои записи: домен вместе с поддоменами отвечает этим адресом, вопрос наружу не уходит\n");
        for h in hosts {
            let d = normalize_domain(&h.domain, 1).unwrap_or_else(|_| h.domain.clone());
            let a: std::net::IpAddr = h.address.parse().expect("проверено");
            s.push_str(&format!("address=/{d}/{a}\n"));
        }
    }
    if !plan.sets.is_empty() {
        s.push_str(&format!("# mi-lumruri: адреса доменов правил → ipset ({} доменов)\n", plan.sets.len()));
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
    if let Some(AdblockConfig { enabled: true, exceptions, .. }) = adblock {
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
        let (d, skipped) = parse_adblock_list("# c\nads.example\n0.0.0.0 tracker.example # x\n\n! adblock\nADS.example\n").unwrap();
        assert_eq!((d, skipped), (vec!["ads.example".to_string(), "tracker.example".to_string()], 0));
        // единичная кривая строка пропускается, список не отвергается
        assert_eq!(parse_adblock_list("ok.example\nbad domain here\n").unwrap(), (vec!["ok.example".to_string()], 1));
        assert!(parse_adblock_list("<!DOCTYPE html><html>").is_err());
        assert!(parse_adblock_list("# only comments\n").is_err());
        let junk: String = (0..30).map(|i| format!("bad_{i} line\n")).collect();
        assert!(parse_adblock_list(&format!("ok.example\n{junk}")).is_err());
        assert_eq!(parse_adblock_list("ok.example\n-bad-.example\n").unwrap().1, 1);
    }

    #[test]
    fn conf_has_ipsets_tunnel_servers_and_adblock() {
        let mut p = DnsPlan { resolver: "1.1.1.1".into(), ..Default::default() };
        p.sets.insert("youtube.com".into(), ["mitt1d".to_string(), "mitt2d".to_string()].into());
        p.tunnel_domains.insert("youtube.com".into());
        let a = AdblockConfig { enabled: true, exceptions: vec!["ok.ads.example".into()], source: Default::default(), url: None };
        let c = dnsmasq_conf(&p, Some(&a), &["ads.example".into()], &[], false);
        assert!(c.contains("ipset=/youtube.com/mitt1d,mitt2d\n"), "{c}");
        assert!(c.contains("server=/youtube.com/1.1.1.1\n"), "{c}");
        assert!(c.contains("address=/ads.example/\n") && c.contains("server=/ok.ads.example/#\n"), "{c}");
        assert!(!c.contains("no-resolv"), "провайдерский DNS остаётся для остальных доменов");
        assert_eq!(dnsmasq_conf(&DnsPlan::default(), None, &[], &[], false), "");
        let s = dnsmasq_conf(&DnsPlan::default(), None, &[], &[], true);
        assert!(s.contains("no-resolv") && s.contains("server=127.0.0.1#5453"), "{s}");
    }

    #[test]
    fn own_host_records() {
        let h = [HostRecord { domain: "Home.Example.com".into(), address: "192.168.31.10".into() }, HostRecord { domain: "nas".into(), address: "fd00::0:5".into() }];
        let c = dnsmasq_conf(&DnsPlan::default(), None, &[], &h, false);
        assert!(c.contains("address=/home.example.com/192.168.31.10\n") && c.contains("address=/nas/fd00::5\n"), "{c}");
    }
}
