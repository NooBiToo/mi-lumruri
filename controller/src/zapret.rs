//! Каталог стратегий Zapret (zapret2, nfqws2) и аргументы nfqws2 по выбору из него.
//! Стратегии взяты из StressOzz/Zapret-Manager (Apache-2.0, см. NOTICE): общая и YouTube — круговой режим
//! (`circular` сам переключает стратегию для сайта, соединения с которым срываются) или одна из его групп;
//! постоянные профили — Discord (TLS, discord.media, голос по UDP) и YouTube по QUIC.
//! Блобы и списки хостов лежат рядом с nfqws2 (`--chdir` без пути = каталог программы).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde::Deserialize;

use crate::model::ZapretConfig;
use crate::plan::ZAPRET_DESYNC_MARK;

pub const AUTO: &str = "auto";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    /// Имя блоба в аргументах → файл.
    pub blobs: BTreeMap<String, String>,
    /// Список хостов (`youtube`, `discord`) → файл.
    pub hostlists: BTreeMap<String, String>,
    /// Постоянные профили: действуют при любом выборе стратегий.
    pub always: Vec<ZProfile>,
    pub strategies: Vec<Strategy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Strategy {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub profiles: Vec<ZProfile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    General,
    Youtube,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// Профиль nfqws2: фильтры (порты, протокол L7, списки хостов) и аргументы Lua-обработки.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZProfile {
    pub proto: Proto,
    /// Порты назначения через запятую, диапазоны через дефис (как в `--filter-tcp`).
    pub ports: String,
    #[serde(default)]
    pub l7: Vec<String>,
    #[serde(default)]
    pub hostlist: Option<String>,
    #[serde(default)]
    pub hostlist_exclude: Vec<String>,
    pub args: Vec<String>,
}

pub fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(include_str!("../data/zapret-strategies.json")).expect("каталог стратегий Zapret"))
}

impl Catalog {
    pub fn find(&self, kind: Kind, id: &str) -> Option<&Strategy> {
        self.strategies.iter().find(|s| s.kind == kind && s.id == id)
    }
}

/// Проверка выбора: `None` — стратегия есть в каталоге и нужного вида, иначе код и сообщение.
pub fn check(kind: Kind, id: &str) -> Option<(&'static str, String)> {
    let c = catalog();
    if c.find(kind, id).is_some() {
        None
    } else if c.strategies.iter().any(|s| s.id == id) {
        Some(("wrong_kind", format!("«{id}» — стратегия {}, а здесь нужна стратегия {}", what(if kind == Kind::General { Kind::Youtube } else { Kind::General }), what(kind))))
    } else {
        Some(("unknown_strategy", format!("стратегии «{id}» нет в каталоге")))
    }
}

fn what(k: Kind) -> &'static str {
    match k {
        Kind::General => "для всех сайтов",
        Kind::Youtube => "для YouTube",
    }
}

/// Профили по порядку проверки nfqws2 (первый подходящий): постоянные, YouTube, общая стратегия.
pub fn selected(cfg: &ZapretConfig) -> Vec<&'static ZProfile> {
    let c = catalog();
    // неизвестный выбор отклоняет проверка настроек; здесь на всякий случай — круговой режим
    let pick = |kind, id: &str| &c.find(kind, id).or_else(|| c.find(kind, AUTO)).expect("auto есть в каталоге").profiles;
    c.always.iter().chain(pick(Kind::Youtube, &cfg.youtube)).chain(pick(Kind::General, &cfg.strategy)).collect()
}

/// Имена блобов в параметрах `--lua-desync` (`blob=`, `seqovl_pattern=`, `pattern=`).
fn blob_refs(arg: &str) -> impl Iterator<Item = &str> {
    arg.strip_prefix("--lua-desync=")
        .into_iter()
        .flat_map(|d| d.split(':'))
        .filter_map(|p| p.split_once('='))
        .filter(|(k, _)| matches!(*k, "blob" | "seqovl_pattern" | "pattern"))
        .map(|(_, v)| v)
}

/// Аргументы nfqws2: очередь, метка своих пакетов, Lua-библиотеки, используемые блобы, затем профили через `--new`.
pub fn nfqws2_args(cfg: &ZapretConfig, qnum: u16) -> Vec<String> {
    let c = catalog();
    let profiles = selected(cfg);
    let used: BTreeSet<&str> = profiles.iter().flat_map(|p| p.args.iter().flat_map(|a| blob_refs(a))).collect();
    let mut a: Vec<String> = vec![format!("--qnum={qnum}"), format!("--fwmark=0x{ZAPRET_DESYNC_MARK:x}"), "--chdir".into()];
    a.extend(["zapret-lib", "zapret-antidpi", "zapret-auto"].map(|l| format!("--lua-init=@{l}.lua.gz")));
    a.extend(c.blobs.iter().filter(|(n, _)| used.contains(n.as_str())).map(|(n, f)| format!("--blob={n}:@{f}")));
    for (i, p) in profiles.iter().enumerate() {
        if i > 0 {
            a.push("--new".into());
        }
        a.push(format!("--filter-{}={}", p.proto.as_str(), p.ports));
        if !p.l7.is_empty() {
            a.push(format!("--filter-l7={}", p.l7.join(",")));
        }
        a.extend(p.hostlist.iter().map(|h| format!("--hostlist={}", c.hostlists[h])));
        a.extend(p.hostlist_exclude.iter().map(|h| format!("--hostlist-exclude={}", c.hostlists[h])));
        a.extend(p.args.iter().cloned());
    }
    a
}

/// Порты очереди NFQUEUE по протоколу: объединение портов выбранных профилей.
pub fn queue(cfg: &ZapretConfig) -> Vec<(Proto, String)> {
    let profiles = selected(cfg);
    [Proto::Tcp, Proto::Udp]
        .into_iter()
        .filter_map(|proto| {
            let mut ports: Vec<&str> = profiles.iter().filter(|p| p.proto == proto).flat_map(|p| p.ports.split(',')).collect();
            ports.sort_by_key(|x| (x.split('-').next().and_then(|n| n.parse::<u16>().ok()), *x));
            ports.dedup();
            (!ports.is_empty()).then(|| (proto, ports.join(",")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Config;
    use crate::validate::validate_config;

    #[test]
    fn catalog_is_consistent() {
        let c = catalog();
        let profiles: Vec<&ZProfile> = c.always.iter().chain(c.strategies.iter().flat_map(|s| &s.profiles)).collect();
        for p in &profiles {
            // блобы, которые профиль создаёт сам (tls_client_hello_clone:blob=…), объявлять не нужно
            let mut own = BTreeSet::new();
            for a in &p.args {
                assert!(a.starts_with("--") && !a.contains(|ch: char| ch.is_whitespace() || "*?[]'\"\\$`".contains(ch)), "аргумент без пробелов и спецсимволов оболочки: {a}");
                if let Some(b) = a.strip_prefix("--lua-desync=tls_client_hello_clone:").and_then(|r| r.split(':').find_map(|x| x.strip_prefix("blob="))) {
                    own.insert(b);
                    continue;
                }
                for b in blob_refs(a) {
                    assert!(c.blobs.contains_key(b) || own.contains(b) || b.starts_with("fake_default_") || b.starts_with("0x"), "блоб {b} не объявлен: {a}");
                }
            }
            for h in p.hostlist.iter().chain(&p.hostlist_exclude) {
                assert!(c.hostlists.contains_key(h), "нет списка хостов {h}");
            }
            assert!(!p.ports.is_empty() && p.ports.split(',').all(|x| x.split('-').all(|n| n.parse::<u16>().is_ok_and(|n| n > 0))), "порты {}", p.ports);
            // до разделения очереди по протоколам (план) TCP-порты — только одиночные
            assert!(p.proto == Proto::Udp || p.ports.split(',').all(|x| x.parse::<u16>().is_ok()), "{}", p.ports);
        }
        // каждый объявленный блоб используется, файлы — простые имена
        for (b, f) in &c.blobs {
            assert!(profiles.iter().any(|p| p.args.iter().any(|a| blob_refs(a).any(|x| x == b))), "лишний блоб {b}");
            assert!(f.ends_with(".bin") && !f.contains('/'), "{f}");
        }
        let ids: BTreeSet<(&str, bool)> = c.strategies.iter().map(|s| (s.id.as_str(), s.kind == Kind::General)).collect();
        assert_eq!(ids.len(), c.strategies.len(), "id стратегий уникальны в своём виде");
        assert!(c.find(Kind::General, AUTO).is_some() && c.find(Kind::Youtube, AUTO).is_some());
        assert!(c.strategies.iter().filter(|s| s.kind == Kind::General).count() >= 8);
        for s in &c.strategies {
            assert!(!s.profiles.is_empty() && !s.name.is_empty(), "{}", s.id);
            let circular = s.profiles.iter().any(|p| p.args.iter().any(|a| a.contains("=circular:")));
            assert_eq!(circular, s.id == AUTO, "круговой режим — только у auto: {}", s.id);
            if s.id != AUTO {
                assert!(!s.profiles.iter().flat_map(|p| &p.args).any(|a| a.contains(":strategy=") || a.ends_with(":final")), "{}", s.id);
            }
        }
    }

    #[test]
    fn auto_args_have_circular_and_profiles() {
        let a = nfqws2_args(&ZapretConfig::default(), 200);
        assert_eq!(&a[..6], ["--qnum=200", "--fwmark=0x40000000", "--chdir", "--lua-init=@zapret-lib.lua.gz", "--lua-init=@zapret-antidpi.lua.gz", "--lua-init=@zapret-auto.lua.gz"]);
        assert!(a.iter().any(|x| x.contains("=circular:")), "{a:#?}");
        assert!(a.iter().filter(|x| *x == "--new").count() >= 4, "{a:#?}");
        // блобы загружаются до профилей, только используемые, из файлов каталога
        let first_new = a.iter().position(|x| x == "--new").unwrap();
        assert!(a.contains(&"--blob=blob_stun:@stun.bin".to_string()));
        assert!(a.iter().skip(first_new).all(|x| !x.starts_with("--blob=")));
        // фильтры профилей
        for want in ["--filter-tcp=443", "--filter-udp=443", "--filter-l7=tls,discord", "--hostlist=zapret-hosts-discord.txt", "--hostlist=zapret-hosts-youtube.txt",
            "--hostlist-exclude=zapret-hosts-youtube.txt", "--filter-udp=19294-19344,50000-50100"] {
            assert!(a.iter().any(|x| x == want), "нет {want}: {a:#?}");
        }
        // общий профиль последний: без списка хостов он перехватил бы Discord
        let last = &a[a.iter().rposition(|x| x == "--new").unwrap()..];
        assert!(last.contains(&"--hostlist-exclude=zapret-hosts-youtube.txt".to_string()) && !last.iter().any(|x| x.starts_with("--hostlist=")), "{last:#?}");

        let v3 = nfqws2_args(&ZapretConfig { strategy: "v3".into(), youtube: "yv4".into() }, 201);
        assert_eq!(v3[0], "--qnum=201");
        let last = &v3[v3.iter().rposition(|x| x == "--new").unwrap()..];
        assert!(last.iter().any(|x| x == "--lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-600000:tcp_md5:repeats=4"), "{last:#?}");
        assert!(!last.iter().any(|x| x.contains("strategy=") || x.contains("circular")), "{last:#?}");
        // у выбранной YouTube-стратегии кругового режима нет; круговой остаётся только у Discord
        assert_eq!(v3.iter().filter(|x| x.contains("=circular:")).count(), 1, "{v3:#?}");
        assert!(v3.iter().any(|x| x.starts_with("--lua-desync=tls_client_hello_clone:blob=cloned_tls")));
        // загружаются только блобы выбранных профилей (cloned_tls создаёт сам профиль)
        let blobs: Vec<&str> = v3.iter().filter(|x| x.starts_with("--blob=")).map(String::as_str).collect();
        assert_eq!(blobs, ["--blob=blob_quic_initial_www_google_com:@quic_initial_www_google_com.bin", "--blob=blob_tls_clienthello_www_google_com:@tls_clienthello_www_google_com.bin"]);
    }

    #[test]
    fn selected_order_and_queue() {
        let p = selected(&ZapretConfig::default());
        assert_eq!(p.len(), 6);
        assert_eq!(p[0].hostlist.as_deref(), Some("discord"));
        assert!(std::ptr::eq(p[4], &catalog().find(Kind::Youtube, AUTO).unwrap().profiles[0]));
        assert!(std::ptr::eq(p[5], &catalog().find(Kind::General, AUTO).unwrap().profiles[0]));
        assert_eq!(
            queue(&ZapretConfig::default()),
            [(Proto::Tcp, "443,2053,2083,2087,2096,8443".to_string()), (Proto::Udp, "443,19294-19344,50000-50100".to_string())]
        );
    }

    fn cfg(z: serde_json::Value) -> Config {
        serde_json::from_value(serde_json::json!({ "version": 1, "default_action": { "type": "direct" }, "zapret": z })).unwrap()
    }

    #[test]
    fn unknown_strategy_rejected() {
        let codes = |z| validate_config(&cfg(z)).into_iter().map(|i| format!("{}:{}", i.path, i.code)).collect::<Vec<_>>();
        assert!(codes(serde_json::json!({})).is_empty(), "по умолчанию — auto");
        assert!(codes(serde_json::json!({ "strategy": "v10", "youtube": "yv22" })).is_empty());
        assert_eq!(codes(serde_json::json!({ "strategy": "nope" })), ["zapret.strategy:unknown_strategy"]);
        assert_eq!(codes(serde_json::json!({ "strategy": "yv1", "youtube": "v1" })), ["zapret.strategy:wrong_kind", "zapret.youtube:wrong_kind"]);
        // прежние поля не принимаются
        assert!(serde_json::from_value::<Config>(serde_json::json!({ "version": 1, "default_action": { "type": "direct" }, "zapret": { "strategy": "auto", "pos": 2 } })).is_err());
    }
}
