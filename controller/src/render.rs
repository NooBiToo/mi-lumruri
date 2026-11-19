//! Формирование действующей конфигурации из сохранённых настроек:
//!  - client.toml для официального клиента TrustTunnel (TUN `mitt0`, маршруты держит mi-tt-admin, не клиент);
//!  - спецификация политики: правила по порядку (источник, набор назначения, действие) и наборы ipset;
//!  - план для dnsmasq: в какие наборы заносить адреса доменов и какие домены разрешать через туннель;
//!  - аргументы nfqws2 для Zapret.
//! Принцип: если политику нельзя выразить точно (нет моста, портов, подсети, пароля), не формируется ничего.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dns::DnsPlan;
use crate::model::*;
use crate::plan::{Act, Entry, PolicyRule, PolicySpec, QueueRule, SET_PREFIX, SetKind, SetSpec, SrcMatch, ZAPRET_QNUM, build_plan};
use crate::preview::{Dest, evaluation_order, expand, normalize_destination};
use crate::validate::{Index, Issue, normalize_domain, normalize_mac, parse_cidr, plain_text, validate_config};
use crate::zapret;

pub const TUN_DEVICE: &str = "mitt0";
pub const TUN_MTU: u16 = 1350;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    pub version: u32,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileSecret>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSecret {
    /// Пароль пользователя TrustTunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// Пароль задан и пригоден для client.toml.
pub fn check_secret(s: &ProfileSecret) -> Result<(), &'static str> {
    match s.password.as_deref() {
        None | Some("") => Err("нужен непустой password"),
        Some(p) if p.len() > 256 => Err("пароль длиннее 256 символов"),
        Some(p) if p.chars().any(char::is_control) => Err("пароль содержит управляющие символы"),
        _ => Ok(()),
    }
}

#[derive(Debug, Serialize)]
pub struct Routes {
    /// Команды по порядку (первый элемент — программа). Для информации: применяет mi-tt-admin с учётом живого состояния.
    pub apply: Vec<Vec<String>>,
    pub revert: Vec<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct Rendered {
    pub policy: PolicySpec,
    /// План без живого контекста (для обзора и тестов).
    pub plan: Vec<Entry>,
    pub routes: Routes,
    /// Конфигурация клиента TrustTunnel (с паролем); None — туннель не нужен.
    #[serde(skip)]
    pub client_toml: Option<String>,
    #[serde(skip)]
    pub dns: DnsPlan,
    pub warnings: Vec<String>,
    /// Аргументы nfqws2 (по одному на строку в nfqws2.args), если используется Zapret.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nfqws2_args: Vec<String>,
}

/// Списки категорий: id → записи (домены или IP-префиксы), как их вернул `parse_category_list`.
pub type Lists = BTreeMap<String, Vec<String>>;

/// Список категории: по записи в строке, `#` — комментарий. Домены — суффиксы (допускаются `+.`, `*.` и ведущая `.`),
/// IP — префиксы IPv4/IPv6. Ошибочная строка — отказ всего списка.
pub fn parse_category_list(kind: CategoryKind, text: &str) -> Result<Vec<String>, Vec<Issue>> {
    let mut out = BTreeSet::new();
    let mut issues = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let r = match kind {
            CategoryKind::Domain => {
                let d = line.trim_start_matches("+.").trim_start_matches("*.");
                normalize_domain(d.strip_prefix('.').unwrap_or(d), 1)
            },
            CategoryKind::Ip => parse_cidr(line).map(|c| c.to_string()),
        };
        match r {
            Ok(v) => {
                out.insert(v);
            }
            Err(m) => issues.push(Issue::new(format!("list[{}]", n + 1), "bad_entry", m)),
        }
        if issues.len() > 20 {
            break;
        }
    }
    if out.len() > 100_000 {
        issues.push(Issue::new("list", "too_many", "больше 100 000 записей"));
    }
    if issues.is_empty() && out.is_empty() {
        issues.push(Issue::new("list", "empty", "пустой список"));
    }
    if issues.is_empty() { Ok(out.into_iter().collect()) } else { Err(issues) }
}

/// Категории, на которые ссылаются включённые правила.
pub fn used_categories(cfg: &Config) -> BTreeSet<String> {
    let idx = Index::new(cfg);
    evaluation_order(&cfg.rules)
        .iter()
        .flat_map(|r| expand(&r.destination, &idx))
        .filter_map(|d| if let Dest::Category(id) = d { Some(id) } else { None })
        .collect()
}

/// Списки используемых категорий из `categories/<id>.list` рядом с настройками. Нет или ошибочный список — отказ:
/// правило не применяется молча без своих назначений.
pub fn load_lists(cfg: &Config, config_path: &Path) -> Result<Lists, String> {
    let mut out = Lists::new();
    for id in used_categories(cfg) {
        let c = cfg.categories.iter().find(|c| c.id == id).ok_or(format!("категория {id} не найдена"))?;
        let src = config_path.with_file_name("categories").join(format!("{id}.list"));
        let text = crate::api::read_limited(&src.to_string_lossy(), 8 * 1024 * 1024).map_err(|e| format!("список категории «{id}»: {e}"))?;
        let entries = parse_category_list(c.kind, &String::from_utf8_lossy(&text))
            .map_err(|i| format!("список категории «{id}» не прошёл проверку: {}", i.iter().map(|x| format!("{} {}", x.path, x.message)).collect::<Vec<_>>().join("; ")))?;
        out.insert(id, entries);
    }
    Ok(out)
}

fn zapret_queue(z: &ZapretConfig) -> Vec<QueueRule> {
    zapret::queue(z).into_iter().map(|(p, ports)| QueueRule { proto: p.as_str().into(), ports }).collect()
}

fn toml_str(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

/// client.toml для trusttunnel_client 1.1.x. Маршруты (`included_routes`) пустые: выбор маршрута держит
/// mi-tt-admin (метка и таблица 3100), клиент только создаёт TUN `mitt0` и передаёт в туннель то, что в него пришло.
pub fn client_toml(e: &Endpoint, password: &str) -> String {
    let ip: std::net::IpAddr = e.server.parse().expect("проверено");
    let addr = if ip.is_ipv6() { format!("[{ip}]:{}", e.port) } else { format!("{ip}:{}", e.port) };
    let host = e.sni.as_deref().map(|s| normalize_domain(s, 1).unwrap_or_else(|_| s.to_string())).unwrap_or_else(|| e.server.clone());
    let cert = match &e.certificate {
        Some(c) => format!("certificate = '''\n{}\n'''", c.trim()),
        None => "certificate = \"\"".into(),
    };
    format!(
        "# mi-trusttunnel: сформировано автоматически, правки перезаписываются\n\
loglevel = \"info\"\n\
vpn_mode = \"general\"\n\
killswitch_enabled = false\n\
post_quantum_group_enabled = true\n\
exclusions = []\n\
\n\
[endpoint]\n\
hostname = {host}\n\
addresses = [{addr}]\n\
custom_sni = \"\"\n\
has_ipv6 = false\n\
username = {user}\n\
password = {pass}\n\
client_random = \"\"\n\
skip_verification = false\n\
{cert}\n\
upstream_protocol = \"{proto}\"\n\
anti_dpi = {anti}\n\
dns_upstreams = []\n\
\n\
[listener.tun]\n\
device_name = \"{TUN_DEVICE}\"\n\
included_routes = []\n\
excluded_routes = []\n\
mtu_size = {TUN_MTU}\n\
change_system_dns = false\n",
        host = toml_str(&host),
        addr = toml_str(&addr),
        user = toml_str(&e.username),
        pass = toml_str(password),
        proto = if e.quic { "http3" } else { "http2" },
        anti = e.anti_dpi,
    )
}

/// Имя набора по назначению правила: одно назначение в разных правилах — один набор.
fn set_base(d: &Destination) -> String {
    let h = Sha256::digest(serde_json::to_vec(&normalize_destination(d)).unwrap_or_default());
    format!("{SET_PREFIX}{}", h.iter().take(6).map(|b| format!("{b:02x}")).collect::<String>())
}

pub fn render(cfg: &Config, secrets: &Secrets, lists: &Lists) -> Result<Rendered, Vec<Issue>> {
    let base = validate_config(cfg);
    if !base.is_empty() {
        return Err(base.into_iter().map(|i| Issue { path: format!("config.{}", i.path), ..i }).collect());
    }
    let idx = Index::new(cfg);
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if secrets.version != 1 {
        issues.push(Issue::new("secrets.version", "unsupported_version", "поддерживается версия secrets.json 1"));
    }
    let mut tunnel_profile: Option<&Profile> = None;
    let mut act_of = |a: &Action, path: &str, issues: &mut Vec<Issue>| -> Option<Act> {
        match a {
            Action::Direct => Some(Act::Direct),
            Action::DirectZapret => Some(Act::Zapret),
            Action::Block => Some(Act::Block),
            Action::Profile { id } => {
                let p = idx.profiles[id.as_str()];
                if p.endpoint.is_none() {
                    issues.push(Issue::new(path, "no_endpoint", format!("у профиля «{id}» нет точки подключения")));
                    return None;
                }
                match secrets.profiles.get(id).map(check_secret) {
                    None => {
                        issues.push(Issue::new(path, "no_secret", format!("нет пароля профиля «{id}» в secrets.json")));
                        return None;
                    }
                    Some(Err(m)) => {
                        issues.push(Issue::new(path, "bad_secret", format!("секреты профиля «{id}»: {m}")));
                        return None;
                    }
                    Some(Ok(())) => {}
                }
                tunnel_profile = Some(p);
                Some(Act::Tunnel)
            }
        }
    };

    let net_subnet = |n: &Network| n.subnet.as_deref().and_then(|s| parse_cidr(s).ok()).filter(|c| c.addr.is_ipv4()).map(|c| c.to_string());
    let lan_bridges = || -> Result<Vec<String>, Issue> {
        let mut v = BTreeSet::new();
        for n in &cfg.networks {
            match (&n.bridge, net_subnet(n)) {
                (Some(b), Some(_)) => {
                    v.insert(b.clone());
                }
                _ => return Err(Issue::new("networks", "no_subnet", format!("для правил всей LAN у сети «{}» нужны bridge и IPv4 subnet", n.id))),
            }
        }
        if v.is_empty() {
            return Err(Issue::new("networks", "no_networks", "для правил всей LAN нужна хотя бы одна сеть с мостом и подсетью"));
        }
        Ok(v.into_iter().collect())
    };

    let mut rules: Vec<PolicyRule> = Vec::new();
    let mut sets: BTreeMap<String, SetSpec> = BTreeMap::new();
    let mut dns = DnsPlan { resolver: cfg.dns.as_ref().map(|d| d.resolver().to_string()).unwrap_or_else(|| DEFAULT_TUNNEL_RESOLVER.into()), ..Default::default() };
    let mut v6_block: BTreeSet<SrcMatch> = BTreeSet::new();
    let (mut exact_warned, mut v6_warned) = (false, false);

    for r in evaluation_order(&cfg.rules) {
        let pos = cfg.rules.iter().position(|x| x.id == r.id).unwrap_or(0);
        let path = format!("rules[{pos}]");
        let srcs: Vec<SrcMatch> = match &r.source {
            Source::Device { id } => {
                let d = idx.devices[id.as_str()];
                let n = idx.networks[d.network.as_str()];
                let Some(bridge) = n.bridge.clone() else {
                    issues.push(Issue::new(format!("{path}.source"), "no_bridge", format!("у сети «{}» устройства «{}» не задан мост", n.id, d.id)));
                    continue;
                };
                vec![SrcMatch::Mac { bridge, mac: normalize_mac(&d.mac).unwrap_or_default() }]
            }
            Source::Network { id } => {
                let n = idx.networks[id.as_str()];
                let (Some(_), Some(bridge)) = (net_subnet(n), n.bridge.clone()) else {
                    issues.push(Issue::new(format!("{path}.source"), "no_subnet", format!("у сети «{id}» нужны IPv4 subnet и bridge")));
                    continue;
                };
                if n.ports.is_empty() {
                    issues.push(Issue::new(format!("{path}.source"), "no_ports", format!("у сети «{id}» не заданы порты моста (интерфейсы SSID)")));
                    continue;
                }
                vec![SrcMatch::Network { bridge, ports: n.ports.clone() }]
            }
            Source::Lan => match lan_bridges() {
                Ok(b) => b.into_iter().map(|bridge| SrcMatch::Bridge { bridge }).collect(),
                Err(i) => {
                    issues.push(i);
                    continue;
                }
            },
        };
        let Some(act) = act_of(&r.action, &format!("{path}.action"), &mut issues) else { continue };
        let (mut domains, mut nets) = (BTreeSet::new(), BTreeSet::new());
        for d in expand(&r.destination, &idx) {
            match d {
                Dest::Domain(x) => {
                    exact_warned = true;
                    domains.insert(x);
                }
                Dest::Suffix(x) => {
                    domains.insert(x);
                }
                Dest::Net(c) if c.addr.is_ipv4() => {
                    nets.insert(c.to_string());
                }
                Dest::Net(_) => v6_warned = true,
                Dest::Category(id) => {
                    let kind = idx.categories[id.as_str()].kind;
                    for e in lists.get(&id).map(Vec::as_slice).unwrap_or_default() {
                        match kind {
                            CategoryKind::Domain => {
                                domains.insert(e.clone());
                            }
                            CategoryKind::Ip if !e.contains(':') => {
                                nets.insert(e.clone());
                            }
                            CategoryKind::Ip => v6_warned = true,
                        }
                    }
                }
            }
        }
        let base = set_base(&r.destination);
        let mut add_rule = |name: String, kind: SetKind, entries: Vec<String>| {
            sets.entry(name.clone()).or_insert(SetSpec { name: name.clone(), kind, entries });
            for src in &srcs {
                rules.push(PolicyRule { from: r.id.clone(), src: src.clone(), set: Some(name.clone()), act });
            }
        };
        if !domains.is_empty() {
            let name = format!("{base}d");
            for d in &domains {
                dns.sets.entry(d.clone()).or_default().insert(name.clone());
                if act == Act::Tunnel {
                    dns.tunnel_domains.insert(d.clone());
                }
            }
            add_rule(name, SetKind::Dns, Vec::new());
        }
        if !nets.is_empty() {
            add_rule(format!("{base}n"), SetKind::Static, nets.into_iter().collect());
        }
        if act != Act::Direct {
            v6_block.extend(srcs.iter().cloned());
        }
    }
    if let Some(act) = act_of(&cfg.default_action, "default_action", &mut issues) {
        if act != Act::Direct {
            match lan_bridges() {
                Ok(b) => {
                    for bridge in b {
                        let src = SrcMatch::Bridge { bridge };
                        rules.push(PolicyRule { from: "default_action".into(), src: src.clone(), set: None, act });
                        v6_block.insert(src);
                    }
                }
                Err(i) => issues.push(i),
            }
        }
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    if exact_warned {
        warnings.push("точный домен сопоставляется через DNS вместе с поддоменами (так работает ipset в dnsmasq)".into());
    }
    if v6_warned {
        warnings.push("IPv6-префиксы назначений не используются: IPv6 защищаемых источников блокируется".into());
    }
    if !v6_block.is_empty() {
        warnings.push("IPv6 источников с правилами туннеля, Zapret или блокировки наружу не идёт: домены сопоставляются по IPv4".into());
    }
    if !dns.sets.is_empty() {
        warnings.push("доменные правила срабатывают по ответам DNS роутера: устройство со своим DoH/DoT обходит сопоставление".into());
    }

    let zcfg = cfg.zapret.clone().unwrap_or_default();
    let uses_zapret = rules.iter().any(|r| r.act == Act::Zapret);
    let client = tunnel_profile.map(|p| {
        let e = p.endpoint.as_ref().expect("проверено");
        client_toml(e, secrets.profiles[p.id.as_str()].password.as_deref().unwrap_or_default())
    });
    if let Some(p) = tunnel_profile {
        if !plain_text(&p.endpoint.as_ref().expect("проверено").username) {
            return Err(vec![Issue::new("profiles", "bad_username", "имя пользователя содержит недопустимые символы")]);
        }
    }
    let policy = PolicySpec {
        rules,
        sets: sets.into_values().collect(),
        lan_subnets: cfg.networks.iter().filter_map(net_subnet).collect::<BTreeSet<_>>().into_iter().collect(),
        tun: TUN_DEVICE.into(),
        fail_open: tunnel_profile.is_some_and(|p| p.on_failure == FailurePolicy::Direct),
        zapret_queue: if uses_zapret { zapret_queue(&zcfg) } else { Vec::new() },
        dns_resolver: (client.is_some() && !dns.tunnel_domains.is_empty()).then(|| dns.resolver.clone()),
        v6_block: v6_block.into_iter().collect(),
    };
    if client.is_none() {
        dns.tunnel_domains.clear();
    }
    let plan: Vec<Entry> = {
        let mut v: Vec<Entry> = build_plan(&policy, &[], &BTreeMap::new(), false).into_iter().collect();
        v.sort_by_key(|e| (e.rank(), e.clone()));
        v
    };
    let cmds = |e: &Entry, op: &str| e.cmds(op).into_iter().map(|(prog, args)| std::iter::once(prog.to_string()).chain(args).collect::<Vec<String>>()).collect::<Vec<_>>();
    let routes = Routes { apply: plan.iter().flat_map(|e| cmds(e, "add")).collect(), revert: plan.iter().rev().flat_map(|e| cmds(e, "del")).collect() };
    Ok(Rendered {
        nfqws2_args: if uses_zapret { zapret::nfqws2_args(&zcfg, ZAPRET_QNUM) } else { Vec::new() },
        policy,
        plan,
        routes,
        client_toml: client,
        dns,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep() -> Endpoint {
        Endpoint { server: "203.0.113.10".into(), port: 443, sni: Some("vpn.example".into()), username: "user1".into(), quic: false, anti_dpi: true, certificate: None }
    }

    #[test]
    fn client_toml_is_escaped_and_keeps_routes_to_us() {
        let t = client_toml(&ep(), "p\"a\\ss");
        assert!(t.contains("hostname = \"vpn.example\"\n") && t.contains("addresses = [\"203.0.113.10:443\"]\n"), "{t}");
        assert!(t.contains("password = \"p\\\"a\\\\ss\"\n"), "{t}");
        assert!(t.contains("device_name = \"mitt0\"\n") && t.contains("included_routes = []\n") && t.contains("anti_dpi = true\n"), "{t}");
        assert!(t.contains("upstream_protocol = \"http2\"") && t.contains("certificate = \"\""), "{t}");
        let mut e = ep();
        e.certificate = Some("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into());
        e.quic = true;
        let t = client_toml(&e, "x");
        assert!(t.contains("certificate = '''\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'''\n") && t.contains("http3"), "{t}");
    }

    #[test]
    fn category_lists_take_plain_and_prefixed_domains() {
        assert_eq!(parse_category_list(CategoryKind::Domain, "+.youtube.com\n*.ytimg.com\ngooglevideo.com # x\n").unwrap(), ["googlevideo.com", "youtube.com", "ytimg.com"]);
        assert!(parse_category_list(CategoryKind::Ip, "10.0.0.0/8\nbad\n").is_err());
        assert_eq!(parse_category_list(CategoryKind::Domain, ".ua\n.example.com\n").unwrap(), ["example.com", "ua"]);
        assert!(parse_category_list(CategoryKind::Domain, "..ua\n").is_err());
        assert!(parse_category_list(CategoryKind::Domain, ".\n").is_err());
    }
}
