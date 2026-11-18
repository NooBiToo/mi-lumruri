//! Формирование действующей конфигурации из сохранённых настроек:
//!  - config.yaml для Mihomo (JSON — подмножество YAML 1.2; строки экранирует serde_json, вставка YAML-разметки невозможна);
//!  - спецификация захвата: какие источники и по какому наблюдаемому на входе признаку помечаются
//!    (MAC устройства на входе моста, порт моста = SSID для политики сети, мост целиком для всей LAN);
//!  - предварительный план правил (без учёта живого состояния; точный план строит mi-tt-admin).
//! Принцип: если политику нельзя выразить точно (нет моста, портов, подсети, пароля), не формируется ничего.
//! Неизвестный адрес устройства — не ошибка: устройство блокируется по MAC до появления адреса.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::model::*;
use crate::plan::{CaptureSpec, DevCap, Entry, LanCap, MAX_MARKS, NetCap, build_plan, device_mark, network_mark};
use crate::preview::{Dest, evaluation_order, expand};
use crate::validate::{Index, Issue, normalize_mac, normalize_sha256, parse_cidr, validate_config};

pub const TUN_DEVICE: &str = "mitt0";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Secrets {
    pub version: u32,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileSecret>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileSecret {
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct Routes {
    /// Команды по порядку (первый элемент — программа: ip или tc). Для информации: применяет mi-tt-admin
    /// с учётом живого состояния (существующие хуки tc, IPv6-префиксы мостов).
    pub apply: Vec<Vec<String>>,
    pub revert: Vec<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct Rendered {
    #[serde(skip)]
    pub mihomo: Value,
    pub capture: CaptureSpec,
    /// План без живого контекста (для обзора и тестов).
    pub plan: Vec<Entry>,
    pub routes: Routes,
    pub rules: Vec<String>,
    pub warnings: Vec<String>,
}

/// dnsmasq: `<expiry> <mac> <ip> <hostname> <client-id>`; берём IPv4 с наибольшим сроком.
pub fn parse_leases(text: &str) -> HashMap<String, IpAddr> {
    let mut best: HashMap<String, (u64, IpAddr)> = HashMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let (Ok(exp), Ok(mac), Ok(ip)) = (f[0].parse::<u64>(), normalize_mac(f[1]), f[2].parse::<IpAddr>()) else { continue };
        if !ip.is_ipv4() {
            continue;
        }
        if best.get(&mac).is_none_or(|(e, _)| exp >= *e) {
            best.insert(mac, (exp, ip));
        }
    }
    best.into_iter().map(|(m, (_, ip))| (m, ip)).collect()
}

fn matcher(d: &Dest) -> String {
    match d {
        Dest::Domain(x) => format!("DOMAIN,{x}"),
        Dest::Suffix(x) => format!("DOMAIN-SUFFIX,{x}"),
        Dest::Net(c) if c.addr.is_ipv4() => format!("IP-CIDR,{c}"),
        Dest::Net(c) => format!("IP-CIDR6,{c}"),
    }
}

pub fn render(cfg: &Config, secrets: &Secrets, leases: &HashMap<String, IpAddr>) -> Result<Rendered, Vec<Issue>> {
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
    let mut used_profiles: BTreeSet<&str> = BTreeSet::new();

    let mut target = |a: &Action, path: &str, issues: &mut Vec<Issue>, warnings: &mut Vec<String>| -> Option<String> {
        match a {
            Action::Direct => Some("DIRECT".into()),
            Action::DirectZapret => {
                warnings.push(format!("{path}: Zapret в этом этапе не подключён, трафик идёт напрямую без обработки"));
                Some("DIRECT".into())
            }
            Action::Block => Some("REJECT".into()),
            Action::Profile { id } => {
                let p = idx.profiles[id.as_str()];
                if p.kind != ProfileKind::Trusttunnel {
                    issues.push(Issue::new(path, "profile_not_supported", format!("профиль «{id}» ({}) этим этапом не формируется", p.kind.label())));
                    return None;
                }
                if p.on_failure != FailurePolicy::Block {
                    issues.push(Issue::new(path, "fail_open_not_supported", format!("профиль «{id}»: режим выхода в обход при отказе не поддерживается")));
                    return None;
                }
                if p.endpoint.is_none() {
                    issues.push(Issue::new(path, "no_endpoint", format!("у профиля «{id}» нет точки подключения")));
                    return None;
                }
                if !secrets.profiles.contains_key(id) {
                    issues.push(Issue::new(path, "no_secret", format!("нет пароля профиля «{id}» в secrets.json")));
                    return None;
                }
                used_profiles.insert(idx.profiles[id.as_str()].id.as_str());
                Some(id.clone())
            }
        }
    };

    let net_subnet = |n: &Network| n.subnet.as_deref().and_then(|s| parse_cidr(s).ok()).map(|c| c.to_string());
    let mut rules_out = Vec::new();
    let mut dev_caps: BTreeMap<String, (String, Option<String>, String)> = BTreeMap::new(); // id → (mac, ipv4, bridge)
    let mut net_caps: BTreeMap<String, (String, Vec<String>, String)> = BTreeMap::new(); // id → (bridge, ports, subnet)
    let mut capture_all = false;
    let ordered = evaluation_order(&cfg.rules);
    for r in &ordered {
        let pos = cfg.rules.iter().position(|x| x.id == r.id).unwrap_or(0);
        let path = format!("rules[{pos}]");
        // Источник для Mihomo: IP устройства из аренды, подсеть сети или без условия (вся LAN).
        // Для маршрутизации источник определяется наблюдаемым признаком на входе — см. спецификацию захвата.
        let src: Option<Option<String>> = match &r.source {
            Source::Device { id } => {
                let d = idx.devices[id.as_str()];
                let mac = normalize_mac(&d.mac).unwrap_or_default();
                let n = idx.networks[d.network.as_str()];
                let Some(bridge) = n.bridge.clone() else {
                    issues.push(Issue::new(format!("{path}.source"), "no_bridge", format!("у сети «{}» устройства «{}» не задан мост", n.id, d.id)));
                    continue;
                };
                let ip = leases.get(&mac).filter(|a| a.is_ipv4()).map(|a| a.to_string());
                if ip.is_none() {
                    warnings.push(format!("устройство «{}» ({mac}) без аренды DHCP: его маршрутизируемый трафик блокируется по MAC до apply с известным адресом", d.id));
                }
                dev_caps.insert(d.id.clone(), (mac, ip.clone(), bridge));
                Some(ip.map(|a| format!("{a}/32")))
            }
            Source::Network { id } => {
                let n = idx.networks[id.as_str()];
                let (Some(sub), Some(bridge)) = (net_subnet(n), n.bridge.clone()) else {
                    issues.push(Issue::new(format!("{path}.source"), "no_subnet", format!("у сети «{id}» нужны subnet и bridge")));
                    continue;
                };
                if n.ports.is_empty() {
                    issues.push(Issue::new(format!("{path}.source"), "no_ports", format!("у сети «{id}» не заданы порты моста (интерфейсы SSID)")));
                    continue;
                }
                net_caps.insert(n.id.clone(), (bridge, n.ports.clone(), sub.clone()));
                Some(Some(sub))
            }
            Source::Lan => None,
        };
        let Some(t) = target(&r.action, &format!("{path}.action"), &mut issues, &mut warnings) else { continue };
        match &src {
            None => capture_all = true,
            Some(None) => continue, // устройство без адреса: в Mihomo не попадает, маршрутизация его блокирует
            Some(Some(_)) => {}
        }
        for d in expand(&r.destination, &idx) {
            rules_out.push(match &src {
                Some(Some(s)) => format!("AND,((SRC-IP-CIDR,{s}),({})),{t}", matcher(&d)),
                _ => format!("{},{t}", matcher(&d)),
            });
        }
    }
    let default_target = target(&cfg.default_action, "default_action", &mut issues, &mut warnings);
    if default_target.as_deref().is_some_and(|t| t != "DIRECT") {
        capture_all = true;
    }

    let lan_subnets: Vec<String> = cfg.networks.iter().filter_map(net_subnet).collect::<BTreeSet<_>>().into_iter().collect();
    let mut lanwide = Vec::new();
    if capture_all {
        for n in &cfg.networks {
            match (n.bridge.clone(), net_subnet(n)) {
                (Some(bridge), Some(subnet)) => lanwide.push(LanCap { bridge, subnet }),
                _ => issues.push(Issue::new("networks", "no_subnet", format!("для правил всей LAN у сети «{}» нужны bridge и subnet", n.id))),
            }
        }
    }
    if dev_caps.len() > MAX_MARKS as usize || net_caps.len() > MAX_MARKS as usize {
        issues.push(Issue::new("rules", "too_many_sources", format!("не больше {MAX_MARKS} защищаемых устройств и {MAX_MARKS} сетей")));
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    // В TUN попадает только захваченный трафик. Источник, неизвестный этой конфигурации (новый адрес устройства,
    // пока Mihomo работает со старой конфигурацией), отклоняется, а не уходит в MATCH/DIRECT.
    let mut known: BTreeSet<String> = BTreeSet::new();
    known.extend(dev_caps.values().filter_map(|(_, ip, _)| ip.as_ref().map(|a| format!("{a}/32"))));
    known.extend(net_caps.values().map(|(_, _, s)| s.clone()));
    known.extend(lanwide.iter().map(|l| l.subnet.clone()));
    let captured_any = !dev_caps.is_empty() || !net_caps.is_empty() || !lanwide.is_empty();
    match known.len() {
        _ if !captured_any => {}
        0 => rules_out.push("MATCH,REJECT".into()),
        1 => rules_out.push(format!("NOT,((SRC-IP-CIDR,{})),REJECT", known.iter().next().unwrap())),
        _ => rules_out.push(format!("NOT,((OR,({}))),REJECT", known.iter().map(|k| format!("(SRC-IP-CIDR,{k})")).collect::<Vec<_>>().join(","))),
    }
    rules_out.push(format!("MATCH,{}", default_target.unwrap_or_else(|| "DIRECT".into())));

    let capture = CaptureSpec {
        devices: dev_caps
            .into_iter()
            .enumerate()
            .map(|(i, (id, (mac, ipv4, bridge)))| DevCap { id, mac, ipv4, bridge, mark: device_mark(i as u32 + 1) })
            .collect(),
        networks: net_caps
            .into_iter()
            .enumerate()
            .map(|(i, (id, (bridge, ports, subnet)))| NetCap { id, bridge, ports, subnet, mark: network_mark(i as u32 + 1) })
            .collect(),
        lanwide,
        lan_subnets,
        tun: TUN_DEVICE.into(),
    };

    let proxies: Vec<Value> = used_profiles
        .iter()
        .map(|id| {
            let p = idx.profiles[id];
            let e = p.endpoint.as_ref().expect("checked");
            let mut v = json!({
                "name": p.id, "type": "trusttunnel", "server": e.server, "port": e.port,
                "username": e.username, "password": secrets.profiles[p.id.as_str()].password,
                "udp": true, "quic": e.quic,
            });
            if let Some(sni) = &e.sni {
                v["sni"] = json!(sni);
            }
            if let Some(fp) = &e.cert_sha256 {
                v["fingerprint"] = json!(normalize_sha256(fp).unwrap_or_default());
            }
            v
        })
        .collect();

    let has_domains = ordered.iter().any(|r| expand(&r.destination, &idx).iter().any(|d| !matches!(d, Dest::Net(_))));
    // ipv6: false — IPv6 не туннелируется (защищённые источники блокируются по метке), а TUN без IPv6-адреса
    // не заставляет sing-tun добавлять своё правило «oif mitt0 lookup 2022» вне нашей зоны.
    let mut mihomo = json!({
        "mode": "rule",
        "log-level": "info",
        "ipv6": false,
        "allow-lan": false,
        "bind-address": "127.0.0.1",
        "find-process-mode": "off",
        "profile": { "store-selected": false, "store-fake-ip": false },
        "tun": { "enable": true, "stack": "system", "device": TUN_DEVICE, "auto-route": false, "auto-redirect": false, "auto-detect-interface": false },
        "proxies": proxies,
        "rules": rules_out,
    });
    if has_domains {
        mihomo["sniffer"] = json!({ "enable": true, "override-destination": false,
            "sniff": { "HTTP": { "ports": [80, 8080] }, "TLS": { "ports": [443, 8443] } } });
        warnings.push("доменные назначения распознаются по HTTP Host и TLS SNI; DNS-интеграция в этом этапе не подключена".into());
    }
    if !capture.devices.is_empty() || !capture.networks.is_empty() || !capture.lanwide.is_empty() {
        warnings.push("IPv6 защищаемых источников не туннелируется: внешний IPv6 блокируется по той же метке (локальные NDP/DHCPv6/управление сохраняются)".into());
    }

    let plan: Vec<Entry> = {
        let mut v: Vec<Entry> = build_plan(&capture, &[], &BTreeSet::new(), &BTreeSet::new(), false).into_iter().collect();
        v.sort_by_key(|e| (e.rank(), e.clone()));
        v
    };
    let cmd = |e: &Entry, op: &str| {
        let (prog, args) = e.cmd(op);
        std::iter::once(prog.to_string()).chain(args).collect::<Vec<String>>()
    };
    let routes = Routes { apply: plan.iter().map(|e| cmd(e, "add")).collect(), revert: plan.iter().rev().map(|e| cmd(e, "del")).collect() };

    Ok(Rendered {
        rules: mihomo["rules"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        mihomo,
        capture,
        plan,
        routes,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_take_latest_ipv4() {
        let l = parse_leases("100 AA:BB:CC:00:00:01 10.0.0.5 tv *\n200 aa:bb:cc:00:00:01 10.0.0.6 tv *\nbad line\n300 aa:bb:cc:00:00:02 fe80::1 x *\n");
        assert_eq!(l["aa:bb:cc:00:00:01"], "10.0.0.6".parse::<IpAddr>().unwrap());
        assert!(!l.contains_key("aa:bb:cc:00:00:02"));
    }
}
