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
use crate::plan::{CaptureSpec, DevCap, Entry, LanCap, MAX_MARKS, NF_MARK, NetCap, ZAPRET_DESYNC_MARK, ZAPRET_QNUM, ZapretSpec, build_plan, device_mark, network_mark};
use crate::preview::{Dest, evaluation_order, expand};
use crate::validate::{Index, Issue, normalize_mac, normalize_sha256, parse_cidr, validate_config};

pub const TUN_DEVICE: &str = "mitt0";

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
    /// Пароль TrustTunnel и Hysteria2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Пароль обфускации salamander (только Hysteria2 с `obfs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    /// UUID клиента VLESS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// Закрытый ключ клиента WireGuard/AmneziaWG (base64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// Общий ключ WireGuard (необязательно).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
}

fn is_uuid(u: &str) -> bool {
    let b = u.as_bytes();
    b.len() == 36 && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// Набор секретов соответствует виду профиля: нужные заданы и корректны, лишних нет.
pub fn check_secret(kind: ProfileKind, s: &ProfileSecret) -> Result<(), &'static str> {
    let filled = |x: &Option<String>| x.as_deref().is_some_and(|v| !v.is_empty());
    let clean = |x: &Option<String>| x.as_deref().is_none_or(|v| !v.chars().any(char::is_control));
    if ![&s.password, &s.obfs_password, &s.uuid, &s.private_key, &s.preshared_key].iter().all(|x| clean(x)) {
        return Err("секрет содержит управляющие символы");
    }
    match kind {
        ProfileKind::Trusttunnel | ProfileKind::Hysteria2 => {
            if !filled(&s.password) {
                return Err("нужен непустой password");
            }
            if s.uuid.is_some() || s.private_key.is_some() || s.preshared_key.is_some() {
                return Err("uuid и ключи WireGuard к этому профилю не относятся");
            }
        }
        ProfileKind::Vless => {
            if !s.uuid.as_deref().is_some_and(is_uuid) {
                return Err("нужен uuid клиента VLESS (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)");
            }
            if s.password.is_some() || s.private_key.is_some() || s.preshared_key.is_some() {
                return Err("password и ключи WireGuard к VLESS не относятся");
            }
        }
        ProfileKind::Wireguard => {
            if !s.private_key.as_deref().is_some_and(crate::validate::is_wg_key) {
                return Err("нужен private_key клиента WireGuard (32 байта base64)");
            }
            if s.preshared_key.as_deref().is_some_and(|k| !crate::validate::is_wg_key(k)) {
                return Err("preshared_key — 32 байта base64");
            }
            if s.password.is_some() || s.uuid.is_some() {
                return Err("password и uuid к WireGuard не относятся");
            }
        }
    }
    Ok(())
}

/// Профили, которые этот срез формирует для Mihomo.
pub fn renderable(kind: ProfileKind) -> bool {
    matches!(kind, ProfileKind::Trusttunnel | ProfileKind::Hysteria2 | ProfileKind::Vless | ProfileKind::Wireguard)
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
    /// Аргументы nfqws2 (по одному на строку в nfqws2.args), если используется Zapret.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nfqws2_args: Vec<String>,
    /// Категории, на которые ссылаются правила: их списки копируются в rules/<id>.txt.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
}

/// Имя rule-provider Mihomo для категории (файл rules/<id>.txt рядом с config.yaml).
pub fn category_provider(id: &str) -> String {
    format!("cat-{id}")
}

/// Список категории: по записи в строке, `#` — комментарий. Домены — суффиксы (`+.домен` в формате Mihomo),
/// IP — префиксы IPv4/IPv6. Ошибочная строка — отказ всего списка.
pub fn parse_category_list(kind: CategoryKind, text: &str) -> Result<Vec<String>, Vec<Issue>> {
    use crate::validate::normalize_domain;
    let mut out = BTreeSet::new();
    let mut issues = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let r = match kind {
            CategoryKind::Domain => normalize_domain(line.trim_start_matches("+.").trim_start_matches("*."), 1).map(|d| format!("+.{d}")),
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

/// Имя выхода Mihomo для действия «напрямую с Zapret».
pub const ZAPRET_PROXY: &str = "mitt-zapret";

/// Аргументы nfqws2 для проверенной стратегии. Lua-библиотеки zapret2 лежат рядом с nfqws2 (`--chdir` без пути = каталог программы).
pub fn nfqws2_args_for(z: &ZapretConfig) -> Vec<String> {
    let ports = z.tcp_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let f = match z.strategy {
        ZapretStrategy::Multisplit => "multisplit",
        ZapretStrategy::Multidisorder => "multidisorder",
    };
    vec![
        format!("--qnum={ZAPRET_QNUM}"),
        format!("--fwmark=0x{ZAPRET_DESYNC_MARK:x}"),
        "--chdir".into(),
        "--lua-init=@zapret-lib.lua.gz".into(),
        "--lua-init=@zapret-antidpi.lua.gz".into(),
        format!("--filter-tcp={ports}"),
        "--payload=tls_client_hello,http_req".into(),
        format!("--lua-desync={f}:pos={}", z.pos),
    ]
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
        Dest::Category(id) => format!("RULE-SET,{}", category_provider(id)),
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
    let mut uses_zapret = false;

    let mut target = |a: &Action, path: &str, issues: &mut Vec<Issue>, _warnings: &mut Vec<String>| -> Option<String> {
        match a {
            Action::Direct => Some("DIRECT".into()),
            Action::DirectZapret => {
                uses_zapret = true;
                Some(ZAPRET_PROXY.into())
            }
            Action::Block => Some("REJECT".into()),
            Action::Profile { id } => {
                let p = idx.profiles[id.as_str()];
                if !renderable(p.kind) {
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
                let Some(sec) = secrets.profiles.get(id) else {
                    issues.push(Issue::new(path, "no_secret", format!("нет пароля профиля «{id}» в secrets.json")));
                    return None;
                };
                let obfs = p.endpoint.as_ref().and_then(|e| e.obfs);
                if obfs.is_some() != sec.obfs_password.as_deref().is_some_and(|x| !x.is_empty()) {
                    issues.push(Issue::new(path, "obfs_secret_mismatch", format!("профиль «{id}»: obfs и obfs_password в secrets.json задаются вместе")));
                    return None;
                }
                if let Err(m) = check_secret(p.kind, sec) {
                    issues.push(Issue::new(path, "bad_secret", format!("секреты профиля «{id}»: {m}")));
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
        zapret: None,
    };
    let zcfg = cfg.zapret.clone().unwrap_or_default();
    let mut capture = capture;
    let mut nfqws2_args = Vec::new();
    if uses_zapret {
        capture.zapret = Some(ZapretSpec { qnum: ZAPRET_QNUM, mark: NF_MARK, tcp_ports: zcfg.tcp_ports.clone() });
        nfqws2_args = nfqws2_args_for(&zcfg);
        warnings.push(format!("Zapret: прямые соединения Mihomo через «{ZAPRET_PROXY}» помечаются 0x{NF_MARK:x} и обрабатываются nfqws2 (очередь {ZAPRET_QNUM}); без nfqws2 они идут напрямую без обработки"));
    }

    let mut proxies: Vec<Value> = used_profiles
        .iter()
        .map(|id| {
            let p = idx.profiles[id];
            let e = p.endpoint.as_ref().expect("checked");
            let sec = &secrets.profiles[p.id.as_str()];
            let mut v = match p.kind {
                ProfileKind::Hysteria2 => {
                    // проверка TLS никогда не отключается: skip-cert-verify явно false; ALPN h3 — как у сервера Hysteria2
                    let mut v = json!({
                        "name": p.id, "type": "hysteria2", "server": e.server, "port": e.port,
                        "password": sec.password.as_deref().unwrap_or_default(), "udp": true, "skip-cert-verify": false, "alpn": ["h3"],
                    });
                    if let (Some(Obfs::Salamander), Some(op)) = (e.obfs, &sec.obfs_password) {
                        v["obfs"] = json!("salamander");
                        v["obfs-password"] = json!(op);
                    }
                    v
                }
                ProfileKind::Vless => {
                    // TLS: проверка цепочки по servername или закреплённому SHA-256; REALITY: открытый ключ сервера.
                    // skip-cert-verify явно false; uTLS-отпечаток по умолчанию chrome
                    let mut v = json!({
                        "name": p.id, "type": "vless", "server": e.server, "port": e.port, "uuid": sec.uuid.as_deref().unwrap_or_default(),
                        "network": "tcp", "tls": true, "udp": true, "skip-cert-verify": false,
                        "client-fingerprint": e.client_fingerprint.as_deref().unwrap_or("chrome"),
                    });
                    if let Some(sni) = &e.sni {
                        v["servername"] = json!(sni);
                    }
                    if e.flow == Some(VlessFlow::Vision) {
                        v["flow"] = json!("xtls-rprx-vision");
                    }
                    if let (Some(VlessSecurity::Reality), Some(r)) = (e.security, &e.reality) {
                        v["reality-opts"] = json!({ "public-key": r.public_key, "short-id": r.short_id });
                    }
                    if let Some(fp) = &e.cert_sha256 {
                        v["fingerprint"] = json!(normalize_sha256(fp).unwrap_or_default());
                    }
                    return v;
                }
                ProfileKind::Wireguard => {
                    let ip = e.address.as_deref().unwrap_or_default().split('/').next().unwrap_or_default();
                    let mut v = json!({
                        "name": p.id, "type": "wireguard", "server": e.server, "port": e.port, "ip": ip,
                        "private-key": sec.private_key.as_deref().unwrap_or_default(),
                        "public-key": e.public_key.as_deref().unwrap_or_default(),
                        "allowed-ips": ["0.0.0.0/0"], "udp": true, "mtu": e.mtu.unwrap_or(1408),
                    });
                    if let Some(k) = &sec.preshared_key {
                        v["pre-shared-key"] = json!(k);
                    }
                    if let Some(a) = e.awg {
                        v["amnezia-wg-option"] = json!({ "jc": a.jc, "jmin": a.jmin, "jmax": a.jmax, "s1": a.s1, "s2": a.s2,
                            "h1": a.h1.to_string(), "h2": a.h2.to_string(), "h3": a.h3.to_string(), "h4": a.h4.to_string() });
                    }
                    return v;
                }
                ProfileKind::Trusttunnel => json!({
                    "name": p.id, "type": "trusttunnel", "server": e.server, "port": e.port,
                    "username": e.username, "password": sec.password.as_deref().unwrap_or_default(),
                    "udp": true, "quic": e.quic,
                }),
            };
            if let Some(sni) = &e.sni {
                v["sni"] = json!(sni);
            }
            if let Some(fp) = &e.cert_sha256 {
                v["fingerprint"] = json!(normalize_sha256(fp).unwrap_or_default());
            }
            v
        })
        .collect();

    if uses_zapret {
        // DIRECT с меткой сокета: по ней mi-tt-admin отправляет пакеты в NFQUEUE (mangle OUTPUT)
        proxies.push(json!({ "name": ZAPRET_PROXY, "type": "direct", "udp": true, "routing-mark": NF_MARK }));
    }
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
    let used_categories: BTreeSet<String> = ordered.iter().flat_map(|r| expand(&r.destination, &idx)).filter_map(|d| match d {
        Dest::Category(id) => Some(id),
        _ => None,
    }).collect();
    if !used_categories.is_empty() {
        let mut rp = serde_json::Map::new();
        for id in &used_categories {
            let behavior = match idx.categories[id.as_str()].kind {
                CategoryKind::Domain => "domain",
                CategoryKind::Ip => "ipcidr",
            };
            rp.insert(category_provider(id), json!({ "type": "file", "behavior": behavior, "format": "text", "path": format!("./rules/{id}.txt") }));
        }
        mihomo["rule-providers"] = Value::Object(rp);
    }
    if let Some(d) = &cfg.dns {
        let mut dd = crate::dns::mihomo_dns(d);
        // hosts в Mihomo — ключ верхнего уровня; dns.use-hosts включает его для DNS-слушателя
        if let Some(h) = dd.as_object_mut().and_then(|o| o.remove("hosts")).filter(|h| h.as_object().is_some_and(|m| !m.is_empty())) {
            mihomo["hosts"] = h;
        }
        mihomo["dns"] = dd;
    }
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
        nfqws2_args,
        categories: used_categories.into_iter().collect(),
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
