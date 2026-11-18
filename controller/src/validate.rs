//! Проверка настроек и черновика правила. Сообщения — для панели, на русском.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::Serialize;

use crate::model::*;

pub const MAX_RULES: usize = 512;
pub const MAX_ITEMS: usize = 256;
pub const MAX_GROUP_DESTINATIONS: usize = 1024;
pub const MAX_NAME_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub path: String,
    pub code: &'static str,
    pub message: String,
}

impl Issue {
    pub fn new(path: impl Into<String>, code: &'static str, message: impl Into<String>) -> Self {
        Issue { path: path.into(), code, message: message.into() }
    }
}

// ---------- примитивы ----------

pub fn check_id(id: &str) -> Result<(), String> {
    let b = id.as_bytes();
    if b.is_empty() || b.len() > 32 {
        return Err("идентификатор должен содержать от 1 до 32 символов".into());
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return Err("идентификатор начинается со строчной латинской буквы или цифры".into());
    }
    if !b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_') {
        return Err("допустимы только a-z, 0-9, '-' и '_'".into());
    }
    Ok(())
}

pub fn check_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() {
        return Err("имя не может быть пустым".into());
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("имя длиннее {MAX_NAME_CHARS} символов"));
    }
    if name.chars().any(char::is_control) {
        return Err("имя содержит управляющие символы".into());
    }
    Ok(())
}

/// Имя сетевого интерфейса Linux: 1–15 символов, без пробелов, «/» и «:».
pub fn check_ifname(n: &str) -> Result<(), String> {
    if n.is_empty() || n.len() > 15 || n == "." || n == ".." {
        return Err("имя интерфейса — от 1 до 15 символов".into());
    }
    if !n.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'@')) {
        return Err(format!("недопустимые символы в имени интерфейса «{n}»"));
    }
    Ok(())
}

/// Нормализует MAC в вид `aa:bb:cc:dd:ee:ff`. Групповые адреса устройствам не принадлежат.
pub fn normalize_mac(mac: &str) -> Result<String, String> {
    let parts: Vec<&str> = if mac.contains(':') { mac.split(':').collect() } else { mac.split('-').collect() };
    if parts.len() != 6 || !parts.iter().all(|p| p.len() == 2 && p.bytes().all(|c| c.is_ascii_hexdigit())) {
        return Err("MAC-адрес ожидается в виде aa:bb:cc:dd:ee:ff".into());
    }
    let first = u8::from_str_radix(parts[0], 16).map_err(|e| e.to_string())?;
    if first & 1 == 1 {
        return Err("групповой (multicast/broadcast) MAC не может принадлежать устройству".into());
    }
    if parts.iter().all(|p| *p == "00") {
        return Err("нулевой MAC-адрес недопустим".into());
    }
    Ok(parts.join(":").to_ascii_lowercase())
}

/// Нормализует доменное имя: нижний регистр, без завершающей точки, только ASCII (punycode).
pub fn normalize_domain(value: &str, min_labels: usize) -> Result<String, String> {
    if value.contains('*') {
        return Err("маски '*' не поддерживаются, используйте тип domain_suffix".into());
    }
    if !value.is_ascii() {
        return Err("имя с не-ASCII символами нужно записать в punycode (xn--...)".into());
    }
    let d = value.strip_suffix('.').unwrap_or(value).to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 {
        return Err("длина домена должна быть от 1 до 253 символов".into());
    }
    if d.parse::<IpAddr>().is_ok() {
        return Err("это IP-адрес, используйте тип cidr".into());
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < min_labels {
        return Err(format!("домен должен содержать не меньше {min_labels} меток (пример: example.com)"));
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 {
            return Err(format!("метка «{l}» должна иметь длину от 1 до 63 символов"));
        }
        if l.starts_with('-') || l.ends_with('-') {
            return Err(format!("метка «{l}» не может начинаться или заканчиваться '-'"));
        }
        if !l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
            return Err(format!("метка «{l}» содержит недопустимые символы"));
        }
    }
    if labels.last().is_some_and(|tld| tld.bytes().all(|c| c.is_ascii_digit())) {
        return Err("домен верхнего уровня не может состоять из цифр".into());
    }
    Ok(d)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    fn bits(addr: IpAddr) -> (u128, u8) {
        match addr {
            IpAddr::V4(a) => (u32::from(a) as u128, 32),
            IpAddr::V6(a) => (u128::from(a), 128),
        }
    }
    fn mask(prefix: u8, width: u8) -> u128 {
        mask_width(width) & !low_bits(width - prefix)
    }
    pub fn contains(&self, other: &Cidr) -> bool {
        let (a, wa) = Self::bits(self.addr);
        let (b, wb) = Self::bits(other.addr);
        if wa != wb || self.prefix > other.prefix {
            return false;
        }
        let m = Self::mask(self.prefix, wa);
        a & m == b & m
    }
    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.contains(other) || other.contains(self)
    }
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        let width = if ip.is_ipv4() { 32 } else { 128 };
        self.contains(&Cidr { addr: ip, prefix: width })
    }
}

fn mask_width(width: u8) -> u128 {
    if width == 128 { !0 } else { (1u128 << width) - 1 }
}
fn low_bits(n: u8) -> u128 {
    if n >= 128 { !0 } else { (1u128 << n) - 1 }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

pub fn parse_cidr(value: &str) -> Result<Cidr, String> {
    let (a, p) = value.split_once('/').ok_or("подсеть ожидается в виде адрес/префикс, например 203.0.113.0/24")?;
    let addr: IpAddr = a.parse().map_err(|_| format!("«{a}» не является IPv4/IPv6-адресом"))?;
    let width = if addr.is_ipv4() { 32 } else { 128 };
    if p.is_empty() || !p.bytes().all(|c| c.is_ascii_digit()) || p.len() > 3 {
        return Err("префикс должен быть числом".into());
    }
    let prefix: u8 = p.parse().map_err(|_| "префикс должен быть числом".to_string())?;
    if prefix > width {
        return Err(format!("префикс {prefix} больше {width}"));
    }
    if prefix == 0 {
        return Err("префикс /0 перехватывает весь трафик семейства; задайте маршрут по умолчанию вместо этого".into());
    }
    let c = Cidr { addr, prefix };
    let (bits, w) = Cidr::bits(addr);
    let net = bits & Cidr::mask(prefix, w);
    if net != bits {
        let canon = match addr {
            IpAddr::V4(_) => IpAddr::V4((net as u32).into()),
            IpAddr::V6(_) => IpAddr::V6(net.into()),
        };
        return Err(format!("в адресе установлены биты узла; сеть: {canon}/{prefix}"));
    }
    Ok(c)
}

// ---------- проверка настроек ----------

pub struct Index<'a> {
    pub profiles: HashMap<&'a str, &'a Profile>,
    pub networks: HashMap<&'a str, &'a Network>,
    pub devices: HashMap<&'a str, &'a Device>,
    pub groups: HashMap<&'a str, &'a Group>,
    pub categories: HashMap<&'a str, &'a Category>,
}

impl<'a> Index<'a> {
    pub fn new(c: &'a Config) -> Self {
        Index {
            profiles: c.profiles.iter().map(|x| (x.id.as_str(), x)).collect(),
            networks: c.networks.iter().map(|x| (x.id.as_str(), x)).collect(),
            devices: c.devices.iter().map(|x| (x.id.as_str(), x)).collect(),
            groups: c.groups.iter().map(|x| (x.id.as_str(), x)).collect(),
            categories: c.categories.iter().map(|x| (x.id.as_str(), x)).collect(),
        }
    }
}

fn check_unique<'a>(issues: &mut Vec<Issue>, kind: &str, ids: impl Iterator<Item = &'a str>) {
    let mut seen = HashSet::new();
    for (i, id) in ids.enumerate() {
        if let Err(e) = check_id(id) {
            issues.push(Issue::new(format!("{kind}[{i}].id"), "bad_id", e));
        } else if !seen.insert(id) {
            issues.push(Issue::new(format!("{kind}[{i}].id"), "duplicate_id", format!("идентификатор «{id}» уже используется")));
        }
    }
}

fn check_names<'a>(issues: &mut Vec<Issue>, kind: &str, names: impl Iterator<Item = &'a str>) {
    for (i, n) in names.enumerate() {
        if let Err(e) = check_name(n) {
            issues.push(Issue::new(format!("{kind}[{i}].name"), "bad_name", e));
        }
    }
}

fn limit(issues: &mut Vec<Issue>, path: &str, len: usize, max: usize) {
    if len > max {
        issues.push(Issue::new(path, "too_many", format!("не больше {max} элементов, получено {len}")));
    }
}

pub fn validate_config(c: &Config) -> Vec<Issue> {
    let mut issues = Vec::new();
    if c.version != SCHEMA_VERSION {
        issues.push(Issue::new("version", "unsupported_version", format!("поддерживается версия схемы {SCHEMA_VERSION}, получена {}", c.version)));
        return issues;
    }
    limit(&mut issues, "profiles", c.profiles.len(), MAX_ITEMS);
    limit(&mut issues, "networks", c.networks.len(), MAX_ITEMS);
    limit(&mut issues, "devices", c.devices.len(), MAX_ITEMS);
    limit(&mut issues, "groups", c.groups.len(), MAX_ITEMS);
    limit(&mut issues, "rules", c.rules.len(), MAX_RULES);

    check_unique(&mut issues, "profiles", c.profiles.iter().map(|x| x.id.as_str()));
    check_unique(&mut issues, "networks", c.networks.iter().map(|x| x.id.as_str()));
    check_unique(&mut issues, "devices", c.devices.iter().map(|x| x.id.as_str()));
    check_unique(&mut issues, "groups", c.groups.iter().map(|x| x.id.as_str()));
    check_unique(&mut issues, "categories", c.categories.iter().map(|x| x.id.as_str()));
    check_names(&mut issues, "categories", c.categories.iter().map(|x| x.name.as_str()));
    limit(&mut issues, "categories", c.categories.len(), MAX_ITEMS);
    check_unique(&mut issues, "rules", c.rules.iter().map(|x| x.id.as_str()));
    check_names(&mut issues, "profiles", c.profiles.iter().map(|x| x.name.as_str()));
    check_names(&mut issues, "networks", c.networks.iter().map(|x| x.name.as_str()));
    check_names(&mut issues, "devices", c.devices.iter().map(|x| x.name.as_str()));
    check_names(&mut issues, "groups", c.groups.iter().map(|x| x.name.as_str()));

    let idx = Index::new(c);

    let mut ssids: HashMap<(&str, Option<&str>), usize> = HashMap::new();
    let mut ports: HashMap<String, usize> = HashMap::new();
    for (i, n) in c.networks.iter().enumerate() {
        let p = format!("networks[{i}]");
        if n.ssid.is_empty() || n.ssid.len() > 32 {
            issues.push(Issue::new(format!("{p}.ssid"), "bad_ssid", "SSID занимает от 1 до 32 байт"));
        }
        if let Some(seg) = &n.segment {
            if let Err(e) = check_id(seg) {
                issues.push(Issue::new(format!("{p}.segment"), "bad_segment", e));
            }
        }
        if let Some(sub) = &n.subnet {
            if let Err(e) = parse_cidr(sub) {
                issues.push(Issue::new(format!("{p}.subnet"), "bad_cidr", e));
            }
        }
        for (k, ifname) in n.bridge.iter().map(|b| ("bridge".to_string(), b)).chain(n.ports.iter().enumerate().map(|(j, x)| (format!("ports[{j}]"), x))) {
            if let Err(e) = check_ifname(ifname) {
                issues.push(Issue::new(format!("{p}.{k}"), "bad_ifname", e));
            }
        }
        if !n.ports.is_empty() && n.bridge.is_none() {
            issues.push(Issue::new(format!("{p}.ports"), "ports_without_bridge", "порты задаются вместе с мостом (bridge)"));
        }
        for (j, port) in n.ports.iter().enumerate() {
            if let Some(prev) = ports.insert(port.clone(), i) {
                issues.push(Issue::new(format!("{p}.ports[{j}]"), "duplicate_port", format!("порт «{port}» уже относится к networks[{prev}]")));
            }
            if n.bridge.as_deref() == Some(port.as_str()) {
                issues.push(Issue::new(format!("{p}.ports[{j}]"), "port_is_bridge", "порт не может совпадать с мостом"));
            }
        }
        if let Some(prev) = ssids.insert((n.ssid.as_str(), n.segment.as_deref()), i) {
            issues.push(Issue::new(format!("{p}.ssid"), "ambiguous_ssid",
                format!("SSID «{}» совпадает с networks[{prev}]; задайте разные segment", n.ssid)));
        }
    }

    let mut macs: HashMap<String, usize> = HashMap::new();
    for (i, d) in c.devices.iter().enumerate() {
        let p = format!("devices[{i}]");
        match normalize_mac(&d.mac) {
            Ok(m) => {
                if let Some(prev) = macs.insert(m.clone(), i) {
                    issues.push(Issue::new(format!("{p}.mac"), "duplicate_mac", format!("MAC {m} уже назначен devices[{prev}]")));
                }
            }
            Err(e) => issues.push(Issue::new(format!("{p}.mac"), "bad_mac", e)),
        }
        if !idx.networks.contains_key(d.network.as_str()) {
            issues.push(Issue::new(format!("{p}.network"), "unknown_network", format!("сеть «{}» не найдена", d.network)));
        }
    }

    for (i, g) in c.groups.iter().enumerate() {
        let p = format!("groups[{i}]");
        if g.destinations.is_empty() {
            issues.push(Issue::new(format!("{p}.destinations"), "empty_group", "группа должна содержать хотя бы одно назначение"));
        }
        limit(&mut issues, &format!("{p}.destinations"), g.destinations.len(), MAX_GROUP_DESTINATIONS);
        for (j, d) in g.destinations.iter().enumerate() {
            let dp = format!("{p}.destinations[{j}]");
            if let Destination::Group { .. } = d {
                issues.push(Issue::new(dp, "nested_group", "группа не может включать другую группу"));
            } else {
                check_destination(&mut issues, &dp, d, &idx);
            }
        }
    }

    for (i, p) in c.profiles.iter().enumerate() {
        if let Some(e) = &p.endpoint {
            check_endpoint(&mut issues, &format!("profiles[{i}].endpoint"), p.kind, e);
        }
    }

    for (i, r) in c.rules.iter().enumerate() {
        check_rule_refs(&mut issues, &format!("rules[{i}]"), r, &idx);
    }
    check_action(&mut issues, "default_action", &c.default_action, &idx);
    if let Some(d) = &c.dns {
        check_dns(&mut issues, d);
    }
    if let Some(z) = &c.zapret {
        if !(1..=64).contains(&z.pos) {
            issues.push(Issue::new("zapret.pos", "bad_pos", "позиция разреза — от 1 до 64 байт"));
        }
        if z.tcp_ports.is_empty() || z.tcp_ports.len() > 8 || z.tcp_ports.contains(&0) {
            issues.push(Issue::new("zapret.tcp_ports", "bad_ports", "от 1 до 8 TCP-портов, каждый от 1 до 65535"));
        }
    }
    issues
}

/// SHA-256 сертификата: 64 hex-символа, двоеточия допускаются. Возвращает нижний регистр без двоеточий.
pub fn normalize_sha256(v: &str) -> Result<String, String> {
    let h: String = v.chars().filter(|c| *c != ':').collect::<String>().to_ascii_lowercase();
    if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("отпечаток сертификата — 64 шестнадцатеричных символа SHA-256".into());
    }
    Ok(h)
}

fn check_endpoint(issues: &mut Vec<Issue>, path: &str, kind: ProfileKind, e: &Endpoint) {
    let na = |issues: &mut Vec<Issue>, present: bool, field: &str| {
        if present {
            issues.push(Issue::new(format!("{path}.{field}"), "not_applicable", format!("поле {field} не применяется к профилю {}", kind.label())));
        }
    };
    let tt = kind == ProfileKind::Trusttunnel;
    let hy = kind == ProfileKind::Hysteria2;
    let vl = kind == ProfileKind::Vless;
    let wg = kind == ProfileKind::Wireguard;
    na(issues, !tt && !e.username.is_empty(), "username");
    na(issues, !tt && e.quic, "quic");
    na(issues, !hy && e.obfs.is_some(), "obfs");
    na(issues, !vl && e.security.is_some(), "security");
    na(issues, !vl && e.flow.is_some(), "flow");
    na(issues, !vl && e.reality.is_some(), "reality");
    na(issues, !vl && e.client_fingerprint.is_some(), "client_fingerprint");
    na(issues, !wg && e.public_key.is_some(), "public_key");
    na(issues, !wg && e.address.is_some(), "address");
    na(issues, !wg && e.mtu.is_some(), "mtu");
    na(issues, !wg && e.awg.is_some(), "awg");
    na(issues, wg && e.sni.is_some(), "sni");
    na(issues, wg && e.cert_sha256.is_some(), "cert_sha256");
    let reality = vl && e.security == Some(VlessSecurity::Reality);
    na(issues, reality && e.cert_sha256.is_some(), "cert_sha256");

    if e.server.parse::<IpAddr>().is_err() {
        if let Err(m) = normalize_domain(&e.server, 2) {
            issues.push(Issue::new(format!("{path}.server"), "bad_server", m));
        }
    }
    if e.port == 0 {
        issues.push(Issue::new(format!("{path}.port"), "bad_port", "порт должен быть от 1 до 65535"));
    }
    if let Some(sni) = &e.sni {
        if let Err(m) = normalize_domain(sni, 1) {
            issues.push(Issue::new(format!("{path}.sni"), "bad_sni", m));
        }
    }
    if tt && (e.username.is_empty() || e.username.len() > 64 || e.username.chars().any(|c| c.is_control() || c == ':')) {
        issues.push(Issue::new(format!("{path}.username"), "bad_username", "имя пользователя: 1–64 символа без ':' и управляющих"));
    }
    if let Some(fp) = &e.cert_sha256 {
        if let Err(m) = normalize_sha256(fp) {
            issues.push(Issue::new(format!("{path}.cert_sha256"), "bad_fingerprint", m));
        }
    }
    // проверка TLS не отключается: сервер по IP без SNI и без закреплённого сертификата проверить нельзя
    let tls_checked = hy || (vl && e.security == Some(VlessSecurity::Tls));
    if tls_checked && e.server.parse::<IpAddr>().is_ok() && e.sni.is_none() && e.cert_sha256.is_none() {
        issues.push(Issue::new(path.to_string(), "tls_unverifiable", "сервер задан IP-адресом: нужен sni (имя в сертификате) или cert_sha256 (закреплённый сертификат)"));
    }
    if vl {
        match e.security {
            None => issues.push(Issue::new(format!("{path}.security"), "required", "для VLESS нужна защита транспорта: tls или reality")),
            Some(VlessSecurity::Reality) => {
                match &e.reality {
                    None => issues.push(Issue::new(format!("{path}.reality"), "required", "для REALITY нужны public_key и short_id сервера")),
                    Some(r) => {
                        if data_encoding::BASE64URL_NOPAD.decode(r.public_key.as_bytes()).map(|k| k.len()) != Ok(32) {
                            issues.push(Issue::new(format!("{path}.reality.public_key"), "bad_key", "открытый ключ REALITY — 32 байта x25519 в base64url"));
                        }
                        if r.short_id.len() > 16 || r.short_id.len() % 2 != 0 || !r.short_id.bytes().all(|c| c.is_ascii_hexdigit()) {
                            issues.push(Issue::new(format!("{path}.reality.short_id"), "bad_short_id", "short id — до 16 шестнадцатеричных символов, чётная длина"));
                        }
                    }
                }
                if e.sni.is_none() {
                    issues.push(Issue::new(format!("{path}.sni"), "required", "для REALITY нужен sni — имя сайта, под который маскируется соединение"));
                }
            }
            Some(VlessSecurity::Tls) => na(issues, e.reality.is_some(), "reality"),
        }
        if let Some(f) = &e.client_fingerprint {
            if !["chrome", "firefox", "safari", "ios", "edge", "random"].contains(&f.as_str()) {
                issues.push(Issue::new(format!("{path}.client_fingerprint"), "bad_fingerprint", "client_fingerprint: chrome, firefox, safari, ios, edge или random"));
            }
        }
    }
    if wg {
        match &e.public_key {
            None => issues.push(Issue::new(format!("{path}.public_key"), "required", "нужен открытый ключ сервера WireGuard")),
            Some(k) if !is_wg_key(k) => issues.push(Issue::new(format!("{path}.public_key"), "bad_key", "ключ WireGuard — 32 байта в base64")),
            _ => {}
        }
        match e.address.as_deref().map(parse_cidr) {
            None => issues.push(Issue::new(format!("{path}.address"), "required", "нужен адрес клиента в туннеле, например 10.66.66.2/32")),
            Some(Ok(c)) if c.addr.is_ipv4() && c.prefix == 32 => {}
            Some(_) => issues.push(Issue::new(format!("{path}.address"), "bad_address", "адрес клиента в туннеле — IPv4/32")),
        }
        if let Some(m) = e.mtu {
            if !(1280..=1500).contains(&m) {
                issues.push(Issue::new(format!("{path}.mtu"), "bad_mtu", "MTU туннеля — от 1280 до 1500"));
            }
        }
        if let Some(a) = &e.awg {
            let mut bad = |f: &str, m: &str| issues.push(Issue::new(format!("{path}.awg.{f}"), "bad_awg", m.to_string()));
            if a.jc > 128 {
                bad("jc", "jc — от 0 до 128");
            }
            if a.jmin > a.jmax || a.jmax > 1280 {
                bad("jmax", "нужно jmin ≤ jmax ≤ 1280");
            }
            if a.s1 > 1132 || a.s2 > 1188 || a.s1 + 56 == a.s2 {
                bad("s2", "s1 ≤ 1132, s2 ≤ 1188 и s1 + 56 ≠ s2 (иначе размеры init и response совпадут)");
            }
            let h = [a.h1, a.h2, a.h3, a.h4];
            if h.iter().any(|x| *x < 5) || (0..4).any(|i| (i + 1..4).any(|j| h[i] == h[j])) {
                bad("h1", "h1–h4 различны и не меньше 5 (1–4 — заголовки обычного WireGuard)");
            }
        }
    }
}

fn check_dns(issues: &mut Vec<Issue>, d: &DnsConfig) {
    let host = |issues: &mut Vec<Issue>, p: &str, h: &str| {
        if let Err(m) = normalize_domain(h, 2) {
            issues.push(Issue::new(format!("{p}.host"), "bad_host", m));
        }
    };
    let ip = |issues: &mut Vec<Issue>, p: &str, v: &str| {
        if v.parse::<IpAddr>().is_err() {
            issues.push(Issue::new(format!("{p}.ip"), "bad_ip", "нужен IP-адрес сервера: имя не разрешается через открытый DNS"));
        }
    };
    let path_ok = |v: &str| v.starts_with('/') && v.len() <= 128 && v.bytes().all(|c| c.is_ascii_graphic() && c != b'?' && c != b'#');
    if d.transport == DnsTransport::Odoh {
        if !d.servers.is_empty() {
            issues.push(Issue::new("dns.servers", "not_applicable", "для ODoH серверы задаются в dns.odoh"));
        }
        match &d.odoh {
            None => issues.push(Issue::new("dns.odoh", "required", "для ODoH нужны target и хотя бы один relay")),
            Some(o) => {
                let eps = std::iter::once(("dns.odoh.target".to_string(), &o.target)).chain(o.relays.iter().enumerate().map(|(i, r)| (format!("dns.odoh.relays[{i}]"), r)));
                for (p, e) in eps {
                    host(issues, &p, &e.host);
                    ip(issues, &p, &e.ip);
                    if !path_ok(&e.path) {
                        issues.push(Issue::new(format!("{p}.path"), "bad_path", "путь начинается с / и без ? и #"));
                    }
                    if e.port == Some(0) {
                        issues.push(Issue::new(format!("{p}.port"), "bad_port", "порт от 1 до 65535"));
                    }
                }
                if o.relays.is_empty() || o.relays.len() > 4 {
                    issues.push(Issue::new("dns.odoh.relays", "bad_relays", "от 1 до 4 relay; без relay ODoH не отличается от DoH"));
                }
                if o.relays.iter().any(|r| r.host == o.target.host || r.ip == o.target.ip) {
                    issues.push(Issue::new("dns.odoh.relays", "relay_is_target", "relay и target должны быть разными серверами"));
                }
            }
        }
    } else {
        if d.odoh.is_some() {
            issues.push(Issue::new("dns.odoh", "not_applicable", "dns.odoh задаётся только для transport odoh"));
        }
        if d.servers.is_empty() || d.servers.len() > 4 {
            issues.push(Issue::new("dns.servers", "bad_servers", "от 1 до 4 серверов"));
        }
        for (i, sv) in d.servers.iter().enumerate() {
            let p = format!("dns.servers[{i}]");
            host(issues, &p, &sv.host);
            ip(issues, &p, &sv.ip);
            if sv.port == Some(0) {
                issues.push(Issue::new(format!("{p}.port"), "bad_port", "порт от 1 до 65535"));
            }
            match (&sv.path, matches!(d.transport, DnsTransport::Doh | DnsTransport::Doh3)) {
                (Some(_), false) => issues.push(Issue::new(format!("{p}.path"), "not_applicable", "путь задаётся только для DoH и DoH3")),
                (Some(v), true) if !path_ok(v) => issues.push(Issue::new(format!("{p}.path"), "bad_path", "путь начинается с / и без ? и #")),
                _ => {}
            }
        }
    }
    if let Some(a) = &d.adblock {
        if a.exceptions.len() > 256 {
            issues.push(Issue::new("dns.adblock.exceptions", "too_many", "не больше 256 исключений"));
        }
        for (i, e) in a.exceptions.iter().enumerate() {
            if let Err(m) = normalize_domain(e, 2) {
                issues.push(Issue::new(format!("dns.adblock.exceptions[{i}]"), "bad_domain", m));
            }
        }
    }
}

/// Ключ WireGuard: 32 байта в стандартном base64.
pub fn is_wg_key(k: &str) -> bool {
    data_encoding::BASE64.decode(k.as_bytes()).map(|b| b.len() == 32).unwrap_or(false)
}

pub fn check_destination(issues: &mut Vec<Issue>, path: &str, d: &Destination, idx: &Index) {
    match d {
        Destination::Domain { value } => {
            if let Err(e) = normalize_domain(value, 2) {
                issues.push(Issue::new(format!("{path}.value"), "bad_domain", e));
            }
        }
        Destination::DomainSuffix { value } => {
            if let Err(e) = normalize_domain(value, 1) {
                issues.push(Issue::new(format!("{path}.value"), "bad_domain", e));
            }
        }
        Destination::Cidr { value } => {
            if let Err(e) = parse_cidr(value) {
                issues.push(Issue::new(format!("{path}.value"), "bad_cidr", e));
            }
        }
        Destination::Category { id } => {
            if !idx.categories.contains_key(id.as_str()) {
                issues.push(Issue::new(format!("{path}.id"), "unknown_category", format!("категория «{id}» не найдена")));
            }
        }
        Destination::Group { id } => {
            if !idx.groups.contains_key(id.as_str()) {
                issues.push(Issue::new(format!("{path}.id"), "unknown_group", format!("группа «{id}» не найдена")));
            }
        }
    }
}

fn check_action(issues: &mut Vec<Issue>, path: &str, a: &Action, idx: &Index) {
    if let Action::Profile { id } = a {
        if !idx.profiles.contains_key(id.as_str()) {
            issues.push(Issue::new(format!("{path}.id"), "unknown_profile", format!("VPN-профиль «{id}» не найден")));
        }
    }
}

/// Проверка правила в контексте настроек: ссылки на источник, назначение и профиль.
pub fn check_rule_refs(issues: &mut Vec<Issue>, path: &str, r: &Rule, idx: &Index) {
    if let Err(e) = check_id(&r.id) {
        issues.push(Issue::new(format!("{path}.id"), "bad_id", e));
    }
    match &r.source {
        Source::Device { id } if !idx.devices.contains_key(id.as_str()) => {
            issues.push(Issue::new(format!("{path}.source.id"), "unknown_device", format!("устройство «{id}» не найдено")));
        }
        Source::Network { id } if !idx.networks.contains_key(id.as_str()) => {
            issues.push(Issue::new(format!("{path}.source.id"), "unknown_network", format!("сеть «{id}» не найдена")));
        }
        _ => {}
    }
    check_destination(issues, &format!("{path}.destination"), &r.destination, idx);
    check_action(issues, &format!("{path}.action"), &r.action, idx);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_normalization() {
        assert_eq!(normalize_mac("AA-BB-CC-00-11-22").unwrap(), "aa:bb:cc:00:11:22");
        assert!(normalize_mac("01:00:5e:00:00:01").is_err(), "multicast");
        assert!(normalize_mac("ff:ff:ff:ff:ff:ff").is_err(), "broadcast");
        assert!(normalize_mac("00:00:00:00:00:00").is_err());
        assert!(normalize_mac("aa:bb:cc:dd:ee").is_err());
        assert!(normalize_mac("aa:bb:cc:dd:ee:gg").is_err());
    }

    #[test]
    fn domains() {
        assert_eq!(normalize_domain("WWW.YouTube.com.", 2).unwrap(), "www.youtube.com");
        assert_eq!(normalize_domain("ru", 1).unwrap(), "ru");
        assert!(normalize_domain("ru", 2).is_err());
        assert!(normalize_domain("*.youtube.com", 1).is_err());
        assert!(normalize_domain("ютуб.рф", 1).is_err());
        assert!(normalize_domain("-bad.com", 1).is_err());
        assert!(normalize_domain("a..com", 1).is_err());
        assert!(normalize_domain("10.0.0.1", 1).is_err());
        assert!(normalize_domain(&format!("{}.com", "a".repeat(64)), 2).is_err());
    }

    #[test]
    fn cidrs() {
        assert!(parse_cidr("203.0.113.0/24").is_ok());
        assert!(parse_cidr("2001:db8::/32").is_ok());
        assert!(parse_cidr("203.0.113.5/24").unwrap_err().contains("203.0.113.0/24"));
        assert!(parse_cidr("2001:db8::1/32").unwrap_err().contains("2001:db8::/32"));
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("10.0.0.0/0").is_err());
        assert!(parse_cidr("10.0.0.0").is_err());
        assert!(parse_cidr("10.0.0.0/+8").is_err());
        assert!(parse_cidr("10.0.0.1/32").is_ok());
        let a = parse_cidr("10.0.0.0/8").unwrap();
        let b = parse_cidr("10.20.0.0/16").unwrap();
        assert!(a.contains(&b) && !b.contains(&a) && a.overlaps(&b));
        assert!(!a.overlaps(&parse_cidr("11.0.0.0/8").unwrap()));
        assert!(!a.overlaps(&parse_cidr("2001:db8::/32").unwrap()));
        assert!(a.contains_ip("10.1.2.3".parse().unwrap()));
        assert!(parse_cidr("::/1").unwrap().contains_ip("::1".parse().unwrap()));
        assert!(parse_cidr("1.2.3.4/32").unwrap().contains_ip("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn ids() {
        assert!(check_id("tv-1").is_ok());
        assert!(check_id("").is_err());
        assert!(check_id("TV").is_err());
        assert!(check_id("-tv").is_err());
        assert!(check_id(&"a".repeat(33)).is_err());
    }
}
