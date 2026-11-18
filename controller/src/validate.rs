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
}

impl<'a> Index<'a> {
    pub fn new(c: &'a Config) -> Self {
        Index {
            profiles: c.profiles.iter().map(|x| (x.id.as_str(), x)).collect(),
            networks: c.networks.iter().map(|x| (x.id.as_str(), x)).collect(),
            devices: c.devices.iter().map(|x| (x.id.as_str(), x)).collect(),
            groups: c.groups.iter().map(|x| (x.id.as_str(), x)).collect(),
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
            check_endpoint(&mut issues, &format!("profiles[{i}].endpoint"), e);
        }
    }

    for (i, r) in c.rules.iter().enumerate() {
        check_rule_refs(&mut issues, &format!("rules[{i}]"), r, &idx);
    }
    check_action(&mut issues, "default_action", &c.default_action, &idx);
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

fn check_endpoint(issues: &mut Vec<Issue>, path: &str, e: &Endpoint) {
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
    if e.username.is_empty() || e.username.len() > 64 || e.username.chars().any(|c| c.is_control() || c == ':') {
        issues.push(Issue::new(format!("{path}.username"), "bad_username", "имя пользователя: 1–64 символа без ':' и управляющих"));
    }
    if let Some(fp) = &e.cert_sha256 {
        if let Err(m) = normalize_sha256(fp) {
            issues.push(Issue::new(format!("{path}.cert_sha256"), "bad_fingerprint", m));
        }
    }
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
