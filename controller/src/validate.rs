//! Проверка настроек и черновика правила. Сообщения — для панели, на русском.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::Serialize;

use crate::model::*;
use crate::zapret::Kind;

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

pub const MAX_PANEL_ORIGINS: usize = 16;

/// Адрес панели — как его присылает браузер в Origin: `https://хост` или `https://хост:порт`, без пути и `*`.
/// Только HTTPS: вход в панель (cookie __Host-) по HTTP не работает.
pub fn check_panel_origin(o: &str) -> Result<(), String> {
    let rest = o.strip_prefix("https://").ok_or("адрес панели — https://хост или https://хост:порт")?;
    let (host, port) = rest.split_once(':').map_or((rest, None), |(h, p)| (h, Some(p)));
    let host_ok = !host.is_empty() && host.len() <= 253 && host.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'));
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.len() <= 5 && p.bytes().all(|c| c.is_ascii_digit()) && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n)));
    if host_ok && port_ok { Ok(()) } else { Err("адрес панели — https://хост или https://хост:порт (строчными буквами, без пути)".into()) }
}

/// Имён устройств — не больше (у дома столько устройств не бывает; защита размера настроек).
pub const MAX_DEVICE_NAMES: usize = 512;

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
    limit(&mut issues, "device_names", c.device_names.len(), MAX_DEVICE_NAMES);
    limit(&mut issues, "panel_origins", c.panel_origins.len(), MAX_PANEL_ORIGINS);
    for (i, o) in c.panel_origins.iter().enumerate() {
        if let Err(m) = check_panel_origin(o) {
            issues.push(Issue::new(format!("panel_origins[{i}]"), "bad_origin", m));
        }
    }
    for (mac, name) in &c.device_names {
        if normalize_mac(mac).ok().as_deref() != Some(mac.as_str()) {
            issues.push(Issue::new(format!("device_names.{mac}"), "bad_mac", "MAC-адрес ожидается в виде aa:bb:cc:dd:ee:ff"));
        }
        if name.trim().is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            issues.push(Issue::new(format!("device_names.{mac}"), "bad_name", "имя — от 1 до 64 печатных символов"));
        }
    }
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

    if c.profiles.len() > 1 {
        issues.push(Issue::new("profiles", "too_many_profiles", "поддерживается один профиль TrustTunnel"));
    }
    for (i, p) in c.profiles.iter().enumerate() {
        if let Some(e) = &p.endpoint {
            check_endpoint(&mut issues, &format!("profiles[{i}].endpoint"), e);
        }
        if let Some(b) = &p.backup {
            check_endpoint(&mut issues, &format!("profiles[{i}].backup"), b);
            if p.endpoint.is_none() {
                issues.push(Issue::new(format!("profiles[{i}].backup"), "backup_without_primary", "запасной сервер задаётся вместе с основным"));
            }
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
        for (path, kind, id) in [("zapret.strategy", Kind::General, &z.strategy), ("zapret.youtube", Kind::Youtube, &z.youtube)] {
            if let Some((code, m)) = crate::zapret::check(kind, id) {
                issues.push(Issue::new(path, code, m));
            }
        }
    }
    issues
}

/// Сертификат сервера в PEM: один или несколько блоков CERTIFICATE, только печатные ASCII и переводы строк.
pub fn check_certificate(pem: &str) -> Result<(), String> {
    if pem.len() > 16 * 1024 {
        return Err("сертификат больше 16 КиБ".into());
    }
    if !pem.bytes().all(|c| c == b'\n' || c == b'\r' || (0x20..0x7f).contains(&c)) {
        return Err("сертификат — текст PEM без управляющих и не-ASCII символов".into());
    }
    let t = pem.trim();
    // в client.toml PEM записывается литеральной строкой TOML '''…''': апострофов в сертификате быть не должно
    if !t.starts_with("-----BEGIN CERTIFICATE-----") || !t.ends_with("-----END CERTIFICATE-----") || t.contains('\'') {
        return Err("нужен сертификат PEM: -----BEGIN CERTIFICATE----- … -----END CERTIFICATE-----".into());
    }
    Ok(())
}

/// Ссылка на список для загрузки службой (curl в сценарии): только https, печатные ASCII без пробелов и кавычек.
pub fn check_list_url(u: &str) -> bool {
    u.len() <= 512 && u.starts_with("https://") && u.len() > "https://".len() && u.bytes().all(|c| c.is_ascii_graphic() && !b"\"'`\\$<>|;".contains(&c))
}

/// Строка для client.toml и аргументов: без кавычек, обратной косой черты и управляющих символов.
pub fn plain_text(v: &str) -> bool {
    !v.chars().any(|c| c.is_control() || c == '"' || c == '\\')
}

fn check_endpoint(issues: &mut Vec<Issue>, path: &str, e: &Endpoint) {
    // IP-адрес или доменное имя: домен клиент TrustTunnel разрешает сам через DNS роутера
    if e.server.parse::<IpAddr>().is_err() && normalize_domain(&e.server, 1).is_err() {
        issues.push(Issue::new(format!("{path}.server"), "bad_server", "адрес сервера — IP-адрес или доменное имя, например vpn.example.com"));
    }
    if e.port == 0 {
        issues.push(Issue::new(format!("{path}.port"), "bad_port", "порт должен быть от 1 до 65535"));
    }
    if let Some(sni) = &e.sni {
        if let Err(m) = normalize_domain(sni, 1) {
            issues.push(Issue::new(format!("{path}.sni"), "bad_sni", m));
        }
    }
    if e.username.is_empty() || e.username.len() > 64 || e.username.contains(':') || !plain_text(&e.username) {
        issues.push(Issue::new(format!("{path}.username"), "bad_username", "имя пользователя: 1–64 символа без «:», кавычек, «\\» и управляющих"));
    }
    if let Some(c) = &e.certificate {
        if let Err(m) = check_certificate(c) {
            issues.push(Issue::new(format!("{path}.certificate"), "bad_certificate", m));
        }
    }
    // client_random: «prefix[/mask]» — hex, маска той же длины; ключ — hex. Клиент берёт ключ, если заданы оба: не путаем
    let hex = |s: &str| !s.is_empty() && s.len() <= 64 && s.len() % 2 == 0 && s.bytes().all(|c| c.is_ascii_hexdigit());
    if let Some(r) = &e.client_random {
        let ok = match r.split_once('/') {
            Some((p, m)) => hex(p) && hex(m) && p.len() == m.len(),
            None => hex(r),
        };
        if !ok {
            issues.push(Issue::new(format!("{path}.client_random"), "bad_client_random", "client_random — hex-строка (чётная длина, до 64 знаков), с маской: «префикс/маска» одинаковой длины"));
        }
    }
    if let Some(k) = &e.client_random_auth_key {
        if !hex(k) {
            issues.push(Issue::new(format!("{path}.client_random_auth_key"), "bad_client_random_auth_key", "ключ client_random — hex-строка чётной длины, до 64 знаков"));
        }
    }
    if e.client_random.is_some() && e.client_random_auth_key.is_some() {
        issues.push(Issue::new(format!("{path}.client_random"), "client_random_conflict", "задайте что-то одно: префикс client_random или ключ client_random"));
    }
}

fn check_dns(issues: &mut Vec<Issue>, d: &DnsConfig) {
    if let Some(r) = &d.tunnel_resolver {
        match r.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) if !a.is_unspecified() && !a.is_loopback() && !a.is_private() && !a.is_link_local() && !a.is_multicast() => {}
            _ => issues.push(Issue::new("dns.tunnel_resolver", "bad_resolver", "резолвер туннеля — публичный IPv4-адрес DNS-сервера, например 1.1.1.1")),
        }
    }
    if let Some(Err(m)) = d.tunnel_proxy_args() {
        issues.push(Issue::new("dns.tunnel_secure", "tunnel_secure_unavailable", m));
    }
    if let Some(s) = &d.secure {
        // DoH у Quad9 — только HTTP/2, а mi-tt-dns говорит HTTP/1.1 (сервер отвечает 505)
        if s.protocol == SecureProto::Doh && s.server == SecureServer::Quad9 {
            issues.push(Issue::new("dns.secure.server", "quad9_doh", "Quad9 по DoH работает только через HTTP/2 — выберите DoT или другой сервер"));
        }
        match s.server {
            SecureServer::Nextdns => {
                if !s.nextdns_id.as_deref().is_some_and(|i| i.len() == 6 && i.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())) {
                    issues.push(Issue::new("dns.secure.nextdns_id", "bad_nextdns_id", "ID профиля NextDNS — 6 символов 0-9 и a-f из личного кабинета"));
                }
            }
            SecureServer::Custom => {
                let ok = match (s.protocol, s.url.as_deref()) {
                    (SecureProto::Doh, Some(u)) => check_list_url(u) && u.trim_start_matches("https://").split(['/', ':']).next().is_some_and(|h| normalize_domain(h, 2).is_ok()),
                    (SecureProto::Dot, Some(u)) => u.rsplit_once(':').map_or(u, |(h, p)| if p.parse::<u16>().is_ok() { h } else { u }) != ""
                        && normalize_domain(u.rsplit_once(':').filter(|(_, p)| p.parse::<u16>().is_ok()).map_or(u, |(h, _)| h), 2).is_ok(),
                    _ => false,
                };
                if !ok {
                    issues.push(Issue::new("dns.secure.url", "bad_url", match s.protocol {
                        SecureProto::Doh => "сервер DoH — ссылка https://имя/путь, например https://dns.example/dns-query",
                        SecureProto::Dot => "сервер DoT — имя сервера, например dns.example или dns.example:853",
                    }));
                }
                if s.ips.is_empty() || s.ips.len() > 4 || !s.ips.iter().all(|i| i.parse::<IpAddr>().is_ok_and(|a| !a.is_unspecified() && !a.is_loopback() && !a.is_multicast())) {
                    issues.push(Issue::new("dns.secure.ips", "bad_ips", "IP-адреса сервера — от 1 до 4, через них роутер подключается без DNS"));
                }
            }
            _ => {}
        }
    }
    if d.hosts.len() > 256 {
        issues.push(Issue::new("dns.hosts", "too_many", "не больше 256 своих записей"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (i, h) in d.hosts.iter().enumerate() {
        match normalize_domain(&h.domain, 1) {
            Ok(n) if !seen.insert(n.clone()) => issues.push(Issue::new(format!("dns.hosts[{i}].domain"), "duplicate", format!("{n}: запись для этого домена уже есть"))),
            Ok(_) => {}
            Err(m) => issues.push(Issue::new(format!("dns.hosts[{i}].domain"), "bad_domain", m)),
        }
        match h.address.parse::<IpAddr>() {
            Ok(a) if !a.is_unspecified() && !a.is_multicast() => {}
            _ => issues.push(Issue::new(format!("dns.hosts[{i}].address"), "bad_address", "адрес — IPv4 или IPv6, например 192.168.31.10")),
        }
    }
    if let Some(a) = &d.adblock {
        if a.source == AdblockSource::Url {
            match a.url.as_deref() {
                Some(u) if check_list_url(u) => {}
                _ => issues.push(Issue::new("dns.adblock.url", "bad_url", "ссылка на список — https://…, без пробелов и кавычек, до 512 символов")),
            }
        }
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
    fn endpoint_server_ip_or_domain() {
        let ep = |s: &str| Endpoint { server: s.into(), port: 443, sni: None, username: "u".into(), quic: false, anti_dpi: false, certificate: None, tls_profile: None, client_random: None, client_random_auth_key: None };
        for ok in ["203.0.113.10", "2001:db8::1", "tunnel.example.com"] {
            let mut i = Vec::new();
            check_endpoint(&mut i, "e", &ep(ok));
            assert!(i.is_empty(), "{ok}");
        }
        for bad in ["", "tunnel example", "a..com", "host:443"] {
            let mut i = Vec::new();
            check_endpoint(&mut i, "e", &ep(bad));
            assert!(i.iter().any(|x| x.code == "bad_server"), "{bad}");
        }
    }

    #[test]
    fn endpoint_client_random() {
        let base = || Endpoint { server: "203.0.113.10".into(), port: 443, sni: None, username: "u".into(), quic: false, anti_dpi: false, certificate: None, tls_profile: None, client_random: None, client_random_auth_key: None };
        let codes = |e: Endpoint| {
            let mut i = Vec::new();
            check_endpoint(&mut i, "e", &e);
            i.into_iter().map(|x| x.code).collect::<Vec<_>>()
        };
        assert!(codes(Endpoint { client_random: Some("ab12".into()), ..base() }).is_empty());
        assert!(codes(Endpoint { client_random: Some("ab12/ff00".into()), ..base() }).is_empty());
        assert!(codes(Endpoint { client_random_auth_key: Some("00112233445566778899aabbccddeeff".into()), ..base() }).is_empty());
        for bad in ["", "abc", "zz", "ab12/ff", "ab12/"] {
            assert_eq!(codes(Endpoint { client_random: Some(bad.into()), ..base() }), ["bad_client_random"], "{bad}");
        }
        assert_eq!(codes(Endpoint { client_random_auth_key: Some("xyz0".into()), ..base() }), ["bad_client_random_auth_key"]);
        assert_eq!(codes(Endpoint { client_random: Some("ab".into()), client_random_auth_key: Some("cd".into()), ..base() }), ["client_random_conflict"]);
        let e: Endpoint = serde_json::from_str(r#"{"server":"203.0.113.10","port":443,"username":"u","tls_profile":"chrome_canary"}"#).unwrap();
        assert_eq!(e.tls_profile, Some(crate::model::TlsProfile::ChromeCanary));
        assert!(serde_json::from_str::<Endpoint>(r#"{"server":"x","port":1,"username":"u","tls_profile":"default"}"#).is_err());
    }

    #[test]
    fn own_host_records() {
        let rec = |d: &str, a: &str| HostRecord { domain: d.into(), address: a.into() };
        let check = |h: Vec<HostRecord>| {
            let mut i = Vec::new();
            check_dns(&mut i, &DnsConfig { tunnel_resolver: None, tunnel_secure: None, adblock: None, secure: None, hosts: h });
            i.into_iter().map(|x| format!("{}:{}", x.path, x.code)).collect::<Vec<_>>()
        };
        assert!(check(vec![rec("home.example.com", "192.168.31.10"), rec("nas", "fd00::5")]).is_empty());
        assert_eq!(check(vec![rec("home.example.com", "192.168.31.10"), rec("Home.Example.com.", "192.168.31.11")]), ["dns.hosts[1].domain:duplicate"]);
        assert_eq!(check(vec![rec("*.home.example.com", "0.0.0.0")]), ["dns.hosts[0].domain:bad_domain", "dns.hosts[0].address:bad_address"]);
        assert_eq!(check(vec![rec("home.example.com", "192.168.31.10/24")]), ["dns.hosts[0].address:bad_address"]);
    }

    #[test]
    fn secure_dns_checks() {
        let check = |json: &str| {
            let mut i = Vec::new();
            let secure: SecureDns = serde_json::from_str(json).unwrap();
            check_dns(&mut i, &DnsConfig { tunnel_resolver: None, tunnel_secure: None, adblock: None, secure: Some(secure), hosts: vec![] });
            i.into_iter().map(|x| x.code).collect::<Vec<_>>()
        };
        assert!(check(r#"{"protocol":"doh","server":"google"}"#).is_empty());
        assert_eq!(check(r#"{"protocol":"doh","server":"quad9"}"#), ["quad9_doh"]);
        assert!(check(r#"{"protocol":"dot","server":"quad9"}"#).is_empty());
        assert_eq!(check(r#"{"protocol":"doh","server":"nextdns","nextdns_id":"ABC123"}"#), ["bad_nextdns_id"]);
        assert!(check(r#"{"protocol":"dot","server":"nextdns","nextdns_id":"abc123"}"#).is_empty());
        assert!(check(r#"{"protocol":"doh","server":"custom","url":"https://dns.example/dns-query","ips":["203.0.113.5"]}"#).is_empty());
        assert!(check(r#"{"protocol":"dot","server":"custom","url":"dns.example:853","ips":["203.0.113.5","2001:db8::5"]}"#).is_empty());
        assert_eq!(check(r#"{"protocol":"doh","server":"custom","url":"http://dns.example/q","ips":["203.0.113.5"]}"#), ["bad_url"]);
        assert_eq!(check(r#"{"protocol":"dot","server":"custom","url":"dns.example","ips":[]}"#), ["bad_ips"]);
        assert_eq!(check(r#"{"protocol":"dot","server":"custom","url":"dns.example","ips":["127.0.0.1"]}"#), ["bad_ips"]);
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
