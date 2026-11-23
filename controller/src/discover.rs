//! Имена устройств, которые они сами объявляют в локальной сети: mDNS/DNS-SD (iPhone, Mac, Chromecast, Android TV,
//! AirPlay-колонки, принтеры) и SSDP/UPnP (телевизоры, медиаплееры). Роутер ничего не слушает постоянно: служба раз в
//! несколько минут вызывает `mi-tt-ctl names-scan`, который шлёт запросы с временного порта — по RFC 6762 §6.7
//! («legacy unicast») устройства отвечают прямо на этот порт, порт 5353 не занимается. Ответ приписывается адресу
//! отправителя, адрес → MAC по арендам DHCP. Итог — `names.json` (MAC → имя, тип, модель), прежние записи сохраняются
//! (устройство может быть выключено), старше 30 суток — удаляются.
//!
//! Всё, что пришло из сети, — недоверенный текст: только печатные символы, до 64 знаков; описание UPnP скачивается
//! лишь с адреса ответившего устройства в LAN, до 64 КиБ, за 2 секунды.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const MDNS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
pub const SSDP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
const KEEP_SECS: u64 = 30 * 86_400;

/// Службы DNS-SD, по которым устройства себя называют (и по которым понятно, что это за устройство).
pub const SERVICES: &[&str] = &[
    "_googlecast._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_companion-link._tcp.local",
    "_androidtvremote2._tcp.local",
    "_spotify-connect._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_hap._tcp.local",
    "_smb._tcp.local",
    "_workstation._tcp.local",
    "_device-info._tcp.local",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub model: String,
    /// mdns | ssdp
    pub source: String,
    /// Насколько имени можно верить: больше — лучше (выбор между ответами разных служб).
    #[serde(default)]
    pub rank: u8,
    #[serde(default)]
    pub seen: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Names {
    pub at: u64,
    pub devices: BTreeMap<String, Found>,
}

/// Только печатные символы, без лишних пробелов, до 64 знаков.
pub fn clean(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    t.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(64).collect()
}

// ---------- DNS ----------

fn put_name(out: &mut Vec<u8>, name: &str) {
    for l in name.trim_end_matches('.').split('.') {
        out.push(l.len().min(63) as u8);
        out.extend_from_slice(&l.as_bytes()[..l.len().min(63)]);
    }
    out.push(0);
}

/// Запрос PTR по списку служб (id 0, без флагов). Отправленный не с порта 5353, он считается legacy unicast.
pub fn query(services: &[&str]) -> Vec<u8> {
    let mut p = vec![0, 0, 0, 0, 0, services.len() as u8, 0, 0, 0, 0, 0, 0];
    p[4] = (services.len() >> 8) as u8;
    for s in services {
        put_name(&mut p, s);
        p.extend_from_slice(&[0, 12, 0, 1]);
    }
    p
}

fn read_name(p: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *p.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *p.get(i + 1)? as usize;
            end.get_or_insert(i + 2);
            jumps += 1;
            if jumps > 16 || ptr >= p.len() {
                return None;
            }
            i = ptr;
            continue;
        }
        let l = p.get(i + 1..i + 1 + len)?;
        labels.push(String::from_utf8_lossy(l).into_owned());
        i += 1 + len;
        if labels.len() > 64 {
            return None;
        }
    }
    Some((labels.join("."), end.unwrap_or(i)))
}

#[derive(Debug, Clone, PartialEq)]
pub enum Rr {
    Ptr(String, String),
    Srv(String, String),
    Txt(String, Vec<String>),
    A(String, Ipv4Addr),
}

/// Записи ответа (ответы, авторитетные и дополнительные): PTR, SRV, TXT, A.
pub fn parse(p: &[u8]) -> Vec<Rr> {
    let mut out = Vec::new();
    if p.len() < 12 || p[2] & 0x80 == 0 {
        return out;
    }
    let n = |k: usize| ((p[k] as usize) << 8) | p[k + 1] as usize;
    let (qd, rrs) = (n(4), n(6) + n(8) + n(10));
    let mut i = 12;
    for _ in 0..qd {
        let Some((_, j)) = read_name(p, i) else { return out };
        i = j + 4;
    }
    for _ in 0..rrs.min(256) {
        let Some((name, j)) = read_name(p, i) else { return out };
        let Some(h) = p.get(j..j + 10) else { return out };
        let ty = ((h[0] as usize) << 8) | h[1] as usize;
        let len = ((h[8] as usize) << 8) | h[9] as usize;
        let d = j + 10;
        let Some(data) = p.get(d..d + len) else { return out };
        match ty {
            12 => {
                if let Some((t, _)) = read_name(p, d) {
                    out.push(Rr::Ptr(name, t));
                }
            }
            33 if len > 6 => {
                if let Some((t, _)) = read_name(p, d + 6) {
                    out.push(Rr::Srv(name, t));
                }
            }
            16 => {
                let mut v = Vec::new();
                let mut k = 0;
                while k < data.len() {
                    let l = data[k] as usize;
                    if let Some(s) = data.get(k + 1..k + 1 + l) {
                        v.push(String::from_utf8_lossy(s).into_owned());
                    }
                    k += 1 + l;
                }
                out.push(Rr::Txt(name, v));
            }
            1 if len == 4 => out.push(Rr::A(name, Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            _ => {}
        }
        i = d + len;
    }
    out
}

fn txt<'a>(rrs: &'a [Rr], inst: &str, key: &str) -> Option<&'a str> {
    rrs.iter().find_map(|r| match r {
        Rr::Txt(n, v) if n.eq_ignore_ascii_case(inst) => v.iter().find_map(|kv| kv.split_once('=').filter(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, x)| x)),
        _ => None,
    })
}

/// Тип по модели Apple (rpMd/model) или по службе.
fn apple_kind(model: &str) -> &'static str {
    let m = model.to_ascii_lowercase();
    if m.starts_with("iphone") { "phone" } else if m.starts_with("ipad") { "tablet" } else if m.starts_with("appletv") { "tv" }
    else if m.starts_with("watch") { "watch" } else if m.starts_with("audioaccessory") || m.starts_with("homepod") { "speaker" }
    else if m.starts_with("mac") || m.contains("book") || m.starts_with("imac") { "computer" } else { "" }
}

/// Что устройство сказало о себе одним ответом mDNS.
pub fn from_mdns(rrs: &[Rr]) -> Option<Found> {
    let mut best: Option<Found> = None;
    fn offer(best: &mut Option<Found>, f: Found) {
        if !f.name.is_empty() && best.as_ref().is_none_or(|b| f.rank > b.rank) {
            *best = Some(f);
        }
    }
    for r in rrs {
        let Rr::Ptr(svc, inst) = r else { continue };
        let svc = svc.to_ascii_lowercase();
        let label = inst.strip_suffix(&format!(".{svc}")).or_else(|| inst.split("._").next()).unwrap_or(inst);
        let (name, kind, model, rank) = match svc.as_str() {
            "_googlecast._tcp.local" => (txt(rrs, inst, "fn").unwrap_or(label).to_string(), "tv", txt(rrs, inst, "md").unwrap_or(""), 9),
            "_airplay._tcp.local" => { let m = txt(rrs, inst, "model").unwrap_or(""); (label.to_string(), if apple_kind(m).is_empty() { "tv" } else { apple_kind(m) }, m, 8) }
            "_companion-link._tcp.local" => { let m = txt(rrs, inst, "rpMd").unwrap_or(""); (label.to_string(), apple_kind(m), m, 8) }
            "_androidtvremote2._tcp.local" => (label.to_string(), "tv", "", 8),
            // «AABBCCDDEEFF@Кухня» — имя после @
            "_raop._tcp.local" => (label.split_once('@').map_or(label, |(_, n)| n).to_string(), "speaker", txt(rrs, inst, "am").unwrap_or(""), 6),
            "_spotify-connect._tcp.local" => (label.to_string(), "speaker", "", 5),
            "_ipp._tcp.local" | "_printer._tcp.local" => (label.to_string(), "printer", txt(rrs, inst, "ty").unwrap_or(""), 7),
            "_hap._tcp.local" => (label.to_string(), "smart", txt(rrs, inst, "md").unwrap_or(""), 5),
            "_smb._tcp.local" | "_workstation._tcp.local" => (label.split(" [").next().unwrap_or(label).to_string(), "computer", "", 4),
            "_device-info._tcp.local" => (label.to_string(), apple_kind(txt(rrs, inst, "model").unwrap_or("")), txt(rrs, inst, "model").unwrap_or(""), 3),
            _ => continue,
        };
        offer(&mut best, Found { name: clean(&name), kind: kind.into(), model: clean(model), source: "mdns".into(), rank, seen: 0 });
    }
    // имя хоста из записи A: «Erlans-iPhone.local» → «Erlans iPhone»
    if best.is_none() {
        if let Some(h) = rrs.iter().find_map(|r| if let Rr::A(n, _) = r { Some(n) } else { None }) {
            let base = h.trim_end_matches(".local").replace('-', " ");
            offer(&mut best, Found { name: clean(&base), source: "mdns".into(), rank: 2, ..Default::default() });
        }
    }
    best
}

// ---------- SSDP / UPnP ----------

pub const MSEARCH: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: upnp:rootdevice\r\n\r\n";

/// LOCATION из ответа SSDP: только http://<адрес отправителя>:<порт>/<путь>.
pub fn ssdp_location(resp: &str, from: Ipv4Addr) -> Option<(u16, String)> {
    let loc = resp.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("location")).map(|(_, v)| v.trim()))?;
    let rest = loc.strip_prefix("http://")?;
    let (hostport, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
    let (host, port) = hostport.rsplit_once(':').map_or((hostport, 80), |(h, p)| (h, p.parse().unwrap_or(0)));
    (host.parse::<Ipv4Addr>().ok()? == from && port > 0 && path.chars().all(|c| c.is_ascii_graphic())).then(|| (port, format!("/{path}")))
}

fn tag<'a>(xml: &'a str, t: &str) -> Option<&'a str> {
    let a = xml.find(&format!("<{t}>"))? + t.len() + 2;
    let b = xml[a..].find(&format!("</{t}>"))? + a;
    Some(xml[a..b].trim())
}

/// Описание устройства UPnP: friendlyName, производитель и модель, тип (MediaRenderer — телевизор или приставка).
pub fn from_upnp(xml: &str) -> Option<Found> {
    let name = clean(tag(xml, "friendlyName")?);
    if name.is_empty() {
        return None;
    }
    let model = clean(&[tag(xml, "manufacturer").unwrap_or(""), tag(xml, "modelName").unwrap_or("")].join(" "));
    let dt = tag(xml, "deviceType").unwrap_or("").to_ascii_lowercase();
    let kind = if dt.contains("mediarenderer") || dt.contains("tv") { "tv" } else if dt.contains("printer") { "printer" } else if dt.contains("mediaserver") || dt.contains("nas") { "storage" } else { "" };
    Some(Found { name, kind: kind.into(), model, source: "ssdp".into(), rank: 7, seen: 0 })
}

fn http_get(ip: Ipv4Addr, port: u16, path: &str) -> Option<String> {
    let mut s = TcpStream::connect_timeout(&SocketAddrV4::new(ip, port).into(), Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(s, "GET {path} HTTP/1.0\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n").ok()?;
    let mut buf = Vec::new();
    s.take(64 * 1024).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

// ---------- сбор ----------

fn socket(from: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let s = UdpSocket::bind(SocketAddrV4::new(from, 0))?;
    s.set_multicast_ttl_v4(1)?;
    s.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok(s)
}

/// Опрос LAN: ответы mDNS и SSDP за `wait`; адрес отправителя → находка (лучшая по rank).
pub fn scan(from: Ipv4Addr, wait: Duration) -> std::io::Result<BTreeMap<Ipv4Addr, Found>> {
    let m = socket(from)?;
    let u = socket(from)?;
    let q = query(SERVICES);
    m.send_to(&q, MDNS)?;
    u.send_to(MSEARCH.as_bytes(), SSDP)?;
    let mut out: BTreeMap<Ipv4Addr, Found> = BTreeMap::new();
    let mut locations: BTreeMap<Ipv4Addr, (u16, String)> = BTreeMap::new();
    let start = Instant::now();
    let mut resent = false;
    let mut buf = [0u8; 9000];
    while start.elapsed() < wait {
        // повтор запроса mDNS: часть устройств пропускает первый (спящий Wi‑Fi)
        if !resent && start.elapsed() > wait / 2 {
            let _ = m.send_to(&q, MDNS);
            resent = true;
        }
        if let Ok((n, std::net::SocketAddr::V4(a))) = m.recv_from(&mut buf) {
            if *a.ip() != from {
                if let Some(f) = from_mdns(&parse(&buf[..n])) {
                    let e = out.entry(*a.ip()).or_default();
                    if f.rank > e.rank {
                        *e = f;
                    }
                }
            }
        }
        if let Ok((n, std::net::SocketAddr::V4(a))) = u.recv_from(&mut buf) {
            if *a.ip() != from {
                if let Some(l) = ssdp_location(&String::from_utf8_lossy(&buf[..n]), *a.ip()) {
                    locations.entry(*a.ip()).or_insert(l);
                }
            }
        }
    }
    for (ip, (port, path)) in locations {
        if out.get(&ip).is_some_and(|f| f.rank >= 7) {
            continue;
        }
        if let Some(f) = http_get(ip, port, &path).and_then(|r| from_upnp(&r)) {
            let e = out.entry(ip).or_default();
            if f.rank > e.rank {
                *e = f;
            }
        }
    }
    Ok(out)
}

/// Слияние с прежним файлом: новые находки по MAC (адрес без аренды — пропускается), устаревшие — удаляются.
pub fn merge(prev: Names, found: BTreeMap<Ipv4Addr, Found>, ip_mac: &BTreeMap<String, String>, now: u64) -> Names {
    let mut d = prev.devices;
    for (ip, mut f) in found {
        let Some(mac) = ip_mac.get(&ip.to_string()) else { continue };
        f.seen = now;
        d.insert(mac.clone(), f);
    }
    d.retain(|_, f| f.seen + KEEP_SECS > now);
    Names { at: now, devices: d }
}

/// `mi-tt-ctl names-scan --from <IPv4 LAN> --out <names.json> [--wait <мс>]`
pub fn scan_cmd(from: &str, out: &str, wait_ms: u64, now: u64) -> Result<usize, String> {
    let from: Ipv4Addr = from.parse().map_err(|_| "--from: IPv4-адрес роутера в LAN".to_string())?;
    let found = scan(from, Duration::from_millis(wait_ms.clamp(500, 10_000))).map_err(|e| format!("опрос сети: {e}"))?;
    let leases = String::from_utf8_lossy(&crate::api::read_limited(&crate::manage::leases_path().to_string_lossy(), 1024 * 1024).unwrap_or_default()).into_owned();
    let p = std::path::Path::new(out);
    let prev: Names = crate::api::read_limited(out, 512 * 1024).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let n = found.len();
    let names = merge(prev, found, &crate::stats::ip_to_mac(&leases), now);
    crate::store::write_atomic(p, &serde_json::to_vec(&names).map_err(|e| e.to_string())?)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ответ mDNS из записей (имена без сжатия).
    fn answer(rrs: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, rrs.len() as u8, 0, 0, 0, 0];
        for (name, ty, data) in rrs {
            put_name(&mut p, name);
            p.extend_from_slice(&[(ty >> 8) as u8, *ty as u8, 0x80, 1, 0, 0, 0x11, 0x94, (data.len() >> 8) as u8, data.len() as u8]);
            p.extend_from_slice(data);
        }
        p
    }
    fn nm(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        put_name(&mut v, s);
        v
    }
    fn txtd(kv: &[&str]) -> Vec<u8> {
        kv.iter().flat_map(|s| std::iter::once(s.len() as u8).chain(s.bytes())).collect()
    }

    #[test]
    fn query_has_all_services() {
        let q = query(SERVICES);
        assert_eq!(q[5] as usize, SERVICES.len());
        assert!(q.windows(11).any(|w| w == b"_googlecast"));
    }

    #[test]
    fn chromecast_friendly_name_from_txt() {
        let inst = "Chromecast-8a1b._googlecast._tcp.local";
        let p = answer(&[
            ("_googlecast._tcp.local", 12, nm(inst)),
            (inst, 16, txtd(&["id=8a1b", "md=Chromecast", "fn=Гостиная ТВ"])),
            (inst, 33, [vec![0, 0, 0, 0, 0x1f, 0x49], nm("8a1b.local")].concat()),
            ("8a1b.local", 1, vec![192, 168, 31, 20]),
        ]);
        let f = from_mdns(&parse(&p)).unwrap();
        assert_eq!((f.name.as_str(), f.kind.as_str(), f.model.as_str()), ("Гостиная ТВ", "tv", "Chromecast"));
    }

    #[test]
    fn iphone_companion_link_and_raop() {
        let inst = "iPhone Эрлана._companion-link._tcp.local";
        let p = answer(&[("_companion-link._tcp.local", 12, nm(inst)), (inst, 16, txtd(&["rpMd=iPhone15,2", "rpVr=500"]))]);
        let f = from_mdns(&parse(&p)).unwrap();
        assert_eq!((f.name.as_str(), f.kind.as_str()), ("iPhone Эрлана", "phone"));
        let r = answer(&[("_raop._tcp.local", 12, nm("AABBCCDDEEFF@Кухня._raop._tcp.local"))]);
        assert_eq!(from_mdns(&parse(&r)).unwrap().name, "Кухня");
        // только запись A — имя хоста
        let a = answer(&[("Erlans-MacBook.local", 1, vec![192, 168, 31, 5])]);
        assert_eq!(from_mdns(&parse(&a)).unwrap().name, "Erlans MacBook");
    }

    #[test]
    fn malformed_packets_do_not_panic() {
        for p in [vec![], vec![0; 11], vec![0, 0, 0x84, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0xC0, 0x0C], vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 63]] {
            assert!(from_mdns(&parse(&p)).is_none());
        }
        // имя с петлёй указателей
        let mut p = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 12];
        p.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 1, 0, 2, 0xC0, 12]);
        let _ = parse(&p);
    }

    #[test]
    fn ssdp_and_upnp() {
        let from = Ipv4Addr::new(192, 168, 31, 30);
        let r = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.31.30:9197/dmr\r\nST: upnp:rootdevice\r\n\r\n";
        assert_eq!(ssdp_location(r, from), Some((9197, "/dmr".into())));
        // описание только с адреса ответившего
        assert_eq!(ssdp_location("LOCATION: http://10.0.0.1:80/x\r\n", from), None);
        let xml = "<root><device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>[TV] Samsung 7 Series</friendlyName><manufacturer>Samsung Electronics</manufacturer><modelName>UE55</modelName></device></root>";
        let f = from_upnp(xml).unwrap();
        assert_eq!((f.name.as_str(), f.kind.as_str(), f.model.as_str()), ("[TV] Samsung 7 Series", "tv", "Samsung Electronics UE55"));
    }

    #[test]
    fn merge_keeps_old_and_maps_by_mac() {
        let mut ip_mac = BTreeMap::new();
        ip_mac.insert("192.168.31.20".to_string(), "aa:bb:cc:dd:ee:01".to_string());
        let mut found = BTreeMap::new();
        found.insert(Ipv4Addr::new(192, 168, 31, 20), Found { name: "ТВ".into(), source: "mdns".into(), rank: 9, ..Default::default() });
        found.insert(Ipv4Addr::new(192, 168, 31, 99), Found { name: "без аренды".into(), ..Default::default() });
        let mut prev = Names::default();
        prev.devices.insert("aa:bb:cc:dd:ee:02".into(), Found { name: "старое".into(), seen: 20 * 86_400, ..Default::default() });
        prev.devices.insert("aa:bb:cc:dd:ee:03".into(), Found { name: "очень старое".into(), seen: 1, ..Default::default() });
        let n = merge(prev, found, &ip_mac, 31 * 86_400);
        assert_eq!(n.devices.keys().cloned().collect::<Vec<_>>(), vec!["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]);
        let n2 = merge(n, BTreeMap::new(), &ip_mac, 51 * 86_400);
        assert!(!n2.devices.contains_key("aa:bb:cc:dd:ee:02"));
    }

    #[test]
    fn clean_strips_controls_and_limits() {
        assert_eq!(clean("a\u{0}b\n  c"), "a b c");
        assert_eq!(clean(&"x".repeat(100)).len(), 64);
    }
}
