//! Серверы модуля sing-box: разбор ссылок `vless://`, `hysteria2://` (`hy2://`), `trojan://`, `ss://` и конфигурация
//! sing-box для одного туннеля. Ссылка целиком — секрет профиля (`secrets.json`, поле `link`): в ней UUID или пароль.
//! В настройках хранится только сводка (`ProxyInfo`) для панели.
//!
//! sing-box запускается на каждый такой туннель: вход — TUN `mitt<n>` без своей маршрутизации (`auto_route: false`,
//! маршруты и метки держит mi-tt-admin), выход — один сервер. Имя сервера sing-box разрешает через системный DNS
//! роутера (dnsmasq). Схема проверена `sing-box check` 1.14.4.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::model::ProfileKind;

/// Сводка сервера для показа в панели (без секрета).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyInfo {
    pub server: String,
    pub port: u16,
    /// none | tls | reality
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    /// tcp | ws | grpc | http | httpupgrade | quic | …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
}

/// Разобранная ссылка.
#[derive(Debug, Clone, PartialEq)]
pub struct Proxy {
    pub kind: ProfileKind,
    pub info: ProxyInfo,
    /// Имя из `#фрагмента` ссылки.
    pub name: Option<String>,
    /// Выход sing-box без `tag`.
    pub outbound: Value,
    /// Параметры ссылки, которые не поддерживаются и пропущены.
    pub warnings: Vec<String>,
}

const MAX_LINK: usize = 4096;

fn pct_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3).and_then(|x| u8::from_str_radix(x, 16).ok()).ok_or("неверное %-кодирование в ссылке")?;
            out.push(h);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "ссылка содержит не UTF-8".to_string())
}

fn b64(s: &str) -> Option<Vec<u8>> {
    let t: String = s.trim().chars().filter(|c| !c.is_whitespace()).collect();
    let t = t.trim_end_matches('=');
    let std = t.replace('-', "+").replace('_', "/");
    data_encoding::BASE64_NOPAD.decode(std.as_bytes()).ok()
}

fn host_ok(h: &str) -> bool {
    h.parse::<std::net::IpAddr>().is_ok() || crate::validate::normalize_domain(h, 1).is_ok()
}

/// `host:port`, IPv6 — в квадратных скобках.
fn host_port(s: &str) -> Result<(String, u16), String> {
    let (h, p) = if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or("неверный адрес IPv6 в ссылке")?;
        (h.to_string(), tail.strip_prefix(':').ok_or("в ссылке нет порта сервера")?)
    } else {
        let (h, p) = s.rsplit_once(':').ok_or("в ссылке нет порта сервера")?;
        (h.to_string(), p)
    };
    let port: u16 = p.parse().ok().filter(|p| *p > 0).ok_or("порт сервера — число от 1 до 65535")?;
    if !host_ok(&h) {
        return Err("адрес сервера — IP-адрес или доменное имя".into());
    }
    Ok((h, port))
}

struct Parts {
    user: String,
    host: String,
    port: u16,
    query: Vec<(String, String)>,
    name: Option<String>,
}

/// `схема://user@host:port[/путь][?query][#name]`; user уже раскодирован.
fn split(rest: &str) -> Result<Parts, String> {
    let (main, frag) = rest.split_once('#').map_or((rest, None), |(a, b)| (a, Some(b)));
    let (main, q) = main.split_once('?').map_or((main, ""), |(a, b)| (a, b));
    let (user, hp) = main.rsplit_once('@').ok_or("в ссылке нет учётных данных (часть до @)")?;
    let hp = hp.trim_end_matches('/');
    let (host, port) = host_port(hp)?;
    let mut query = Vec::new();
    for kv in q.split('&').filter(|x| !x.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        query.push((pct_decode(k)?, pct_decode(&v.replace('+', "%20"))?));
    }
    let name = frag.map(pct_decode).transpose()?.map(|n| n.chars().filter(|c| !c.is_control()).take(64).collect::<String>()).filter(|n| !n.trim().is_empty());
    Ok(Parts { user: pct_decode(user)?, host, port, query, name })
}

struct Q<'a> {
    q: &'a [(String, String)],
    used: std::cell::RefCell<Vec<&'a str>>,
}

impl<'a> Q<'a> {
    fn get(&self, k: &'a str) -> Option<&'a str> {
        self.used.borrow_mut().push(k);
        self.q.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
    }
    fn flag(&self, k: &'a str) -> bool {
        matches!(self.get(k), Some("1" | "true" | "yes"))
    }
    /// Параметры, которые не прочитаны (без известных безвредных).
    fn unused(&self) -> Vec<String> {
        const HARMLESS: &[&str] = &["encryption", "headerType", "spx", "remarks", "mode", "authority", "allowinsecure", "ech"];
        let used = self.used.borrow();
        self.q.iter().filter(|(k, v)| !v.is_empty() && !used.contains(&k.as_str()) && !HARMLESS.contains(&k.as_str())).map(|(k, _)| k.clone()).collect()
    }
}

fn clean(v: &str, what: &str) -> Result<String, String> {
    if v.is_empty() || v.len() > 512 || v.chars().any(char::is_control) {
        return Err(format!("{what}: пусто, слишком длинно или есть управляющие символы"));
    }
    Ok(v.to_string())
}

/// `tls` sing-box из параметров ссылки: security (tls/reality/none), sni, alpn, fp, pbk, sid, allowInsecure.
fn tls(q: &Q, host: &str, default_on: bool, alpn_default: Option<&[&str]>) -> Result<(Option<Value>, String), String> {
    let sec = q.get("security").unwrap_or(if default_on { "tls" } else { "none" }).to_ascii_lowercase();
    if sec == "none" || sec.is_empty() {
        return Ok((None, "none".into()));
    }
    if sec != "tls" && sec != "reality" && sec != "xtls" {
        return Err(format!("шифрование «{sec}» не поддерживается"));
    }
    let mut t = Map::new();
    t.insert("enabled".into(), json!(true));
    let sni = q.get("sni").or(q.get("peer")).map(String::from).or_else(|| host.parse::<std::net::IpAddr>().is_err().then(|| host.to_string()));
    if let Some(s) = sni {
        t.insert("server_name".into(), json!(clean(&s, "имя сервера (sni)")?));
    }
    if q.flag("allowInsecure") || q.flag("insecure") {
        t.insert("insecure".into(), json!(true));
    }
    match q.get("alpn") {
        Some(a) => {
            t.insert("alpn".into(), json!(a.split(',').map(str::trim).filter(|x| !x.is_empty()).collect::<Vec<_>>()));
        }
        None => {
            if let Some(d) = alpn_default {
                t.insert("alpn".into(), json!(d));
            }
        }
    }
    let fp = q.get("fp").map(str::to_ascii_lowercase);
    if let Some(fp) = &fp {
        const FPS: &[&str] = &["chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"];
        if !FPS.contains(&fp.as_str()) {
            return Err(format!("отпечаток TLS «{fp}» не поддерживается"));
        }
    }
    if sec == "reality" {
        let pbk = q.get("pbk").ok_or("в ссылке Reality нет открытого ключа (pbk)")?;
        let mut r = Map::new();
        r.insert("enabled".into(), json!(true));
        r.insert("public_key".into(), json!(clean(pbk, "ключ Reality")?));
        if let Some(sid) = q.get("sid") {
            if !sid.bytes().all(|c| c.is_ascii_hexdigit()) || sid.len() > 16 {
                return Err("short id Reality — до 16 шестнадцатеричных символов".into());
            }
            r.insert("short_id".into(), json!(sid));
        }
        t.insert("reality".into(), Value::Object(r));
        // Reality работает только с uTLS
        t.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp.clone().unwrap_or_else(|| "chrome".into()) }));
    } else if let Some(fp) = fp {
        t.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
    }
    Ok((Some(Value::Object(t)), if sec == "reality" { "reality".into() } else { "tls".into() }))
}

/// Транспорт V2Ray (type=ws|grpc|http|h2|httpupgrade); tcp — без транспорта.
fn transport(q: &Q) -> Result<(Option<Value>, String), String> {
    let ty = q.get("type").unwrap_or("tcp").to_ascii_lowercase();
    let host = q.get("host");
    let path = q.get("path");
    let v = match ty.as_str() {
        "tcp" | "raw" => None,
        "ws" | "websocket" => {
            let mut m = json!({ "type": "ws", "path": path.unwrap_or("/") });
            if let Some(h) = host {
                m["headers"] = json!({ "Host": h });
            }
            Some(m)
        }
        "httpupgrade" => {
            let mut m = json!({ "type": "httpupgrade", "path": path.unwrap_or("/") });
            if let Some(h) = host {
                m["host"] = json!(h);
            }
            Some(m)
        }
        "grpc" => Some(json!({ "type": "grpc", "service_name": q.get("serviceName").unwrap_or("") })),
        "http" | "h2" => {
            let mut m = json!({ "type": "http", "path": path.unwrap_or("/") });
            if let Some(h) = host {
                m["host"] = json!(h.split(',').map(str::trim).collect::<Vec<_>>());
            }
            Some(m)
        }
        other => return Err(format!("транспорт «{other}» не поддерживается")),
    };
    Ok((v, if ty == "raw" { "tcp".into() } else if ty == "websocket" { "ws".into() } else if ty == "h2" { "http".into() } else { ty }))
}

fn vless(p: Parts) -> Result<Proxy, String> {
    let q = Q { q: &p.query, used: Default::default() };
    if uuid_ok(&p.user).is_err() {
        return Err("UUID в ссылке VLESS неверный".into());
    }
    let (tls, security) = tls(&q, &p.host, false, None)?;
    let (tr, transport) = transport(&q)?;
    let mut o = json!({ "type": "vless", "server": p.host, "server_port": p.port, "uuid": p.user, "packet_encoding": "xudp" });
    if let Some(flow) = q.get("flow") {
        if flow != "xtls-rprx-vision" {
            return Err(format!("flow «{flow}» не поддерживается (только xtls-rprx-vision)"));
        }
        o["flow"] = json!(flow);
    }
    if let Some(t) = tls {
        o["tls"] = t;
    }
    if let Some(t) = tr {
        o["transport"] = t;
    }
    finish(ProfileKind::Vless, p.host, p.port, security, transport, p.name, o, &q)
}

fn trojan(p: Parts) -> Result<Proxy, String> {
    let q = Q { q: &p.query, used: Default::default() };
    let password = clean(&p.user, "пароль Trojan")?;
    let (tls, security) = tls(&q, &p.host, true, None)?;
    let (tr, transport) = transport(&q)?;
    let mut o = json!({ "type": "trojan", "server": p.host, "server_port": p.port, "password": password });
    if let Some(t) = tls {
        o["tls"] = t;
    }
    if let Some(t) = tr {
        o["transport"] = t;
    }
    finish(ProfileKind::Trojan, p.host, p.port, security, transport, p.name, o, &q)
}

fn hysteria2(p: Parts) -> Result<Proxy, String> {
    let q = Q { q: &p.query, used: Default::default() };
    let password = clean(&p.user, "пароль Hysteria2")?;
    let (tls, _) = tls(&q, &p.host, true, Some(&["h3"]))?;
    let mut o = json!({ "type": "hysteria2", "server": p.host, "server_port": p.port, "password": password });
    if let Some(obfs) = q.get("obfs") {
        if obfs != "salamander" {
            return Err(format!("обфускация «{obfs}» не поддерживается (только salamander)"));
        }
        o["obfs"] = json!({ "type": "salamander", "password": clean(q.get("obfs-password").unwrap_or(""), "пароль обфускации")? });
    }
    o["tls"] = tls.unwrap_or_else(|| json!({ "enabled": true, "alpn": ["h3"] }));
    finish(ProfileKind::Hysteria2, p.host, p.port, "tls".into(), "quic".into(), p.name, o, &q)
}

fn shadowsocks(rest: &str) -> Result<Proxy, String> {
    const METHODS: &[&str] = &[
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    ];
    let (main, frag) = rest.split_once('#').map_or((rest, None), |(a, b)| (a, Some(b)));
    let (main, q) = main.split_once('?').map_or((main, ""), |(a, b)| (a, b));
    let main = main.trim_end_matches('/');
    // SIP002: userinfo@host:port (userinfo — base64url или method:password в %-кодировке); старый вид: base64(всего)
    let (userinfo, hp) = match main.rsplit_once('@') {
        Some((u, hp)) => {
            let u = pct_decode(u)?;
            let u = if u.contains(':') { u } else { String::from_utf8(b64(&u).ok_or("ссылка ss:// не разобрана")?).map_err(|_| "ссылка ss:// не разобрана")? };
            (u, hp.to_string())
        }
        None => {
            let all = String::from_utf8(b64(main).ok_or("ссылка ss:// не разобрана")?).map_err(|_| "ссылка ss:// не разобрана")?;
            let (u, hp) = all.rsplit_once('@').ok_or("ссылка ss:// не разобрана")?;
            (u.to_string(), hp.to_string())
        }
    };
    let (method, password) = userinfo.split_once(':').ok_or("в ссылке ss:// нет метода и пароля")?;
    let method = method.to_ascii_lowercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(format!("шифр Shadowsocks «{method}» не поддерживается"));
    }
    let (host, port) = host_port(&hp)?;
    let mut warnings = Vec::new();
    if q.split('&').any(|kv| kv.starts_with("plugin=")) {
        return Err("плагины Shadowsocks (obfs, v2ray-plugin) не поддерживаются".into());
    }
    if !q.is_empty() {
        warnings.push(format!("параметры ss:// пропущены: {q}"));
    }
    let name = frag.map(pct_decode).transpose()?.map(|n| n.chars().filter(|c| !c.is_control()).take(64).collect::<String>()).filter(|n| !n.trim().is_empty());
    let o = json!({ "type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": clean(password, "пароль Shadowsocks")? });
    Ok(Proxy { kind: ProfileKind::Shadowsocks, info: ProxyInfo { server: host, port, security: None, transport: None }, name, outbound: o, warnings })
}

#[allow(clippy::too_many_arguments)]
fn finish(kind: ProfileKind, server: String, port: u16, security: String, transport: String, name: Option<String>, outbound: Value, q: &Q) -> Result<Proxy, String> {
    let unused = q.unused();
    let warnings = if unused.is_empty() { Vec::new() } else { vec![format!("параметры ссылки пропущены: {}", unused.join(", "))] };
    Ok(Proxy { kind, info: ProxyInfo { server, port, security: Some(security), transport: Some(transport) }, name, outbound, warnings })
}

fn uuid_ok(u: &str) -> Result<(), ()> {
    let parts: Vec<&str> = u.split('-').collect();
    let lens = [8, 4, 4, 4, 12];
    (parts.len() == 5 && parts.iter().zip(lens).all(|(p, l)| p.len() == l && p.bytes().all(|c| c.is_ascii_hexdigit()))).then_some(()).ok_or(())
}

/// Ссылка сервера модуля sing-box.
pub fn parse_link(link: &str) -> Result<Proxy, String> {
    let link = link.trim();
    if link.len() > MAX_LINK || link.chars().any(|c| c.is_control() || c == ' ') {
        return Err("ссылка слишком длинная или содержит пробелы и управляющие символы".into());
    }
    let (scheme, rest) = link.split_once("://").ok_or("это не ссылка на сервер (нет схемы://)")?;
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => vless(split(rest)?),
        "trojan" => trojan(split(rest)?),
        "hysteria2" | "hy2" => hysteria2(split(rest)?),
        "ss" => shadowsocks(rest),
        "vmess" => Err("VMess не поддерживается: используйте VLESS".into()),
        other => Err(format!("ссылки «{other}://» не поддерживаются")),
    }
}

/// Вид профиля для схемы ссылки (без разбора всего остального).
pub fn kind_of_link(link: &str) -> Option<ProfileKind> {
    match link.trim().split_once("://")?.0.to_ascii_lowercase().as_str() {
        "vless" => Some(ProfileKind::Vless),
        "trojan" => Some(ProfileKind::Trojan),
        "hysteria2" | "hy2" => Some(ProfileKind::Hysteria2),
        "ss" => Some(ProfileKind::Shadowsocks),
        _ => None,
    }
}

/// `sing-box.json` туннеля n: TUN `dev` без своей маршрутизации, один выход `proxy`.
pub fn singbox_config(p: &Proxy, dev: &str, n: u8, ipv6: bool) -> String {
    let mut address = vec![format!("172.19.{n}.1/30")];
    if ipv6 {
        address.push(format!("fdfe:dcba:9876:{n:x}::1/126"));
    }
    let mut out = p.outbound.clone();
    out["tag"] = json!("proxy");
    out["domain_resolver"] = json!("local");
    let v = json!({
        "log": { "level": "warn", "timestamp": true },
        "dns": { "servers": [{ "type": "local", "tag": "local" }] },
        "inbounds": [{ "type": "tun", "tag": "tun", "interface_name": dev, "address": address, "mtu": 1400, "auto_route": false, "stack": "system" }],
        "outbounds": [out],
        "route": { "final": "proxy", "default_domain_resolver": "local" },
    });
    serde_json::to_string_pretty(&v).unwrap_or_default() + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";

    #[test]
    fn vless_reality_vision() {
        let l = format!("vless://{UUID}@203.0.113.5:443?type=tcp&security=reality&sni=www.example.com&fp=chrome&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=0123abcd&flow=xtls-rprx-vision&encryption=none#%D0%94%D0%BE%D0%BC");
        let p = parse_link(&l).unwrap();
        assert_eq!(p.kind, ProfileKind::Vless);
        assert_eq!(p.name.as_deref(), Some("Дом"));
        assert_eq!(p.info, ProxyInfo { server: "203.0.113.5".into(), port: 443, security: Some("reality".into()), transport: Some("tcp".into()) });
        assert_eq!(p.outbound["flow"], "xtls-rprx-vision");
        assert_eq!(p.outbound["tls"]["reality"]["short_id"], "0123abcd");
        assert_eq!(p.outbound["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(p.outbound["tls"]["server_name"], "www.example.com");
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
    }

    #[test]
    fn vless_ws_tls_and_grpc_ipv6() {
        let p = parse_link(&format!("vless://{UUID}@[2001:db8::7]:8443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com")).unwrap();
        assert_eq!(p.info.server, "2001:db8::7");
        assert_eq!(p.outbound["transport"], json!({ "type": "ws", "path": "/ws?ed=2048", "headers": { "Host": "cdn.example.com" } }));
        let g = parse_link(&format!("vless://{UUID}@a.example.com:443?type=grpc&serviceName=svc&security=tls")).unwrap();
        assert_eq!(g.outbound["transport"], json!({ "type": "grpc", "service_name": "svc" }));
        assert_eq!(g.outbound["tls"]["server_name"], "a.example.com");
    }

    #[test]
    fn hysteria2_and_hy2() {
        let p = parse_link("hysteria2://p%40ss@hy.example.com:8443/?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=ob#HY").unwrap();
        assert_eq!(p.kind, ProfileKind::Hysteria2);
        assert_eq!(p.outbound["password"], "p@ss");
        assert_eq!(p.outbound["obfs"], json!({ "type": "salamander", "password": "ob" }));
        assert_eq!(p.outbound["tls"], json!({ "enabled": true, "server_name": "hy.example.com", "insecure": true, "alpn": ["h3"] }));
        assert_eq!(parse_link("hy2://pw@203.0.113.9:443").unwrap().outbound["tls"], json!({ "enabled": true, "alpn": ["h3"] }));
    }

    #[test]
    fn trojan_defaults_to_tls() {
        let p = parse_link("trojan://secret@t.example.com:443?type=ws&path=/t&host=t.example.com#T").unwrap();
        assert_eq!(p.outbound["tls"]["server_name"], "t.example.com");
        assert_eq!(p.outbound["transport"]["path"], "/t");
        assert_eq!(p.info.security.as_deref(), Some("tls"));
    }

    #[test]
    fn shadowsocks_forms() {
        // SIP002 base64url userinfo
        let ui = data_encoding::BASE64URL_NOPAD.encode(b"aes-256-gcm:pw1");
        let p = parse_link(&format!("ss://{ui}@203.0.113.1:8388#S")).unwrap();
        assert_eq!((p.outbound["method"].as_str(), p.outbound["password"].as_str()), (Some("aes-256-gcm"), Some("pw1")));
        // 2022: method:password в %-кодировке
        let p = parse_link("ss://2022-blake3-aes-128-gcm:8JCsPssfgS8tiRwiMlhARg%3D%3D@ss.example.com:443").unwrap();
        assert_eq!(p.outbound["password"], "8JCsPssfgS8tiRwiMlhARg==");
        // старый вид: base64 всей части
        let all = data_encoding::BASE64.encode(b"chacha20-ietf-poly1305:pw2@203.0.113.2:443");
        assert_eq!(parse_link(&format!("ss://{all}#old")).unwrap().info.port, 443);
        assert!(parse_link(&format!("ss://{ui}@h.example.com:1?plugin=obfs-local")).is_err());
        assert!(parse_link("ss://rc4-md5:x@h.example.com:1").is_err());
    }

    #[test]
    fn errors_and_warnings() {
        for bad in ["http://x", "vmess://abc", "vless://nouuid@h.example.com:443", "vless://bf000d23-0752-40b4-affe-68f7707a9661@h.example.com",
            "vless://bf000d23-0752-40b4-affe-68f7707a9661@bad host:443", "trojan://@h.example.com:443",
            "vless://bf000d23-0752-40b4-affe-68f7707a9661@h.example.com:443?security=reality", "vless://bf000d23-0752-40b4-affe-68f7707a9661@h.example.com:443?type=kcp"] {
            assert!(parse_link(bad).is_err(), "{bad}");
        }
        let p = parse_link(&format!("vless://{UUID}@h.example.com:443?security=tls&xyz=1")).unwrap();
        assert_eq!(p.warnings, ["параметры ссылки пропущены: xyz"]);
        assert_eq!(kind_of_link("HY2://x"), Some(ProfileKind::Hysteria2));
    }

    #[test]
    fn config_shape() {
        let p = parse_link(&format!("vless://{UUID}@203.0.113.5:443?security=tls&sni=a.example.com")).unwrap();
        let c: Value = serde_json::from_str(&singbox_config(&p, "mitt3", 3, true)).unwrap();
        assert_eq!(c["inbounds"][0]["interface_name"], "mitt3");
        assert_eq!(c["inbounds"][0]["address"], json!(["172.19.3.1/30", "fdfe:dcba:9876:3::1/126"]));
        assert_eq!(c["inbounds"][0]["auto_route"], false);
        assert_eq!(c["outbounds"][0]["tag"], "proxy");
        assert_eq!(c["route"]["final"], "proxy");
    }
}
