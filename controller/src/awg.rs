//! Серверы AmneziaWG (модуль amneziawg): конфигурация клиента в формате wg-quick (`[Interface]`, `[Peer]`) с
//! параметрами обфускации AmneziaWG (Jc, Jmin, Jmax, S1–S4, H1–H4, I1–I5). Конфигурация целиком — секрет профиля
//! (`secrets.json`, поле `link`: в ней закрытый ключ); в настройках — сводка.
//!
//! Программа модуля — userspace `amneziawg-go -f mitt<n>`: создаёт TUN и сокет UAPI
//! (`/var/run/amneziawg/mitt<n>.sock`). Рендер пишет `awg.uapi` (команды UAPI, endpoint ещё с именем) и `awg.addr`
//! (адреса и MTU); служба передаёт команды `mi-tt-ctl awg-set` (имя сервера разрешается здесь — UAPI принимает только
//! IP) и назначает адреса. AllowedIPs из конфигурации не используются: что идёт в туннель, решают правила пакета
//! (в UAPI — 0.0.0.0/0 и ::/0).

use crate::proxy::ProxyInfo;

#[derive(Debug, Clone, PartialEq)]
pub struct AwgConf {
    pub private_key: [u8; 32],
    pub addresses: Vec<String>,
    pub mtu: Option<u16>,
    /// Параметры обфускации AmneziaWG в порядке конфигурации: (ключ UAPI, значение).
    pub obf: Vec<(String, String)>,
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub keepalive: Option<u16>,
}

const MAX_CONF: usize = 16 * 1024;

fn key(v: &str, what: &str) -> Result<[u8; 32], String> {
    let b = data_encoding::BASE64.decode(v.trim().as_bytes()).map_err(|_| format!("{what}: нужен ключ base64"))?;
    b.try_into().map_err(|_| format!("{what}: ключ должен быть 32 байта"))
}

fn hex(k: &[u8; 32]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

/// Это похоже на конфигурацию WireGuard/AmneziaWG (а не на ссылку).
pub fn looks_like_conf(text: &str) -> bool {
    text.contains("[Interface]") && text.contains("[Peer]")
}

pub fn parse(text: &str) -> Result<AwgConf, String> {
    if text.len() > MAX_CONF {
        return Err("конфигурация больше 16 КиБ".into());
    }
    let mut sec = "";
    let mut peers = 0;
    let (mut pk, mut pubk, mut psk, mut ep, mut ka, mut mtu) = (None, None, None, None, None, None);
    let mut addresses = Vec::new();
    let mut obf = Vec::new();
    for raw in text.lines() {
        let l = raw.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        if l.starts_with('[') {
            sec = match l.to_ascii_lowercase().as_str() {
                "[interface]" => "i",
                "[peer]" => {
                    peers += 1;
                    "p"
                }
                _ => return Err(format!("неизвестный раздел {l}")),
            };
            continue;
        }
        let (k, v) = l.split_once('=').ok_or_else(|| format!("строка без «=»: {l}"))?;
        let (k, v) = (k.trim(), v.trim());
        if v.chars().any(char::is_control) {
            return Err(format!("{k}: управляющие символы"));
        }
        match (sec, k.to_ascii_lowercase().as_str()) {
            ("i", "privatekey") => pk = Some(key(v, "PrivateKey")?),
            ("i", "address") => {
                for a in v.split(',').map(str::trim).filter(|a| !a.is_empty()) {
                    let c = crate::validate::parse_cidr(a).map_err(|_| format!("Address: «{a}» — нужен адрес с маской, например 10.8.0.2/32"))?;
                    addresses.push(c.to_string());
                }
            }
            ("i", "mtu") => mtu = Some(v.parse::<u16>().ok().filter(|m| (576..=9000).contains(m)).ok_or("MTU — число от 576 до 9000")?),
            ("i", "dns" | "listenport" | "table" | "preup" | "postup" | "predown" | "postdown" | "saveconfig" | "fwmark") => {}
            ("i", k2 @ ("jc" | "jmin" | "jmax" | "s1" | "s2" | "s3" | "s4")) => {
                v.parse::<u32>().map_err(|_| format!("{k}: нужно число"))?;
                obf.push((k2.to_string(), v.to_string()));
            }
            ("i", k2 @ ("h1" | "h2" | "h3" | "h4")) => {
                let ok = v.split_once('-').map_or(v.parse::<u32>().is_ok(), |(a, b)| a.trim().parse::<u32>().is_ok() && b.trim().parse::<u32>().is_ok());
                if !ok {
                    return Err(format!("{k}: число или диапазон «a-b»"));
                }
                obf.push((k2.to_string(), v.replace(' ', "")));
            }
            ("i", k2 @ ("i1" | "i2" | "i3" | "i4" | "i5")) => obf.push((k2.to_string(), v.to_string())),
            ("p", "publickey") => pubk = Some(key(v, "PublicKey")?),
            ("p", "presharedkey") => psk = Some(key(v, "PresharedKey")?),
            ("p", "endpoint") => ep = Some(v.to_string()),
            ("p", "persistentkeepalive") => ka = Some(v.parse::<u16>().map_err(|_| "PersistentKeepalive — число секунд")?),
            ("p", "allowedips") => {}
            (_, other) => return Err(format!("параметр «{other}» не поддерживается")),
        }
    }
    if peers != 1 {
        return Err("нужен ровно один раздел [Peer]".into());
    }
    let ep = ep.ok_or("в [Peer] нет Endpoint")?;
    let (host, port) = if let Some(r) = ep.strip_prefix('[') {
        let (h, p) = r.split_once("]:").ok_or("Endpoint: неверный адрес IPv6")?;
        (h.to_string(), p)
    } else {
        let (h, p) = ep.rsplit_once(':').ok_or("Endpoint: нужен адрес:порт")?;
        (h.to_string(), p)
    };
    let port = port.parse::<u16>().ok().filter(|p| *p > 0).ok_or("Endpoint: порт от 1 до 65535")?;
    if host.parse::<std::net::IpAddr>().is_err() && crate::validate::normalize_domain(&host, 1).is_err() {
        return Err("Endpoint: адрес сервера — IP или доменное имя".into());
    }
    if addresses.is_empty() {
        return Err("в [Interface] нет Address".into());
    }
    Ok(AwgConf {
        private_key: pk.ok_or("в [Interface] нет PrivateKey")?,
        addresses,
        mtu,
        obf,
        public_key: pubk.ok_or("в [Peer] нет PublicKey")?,
        preshared_key: psk,
        endpoint_host: host,
        endpoint_port: port,
        keepalive: ka,
    })
}

impl AwgConf {
    pub fn info(&self) -> ProxyInfo {
        ProxyInfo { server: self.endpoint_host.clone(), port: self.endpoint_port, security: Some("awg".into()), transport: Some("udp".into()) }
    }
    /// Команды UAPI (без `set=1` и пустой строки в конце); endpoint — с именем сервера, его разрешает `awg-set`.
    pub fn uapi(&self, ipv6: bool) -> String {
        let mut s = format!("private_key={}\nreplace_peers=true\n", hex(&self.private_key));
        for (k, v) in &self.obf {
            s.push_str(&format!("{k}={v}\n"));
        }
        s.push_str(&format!("public_key={}\n", hex(&self.public_key)));
        if let Some(p) = &self.preshared_key {
            s.push_str(&format!("preshared_key={}\n", hex(p)));
        }
        let host = if self.endpoint_host.contains(':') { format!("[{}]", self.endpoint_host) } else { self.endpoint_host.clone() };
        s.push_str(&format!("endpoint={host}:{}\n", self.endpoint_port));
        if let Some(k) = self.keepalive {
            s.push_str(&format!("persistent_keepalive_interval={k}\n"));
        }
        s.push_str("replace_allowed_ips=true\nallowed_ip=0.0.0.0/0\n");
        if ipv6 {
            s.push_str("allowed_ip=::/0\n");
        }
        s
    }
    /// Адреса интерфейса (по строке) и `mtu N` — для службы. IPv6-адреса — только при IPv6 через VPN.
    pub fn addr_file(&self, ipv6: bool) -> String {
        let mut s: String = self.addresses.iter().filter(|a| ipv6 || !a.contains(':')).map(|a| format!("{a}\n")).collect();
        s.push_str(&format!("mtu {}\n", self.mtu.unwrap_or(1280)));
        s
    }
}

/// `mi-tt-ctl awg-set <dev> <файл UAPI>`: имя в endpoint → IP (системный DNS роутера), команды — в сокет UAPI
/// `$MI_TT_AWG_SOCKDIR/<dev>.sock` (по умолчанию /var/run/amneziawg).
#[cfg(unix)]
pub fn set_cmd(dev: &str, file: &str) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::ToSocketAddrs;
    if !dev.bytes().all(|c| c.is_ascii_alphanumeric()) || dev.is_empty() {
        return Err("неверное имя интерфейса".into());
    }
    let text = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let mut out = String::from("set=1\n");
    for l in text.lines() {
        if let Some(ep) = l.strip_prefix("endpoint=") {
            let addr = ep.to_socket_addrs().map_err(|e| format!("сервер {ep} не разрешился: {e}"))?;
            let v: Vec<std::net::SocketAddr> = addr.collect();
            let a = v.iter().find(|a| a.is_ipv4()).or(v.first()).ok_or(format!("сервер {ep} не разрешился"))?;
            out.push_str(&format!("endpoint={a}\n"));
        } else {
            out.push_str(l);
            out.push('\n');
        }
    }
    out.push('\n');
    let dir = std::env::var("MI_TT_AWG_SOCKDIR").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/var/run/amneziawg".into());
    let sock = format!("{dir}/{dev}.sock");
    let mut s = std::os::unix::net::UnixStream::connect(&sock).map_err(|e| format!("{sock}: {e}"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
    s.write_all(out.as_bytes()).map_err(|e| format!("{sock}: {e}"))?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    loop {
        line.clear();
        if r.read_line(&mut line).map_err(|e| format!("{sock}: {e}"))? == 0 {
            return Err("UAPI: нет ответа".into());
        }
        if let Some(e) = line.trim().strip_prefix("errno=") {
            return if e == "0" { Ok(()) } else { Err(format!("UAPI отклонил настройки (errno={e})")) };
        }
    }
}

#[cfg(not(unix))]
pub fn set_cmd(_dev: &str, _file: &str) -> Result<(), String> {
    Err("awg-set работает только на Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="; // secret-scan: allow тестовый ключ
    const PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="; // secret-scan: allow тестовый ключ

    fn conf() -> String {
        format!(
            "[Interface]\nPrivateKey = {PK}\nAddress = 10.8.0.2/32, fd00::2/128\nDNS = 1.1.1.1\nMTU = 1360\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 23\nH1 = 1356111720\nH2 = 100-200\nH3 = 3\nH4 = 4\nI1 = <b 0xf6ab3267fa><c><t>\n\n[Peer]\nPublicKey = {PUB}\nPresharedKey = {PK}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = awg.example.com:51820\nPersistentKeepalive = 25\n"
        )
    }

    #[test]
    fn parse_and_uapi() {
        let c = parse(&conf()).unwrap();
        assert_eq!(c.info(), ProxyInfo { server: "awg.example.com".into(), port: 51820, security: Some("awg".into()), transport: Some("udp".into()) });
        let u = c.uapi(false);
        assert!(u.starts_with("private_key=c809f3e5317e95"), "{u}");
        for want in ["jc=4\n", "jmin=40\n", "h2=100-200\n", "i1=<b 0xf6ab3267fa><c><t>\n", "endpoint=awg.example.com:51820\n", "persistent_keepalive_interval=25\n", "allowed_ip=0.0.0.0/0\n"] {
            assert!(u.contains(want), "нет {want}: {u}");
        }
        assert!(!u.contains("::/0"));
        assert_eq!(c.addr_file(false), "10.8.0.2/32\nmtu 1360\n");
        assert_eq!(c.addr_file(true), "10.8.0.2/32\nfd00::2/128\nmtu 1360\n");
        assert!(looks_like_conf(&conf()));
    }

    #[test]
    fn errors() {
        let base = conf();
        for (from, to) in [("PrivateKey = ", "PrivateKey = x"), ("Endpoint = awg.example.com:51820", "Endpoint = awg.example.com"), ("Jc = 4", "Jc = four"),
            ("H2 = 100-200", "H2 = a-b"), ("Address = 10.8.0.2/32, fd00::2/128", "Address = nope"), ("PersistentKeepalive = 25", "Foo = 1")] {
            assert!(parse(&base.replacen(from, to, 1)).is_err(), "{to}");
        }
        assert!(parse(&format!("{base}\n[Peer]\nPublicKey = {PUB}\nEndpoint = b.example.com:1\n")).is_err(), "два peer");
    }
}
