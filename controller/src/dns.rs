//! Шифрованный DNS роутера (этап 10).
//!
//! Цепочка: клиент → dnsmasq роутера (DHCP, локальные имена, фильтр рекламы) → DNS-слушатель Mihomo 127.0.0.1:1053 →
//! DoH/DoT/DoQ/DoH3 к серверам по заданным IP (имя сервера — только для SNI и проверки TLS) или, для ODoH,
//! dnscrypt-proxy 127.0.0.1:5300 → relay → target. Открытого DNS наружу нет ни в штатной работе, ни при сбое:
//! dnsmasq не читает resolv-файл провайдера; bootstrap Mihomo — закрытый локальный порт, bootstrap dnscrypt-proxy — Mihomo
//! с адресами target и relay из настроек.

use std::collections::BTreeSet;

use data_encoding::BASE64URL_NOPAD;
use serde_json::{Value, json};

use crate::model::{AdblockConfig, DnsConfig, DnsTransport, OdohEndpoint};
use crate::validate::{Issue, normalize_domain};

pub const MIHOMO_DNS: &str = "127.0.0.1:1053";
pub const DNSCRYPT_LISTEN: &str = "127.0.0.1:5300";
/// Закрытый локальный порт вместо bootstrap-резолвера: попытка разрешить имя мимо политики завершается ошибкой.
pub const BLACKHOLE_DNS: &str = "127.0.0.1:9";
pub const ADBLOCK_MAX_ENTRIES: usize = 200_000;
pub const ADBLOCK_MAX_BYTES: usize = 8 * 1024 * 1024;

fn hostport(host: &str, port: Option<u16>, default: u16) -> String {
    if port.unwrap_or(default) == default { host.to_string() } else { format!("{host}:{}", port.unwrap_or(default)) }
}

fn ip_host(ip: &str) -> String {
    if ip.contains(':') { format!("[{ip}]") } else { ip.to_string() }
}

/// Раздел `dns` для Mihomo. Серверы — по IP из настроек; сертификат проверяется по имени (`name-cert-verify`),
/// поэтому имя сервера ни через какой DNS не разрешается. Для ODoH — адреса target и relay в hosts Mihomo:
/// по ним dnscrypt-proxy (bootstrap = Mihomo) находит серверы без открытого DNS.
pub fn mihomo_dns(d: &DnsConfig) -> Value {
    let mut hosts = serde_json::Map::new();
    let servers: Vec<String> = match d.transport {
        DnsTransport::Odoh => {
            if let Some(o) = &d.odoh {
                for e in std::iter::once(&o.target).chain(o.relays.iter()) {
                    hosts.insert(e.host.clone(), json!(e.ip));
                }
            }
            vec![DNSCRYPT_LISTEN.to_string()]
        }
        t => d
            .servers
            .iter()
            .map(|s| {
                let path = s.path.as_deref().unwrap_or("/dns-query");
                let ip = ip_host(&s.ip);
                let v = format!("name-cert-verify={}", s.host);
                match t {
                    DnsTransport::Doh => format!("https://{}{path}#{v}", hostport(&ip, s.port, 443)),
                    DnsTransport::Doh3 => format!("https://{}{path}#h3=true&{v}", hostport(&ip, s.port, 443)),
                    DnsTransport::Dot => format!("tls://{ip}:{}#{v}", s.port.unwrap_or(853)),
                    DnsTransport::Doq => format!("quic://{ip}:{}#{v}", s.port.unwrap_or(853)),
                    DnsTransport::Odoh => unreachable!(),
                }
            })
            .collect(),
    };
    json!({
        "enable": true,
        "listen": MIHOMO_DNS,
        // движок работает с ipv6: false (TUN без IPv6-правил вне нашей зоны), поэтому на AAAA он сам отвечает пустым
        // NOERROR, не спрашивая сервер: при шифрованном DNS имена разрешаются только в IPv4 (утечки IPv6 нет)
        "ipv6": false,
        "enhanced-mode": "redir-host",
        "use-hosts": true,
        "use-system-hosts": false,
        "respect-rules": false,
        "hosts": hosts,
        // имена серверов DoH/DoT берутся из hosts; всё прочее, что движок попытался бы разрешить мимо политики, — ошибка
        "default-nameserver": [BLACKHOLE_DNS],
        "nameserver": servers,
        // DNS самого движка (имена VPN-серверов) идёт тем же шифрованным путём
        "proxy-server-nameserver": servers,
    })
}

fn lp(out: &mut Vec<u8>, s: &[u8]) {
    out.push(s.len() as u8);
    out.extend_from_slice(s);
}

/// Штамп ODoH target: 0x05 || props || LP(hostname) || LP(path).
pub fn stamp_odoh_target(e: &OdohEndpoint) -> String {
    let mut b = vec![0x05];
    b.extend_from_slice(&0u64.to_le_bytes());
    lp(&mut b, hostport(&e.host, e.port, 443).as_bytes());
    lp(&mut b, e.path.as_bytes());
    format!("sdns://{}", BASE64URL_NOPAD.encode(&b))
}

/// Штамп ODoH relay: 0x85 || props || LP(addr) || VLP(hashes: пусто) || LP(hostname) || LP(path).
pub fn stamp_odoh_relay(e: &OdohEndpoint) -> String {
    let mut b = vec![0x85];
    b.extend_from_slice(&0u64.to_le_bytes());
    let addr = if e.port.unwrap_or(443) == 443 { e.ip.clone() } else { format!("{}:{}", e.ip, e.port.unwrap_or(443)) };
    lp(&mut b, addr.as_bytes());
    b.push(0); // без закрепления хэша сертификата: проверка по цепочке и имени
    lp(&mut b, hostport(&e.host, e.port, 443).as_bytes());
    lp(&mut b, e.path.as_bytes());
    format!("sdns://{}", BASE64URL_NOPAD.encode(&b))
}

/// Конфигурация dnscrypt-proxy для строгого ODoH: только target через relay; без открытого и прямого DoH.
pub fn dnscrypt_toml(d: &DnsConfig) -> Option<String> {
    let o = d.odoh.as_ref().filter(|_| d.transport == DnsTransport::Odoh)?;
    let relays: Vec<String> = o.relays.iter().map(|r| format!("'{}'", stamp_odoh_relay(r))).collect();
    Some(format!(
        "# mi-trusttunnel: строгий ODoH — вопросы только через relay, без DNSCrypt, DoH и открытого DNS\n\
listen_addresses = ['{DNSCRYPT_LISTEN}']\n\
server_names = ['mitt-odoh']\n\
odoh_servers = true\n\
dnscrypt_servers = false\n\
doh_servers = false\n\
ipv4_servers = true\n\
ipv6_servers = false\n\
require_dnssec = false\n\
require_nolog = false\n\
require_nofilter = false\n\
ignore_system_dns = true\n\
bootstrap_resolvers = ['{MIHOMO_DNS}']\n\
netprobe_timeout = 0\n\
cache = true\n\
log_level = 2\n\
\n\
[static]\n\
  [static.'mitt-odoh']\n\
  stamp = '{}'\n\
\n\
[anonymized_dns]\n\
routes = [{{ server_name = 'mitt-odoh', via = [{}] }}]\n\
skip_incompatible = false\n",
        stamp_odoh_target(&o.target),
        relays.join(", ")
    ))
}

/// Разбор списка блокировки: по домену в строке, `#` — комментарий, допускаются строки hosts (`0.0.0.0 домен`).
/// Ошибочная строка — отказ всего списка (действующий список остаётся прежним).
pub fn parse_adblock_list(text: &str) -> Result<Vec<String>, Vec<Issue>> {
    let mut issues = Vec::new();
    let mut out = BTreeSet::new();
    if text.len() > ADBLOCK_MAX_BYTES {
        return Err(vec![Issue::new("adblock", "too_large", format!("список больше {ADBLOCK_MAX_BYTES} байт"))]);
    }
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let mut f = line.split_whitespace();
        let first = f.next().unwrap_or_default();
        let dom = if matches!(first, "0.0.0.0" | "127.0.0.1" | "::" | "::1") { f.next().unwrap_or_default() } else { first };
        if f.next().is_some() {
            issues.push(Issue::new(format!("adblock[{}]", n + 1), "bad_line", "в строке больше одного домена"));
            continue;
        }
        match normalize_domain(dom, 2) {
            Ok(d) => {
                out.insert(d);
            }
            Err(m) => issues.push(Issue::new(format!("adblock[{}]", n + 1), "bad_domain", m)),
        }
        if issues.len() > 20 {
            break;
        }
    }
    if out.len() > ADBLOCK_MAX_ENTRIES {
        issues.push(Issue::new("adblock", "too_many", format!("больше {ADBLOCK_MAX_ENTRIES} доменов")));
    }
    if issues.is_empty() { Ok(out.into_iter().collect()) } else { Err(issues) }
}

/// Файл для каталога conf-dir dnsmasq: только шифрованный путь, блокировка рекламы и исключения.
pub fn dnsmasq_conf(d: &DnsConfig, blocked: &[String]) -> String {
    let up = MIHOMO_DNS.replace(':', "#");
    let mut s = format!(
        "# mi-trusttunnel: внешние вопросы — только через шифрованный DNS ({:?}); resolv-файл провайдера не читается\nno-resolv\nserver={up}\n",
        d.transport
    );
    if let Some(AdblockConfig { enabled: true, exceptions }) = &d.adblock {
        s.push_str(&format!("# блокировка рекламы: {} доменов (NXDOMAIN для A и AAAA, вопрос наружу не уходит)\n", blocked.len()));
        for b in blocked {
            s.push_str(&format!("address=/{b}/\n"));
        }
        for e in exceptions {
            s.push_str(&format!("server=/{e}/{up}\n"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DnsServer, OdohConfig};

    fn ep(h: &str, ip: &str) -> OdohEndpoint {
        OdohEndpoint { host: h.into(), ip: ip.into(), port: None, path: "/dns-query".into() }
    }

    #[test]
    fn stamps_roundtrip_layout() {
        let t = stamp_odoh_target(&ep("odoh.example", "1.2.3.4"));
        let b = BASE64URL_NOPAD.decode(t.trim_start_matches("sdns://").as_bytes()).unwrap();
        assert_eq!(b[0], 0x05);
        assert_eq!(&b[10..10 + b[9] as usize], b"odoh.example");
        let r = stamp_odoh_relay(&OdohEndpoint { port: Some(8443), path: "/proxy".into(), ..ep("relay.example", "5.6.7.8") });
        let b = BASE64URL_NOPAD.decode(r.trim_start_matches("sdns://").as_bytes()).unwrap();
        assert_eq!(b[0], 0x85);
        assert_eq!(&b[10..10 + b[9] as usize], b"5.6.7.8:8443");
    }

    #[test]
    fn mihomo_urls_per_transport_and_no_open_bootstrap() {
        let mk = |t| DnsConfig { transport: t, servers: vec![DnsServer { host: "dns.example".into(), ip: "9.9.9.9".into(), port: None, path: None }], odoh: None, adblock: None };
        assert_eq!(mihomo_dns(&mk(DnsTransport::Doh))["nameserver"], json!(["https://9.9.9.9/dns-query#name-cert-verify=dns.example"]));
        assert_eq!(mihomo_dns(&mk(DnsTransport::Doh3))["nameserver"], json!(["https://9.9.9.9/dns-query#h3=true&name-cert-verify=dns.example"]));
        assert_eq!(mihomo_dns(&mk(DnsTransport::Dot))["nameserver"], json!(["tls://9.9.9.9:853#name-cert-verify=dns.example"]));
        assert_eq!(mihomo_dns(&mk(DnsTransport::Doq))["nameserver"], json!(["quic://9.9.9.9:853#name-cert-verify=dns.example"]));
        let m = mihomo_dns(&mk(DnsTransport::Doh));
        assert_eq!(m["default-nameserver"], json!([BLACKHOLE_DNS]));
        let o = DnsConfig { transport: DnsTransport::Odoh, servers: vec![], odoh: Some(OdohConfig { target: ep("t.example", "1.1.1.2"), relays: vec![ep("r.example", "1.1.1.3")] }), adblock: None };
        assert_eq!(mihomo_dns(&o)["nameserver"], json!([DNSCRYPT_LISTEN]));
        assert_eq!(mihomo_dns(&o)["hosts"], json!({ "t.example": "1.1.1.2", "r.example": "1.1.1.3" }));
        let toml = dnscrypt_toml(&o).unwrap();
        assert!(toml.contains("odoh_servers = true") && toml.contains("doh_servers = false") && toml.contains("skip_incompatible = false"));
    }

    #[test]
    fn adblock_list_strict_and_conf() {
        assert_eq!(parse_adblock_list("# c\nads.example\n0.0.0.0 tracker.example # x\n\nADS.example\n").unwrap(), ["ads.example", "tracker.example"]);
        assert!(parse_adblock_list("ok.example\nbad domain here\n").is_err());
        assert!(parse_adblock_list("ok.example\n-bad-.example\n").is_err());
        let d = DnsConfig { transport: DnsTransport::Dot, servers: vec![], odoh: None, adblock: Some(AdblockConfig { enabled: true, exceptions: vec!["ok.ads.example".into()] }) };
        let c = dnsmasq_conf(&d, &["ads.example".into()]);
        assert!(c.contains("no-resolv\nserver=127.0.0.1#1053\n") && c.contains("address=/ads.example/\n") && c.contains("server=/ok.ads.example/127.0.0.1#1053\n"));
    }
}
