//! Подписка TrustTunnel 1.3 (раздел `[subscription]` сервера, тег 0x0E ссылки `tt://`): по ссылке
//! `https://user:pass@host/path` сервер отдаёт JSON с параметрами подключения и паролем пользователя. Служба роутера
//! скачивает его (mitt-sub.sh), а `mi-tt-ctl subscription-import` переносит в настройки профиля и secrets.json.
//! Неизвестные поля пропускаются: сервер новее роутера не ломает обновление.

use serde::Deserialize;

use crate::model::Endpoint;

#[derive(Debug, Deserialize)]
pub struct SubscriptionJson {
    #[serde(default)]
    pub version: u32,
    /// Имя сервера в сертификате (TLS).
    pub hostname: String,
    /// `host:port`, `ip:port` или `[ipv6]:port`.
    pub address: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub upstream_protocol: String,
    #[serde(default)]
    pub anti_dpi: bool,
    #[serde(default)]
    pub skip_verification: bool,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub custom_sni: Option<String>,
    #[serde(default)]
    pub client_random_prefix: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Итог переноса: новая точка подключения, пароль и предупреждения о том, чего роутер не поддерживает.
pub struct Imported {
    pub endpoint: Endpoint,
    pub password: String,
    pub name: Option<String>,
    pub warnings: Vec<String>,
}

fn split_address(a: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = a.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h.to_string(), p)
    } else {
        let (h, p) = a.rsplit_once(':')?;
        (h.to_string(), p)
    };
    let port: u16 = port.parse().ok().filter(|p| *p > 0)?;
    (!host.is_empty()).then_some((host, port))
}

/// Перенос подписки в точку подключения поверх прежней: профиль TLS и ключ client_random (их в подписке нет)
/// сохраняются; префикс client_random из подписки — только если ключа нет (задаётся что-то одно).
pub fn apply(j: &SubscriptionJson, old: Option<&Endpoint>) -> Result<Imported, String> {
    let (server, port) = split_address(j.address.trim()).ok_or_else(|| format!("адрес «{}» в подписке — host:port", j.address))?;
    if j.username.trim().is_empty() || j.password.is_empty() {
        return Err("в подписке нет логина или пароля".into());
    }
    let mut warnings = Vec::new();
    if j.skip_verification {
        warnings.push("сервер разрешает не проверять сертификат (skip_verification) — роутер всегда проверяет".into());
    }
    if let Some(s) = j.custom_sni.as_deref().filter(|s| !s.is_empty() && *s != j.hostname) {
        warnings.push(format!("сервер задаёт для TLS другое имя ({s}) — роутер подключается по имени {}", j.hostname));
    }
    let key = old.and_then(|e| e.client_random_auth_key.clone());
    let prefix = if key.is_some() { None } else { j.client_random_prefix.clone().filter(|p| !p.is_empty()) };
    let host = j.hostname.trim();
    let endpoint = Endpoint {
        server: server.clone(),
        port,
        sni: (!host.is_empty() && host != server).then(|| host.to_string()),
        username: j.username.trim().to_string(),
        quic: j.upstream_protocol.eq_ignore_ascii_case("http3"),
        anti_dpi: j.anti_dpi,
        certificate: j.certificate.as_deref().map(str::trim).filter(|c| !c.is_empty()).map(|c| format!("{c}\n")),
        tls_profile: old.and_then(|e| e.tls_profile),
        client_random: prefix,
        client_random_auth_key: key,
    };
    Ok(Imported { endpoint, password: j.password.clone(), name: j.name.clone().filter(|n| !n.trim().is_empty()), warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(extra: &str) -> SubscriptionJson {
        serde_json::from_str(&format!(r#"{{"version":1,"hostname":"vpn.example.com","address":"203.0.113.1:443","username":"alice","password":"pw","has_ipv6":false,"upstream_protocol":"http2","anti_dpi":false,"skip_verification":false{extra}}}"#)).unwrap()
    }

    #[test]
    fn subscription_to_endpoint() {
        let i = apply(&sub(r#","client_random_prefix":"a0b0/f0f0","name":"Acme VPN","dns_upstreams":["tls://1.1.1.1"],"future_field":1"#), None).unwrap();
        assert_eq!((i.endpoint.server.as_str(), i.endpoint.port, i.endpoint.sni.as_deref()), ("203.0.113.1", 443, Some("vpn.example.com")));
        assert_eq!((i.endpoint.username.as_str(), i.password.as_str(), i.endpoint.client_random.as_deref()), ("alice", "pw", Some("a0b0/f0f0")));
        assert_eq!(i.name.as_deref(), Some("Acme VPN"));
        assert!(i.warnings.is_empty());
        // http3, IPv6, неподдерживаемые параметры — предупреждения
        let j: SubscriptionJson = serde_json::from_str(r#"{"hostname":"vpn.example.com","address":"[2001:db8::1]:8443","username":"bob","password":"x",
            "upstream_protocol":"http3","skip_verification":true,"custom_sni":"cdn.example.net","certificate":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"}"#).unwrap();
        let i = apply(&j, None).unwrap();
        assert_eq!((i.endpoint.server.as_str(), i.endpoint.port, i.endpoint.quic), ("2001:db8::1", 8443, true));
        assert!(i.endpoint.certificate.as_deref().is_some_and(|c| c.ends_with("-----END CERTIFICATE-----\n")));
        assert_eq!(i.warnings.len(), 2);
    }

    #[test]
    fn subscription_keeps_tls_profile_and_auth_key() {
        let old = Endpoint {
            server: "198.51.100.1".into(), port: 443, sni: None, username: "old".into(), quic: false, anti_dpi: false, certificate: None,
            tls_profile: Some(crate::model::TlsProfile::Safari), client_random: None, client_random_auth_key: Some("00ff".into()),
        };
        let i = apply(&sub(r#","client_random_prefix":"a0b0""#), Some(&old)).unwrap();
        assert_eq!(i.endpoint.tls_profile, Some(crate::model::TlsProfile::Safari));
        assert_eq!((i.endpoint.client_random.as_deref(), i.endpoint.client_random_auth_key.as_deref()), (None, Some("00ff")));
    }

    #[test]
    fn bad_subscriptions() {
        let j: SubscriptionJson = serde_json::from_str(r#"{"hostname":"h","address":"203.0.113.1","username":"a","password":"p"}"#).unwrap();
        assert!(apply(&j, None).is_err());
        let j: SubscriptionJson = serde_json::from_str(r#"{"hostname":"h","address":"203.0.113.1:443","username":"","password":"p"}"#).unwrap();
        assert!(apply(&j, None).is_err());
        assert!(serde_json::from_str::<SubscriptionJson>(r#"{"hostname":"h"}"#).is_err());
        assert_eq!(split_address("[2001:db8::1]:8443"), Some(("2001:db8::1".into(), 8443)));
        assert_eq!(split_address("vpn.example.com:0"), None);
    }
}
