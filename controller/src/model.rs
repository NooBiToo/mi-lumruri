//! Версионированная модель настроек (схема v1): один VPN — TrustTunnel, прямой выход, Zapret и блокировка.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub networks: Vec<Network>,
    #[serde(default)]
    pub devices: Vec<Device>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<Category>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    pub default_action: Action,
    /// Настройка Zapret для действия «напрямую с Zapret» (nfqws2). Без неё — стратегия по умолчанию.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zapret: Option<ZapretConfig>,
    /// Резолвер туннельных доменов и блокировка рекламы. Без раздела — резолвер по умолчанию, без блокировки.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
    /// Как часто служба сама обновляет списки сайтов и перепроверяет способ Zapret. Без раздела — по умолчанию.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<ScheduleConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    #[serde(default)]
    pub lists: ListsUpdate,
    #[serde(default)]
    pub zapret_check: ZapretCheck,
}

/// Проверка обновлений готовых списков сайтов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListsUpdate {
    #[serde(rename = "6h")]
    Hours6,
    #[default]
    Daily,
    Weekly,
    /// Только по кнопке в панели.
    Manual,
}

/// Автоматическая перепроверка способа Zapret (тот же подбор, что по кнопке: новый способ — только если он лучше).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretCheck {
    #[default]
    Off,
    Daily,
    Weekly,
}

impl ScheduleConfig {
    /// Файл для службы: секунды между проверками, 0 — не проверять самой.
    pub fn file(&self) -> String {
        let lists = match self.lists { ListsUpdate::Hours6 => 6 * 3600, ListsUpdate::Daily => 86_400, ListsUpdate::Weekly => 7 * 86_400, ListsUpdate::Manual => 0 };
        let zapret = match self.zapret_check { ZapretCheck::Off => 0, ZapretCheck::Daily => 86_400, ZapretCheck::Weekly => 7 * 86_400 };
        format!("lists={lists}\nzapret_check={zapret}\n")
    }
}

/// DNS роутера: штатный dnsmasq сохраняет DHCP и локальные имена. Домены правил «через TrustTunnel» он
/// разрешает через `tunnel_resolver`, и сам вопрос уходит в туннель: провайдер не видит и не подменяет ответ.
/// Ответы dnsmasq заносит в ipset правил — по ним ядро выбирает маршрут.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// IPv4-адрес DNS-сервера для доменов, которые идут через туннель (по умолчанию 1.1.1.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_resolver: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adblock: Option<AdblockConfig>,
    /// Защищённый DNS (DoH/DoT) для доменов, которые не идут через туннель: их вопросы dnsmasq отдаёт mi-tt-dns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<SecureDns>,
    /// Свои записи: домен вместе с поддоменами отвечает заданным адресом (например, домашний сервер за Traefik).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecureDns {
    pub protocol: SecureProto,
    pub server: SecureServer,
    /// NextDNS: ID профиля (6 символов 0-9a-f) из личного кабинета.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nextdns_id: Option<String>,
    /// Свой сервер: ссылка DoH `https://имя/путь` или имя DoT `имя[:порт]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Свой сервер: его IP-адреса (подключение без DNS), 1–4.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureProto {
    Doh,
    Dot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureServer {
    Cloudflare,
    Quad9,
    Google,
    Adguard,
    Nextdns,
    Custom,
}

/// Порт, на котором mi-tt-dns ждёт вопросы dnsmasq (только 127.0.0.1).
pub const DNS_PROXY_PORT: u16 = 5453;

impl SecureDns {
    /// Параметры mi-tt-dns (по одному в строке): адрес приёма, сервер и его IP. Запасной путь и файл состояния
    /// добавляет служба. None — свой сервер или NextDNS заданы не полностью (это ловит проверка настроек).
    pub fn proxy_args(&self) -> Option<Vec<String>> {
        let (doh, dot, ips): (String, String, Vec<String>) = match self.server {
            SecureServer::Cloudflare => ("https://cloudflare-dns.com/dns-query".into(), "one.one.one.one".into(), vec!["1.1.1.1".into(), "1.0.0.1".into()]),
            SecureServer::Quad9 => ("https://dns.quad9.net/dns-query".into(), "dns.quad9.net".into(), vec!["9.9.9.9".into(), "149.112.112.112".into()]),
            SecureServer::Google => ("https://dns.google/dns-query".into(), "dns.google".into(), vec!["8.8.8.8".into(), "8.8.4.4".into()]),
            SecureServer::Adguard => ("https://dns.adguard-dns.com/dns-query".into(), "dns.adguard-dns.com".into(), vec!["94.140.14.14".into(), "94.140.15.15".into()]),
            SecureServer::Nextdns => {
                let id = self.nextdns_id.as_deref()?;
                (format!("https://dns.nextdns.io/{id}"), format!("{id}.dns.nextdns.io"), vec!["45.90.28.0".into(), "45.90.30.0".into()])
            }
            SecureServer::Custom => {
                let u = self.url.clone()?;
                if self.ips.is_empty() {
                    return None;
                }
                (u.clone(), u, self.ips.clone())
            }
        };
        let mut a = vec!["--listen".to_string(), format!("127.0.0.1:{DNS_PROXY_PORT}")];
        match self.protocol {
            SecureProto::Doh => a.extend(["--doh".to_string(), doh]),
            SecureProto::Dot => a.extend(["--dot".to_string(), dot]),
        }
        for ip in ips {
            a.extend(["--ip".to_string(), ip]);
        }
        Some(a)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostRecord {
    pub domain: String,
    /// IPv4 или IPv6.
    pub address: String,
}

pub const DEFAULT_TUNNEL_RESOLVER: &str = "1.1.1.1";

impl DnsConfig {
    pub fn resolver(&self) -> &str {
        self.tunnel_resolver.as_deref().unwrap_or(DEFAULT_TUNNEL_RESOLVER)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdblockConfig {
    pub enabled: bool,
    /// Домены-исключения: их вопросы не блокируются, даже если домен или родитель есть в списке.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exceptions: Vec<String>,
    /// Откуда служба скачивает список: HaGeZi Light (по умолчанию), HaGeZi Normal или своя ссылка `url`.
    #[serde(default, skip_serializing_if = "AdblockSource::is_default")]
    pub source: AdblockSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdblockSource {
    #[default]
    Light,
    Normal,
    Url,
}

impl AdblockSource {
    fn is_default(&self) -> bool {
        *self == AdblockSource::Light
    }
}

/// Списки HaGeZi (GPL-3.0) в виде «домен вместе с поддоменами» — как `address=/домен/` у dnsmasq.
pub const HAGEZI_LIGHT: &str = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt";
pub const HAGEZI_NORMAL: &str = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt";

impl AdblockConfig {
    /// Ссылка, по которой служба скачивает список; None — своя ссылка не задана.
    pub fn list_url(&self) -> Option<&str> {
        match self.source {
            AdblockSource::Light => Some(HAGEZI_LIGHT),
            AdblockSource::Normal => Some(HAGEZI_NORMAL),
            AdblockSource::Url => self.url.as_deref(),
        }
    }
}

/// Выбор стратегий Zapret из встроенного каталога (`zapret::catalog`): произвольные аргументы nfqws2 не принимаются.
/// Раздел версии 0.2.0 (`strategy`: `multisplit`|`multidisorder`, `pos`, `tcp_ports`) читается как `auto`/`auto`:
/// иначе после обновления настройки не разобрать и панель не может их исправить.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "RawZapret")]
pub struct ZapretConfig {
    /// Стратегия для всех сайтов: `auto` (круговой режим) или id стратегии каталога.
    pub strategy: String,
    /// Стратегия для YouTube: `auto` или id YouTube-стратегии каталога.
    pub youtube: String,
}

/// Раздел `zapret` как он записан: новый вид или вид 0.2.0.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawZapret {
    strategy: Option<String>,
    youtube: Option<String>,
    pos: Option<serde_json::Value>,
    tcp_ports: Option<serde_json::Value>,
}

impl TryFrom<RawZapret> for ZapretConfig {
    type Error = String;
    fn try_from(r: RawZapret) -> Result<Self, String> {
        let legacy = matches!(r.strategy.as_deref(), Some("multisplit" | "multidisorder")) && r.youtube.is_none();
        if legacy {
            return Ok(ZapretConfig::default());
        }
        if let Some(f) = [("pos", &r.pos), ("tcp_ports", &r.tcp_ports)].iter().find_map(|(n, v)| v.as_ref().map(|_| *n)) {
            return Err(format!("unknown field `{f}`, expected `strategy` or `youtube`"));
        }
        Ok(ZapretConfig { strategy: r.strategy.unwrap_or_else(auto), youtube: r.youtube.unwrap_or_else(auto) })
    }
}

fn auto() -> String {
    "auto".into()
}

impl Default for ZapretConfig {
    fn default() -> Self {
        ZapretConfig { strategy: auto(), youtube: auto() }
    }
}

/// Профиль TrustTunnel: сервер, к которому подключается официальный клиент `trusttunnel_client`.
/// Поддерживается один профиль: у стока свободен один бит метки для выбора маршрута.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub kind: ProfileKind,
    #[serde(default)]
    pub on_failure: FailurePolicy,
    /// Точка подключения. Пароль хранится отдельно (secrets.json) и в API не попадает.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// IP-адрес сервера (клиент подключается по адресу; имя для TLS — в `sni`).
    pub server: String,
    pub port: u16,
    /// Имя сервера в сертификате (hostname клиента TrustTunnel). Без него — адрес сервера.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Имя пользователя TrustTunnel; пароль — в secrets.json.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// HTTP/3 (QUIC) вместо HTTP/2.
    #[serde(default)]
    pub quic: bool,
    /// Защита от DPI на стороне клиента (anti_dpi).
    #[serde(default)]
    pub anti_dpi: bool,
    /// Сертификат сервера (PEM) для самоподписанного сервера. Без него — проверка цепочки до корневых сертификатов.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Trusttunnel,
}

impl ProfileKind {
    pub fn label(self) -> &'static str {
        match self {
            ProfileKind::Trusttunnel => "TrustTunnel",
        }
    }
}

/// Что делать с трафиком правила, если туннель недоступен. По умолчанию — блокировать (без выхода в обход).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    #[default]
    Block,
    Direct,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub ssid: String,
    /// Дополнительный идентификатор сегмента для одинаковых SSID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment: Option<String>,
    /// Подсеть клиентов этой сети; нужна, чтобы применить правила сети и не захватывать трафик внутри LAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,
    /// Мост, на котором клиенты этой сети попадают в маршрутизацию (например, br-lan).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,
    /// Порты моста этой сети (интерфейсы SSID): по ним определяется источник для политики сети.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub mac: String,
    pub network: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub destinations: Vec<Destination>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Destination {
    Domain { value: String },
    DomainSuffix { value: String },
    Cidr { value: String },
    Group { id: String },
    /// Категория (геокатегория доменов или IP-префиксов): записи — в локальном списке categories/<id>.list.
    Category { id: String },
}

/// Категория назначений: список доменов (суффиксы) или IP-префиксов, хранится отдельно от настроек
/// (`categories/<id>.list` рядом с config.json) и обновляется атомарно с проверкой.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    pub id: String,
    pub name: String,
    pub kind: CategoryKind,
    /// Откуда взят список (для панели), например «geosite:youtube».
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryKind {
    Domain,
    Ip,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Device { id: String },
    Network { id: String },
    Lan,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Profile { id: String },
    Direct,
    DirectZapret,
    Block,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub source: Source,
    pub destination: Destination,
    pub action: Action,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

impl Source {
    /// Уровень приоритета: устройство, затем сеть, затем вся LAN.
    pub fn level(&self) -> u8 {
        match self {
            Source::Device { .. } => 1,
            Source::Network { .. } => 2,
            Source::Lan => 3,
        }
    }
}

#[cfg(test)]
mod schedule_tests {
    use super::*;

    #[test]
    fn schedule_file_for_service() {
        assert_eq!(ScheduleConfig::default().file(), "lists=86400\nzapret_check=0\n");
        let s: ScheduleConfig = serde_json::from_str(r#"{"lists":"6h","zapret_check":"weekly"}"#).unwrap();
        assert_eq!(s.file(), "lists=21600\nzapret_check=604800\n");
        assert_eq!(serde_json::from_str::<ScheduleConfig>(r#"{"lists":"manual"}"#).unwrap().file(), "lists=0\nzapret_check=0\n");
        assert!(serde_json::from_str::<ScheduleConfig>(r#"{"lists":"hourly"}"#).is_err());
        assert_eq!(serde_json::to_string(&s).unwrap(), r#"{"lists":"6h","zapret_check":"weekly"}"#);
    }
}

#[cfg(test)]
mod secure_dns_tests {
    use super::*;

    fn sd(json: &str) -> SecureDns {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn proxy_args_for_presets_and_custom() {
        let a = sd(r#"{"protocol":"doh","server":"cloudflare"}"#).proxy_args().unwrap();
        assert_eq!(a, ["--listen", "127.0.0.1:5453", "--doh", "https://cloudflare-dns.com/dns-query", "--ip", "1.1.1.1", "--ip", "1.0.0.1"]);
        let q = sd(r#"{"protocol":"dot","server":"quad9"}"#).proxy_args().unwrap();
        assert_eq!(&q[2..4], ["--dot", "dns.quad9.net"]);
        let n = sd(r#"{"protocol":"dot","server":"nextdns","nextdns_id":"abc123"}"#).proxy_args().unwrap();
        assert_eq!(&n[2..4], ["--dot", "abc123.dns.nextdns.io"]);
        assert!(sd(r#"{"protocol":"doh","server":"nextdns"}"#).proxy_args().is_none());
        let c = sd(r#"{"protocol":"doh","server":"custom","url":"https://dns.example/q","ips":["203.0.113.5"]}"#).proxy_args().unwrap();
        assert_eq!(&c[2..], ["--doh", "https://dns.example/q", "--ip", "203.0.113.5"]);
        assert!(sd(r#"{"protocol":"doh","server":"custom","url":"https://dns.example/q"}"#).proxy_args().is_none());
        assert!(serde_json::from_str::<SecureDns>(r#"{"protocol":"doq","server":"google"}"#).is_err());
    }
}
