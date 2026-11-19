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
}

/// Проверенный набор стратегий nfqws2 (zapret2): произвольные аргументы не принимаются.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ZapretConfig {
    pub strategy: ZapretStrategy,
    /// Позиция разреза в первом пакете данных (байт).
    #[serde(default = "default_zapret_pos")]
    pub pos: u16,
    /// TCP-порты назначения, к которым применяется обработка.
    #[serde(default = "default_zapret_ports")]
    pub tcp_ports: Vec<u16>,
}

fn default_zapret_pos() -> u16 {
    2
}
fn default_zapret_ports() -> Vec<u16> {
    vec![80, 443]
}

impl Default for ZapretConfig {
    fn default() -> Self {
        ZapretConfig { strategy: ZapretStrategy::Multisplit, pos: default_zapret_pos(), tcp_ports: default_zapret_ports() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretStrategy {
    /// Разрезать первый пакет (TLS ClientHello, HTTP-запрос) на сегменты.
    Multisplit,
    /// Разрезать и отправить сегменты в обратном порядке.
    Multidisorder,
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
