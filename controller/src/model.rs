//! Версионированная модель настроек (схема v1). Только чтение: контроллер этого среза ничего не записывает.

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
    /// Шифрованный DNS роутера и блокировка рекламы. Без раздела DNS роутера не меняется.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
}

/// dnsmasq роутера сохраняет DHCP и локальные имена, внешние вопросы (после фильтра рекламы) передаёт DNS-слушателю
/// Mihomo на 127.0.0.1, который ходит к выбранным серверам только шифрованным транспортом. ODoH — через
/// dnscrypt-proxy и настроенный relay. Открытого DNS наружу нет: при отказе клиент получает ошибку.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub transport: DnsTransport,
    /// Серверы для doh/dot/doq/doh3 (1–4, по порядку).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<DnsServer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub odoh: Option<OdohConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adblock: Option<AdblockConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
    Doh,
    Dot,
    Doq,
    Doh3,
    Odoh,
}

/// Сервер шифрованного DNS. `ip` обязателен: имя сервера не разрешается через открытый DNS провайдера.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServer {
    /// Имя в сертификате (SNI и проверка TLS).
    pub host: String,
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Путь DoH/DoH3, по умолчанию /dns-query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// ODoH (RFC 9230): вопрос шифруется ключом target и передаётся через relay; relay видит клиента, target — вопрос.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdohConfig {
    pub target: OdohEndpoint,
    /// Один или несколько relay (1–4). Если все недоступны, клиент получает ошибку: напрямую к target вопрос не идёт.
    pub relays: Vec<OdohEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OdohEndpoint {
    pub host: String,
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub path: String,
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

/// VPN-профиль. Параметры сервера и ключи в этот срез не входят: здесь только ссылка для правил.
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
    /// IP-адрес или доменное имя сервера.
    pub server: String,
    pub port: u16,
    /// Имя для TLS SNI и проверки сертификата.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Имя пользователя TrustTunnel. У Hysteria2 нет имени: авторизация только паролем из secrets.json.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// SHA-256 сертификата сервера (закрепление). Без него проверяется цепочка до системных корневых сертификатов.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_sha256: Option<String>,
    /// HTTP/3 (QUIC) вместо HTTP/2 (TrustTunnel). Hysteria2 всегда работает поверх QUIC, поле для неё не задаётся.
    #[serde(default)]
    pub quic: bool,
    /// Обфускация Hysteria2 (salamander); пароль обфускации — в secrets.json (`obfs_password`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<Obfs>,
    /// VLESS: защита транспорта — TLS (проверка по SNI или закреплённому SHA-256) или REALITY (открытый ключ сервера).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<VlessSecurity>,
    /// VLESS: поток XTLS (`xtls-rprx-vision`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<VlessFlow>,
    /// VLESS REALITY: открытый ключ x25519 сервера (base64url) и short id (hex).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<Reality>,
    /// VLESS: отпечаток TLS-клиента (uTLS), по умолчанию chrome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_fingerprint: Option<String>,
    /// WireGuard/AmneziaWG: открытый ключ сервера (base64, 32 байта).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// WireGuard/AmneziaWG: адрес клиента в туннеле (IPv4/32).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// WireGuard/AmneziaWG: MTU туннеля (1280–1500).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Параметры AmneziaWG 1.0; без них — обычный WireGuard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub awg: Option<AwgParams>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VlessSecurity {
    Tls,
    Reality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum VlessFlow {
    #[serde(rename = "xtls-rprx-vision")]
    Vision,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reality {
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
}

/// AmneziaWG 1.0: мусорные пакеты перед рукопожатием (jc, jmin, jmax), заполнение init/response (s1, s2)
/// и заголовки типов сообщений (h1–h4). Должны совпадать с сервером.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwgParams {
    pub jc: u16,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Obfs {
    Salamander,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Trusttunnel,
    Vless,
    Hysteria2,
    Wireguard,
}

impl ProfileKind {
    pub fn label(self) -> &'static str {
        match self {
            ProfileKind::Trusttunnel => "TrustTunnel",
            ProfileKind::Vless => "VLESS",
            ProfileKind::Hysteria2 => "Hysteria2",
            ProfileKind::Wireguard => "WireGuard/AmneziaWG",
        }
    }
}

/// Что делать с трафиком правила, если профиль недоступен. По умолчанию — блокировать (без выхода в обход).
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
