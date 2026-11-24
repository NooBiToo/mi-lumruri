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
    /// IPv6 через VPN для источников, у которых через туннель идёт весь интернет («Всё через VPN»): клиент с has_ipv6,
    /// весь их IPv6 — в туннель (исключения и сайты с Zapret сопоставляются только по IPv4, по IPv6 они тоже идут в
    /// туннель). Выборочные правила по доменам IPv6 не используют: адреса доменов попадают в наборы только по IPv4.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ipv6_via_vpn: bool,
    /// Имена устройств, которые дал пользователь (MAC → имя): только для экрана «Устройства», на маршрутизацию не
    /// влияют и устройство не отмечают.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub device_names: std::collections::BTreeMap<String, String>,
    /// Дополнительные адреса панели (`https://хост[:порт]`), например обратный прокси на другом устройстве:
    /// страницы с них могут записывать настройки. Адрес по IP роутера и свои DNS-записи на роутер — без этого списка.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub panel_origins: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleConfig {
    #[serde(default)]
    pub lists: ListsUpdate,
    #[serde(default)]
    pub zapret_check: ZapretCheck,
    /// Проверка новой версии пакета на GitHub (только проверка: ставит пользователь кнопкой).
    #[serde(default)]
    pub update_check: UpdateCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateCheck {
    #[default]
    Daily,
    Weekly,
    /// Только по кнопке в панели.
    Manual,
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
        let update = match self.update_check { UpdateCheck::Daily => 86_400, UpdateCheck::Weekly => 7 * 86_400, UpdateCheck::Manual => 0 };
        format!("lists={lists}\nzapret_check={zapret}\nupdate_check={update}\n")
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
    /// Шифрование вопросов к резолверу туннеля (DoH/DoT поверх туннеля): защищает и участок от VPN-сервера до DNS.
    /// Только для готовых серверов (Cloudflare, Google, AdGuard; Quad9 — DoT): для них известно имя в сертификате.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_secure: Option<SecureProto>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adblock: Option<AdblockConfig>,
    /// Защищённый DNS (DoH/DoT) для доменов, которые не идут через туннель: их вопросы dnsmasq отдаёт mi-tt-dns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure: Option<SecureDns>,
    /// Свои записи: домен вместе с поддоменами отвечает заданным адресом (например, домашний сервер за Traefik).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostRecord>,
    /// Профиль, через туннель которого идут DNS-вопросы к `tunnel_resolver` (несколько серверов). Без него —
    /// профиль с наименьшим номером туннеля.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_profile: Option<String>,
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
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
/// Порт второго mi-tt-dns — для доменов туннеля (DoH/DoT поверх туннеля).
pub const DNS_TUNNEL_PORT: u16 = 5454;

impl SecureDns {
    /// Параметры mi-tt-dns (по одному в строке): адрес приёма, сервер и его IP. Запасной путь и файл состояния
    /// добавляет служба. None — свой сервер или NextDNS заданы не полностью (это ловит проверка настроек).
    /// Аргументы mi-tt-dns. У готовых серверов адреса IPv4, затем IPv6: прокси ходит на IPv6 только при недоступности
    /// всех IPv4 (запасной путь на будущее; без IPv6 у провайдера он не мешает). У NextDNS адреса IPv6 личные — только IPv4.
    pub fn proxy_args(&self) -> Option<Vec<String>> {
        fn v4v6(v4: &[&str], v6: &[&str]) -> Vec<String> {
            v4.iter().chain(v6).map(|s| s.to_string()).collect()
        }
        let (doh, dot, ips): (String, String, Vec<String>) = match self.server {
            SecureServer::Cloudflare => ("https://cloudflare-dns.com/dns-query".into(), "one.one.one.one".into(), v4v6(&["1.1.1.1", "1.0.0.1"], &["2606:4700:4700::1111", "2606:4700:4700::1001"])),
            SecureServer::Quad9 => ("https://dns.quad9.net/dns-query".into(), "dns.quad9.net".into(), v4v6(&["9.9.9.9", "149.112.112.112"], &["2620:fe::fe", "2620:fe::9"])),
            SecureServer::Google => ("https://dns.google/dns-query".into(), "dns.google".into(), v4v6(&["8.8.8.8", "8.8.4.4"], &["2001:4860:4860::8888", "2001:4860:4860::8844"])),
            SecureServer::Adguard => ("https://dns.adguard-dns.com/dns-query".into(), "dns.adguard-dns.com".into(), v4v6(&["94.140.14.14", "94.140.15.15"], &["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"])),
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

    /// Параметры второго mi-tt-dns для доменов туннеля: порт 5454, метка туннеля на сокетах (соединения идут в TUN по
    /// правилу fwmark), без запасного пути — без туннеля вопрос не должен уходить провайдеру. None — шифрование выключено;
    /// Err — для этого резолвера оно недоступно (своё IP, NextDNS без ID, DoH у Quad9).
    /// `dev` — TUN туннеля DNS; `mark` — метка сокетов (только при одном туннеле: при нескольких номер в метке
    /// выбирает mi-tt-admin, и решает привязка к TUN).
    pub fn tunnel_proxy_args(&self, dev: &str, mark: Option<u32>) -> Option<Result<Vec<String>, &'static str>> {
        let protocol = self.tunnel_secure?;
        let server = match self.resolver() {
            "1.1.1.1" | "1.0.0.1" => SecureServer::Cloudflare,
            "8.8.8.8" | "8.8.4.4" => SecureServer::Google,
            "94.140.14.14" | "94.140.15.15" => SecureServer::Adguard,
            "9.9.9.9" | "149.112.112.112" => SecureServer::Quad9,
            _ => return Some(Err("шифрование DNS через VPN есть только для Cloudflare, Google, AdGuard и Quad9 (DoT)")),
        };
        if protocol == SecureProto::Doh && server == SecureServer::Quad9 {
            return Some(Err("Quad9 по DoH работает только через HTTP/2 — выберите DoT"));
        }
        let mut a = SecureDns { protocol, server, nextdns_id: None, url: None, ips: vec![] }.proxy_args()?;
        a[1] = format!("127.0.0.1:{DNS_TUNNEL_PORT}");
        // привязка к TUN обязательна: прошивка в mangle OUTPUT переписывает метку, и пакет перемаршрутизируется мимо туннеля
        // (EHOSTUNREACH); метка остаётся для правила fwmark, привязанный сокет из mitt0 не выйдет
        a.extend(["--device".to_string(), dev.to_string()]);
        if let Some(m) = mark {
            a.extend(["--mark".to_string(), format!("{m:#x}")]);
        }
        Some(Ok(a))
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

/// Профиль (сервер VPN): для TrustTunnel — сервер, к которому подключается официальный клиент `trusttunnel_client`.
/// Профилей до 16, каждый — свой туннель (`tunnel`: таблица 3100+n, TUN `mitt<n>`), правила выбирают профиль.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub kind: ProfileKind,
    #[serde(default)]
    pub on_failure: FailurePolicy,
    /// Номер туннеля 0..=15: стабильный, не сдвигается при удалении других профилей.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub tunnel: u8,
    /// Точка подключения. Пароль хранится отдельно (secrets.json) и в API не попадает.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Endpoint>,
    /// Запасной сервер: служба переключается на него, если основной не подключается, и возвращается, когда основной
    /// снова отвечает. Пароль — `backup_password` в secrets.json.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<Endpoint>,
    /// Выбирать из основного и запасного сервер с меньшей задержкой (служба замеряет раз в полчаса), а не
    /// возвращаться на основной.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub prefer_fastest: bool,
    /// Сводка сервера модуля sing-box (для панели); сам сервер — ссылка в secrets.json.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<crate::proxy::ProxyInfo>,
    /// Сервер из подписки sing-box (имя из списка); без него — прежняя ссылка или первая в списке.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_pick: Option<String>,
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
    /// Отпечаток TLS ClientHello, под который маскируется клиент (`tls_profile`, клиент 1.3). Без него — chrome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_profile: Option<TlsProfile>,
    /// Префикс client_random (hex, `prefix[/mask]`): сервер с правилом по префиксу пускает только такие подключения.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_random: Option<String>,
    /// Ключ client_random (hex, `client_random_auth_key`, сервер 1.3): client_random выводится из ключа и имени сервера.
    /// Заменяет префикс — задаётся что-то одно.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_random_auth_key: Option<String>,
}

/// Отпечаток TLS ClientHello клиента TrustTunnel 1.3 (`[endpoint].tls_profile`; в ссылке tt:// — тег 0x10, байт 0–6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsProfile {
    Chrome,
    ChromeCanary,
    Safari,
    Firefox,
    Okhttp,
    Openssl,
    /// Собственный ClientHello библиотеки TLS, без маскировки.
    Boringssl,
}

impl TlsProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            TlsProfile::Chrome => "chrome",
            TlsProfile::ChromeCanary => "chrome_canary",
            TlsProfile::Safari => "safari",
            TlsProfile::Firefox => "firefox",
            TlsProfile::Okhttp => "okhttp",
            TlsProfile::Openssl => "openssl",
            TlsProfile::Boringssl => "boringssl",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Trusttunnel,
    /// Виды модуля sing-box: сервер задаётся ссылкой (секрет `link`), сводка — `Profile.proxy`.
    Vless,
    Hysteria2,
    Trojan,
    Shadowsocks,
    /// Модуль amneziawg: сервер — конфигурация AmneziaWG (секрет `link`).
    Amneziawg,
}

impl ProfileKind {
    pub fn label(self) -> &'static str {
        match self {
            ProfileKind::Trusttunnel => "TrustTunnel",
            ProfileKind::Vless => "VLESS",
            ProfileKind::Hysteria2 => "Hysteria2",
            ProfileKind::Trojan => "Trojan",
            ProfileKind::Shadowsocks => "Shadowsocks",
            ProfileKind::Amneziawg => "AmneziaWG",
        }
    }
    /// Сервер работает через модуль sing-box (ссылка vless://, hysteria2://, trojan://, ss://).
    pub fn singbox(self) -> bool {
        matches!(self, ProfileKind::Vless | ProfileKind::Hysteria2 | ProfileKind::Trojan | ProfileKind::Shadowsocks)
    }
    /// Сервер работает через модуль (не TrustTunnel): адрес — в секрете `link`, в настройках — сводка `proxy`.
    pub fn module(self) -> bool {
        self != ProfileKind::Trusttunnel
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
        assert_eq!(ScheduleConfig::default().file(), "lists=86400\nzapret_check=0\nupdate_check=86400\n");
        let s: ScheduleConfig = serde_json::from_str(r#"{"lists":"6h","zapret_check":"weekly"}"#).unwrap();
        assert_eq!(s.file(), "lists=21600\nzapret_check=604800\nupdate_check=86400\n");
        assert_eq!(serde_json::from_str::<ScheduleConfig>(r#"{"lists":"manual","update_check":"manual"}"#).unwrap().file(), "lists=0\nzapret_check=0\nupdate_check=0\n");
        assert_eq!(serde_json::from_str::<ScheduleConfig>(r#"{"update_check":"weekly"}"#).unwrap().file(), "lists=86400\nzapret_check=0\nupdate_check=604800\n");
        assert!(serde_json::from_str::<ScheduleConfig>(r#"{"lists":"hourly"}"#).is_err());
        assert_eq!(serde_json::to_string(&s).unwrap(), r#"{"lists":"6h","zapret_check":"weekly","update_check":"daily"}"#);
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
        assert_eq!(a, ["--listen", "127.0.0.1:5453", "--doh", "https://cloudflare-dns.com/dns-query", "--ip", "1.1.1.1", "--ip", "1.0.0.1", "--ip", "2606:4700:4700::1111", "--ip", "2606:4700:4700::1001"]);
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

#[cfg(test)]
mod tunnel_secure_tests {
    use super::*;

    fn dns(json: &str) -> DnsConfig {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn tunnel_proxy_args_mark_and_port() {
        assert!(dns(r#"{}"#).tunnel_proxy_args("mitt0", None).is_none());
        assert_eq!(dns(r#"{"tunnel_secure":"doh"}"#).tunnel_proxy_args("mitt2", None).unwrap().unwrap().last().unwrap(), "mitt2");
        let a = dns(r#"{"tunnel_secure":"doh"}"#).tunnel_proxy_args("mitt0", Some(0x4000)).unwrap().unwrap();
        assert_eq!(a, ["--listen", "127.0.0.1:5454", "--doh", "https://cloudflare-dns.com/dns-query", "--ip", "1.1.1.1", "--ip", "1.0.0.1", "--ip", "2606:4700:4700::1111", "--ip", "2606:4700:4700::1001", "--device", "mitt0", "--mark", "0x4000"]);
        let g = dns(r#"{"tunnel_resolver":"8.8.8.8","tunnel_secure":"dot"}"#).tunnel_proxy_args("mitt0", Some(0x4000)).unwrap().unwrap();
        assert_eq!(&g[2..4], ["--dot", "dns.google"]);
        assert!(dns(r#"{"tunnel_resolver":"9.9.9.9","tunnel_secure":"dot"}"#).tunnel_proxy_args("mitt0", Some(0x4000)).unwrap().is_ok());
        assert!(dns(r#"{"tunnel_resolver":"9.9.9.9","tunnel_secure":"doh"}"#).tunnel_proxy_args("mitt0", Some(0x4000)).unwrap().is_err());
        assert!(dns(r#"{"tunnel_resolver":"45.90.28.0","tunnel_secure":"doh"}"#).tunnel_proxy_args("mitt0", Some(0x4000)).unwrap().is_err());
    }
}
