//! Управление настройками из панели (этап 11): правила (удаление, порядок), профили, группы, категории, DNS, Zapret,
//! списки рекламы и категорий, секреты профилей (только запись), запрос применения и статус.
//!
//! Все изменения настроек — через `store::update_config` (блокировка, ревизия, полная проверка, атомарная запись).
//! Доступ проверяет шлюз CGI до вызова: Origin, сессия после пароля и второго фактора, CSRF.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{MAX_CONFIG_BYTES, Response, parse_json, read_limited};
use crate::model::{Category, Config, Device, DnsConfig, Group, Network, Profile, ZapretConfig};
use crate::render::{ProfileSecret, Secrets, merge_secret, parse_category_list};
use crate::store::{self, SaveError, update_config};
use crate::validate::{Issue, MAX_RULES, normalize_mac};

/// Предел тела для загрузки списков (реклама, категории); для остальных — `api::MAX_BODY_BYTES`.
pub const MAX_LIST_BODY: usize = 8 * 1024 * 1024;

pub const PATHS: &[&str] = &["/rules/delete", "/rules/move", "/profiles", "/profiles/delete", "/groups", "/groups/delete", "/categories",
    "/categories/delete", "/networks", "/networks/delete", "/devices", "/devices/delete", "/leases", "/dns", "/zapret", "/adblock/list",
    "/categories/list", "/secrets", "/apply-request", "/status", "/zapret/test", "/lists", "/lists/update", "/router", "/diag", "/service/restart", "/update", "/subscription", "/subscription/update", "/backup/export", "/backup/restore", "/notify", "/notify/test"];

pub fn is_manage_path(path: &str) -> bool {
    PATHS.contains(&path.trim_end_matches('/'))
}

pub fn is_list_upload(path: &str) -> bool {
    matches!(path.trim_end_matches('/'), "/adblock/list" | "/categories/list")
}

pub(crate) fn saved(r: Result<store::Saved, SaveError>, what: &str) -> Response {
    match r {
        Ok(s) => Response { status: 200, body: json!({ "ok": true, "mode": s.mode, "what": what, "previous_revision": s.previous_revision, "revision": s.revision, "config": s.config, "issues": [] }) },
        Err(SaveError::Conflict { current }) => Response {
            status: 409,
            body: json!({ "ok": false, "error": { "code": "revision_conflict", "message": "настройки изменились после загрузки панели; обновите их и повторите" }, "current_revision": current, "issues": [] }),
        },
        Err(SaveError::Busy(m)) => Response::error(503, "busy", m),
        Err(SaveError::Io(m)) => Response::error(500, "write_failed", m),
        Err(SaveError::ConfigInvalid(i)) => Response { status: 409, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "сохранённые настройки не проходят проверку" }, "issues": i }) },
        Err(SaveError::RuleInvalid(i)) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "invalid", "message": "изменение не прошло проверку; ничего не записано" }, "issues": i }) },
    }
}

pub(crate) fn bad(i: Vec<Issue>) -> Response {
    Response { status: 400, body: json!({ "ok": false, "error": { "code": "bad_request", "message": "тело запроса не соответствует схеме" }, "issues": i }) }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ById {
    base_revision: String,
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Move {
    base_revision: String,
    id: String,
    position: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct With<T> {
    base_revision: String,
    #[serde(alias = "profile", alias = "group", alias = "category", alias = "network", alias = "device", alias = "dns", alias = "zapret")]
    item: Option<T>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListUpload {
    #[serde(default)]
    id: Option<String>,
    list: String,
}

/// Заявка обновления из релизов GitHub: проверить или установить; trust_official — разрешить смену ключа на ключ релизов.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRequest {
    action: String,
    #[serde(default)]
    trust_official: bool,
}

/// Заявка диагностики: по желанию — сайт, который проверить (домен, без схемы и пути).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiagRequest {
    #[serde(default)]
    site: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZapretTest {
    mode: ZapretTestMode,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum ZapretTestMode {
    Quick,
}

/// Сценарий подбора обновляет файл состояния не реже раза в минуту (после каждой четвёрки целей). Файл `running`,
/// не менявшийся дольше этого, — от убитого сценария и новой заявке не мешает.
const ZAPRET_TEST_STALE: u64 = 300;

/// Подбор действительно идёт: состояние `running`, процесс сценария жив (где есть /proc) и файл недавно обновлялся.
fn zapret_test_running(file: &Path) -> bool {
    let Some(st) = std::fs::read(file).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { return false };
    if st["state"] != "running" {
        return false;
    }
    let proc = Path::new("/proc");
    if let Some(pid) = st["pid"].as_u64() {
        if proc.is_dir() && !proc.join(pid.to_string()).exists() {
            return false;
        }
    }
    let age = std::fs::metadata(file).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map(|d| d.as_secs());
    age.is_none_or(|a| a < ZAPRET_TEST_STALE)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretUpload {
    profile_id: String,
    secret: ProfileSecret,
}

fn upsert<T: Clone>(v: &mut Vec<T>, item: T, id: impl Fn(&T) -> &str, max: usize) -> Result<&'static str, Vec<Issue>> {
    let key = id(&item).to_string();
    match v.iter().position(|x| id(x) == key) {
        Some(i) => {
            v[i] = item;
            Ok("replace")
        }
        None if v.len() >= max => Err(vec![Issue::new("item", "too_many", format!("не больше {max} элементов"))]),
        None => {
            v.push(item);
            Ok("add")
        }
    }
}

fn remove<T>(v: &mut Vec<T>, key: &str, id: impl Fn(&T) -> &str) -> Result<&'static str, Vec<Issue>> {
    match v.iter().position(|x| id(x) == key) {
        Some(i) => {
            v.remove(i);
            Ok("delete")
        }
        None => Err(vec![Issue::new("id", "not_found", format!("«{key}» не найден"))]),
    }
}

pub(crate) fn config_dir(config_path: &str) -> PathBuf {
    Path::new(config_path).parent().map(Path::to_path_buf).unwrap_or_default()
}

pub fn secrets_path(config_path: &str) -> PathBuf {
    std::env::var("MI_TT_SECRETS").ok().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| config_dir(config_path).join("secrets.json"))
}

/// Файл аренд DHCP dnsmasq (по умолчанию штатный /tmp/dhcp.leases).
pub fn leases_path() -> PathBuf {
    std::env::var("MI_TT_LEASES").ok().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp/dhcp.leases"))
}

/// Клиенты из аренд DHCP для выбора устройства в панели: MAC, IPv4, имя (данные клиента LAN — только как текст, до 64 символов)
/// и устройство настроек с этим MAC, если оно уже заведено.
pub fn leases_view(text: &str, cfg: &Config) -> Vec<Value> {
    let known: BTreeMap<String, &str> = cfg.devices.iter().filter_map(|d| normalize_mac(&d.mac).ok().map(|m| (m, d.id.as_str()))).collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for line in text.lines().take(4096) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 {
            continue;
        }
        let (Ok(mac), Ok(ip)) = (normalize_mac(f[1]), f[2].parse::<std::net::Ipv4Addr>()) else { continue };
        if !seen.insert(mac.clone()) {
            continue;
        }
        let host: String = f.get(3).filter(|h| **h != "*").map(|h| h.chars().filter(|c| !c.is_control()).take(64).collect()).unwrap_or_default();
        out.push(json!({ "mac": mac, "ip": ip.to_string(), "hostname": host, "device": known.get(&mac) }));
    }
    out
}

/// Каталог готовых списков текущего релиза (catalog.json); путь передаёт CGI-обёртка службы.
pub fn lists_dir() -> Option<PathBuf> {
    std::env::var("MI_TT_LISTS_DIR").ok().filter(|s| !s.is_empty()).map(PathBuf::from)
}

/// Каталог состояния службы (запрос применения, статус). По умолчанию — RAM.
pub fn run_dir() -> PathBuf {
    std::env::var("MI_TT_RUN_DIR").ok().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp/mi-lumruri/run"))
}

/// Итог диагностики службы (каталог `diag` рядом с состоянием, пишет mitt-diag.sh) и маршрут проверенного сайта
/// по политике последнего рендера. До первой проверки — пустые списки.
fn diag_report() -> Response {
    let d = run_dir();
    let dd = d.join("diag");
    let text = |name: &str, max: u64| read_limited(&dd.join(name).to_string_lossy(), max).ok().map(|b| String::from_utf8_lossy(&b).into_owned());
    let stamp = |name: &str| text(name, 64).and_then(|s| s.trim().parse::<u64>().ok());
    let checks: Vec<Value> = text("checks.tsv", 64 * 1024)
        .map(|t| {
            t.lines()
                .filter_map(|l| {
                    let mut p = l.splitn(3, '\t');
                    let (id, status) = (p.next()?, p.next()?);
                    Some(json!({ "id": id, "status": status, "detail": p.next().unwrap_or("") }))
                })
                .collect()
        })
        .unwrap_or_default();
    let site = text("site.tsv", 4096).map(|t| {
        let kv: BTreeMap<&str, &str> = t.lines().filter_map(|l| l.split_once('\t')).collect();
        let sets: Vec<&str> = kv.get("sets").map(|s| s.split_whitespace().collect()).unwrap_or_default();
        let ip = kv.get("ip").copied().filter(|s| !s.is_empty());
        json!({
            "domain": kv.get("domain").copied().unwrap_or(""),
            "ip": ip,
            "route": ip.and_then(|_| site_route(&sets, &d)),
            "direct": http_probe(kv.get("direct").copied()),
            "tunnel": http_probe(kv.get("tunnel").copied()),
        })
    });
    let mut logs = serde_json::Map::new();
    for (k, f) in [("service", "log-service.txt"), ("trusttunnel", "log-trusttunnel.txt"), ("nfqws2", "log-nfqws2.txt")] {
        let lines: Vec<String> = text(f, 128 * 1024).map(|t| t.lines().map(|l| l.chars().take(400).collect()).collect()).unwrap_or_default();
        logs.insert(k.into(), json!(lines));
    }
    let running = d.join("diag.request").exists() || d.join("diag.request.run").exists();
    Response { status: 200, body: json!({ "ok": true, "running": running, "started": stamp("started"), "finished": stamp("finished"), "checks": checks, "site": site, "logs": logs, "issues": [] }) }
}

/// Пробный запрос mitt-diag.sh: «код время» от curl; пусто — не проверялось, код 0 — нет ответа.
fn http_probe(v: Option<&str>) -> Value {
    let Some(v) = v.map(str::trim).filter(|s| !s.is_empty()) else { return Value::Null };
    let mut p = v.split_whitespace();
    let code = p.next().and_then(|c| c.parse::<u16>().ok()).unwrap_or(0);
    let seconds = p.next().and_then(|t| t.parse::<f64>().ok());
    json!({ "code": code, "seconds": seconds })
}

/// Действие первого правила политики, чей набор содержит адрес сайта (или правила без набора — «всё остальное»).
/// Устройство не учитывается: правила «для выбранных устройств» показываются как для всех.
fn site_route(sets: &[&str], run: &Path) -> Option<String> {
    let policy = run.parent()?.join("render").join("policy.json");
    let v: Value = serde_json::from_slice(&std::fs::read(policy).ok()?).ok()?;
    for r in v.get("rules")?.as_array()? {
        let hit = match r.get("set").and_then(Value::as_str) {
            Some(s) => sets.contains(&s),
            None => true,
        };
        if hit {
            return r.get("act").and_then(Value::as_str).map(String::from);
        }
    }
    Some("direct".into())
}

pub(crate) fn read_config(config_path: &str) -> Result<Config, Response> {
    let b = read_limited(config_path, MAX_CONFIG_BYTES).map_err(|m| Response::error(500, "unreadable", m))?;
    parse_json(&b, "config").map_err(|i| Response { status: 409, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки не разобраны" }, "issues": i }) })
}

fn load_secrets(p: &Path) -> Result<Secrets, Response> {
    if !p.exists() {
        return Ok(Secrets { version: 1, profiles: BTreeMap::new(), notify: None });
    }
    let b = read_limited(&p.to_string_lossy(), 256 * 1024).map_err(|m| Response::error(500, "unreadable", m))?;
    parse_json(&b, "secrets").map_err(|_| Response::error(409, "secrets_invalid", "secrets.json не разобран; исправьте его на роутере"))
}

/// Атомарная замена списка (реклама или категория) с копией предыдущего; `entries` уже проверены.
pub fn replace_list(target: &Path, entries: &[String]) -> Result<String, String> {
    if let Some(d) = target.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let _g = store::lock(target)?;
    if target.exists() {
        std::fs::copy(target, store::sidecar(target, ".prev")).map_err(|e| e.to_string())?;
    }
    let body = format!("{}\n", entries.join("\n"));
    store::write_atomic(target, body.as_bytes())?;
    Ok(store::revision(body.as_bytes()))
}

pub fn adblock_list(config_path: &str, text: &str) -> Response {
    match crate::dns::parse_adblock_list(text) {
        Ok((d, skipped)) if !d.is_empty() => match replace_list(&config_dir(config_path).join("adblock.list"), &d) {
            Ok(sha) => Response { status: 200, body: json!({ "ok": true, "domains": d.len(), "skipped": skipped, "sha256": sha, "issues": [] }) },
            Err(m) => Response::error(500, "write_failed", m),
        },
        Err(i) if i.iter().any(|x| x.code == "empty") => Response::error(422, "adblock_empty", "пустой список не применяется; действующий список сохранён"),
        Ok(_) => Response::error(422, "adblock_empty", "пустой список не применяется; действующий список сохранён"),
        Err(i) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "adblock_invalid", "message": "список не прошёл проверку; действующий список сохранён" }, "issues": i }) },
    }
}

pub fn category_list(config_path: &str, id: &str, text: &str) -> Response {
    let cfg = match read_config(config_path) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(c) = cfg.categories.iter().find(|c| c.id == id) else {
        return Response::error(404, "unknown_category", format!("категория «{id}» не найдена в настройках"));
    };
    match parse_category_list(c.kind, text) {
        Ok(e) => {
            let plain: Vec<String> = e.iter().map(|x| x.trim_start_matches("+.").to_string()).collect();
            match replace_list(&config_dir(config_path).join("categories").join(format!("{id}.list")), &plain) {
                Ok(sha) => Response { status: 200, body: json!({ "ok": true, "category": id, "entries": plain.len(), "sha256": sha, "issues": [] }) },
                Err(m) => Response::error(500, "write_failed", m),
            }
        }
        Err(i) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "category_invalid", "message": "список не прошёл проверку; действующий список сохранён" }, "issues": i }) },
    }
}

/// Заявка на применение: CGI без привилегий только пишет запрос; применяет служба mi-tt-admin (root) по текущей ревизии настроек.
pub(crate) fn queue_apply(config_path: &str) -> Result<Option<String>, String> {
    let rev = read_limited(config_path, MAX_CONFIG_BYTES).ok().map(|b| store::revision(&b));
    let d = run_dir();
    let req = json!({ "requested_unix": crate::auth::now(), "config_revision": rev });
    std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("apply.request"), req.to_string().as_bytes()))?;
    Ok(rev)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replace {
    base_revision: String,
    config: Config,
}

/// `POST /config`: замена настроек целиком (полная проверка, атомарная запись) и сразу заявка на применение.
/// Ссылка-подписка профиля (для mitt-sub.sh): только из secrets.json, наружу через API не отдаётся.
pub fn subscription_url(config_path: &str, profile_id: &str) -> Option<String> {
    let s = load_secrets(&secrets_path(config_path)).ok()?;
    s.profiles.get(profile_id)?.subscription_url.clone()
}

/// Ответ подписки (JSON, скачанный службой) → точка подключения профиля и пароль. Ничего не изменилось — ничего не
/// пишется; изменилось — пароль в secrets.json, точка подключения в настройках (с проверкой и ревизией) и заявка на
/// применение.
pub fn subscription_import(config_path: &str, profile_id: &str, json_path: &str) -> Response {
    let body = match read_limited(json_path, 256 * 1024) {
        Ok(b) => b,
        Err(m) => return Response::error(500, "unreadable", m),
    };
    let j: crate::subscription::SubscriptionJson = match serde_json::from_slice(&body) {
        Ok(j) => j,
        Err(e) => return Response::error(422, "subscription_invalid", format!("ответ подписки не разобран: {e}")),
    };
    let raw = match read_limited(config_path, MAX_CONFIG_BYTES) {
        Ok(b) => b,
        Err(m) => return Response::error(500, "unreadable", m),
    };
    let cfg: Config = match parse_json(&raw, "config") {
        Ok(c) => c,
        Err(_) => return Response::error(409, "config_invalid", "настройки не разобраны"),
    };
    let Some(i) = cfg.profiles.iter().position(|p| p.id == profile_id) else {
        return Response::error(404, "unknown_profile", format!("профиль «{profile_id}» не найден"));
    };
    let imp = match crate::subscription::apply(&j, cfg.profiles[i].endpoint.as_ref()) {
        Ok(x) => x,
        Err(m) => return Response::error(422, "subscription_invalid", m),
    };
    if let Err(m) = crate::render::check_secret(&ProfileSecret { password: Some(imp.password.clone()), subscription_url: None, backup_password: None }) {
        return Response::error(422, "subscription_invalid", format!("пароль из подписки: {m}"));
    }
    let sp = secrets_path(config_path);
    let _g = match store::lock(&sp) {
        Ok(g) => g,
        Err(m) => return Response::error(503, "busy", m),
    };
    let mut s = match load_secrets(&sp) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let old_ep = serde_json::to_value(&cfg.profiles[i].endpoint).unwrap_or_default();
    let ep_changed = old_ep != serde_json::to_value(Some(&imp.endpoint)).unwrap_or_default();
    let pw_changed = s.profiles.get(profile_id).and_then(|x| x.password.as_deref()) != Some(imp.password.as_str());
    if !ep_changed && !pw_changed {
        return Response { status: 200, body: json!({ "ok": true, "changed": false, "warnings": imp.warnings, "issues": [] }) };
    }
    // новая точка подключения проверяется до записи пароля: при отказе не меняется ничего
    let mut next = cfg.clone();
    next.profiles[i].endpoint = Some(imp.endpoint);
    if ep_changed {
        let issues = crate::validate::validate_config(&next);
        if !issues.is_empty() {
            return Response { status: 422, body: json!({ "ok": false, "error": { "code": "subscription_invalid", "message": "параметры из подписки не прошли проверку; ничего не записано" }, "issues": issues }) };
        }
    }
    if pw_changed {
        let e = s.profiles.entry(profile_id.to_string()).or_insert(ProfileSecret { password: None, subscription_url: None, backup_password: None });
        e.password = Some(imp.password);
        let mut out = serde_json::to_vec_pretty(&s).unwrap_or_default();
        out.push(b'\n');
        if let Err(m) = store::write_atomic(&sp, &out) {
            return Response::error(500, "write_failed", m);
        }
    }
    if ep_changed {
        if let Err(e) = store::replace_config(Path::new(config_path), &store::revision(&raw), MAX_CONFIG_BYTES, &next) {
            return saved(Err(e), "config");
        }
    }
    match queue_apply(config_path) {
        Ok(_) => Response { status: 200, body: json!({ "ok": true, "changed": true, "endpoint": ep_changed, "password": pw_changed, "name": imp.name, "warnings": imp.warnings, "issues": [] }) },
        Err(m) => Response::error(500, "write_failed", format!("подписка перенесена, но заявка на применение не записана: {m}")),
    }
}

pub fn replace_config(body: Option<&[u8]>, config_path: &str) -> Response {
    let q = match parse_json::<Replace>(body.unwrap_or_default(), "") {
        Ok(q) => q,
        Err(i) => return bad(i),
    };
    let r = match store::replace_config(Path::new(config_path), &q.base_revision, MAX_CONFIG_BYTES, &q.config) {
        Err(SaveError::RuleInvalid(i)) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "новые настройки не прошли проверку; ничего не записано" }, "issues": i }) },
        r => saved(r, "config"),
    };
    if r.status != 200 {
        return r;
    }
    match queue_apply(config_path) {
        Ok(_) => Response { status: 200, body: { let mut b = r.body; b["queued"] = json!(true); b } },
        Err(m) => Response::error(500, "write_failed", format!("настройки сохранены, но заявка на применение не записана: {m}")),
    }
}

fn uci_network_path() -> PathBuf {
    std::env::var("MI_TT_UCI_NETWORK").ok().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/etc/config/network"))
}

/// Значение uci: до конца строки, в кавычках ' или " (внутри кавычек `#` не комментарий), иначе до комментария.
fn uci_value(rest: &str) -> String {
    let r = rest.trim();
    for q in ['\'', '"'] {
        if let Some(t) = r.strip_prefix(q) {
            return t.split(q).next().unwrap_or("").to_string();
        }
    }
    r.split('#').next().unwrap_or("").trim().to_string()
}

/// Параметры секции `config interface 'lan'` из файла uci; при повторе опции побеждает последняя.
fn parse_uci_lan(text: &str) -> Option<BTreeMap<String, String>> {
    let mut in_lan = false;
    let mut found = false;
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let t = line.trim_start();
        let (kw, rest) = t.split_once(char::is_whitespace).unwrap_or((t, ""));
        let rest = rest.trim_start();
        match kw {
            "config" => {
                let (kind, name) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                in_lan = kind == "interface" && uci_value(name) == "lan";
                found |= in_lan;
            }
            "option" if in_lan => {
                let (k, v) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
                m.insert(k.to_string(), uci_value(v));
            }
            _ => {}
        }
    }
    found.then_some(m)
}

fn router_lan() -> Response {
    let unavailable = |m: String| Response::error(503, "router_network_unavailable", m);
    let path = uci_network_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => return unavailable(format!("не удалось прочитать сетевые настройки роутера ({}): {e}", path.display())),
    };
    let Some(o) = parse_uci_lan(&text) else {
        return unavailable("в сетевых настройках роутера нет интерфейса lan".into());
    };
    // адрес с длиной префикса (ipaddr '192.168.31.1/24', OpenWrt 21+) — маска из него, netmask не нужен
    let (ip, mask) = match o.get("ipaddr").map(|a| a.split_once('/').map_or((a.as_str(), None), |(a, p)| (a, Some(p)))) {
        Some((ip, Some(prefix))) => {
            (ip, Some(prefix.parse::<u32>().ok().filter(|p| (1..=32).contains(p)).map(|p| std::net::Ipv4Addr::from(u32::MAX << (32 - p))).ok_or(())))
        }
        Some((ip, None)) => (ip, o.get("netmask").map(|m| m.parse::<std::net::Ipv4Addr>().map_err(|_| ()))),
        None => return unavailable("у интерфейса lan не задан адрес".into()),
    };
    let Some(mask) = mask else {
        return unavailable("у интерфейса lan не заданы адрес и маска сети".into());
    };
    let (Ok(ip), Ok(mask)) = (ip.parse::<std::net::Ipv4Addr>(), mask) else {
        return unavailable("адрес или маска интерфейса lan записаны в неизвестном виде".into());
    };
    let m = u32::from(mask);
    if m.count_ones() != m.leading_ones() {
        return unavailable("маска интерфейса lan не является маской подсети".into());
    }
    let net = std::net::Ipv4Addr::from(u32::from(ip) & m);
    let bridge = o.get("device").or_else(|| o.get("ifname")).filter(|d| d.starts_with("br-")).cloned().unwrap_or_else(|| "br-lan".into());
    Response { status: 200, body: json!({ "ok": true, "lan": { "bridge": bridge, "subnet": format!("{net}/{}", m.count_ones()), "address": ip.to_string() }, "issues": [] }) }
}

/// Маршруты управления. `None` — адрес не относится к управлению.
pub fn handle(method: &str, path: &str, body: Option<&[u8]>, config_path: &str) -> Option<Response> {
    let p = Path::new(config_path);
    let b = body.unwrap_or_default();
    let r = match (method, path) {
        ("POST", "/rules/delete") => match parse_json::<ById>(b, "") {
            Ok(q) => saved(update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| remove(&mut c.rules, &q.id, |r| r.id.as_str())), "rule"),
            Err(i) => bad(i),
        },
        ("POST", "/rules/move") => match parse_json::<Move>(b, "") {
            Ok(q) => saved(
                update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| {
                    let i = c.rules.iter().position(|r| r.id == q.id).ok_or(vec![Issue::new("id", "not_found", format!("правило «{}» не найдено", q.id))])?;
                    if q.position >= c.rules.len() {
                        return Err(vec![Issue::new("position", "out_of_range", format!("позиция от 0 до {}", c.rules.len() - 1))]);
                    }
                    let r = c.rules.remove(i);
                    c.rules.insert(q.position, r);
                    Ok("move")
                }),
                "rule",
            ),
            Err(i) => bad(i),
        },
        ("POST", "/profiles") => match parse_json::<With<Profile>>(b, "") {
            Ok(With { base_revision, item: Some(pr) }) => saved(update_config(p, &base_revision, MAX_CONFIG_BYTES, |c| upsert(&mut c.profiles, pr, |x| x.id.as_str(), 64)), "profile"),
            Ok(_) => Response::error(400, "bad_request", "нужен profile"),
            Err(i) => bad(i),
        },
        ("POST", "/profiles/delete") => match parse_json::<ById>(b, "") {
            Ok(q) => saved(update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| remove(&mut c.profiles, &q.id, |x| x.id.as_str())), "profile"),
            Err(i) => bad(i),
        },
        ("POST", "/groups") => match parse_json::<With<Group>>(b, "") {
            Ok(With { base_revision, item: Some(g) }) => saved(update_config(p, &base_revision, MAX_CONFIG_BYTES, |c| upsert(&mut c.groups, g, |x| x.id.as_str(), 64)), "group"),
            Ok(_) => Response::error(400, "bad_request", "нужен group"),
            Err(i) => bad(i),
        },
        ("POST", "/groups/delete") => match parse_json::<ById>(b, "") {
            Ok(q) => saved(update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| remove(&mut c.groups, &q.id, |x| x.id.as_str())), "group"),
            Err(i) => bad(i),
        },
        ("POST", "/categories") => match parse_json::<With<Category>>(b, "") {
            Ok(With { base_revision, item: Some(cat) }) => saved(update_config(p, &base_revision, MAX_CONFIG_BYTES, |c| upsert(&mut c.categories, cat, |x| x.id.as_str(), 64)), "category"),
            Ok(_) => Response::error(400, "bad_request", "нужен category"),
            Err(i) => bad(i),
        },
        ("POST", "/categories/delete") => match parse_json::<ById>(b, "") {
            Ok(q) => saved(update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| remove(&mut c.categories, &q.id, |x| x.id.as_str())), "category"),
            Err(i) => bad(i),
        },
        ("POST", "/networks") => match parse_json::<With<Network>>(b, "") {
            Ok(With { base_revision, item: Some(n) }) => saved(update_config(p, &base_revision, MAX_CONFIG_BYTES, |c| upsert(&mut c.networks, n, |x| x.id.as_str(), 32)), "network"),
            Ok(_) => Response::error(400, "bad_request", "нужен network"),
            Err(i) => bad(i),
        },
        ("POST", "/networks/delete") => match parse_json::<ById>(b, "") {
            Ok(q) => saved(update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| remove(&mut c.networks, &q.id, |x| x.id.as_str())), "network"),
            Err(i) => bad(i),
        },
        ("POST", "/devices") => match parse_json::<With<Device>>(b, "") {
            Ok(With { base_revision, item: Some(d) }) => saved(update_config(p, &base_revision, MAX_CONFIG_BYTES, |c| upsert(&mut c.devices, d, |x| x.id.as_str(), 256)), "device"),
            Ok(_) => Response::error(400, "bad_request", "нужен device"),
            Err(i) => bad(i),
        },
        ("POST", "/devices/delete") => match parse_json::<ById>(b, "") {
            Ok(q) => saved(update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| remove(&mut c.devices, &q.id, |x| x.id.as_str())), "device"),
            Err(i) => bad(i),
        },
        ("GET", "/leases") => {
            let cfg = match read_config(config_path) {
                Ok(c) => c,
                Err(r) => return Some(r),
            };
            let text = read_limited(&leases_path().to_string_lossy(), 1024 * 1024).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
            Response { status: 200, body: json!({ "ok": true, "leases": leases_view(&text, &cfg), "issues": [] }) }
        }
        ("POST", "/dns") => match parse_json::<With<DnsConfig>>(b, "") {
            Ok(q) => saved(
                update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| {
                    c.dns = q.item;
                    Ok(if c.dns.is_some() { "set" } else { "clear" })
                }),
                "dns",
            ),
            Err(i) => bad(i),
        },
        ("POST", "/zapret") => match parse_json::<With<ZapretConfig>>(b, "") {
            Ok(q) => saved(
                update_config(p, &q.base_revision, MAX_CONFIG_BYTES, |c| {
                    c.zapret = q.item;
                    Ok(if c.zapret.is_some() { "set" } else { "clear" })
                }),
                "zapret",
            ),
            Err(i) => bad(i),
        },
        ("POST", "/adblock/list") => match parse_json::<ListUpload>(b, "") {
            Ok(q) if q.id.is_none() => adblock_list(config_path, &q.list),
            Ok(_) => Response::error(400, "bad_request", "id не задаётся для списка рекламы"),
            Err(i) => bad(i),
        },
        ("POST", "/categories/list") => match parse_json::<ListUpload>(b, "") {
            Ok(ListUpload { id: Some(id), list }) => category_list(config_path, &id, &list),
            Ok(_) => Response::error(400, "bad_request", "нужен id категории"),
            Err(i) => bad(i),
        },
        ("GET", "/secrets") => {
            let cfg = match read_config(config_path) {
                Ok(c) => c,
                Err(r) => return Some(r),
            };
            let s = match load_secrets(&secrets_path(config_path)) {
                Ok(s) => s,
                Err(r) => return Some(r),
            };
            // только признак наличия; значения секретов API никогда не возвращает
            // пароль задан; отдельно — есть ли ссылка-подписка (значения не возвращаются)
            let m: serde_json::Map<String, Value> = cfg.profiles.iter().map(|pr| (pr.id.clone(), json!(s.profiles.get(&pr.id).is_some_and(|x| x.password.is_some())))).collect();
            let sub: serde_json::Map<String, Value> = cfg.profiles.iter().map(|pr| (pr.id.clone(), json!(s.profiles.get(&pr.id).is_some_and(|x| x.subscription_url.is_some())))).collect();
            let backup: serde_json::Map<String, Value> = cfg.profiles.iter().map(|pr| (pr.id.clone(), json!(s.profiles.get(&pr.id).is_some_and(|x| x.backup_password.is_some())))).collect();
            Response { status: 200, body: json!({ "ok": true, "profiles": m, "subscriptions": sub, "backups": backup, "issues": [] }) }
        }
        ("POST", "/secrets") => match parse_json::<SecretUpload>(b, "") {
            Ok(q) => {
                let cfg = match read_config(config_path) {
                    Ok(c) => c,
                    Err(r) => return Some(r),
                };
                let Some(pr) = cfg.profiles.iter().find(|x| x.id == q.profile_id) else {
                    return Some(Response::error(404, "unknown_profile", format!("профиль «{}» не найден", q.profile_id)));
                };
                let sp = secrets_path(config_path);
                let _g = match store::lock(&sp) {
                    Ok(g) => g,
                    Err(m) => return Some(Response::error(503, "busy", m)),
                };
                let mut s = match load_secrets(&sp) {
                    Ok(s) => s,
                    Err(r) => return Some(r),
                };
                // поля, которых нет в запросе, не меняются (пароль и ссылка-подписка задаются по отдельности)
                let merged = match merge_secret(s.profiles.remove(&q.profile_id), q.secret) {
                    Ok(m) => m,
                    Err(m) => return Some(Response::error(422, "bad_secret", format!("секреты профиля «{}»: {m}", pr.id))),
                };
                s.profiles.insert(q.profile_id.clone(), merged);
                let mut out = serde_json::to_vec_pretty(&s).unwrap_or_default();
                out.push(b'\n');
                match store::write_atomic(&sp, &out) {
                    Ok(()) => Response { status: 200, body: json!({ "ok": true, "profile_id": q.profile_id, "stored": true, "issues": [] }) },
                    Err(m) => Response::error(500, "write_failed", m),
                }
            }
            Err(i) => bad(i),
        },
        ("POST", "/backup/export") => crate::backup::export(b, config_path),
        ("GET", "/notify") => crate::notify::get(config_path),
        ("POST", "/notify") => crate::notify::set(b, config_path),
        ("POST", "/notify/test") => crate::notify::test(config_path),
        ("POST", "/backup/restore") => crate::backup::restore(b, config_path),
        ("POST", "/apply-request") => match queue_apply(config_path) {
            Ok(rev) => Response { status: 202, body: json!({ "ok": true, "queued": true, "config_revision": rev, "issues": [] }) },
            Err(m) => Response::error(500, "write_failed", m),
        },
        ("GET", "/zapret/test") => {
            // файл состояния пишет сценарий подбора (mitt-zapret-test.sh); до первого подбора — idle
            let st = std::fs::read(run_dir().join("zapret-test.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).unwrap_or(json!({ "state": "idle" }));
            Response { status: 200, body: json!({ "ok": true, "test": st, "requested": run_dir().join("zapret-test.request").exists(), "issues": [] }) }
        }
        ("POST", "/zapret/test") => match parse_json::<ZapretTest>(b, "") {
            Ok(q) => {
                // CGI без привилегий: только заявка; подбор запускает служба (root), один одновременно
                let d = run_dir();
                let now = crate::auth::now();
                if zapret_test_running(&d.join("zapret-test.json")) || d.join("zapret-test.request").exists() {
                    return Some(Response::error(409, "zapret_test_running", "подбор стратегии уже идёт"));
                }
                let req = json!({ "requested_unix": now, "mode": q.mode });
                match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("zapret-test.request"), req.to_string().as_bytes())) {
                    Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "issues": [] }) },
                    Err(m) => Response::error(500, "write_failed", m),
                }
            }
            Err(i) => bad(i),
        },
        ("GET", "/lists") => {
            // каталог — из релиза (снимок itdoginfo), состояние обновления пишет mitt-lists.sh update; до первой проверки — null
            let Some(cat) = lists_dir().and_then(|d| read_limited(&d.join("catalog.json").to_string_lossy(), 1024 * 1024).ok()).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else {
                return Some(Response::error(503, "lists_unavailable", "каталог списков недоступен (релиз не найден)"));
            };
            let st = std::fs::read(run_dir().join("lists.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            Response { status: 200, body: json!({ "ok": true, "catalog": cat, "status": st, "requested": run_dir().join("lists-update.request").exists(), "issues": [] }) }
        }
        ("POST", "/lists/update") => {
            // CGI без привилегий: только заявка; загрузку запускает служба в фоне (повторная заявка ничего не меняет)
            let d = run_dir();
            let req = json!({ "requested_unix": crate::auth::now() });
            match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("lists-update.request"), req.to_string().as_bytes())) {
                Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "issues": [] }) },
                Err(m) => Response::error(500, "write_failed", m),
            }
        }
        ("GET", "/router") => router_lan(),
        ("GET", "/diag") => diag_report(),
        ("POST", "/diag") => match parse_json::<DiagRequest>(b, "") {
            Ok(q) => {
                // CGI без привилегий: только заявка; проверки (ip, iptables, пробные запросы) выполняет служба
                let site = match q.site.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    None => None,
                    Some(s) => match crate::validate::normalize_domain(s, 2) {
                        Ok(d) => Some(d),
                        Err(m) => return Some(bad(vec![Issue::new("site", "bad_domain", m)])),
                    },
                };
                let d = run_dir();
                if d.join("diag.request").exists() || d.join("diag.request.run").exists() {
                    return Some(Response::error(409, "diag_running", "проверка уже идёт"));
                }
                let req = json!({ "requested_unix": crate::auth::now(), "site": site });
                match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("diag.request"), req.to_string().as_bytes())) {
                    Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "issues": [] }) },
                    Err(m) => Response::error(500, "write_failed", m),
                }
            }
            Err(i) => bad(i),
        },
        ("GET", "/subscription") => {
            // итог последнего обновления по подписке (mitt-sub.sh); подписки нет или ещё не обновлялась — null
            let d = run_dir();
            let st = std::fs::read(d.join("subscription.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            let running = d.join("sub-update.request").exists() || d.join("sub-update.request.run").exists();
            Response { status: 200, body: json!({ "ok": true, "running": running, "subscription": st, "issues": [] }) }
        }
        ("POST", "/subscription/update") => {
            let d = run_dir();
            let req = json!({ "requested_unix": crate::auth::now() });
            match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("sub-update.request"), req.to_string().as_bytes())) {
                Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "issues": [] }) },
                Err(m) => Response::error(500, "write_failed", m),
            }
        }
        ("GET", "/update") => {
            // итог последней проверки или установки (mitt-update.sh); до первой — null
            let d = run_dir();
            let st = std::fs::read(d.join("update.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            let running = d.join("update.request").exists() || d.join("update.request.run").exists();
            Response { status: 200, body: json!({ "ok": true, "running": running, "update": st, "issues": [] }) }
        }
        ("POST", "/update") => match parse_json::<UpdateRequest>(b, "") {
            Ok(q) => {
                // CGI без привилегий: только заявка; загрузку и установку выполняет служба
                if q.action != "check" && q.action != "install" {
                    return Some(bad(vec![Issue::new("action", "bad_action", "действие — check или install")]));
                }
                let d = run_dir();
                if d.join("update.request").exists() || d.join("update.request.run").exists() {
                    return Some(Response::error(409, "update_running", "обновление уже идёт"));
                }
                let req = json!({ "requested_unix": crate::auth::now(), "action": q.action, "trust_official": q.trust_official });
                match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("update.request"), req.to_string().as_bytes())) {
                    Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "issues": [] }) },
                    Err(m) => Response::error(500, "write_failed", m),
                }
            }
            Err(i) => bad(i),
        },
        ("POST", "/service/restart") => {
            let d = run_dir();
            let req = json!({ "requested_unix": crate::auth::now() });
            match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("restart.request"), req.to_string().as_bytes())) {
                Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "issues": [] }) },
                Err(m) => Response::error(500, "write_failed", m),
            }
        }
        ("GET", "/status") => {
            let st = std::fs::read(run_dir().join("status.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            let pending = run_dir().join("apply.request").exists();
            // итог последней загрузки списка рекламы (mitt-adblock.sh); до первой — null
            let adblock = std::fs::read(run_dir().join("adblock.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            // состояние прокси DoH/DoT (mi-tt-dns пишет раз в 15 секунд); выключен — null
            let dns_proxy = std::fs::read(run_dir().join("dns-proxy.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            let dns_tunnel = std::fs::read(run_dir().join("dns-tunnel.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            Response { status: 200, body: json!({ "ok": true, "service": st, "apply_pending": pending, "adblock": adblock, "dns_proxy": dns_proxy, "dns_tunnel": dns_tunnel, "max_rules": MAX_RULES, "issues": [] }) }
        }
        (_, x) if PATHS.contains(&x) => {
            Response::error(405, "method_not_allowed", format!("метод {method} не поддерживается"))
        }
        _ => return None,
    };
    Some(r)
}
