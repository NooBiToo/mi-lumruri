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
use crate::render::{ProfileSecret, Secrets, check_secret, parse_category_list};
use crate::store::{self, SaveError, update_config};
use crate::validate::{Issue, MAX_RULES, normalize_mac};

/// Предел тела для загрузки списков (реклама, категории); для остальных — `api::MAX_BODY_BYTES`.
pub const MAX_LIST_BODY: usize = 8 * 1024 * 1024;

pub const PATHS: &[&str] = &["/rules/delete", "/rules/move", "/profiles", "/profiles/delete", "/groups", "/groups/delete", "/categories",
    "/categories/delete", "/networks", "/networks/delete", "/devices", "/devices/delete", "/leases", "/dns", "/zapret", "/adblock/list",
    "/categories/list", "/secrets", "/apply-request", "/status", "/zapret/test"];

pub fn is_manage_path(path: &str) -> bool {
    PATHS.contains(&path.trim_end_matches('/'))
}

pub fn is_list_upload(path: &str) -> bool {
    matches!(path.trim_end_matches('/'), "/adblock/list" | "/categories/list")
}

fn saved(r: Result<store::Saved, SaveError>, what: &str) -> Response {
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

fn bad(i: Vec<Issue>) -> Response {
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

/// Подбор, оставшийся в состоянии `running` дольше этого (сценарий убит без завершения), не мешает новой заявке.
const ZAPRET_TEST_STALE: u64 = 3600;

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

fn config_dir(config_path: &str) -> PathBuf {
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

/// Каталог состояния службы (запрос применения, статус). По умолчанию — RAM.
pub fn run_dir() -> PathBuf {
    std::env::var("MI_TT_RUN_DIR").ok().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp/mi-trusttunnel/run"))
}

fn read_config(config_path: &str) -> Result<Config, Response> {
    let b = read_limited(config_path, MAX_CONFIG_BYTES).map_err(|m| Response::error(500, "unreadable", m))?;
    parse_json(&b, "config").map_err(|i| Response { status: 409, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки не разобраны" }, "issues": i }) })
}

fn load_secrets(p: &Path) -> Result<Secrets, Response> {
    if !p.exists() {
        return Ok(Secrets { version: 1, profiles: BTreeMap::new() });
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
        Ok(d) if !d.is_empty() => match replace_list(&config_dir(config_path).join("adblock.list"), &d) {
            Ok(sha) => Response { status: 200, body: json!({ "ok": true, "domains": d.len(), "sha256": sha, "issues": [] }) },
            Err(m) => Response::error(500, "write_failed", m),
        },
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
            let m: serde_json::Map<String, Value> = cfg.profiles.iter().map(|pr| (pr.id.clone(), json!(s.profiles.contains_key(&pr.id)))).collect();
            Response { status: 200, body: json!({ "ok": true, "profiles": m, "issues": [] }) }
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
                if let Err(m) = check_secret(&q.secret) {
                    return Some(Response::error(422, "bad_secret", format!("секреты профиля «{}»: {m}", pr.id)));
                }
                let sp = secrets_path(config_path);
                let _g = match store::lock(&sp) {
                    Ok(g) => g,
                    Err(m) => return Some(Response::error(503, "busy", m)),
                };
                let mut s = match load_secrets(&sp) {
                    Ok(s) => s,
                    Err(r) => return Some(r),
                };
                s.profiles.insert(q.profile_id.clone(), q.secret);
                let mut out = serde_json::to_vec_pretty(&s).unwrap_or_default();
                out.push(b'\n');
                match store::write_atomic(&sp, &out) {
                    Ok(()) => Response { status: 200, body: json!({ "ok": true, "profile_id": q.profile_id, "stored": true, "issues": [] }) },
                    Err(m) => Response::error(500, "write_failed", m),
                }
            }
            Err(i) => bad(i),
        },
        ("POST", "/apply-request") => {
            // CGI без привилегий: только запрос; применяет служба mi-tt-admin (root) по текущей ревизии настроек
            let rev = read_limited(config_path, MAX_CONFIG_BYTES).ok().map(|b| store::revision(&b));
            let d = run_dir();
            let req = json!({ "requested_unix": crate::auth::now(), "config_revision": rev });
            match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("apply.request"), req.to_string().as_bytes())) {
                Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "config_revision": rev, "issues": [] }) },
                Err(m) => Response::error(500, "write_failed", m),
            }
        }
        ("GET", "/zapret/test") => {
            // файл состояния пишет сценарий подбора (mitt-zapret-test.sh); до первого подбора — idle
            let st = std::fs::read(run_dir().join("zapret-test.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).unwrap_or(json!({ "state": "idle" }));
            Response { status: 200, body: json!({ "ok": true, "test": st, "requested": run_dir().join("zapret-test.request").exists(), "issues": [] }) }
        }
        ("POST", "/zapret/test") => match parse_json::<ZapretTest>(b, "") {
            Ok(q) => {
                // CGI без привилегий: только заявка; подбор запускает служба (root), один одновременно
                let d = run_dir();
                let st = std::fs::read(d.join("zapret-test.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
                let now = crate::auth::now();
                let running = st.as_ref().is_some_and(|s| s["state"] == "running" && s["started"].as_u64().is_some_and(|t| t + ZAPRET_TEST_STALE > now));
                if running || d.join("zapret-test.request").exists() {
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
        ("GET", "/status") => {
            let st = std::fs::read(run_dir().join("status.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            let pending = run_dir().join("apply.request").exists();
            Response { status: 200, body: json!({ "ok": true, "service": st, "apply_pending": pending, "max_rules": MAX_RULES, "issues": [] }) }
        }
        (_, x) if PATHS.contains(&x) => {
            Response::error(405, "method_not_allowed", format!("метод {method} не поддерживается"))
        }
        _ => return None,
    };
    Some(r)
}
