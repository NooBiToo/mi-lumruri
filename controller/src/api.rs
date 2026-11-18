//! Обработчики JSON API. Общие для CLI и CGI, чтобы стенд и командная строка шли одним путём.

use std::fs;
use std::io::Read;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::model::{Config, SCHEMA_VERSION};
use crate::store::{SaveError, SaveRequest, revision, save_rule};
use crate::preview::{PreviewRequest, preview};
use crate::validate::{Issue, validate_config};

pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
pub const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct Response {
    pub status: u16,
    pub body: Value,
}

impl Response {
    fn ok(body: Value) -> Self {
        Response { status: 200, body }
    }
    pub fn error(status: u16, code: &str, message: impl Into<String>) -> Self {
        Response { status, body: json!({ "ok": false, "error": { "code": code, "message": message.into() }, "issues": [] }) }
    }
    fn issues(status: u16, code: &str, message: &str, issues: Vec<Issue>) -> Self {
        Response { status, body: json!({ "ok": false, "error": { "code": code, "message": message }, "issues": issues }) }
    }
}

/// Строгий разбор JSON: путь к ошибочному полю, запрет хвоста после документа.
pub fn parse_json<T: DeserializeOwned>(bytes: &[u8], prefix: &str) -> Result<T, Vec<Issue>> {
    let de = &mut serde_json::Deserializer::from_slice(bytes);
    let res: Result<T, _> = serde_path_to_error::deserialize(&mut *de);
    let mk = |path: String, msg: String| {
        let p = if path == "." || path.is_empty() { prefix.to_string() } else if prefix.is_empty() { path } else { format!("{prefix}.{path}") };
        vec![Issue::new(if p.is_empty() { "$".into() } else { p }, "parse", format!("ошибка формата: {msg}"))]
    };
    match res {
        Ok(v) => match de.end() {
            Ok(()) => Ok(v),
            Err(e) => Err(mk(String::new(), e.to_string())),
        },
        Err(e) => Err(mk(e.path().to_string(), e.inner().to_string())),
    }
}

pub fn read_limited(path: &str, max: u64) -> Result<Vec<u8>, String> {
    let f = fs::File::open(path).map_err(|e| format!("не удалось открыть {path}: {e}"))?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf).map_err(|e| format!("не удалось прочитать {path}: {e}"))?;
    if buf.len() as u64 > max {
        return Err(format!("{path} больше {max} байт"));
    }
    Ok(buf)
}

pub enum Loaded {
    Ok(Config),
    Invalid(Vec<Issue>),
}

pub fn load_config(path: &str) -> Result<Loaded, Response> {
    let bytes = read_limited(path, MAX_CONFIG_BYTES).map_err(|m| Response::error(500, "config_unreadable", m))?;
    Ok(match parse_json::<Config>(&bytes, "") {
        Ok(c) => Loaded::Ok(c),
        Err(i) => Loaded::Invalid(i),
    })
}

/// Право записи. CGI вычисляет его по Origin до вызова обработчика; локальная командная строка доверенная.
pub enum WriteAccess {
    Local,
    Denied(Response),
    Allowed,
}

/// Проверка источника записывающего запроса из браузера: Origin обязателен и должен быть в списке
/// MI_TT_ALLOWED_ORIGINS; Sec-Fetch-Site, если браузер его прислал, — только same-origin.
pub fn check_origin(allowed: &str, origin: Option<&str>, fetch_site: Option<&str>) -> WriteAccess {
    let list: Vec<&str> = allowed.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if list.is_empty() {
        return WriteAccess::Denied(Response::error(403, "write_disabled", "запись через веб-интерфейс не настроена (MI_TT_ALLOWED_ORIGINS)"));
    }
    let Some(o) = origin else {
        return WriteAccess::Denied(Response::error(403, "origin_required", "запрос на запись без заголовка Origin отклонён"));
    };
    if !list.contains(&o) {
        return WriteAccess::Denied(Response::error(403, "origin_forbidden", format!("источник {o} не допущен к записи")));
    }
    if let Some(s) = fetch_site {
        if s != "same-origin" {
            return WriteAccess::Denied(Response::error(403, "cross_site", "запись разрешена только со страницы самой панели"));
        }
    }
    WriteAccess::Allowed
}

pub fn handle(method: &str, path: &str, body: Option<&[u8]>, config_path: &str) -> Response {
    handle_with(method, path, body, config_path, WriteAccess::Local)
}

fn save(body: Option<&[u8]>, config_path: &str) -> Response {
    let req: SaveRequest = match parse_json(body.unwrap_or_default(), "") {
        Ok(r) => r,
        Err(i) => return Response::issues(400, "bad_request", "тело запроса не соответствует схеме", i),
    };
    match save_rule(std::path::Path::new(config_path), &req, MAX_CONFIG_BYTES) {
        Ok(s) => Response::ok(json!({ "ok": true, "mode": s.mode, "previous_revision": s.previous_revision,
            "revision": s.revision, "rule_id": req.rule.id, "config": s.config, "issues": [] })),
        Err(SaveError::Conflict { current }) => Response {
            status: 409,
            body: json!({ "ok": false, "error": { "code": "revision_conflict",
                "message": "настройки изменились после загрузки панели; обновите их и повторите" }, "current_revision": current, "issues": [] }),
        },
        Err(SaveError::Busy(m)) => Response::error(503, "busy", m),
        Err(SaveError::Io(m)) => Response::error(500, "write_failed", m),
        Err(SaveError::ConfigInvalid(i)) => Response::issues(409, "config_invalid", "сохранённые настройки не проходят проверку", i),
        Err(SaveError::RuleInvalid(i)) => Response::issues(422, "rule_invalid", "правило не прошло проверку", i),
    }
}

pub fn handle_with(method: &str, path: &str, body: Option<&[u8]>, config_path: &str, access: WriteAccess) -> Response {
    let path = path.trim_end_matches('/');
    // управление (этап 11): изменения только при разрешённом доступе (локально или после шлюза CGI)
    if crate::manage::is_manage_path(path) {
        if method == "POST" {
            if let WriteAccess::Denied(r) = access {
                return r;
            }
        }
        return crate::manage::handle(method, path, body, config_path).unwrap_or_else(|| Response::error(404, "not_found", format!("неизвестный адрес {path}")));
    }
    match (method, path) {
        ("GET", "/config") => {
            let rev = read_limited(config_path, MAX_CONFIG_BYTES).ok().map(|b| revision(&b));
            match load_config(config_path) {
                Err(r) => r,
                Ok(Loaded::Invalid(issues)) => {
                    Response::ok(json!({ "ok": false, "schema_version": SCHEMA_VERSION, "revision": rev, "config": null, "issues": issues }))
                }
                Ok(Loaded::Ok(cfg)) => {
                    let issues = validate_config(&cfg);
                    Response::ok(json!({ "ok": issues.is_empty(), "schema_version": SCHEMA_VERSION, "revision": rev, "config": cfg, "issues": issues }))
                }
            }
        }
        ("POST", "/rules") => match access {
            WriteAccess::Denied(r) => r,
            WriteAccess::Local | WriteAccess::Allowed => save(body, config_path),
        },
        ("POST", "/preview") => {
            let req: PreviewRequest = match parse_json(body.unwrap_or_default(), "") {
                Ok(r) => r,
                Err(i) => return Response::issues(400, "bad_request", "тело запроса не соответствует схеме", i),
            };
            let cfg = match load_config(config_path) {
                Err(r) => return r,
                Ok(Loaded::Invalid(i)) => {
                    let i = i.into_iter().map(|x| Issue { path: format!("config.{}", x.path), ..x }).collect();
                    return Response::issues(409, "config_invalid", "сохранённые настройки не проходят проверку", i);
                }
                Ok(Loaded::Ok(c)) => c,
            };
            match preview(&cfg, &req) {
                Ok(p) => Response::ok(json!({ "ok": true, "preview": p })),
                Err(i) if i.iter().any(|x| x.path.starts_with("config.")) => {
                    Response::issues(409, "config_invalid", "сохранённые настройки не проходят проверку", i)
                }
                Err(i) => Response::issues(422, "rule_invalid", "правило не прошло проверку", i),
            }
        }
        (_, "/config") | (_, "/preview") | (_, "/rules") => Response::error(405, "method_not_allowed", format!("метод {method} не поддерживается")),
        _ => Response::error(404, "not_found", format!("неизвестный адрес {path}")),
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        403 => "Forbidden",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}
