//! mi-tt-ctl — контроллер mi-trusttunnel, срез «чтение, проверка и предпросмотр правила».
//! Ничего не применяет к сети и не записывает настройки.

use mi_tt::{api, model, render, store};

use std::io::{self, Read, Write};
use std::process::ExitCode;

use api::{MAX_BODY_BYTES, MAX_CONFIG_BYTES, Response, WriteAccess, check_origin, handle, handle_with, read_limited, reason};

const DEFAULT_CONFIG: &str = "/data/mi-trusttunnel/config.json";
const USAGE: &str = "mi-tt-ctl — чтение, проверка и предпросмотр правил (срез без применения)

  mi-tt-ctl validate <config.json>
  mi-tt-ctl preview <config.json> <request.json>
  mi-tt-ctl save <config.json> <request.json>        # {\"base_revision\", \"rule\"}: атомарно, с блокировкой
  mi-tt-ctl render <config.json> <secrets.json> <dhcp.leases> <out-dir>   # config.yaml для Mihomo и routes.json
  mi-tt-ctl cgi            # CGI для uhttpd: MI_TT_CONFIG, MI_TT_ALLOWED_ORIGINS, REQUEST_METHOD, PATH_INFO, CONTENT_LENGTH
  mi-tt-ctl --version

Код выхода: 0 — проверка пройдена, 1 — найдены ошибки, 2 — ошибка запуска или чтения.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["--version"] => {
            println!("mi-tt-ctl {} (schema v{})", env!("CARGO_PKG_VERSION"), model::SCHEMA_VERSION);
            ExitCode::SUCCESS
        }
        ["validate", cfg] => cli(handle("GET", "/config", None, cfg)),
        ["preview", cfg, req] => match read_limited(req, MAX_BODY_BYTES as u64) {
            Ok(body) => cli(handle("POST", "/preview", Some(&body), cfg)),
            Err(m) => cli(Response::error(500, "request_unreadable", m)),
        },
        ["save", cfg, req] => match read_limited(req, MAX_BODY_BYTES as u64) {
            Ok(body) => cli(handle("POST", "/rules", Some(&body), cfg)),
            Err(m) => cli(Response::error(500, "request_unreadable", m)),
        },
        ["render", cfg, secrets, leases, out] => cli(render_cmd(cfg, secrets, leases, out)),
        ["cgi"] => cgi(),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn cli(r: Response) -> ExitCode {
    let out = serde_json::to_string_pretty(&r.body).unwrap_or_default();
    println!("{out}");
    let ok = r.body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    match r.status {
        200 if ok => ExitCode::SUCCESS,
        200 | 409 | 422 | 400 | 403 => ExitCode::from(1),
        _ => ExitCode::from(2),
    }
}

fn render_cmd(cfg: &str, secrets: &str, leases: &str, out: &str) -> Response {
    use serde_json::json;
    let read = |p: &str, max: u64| read_limited(p, max).map_err(|m| Response::error(500, "unreadable", m));
    let (c, s, l) = match (read(cfg, MAX_CONFIG_BYTES), read(secrets, 64 * 1024), read(leases, MAX_CONFIG_BYTES)) {
        (Ok(c), Ok(s), Ok(l)) => (c, s, l),
        (Err(r), _, _) | (_, Err(r), _) | (_, _, Err(r)) => return r,
    };
    let config: model::Config = match api::parse_json(&c, "config") {
        Ok(v) => v,
        Err(i) => return Response { status: 422, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки не разобраны" }, "issues": i }) },
    };
    let sec: render::Secrets = match api::parse_json(&s, "secrets") {
        Ok(v) => v,
        Err(i) => return Response { status: 422, body: json!({ "ok": false, "error": { "code": "secrets_invalid", "message": "secrets.json не разобран" }, "issues": i }) },
    };
    let mut warnings = Vec::new();
    #[cfg(unix)]
    if let Ok(m) = std::fs::metadata(secrets) {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            warnings.push(format!("{secrets} доступен не только владельцу (режим {:o})", m.permissions().mode() & 0o777));
        }
    }
    let leases = render::parse_leases(&String::from_utf8_lossy(&l));
    match render::render(&config, &sec, &leases) {
        Err(i) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "not_renderable", "message": "действующую конфигурацию нельзя сформировать точно; ничего не записано" }, "issues": i }) },
        Ok(r) => {
            let dir = std::path::Path::new(out);
            let yaml = serde_json::to_vec_pretty(&r.mihomo).unwrap_or_default();
            let routes = serde_json::to_vec_pretty(&r.routes).unwrap_or_default();
            if let Err(m) = std::fs::create_dir_all(dir).map_err(|e| format!("не удалось создать каталог {}: {e}", dir.display()))
                .and_then(|_| store::write_atomic(&dir.join("config.yaml"), &yaml))
                .and_then(|_| store::write_atomic(&dir.join("routes.json"), &routes))
            {
                return Response::error(500, "write_failed", m);
            }
            warnings.extend(r.warnings.iter().cloned());
            Response { status: 200, body: json!({ "ok": true, "source_revision": store::revision(&c), "mihomo_sha256": store::revision(&yaml),
                "rules": r.rules, "capture": r.capture,
                "plan": r.plan.iter().map(|e| e.label()).collect::<Vec<_>>(), "routes": r.routes, "warnings": warnings, "issues": [] }) }
        }
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn cgi_request() -> Response {
    let config = env("MI_TT_CONFIG").unwrap_or_else(|| DEFAULT_CONFIG.into());
    let method = env("REQUEST_METHOD").unwrap_or_default();
    let path = env("PATH_INFO").unwrap_or_else(|| "/".into());
    let mut body = None;
    if method == "POST" {
        let ctype = env("CONTENT_TYPE").unwrap_or_default();
        if !ctype.to_ascii_lowercase().starts_with("application/json") {
            return Response::error(415, "unsupported_media_type", "ожидается Content-Type: application/json");
        }
        let Some(len) = env("CONTENT_LENGTH") else {
            return Response::error(411, "length_required", "нужен заголовок Content-Length");
        };
        let Ok(len) = len.parse::<usize>() else {
            return Response::error(400, "bad_length", "некорректный Content-Length");
        };
        if len > MAX_BODY_BYTES {
            return Response::error(413, "too_large", format!("тело запроса больше {MAX_BODY_BYTES} байт"));
        }
        let mut buf = vec![0u8; len];
        if io::stdin().lock().read_exact(&mut buf).is_err() {
            return Response::error(400, "short_body", "тело запроса короче Content-Length");
        }
        body = Some(buf);
    }
    let access = if method == "GET" {
        WriteAccess::Denied(Response::error(405, "method_not_allowed", "чтение"))
    } else {
        check_origin(&env("MI_TT_ALLOWED_ORIGINS").unwrap_or_default(), env("HTTP_ORIGIN").as_deref(), env("HTTP_SEC_FETCH_SITE").as_deref())
    };
    handle_with(&method, &path, body.as_deref(), &config, access)
}

fn cgi() -> ExitCode {
    let r = cgi_request();
    let body = serde_json::to_vec(&r.body).unwrap_or_default();
    let mut out = io::stdout().lock();
    let head = format!(
        "Status: {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        r.status,
        reason(r.status),
        body.len()
    );
    let _ = out.write_all(head.as_bytes()).and_then(|_| out.write_all(&body)).and_then(|_| out.flush());
    ExitCode::SUCCESS
}
