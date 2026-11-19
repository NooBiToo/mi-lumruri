//! Вход в веб-панель через CGI: маршруты `/auth/*` и допуск к защищённым API (`/config`, `/preview`, `/rules`
//! и любым другим адресам вне `/auth/`). Регистрации по сети нет: учётные данные создаёт только `mi-tt-admin auth`.
//!
//! Порядок проверок защищённого запроса: (POST) Origin/Sec-Fetch-Site → полная сессия → (POST) CSRF-заголовок.
//! Без настроенного входа защищённые адреса отвечают 503, без сессии — 401: production по умолчанию закрыт.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::{Response, WriteAccess, handle_with, parse_json};
use crate::auth::{
    self, AuthState, COOKIE_PENDING, COOKIE_SESSION, PENDING_MAX_FAILS, PENDING_TTL, Paths, SESSION_IDLE, SESSION_MAX, Session, Stage, clear_cookie,
    clock_trusted, cookie_value, ct_eq, set_cookie,
};

/// Сведения о запросе, извлечённые из окружения CGI.
pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub body: Option<&'a [u8]>,
    pub cookie: Option<&'a str>,
    pub csrf: Option<&'a str>,
    /// Результат проверки Origin для POST (для GET не используется).
    pub origin: WriteAccess,
    /// Запрос пришёл по HTTPS (`HTTPS=on` от веб-сервера).
    pub https: bool,
}

pub struct Reply {
    pub resp: Response,
    pub headers: Vec<String>,
}

impl From<Response> for Reply {
    fn from(resp: Response) -> Self {
        Reply { resp, headers: Vec::new() }
    }
}

fn ok(body: Value) -> Response {
    Response { status: 200, body }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecondBody {
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
}

fn configured(p: &Paths) -> Result<AuthState, Response> {
    match auth::load_state(p) {
        Ok(Some(s)) if s.login_ready() => Ok(s),
        Ok(Some(_)) => Err(Response::error(503, "auth_not_configured", "TOTP не подтверждён: выполните на роутере mi-tt-admin auth confirm")),
        Ok(None) => Err(Response::error(503, "auth_not_configured", "вход не настроен: выполните на роутере mi-tt-admin auth init")),
        Err(m) => Err(Response::error(500, "auth_state_corrupt", m)),
    }
}

fn too_many(until: u64, now: u64) -> Reply {
    let wait = until.saturating_sub(now).max(1);
    Reply {
        resp: Response { status: 429, body: json!({ "ok": false, "error": { "code": "too_many_attempts",
            "message": format!("слишком много неудачных попыток; повторите через {wait} с") }, "retry_after": wait, "issues": [] }) },
        headers: vec![format!("Retry-After: {wait}")],
    }
}

fn session_info(s: &Session, st: &AuthState, now: u64) -> Value {
    json!({ "authenticated": true, "totp": !st.totp_off(), "csrf": s.csrf, "expires": s.expires, "idle_timeout": SESSION_IDLE,
        "recovery_codes_left": st.recovery.iter().filter(|r| !r.used).count(), "clock_trusted": clock_trusted(now, st.last_good_time) })
}

/// Полная сессия из cookie (с продлением простоя).
fn full_session(p: &Paths, req: &Request, st: &AuthState, now: u64) -> Option<(String, Session)> {
    let token = cookie_value(req.cookie?, COOKIE_SESSION)?;
    let mut s = auth::load_session(p, &token, Stage::Full, st.sessions_epoch, now)?;
    if now >= s.last_seen + 30 {
        s.last_seen = now;
        auth::write_session(p, &token, &s);
    }
    Some((token, s))
}

pub fn serve(p: &Paths, req: Request, config_path: &str) -> Reply {
    let path = req.path.trim_end_matches('/');
    let now = auth::now();
    match (req.method, path) {
        ("POST", "/auth/login") => login(p, &req, now),
        ("POST", "/auth/second") => second(p, &req, now),
        ("GET", "/auth/session") => session(p, &req, now),
        ("POST", "/auth/logout") => logout(p, &req, now),
        (m, "/auth/login" | "/auth/second" | "/auth/session" | "/auth/logout") => {
            Response::error(405, "method_not_allowed", format!("метод {m} не поддерживается")).into()
        }
        (_, x) if x == "/auth" || x.starts_with("/auth/") => Response::error(404, "not_found", format!("неизвестный адрес {x}")).into(),
        _ => protected(p, req, config_path, now),
    }
}

fn protected(p: &Paths, req: Request, config_path: &str, now: u64) -> Reply {
    let post = req.method == "POST";
    if post {
        if let WriteAccess::Denied(r) = req.origin {
            return r.into();
        }
    }
    let st = match configured(p) {
        Ok(s) => s,
        Err(r) => return r.into(),
    };
    let Some((_, s)) = full_session(p, &req, &st, now) else {
        return Response::error(401, "auth_required", "нужен вход: пароль и второй фактор").into();
    };
    if post && !req.csrf.is_some_and(|c| ct_eq(c, &s.csrf)) {
        return Response::error(403, "csrf_failed", "нет или неверен заголовок X-MITT-CSRF").into();
    }
    // GET не пишет; для POST доступ уже подтверждён Origin, сессией и CSRF
    let access = if post { WriteAccess::Allowed } else { WriteAccess::Denied(Response::error(405, "method_not_allowed", "чтение")) };
    handle_with(req.method, req.path, req.body, config_path, access).into()
}

fn login(p: &Paths, req: &Request, now: u64) -> Reply {
    if let WriteAccess::Denied(r) = &req.origin {
        return Response { status: r.status, body: r.body.clone() }.into();
    }
    if !req.https {
        return Response::error(403, "https_required", "вход только по HTTPS").into();
    }
    let body: LoginBody = match parse_json(req.body.unwrap_or_default(), "") {
        Ok(b) => b,
        Err(_) => return Response::error(400, "bad_request", "ожидается {\"password\": \"…\"}").into(),
    };
    let _g = match auth::lock_auth(p) {
        Ok(g) => g,
        Err(m) => return Response::error(503, "busy", m).into(),
    };
    let st = match configured(p) {
        Ok(s) => s,
        Err(r) => return r.into(),
    };
    let a = auth::load_attempts(p);
    if a.locked_until > now {
        return too_many(a.locked_until, now);
    }
    if !auth::verify_password(&body.password, &st.password_hash) {
        let a = auth::record_failure(p, now);
        if a.locked_until > now {
            return too_many(a.locked_until, now);
        }
        return Response::error(401, "invalid_credentials", "неверный пароль").into();
    }
    if st.totp_off() {
        // вход только паролем: сразу полная сессия
        auth::reset_attempts(p);
        let (full, s) = match auth::create_session(p, Stage::Full, st.sessions_epoch, now) {
            Ok(t) => t,
            Err(m) => return Response::error(500, "session_failed", m).into(),
        };
        let mut info = session_info(&s, &st, now);
        info["ok"] = json!(true);
        info["stage"] = json!("done");
        return Reply { resp: ok(info), headers: vec![set_cookie(COOKIE_SESSION, &full, SESSION_MAX), clear_cookie(COOKIE_PENDING)] };
    }
    let (token, _) = match auth::create_session(p, Stage::Pending, st.sessions_epoch, now) {
        Ok(t) => t,
        Err(m) => return Response::error(500, "session_failed", m).into(),
    };
    Reply {
        resp: ok(json!({ "ok": true, "stage": "second_factor", "methods": ["totp", "recovery_code"],
            "clock_trusted": clock_trusted(now, st.last_good_time), "expires_in": PENDING_TTL })),
        headers: vec![set_cookie(COOKIE_PENDING, &token, PENDING_TTL)],
    }
}

fn second(p: &Paths, req: &Request, now: u64) -> Reply {
    if let WriteAccess::Denied(r) = &req.origin {
        return Response { status: r.status, body: r.body.clone() }.into();
    }
    if !req.https {
        return Response::error(403, "https_required", "вход только по HTTPS").into();
    }
    let body: SecondBody = match parse_json(req.body.unwrap_or_default(), "") {
        Ok(b) => b,
        Err(_) => return Response::error(400, "bad_request", "ожидается {\"totp\": \"123456\"} или {\"recovery_code\": \"…\"}").into(),
    };
    if body.totp.is_some() == body.recovery_code.is_some() {
        return Response::error(400, "bad_request", "нужен ровно один из totp или recovery_code").into();
    }
    // Проверка кода и запись последнего шага — под эксклюзивной блокировкой: одновременные запросы с одним кодом
    // выполняются по очереди, и успешен только первый.
    let _g = match auth::lock_auth(p) {
        Ok(g) => g,
        Err(m) => return Response::error(503, "busy", m).into(),
    };
    let mut st = match configured(p) {
        Ok(s) => s,
        Err(r) => return r.into(),
    };
    if st.totp_off() {
        return Response::error(409, "totp_off", "второй фактор не включён; войдите паролем").into();
    }
    let Some(token) = req.cookie.and_then(|c| cookie_value(c, COOKIE_PENDING)) else {
        return Response::error(401, "login_required", "сначала введите пароль").into();
    };
    let Some(mut pending) = auth::load_session(p, &token, Stage::Pending, st.sessions_epoch, now) else {
        return Reply { resp: Response::error(401, "login_required", "этап пароля истёк; войдите заново"), headers: vec![clear_cookie(COOKIE_PENDING)] };
    };
    let a = auth::load_attempts(p);
    if a.locked_until > now {
        return too_many(a.locked_until, now);
    }
    let verdict: Result<(), (&str, &str)> = if let Some(code) = &body.totp {
        if !clock_trusted(now, st.last_good_time) {
            // не считается попыткой: код не проверялся
            return Response::error(409, "clock_untrusted", "часы роутера не синхронизированы — TOTP недоступен; используйте recovery-код").into();
        }
        match auth::totp_match(&st.totp_secret_b32, code.trim(), now) {
            Some(step) if step > st.totp_last_step => {
                st.totp_last_step = step;
                st.last_good_time = st.last_good_time.max(now);
                Ok(())
            }
            Some(_) => Err(("code_reused", "этот код уже использован; дождитесь следующего")),
            None => Err(("invalid_code", "неверный код")),
        }
    } else {
        match auth::recovery_match(&st.recovery, body.recovery_code.as_deref().unwrap_or_default()) {
            Some(i) => {
                st.recovery[i].used = true;
                Ok(())
            }
            None => Err(("invalid_code", "неверный или уже использованный recovery-код")),
        }
    };
    if let Err((code, msg)) = verdict {
        let a = auth::record_failure(p, now);
        pending.fails += 1;
        let mut headers = Vec::new();
        if pending.fails >= PENDING_MAX_FAILS {
            auth::delete_session(p, &token);
            headers.push(clear_cookie(COOKIE_PENDING));
        } else {
            auth::write_session(p, &token, &pending);
        }
        if a.locked_until > now {
            let mut r = too_many(a.locked_until, now);
            r.headers.extend(headers);
            return r;
        }
        return Reply { resp: Response::error(401, code, msg), headers };
    }
    if let Err(m) = auth::save_state(p, &st) {
        return Response::error(500, "auth_write_failed", m).into();
    }
    auth::delete_session(p, &token);
    auth::reset_attempts(p);
    let (full, s) = match auth::create_session(p, Stage::Full, st.sessions_epoch, now) {
        Ok(t) => t,
        Err(m) => return Response::error(500, "session_failed", m).into(),
    };
    let mut info = session_info(&s, &st, now);
    info["ok"] = json!(true);
    Reply { resp: ok(info), headers: vec![set_cookie(COOKIE_SESSION, &full, SESSION_MAX), clear_cookie(COOKIE_PENDING)] }
}

fn session(p: &Paths, req: &Request, now: u64) -> Reply {
    let st = match configured(p) {
        Ok(s) => s,
        Err(r) => return r.into(),
    };
    if let Some((_, s)) = full_session(p, req, &st, now) {
        let mut info = session_info(&s, &st, now);
        info["ok"] = json!(true);
        return ok(info).into();
    }
    let pending = req
        .cookie
        .and_then(|c| cookie_value(c, COOKIE_PENDING))
        .and_then(|t| auth::load_session(p, &t, Stage::Pending, st.sessions_epoch, now))
        .is_some();
    let pending = pending && !st.totp_off();
    ok(json!({ "ok": true, "authenticated": false, "stage": if pending { "second_factor" } else { "password" },
        "clock_trusted": clock_trusted(now, st.last_good_time) }))
    .into()
}

fn logout(p: &Paths, req: &Request, now: u64) -> Reply {
    if let WriteAccess::Denied(r) = &req.origin {
        return Response { status: r.status, body: r.body.clone() }.into();
    }
    let clear = vec![clear_cookie(COOKIE_SESSION), clear_cookie(COOKIE_PENDING)];
    let st = match auth::load_state(p) {
        Ok(Some(s)) => s,
        _ => return Reply { resp: ok(json!({ "ok": true })), headers: clear },
    };
    if let Some((token, s)) = full_session(p, req, &st, now) {
        if !req.csrf.is_some_and(|c| ct_eq(c, &s.csrf)) {
            return Response::error(403, "csrf_failed", "нет или неверен заголовок X-MITT-CSRF").into();
        }
        auth::delete_session(p, &token);
    }
    if let Some(t) = req.cookie.and_then(|c| cookie_value(c, COOKIE_PENDING)) {
        auth::delete_session(p, &t);
    }
    Reply { resp: ok(json!({ "ok": true })), headers: clear }
}
