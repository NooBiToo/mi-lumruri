//! Общие помощники интеграционных тестов: изолированный вход в панель через настоящие бинарники.
//! Пароль и секрет TOTP создаются заново при каждом прогоне (случайные), в репозитории постоянных тестовых секретов нет.
//! Время задаётся MI_TT_TEST_NOW — подмена существует только в отладочной сборке (`cfg(debug_assertions)`).
#![allow(dead_code)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[allow(unused_imports)]
pub use mi_tt::auth::{PENDING_TTL, SESSION_IDLE, SESSION_MAX, TIME_FLOOR, hex, random_bytes, totp_at};

pub const ORIGIN: &str = "https://127.0.0.1:8787";
/// Опорное время тестов: заведомо после нижней границы доверенного времени, кратно шагу TOTP.
pub const T0: u64 = (TIME_FLOOR / 30 + 100_000) * 30;

pub fn ctl() -> &'static str {
    env!("CARGO_BIN_EXE_mi-tt-ctl")
}

pub fn admin() -> &'static str {
    env!("CARGO_BIN_EXE_mi-tt-admin")
}

pub fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("fixtures").join(name).to_string_lossy().into_owned()
}

pub fn rand_hex(n: usize) -> String {
    let b: [u8; 32] = random_bytes();
    hex(&b)[..n].to_string()
}

pub struct Auth {
    pub auth_dir: PathBuf,
    pub session_dir: PathBuf,
    pub password: String,
    pub secret: String,
    pub recovery: Vec<String>,
    pub config: String,
}

#[derive(Debug, Clone)]
pub struct Sess {
    pub cookie: String,
    pub csrf: String,
    pub now: u64,
}

pub struct Out {
    pub status: u16,
    pub body: Value,
    pub head: String,
}

impl Out {
    pub fn code(&self) -> &str {
        self.body["error"]["code"].as_str().unwrap_or("")
    }
    pub fn set_cookies(&self) -> Vec<&str> {
        self.head.lines().filter_map(|l| l.strip_prefix("Set-Cookie: ")).collect()
    }
    /// Значение cookie из Set-Cookie (пустая строка, если cookie стирается).
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.set_cookies().into_iter().find_map(|c| c.split(';').next()?.strip_prefix(&format!("{name}=")).map(str::to_string))
    }
}

/// Запуск mi-tt-admin auth с секретами через stdin (никогда не argv).
pub fn admin_auth(a: &Auth, args: &[&str], stdin: &str, now: u64) -> (i32, Value) {
    let mut c = Command::new(admin());
    c.arg("auth")
        .args(args)
        .env_remove("GATEWAY_INTERFACE")
        .env_remove("REQUEST_METHOD")
        .env_remove("SERVER_SOFTWARE")
        .env_remove("HTTP_HOST")
        .env("MI_TT_AUTH_DIR", &a.auth_dir)
        .env("MI_TT_SESSION_DIR", &a.session_dir)
        .env("MI_TT_TEST_NOW", now.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut ch = c.spawn().unwrap();
    ch.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = ch.wait_with_output().unwrap();
    (o.status.code().unwrap(), serde_json::from_slice(&o.stdout).unwrap_or(Value::Null))
}

impl Auth {
    /// Пустой каталог входа (ещё не настроен).
    pub fn empty(name: &str) -> Auth {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("auth-{name}-{}", rand_hex(8)));
        Auth { auth_dir: root.join("auth"), session_dir: root.join("sessions"), password: format!("pw-{}", rand_hex(24)), secret: String::new(), recovery: vec![],
            config: fixture("config.valid.json") }
    }

    /// Настроенный вход: init (пароль из stdin, Argon2id с уменьшенной для тестов памятью) и confirm в момент T0.
    pub fn new(name: &str) -> Auth {
        let mut a = Auth::empty(name);
        let pw = a.password.clone();
        let (code, v) = admin_auth(&a, &["init", "--stdin", "--kdf-m", "8192", "--kdf-t", "1"], &format!("{pw}\n{pw}\n"), T0);
        assert_eq!(code, 0, "{v}");
        a.secret = v["totp_secret_base32"].as_str().unwrap().to_string();
        a.recovery = v["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
        let (code, v) = admin_auth(&a, &["confirm", "--stdin"], &format!("{}\n", a.totp(T0)), T0);
        assert_eq!(code, 0, "{v}");
        a
    }

    pub fn totp(&self, t: u64) -> String {
        totp_at(&self.secret, t).unwrap()
    }

    /// CGI-запрос: окружение задаётся явно, остальное очищено.
    pub fn cgi(&self, method: &str, path: &str, body: Option<&[u8]>, now: u64, extra: &[(&str, &str)]) -> Out {
        cgi_raw(ctl(), method, path, body, &self.env(now), extra)
    }

    pub fn env(&self, now: u64) -> Vec<(String, String)> {
        vec![
            ("MI_TT_AUTH_DIR".into(), self.auth_dir.to_string_lossy().into_owned()),
            ("MI_TT_SESSION_DIR".into(), self.session_dir.to_string_lossy().into_owned()),
            ("MI_TT_TEST_NOW".into(), now.to_string()),
            ("MI_TT_ALLOWED_ORIGINS".into(), ORIGIN.into()),
            ("HTTPS".into(), "on".into()),
            ("MI_TT_CONFIG".into(), self.config.clone()),
            ("MI_TT_RUN_DIR".into(), self.session_dir.with_file_name("run").to_string_lossy().into_owned()),
        ]
    }

    /// Первый фактор: пароль → cookie предварительной сессии.
    pub fn password_step(&self, password: &str, now: u64) -> Out {
        let body = json!({ "password": password }).to_string();
        self.cgi("POST", "/auth/login", Some(body.as_bytes()), now, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "same-origin")])
    }

    pub fn second_step(&self, pre: &str, field: &str, code: &str, now: u64) -> Out {
        let body = json!({ field: code }).to_string();
        let cookie = format!("__Host-mitt_pre={pre}");
        self.cgi("POST", "/auth/second", Some(body.as_bytes()), now, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", &cookie)])
    }

    pub fn pending(&self, now: u64) -> String {
        let o = self.password_step(&self.password.clone(), now);
        assert_eq!(o.status, 200, "{}", o.body);
        o.cookie("__Host-mitt_pre").unwrap()
    }

    /// Полный вход с TOTP в момент `now` (шаг должен быть новее последнего принятого).
    pub fn login(&self, now: u64) -> Sess {
        let pre = self.pending(now);
        let o = self.second_step(&pre, "totp", &self.totp(now), now);
        assert_eq!(o.status, 200, "{}", o.body);
        Sess { cookie: format!("__Host-mitt_sess={}", o.cookie("__Host-mitt_sess").unwrap()), csrf: o.body["csrf"].as_str().unwrap().to_string(), now }
    }

    /// Защищённый запрос в рамках сессии (POST — с Origin и CSRF).
    pub fn api(&self, s: &Sess, method: &str, path: &str, body: Option<&[u8]>, now: u64) -> Out {
        let mut e: Vec<(&str, &str)> = vec![("HTTP_COOKIE", &s.cookie)];
        if method == "POST" {
            e.extend([("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "same-origin"), ("HTTP_X_MITT_CSRF", &s.csrf)]);
        }
        self.cgi(method, path, body, now, &e)
    }
}

pub fn cgi_raw(bin: &str, method: &str, path: &str, body: Option<&[u8]>, base: &[(String, String)], extra: &[(&str, &str)]) -> Out {
    let mut c = Command::new(bin);
    c.arg("cgi").env_clear().env("REQUEST_METHOD", method).env("PATH_INFO", path).stdin(Stdio::piped()).stdout(Stdio::piped());
    // Windows: без SystemRoot ОС не отдаёт процессу случайные байты
    if let Ok(v) = std::env::var("SystemRoot") {
        c.env("SystemRoot", v);
    }
    for (k, v) in base {
        c.env(k, v);
    }
    if let Some(b) = body {
        c.env("CONTENT_TYPE", "application/json").env("CONTENT_LENGTH", b.len().to_string());
    }
    for (k, v) in extra {
        c.env(k, v);
    }
    let mut ch = c.spawn().unwrap();
    {
        let mut si = ch.stdin.take().unwrap();
        if let Some(b) = body {
            let _ = si.write_all(b);
        }
    }
    let o = ch.wait_with_output().unwrap();
    assert!(o.status.success());
    let text = String::from_utf8(o.stdout).unwrap();
    let (head, b) = text.split_once("\r\n\r\n").expect("CGI headers");
    let status: u16 = head.strip_prefix("Status: ").unwrap()[..3].parse().unwrap();
    assert!(head.contains(&format!("Content-Length: {}", b.len())));
    Out { status, body: serde_json::from_str(b).unwrap(), head: head.to_string() }
}

/// Один настроенный вход и одна сессия на тестовый бинарник (для тестов прошлых этапов).
pub fn shared() -> &'static (Auth, Sess) {
    static S: std::sync::OnceLock<(Auth, Sess)> = std::sync::OnceLock::new();
    S.get_or_init(|| {
        let a = Auth::new("shared");
        let s = a.login(T0 + 30);
        (a, s)
    })
}

/// Окружение CGI с действующей общей сессией (cookie и CSRF); `origin` добавляет допустимый Origin.
pub fn shared_env(origin: bool) -> Vec<(String, String)> {
    let (a, s) = shared();
    let mut e: Vec<(String, String)> = a.env(s.now).into_iter().filter(|(k, _)| k != "MI_TT_ALLOWED_ORIGINS" && k != "MI_TT_CONFIG").collect();
    e.push(("HTTP_COOKIE".into(), s.cookie.clone()));
    e.push(("HTTP_X_MITT_CSRF".into(), s.csrf.clone()));
    if origin {
        e.push(("MI_TT_ALLOWED_ORIGINS".into(), ORIGIN.into()));
        e.push(("HTTP_ORIGIN".into(), ORIGIN.into()));
    }
    e
}
