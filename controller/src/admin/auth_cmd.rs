//! `mi-tt-admin auth …` — первичная настройка и восстановление входа в панель. Только локально (SSH/консоль):
//! регистрации по сети нет. Секреты вводятся с терминала без эха или построчно из stdin (`--stdin`), никогда через argv;
//! новый секрет TOTP и recovery-коды выводятся один раз в stdout оператору и нигде не сохраняются открытым текстом.

use std::io::BufRead;
use std::process::ExitCode;

use serde_json::json;

use mi_tt::auth::{self, AuthState, KdfParams, Paths, clock_trusted};

pub const USAGE: &str = "  mi-tt-admin auth init [--stdin] [--force] [--label NAME] [--kdf-m KiB] [--kdf-t N]  # пароль, TOTP, recovery-коды
  mi-tt-admin auth confirm [--stdin]          # подтвердить TOTP кодом из приложения — после этого вход включён
  mi-tt-admin auth reset-password [--stdin]   # новый пароль; все сессии отзываются
  mi-tt-admin auth reset-totp [--stdin]       # новый секрет TOTP (нужен confirm); все сессии отзываются
  mi-tt-admin auth recovery-codes             # новые одноразовые recovery-коды взамен старых
  mi-tt-admin auth unlock                     # снять блокировку после неудачных попыток
  mi-tt-admin auth revoke-sessions            # завершить все сессии
  mi-tt-admin auth status                     # состояние без секретов
  Каталоги: --auth-dir (MI_TT_AUTH_DIR, по умолчанию /data/mi-trusttunnel/auth), --session-dir (MI_TT_SESSION_DIR).";

struct Opts {
    cmd: String,
    stdin: bool,
    force: bool,
    label: String,
    kdf: KdfParams,
    paths: Paths,
}

fn out(code: u8, v: serde_json::Value) -> ExitCode {
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    ExitCode::from(code)
}

fn fail(code: u8, err: &str, msg: impl Into<String>) -> ExitCode {
    out(code, json!({ "ok": false, "error": { "code": err, "message": msg.into() } }))
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut it = args.iter();
    let cmd = it.next().ok_or("auth: нет подкоманды")?.clone();
    let mut o = Opts { cmd, stdin: false, force: false, label: "router".into(), kdf: KdfParams::default(), paths: Paths::from_env() };
    while let Some(k) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{k}: нужно значение"));
        match k.as_str() {
            "--stdin" => o.stdin = true,
            "--force" => o.force = true,
            "--label" => o.label = val()?,
            "--auth-dir" => o.paths.auth_dir = val()?.into(),
            "--session-dir" => o.paths.session_dir = val()?.into(),
            "--kdf-m" => o.kdf.m_kib = val()?.parse().map_err(|_| "--kdf-m: число КиБ")?,
            "--kdf-t" => o.kdf.t = val()?.parse().map_err(|_| "--kdf-t: число проходов")?,
            // секреты в argv не принимаются: они видны в ps и истории оболочки
            "--password" | "--code" | "--totp" => return Err(format!("{k}: секреты не передаются аргументами; используйте терминал или --stdin")),
            _ => return Err(format!("неизвестный аргумент {k}")),
        }
    }
    if !o.label.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) || o.label.is_empty() || o.label.len() > 32 {
        return Err("--label: латиница, цифры, - _ . (до 32)".into());
    }
    if o.kdf.m_kib < 8 * 1024 || o.kdf.t < 1 {
        return Err("параметры Argon2id ниже минимума (m ≥ 8192 КиБ, t ≥ 1)".into());
    }
    Ok(o)
}

/// Секрет: построчно из stdin (`--stdin`) или с терминала без эха.
struct Input {
    stdin: bool,
}

impl Input {
    fn read(&self, prompt: &str) -> Result<String, String> {
        if self.stdin {
            let mut l = String::new();
            std::io::stdin().lock().read_line(&mut l).map_err(|e| format!("stdin: {e}"))?;
            if l.is_empty() {
                return Err("stdin закончился раньше, чем ожидалось".into());
            }
            return Ok(l.trim_end_matches(['\n', '\r']).to_string());
        }
        #[cfg(unix)]
        {
            rpassword::prompt_password(prompt).map_err(|e| format!("терминал недоступен ({e}); используйте --stdin"))
        }
        #[cfg(not(unix))]
        {
            let _ = prompt;
            Err("ввод с терминала без эха поддерживается только на Linux; используйте --stdin".into())
        }
    }

    fn new_password(&self) -> Result<String, String> {
        let a = self.read("Новый пароль панели: ")?;
        auth::check_password_policy(&a)?;
        let b = self.read("Повторите пароль: ")?;
        if !auth::ct_eq(&a, &b) {
            return Err("пароли не совпадают".into());
        }
        Ok(a)
    }
}

fn load(p: &Paths) -> Result<AuthState, ExitCode> {
    match auth::load_state(p) {
        Ok(Some(s)) => Ok(s),
        Ok(None) => Err(fail(2, "auth_not_configured", "вход не настроен: mi-tt-admin auth init")),
        Err(m) => Err(fail(2, "auth_state_corrupt", m)),
    }
}

fn revoke_files(p: &Paths) {
    if let Ok(rd) = std::fs::read_dir(&p.session_dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.len() == 64 && n.bytes().all(|c| c.is_ascii_hexdigit()) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

fn enrollment(st: &AuthState, label: &str, codes: Option<&[String]>) -> serde_json::Value {
    let mut v = json!({ "ok": true, "totp_secret_base32": st.totp_secret_b32, "otpauth_uri": auth::otpauth_uri(&st.totp_secret_b32, label),
        "next": "добавьте секрет в приложение-аутентификатор и выполните: mi-tt-admin auth confirm",
        "notice": "секрет и коды выводятся один раз; сохраните recovery-коды офлайн" });
    if let Some(c) = codes {
        v["recovery_codes"] = json!(c);
    }
    v
}

pub fn run(args: &[String]) -> ExitCode {
    let o = match parse(args) {
        Ok(o) => o,
        Err(m) => {
            eprintln!("{USAGE}");
            return fail(2, "usage", m);
        }
    };
    let p = &o.paths;
    let input = Input { stdin: o.stdin };
    let _g = match auth::lock_auth(p) {
        Ok(g) => g,
        Err(m) => return fail(6, "busy", m),
    };
    let now = auth::now();
    match o.cmd.as_str() {
        "init" => {
            let prev = match auth::load_state(p) {
                Ok(s) => s,
                Err(m) if o.force => {
                    eprintln!("auth.json повреждён и будет заменён: {m}");
                    None
                }
                Err(m) => return fail(2, "auth_state_corrupt", m),
            };
            if prev.is_some() && !o.force {
                return fail(3, "already_configured", "вход уже настроен; для восстановления: reset-password, reset-totp, recovery-codes или init --force");
            }
            let pw = match input.new_password() {
                Ok(p) => p,
                Err(m) => return fail(2, "password_rejected", m),
            };
            let hash = match auth::hash_password(&pw, o.kdf) {
                Ok(h) => h,
                Err(m) => return fail(2, "kdf_failed", m),
            };
            let (plain, stored) = auth::new_recovery_codes();
            let st = AuthState {
                version: 1,
                password_hash: hash,
                totp_secret_b32: auth::new_totp_secret(),
                totp_enrolled: false,
                totp_last_step: 0,
                last_good_time: prev.as_ref().map_or(0, |s| s.last_good_time),
                recovery: stored,
                sessions_epoch: prev.as_ref().map_or(0, |s| s.sessions_epoch + 1),
            };
            if let Err(m) = auth::save_state(p, &st) {
                return fail(2, "write_failed", m);
            }
            revoke_files(p);
            auth::reset_attempts(p);
            out(0, enrollment(&st, &o.label, Some(&plain)))
        }
        "confirm" => {
            let mut st = match load(p) {
                Ok(s) => s,
                Err(c) => return c,
            };
            if !clock_trusted(now, st.last_good_time) {
                return fail(2, "clock_untrusted", "часы роутера не синхронизированы; дождитесь NTP и повторите");
            }
            let code = match input.read("Код из приложения: ") {
                Ok(c) => c,
                Err(m) => return fail(2, "input", m),
            };
            match auth::totp_match(&st.totp_secret_b32, code.trim(), now) {
                Some(step) if step > st.totp_last_step => {
                    st.totp_enrolled = true;
                    st.totp_last_step = step;
                    st.last_good_time = st.last_good_time.max(now);
                    if let Err(m) = auth::save_state(p, &st) {
                        return fail(2, "write_failed", m);
                    }
                    out(0, json!({ "ok": true, "enrolled": true }))
                }
                _ => fail(1, "invalid_code", "код не подошёл; проверьте время на телефоне и роутере"),
            }
        }
        "reset-password" => {
            let mut st = match load(p) {
                Ok(s) => s,
                Err(c) => return c,
            };
            let pw = match input.new_password() {
                Ok(p) => p,
                Err(m) => return fail(2, "password_rejected", m),
            };
            st.password_hash = match auth::hash_password(&pw, o.kdf) {
                Ok(h) => h,
                Err(m) => return fail(2, "kdf_failed", m),
            };
            st.sessions_epoch += 1;
            if let Err(m) = auth::save_state(p, &st) {
                return fail(2, "write_failed", m);
            }
            revoke_files(p);
            auth::reset_attempts(p);
            out(0, json!({ "ok": true, "sessions_revoked": true }))
        }
        "reset-totp" => {
            let mut st = match load(p) {
                Ok(s) => s,
                Err(c) => return c,
            };
            st.totp_secret_b32 = auth::new_totp_secret();
            st.totp_enrolled = false;
            st.totp_last_step = 0;
            st.sessions_epoch += 1;
            if let Err(m) = auth::save_state(p, &st) {
                return fail(2, "write_failed", m);
            }
            revoke_files(p);
            out(0, enrollment(&st, &o.label, None))
        }
        "recovery-codes" => {
            let mut st = match load(p) {
                Ok(s) => s,
                Err(c) => return c,
            };
            let (plain, stored) = auth::new_recovery_codes();
            st.recovery = stored;
            if let Err(m) = auth::save_state(p, &st) {
                return fail(2, "write_failed", m);
            }
            out(0, json!({ "ok": true, "recovery_codes": plain, "notice": "прежние коды больше не действуют" }))
        }
        "unlock" => {
            auth::reset_attempts(p);
            out(0, json!({ "ok": true }))
        }
        "revoke-sessions" => {
            let mut st = match load(p) {
                Ok(s) => s,
                Err(c) => return c,
            };
            st.sessions_epoch += 1;
            if let Err(m) = auth::save_state(p, &st) {
                return fail(2, "write_failed", m);
            }
            revoke_files(p);
            out(0, json!({ "ok": true, "sessions_revoked": true }))
        }
        "status" => {
            let st = match auth::load_state(p) {
                Ok(s) => s,
                Err(m) => return fail(2, "auth_state_corrupt", m),
            };
            let a = auth::load_attempts(p);
            let Some(st) = st else {
                return out(1, json!({ "ok": false, "configured": false, "auth_dir": p.auth_dir }));
            };
            let kdf = st.password_hash.split('$').nth(3).unwrap_or_default().to_string();
            #[cfg(unix)]
            let perms = {
                use std::os::unix::fs::PermissionsExt;
                let m = |f: &std::path::Path| std::fs::metadata(f).map(|m| format!("{:o}", m.permissions().mode() & 0o777)).unwrap_or_default();
                json!({ "auth_dir": m(&p.auth_dir), "auth_json": m(&p.state()) })
            };
            #[cfg(not(unix))]
            let perms = serde_json::Value::Null;
            out(
                if st.totp_enrolled { 0 } else { 1 },
                json!({ "ok": st.totp_enrolled, "configured": true, "enrolled": st.totp_enrolled, "kdf": format!("argon2id {kdf}"),
                    "recovery_codes_left": st.recovery.iter().filter(|r| !r.used).count(),
                    "clock": { "now": now, "last_good_time": st.last_good_time, "trusted": clock_trusted(now, st.last_good_time) },
                    "attempts": { "fails": a.fails, "locked_until": a.locked_until }, "sessions_epoch": st.sessions_epoch,
                    "auth_dir": p.auth_dir, "session_dir": p.session_dir, "permissions": perms }),
            )
        }
        x => {
            eprintln!("{USAGE}");
            fail(2, "usage", format!("неизвестная подкоманда auth {x}"))
        }
    }
}
