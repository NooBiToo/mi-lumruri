//! Этап 6: вход в панель паролем (Argon2id) и вторым фактором (TOTP или одноразовый recovery-код).
//! Все проверки идут через настоящие бинарники: mi-tt-admin auth (настройка и восстановление) и mi-tt-ctl cgi.
//! Пароль и секрет TOTP — случайные на каждый прогон; время подменяется MI_TT_TEST_NOW (только отладочная сборка).

use std::path::PathBuf;

use serde_json::Value;

mod common;
use common::*;

fn preview_body() -> Vec<u8> {
    std::fs::read(fixture("request.tv-video-trusttunnel.json")).unwrap()
}

fn writable_config(a: &mut Auth, name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s6-{name}-{}", rand_hex(6)));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::copy(fixture("lab/config.json"), &cfg).unwrap();
    a.config = cfg.to_string_lossy().into_owned();
    cfg
}

fn save_body(rev: &str, rule_id: &str) -> Vec<u8> {
    format!(
        r#"{{"base_revision":"{rev}","rule":{{"id":"{rule_id}","source":{{"type":"device","id":"tv"}},"destination":{{"type":"group","id":"video"}},"action":{{"type":"profile","id":"tt-lab"}}}}}}"#
    )
    .into_bytes()
}

#[test]
fn normal_login_reaches_all_protected_api() {
    let mut a = Auth::new("normal");
    let t = T0 + 60;

    // до входа панель видит только этап «пароль»
    let o = a.cgi("GET", "/auth/session", None, t, &[]);
    assert_eq!((o.status, o.body["authenticated"].as_bool(), o.body["stage"].as_str()), (200, Some(false), Some("password")));

    let o = a.password_step(&a.password.clone(), t);
    assert_eq!(o.status, 200, "{}", o.body);
    assert_eq!(o.body["stage"], "second_factor");
    assert_eq!(o.body["clock_trusted"], true);
    let pre = o.cookie("__Host-mitt_pre").unwrap();
    let c = o.set_cookies()[0];
    for flag in ["Path=/", "Max-Age=300", "Secure", "HttpOnly", "SameSite=Strict"] {
        assert!(c.contains(flag), "{c}: нет {flag}");
    }
    let o = a.cgi("GET", "/auth/session", None, t, &[("HTTP_COOKIE", &format!("__Host-mitt_pre={pre}"))]);
    assert_eq!(o.body["stage"], "second_factor");

    let o = a.second_step(&pre, "totp", &a.totp(t), t);
    assert_eq!(o.status, 200, "{}", o.body);
    let full = o.cookie("__Host-mitt_sess").unwrap();
    assert_ne!(full, pre, "при входе выдаётся новый токен");
    assert_eq!(o.cookie("__Host-mitt_pre").as_deref(), Some(""), "cookie первого этапа стирается");
    let sc = o.set_cookies().into_iter().find(|c| c.starts_with("__Host-mitt_sess=")).unwrap().to_string();
    for flag in ["Path=/", "Max-Age=28800", "Secure", "HttpOnly", "SameSite=Strict"] {
        assert!(sc.contains(flag), "{sc}: нет {flag}");
    }
    assert!(!sc.contains("Domain"), "__Host- cookie без Domain");
    assert_eq!(o.body["recovery_codes_left"], 10);
    let s = Sess { cookie: format!("__Host-mitt_sess={full}"), csrf: o.body["csrf"].as_str().unwrap().into(), now: t };
    // предварительная сессия больше не действует
    assert_eq!(a.second_step(&pre, "totp", &a.totp(t + 30), t + 1).code(), "login_required");

    // все защищённые API: чтение, preview, запись
    let o = a.api(&s, "GET", "/config", None, t + 5);
    assert_eq!((o.status, o.body["ok"].as_bool()), (200, Some(true)), "{}", o.body);
    let o = a.api(&s, "POST", "/preview", Some(&preview_body()), t + 6);
    assert_eq!(o.status, 200, "{}", o.body);
    assert_eq!(o.body["preview"]["probes"][0]["changed"], true);
    let cfg = writable_config(&mut a, "normal");
    let rev = a.api(&s, "GET", "/config", None, t + 6).body["revision"].as_str().unwrap().to_string();
    let o = a.api(&s, "POST", "/rules", Some(&save_body(&rev, "r-s6")), t + 7);
    assert_eq!((o.status, o.body["ok"].as_bool()), (200, Some(true)), "{}", o.body);
    assert!(std::fs::read_to_string(&cfg).unwrap().contains("r-s6"));
    let o = a.cgi("GET", "/auth/session", None, t + 8, &[("HTTP_COOKIE", &s.cookie)]);
    assert_eq!((o.body["authenticated"].as_bool(), o.body["csrf"].as_str()), (Some(true), Some(s.csrf.as_str())));
    // неизвестные адреса после входа — 404, применения через CGI нет
    assert_eq!(a.api(&s, "POST", "/apply", Some(b"{}"), t + 9).status, 404);

    // секреты не хранятся открытым текстом
    let st = std::fs::read_to_string(a.auth_dir.join("auth.json")).unwrap();
    assert!(!st.contains(&a.password));
    assert!(st.contains("$argon2id$v=19$"));
    for c in &a.recovery {
        assert!(!st.contains(c.as_str()) && !st.contains(&c.replace('-', "")));
    }
    // токен сессии на диск не попадает: имя файла — SHA-256 токена
    for e in std::fs::read_dir(&a.session_dir).unwrap() {
        let e = e.unwrap();
        assert_ne!(e.file_name().to_string_lossy(), full);
        assert!(!std::fs::read_to_string(e.path()).unwrap().contains(&full));
    }
}

#[test]
fn direct_api_is_refused_before_both_factors() {
    // вход не настроен: защищённые адреса закрыты, а не открыты
    let mut e = Auth::empty("unconfigured");
    e.config = fixture("config.valid.json");
    assert_eq!(e.cgi("GET", "/config", None, T0, &[]).code(), "auth_not_configured");
    assert_eq!(e.password_step("anything-long-enough", T0).code(), "auth_not_configured");

    let mut a = Auth::new("direct");
    let cfg = writable_config(&mut a, "direct");
    let before = std::fs::read(&cfg).unwrap();
    let t = T0 + 90;
    let o = a.cgi("GET", "/config", None, t, &[]);
    assert_eq!((o.status, o.code()), (401, "auth_required"));
    assert!(o.body.get("config").is_none());
    let post = [("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "same-origin")];
    let fake = format!("__Host-mitt_sess={}", "a".repeat(64));
    for (path, body) in [("/preview", preview_body()), ("/rules", save_body("0".repeat(64).as_str(), "r-x"))] {
        assert_eq!(a.cgi("POST", path, Some(&body), t, &post).code(), "auth_required");
        assert_eq!(a.cgi("POST", path, Some(&body), t, &[post[0], post[1], ("HTTP_COOKIE", &fake), ("HTTP_X_MITT_CSRF", "x")]).code(), "auth_required");
    }
    // неверный пароль: нет cookie
    let o = a.password_step("wrong-password-123", t);
    assert_eq!((o.status, o.code()), (401, "invalid_credentials"));
    assert!(o.set_cookies().is_empty());
    // только пароль: предварительная сессия не открывает API ни под своим, ни под чужим именем
    let pre = a.pending(t);
    for cookie in [format!("__Host-mitt_pre={pre}"), format!("__Host-mitt_sess={pre}")] {
        assert_eq!(a.cgi("GET", "/config", None, t, &[("HTTP_COOKIE", &cookie)]).code(), "auth_required");
        let o = a.cgi("POST", "/rules", Some(&save_body("0".repeat(64).as_str(), "r-x")), t, &[post[0], post[1], ("HTTP_COOKIE", &cookie)]);
        assert_eq!(o.code(), "auth_required");
    }
    // второй фактор без пароля
    assert_eq!(a.second_step(&"b".repeat(64), "totp", &a.totp(t), t).code(), "login_required");
    // неверный код
    assert_eq!(a.second_step(&pre, "totp", "000000", t).code(), "invalid_code");
    assert_eq!(a.second_step(&pre, "recovery_code", "AAAA-BBBB-CCCC-DDDD", t).code(), "invalid_code");
    assert_eq!(std::fs::read(&cfg).unwrap(), before, "отклонённые запросы не меняют настройки");
}

#[test]
fn totp_replay_and_concurrent_use_admit_one() {
    let a = Auth::new("replay");
    let t1 = T0 + 300;
    a.login(t1);
    // тот же код повторно (новая предварительная сессия) — отказ
    let pre = a.pending(t1 + 5);
    assert_eq!(a.second_step(&pre, "totp", &a.totp(t1), t1 + 5).code(), "code_reused");
    // код предыдущего шага (ещё в окне ±1) — тоже отказ: шаги только растут
    assert_eq!(a.second_step(&pre, "totp", &a.totp(t1 - 30), t1 + 5).code(), "code_reused");
    let (code, _) = admin_auth(&a, &["unlock"], "", t1);
    assert_eq!(code, 0);

    // одновременные запросы с одним кодом из разных предварительных сессий: успешен ровно один
    let t2 = t1 + 600;
    let pres: Vec<String> = (0..5).map(|_| a.pending(t2)).collect();
    let code = a.totp(t2);
    let a = std::sync::Arc::new(a);
    let hs: Vec<_> = pres
        .into_iter()
        .map(|p| {
            let (a, code) = (a.clone(), code.clone());
            std::thread::spawn(move || {
                let o = a.second_step(&p, "totp", &code, t2);
                (o.status, o.code().to_string(), o.cookie("__Host-mitt_sess"))
            })
        })
        .collect();
    let res: Vec<_> = hs.into_iter().map(|h| h.join().unwrap()).collect();
    let ok: Vec<_> = res.iter().filter(|r| r.0 == 200).collect();
    assert_eq!(ok.len(), 1, "{res:?}");
    assert!(res.iter().filter(|r| r.0 != 200).all(|r| (r.0, r.1.as_str()) == (401, "code_reused")), "{res:?}");
    let s = Sess { cookie: format!("__Host-mitt_sess={}", ok[0].2.clone().unwrap()), csrf: String::new(), now: t2 };
    assert_eq!(a.api(&s, "GET", "/config", None, t2 + 1).status, 200);
}

#[test]
fn session_expiry_and_logout() {
    let a = Auth::new("expiry");
    // простой больше 30 минут
    let t = T0 + 1200;
    let s = a.login(t);
    assert_eq!(a.api(&s, "GET", "/config", None, t + SESSION_IDLE - 10).status, 200);
    let t_last = t + SESSION_IDLE - 10;
    assert_eq!(a.api(&s, "GET", "/config", None, t_last + SESSION_IDLE + 1).code(), "auth_required");
    assert_eq!(a.api(&s, "GET", "/config", None, t_last + 10).code(), "auth_required", "истёкшая сессия удалена");

    // абсолютный предел 8 часов при постоянной активности
    let t = T0 + 30 * 3600;
    let s = a.login(t);
    let mut now = t;
    while now + 1500 < t + SESSION_MAX {
        now += 1500;
        assert_eq!(a.api(&s, "GET", "/config", None, now).status, 200, "активная сессия в {now}");
    }
    assert_eq!(a.api(&s, "GET", "/config", None, t + SESSION_MAX).code(), "auth_required");

    // этап пароля живёт 5 минут
    let t = T0 + 60 * 3600;
    let pre = a.pending(t);
    assert_eq!(a.second_step(&pre, "totp", &a.totp(t + PENDING_TTL), t + PENDING_TTL).code(), "login_required");

    // часы ушли назад относительно момента создания сессии — сессия недействительна
    let t = T0 + 70 * 3600;
    let s = a.login(t);
    assert_eq!(a.api(&s, "GET", "/config", None, t - 3600).code(), "auth_required");

    // выход: нужен CSRF; после выхода cookie стёрты и сессия не действует
    let t = T0 + 80 * 3600;
    let s = a.login(t);
    let o = a.cgi("POST", "/auth/logout", Some(b"{}"), t + 1, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", &s.cookie)]);
    assert_eq!(o.code(), "csrf_failed");
    let o = a.cgi("POST", "/auth/logout", Some(b"{}"), t + 2, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", &s.cookie), ("HTTP_X_MITT_CSRF", &s.csrf)]);
    assert_eq!(o.status, 200);
    assert_eq!(o.cookie("__Host-mitt_sess").as_deref(), Some(""));
    assert!(o.set_cookies().iter().all(|c| c.contains("Max-Age=0")));
    assert_eq!(a.api(&s, "GET", "/config", None, t + 3).code(), "auth_required");
}

#[test]
fn csrf_origin_and_https_are_enforced() {
    let a = Auth::new("csrf");
    let t = T0 + 120;
    let s = a.login(t);
    let b = preview_body();
    let cookie = ("HTTP_COOKIE", s.cookie.as_str());
    let o = a.cgi("POST", "/preview", Some(&b), t, &[("HTTP_ORIGIN", ORIGIN), cookie]);
    assert_eq!((o.status, o.code()), (403, "csrf_failed"));
    let o = a.cgi("POST", "/preview", Some(&b), t, &[("HTTP_ORIGIN", ORIGIN), cookie, ("HTTP_X_MITT_CSRF", &"0".repeat(64))]);
    assert_eq!(o.code(), "csrf_failed");
    let o = a.cgi("POST", "/preview", Some(&b), t, &[("HTTP_ORIGIN", "https://evil.example"), cookie, ("HTTP_X_MITT_CSRF", &s.csrf)]);
    assert_eq!(o.code(), "origin_forbidden");
    let o = a.cgi("POST", "/preview", Some(&b), t, &[cookie, ("HTTP_X_MITT_CSRF", &s.csrf)]);
    assert_eq!(o.code(), "origin_required");
    let o = a.cgi("POST", "/preview", Some(&b), t, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "cross-site"), cookie, ("HTTP_X_MITT_CSRF", &s.csrf)]);
    assert_eq!(o.code(), "cross_site");
    assert_eq!(a.api(&s, "POST", "/preview", Some(&b), t).status, 200);

    // вход: только с допустимого Origin и только по HTTPS
    let body = format!(r#"{{"password":"{}"}}"#, a.password);
    let o = a.cgi("POST", "/auth/login", Some(body.as_bytes()), t, &[("HTTP_ORIGIN", "https://evil.example")]);
    assert_eq!(o.code(), "origin_forbidden");
    let mut env = a.env(t);
    env.retain(|(k, _)| k != "HTTPS");
    let o = cgi_raw(ctl(), "POST", "/auth/login", Some(body.as_bytes()), &env, &[("HTTP_ORIGIN", ORIGIN)]);
    assert_eq!(o.code(), "https_required");
    assert!(o.set_cookies().is_empty());
    // этап 12: за локальным TLS-терминатором (nginx) — только с MI_TT_TRUST_PROXY=1 и с loopback
    let px = [("HTTP_ORIGIN", ORIGIN), ("HTTP_X_FORWARDED_PROTO", "https"), ("REMOTE_ADDR", "127.0.0.1"), ("SERVER_ADDR", "127.0.0.1")];
    assert_eq!(cgi_raw(ctl(), "POST", "/auth/login", Some(body.as_bytes()), &env, &px).code(), "https_required", "без MI_TT_TRUST_PROXY заголовку не доверяем");
    let o = cgi_raw(ctl(), "POST", "/auth/login", Some(body.as_bytes()), &env, &[px[0], px[1], ("REMOTE_ADDR", "10.10.1.2"), px[3], ("MI_TT_TRUST_PROXY", "1")]);
    assert_eq!(o.code(), "https_required", "заголовок от клиента LAN (не loopback) не принимается");
    let o = cgi_raw(ctl(), "POST", "/auth/login", Some(body.as_bytes()), &env, &[px[0], px[1], px[2], ("SERVER_ADDR", "10.10.1.1"), ("MI_TT_TRUST_PROXY", "1")]);
    assert_eq!(o.code(), "https_required", "слушатель не на loopback (доступен из LAN) — не доверяем");
    let o = cgi_raw(ctl(), "POST", "/auth/login", Some(body.as_bytes()), &env, &[px[0], ("HTTP_X_FORWARDED_PROTO", "http"), px[2], px[3], ("MI_TT_TRUST_PROXY", "1")]);
    assert_eq!(o.code(), "https_required", "явный X-Forwarded-Proto: http — не HTTPS");
    // штатный uhttpd не передаёт X-Forwarded-Proto в CGI: признак — сам loopback-экземпляр с MI_TT_TRUST_PROXY=1
    let o = cgi_raw(ctl(), "POST", "/auth/login", Some(body.as_bytes()), &env, &[px[0], px[2], px[3], ("MI_TT_TRUST_PROXY", "1")]);
    assert_eq!(o.status, 200, "{}", o.body);
}

#[test]
fn lockout_after_failures() {
    let a = Auth::new("lockout");
    let t = T0 + 600;
    for i in 1..=5 {
        let o = a.password_step("not-the-password-1", t);
        if i < 5 {
            assert_eq!(o.code(), "invalid_credentials");
        } else {
            assert_eq!((o.status, o.code()), (429, "too_many_attempts"));
            assert!(o.head.contains("Retry-After: 30"), "{}", o.head);
        }
    }
    // во время блокировки не проверяется даже верный пароль
    assert_eq!(a.password_step(&a.password.clone(), t + 10).code(), "too_many_attempts");
    // ещё неудача после паузы — пауза удваивается
    let o = a.password_step("not-the-password-1", t + 31);
    assert!(o.head.contains("Retry-After: 60"), "{}", o.head);
    // администратор снимает блокировку локально
    let (code, _) = admin_auth(&a, &["unlock"], "", t + 40);
    assert_eq!(code, 0);
    a.login(t + 60);
    // счётчик сброшен успешным входом
    let (_, v) = admin_auth(&a, &["status"], "", t + 61);
    assert_eq!(v["attempts"]["fails"], 0);
    // перебор второго фактора тоже ограничен: 5 неверных кодов закрывают этап пароля
    let pre = a.pending(t + 90);
    for _ in 0..4 {
        assert_eq!(a.second_step(&pre, "totp", "000000", t + 91).code(), "invalid_code");
    }
    let o = a.second_step(&pre, "totp", "000000", t + 91);
    assert_eq!(o.code(), "too_many_attempts");
    assert_eq!(o.cookie("__Host-mitt_pre").as_deref(), Some(""));
    let (code, _) = admin_auth(&a, &["unlock"], "", t + 92);
    assert_eq!(code, 0);
    assert_eq!(a.second_step(&pre, "totp", &a.totp(t + 120), t + 120).code(), "login_required");
}

#[test]
fn cold_start_with_wrong_clock_uses_recovery_codes() {
    let a = Auth::new("clock");
    // роутер загрузился без NTP: часы в 1970 году
    let t = 1_000;
    let o = a.password_step(&a.password.clone(), t);
    assert_eq!((o.status, o.body["clock_trusted"].as_bool()), (200, Some(false)));
    let pre = o.cookie("__Host-mitt_pre").unwrap();
    let o = a.second_step(&pre, "totp", &a.totp(t), t);
    assert_eq!((o.status, o.code()), (409, "clock_untrusted"), "TOTP по неверным часам не принимается");
    let o = a.second_step(&pre, "recovery_code", &a.recovery[0].to_lowercase(), t);
    assert_eq!(o.status, 200, "{}", o.body);
    assert_eq!(o.body["recovery_codes_left"], 9);
    assert_eq!(o.body["clock_trusted"], false);
    let s = Sess { cookie: format!("__Host-mitt_sess={}", o.cookie("__Host-mitt_sess").unwrap()), csrf: o.body["csrf"].as_str().unwrap().into(), now: t };
    assert_eq!(a.api(&s, "GET", "/config", None, t + 1).status, 200);
    // recovery-код одноразовый
    let pre = a.pending(t + 2);
    assert_eq!(a.second_step(&pre, "recovery_code", &a.recovery[0], t + 2).code(), "invalid_code");
    // часы после последнего достоверного входа ушли назад (но позже нижней границы) — тоже недоверие
    a.login(T0 + 7200);
    let pre = a.pending(T0 + 3600);
    assert_eq!(a.second_step(&pre, "totp", &a.totp(T0 + 3600), T0 + 3600).code(), "clock_untrusted");
    // после синхронизации часов TOTP снова работает
    a.login(T0 + 7300);
}

#[test]
fn restart_and_local_recovery() {
    let mut a = Auth::new("recovery");
    let t = T0 + 900;
    let s = a.login(t);
    // перезагрузка роутера: сессии в RAM пропали, настройки входа на /data остались
    std::fs::remove_dir_all(&a.session_dir).unwrap();
    assert_eq!(a.api(&s, "GET", "/config", None, t + 10).code(), "auth_required");
    let s = a.login(t + 30);
    assert_eq!(a.api(&s, "GET", "/config", None, t + 31).status, 200);

    // повторная настройка без --force запрещена
    let (code, v) = admin_auth(&a, &["init", "--stdin"], "x\nx\n", t + 40);
    assert_eq!((code, v["error"]["code"].as_str()), (3, Some("already_configured")));
    // секреты аргументами не принимаются
    for arg in ["--password", "--code", "--totp"] {
        let (code, v) = admin_auth(&a, &["reset-password", arg, "secret-in-argv-1"], "", t + 40);
        assert_eq!((code, v["error"]["code"].as_str()), (2, Some("usage")));
    }
    // политика и подтверждение пароля
    let (code, _) = admin_auth(&a, &["reset-password", "--stdin"], "short\nshort\n", t + 40);
    assert_eq!(code, 2);
    let (code, _) = admin_auth(&a, &["reset-password", "--stdin"], "long-enough-pass-1\nlong-enough-pass-2\n", t + 40);
    assert_eq!(code, 2);

    // сброс пароля: старый не подходит, сессии отозваны
    let old = a.password.clone();
    a.password = format!("pw-{}", rand_hex(24));
    let (code, v) = admin_auth(&a, &["reset-password", "--stdin", "--kdf-m", "8192", "--kdf-t", "1"], &format!("{0}\n{0}\n", a.password), t + 50);
    assert_eq!(code, 0, "{v}");
    assert_eq!(a.api(&s, "GET", "/config", None, t + 51).code(), "auth_required");
    assert_eq!(a.password_step(&old, t + 52).code(), "invalid_credentials");
    let s = a.login(t + 60);

    // новый секрет TOTP: до подтверждения вход закрыт, после — старый секрет не работает
    let old_secret = a.secret.clone();
    let (code, v) = admin_auth(&a, &["reset-totp"], "", t + 70);
    assert_eq!(code, 0, "{v}");
    a.secret = v["totp_secret_base32"].as_str().unwrap().into();
    assert!(v["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/"));
    assert_eq!(a.api(&s, "GET", "/config", None, t + 71).code(), "auth_not_configured");
    let (code, _) = admin_auth(&a, &["confirm", "--stdin"], "000000\n", t + 90);
    assert_eq!(code, 1);
    let (code, _) = admin_auth(&a, &["confirm", "--stdin"], &format!("{}\n", a.totp(t + 90)), t + 90);
    assert_eq!(code, 0);
    let pre = a.pending(t + 120);
    let old_code = totp_at(&old_secret, t + 120).unwrap();
    if old_code != a.totp(t + 120) {
        assert_eq!(a.second_step(&pre, "totp", &old_code, t + 120).code(), "invalid_code");
    }
    let (code, _) = admin_auth(&a, &["unlock"], "", t + 121);
    assert_eq!(code, 0);
    a.login(t + 150);

    // новые recovery-коды заменяют старые
    let (code, v) = admin_auth(&a, &["recovery-codes"], "", t + 160);
    assert_eq!(code, 0);
    let fresh: Vec<String> = v["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().into()).collect();
    let pre = a.pending(t + 170);
    assert_eq!(a.second_step(&pre, "recovery_code", &a.recovery[1], t + 170).code(), "invalid_code");
    assert_eq!(a.second_step(&pre, "recovery_code", &fresh[0], t + 170).status, 200);

    // явный отзыв всех сессий
    let s = a.login(t + 180);
    let (code, _) = admin_auth(&a, &["revoke-sessions"], "", t + 181);
    assert_eq!(code, 0);
    assert_eq!(a.api(&s, "GET", "/config", None, t + 182).code(), "auth_required");

    // статус без секретов
    let (code, v) = admin_auth(&a, &["status"], "", t + 190);
    assert_eq!(code, 0);
    let text = v.to_string();
    assert!(!text.contains(&a.secret) && !text.contains(&a.password) && !text.contains("$argon2id$"));
    assert_eq!(v["recovery_codes_left"], 9);
    assert_eq!(v["kdf"], "argon2id m=8192,t=1,p=1");

    // административный CLI не запускается из CGI
    let o = std::process::Command::new(admin()).args(["auth", "status"]).env("GATEWAY_INTERFACE", "CGI/1.1").output().unwrap();
    assert_eq!(o.status.code(), Some(77));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["error"]["code"], "cgi_forbidden");
}
