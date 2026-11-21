//! Уведомления в Telegram через настоящий CGI после пароля и TOTP: токен только записывается (API его не отдаёт),
//! проверка формата, смена событий без повторного ввода токена, заявка на пробное сообщение, выключение,
//! сохранность при записи паролей профиля и `mi-tt-ctl notify-conf` для службы.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::*;

const TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"; // secret-scan: allow тестовый токен
const PW: &str = "profile-pass"; // secret-scan: allow тестовый пароль

#[test]
fn notify_settings_roundtrip() {
    let mut a = Auth::new("notify");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("nt-{}", rand_hex(6)));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(fixture("lab/config.json"), dir.join("config.json")).unwrap();
    a.config = dir.join("config.json").to_string_lossy().into_owned();
    let t = T0 + 60;
    let s = a.login(t);
    let post = |p: &str, b: Value| a.api(&s, "POST", p, Some(b.to_string().as_bytes()), t + 1);
    let get = |p: &str| a.api(&s, "GET", p, None, t + 1);

    assert_eq!(get("/notify").body["configured"], false);
    assert_eq!(post("/notify/test", json!({})).code(), "not_configured");
    assert_eq!(post("/notify", json!({ "chat_id": "123" })).code(), "bad_notify", "без токена");
    assert_eq!(post("/notify", json!({ "telegram_token": "nope", "chat_id": "123" })).code(), "bad_notify"); // secret-scan: allow неверный формат токена
    assert_eq!(post("/notify", json!({ "telegram_token": TOKEN, "chat_id": "abc" })).code(), "bad_notify");
    assert_eq!(post("/notify", json!({ "telegram_token": TOKEN, "chat_id": "123", "events": ["weather"] })).code(), "bad_notify");

    let o = post("/notify", json!({ "telegram_token": TOKEN, "chat_id": "-1001234567890", "events": ["tunnel", "update"], "lang": "en" }));
    assert_eq!(o.status, 200, "{}", o.body);
    let g = get("/notify");
    assert_eq!((g.body["configured"].as_bool(), g.body["chat_id"].as_str()), (Some(true), Some("-1001234567890")));
    assert_eq!(g.body["events"], json!(["tunnel", "update"]));
    assert!(!g.body.to_string().contains(TOKEN), "токен не отдаётся");

    // события меняются без токена; пароль профиля не стирает уведомления
    assert_eq!(post("/notify", json!({ "chat_id": "-1001234567890", "events": ["failover"], "lang": "en" })).status, 200);
    let pid = {
        let c: Value = serde_json::from_slice(&std::fs::read(dir.join("config.json")).unwrap()).unwrap();
        c["profiles"][0]["id"].as_str().unwrap().to_string()
    };
    assert_eq!(post("/secrets", json!({ "profile_id": pid, "secret": { "password": PW } })).status, 200);
    let sec = std::fs::read_to_string(dir.join("secrets.json")).unwrap();
    assert!(sec.contains(TOKEN) && sec.contains(PW));

    // параметры для службы
    let out = Command::new(ctl()).args(["notify-conf", &dir.join("secrets.json").to_string_lossy()]).output().unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("token={TOKEN}\nchat=-1001234567890\nevents=failover\nlang=en\n"));

    // пробное сообщение — заявка службе
    assert_eq!(post("/notify/test", json!({})).status, 202);
    assert!(a.session_dir.with_file_name("run").join("notify-test.request").exists());
    assert_eq!(get("/notify").body["test_pending"], true);

    assert_eq!(post("/notify", json!({ "disable": true })).status, 200);
    assert_eq!(get("/notify").body["configured"], false);
    assert!(!std::fs::read_to_string(dir.join("secrets.json")).unwrap().contains(TOKEN));
    let out = Command::new(ctl()).args(["notify-conf", &dir.join("secrets.json").to_string_lossy()]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
}
