//! Уведомления в Telegram. Токен бота и чат хранятся в `secrets.json` (поле `notify`): API их не отдаёт, только
//! признак «настроено», чат и выбранные события. Отправляет служба (mitt-notify.sh): через туннель, если он поднят,
//! иначе напрямую; неотправленное — повтор позже. Параметры для неё печатает `mi-tt-ctl notify-conf`.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{Response, parse_json, read_limited};
use crate::manage::{bad, run_dir, secrets_path};
use crate::render::Secrets;
use crate::store;

/// События: туннель упал или поднялся (и перезапуск клиента сторожем), переключение серверов, обновления пакета,
/// подписка TrustTunnel, запуск службы после перезагрузки роутера.
pub const EVENTS: &[&str] = &["tunnel", "failover", "update", "subscription", "boot"];
pub const LANGS: &[&str] = &["ru", "en", "zh"];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NotifySecret {
    pub telegram_token: String,
    pub chat_id: String,
    #[serde(default)]
    pub events: Vec<String>,
    /// Язык сообщений — язык панели при сохранении.
    #[serde(default = "ru")]
    pub lang: String,
}

fn ru() -> String {
    "ru".into()
}

/// Токен бота: `<число>:<35 знаков [A-Za-z0-9_-]>` (формат @BotFather; длину второй части не фиксируем строго).
pub fn check_token(t: &str) -> Result<(), &'static str> {
    let (id, key) = t.split_once(':').ok_or("токен бота — вида 123456789:AA… (выдаёт @BotFather)")?;
    if id.is_empty() || id.len() > 16 || !id.bytes().all(|b| b.is_ascii_digit()) || key.len() < 20 || key.len() > 80
        || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("токен бота — вида 123456789:AA… (выдаёт @BotFather)");
    }
    Ok(())
}

/// Чат: числовой id (у групп со знаком минус) или @имя канала.
pub fn check_chat(c: &str) -> Result<(), &'static str> {
    let num = c.strip_prefix('-').unwrap_or(c);
    let ok_num = !num.is_empty() && num.len() <= 20 && num.bytes().all(|b| b.is_ascii_digit());
    let ok_name = c.strip_prefix('@').is_some_and(|n| (5..=32).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    if ok_num || ok_name { Ok(()) } else { Err("чат — числовой id (например 123456789) или @имя_канала") }
}

pub fn check(n: &NotifySecret) -> Result<(), String> {
    check_token(&n.telegram_token)?;
    check_chat(&n.chat_id)?;
    if let Some(e) = n.events.iter().find(|e| !EVENTS.contains(&e.as_str())) {
        return Err(format!("неизвестное событие «{e}»"));
    }
    if !LANGS.contains(&n.lang.as_str()) {
        return Err("язык сообщений — ru, en или zh".into());
    }
    Ok(())
}

/// Строки для mitt-notify.sh (`ключ=значение`); None — уведомления не настроены.
pub fn conf_lines(s: &Secrets) -> Option<String> {
    let n = s.notify.as_ref()?;
    check(n).ok()?;
    Some(format!("token={}\nchat={}\nevents={}\nlang={}\n", n.telegram_token, n.chat_id, n.events.join(","), n.lang))
}

fn load(p: &std::path::Path) -> Result<Secrets, Response> {
    if !p.exists() {
        return Ok(Secrets { version: 1, profiles: Default::default(), notify: None });
    }
    let b = read_limited(&p.to_string_lossy(), 256 * 1024).map_err(|m| Response::error(500, "unreadable", m))?;
    parse_json(&b, "secrets").map_err(|_| Response::error(409, "secrets_invalid", "secrets.json не разобран; исправьте его на роутере"))
}

fn last_result() -> Value {
    std::fs::read(run_dir().join("notify.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
}

pub fn get(config_path: &str) -> Response {
    let s = match load(&secrets_path(config_path)) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let n = s.notify.as_ref();
    Response {
        status: 200,
        body: json!({ "ok": true, "configured": n.is_some(), "chat_id": n.map(|n| n.chat_id.clone()), "events": n.map(|n| n.events.clone()).unwrap_or_default(),
            "lang": n.map(|n| n.lang.clone()), "last": last_result(), "test_pending": run_dir().join("notify-test.request").exists(), "issues": [] }),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetReq {
    /// Пусто или нет поля — прежний токен.
    #[serde(default)]
    telegram_token: Option<String>,
    #[serde(default)]
    chat_id: Option<String>,
    #[serde(default)]
    events: Vec<String>,
    #[serde(default)]
    lang: Option<String>,
    /// Выключить уведомления (токен и чат удаляются).
    #[serde(default)]
    disable: bool,
}

pub fn set(body: &[u8], config_path: &str) -> Response {
    let q = match parse_json::<SetReq>(body, "") {
        Ok(q) => q,
        Err(i) => return bad(i),
    };
    let sp = secrets_path(config_path);
    let _g = match store::lock(&sp) {
        Ok(g) => g,
        Err(m) => return Response::error(503, "busy", m),
    };
    let mut s = match load(&sp) {
        Ok(s) => s,
        Err(r) => return r,
    };
    if q.disable {
        s.notify = None;
    } else {
        let token = match q.telegram_token.filter(|t| !t.trim().is_empty()).map(|t| t.trim().to_string()) {
            Some(t) => t,
            None => match s.notify.as_ref() {
                Some(n) => n.telegram_token.clone(),
                None => return Response::error(422, "bad_notify", "нужен токен бота"),
            },
        };
        let n = NotifySecret {
            telegram_token: token,
            chat_id: q.chat_id.unwrap_or_default().trim().to_string(),
            events: q.events,
            lang: q.lang.unwrap_or_else(ru),
        };
        if let Err(m) = check(&n) {
            return Response::error(422, "bad_notify", m);
        }
        s.notify = Some(n);
    }
    let mut out = serde_json::to_vec_pretty(&s).unwrap_or_default();
    out.push(b'\n');
    match store::write_atomic(&sp, &out) {
        Ok(()) => Response { status: 200, body: json!({ "ok": true, "configured": s.notify.is_some(), "issues": [] }) },
        Err(m) => Response::error(500, "write_failed", m),
    }
}

/// Пробное сообщение: заявку подхватывает служба (CGI сам в сеть не ходит).
pub fn test(config_path: &str) -> Response {
    match load(&secrets_path(config_path)) {
        Ok(s) if s.notify.is_some() => {}
        Ok(_) => return Response::error(409, "not_configured", "уведомления не настроены"),
        Err(r) => return r,
    }
    let d = run_dir();
    let req = json!({ "requested_unix": crate::auth::now() });
    match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| store::write_atomic(&d.join("notify-test.request"), req.to_string().as_bytes())) {
        Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "issues": [] }) },
        Err(m) => Response::error(500, "write_failed", m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_chat_formats() {
        assert!(check_token("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw").is_ok());
        for bad in ["", "123456789", "abc:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", "123:short", "123:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsa w"] {
            assert!(check_token(bad).is_err(), "{bad}");
        }
        for ok in ["123456789", "-1001234567890", "@my_channel"] {
            assert!(check_chat(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-", "@ab", "12a", "@bad-name"] {
            assert!(check_chat(bad).is_err(), "{bad}");
        }
    }
}
