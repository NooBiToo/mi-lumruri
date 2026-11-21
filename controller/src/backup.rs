//! Резервная копия настроек (панель: «Скачать копию» / «Восстановить»).
//!
//! Копия — JSON: настройки (`config.json`) и свои списки категорий (`categories/<id>.list`). По желанию — секреты:
//! `secrets.json` (пароли серверов, ссылки-подписки) и `auth/auth.json` (вход в панель). Они шифруются паролем,
//! который пользователь задаёт при скачивании: ключ — Argon2id (соль и параметры в копии), шифр — ChaCha20-Poly1305.
//! Ключ TLS панели и ключ подписи релизов в копию не входят: они принадлежат конкретному роутеру.
//!
//! Восстановление проверяет всё до записи: формат, настройки (как при сохранении из панели, с ревизией), списки,
//! секреты; затем пишет настройки, списки, секреты и ставит заявку на применение.

use std::collections::BTreeMap;
use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{MAX_CONFIG_BYTES, Response, parse_json, read_limited};
use crate::manage::{MAX_LIST_BODY, bad, category_list, config_dir, queue_apply, read_config, saved, secrets_path};
use crate::model::Config;
use crate::render::Secrets;
use crate::store::{self, SaveError};

pub const FORMAT: &str = "mi-lumruri-backup";
pub const VERSION: u32 = 1;
const AAD: &[u8] = b"mi-lumruri-backup v1";
/// Пределы параметров Argon2id из чужого файла: не дать копии занять память и процессор роутера.
const MAX_KDF_M_KIB: u32 = 64 * 1024;
const MAX_KDF_T: u32 = 8;
pub const MIN_PASSPHRASE: usize = 8;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub format: String,
    pub version: u32,
    pub created: u64,
    pub config: Value,
    #[serde(default)]
    pub lists: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Sealed>,
}

/// Зашифрованная часть: Argon2id(пароль, соль) → ключ ChaCha20-Poly1305.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub kdf: String,
    pub m_kib: u32,
    pub t: u32,
    pub salt: String,
    pub nonce: String,
    pub data: String,
}

/// Содержимое зашифрованной части: файлы как есть (текст JSON).
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretFiles {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secrets: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth: Option<String>,
}

fn derive(pass: &str, salt: &[u8], m_kib: u32, t: u32) -> Result<[u8; 32], String> {
    let params = Params::new(m_kib, t, 1, Some(32)).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(pass.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn seal(plain: &[u8], pass: &str) -> Result<Sealed, String> {
    let k = crate::auth::KdfParams::default();
    let salt = crate::auth::random_bytes::<16>();
    let nonce = crate::auth::random_bytes::<12>();
    let key = derive(pass, &salt, k.m_kib, k.t)?;
    let data = ChaCha20Poly1305::new(&key.into()).encrypt(&nonce.into(), Payload { msg: plain, aad: AAD }).map_err(|_| "шифрование не удалось".to_string())?;
    Ok(Sealed { kdf: "argon2id".into(), m_kib: k.m_kib, t: k.t, salt: BASE64.encode(&salt), nonce: BASE64.encode(&nonce), data: BASE64.encode(&data) })
}

/// `Err(true)` — пароль не подошёл (или копия изменена), `Err(false)` — повреждённая или чужая копия.
pub fn open(s: &Sealed, pass: &str) -> Result<Vec<u8>, bool> {
    if s.kdf != "argon2id" || s.m_kib > MAX_KDF_M_KIB || s.t == 0 || s.t > MAX_KDF_T {
        return Err(false);
    }
    let salt = BASE64.decode(s.salt.as_bytes()).map_err(|_| false)?;
    let nonce: [u8; 12] = BASE64.decode(s.nonce.as_bytes()).ok().and_then(|n| n.try_into().ok()).ok_or(false)?;
    let data = BASE64.decode(s.data.as_bytes()).map_err(|_| false)?;
    let key = derive(pass, &salt, s.m_kib, s.t).map_err(|_| false)?;
    ChaCha20Poly1305::new(&key.into()).decrypt(&nonce.into(), Payload { msg: &data, aad: AAD }).map_err(|_| true)
}

fn read_text(p: &Path, max: u64) -> Option<String> {
    if !p.exists() {
        return None;
    }
    read_limited(&p.to_string_lossy(), max).ok().and_then(|b| String::from_utf8(b).ok())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportReq {
    #[serde(default)]
    secrets: bool,
    #[serde(default)]
    passphrase: Option<String>,
}

pub fn export(body: &[u8], config_path: &str) -> Response {
    let q = match parse_json::<ExportReq>(body, "") {
        Ok(q) => q,
        Err(i) => return bad(i),
    };
    let cfg = match read_config(config_path) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let config: Value = match read_limited(config_path, MAX_CONFIG_BYTES).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
        Some(v) => v,
        None => return Response::error(500, "unreadable", "настройки не прочитаны"),
    };
    let dir = config_dir(config_path).join("categories");
    let lists: BTreeMap<String, String> =
        cfg.categories.iter().filter_map(|c| read_text(&dir.join(format!("{}.list", c.id)), MAX_LIST_BODY as u64).map(|t| (c.id.clone(), t))).collect();
    let secrets = if q.secrets {
        let pass = q.passphrase.unwrap_or_default();
        if pass.chars().count() < MIN_PASSPHRASE {
            return Response::error(422, "passphrase_short", format!("пароль копии — не короче {MIN_PASSPHRASE} символов"));
        }
        let files = SecretFiles {
            secrets: read_text(&secrets_path(config_path), 256 * 1024),
            auth: read_text(&crate::auth::Paths::from_env().state(), 64 * 1024),
        };
        match serde_json::to_vec(&files).map_err(|e| e.to_string()).and_then(|p| seal(&p, &pass)) {
            Ok(s) => Some(s),
            Err(m) => return Response::error(500, "seal_failed", m),
        }
    } else {
        None
    };
    let b = Backup { format: FORMAT.into(), version: VERSION, created: crate::auth::now(), config, lists, secrets };
    Response { status: 200, body: json!({ "ok": true, "backup": b, "issues": [] }) }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreReq {
    base_revision: String,
    backup: Backup,
    #[serde(default)]
    passphrase: Option<String>,
    /// Копия с секретами, но пароль копии неизвестен: восстановить без них.
    #[serde(default)]
    skip_secrets: bool,
}

pub fn restore(body: &[u8], config_path: &str) -> Response {
    let q = match parse_json::<RestoreReq>(body, "") {
        Ok(q) => q,
        Err(i) => return Response::error(422, "backup_invalid", format!("файл не похож на копию настроек Mi Lumruri ({} замечаний)", i.len())),
    };
    let b = q.backup;
    if b.format != FORMAT {
        return Response::error(422, "backup_invalid", "файл не похож на копию настроек Mi Lumruri");
    }
    if b.version > VERSION {
        return Response::error(422, "backup_newer", "копия сделана более новой версией — обновите пакет и повторите");
    }
    // секреты: расшифровать и проверить до любой записи
    let mut files = SecretFiles::default();
    if let (Some(s), false) = (&b.secrets, q.skip_secrets) {
        let Some(pass) = q.passphrase.as_deref().filter(|p| !p.is_empty()) else {
            return Response::error(422, "passphrase_required", "копия содержит пароли — введите пароль копии");
        };
        let plain = match open(s, pass) {
            Ok(p) => p,
            Err(true) => return Response::error(422, "passphrase_wrong", "пароль копии не подошёл"),
            Err(false) => return Response::error(422, "backup_invalid", "зашифрованная часть копии повреждена"),
        };
        files = match serde_json::from_slice(&plain) {
            Ok(f) => f,
            Err(_) => return Response::error(422, "backup_invalid", "зашифрованная часть копии повреждена"),
        };
        if files.secrets.as_deref().is_some_and(|t| parse_json::<Secrets>(t.as_bytes(), "secrets").is_err()) {
            return Response::error(422, "backup_invalid", "пароли серверов в копии не разобраны");
        }
        if files.auth.as_deref().is_some_and(|t| serde_json::from_str::<crate::auth::AuthState>(t).is_err()) {
            return Response::error(422, "backup_invalid", "данные входа в панель в копии не разобраны");
        }
    }
    let cfg: Config = match parse_json(b.config.to_string().as_bytes(), "config") {
        Ok(c) => c,
        Err(i) => return Response { status: 422, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки в копии не прошли проверку; ничего не записано" }, "issues": i }) },
    };
    // свои списки — только для категорий из копии; проверка списка — при записи (category_list)
    let unknown: Vec<&String> = b.lists.keys().filter(|id| !cfg.categories.iter().any(|c| &c.id == *id)).collect();
    let r = match store::replace_config(Path::new(config_path), &q.base_revision, MAX_CONFIG_BYTES, &cfg) {
        Err(SaveError::RuleInvalid(i)) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки в копии не прошли проверку; ничего не записано" }, "issues": i }) },
        r => saved(r, "config"),
    };
    if r.status != 200 {
        return r;
    }
    let mut warnings: Vec<String> = unknown.iter().map(|id| format!("список «{id}» пропущен: такой категории нет в настройках")).collect();
    let mut lists = 0;
    for (id, text) in b.lists.iter().filter(|(id, _)| !unknown.contains(id)) {
        let lr = category_list(config_path, id, text);
        if lr.status == 200 {
            lists += 1;
        } else {
            warnings.push(format!("список «{id}» не восстановлен: {}", lr.body["error"]["message"].as_str().unwrap_or("ошибка")));
        }
    }
    let mut secrets = false;
    if let Some(t) = &files.secrets {
        let sp = secrets_path(config_path);
        match store::lock(&sp).and_then(|_g| store::write_atomic(&sp, t.as_bytes())) {
            Ok(()) => secrets = true,
            Err(m) => warnings.push(format!("пароли серверов не записаны: {m}")),
        }
    }
    let mut auth = false;
    if let Some(t) = &files.auth {
        let p = crate::auth::Paths::from_env();
        let res = serde_json::from_str::<crate::auth::AuthState>(t).map_err(|e| e.to_string()).and_then(|s| {
            let _g = crate::auth::lock_auth(&p)?;
            crate::auth::save_state(&p, &s)
        });
        match res {
            Ok(()) => auth = true,
            Err(m) => warnings.push(format!("вход в панель не восстановлен: {m}")),
        }
    }
    if let Err(m) = queue_apply(config_path) {
        warnings.push(format!("настройки восстановлены, но заявка на применение не записана: {m}"));
    }
    Response {
        status: 200,
        body: json!({ "ok": true, "revision": r.body["revision"], "restored": { "config": true, "lists": lists, "secrets": secrets, "auth": auth },
            "secrets_skipped": b.secrets.is_some() && q.skip_secrets, "warnings": warnings, "issues": [] }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip_wrong_pass_and_tamper() {
        let s = seal(b"{\"secrets\":\"x\"}", "correct horse").unwrap();
        assert_eq!(open(&s, "correct horse").unwrap(), b"{\"secrets\":\"x\"}");
        assert_eq!(open(&s, "wrong horse!").unwrap_err(), true);
        let mut t = Sealed { data: s.data.clone(), ..s };
        let mut raw = BASE64.decode(t.data.as_bytes()).unwrap();
        raw[0] ^= 1;
        t.data = BASE64.encode(&raw);
        assert_eq!(open(&t, "correct horse").unwrap_err(), true);
        // параметры KDF из чужого файла ограничены
        let huge = Sealed { m_kib: 1 << 20, ..t };
        assert_eq!(open(&huge, "correct horse").unwrap_err(), false);
    }
}
