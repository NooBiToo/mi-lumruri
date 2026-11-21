//! Резервная копия настроек через настоящий CGI после пароля и TOTP: скачать (без секретов и с секретами под паролем),
//! восстановить — проверка до записи, ревизия, пароль копии, списки категорий, секреты, заявка на применение.

use std::path::PathBuf;

use serde_json::{Value, json};

mod common;
use common::*;

const PW1: &str = "original-pass"; // secret-scan: allow тестовое значение
const PW2: &str = "changed-pass"; // secret-scan: allow тестовое значение
const PW3: &str = "third-pass"; // secret-scan: allow тестовое значение
const BK: &str = "backup-pass-1"; // secret-scan: allow тестовое значение
const BK_SHORT: &str = "short"; // secret-scan: allow тестовое значение
const BK_WRONG: &str = "nope-nope"; // secret-scan: allow тестовое значение

struct Panel {
    a: Auth,
    s: Sess,
    t: u64,
    dir: PathBuf,
}

impl Panel {
    fn new(name: &str) -> Panel {
        let mut a = Auth::new(name);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("bk-{name}-{}", rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(fixture("lab/config.json"), dir.join("config.json")).unwrap();
        a.config = dir.join("config.json").to_string_lossy().into_owned();
        let t = T0 + 60;
        let s = a.login(t);
        Panel { a, s, t, dir }
    }
    fn rev(&self) -> String {
        self.a.api(&self.s, "GET", "/config", None, self.t).body["revision"].as_str().unwrap().to_string()
    }
    fn post(&self, path: &str, body: Value) -> Out {
        self.a.api(&self.s, "POST", path, Some(body.to_string().as_bytes()), self.t + 1)
    }
    fn secrets(&self) -> String {
        std::fs::read_to_string(self.dir.join("secrets.json")).unwrap_or_default()
    }
    fn has_category(&self, id: &str) -> bool {
        let c: Value = serde_json::from_slice(&std::fs::read(self.dir.join("config.json")).unwrap()).unwrap();
        c["categories"].as_array().is_some_and(|a| a.iter().any(|x| x["id"] == id))
    }
}

#[test]
fn export_and_restore_with_and_without_secrets() {
    let p = Panel::new("roundtrip");
    let cat = json!({ "id": "my-sites", "name": "Мои сайты", "kind": "domain" });
    assert_eq!(p.post("/categories", json!({ "base_revision": p.rev(), "category": cat })).status, 200);
    assert_eq!(p.post("/categories/list", json!({ "id": "my-sites", "list": "example.org\nexample.net\n" })).status, 200);
    let pid = {
        let c: Value = serde_json::from_slice(&std::fs::read(p.dir.join("config.json")).unwrap()).unwrap();
        c["profiles"][0]["id"].as_str().unwrap().to_string()
    };
    assert_eq!(p.post("/secrets", json!({ "profile_id": pid, "secret": { "password": PW1 } })).status, 200);

    // без секретов: настройки и списки, зашифрованной части нет
    let o = p.post("/backup/export", json!({}));
    assert_eq!(o.status, 200, "{}", o.body);
    let plain = o.body["backup"].clone();
    assert_eq!(plain["format"], "mi-lumruri-backup");
    assert_eq!(plain["lists"]["my-sites"], "example.net\nexample.org\n");
    assert!(plain.get("secrets").is_none());
    assert!(!plain.to_string().contains(PW1));

    // с секретами: короткий пароль копии — отказ; иначе секреты только в зашифрованном виде
    assert_eq!(p.post("/backup/export", json!({ "secrets": true, "passphrase": BK_SHORT })).code(), "passphrase_short");
    let o = p.post("/backup/export", json!({ "secrets": true, "passphrase": BK }));
    assert_eq!(o.status, 200, "{}", o.body);
    let sealed = o.body["backup"].clone();
    assert_eq!(sealed["secrets"]["kdf"], "argon2id");
    assert!(!sealed.to_string().contains(PW1));

    // изменения после копии: категория удалена, пароль сервера другой
    assert_eq!(p.post("/categories/delete", json!({ "base_revision": p.rev(), "id": "my-sites" })).status, 200);
    assert_eq!(p.post("/secrets", json!({ "profile_id": pid, "secret": { "password": PW2 } })).status, 200);
    assert!(!p.has_category("my-sites"));

    // пароль копии не задан или неверный — ничего не записано
    assert_eq!(p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": sealed })).code(), "passphrase_required");
    assert_eq!(p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": sealed, "passphrase": BK_WRONG })).code(), "passphrase_wrong");
    assert!(!p.has_category("my-sites"));
    assert!(p.secrets().contains(PW2));
    // устаревшая ревизия — конфликт, как при обычном сохранении
    assert_eq!(p.post("/backup/restore", json!({ "base_revision": "0".repeat(64), "backup": sealed, "passphrase": BK })).code(), "revision_conflict");

    // верный пароль: настройки, список и пароль сервера возвращены, вход в панель восстановлен, заявка на применение
    let o = p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": sealed, "passphrase": BK }));
    assert_eq!(o.status, 200, "{}", o.body);
    assert_eq!(o.body["restored"], json!({ "config": true, "lists": 1, "secrets": true, "auth": true }));
    assert!(p.has_category("my-sites"));
    assert_eq!(std::fs::read_to_string(p.dir.join("categories/my-sites.list")).unwrap(), "example.net\nexample.org\n");
    assert!(p.secrets().contains(PW1));
    assert!(p.a.session_dir.with_file_name("run").join("apply.request").exists());

    // копия с секретами без пароля — можно восстановить без них
    assert_eq!(p.post("/secrets", json!({ "profile_id": pid, "secret": { "password": PW3 } })).status, 200);
    let o = p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": sealed, "skip_secrets": true }));
    assert_eq!((o.status, o.body["secrets_skipped"].as_bool()), (200, Some(true)), "{}", o.body);
    assert!(p.secrets().contains(PW3));

    // без секретов — тоже восстанавливается
    let o = p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": plain }));
    assert_eq!((o.status, o.body["restored"]["secrets"].as_bool()), (200, Some(false)), "{}", o.body);
}

#[test]
fn restore_rejects_foreign_and_invalid_files() {
    let p = Panel::new("invalid");
    assert_eq!(p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": { "hello": 1 } })).code(), "backup_invalid");
    let foreign = json!({ "format": "other", "version": 1, "created": 0, "config": {} });
    assert_eq!(p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": foreign })).code(), "backup_invalid");
    let newer = json!({ "format": "mi-lumruri-backup", "version": 99, "created": 0, "config": {} });
    assert_eq!(p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": newer })).code(), "backup_newer");
    let bad_cfg = json!({ "format": "mi-lumruri-backup", "version": 1, "created": 0, "config": { "schema_version": 1 } });
    let before = std::fs::read(p.dir.join("config.json")).unwrap();
    assert_eq!(p.post("/backup/restore", json!({ "base_revision": p.rev(), "backup": bad_cfg })).code(), "config_invalid");
    assert_eq!(std::fs::read(p.dir.join("config.json")).unwrap(), before, "ничего не записано");
}
