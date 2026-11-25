//! Модули пакета: большие движки (sing-box), которые ставятся отдельно — на флешку или во внутреннюю память.
//!
//! - Каталог (`modules.json` из подписанного пакета; служба кладёт копию в `run/modules-catalog.json`): имя, версия,
//!   имя ассета релиза, SHA-256 и размеры tar, протоколы и виды профилей, которые модуль даёт.
//! - Установленные — `etc/modules.json` в /data: версия и каталог модуля на накопителе.
//! - Состояние на этом запуске — `run/modules-state.json` от службы: ok | missing | bad.
//! - Установка и удаление — заявка службе (`run/module.request`), ход и итог — `run/module.json`.
//!
//! Модуль — tar с каталогом `module/`: `manifest.json` (формат пакета, `release.rs`), `manifest.sig`, `payload/*.xz`.
//! Служба проверяет SHA-256 tar по каталогу и подпись манифеста закреплённым ключом релиза.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::Response;
use crate::model::ProfileKind;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogModule {
    pub name: String,
    pub version: String,
    pub title: String,
    pub protocols: Vec<String>,
    pub kinds: Vec<ProfileKind>,
    pub asset: String,
    pub tar_sha256: String,
    pub tar_bytes: u64,
    /// Место в RAM после распаковки.
    pub unpacked_bytes: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub modules: Vec<CatalogModule>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Installed {
    pub version: String,
    /// Каталог модуля (manifest.json, payload/).
    pub path: String,
    pub installed: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledFile {
    #[serde(default)]
    pub modules: BTreeMap<String, Installed>,
}

/// Запас на накопителе сверх двух размеров tar (скачанный tar и распакованный каталог существуют одновременно).
pub const RESERVE: u64 = 2 * 1024 * 1024;

fn name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 32 && n.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

pub fn load_catalog(p: &Path) -> Catalog {
    std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn load_installed(p: &Path) -> InstalledFile {
    std::fs::read(p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Каталог модуля на выбранном накопителе: внутренняя память — `<данные пакета>/modules/<имя>`, флешка —
/// `<точка монтирования>/mi-lumruri-modules/<имя>`.
pub fn module_dir(target: &str, data_path: &str, name: &str) -> String {
    if target == data_path {
        format!("{}/modules/{name}", target.trim_end_matches('/'))
    } else {
        format!("{}/mi-lumruri-modules/{name}", target.trim_end_matches('/'))
    }
}

fn etc_path(config_path: &str) -> PathBuf {
    Path::new(config_path).with_file_name("modules.json")
}

fn used_by(config_path: &str, name: &str, kinds: &[ProfileKind]) -> Vec<String> {
    let Ok(c) = crate::manage::read_config(config_path) else { return Vec::new() };
    let mut v: Vec<String> = c.profiles.iter().filter(|p| kinds.contains(&p.kind)).map(|p| p.name.clone()).collect();
    // модуль tgws — у правил «Telegram через WebSocket», а не у серверов
    if name == "tgws" && c.rules.iter().any(|r| r.action == crate::model::Action::TgWs) {
        v.push("Telegram через WebSocket".into());
    }
    v
}

/// `GET /modules`.
pub fn get(config_path: &str) -> Response {
    let run = crate::manage::run_dir();
    let cat = load_catalog(&run.join("modules-catalog.json"));
    let inst = load_installed(&etc_path(config_path));
    let state: Value = std::fs::read(run.join("modules-state.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
    let op: Value = std::fs::read(run.join("module.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let running = run.join("module.request").exists() || run.join("module.request.run").exists();
    let modules: Vec<Value> = cat
        .modules
        .iter()
        .map(|m| {
            let i = inst.modules.get(&m.name);
            json!({
                "name": m.name, "title": m.title, "version": m.version, "protocols": m.protocols, "kinds": m.kinds,
                "download_bytes": m.tar_bytes, "need_bytes": m.tar_bytes * 2 + RESERVE, "ram_bytes": m.unpacked_bytes,
                "installed": i.map(|i| json!({ "version": i.version, "path": i.path, "installed": i.installed,
                    "state": state.get(&m.name).and_then(|s| s.get("state")).cloned().unwrap_or(json!("unknown")),
                    "update": i.version != m.version })),
                "used_by": used_by(config_path, &m.name, &m.kinds),
            })
        })
        .collect();
    Response { status: 200, body: json!({ "ok": true, "modules": modules, "op": op, "running": running, "issues": [] }) }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallReq {
    name: String,
    /// Путь накопителя из GET /storage (`data.path` или `usb[].path`).
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveReq {
    name: String,
}

fn queue(req: Value) -> Response {
    let d = crate::manage::run_dir();
    if d.join("module.request").exists() || d.join("module.request.run").exists() {
        return Response::error(409, "module_busy", "установка или удаление модуля уже идёт");
    }
    match std::fs::create_dir_all(&d).map_err(|e| e.to_string()).and_then(|_| crate::store::write_atomic(&d.join("module.request"), format!("{req}\n").as_bytes())) {
        Ok(()) => Response { status: 202, body: json!({ "ok": true, "queued": true, "issues": [] }) },
        Err(m) => Response::error(500, "write_failed", m),
    }
}

/// `POST /modules/install`: накопитель — из сведений службы, с записью и местом.
pub fn install(body: &[u8]) -> Response {
    let q: InstallReq = match serde_json::from_slice(body) {
        Ok(q) => q,
        Err(e) => return Response::error(400, "bad_request", format!("запрос не разобран: {e}")),
    };
    let run = crate::manage::run_dir();
    let cat = load_catalog(&run.join("modules-catalog.json"));
    let Some(m) = cat.modules.iter().find(|m| m.name == q.name && name_ok(&m.name)) else {
        return Response::error(404, "unknown_module", format!("модуля «{}» нет в каталоге", q.name));
    };
    let storage: Value = std::fs::read(run.join("storage.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let data_path = storage["data"]["path"].as_str().unwrap_or_default().to_string();
    let drive = std::iter::once(&storage["data"]).chain(storage["usb"].as_array().into_iter().flatten()).find(|d| d["path"].as_str() == Some(q.target.as_str()));
    let Some(drive) = drive.filter(|_| !q.target.is_empty()) else {
        return Response::error(422, "unknown_target", "такого накопителя сейчас нет — обновите страницу");
    };
    if drive["writable"].as_bool() != Some(true) {
        return Response::error(422, "read_only", "накопитель только для чтения");
    }
    let need = m.tar_bytes * 2 + RESERVE;
    if drive["free"].as_u64().unwrap_or(0) < need {
        return Response::error(422, "no_space", format!("на накопителе нужно не меньше {} МБ свободного места", need.div_ceil(1024 * 1024)));
    }
    queue(json!({ "action": "install", "name": m.name, "dir": module_dir(&q.target, &data_path, &m.name), "requested_unix": crate::auth::now() }))
}

/// `POST /modules/remove`: модуль не должен использоваться серверами.
pub fn remove(body: &[u8], config_path: &str) -> Response {
    let q: RemoveReq = match serde_json::from_slice(body) {
        Ok(q) => q,
        Err(e) => return Response::error(400, "bad_request", format!("запрос не разобран: {e}")),
    };
    let inst = load_installed(&etc_path(config_path));
    if !inst.modules.contains_key(&q.name) {
        return Response::error(404, "not_installed", format!("модуль «{}» не установлен", q.name));
    }
    let cat = load_catalog(&crate::manage::run_dir().join("modules-catalog.json"));
    let kinds = cat.modules.iter().find(|m| m.name == q.name).map(|m| m.kinds.clone()).unwrap_or_default();
    let used = used_by(config_path, &q.name, &kinds);
    if !used.is_empty() {
        return Response::error(409, "module_in_use", format!("модуль используется: {}. Сначала выберите другой путь", used.join(", ")));
    }
    queue(json!({ "action": "remove", "name": q.name, "requested_unix": crate::auth::now() }))
}

/// CLI службы: `module-info <каталог> <имя>` — «ассет sha256 версия байт_tar»; `module-list <установленные>` — строки
/// «имя версия каталог»; `module-record <установленные> set <имя> <версия> <каталог>` | `del <имя>`.
pub fn cli(args: &[&str], now: u64) -> Result<String, String> {
    match args {
        ["module-info", cat, name] => {
            let c = load_catalog(Path::new(cat));
            let m = c.modules.iter().find(|m| m.name == *name).ok_or(format!("модуля «{name}» нет в каталоге"))?;
            Ok(format!("{} {} {} {}\n", m.asset, m.tar_sha256, m.version, m.tar_bytes))
        }
        ["module-list", inst] => Ok(load_installed(Path::new(inst)).modules.iter().map(|(n, i)| format!("{n} {} {}\n", i.version, i.path)).collect()),
        ["module-record", inst, "set", name, version, dir] => {
            if !name_ok(name) || version.is_empty() || version.chars().any(|c| c.is_whitespace() || c.is_control()) || dir.chars().any(char::is_control) {
                return Err("неверные данные модуля".into());
            }
            let mut f = load_installed(Path::new(inst));
            f.modules.insert(name.to_string(), Installed { version: version.to_string(), path: dir.to_string(), installed: now });
            crate::store::write_atomic(Path::new(inst), (serde_json::to_string_pretty(&f).unwrap_or_default() + "\n").as_bytes())?;
            Ok(String::new())
        }
        ["module-record", inst, "del", name] => {
            let mut f = load_installed(Path::new(inst));
            f.modules.remove(*name);
            crate::store::write_atomic(Path::new(inst), (serde_json::to_string_pretty(&f).unwrap_or_default() + "\n").as_bytes())?;
            Ok(String::new())
        }
        _ => Err("module-info <каталог> <имя> | module-list <файл> | module-record <файл> set <имя> <версия> <каталог> | module-record <файл> del <имя>".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs_and_records() {
        assert_eq!(module_dir("/data/mi-lumruri", "/data/mi-lumruri", "sing-box"), "/data/mi-lumruri/modules/sing-box");
        assert_eq!(module_dir("/mnt/usb-1a/", "/data/mi-lumruri", "sing-box"), "/mnt/usb-1a/mi-lumruri-modules/sing-box");
        let d = std::env::temp_dir().join(format!("mitt-mod-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("modules.json");
        let fs = f.to_str().unwrap();
        cli(&["module-record", fs, "set", "sing-box", "1.14.4", "/mnt/usb disk/mi-lumruri-modules/sing-box"], 5).unwrap();
        assert_eq!(cli(&["module-list", fs], 0).unwrap(), "sing-box 1.14.4 /mnt/usb disk/mi-lumruri-modules/sing-box\n");
        assert!(cli(&["module-record", fs, "set", "Bad Name", "1", "/x"], 5).is_err());
        cli(&["module-record", fs, "del", "sing-box"], 0).unwrap();
        assert_eq!(cli(&["module-list", fs], 0).unwrap(), "");
        let cat = d.join("cat.json");
        std::fs::write(&cat, r#"{"modules":[{"name":"sing-box","version":"1.14.4","title":"sing-box","protocols":["VLESS"],"kinds":["vless","hysteria2"],"asset":"mitt-mod-sing-box-1.14.4.tar","tar_sha256":"ab","tar_bytes":10,"unpacked_bytes":20}]}"#).unwrap();
        assert_eq!(cli(&["module-info", cat.to_str().unwrap(), "sing-box"], 0).unwrap(), "mitt-mod-sing-box-1.14.4.tar ab 1.14.4 10\n");
        let _ = std::fs::remove_dir_all(d);
    }
}
