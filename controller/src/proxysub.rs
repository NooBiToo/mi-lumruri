//! Подписки серверов модуля sing-box: по ссылке-подписке (`secrets.profiles[id].subscription_url`) сервер отдаёт список
//! ссылок `vless://`, `hysteria2://`, `trojan://`, `ss://` — по одной в строке, обычно в base64. Служба скачивает его
//! (mitt-sub.sh), `mi-tt-ctl proxy-sub-import` разбирает: поддерживаемые ссылки — в `etc/sub/<id>.json` (только root:
//! в ссылках ключи), выбранная — в секрет `link` профиля, вид и сводка — в настройки. Выбор — по имени
//! (`Profile.sub_pick`); не задан или пропал — прежняя ссылка, если она есть в списке, иначе первая.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::Response;
use crate::model::ProfileKind;
use crate::proxy::ProxyInfo;

/// Ссылок в подписке не больше (остальные пропускаются).
pub const MAX_ENTRIES: usize = 200;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Entry {
    pub name: String,
    pub kind: ProfileKind,
    pub info: ProxyInfo,
    pub link: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Stored {
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub skipped: usize,
}

/// Тело ответа подписки → строки-ссылки: открытый текст (есть `://`) или base64 (обычный и URL-safe, с переводами строк).
pub fn decode_list(body: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    let plain = if text.contains("://") {
        text.into_owned()
    } else {
        let t: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let t = t.trim_end_matches('=').replace('-', "+").replace('_', "/");
        match data_encoding::BASE64_NOPAD.decode(t.as_bytes()) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(_) => String::new(),
        }
    };
    plain.lines().map(str::trim).filter(|l| l.contains("://")).map(String::from).collect()
}

/// Разобранный список: поддерживаемые серверы и число пропущенных строк. Имя — из `#фрагмента`, иначе «сервер:порт»;
/// одинаковые имена получают « (2)», « (3)».
pub fn parse_list(lines: &[String]) -> Stored {
    let mut st = Stored::default();
    for l in lines {
        if st.entries.len() >= MAX_ENTRIES {
            st.skipped += 1;
            continue;
        }
        match crate::proxy::parse_link(l) {
            Ok(p) => {
                let base = p.name.clone().unwrap_or_else(|| format!("{}:{}", p.info.server, p.info.port));
                let mut name = base.clone();
                let mut n = 2;
                while st.entries.iter().any(|e| e.name == name) {
                    name = format!("{base} ({n})");
                    n += 1;
                }
                st.entries.push(Entry { name, kind: p.kind, info: p.info, link: l.clone() });
            }
            Err(_) => st.skipped += 1,
        }
    }
    st
}

fn stored_path(config_path: &str, id: &str) -> PathBuf {
    Path::new(config_path).with_file_name("sub").join(format!("{id}.json"))
}

pub fn load(config_path: &str, id: &str) -> Stored {
    std::fs::read(stored_path(config_path, id)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(config_path: &str, id: &str, st: &Stored) -> Result<(), String> {
    let p = stored_path(config_path, id);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
        }
    }
    crate::store::write_atomic(&p, (serde_json::to_string(st).unwrap_or_default() + "\n").as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Записать выбранную ссылку профилю: секрет `link`, вид и сводка в настройках, `sub_pick`, заявка на применение.
/// Ничего не изменилось — ничего не пишется (`changed: false`).
fn apply_entry(config_path: &str, id: &str, e: &Entry, pick: Option<&str>) -> Response {
    let raw = match crate::api::read_limited(config_path, crate::api::MAX_CONFIG_BYTES) {
        Ok(b) => b,
        Err(m) => return Response::error(500, "unreadable", m),
    };
    let cfg = match crate::manage::read_config(config_path) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(i) = cfg.profiles.iter().position(|p| p.id == id) else {
        return Response::error(404, "unknown_profile", format!("профиль «{id}» не найден"));
    };
    if !cfg.profiles[i].kind.singbox() {
        return Response::error(409, "not_singbox", "подписка со списком ссылок — только для серверов модуля sing-box");
    }
    let sp = crate::manage::secrets_path(config_path);
    let _g = match crate::store::lock(&sp) {
        Ok(g) => g,
        Err(m) => return Response::error(503, "busy", m),
    };
    let mut s = match crate::manage::load_secrets_pub(&sp) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let mut next = cfg.clone();
    let p = &mut next.profiles[i];
    p.kind = e.kind;
    p.proxy = Some(e.info.clone());
    if let Some(n) = pick {
        p.sub_pick = Some(n.to_string());
    }
    let cfg_changed = serde_json::to_value(&next.profiles[i]).ok() != serde_json::to_value(&cfg.profiles[i]).ok();
    let link_changed = s.profiles.get(id).and_then(|x| x.link.as_deref()) != Some(e.link.as_str());
    if !cfg_changed && !link_changed {
        return Response { status: 200, body: json!({ "ok": true, "changed": false, "picked": e.name, "issues": [] }) };
    }
    if cfg_changed {
        let issues = crate::validate::validate_config(&next);
        if !issues.is_empty() {
            return Response { status: 422, body: json!({ "ok": false, "error": { "code": "subscription_invalid", "message": "сервер из подписки не прошёл проверку; ничего не записано" }, "issues": issues }) };
        }
    }
    if link_changed {
        s.profiles.entry(id.to_string()).or_default().link = Some(e.link.clone());
        let mut out = serde_json::to_vec_pretty(&s).unwrap_or_default();
        out.push(b'\n');
        if let Err(m) = crate::store::write_atomic(&sp, &out) {
            return Response::error(500, "write_failed", m);
        }
    }
    if cfg_changed {
        if crate::store::replace_config(Path::new(config_path), &crate::store::revision(&raw), crate::api::MAX_CONFIG_BYTES, &next).is_err() {
            return Response::error(409, "config_changed", "настройки изменились во время записи — обновите подписку ещё раз");
        }
    }
    match crate::manage::queue_apply(config_path) {
        Ok(_) => Response { status: 200, body: json!({ "ok": true, "changed": true, "picked": e.name, "issues": [] }) },
        Err(m) => Response::error(500, "write_failed", format!("сервер записан, но заявка на применение не записана: {m}")),
    }
}

/// `mi-tt-ctl proxy-sub-import <config> <профиль> <файл>`: ответ подписки, скачанный службой.
pub fn import(config_path: &str, id: &str, file: &str) -> Response {
    let body = match crate::api::read_limited(file, 1024 * 1024) {
        Ok(b) => b,
        Err(m) => return Response::error(500, "unreadable", m),
    };
    let st = parse_list(&decode_list(&body));
    if st.entries.is_empty() {
        return Response::error(422, "subscription_empty", format!("в ответе подписки нет поддерживаемых серверов (пропущено строк: {})", st.skipped));
    }
    if let Err(m) = save(config_path, id, &st) {
        return Response::error(500, "write_failed", m);
    }
    let cfg = match crate::manage::read_config(config_path) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let pick = cfg.profiles.iter().find(|p| p.id == id).and_then(|p| p.sub_pick.clone());
    let cur = crate::manage::load_secrets_pub(&crate::manage::secrets_path(config_path)).ok().and_then(|s| s.profiles.get(id).and_then(|x| x.link.clone()));
    let chosen = pick.as_deref().and_then(|n| st.entries.iter().find(|e| e.name == n))
        .or_else(|| cur.as_deref().and_then(|l| st.entries.iter().find(|e| e.link == l)))
        .unwrap_or(&st.entries[0]);
    let mut r = apply_entry(config_path, id, chosen, None);
    if let Value::Object(m) = &mut r.body {
        m.insert("count".into(), json!(st.entries.len()));
        m.insert("skipped".into(), json!(st.skipped));
    }
    r
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PickReq {
    profile_id: String,
    name: String,
}

/// `POST /subscription/pick`: сервер из последнего списка подписки.
pub fn pick(body: &[u8], config_path: &str) -> Response {
    let q: PickReq = match serde_json::from_slice(body) {
        Ok(q) => q,
        Err(e) => return Response::error(400, "bad_request", format!("запрос не разобран: {e}")),
    };
    let st = load(config_path, &q.profile_id);
    let Some(e) = st.entries.iter().find(|e| e.name == q.name) else {
        return Response::error(404, "unknown_entry", "такого сервера в подписке нет — обновите подписку");
    };
    apply_entry(config_path, &q.profile_id, e, Some(&q.name))
}

/// Список серверов подписки для панели (без ссылок).
pub fn entries_view(config_path: &str, id: &str) -> Value {
    let st = load(config_path, id);
    json!(st.entries.iter().map(|e| json!({ "name": e.name, "kind": e.kind, "server": e.info.server, "port": e.info.port })).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    const L1: &str = "vless://bf000d23-0752-40b4-affe-68f7707a9661@a.example.com:443?security=tls#A";
    const L2: &str = "hy2://pw@b.example.com:443#B";

    #[test]
    fn plain_and_base64_lists() {
        let plain = format!("{L1}\n{L2}\nvmess://xyz\n\n");
        assert_eq!(decode_list(plain.as_bytes()), [L1, L2, "vmess://xyz"]);
        let b = data_encoding::BASE64.encode(plain.as_bytes());
        let wrapped: String = b.as_bytes().chunks(60).map(|c| String::from_utf8_lossy(c).into_owned() + "\n").collect();
        assert_eq!(decode_list(wrapped.as_bytes()), [L1, L2, "vmess://xyz"]);
        let st = parse_list(&decode_list(wrapped.as_bytes()));
        assert_eq!((st.entries.len(), st.skipped), (2, 1));
        assert_eq!(st.entries[1].kind, ProfileKind::Hysteria2);
        assert!(decode_list(b"<html>not a list</html>").is_empty());
    }

    #[test]
    fn names_unique_and_default() {
        let st = parse_list(&[L1.to_string(), L1.to_string(), "trojan://pw@c.example.com:8443".to_string()]);
        assert_eq!(st.entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["A", "A (2)", "c.example.com:8443"]);
    }
}
