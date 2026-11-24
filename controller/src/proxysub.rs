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
    /// Почему строки пропущены: до трёх разных причин с номером первой такой строки.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

/// Строка — ссылка на сервер: начинается со схемы (`vless://…`), а не просто содержит `://` (адреса в HTML-странице).
fn is_link(l: &str) -> bool {
    l.split_once("://").is_some_and(|(s, _)| {
        !s.is_empty() && s.len() <= 16 && s.starts_with(|c: char| c.is_ascii_alphabetic()) && s.chars().all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    })
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
    plain.lines().map(|l| l.trim().trim_start_matches('\u{feff}')).filter(|l| is_link(l)).map(String::from).collect()
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
            Err(e) => {
                st.skipped += 1;
                let scheme = l.split_once("://").map_or("", |(s, _)| s).to_ascii_lowercase();
                let r = format!("{scheme}: {e}").replace('"', "'");
                if st.reasons.len() < 3 && !st.reasons.iter().any(|x| x.ends_with(&r)) {
                    st.reasons.push(format!("строка {}: {r}", st.entries.len() + st.skipped));
                }
            }
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
fn apply_entry(config_path: &str, id: &str, e: &Entry, pick: Option<&str>, auto: Option<bool>) -> Response {
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
    if let Some(a) = auto {
        p.sub_auto = a;
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
    let lines = decode_list(&body);
    if lines.is_empty() {
        return Response::error(422, "subscription_empty", "в ответе подписки нет ссылок на серверы: похоже, сервер отдал страницу для браузера или настройки для другой программы");
    }
    let st = parse_list(&lines);
    if st.entries.is_empty() {
        return Response::error(422, "subscription_empty", format!("в ответе подписки нет поддерживаемых серверов (пропущено строк: {}; {})", st.skipped, st.reasons.join("; ")));
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
    let mut r = apply_entry(config_path, id, chosen, None, None);
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
    #[serde(default)]
    name: Option<String>,
    /// true — автовыбор по задержке; выбор сервера по имени его выключает.
    #[serde(default)]
    auto: bool,
}

/// `POST /subscription/pick`: сервер из последнего списка подписки или автовыбор по последнему замеру задержки.
pub fn pick(body: &[u8], config_path: &str) -> Response {
    let q: PickReq = match serde_json::from_slice(body) {
        Ok(q) => q,
        Err(e) => return Response::error(400, "bad_request", format!("запрос не разобран: {e}")),
    };
    let st = load(config_path, &q.profile_id);
    if q.auto {
        let pings = load_pings(&ping_path(&q.profile_id));
        let cur = current_link(config_path, &q.profile_id);
        let Some(e) = fastest(&st, &pings).or_else(|| cur.as_deref().and_then(|l| st.entries.iter().find(|e| e.link == l))).or(st.entries.first()) else {
            return Response::error(404, "unknown_entry", "список серверов подписки пуст — обновите подписку");
        };
        return apply_entry(config_path, &q.profile_id, e, None, Some(true));
    }
    let Some(name) = q.name else {
        return Response::error(400, "bad_request", "нужно имя сервера или auto");
    };
    let Some(e) = st.entries.iter().find(|e| e.name == name) else {
        return Response::error(404, "unknown_entry", "такого сервера в подписке нет — обновите подписку");
    };
    apply_entry(config_path, &q.profile_id, e, Some(&name), Some(false))
}

/// Замер задержки до серверов подписки (пишет mitt-sub.sh): `$RUN/sub/<id>.ping`, строки «хост порт мс|-».
pub fn ping_path(id: &str) -> PathBuf {
    crate::manage::run_dir().join("sub").join(format!("{id}.ping"))
}

/// «хост:порт» → мс; «-» (не ответил) — не попадает.
fn load_pings(path: &Path) -> std::collections::BTreeMap<String, u32> {
    let text = crate::api::read_limited(&path.to_string_lossy(), 64 * 1024).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (h, p, ms) = (it.next()?, it.next()?, it.next()?);
            Some((format!("{h}:{p}"), ms.parse().ok()?))
        })
        .collect()
}

fn current_link(config_path: &str, id: &str) -> Option<String> {
    crate::manage::load_secrets_pub(&crate::manage::secrets_path(config_path)).ok().and_then(|s| s.profiles.get(id).and_then(|x| x.link.clone()))
}

fn ping_of(e: &Entry, pings: &std::collections::BTreeMap<String, u32>) -> Option<u32> {
    pings.get(&format!("{}:{}", e.info.server, e.info.port)).copied()
}

/// Сервер с наименьшей задержкой (из тех, что ответили).
fn fastest<'a>(st: &'a Stored, pings: &std::collections::BTreeMap<String, u32>) -> Option<&'a Entry> {
    st.entries.iter().filter_map(|e| ping_of(e, pings).map(|ms| (ms, e))).min_by_key(|(ms, _)| *ms).map(|(_, e)| e)
}

/// Переходить ли с текущего сервера на самый быстрый: текущий не отвечает или новый быстрее на 30 % и не меньше
/// чем на 20 мс (как выбор основного и запасного серверов TrustTunnel) — чтобы не прыгать из-за разброса замеров.
pub fn worth_switching(cur_ms: Option<u32>, best_ms: u32) -> bool {
    match cur_ms {
        None => true,
        Some(c) => best_ms * 10 <= c * 7 && c - best_ms >= 20,
    }
}

/// Адреса серверов последнего списка без повторов: «хост порт вид».
pub fn hosts(config_path: &str, id: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in load(config_path, id).entries {
        let kind = serde_json::to_value(e.kind).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        let l = format!("{} {} {kind}", e.info.server, e.info.port);
        if !out.contains(&l) {
            out.push(l);
        }
    }
    out
}

/// `mi-tt-ctl proxy-sub-auto <config> <профиль> <файл замера>`: при автовыборе — переход на заметно более быстрый сервер.
pub fn auto(config_path: &str, id: &str, file: &str) -> Response {
    let cfg = match crate::manage::read_config(config_path) {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !cfg.profiles.iter().any(|p| p.id == id && p.sub_auto) {
        return Response { status: 200, body: json!({ "ok": true, "changed": false, "auto": false, "issues": [] }) };
    }
    let st = load(config_path, id);
    let pings = load_pings(Path::new(file));
    let Some(best) = fastest(&st, &pings) else {
        return Response { status: 200, body: json!({ "ok": true, "changed": false, "auto": true, "issues": [] }) };
    };
    let cur = current_link(config_path, id).and_then(|l| st.entries.iter().find(|e| e.link == l).cloned());
    if let Some(c) = &cur {
        if c.link == best.link || !worth_switching(ping_of(c, &pings), ping_of(best, &pings).unwrap_or(u32::MAX)) {
            return Response { status: 200, body: json!({ "ok": true, "changed": false, "auto": true, "picked": c.name, "issues": [] }) };
        }
    }
    apply_entry(config_path, id, best, None, None)
}

/// Список серверов подписки для панели (без ссылок).
pub fn entries_view(config_path: &str, id: &str) -> Value {
    let st = load(config_path, id);
    let pings = load_pings(&ping_path(id));
    json!(st
        .entries
        .iter()
        .map(|e| json!({ "name": e.name, "kind": e.kind, "server": e.info.server, "port": e.info.port, "security": e.info.security, "transport": e.info.transport, "ping": ping_of(e, &pings) }))
        .collect::<Vec<_>>())
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
        // страница для браузера: адреса внутри разметки — не ссылки на серверы
        assert!(decode_list(b"<html>\n<link href=\"https://cdn.example.com/a.css\">\n<a href=\"vless://x\">x</a></html>").is_empty());
    }

    #[test]
    fn real_world_links_and_reasons() {
        // название с пробелами, флагом и «%», Vision udp443, отпечаток chrome_auto — как у панелей Remnawave и 3x-ui
        let l = "vless://bf000d23-0752-40b4-affe-68f7707a9661@a.example.com:443?security=reality&pbk=k&sid=ab&fp=chrome_auto&flow=xtls-rprx-vision-udp443&type=tcp#\u{1F1F3}\u{1F1F1} Нидерланды -50% 1";
        let x = "vless://bf000d23-0752-40b4-affe-68f7707a9661@b.example.com:443?type=xhttp#X";
        let st = parse_list(&[l.to_string(), x.to_string()]);
        assert_eq!(st.entries.len(), 1, "{:?}", st.reasons);
        assert_eq!(st.entries[0].name, "\u{1F1F3}\u{1F1F1} Нидерланды -50% 1");
        assert_eq!(st.skipped, 1);
        assert!(st.reasons[0].starts_with("строка 2: vless:") && st.reasons[0].contains("xhttp"), "{:?}", st.reasons);
    }

    #[test]
    fn switching_needs_a_clear_gain() {
        assert!(worth_switching(None, 300));
        assert!(worth_switching(Some(120), 60));
        assert!(!worth_switching(Some(120), 100), "меньше 30 %");
        assert!(!worth_switching(Some(50), 34), "меньше 20 мс");
    }

    #[test]
    fn names_unique_and_default() {
        let st = parse_list(&[L1.to_string(), L1.to_string(), "trojan://pw@c.example.com:8443".to_string()]);
        assert_eq!(st.entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["A", "A (2)", "c.example.com:8443"]);
    }
}
