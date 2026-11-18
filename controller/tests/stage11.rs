//! Этап 11: управление из панели под 2FA — правила (удаление, порядок), профили и секреты (только запись), группы,
//! категории со списками, DNS и реклама, Zapret, запрос применения. Всё через настоящий CGI после пароля и TOTP.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::*;

struct Panel {
    a: Auth,
    s: Sess,
    t: u64,
    dir: PathBuf,
}

impl Panel {
    fn new(name: &str) -> Panel {
        let mut a = Auth::new(name);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s11-{name}-{}", rand_hex(6)));
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
    fn get(&self, path: &str) -> Out {
        self.a.api(&self.s, "GET", path, None, self.t + 1)
    }
    fn config(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.dir.join("config.json")).unwrap()).unwrap()
    }
}

fn rule(id: &str, dest: Value, action: Value) -> Value {
    json!({ "id": id, "source": { "type": "device", "id": "tv" }, "destination": dest, "action": action })
}

#[test]
fn management_requires_both_factors_csrf_and_origin() {
    let p = Panel::new("mgmt-auth");
    let body = json!({ "base_revision": p.rev(), "id": "x" }).to_string();
    // без сессии
    let o = p.a.cgi("POST", "/rules/delete", Some(body.as_bytes()), p.t, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "same-origin")]);
    assert_eq!(o.code(), "auth_required");
    assert_eq!(p.a.cgi("GET", "/secrets", None, p.t, &[]).code(), "auth_required");
    assert_eq!(p.a.cgi("GET", "/status", None, p.t, &[]).code(), "auth_required");
    // без CSRF и с чужим Origin
    let o = p.a.cgi("POST", "/secrets", Some(br#"{"profile_id":"tt-lab","secret":{"password":"x"}}"#), p.t, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", &p.s.cookie)]);
    assert_eq!(o.code(), "csrf_failed");
    let o = p.a.cgi("POST", "/dns", Some(br#"{"base_revision":"x","dns":null}"#), p.t, &[("HTTP_ORIGIN", "https://evil.example"), ("HTTP_COOKIE", &p.s.cookie), ("HTTP_X_MITT_CSRF", &p.s.csrf)]);
    assert_eq!(o.code(), "origin_forbidden");
    // CGI по-прежнему не применяет: /apply нет, есть только заявка для службы
    assert_eq!(p.post("/apply", json!({})).status, 404);
}

#[test]
fn rules_delete_and_reorder_with_revision_check() {
    let p = Panel::new("mgmt-rules");
    for (id, act) in [("r1", json!({ "type": "direct" })), ("r2", json!({ "type": "block" })), ("r3", json!({ "type": "profile", "id": "tt-lab" }))] {
        let o = p.a.api(&p.s, "POST", "/rules", Some(json!({ "base_revision": p.rev(), "rule": rule(id, json!({ "type": "group", "id": "video" }), act) }).to_string().as_bytes()), p.t);
        assert_eq!(o.status, 200, "{}", o.body);
    }
    let o = p.post("/rules/move", json!({ "base_revision": p.rev(), "id": "r3", "position": 0 }));
    assert_eq!(o.status, 200, "{}", o.body);
    let ids = |c: &Value| c["rules"].as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    assert_eq!(ids(&p.config()), ["r3", "r1", "r2"]);
    let stale = p.rev();
    assert_eq!(p.post("/rules/delete", json!({ "base_revision": stale, "id": "r1" })).status, 200);
    let o = p.post("/rules/delete", json!({ "base_revision": stale, "id": "r2" }));
    assert_eq!((o.status, o.code()), (409, "revision_conflict"), "устаревшая ревизия не перезаписывает чужое изменение");
    assert_eq!(ids(&p.config()), ["r3", "r2"]);
    assert_eq!(p.post("/rules/move", json!({ "base_revision": p.rev(), "id": "r2", "position": 9 })).code(), "invalid");
    assert_eq!(p.post("/rules/delete", json!({ "base_revision": p.rev(), "id": "nope" })).code(), "invalid");
}

#[test]
fn profiles_and_write_only_secrets() {
    let p = Panel::new("mgmt-profiles");
    let hy = json!({ "id": "hy", "name": "Hysteria2", "kind": "hysteria2", "endpoint": { "server": "hy.example.com", "port": 443 } });
    assert_eq!(p.post("/profiles", json!({ "base_revision": p.rev(), "profile": hy })).status, 200);
    // невалидный профиль не записывается
    let bad = json!({ "id": "hy2", "name": "Bad", "kind": "hysteria2", "endpoint": { "server": "10.0.0.1", "port": 443 } });
    let o = p.post("/profiles", json!({ "base_revision": p.rev(), "profile": bad }));
    assert_eq!((o.status, o.body["issues"][0]["code"].as_str()), (422, Some("tls_unverifiable")));
    // секрет: только запись; GET отдаёт признак наличия, но не значение
    let pw = format!("s-{}", rand_hex(16));
    let o = p.post("/secrets", json!({ "profile_id": "hy", "secret": { "password": pw } }));
    assert_eq!(o.status, 200, "{}", o.body);
    assert!(!o.body.to_string().contains(&pw));
    let o = p.get("/secrets");
    assert_eq!((o.body["profiles"]["hy"].as_bool(), o.body["profiles"]["tt-lab"].as_bool()), (Some(true), Some(false)));
    assert!(!o.body.to_string().contains(&pw));
    assert!(std::fs::read_to_string(p.dir.join("secrets.json")).unwrap().contains(&pw));
    // секрет не того вида — отказ; неизвестный профиль — 404
    assert_eq!(p.post("/secrets", json!({ "profile_id": "hy", "secret": { "uuid": format!("{}-0000-4000-a000-000000000000", rand_hex(8)) } })).code(), "bad_secret");
    assert_eq!(p.post("/secrets", json!({ "profile_id": "nope", "secret": { "password": rand_hex(16) } })).status, 404);
    // профиль, на который ссылается правило, удалить нельзя
    let r = rule("r-hy", json!({ "type": "group", "id": "video" }), json!({ "type": "profile", "id": "hy" }));
    assert_eq!(p.a.api(&p.s, "POST", "/rules", Some(json!({ "base_revision": p.rev(), "rule": r }).to_string().as_bytes()), p.t).status, 200);
    let o = p.post("/profiles/delete", json!({ "base_revision": p.rev(), "id": "hy" }));
    assert_eq!((o.status, o.body["issues"][0]["code"].as_str()), (422, Some("unknown_profile")));
    assert!(p.config()["profiles"].as_array().unwrap().iter().any(|x| x["id"] == "hy"));
}

#[test]
fn categories_lists_dns_adblock_zapret_and_apply_request() {
    let p = Panel::new("mgmt-cat");
    let cat = json!({ "id": "video-geo", "name": "Видео (geo)", "kind": "domain", "source": "geosite:youtube" });
    assert_eq!(p.post("/categories", json!({ "base_revision": p.rev(), "category": cat })).status, 200);
    let o = p.post("/categories/list", json!({ "id": "video-geo", "list": "youtube.com\n+.googlevideo.com\n# c\n" }));
    assert_eq!((o.status, o.body["entries"].as_u64()), (200, Some(2)), "{}", o.body);
    assert_eq!(p.post("/categories/list", json!({ "id": "video-geo", "list": "bad entry\n" })).code(), "category_invalid");
    assert_eq!(std::fs::read_to_string(p.dir.join("categories/video-geo.list")).unwrap(), "googlevideo.com\nyoutube.com\n", "действующий список сохранён");
    let ipcat = json!({ "id": "ru-ip", "name": "IP RU", "kind": "ip" });
    assert_eq!(p.post("/categories", json!({ "base_revision": p.rev(), "category": ipcat })).status, 200);
    assert_eq!(p.post("/categories/list", json!({ "id": "ru-ip", "list": "203.0.113.0/24\n2001:db8::/32\n" })).status, 200);
    for (id, dest) in [("r-cat", json!({ "type": "category", "id": "video-geo" })), ("r-ip", json!({ "type": "category", "id": "ru-ip" }))] {
        let r = rule(id, dest, json!({ "type": "profile", "id": "tt-lab" }));
        assert_eq!(p.a.api(&p.s, "POST", "/rules", Some(json!({ "base_revision": p.rev(), "rule": r }).to_string().as_bytes()), p.t).status, 200);
    }
    // категорию, на которую ссылается правило, удалить нельзя
    assert_eq!(p.post("/categories/delete", json!({ "base_revision": p.rev(), "id": "ru-ip" })).body["issues"][0]["code"], "unknown_category");
    // DNS и реклама
    let dns = json!({ "transport": "doh", "servers": [{ "host": "dns.example", "ip": "9.9.9.9" }], "adblock": { "enabled": true, "exceptions": ["ok.ads.example"] } });
    assert_eq!(p.post("/dns", json!({ "base_revision": p.rev(), "dns": dns })).status, 200);
    assert_eq!(p.post("/adblock/list", json!({ "list": "ads.example\n0.0.0.0 tracker.example\n" })).body["domains"], 2);
    assert_eq!(p.post("/adblock/list", json!({ "list": "" })).code(), "adblock_empty");
    assert_eq!(p.post("/zapret", json!({ "base_revision": p.rev(), "zapret": { "strategy": "multidisorder", "pos": 3 } })).status, 200);
    // рендер (как служба): RULE-SET категорий, списки rules/<id>.txt, DNS-файлы
    std::fs::write(p.dir.join("secrets.json"), r#"{"version":1,"profiles":{"tt-lab":{"password":"x"}}}"#).unwrap();
    std::fs::write(p.dir.join("leases"), "1999999999 02:00:00:00:0a:02 10.10.1.2 tv *\n").unwrap();
    let out = p.dir.join("out");
    let o = Command::new(ctl())
        .args(["render", p.dir.join("config.json").to_str().unwrap(), p.dir.join("secrets.json").to_str().unwrap(), p.dir.join("leases").to_str().unwrap(), out.to_str().unwrap()])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(0), "{v}");
    let mh: Value = serde_json::from_slice(&std::fs::read(out.join("config.yaml")).unwrap()).unwrap();
    assert_eq!(mh["rule-providers"]["cat-video-geo"], json!({ "type": "file", "behavior": "domain", "format": "text", "path": "./rules/video-geo.txt" }));
    assert_eq!(mh["rule-providers"]["cat-ru-ip"]["behavior"], "ipcidr");
    assert!(mh["rules"].as_array().unwrap().iter().any(|r| r.as_str().unwrap().contains("RULE-SET,cat-video-geo")));
    assert_eq!(std::fs::read_to_string(out.join("rules/video-geo.txt")).unwrap(), "+.googlevideo.com\n+.youtube.com\n");
    assert_eq!(std::fs::read_to_string(out.join("rules/ru-ip.txt")).unwrap(), "2001:db8::/32\n203.0.113.0/24\n");
    assert!(std::fs::read_to_string(out.join("dnsmasq-mitt.conf")).unwrap().contains("address=/tracker.example/"));
    // заявка на применение — служба применит; статус читается
    let o = p.a.cgi("POST", "/apply-request", Some(b"{}"), p.t + 2, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", &p.s.cookie), ("HTTP_X_MITT_CSRF", &p.s.csrf),
        ("MI_TT_RUN_DIR", p.dir.join("run").to_str().unwrap())]);
    assert_eq!((o.status, o.body["queued"].as_bool()), (202, Some(true)), "{}", o.body);
    assert!(p.dir.join("run/apply.request").exists());
    let o = p.a.cgi("GET", "/status", None, p.t + 3, &[("HTTP_COOKIE", &p.s.cookie), ("MI_TT_RUN_DIR", p.dir.join("run").to_str().unwrap())]);
    assert_eq!(o.body["apply_pending"], true);
}
