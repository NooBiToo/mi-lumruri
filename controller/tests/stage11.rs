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
    // единственный профиль TrustTunnel заменяется по id
    let tt = json!({ "id": "tt-lab", "name": "TrustTunnel", "kind": "trusttunnel", "on_failure": "direct",
        "endpoint": { "server": "10.30.0.3", "port": 8443, "sni": "vpn2.lab.test", "username": "tv-user", "quic": true } });
    let o = p.post("/profiles", json!({ "base_revision": p.rev(), "profile": tt }));
    assert_eq!((o.status, o.body["mode"].as_str()), (200, Some("replace")), "{}", o.body);
    assert_eq!(p.config()["profiles"].as_array().unwrap().len(), 1);
    assert_eq!(p.config()["profiles"][0]["endpoint"]["quic"], true);
    // второй профиль не поддерживается; невалидный профиль не записывается
    let before = std::fs::read(p.dir.join("config.json")).unwrap();
    let second = json!({ "id": "tt2", "name": "Второй", "kind": "trusttunnel", "endpoint": { "server": "10.0.0.1", "port": 443, "username": "u" } });
    let o = p.post("/profiles", json!({ "base_revision": p.rev(), "profile": second }));
    assert_eq!((o.status, o.body["issues"][0]["code"].as_str()), (422, Some("too_many_profiles")), "{}", o.body);
    let bad = json!({ "id": "tt-lab", "name": "Bad", "kind": "trusttunnel", "endpoint": { "server": "vpn.example.com", "port": 443, "username": "u" } });
    let o = p.post("/profiles", json!({ "base_revision": p.rev(), "profile": bad }));
    assert_eq!((o.status, o.body["issues"][0]["code"].as_str()), (422, Some("bad_server")), "{}", o.body);
    let hy = json!({ "id": "hy", "name": "Hysteria2", "kind": "hysteria2", "endpoint": { "server": "10.0.0.1", "port": 443 } });
    assert_eq!(p.post("/profiles", json!({ "base_revision": p.rev(), "profile": hy })).status, 400, "удалённые виды профилей схема не принимает");
    assert_eq!(std::fs::read(p.dir.join("config.json")).unwrap(), before);
    // секрет: только запись; GET отдаёт признак наличия, но не значение
    let o = p.get("/secrets");
    assert_eq!(o.body["profiles"]["tt-lab"].as_bool(), Some(false));
    let pw = format!("s-{}", rand_hex(16));
    let o = p.post("/secrets", json!({ "profile_id": "tt-lab", "secret": { "password": pw } }));
    assert_eq!(o.status, 200, "{}", o.body);
    assert!(!o.body.to_string().contains(&pw));
    let o = p.get("/secrets");
    assert_eq!(o.body["profiles"]["tt-lab"].as_bool(), Some(true));
    assert!(!o.body.to_string().contains(&pw));
    assert!(!p.get("/config").body.to_string().contains(&pw), "пароль не попадает в настройки");
    assert!(std::fs::read_to_string(p.dir.join("secrets.json")).unwrap().contains(&pw));
    // пустой пароль — отказ; секреты прежних видов профилей схема не принимает; неизвестный профиль — 404
    assert_eq!(p.post("/secrets", json!({ "profile_id": "tt-lab", "secret": { "password": "" } })).code(), "bad_secret");
    assert_eq!(p.post("/secrets", json!({ "profile_id": "tt-lab", "secret": { "uuid": format!("{}-0000-4000-a000-000000000000", rand_hex(8)) } })).status, 400);
    assert_eq!(p.post("/secrets", json!({ "profile_id": "nope", "secret": { "password": rand_hex(16) } })).status, 404);
    assert!(std::fs::read_to_string(p.dir.join("secrets.json")).unwrap().contains(&pw), "отклонённые запросы не стирают секрет");
    // профиль, на который ссылается правило, удалить нельзя
    let r = rule("r-tt", json!({ "type": "group", "id": "video" }), json!({ "type": "profile", "id": "tt-lab" }));
    assert_eq!(p.a.api(&p.s, "POST", "/rules", Some(json!({ "base_revision": p.rev(), "rule": r }).to_string().as_bytes()), p.t).status, 200);
    let o = p.post("/profiles/delete", json!({ "base_revision": p.rev(), "id": "tt-lab" }));
    assert_eq!((o.status, o.body["issues"][0]["code"].as_str()), (422, Some("unknown_profile")));
    assert!(p.config()["profiles"].as_array().unwrap().iter().any(|x| x["id"] == "tt-lab"));
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
    let dns = json!({ "tunnel_resolver": "9.9.9.9", "adblock": { "enabled": true, "exceptions": ["ok.ads.example"] } });
    assert_eq!(p.post("/dns", json!({ "base_revision": p.rev(), "dns": dns })).status, 200);
    let o = p.post("/dns", json!({ "base_revision": p.rev(), "dns": { "transport": "doh" } }));
    assert_eq!(o.status, 400, "прежние поля DNS не принимаются: {}", o.body);
    assert_eq!(p.post("/adblock/list", json!({ "list": "ads.example
0.0.0.0 tracker.example
" })).body["domains"], 2);
    assert_eq!(p.post("/adblock/list", json!({ "list": "" })).code(), "adblock_empty");
    assert_eq!(p.post("/zapret", json!({ "base_revision": p.rev(), "zapret": { "strategy": "v3" } })).status, 200);
    assert_eq!(p.post("/zapret", json!({ "base_revision": p.rev(), "zapret": { "strategy": "nope" } })).code(), "invalid", "неизвестная стратегия не сохраняется");
    // рендер (как служба): наборы ipset категорий, домены категорий — в dnsmasq, IP-префиксы — в статический набор
    let pw = format!("s-{}", rand_hex(16));
    std::fs::write(p.dir.join("secrets.json"), json!({ "version": 1, "profiles": { "tt-lab": { "password": pw } } }).to_string()).unwrap();
    let out = p.dir.join("out");
    let o = Command::new(ctl())
        .args(["render", p.dir.join("config.json").to_str().unwrap(), p.dir.join("secrets.json").to_str().unwrap(), out.to_str().unwrap()])
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(0), "{v}");
    let rules = v["policy"]["rules"].as_array().unwrap();
    let set_of = |from: &str| rules.iter().find(|r| r["from"] == from).unwrap_or_else(|| panic!("нет {from}: {v}"))["set"].as_str().unwrap().to_string();
    let (cat_set, ip_set) = (set_of("r-cat"), set_of("r-ip"));
    let kind = |name: &str| v["policy"]["sets"].as_array().unwrap().iter().find(|s| s["name"] == name).unwrap()["kind"].as_str().unwrap().to_string();
    assert_eq!((kind(&cat_set).as_str(), kind(&ip_set).as_str()), ("dns", "static"));
    let conf = std::fs::read_to_string(out.join("dnsmasq-mitt.conf")).unwrap();
    for want in [format!("ipset=/googlevideo.com/{cat_set}
"), format!("ipset=/youtube.com/{cat_set}
"), "server=/youtube.com/9.9.9.9
".into(),
        "address=/tracker.example/
".into(), "server=/ok.ads.example/#
".into()] {
        assert!(conf.contains(&want), "нет {want:?}: {conf}");
    }
    assert_eq!(v["policy"]["dns_resolver"], "9.9.9.9");
    // IPv6-префикс категории не используется — об этом есть предупреждение
    assert!(v["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("IPv6-префиксы")), "{v}");
    assert!(!v.to_string().contains(&pw));
    assert!(!out.join("rules").exists() && !out.join("config.yaml").exists(), "файлов Mihomo нет");
    // заявка на применение — служба применит; статус читается
    let o = p.a.cgi("POST", "/apply-request", Some(b"{}"), p.t + 2, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", &p.s.cookie), ("HTTP_X_MITT_CSRF", &p.s.csrf),
        ("MI_TT_RUN_DIR", p.dir.join("run").to_str().unwrap())]);
    assert_eq!((o.status, o.body["queued"].as_bool()), (202, Some(true)), "{}", o.body);
    assert!(p.dir.join("run/apply.request").exists());
    let o = p.a.cgi("GET", "/status", None, p.t + 3, &[("HTTP_COOKIE", &p.s.cookie), ("MI_TT_RUN_DIR", p.dir.join("run").to_str().unwrap())]);
    assert_eq!(o.body["apply_pending"], true);
}

#[test]
fn zapret_test_api() {
    let p = Panel::new("mgmt-ztest");
    let run = p.dir.join("run");
    let rd = run.to_str().unwrap().to_string();
    let call = |m: &str, body: Option<&[u8]>| {
        let mut env = vec![("HTTP_COOKIE", p.s.cookie.as_str()), ("MI_TT_RUN_DIR", rd.as_str())];
        if m == "POST" {
            env.extend([("HTTP_ORIGIN", ORIGIN), ("HTTP_X_MITT_CSRF", p.s.csrf.as_str())]);
        }
        p.a.cgi(m, "/zapret/test", body, p.t + 1, &env)
    };
    // без подбора — idle
    let o = call("GET", None);
    assert_eq!((o.status, o.body["test"]["state"].as_str()), (200, Some("idle")), "{}", o.body);
    assert_eq!(p.a.cgi("GET", "/zapret/test", None, p.t, &[]).code(), "auth_required");
    // заявка
    let o = call("POST", Some(br#"{"mode":"quick"}"#));
    assert_eq!((o.status, o.body["queued"].as_bool()), (202, Some(true)), "{}", o.body);
    let req: Value = serde_json::from_slice(&std::fs::read(run.join("zapret-test.request")).unwrap()).unwrap();
    assert_eq!(req["mode"], "quick");
    assert_eq!(call("POST", Some(br#"{"mode":"quick"}"#)).status, 409, "заявка уже ждёт службу");
    assert_eq!(call("POST", Some(br#"{"mode":"full"}"#)).status, 400);
    // идёт подбор — 409; GET отдаёт файл состояния
    std::fs::remove_file(run.join("zapret-test.request")).unwrap();
    let st = json!({ "state": "running", "pid": std::process::id(), "started": T0 + 50, "finished": null, "progress": { "done": 3, "total": 11, "current": "v3" },
        "control": { "opened": 2, "total": 10 }, "best": null, "applied": false, "message": "Проверка стратегии v3" });
    std::fs::write(run.join("zapret-test.json"), st.to_string()).unwrap();
    let o = call("POST", Some(br#"{"mode":"quick"}"#));
    assert_eq!((o.status, o.code()), (409, "zapret_test_running"), "{}", o.body);
    assert!(!run.join("zapret-test.request").exists());
    let o = call("GET", None);
    assert_eq!(o.body["test"], st, "{}", o.body);
    // зависший running (файл давно не обновлялся — сценарий убит) не мешает
    let f = std::fs::File::options().write(true).open(run.join("zapret-test.json")).unwrap();
    f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(600)).unwrap();
    drop(f);
    assert_eq!(call("POST", Some(br#"{"mode":"quick"}"#)).status, 202, "зависший running");
    std::fs::remove_file(run.join("zapret-test.request")).unwrap();
    // процесс сценария умер — сразу не running (только где есть /proc)
    if std::path::Path::new("/proc/self").exists() {
        let mut dead = st.clone();
        dead["pid"] = json!(u32::MAX);
        std::fs::write(run.join("zapret-test.json"), dead.to_string()).unwrap();
        assert_eq!(call("POST", Some(br#"{"mode":"quick"}"#)).status, 202, "умерший сценарий");
        std::fs::remove_file(run.join("zapret-test.request")).unwrap();
    }
    // без CSRF и с чужим Origin заявка не принимается
    let o = p.a.cgi("POST", "/zapret/test", Some(br#"{"mode":"quick"}"#), p.t + 1, &[("HTTP_COOKIE", p.s.cookie.as_str()), ("HTTP_ORIGIN", ORIGIN), ("MI_TT_RUN_DIR", rd.as_str())]);
    assert_eq!(o.code(), "csrf_failed", "{}", o.body);
    let o = p.a.cgi("POST", "/zapret/test", Some(br#"{"mode":"quick"}"#), p.t + 1,
        &[("HTTP_COOKIE", p.s.cookie.as_str()), ("HTTP_ORIGIN", "https://evil.example"), ("HTTP_X_MITT_CSRF", p.s.csrf.as_str()), ("MI_TT_RUN_DIR", rd.as_str())]);
    assert_eq!(o.code(), "origin_forbidden", "{}", o.body);
    assert!(!run.join("zapret-test.request").exists());
    // завершённый подбор — можно снова
    let mut done = st.clone();
    done["state"] = json!("done");
    std::fs::write(run.join("zapret-test.json"), done.to_string()).unwrap();
    assert_eq!(call("POST", Some(br#"{"mode":"quick"}"#)).status, 202);
}
