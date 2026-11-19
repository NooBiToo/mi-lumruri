//! API простой панели: сеть LAN роутера и замена настроек целиком. Всё через настоящий CGI после пароля и TOTP.

use std::path::PathBuf;

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
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("simple-{name}-{}", rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(fixture("lab/config.json"), dir.join("config.json")).unwrap();
        a.config = dir.join("config.json").to_string_lossy().into_owned();
        let t = T0 + 60;
        let s = a.login(t);
        Panel { a, s, t, dir }
    }
    fn run(&self) -> String {
        self.dir.join("run").to_string_lossy().into_owned()
    }
    fn get(&self, path: &str, extra: &[(&str, &str)]) -> Out {
        let mut e = vec![("HTTP_COOKIE", self.s.cookie.as_str())];
        e.extend_from_slice(extra);
        self.a.cgi("GET", path, None, self.t + 1, &e)
    }
    fn rev_cfg(&self) -> (String, Value) {
        let o = self.get("/config", &[]);
        (o.body["revision"].as_str().unwrap().to_string(), o.body["config"].clone())
    }
    fn replace(&self, body: Value) -> Out {
        let run = self.run();
        self.a.cgi("POST", "/config", Some(body.to_string().as_bytes()), self.t + 2, &[("HTTP_COOKIE", &self.s.cookie), ("HTTP_ORIGIN", ORIGIN),
            ("HTTP_SEC_FETCH_SITE", "same-origin"), ("HTTP_X_MITT_CSRF", &self.s.csrf), ("MI_TT_RUN_DIR", &run)])
    }
}

#[test]
fn router_reads_uci_lan() {
    let p = Panel::new("router");
    let stock = fixture("uci/network.stock");
    let o = p.get("/router", &[("MI_TT_UCI_NETWORK", &stock)]);
    assert_eq!(o.status, 200, "{}", o.body);
    assert_eq!(o.body["lan"], json!({ "bridge": "br-lan", "subnet": "192.168.31.0/24", "address": "192.168.31.1" }));
    // кавычки двойные, мост назван явно, маска не /24
    let f = p.dir.join("network");
    std::fs::write(&f, "config interface \"lan\"\n\toption device \"br-home\"\n\toption ipaddr \"10.10.1.1\"\n\toption netmask \"255.255.255.128\"\n").unwrap();
    let o = p.get("/router", &[("MI_TT_UCI_NETWORK", f.to_str().unwrap())]);
    assert_eq!(o.body["lan"], json!({ "bridge": "br-home", "subnet": "10.10.1.0/25", "address": "10.10.1.1" }), "{}", o.body);
    // нет файла или секции — 503
    let o = p.get("/router", &[("MI_TT_UCI_NETWORK", p.dir.join("none").to_str().unwrap())]);
    assert_eq!((o.status, o.code()), (503, "router_network_unavailable"));
    std::fs::write(&f, "config interface 'wan'\n\toption proto 'dhcp'\n").unwrap();
    let o = p.get("/router", &[("MI_TT_UCI_NETWORK", f.to_str().unwrap())]);
    assert_eq!(o.status, 503);
    assert!(o.body["error"]["message"].as_str().unwrap().contains("lan"));
}

#[test]
fn config_replace_validates_and_queues_apply() {
    let p = Panel::new("replace");
    let (rev, mut cfg) = p.rev_cfg();
    cfg["rules"] = json!([]);
    let o = p.replace(json!({ "base_revision": rev, "config": cfg }));
    assert_eq!(o.status, 200, "{}", o.body);
    assert_eq!(o.body["config"]["rules"], json!([]));
    assert_ne!(o.body["revision"].as_str().unwrap(), rev);
    assert!(p.dir.join("run/apply.request").exists());
    let on_disk: Value = serde_json::from_slice(&std::fs::read(p.dir.join("config.json")).unwrap()).unwrap();
    assert_eq!(on_disk["rules"], json!([]));
    // невалидная конфигурация: 422 с замечаниями, файл и заявка не тронуты
    std::fs::remove_file(p.dir.join("run/apply.request")).unwrap();
    let (rev, mut cfg) = p.rev_cfg();
    cfg["rules"] = json!([{ "id": "bad", "source": { "type": "device", "id": "no-such" }, "destination": { "type": "group", "id": "video" }, "action": { "type": "direct" } }]);
    let before = std::fs::read(p.dir.join("config.json")).unwrap();
    let o = p.replace(json!({ "base_revision": rev, "config": cfg }));
    assert_eq!((o.status, o.code()), (422, "config_invalid"), "{}", o.body);
    assert!(o.body["issues"][0]["path"].as_str().unwrap().starts_with("config."), "{}", o.body);
    assert!(!o.body["issues"].as_array().unwrap().is_empty());
    assert_eq!(std::fs::read(p.dir.join("config.json")).unwrap(), before);
    assert!(!p.dir.join("run/apply.request").exists());
}

#[test]
fn config_replace_recovers_invalid_stored_config() {
    let p = Panel::new("recover");
    let (_, good) = p.rev_cfg();
    let broken = b"{ not json".to_vec();
    std::fs::write(p.dir.join("config.json"), &broken).unwrap();
    let rev = mi_tt::store::revision(&broken);
    let o = p.replace(json!({ "base_revision": rev, "config": good }));
    assert_eq!(o.status, 200, "{}", o.body);
    assert!(p.dir.join("run/apply.request").exists());
    assert_eq!(std::fs::read(p.dir.join("config.json.prev")).unwrap(), broken);
    assert_eq!(p.rev_cfg().1, good);
}

#[test]
fn router_uci_parser_edge_cases() {
    let p = Panel::new("uci-edge");
    let f = p.dir.join("network");
    std::fs::write(&f, "config  interface  'lan'
	option  ipaddr  '1.1.1.1'
	option ipaddr	'10.1.2.3' # c
	option netmask '255.255.0.0'
	option ifname 'x#y'
").unwrap();
    let o = p.get("/router", &[("MI_TT_UCI_NETWORK", f.to_str().unwrap())]);
    assert_eq!(o.body["lan"], json!({ "bridge": "br-lan", "subnet": "10.1.0.0/16", "address": "10.1.2.3" }), "{}", o.body);
}

#[test]
fn config_replace_revision_conflict() {
    let p = Panel::new("conflict");
    let (_, cfg) = p.rev_cfg();
    let o = p.replace(json!({ "base_revision": "0".repeat(64), "config": cfg }));
    assert_eq!((o.status, o.code()), (409, "revision_conflict"), "{}", o.body);
    assert!(!p.dir.join("run/apply.request").exists());
}

#[test]
fn config_replace_requires_session_and_csrf() {
    let p = Panel::new("replace-auth");
    let (rev, cfg) = p.rev_cfg();
    let body = json!({ "base_revision": rev, "config": cfg }).to_string();
    let o = p.a.cgi("POST", "/config", Some(body.as_bytes()), p.t, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "same-origin")]);
    assert_eq!(o.code(), "auth_required");
    assert_eq!(p.a.cgi("GET", "/router", None, p.t, &[]).code(), "auth_required");
    let o = p.a.cgi("POST", "/config", Some(body.as_bytes()), p.t, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", &p.s.cookie)]);
    assert_eq!(o.code(), "csrf_failed");
    let o = p.a.cgi("POST", "/config", Some(body.as_bytes()), p.t, &[("HTTP_ORIGIN", "https://evil.example"), ("HTTP_COOKIE", &p.s.cookie), ("HTTP_X_MITT_CSRF", &p.s.csrf)]);
    assert_eq!((o.status, o.code()), (403, "origin_forbidden"), "{}", o.body);
    assert!(!p.dir.join("run/apply.request").exists());
}
