//! Подписка TrustTunnel 1.3: `mi-tt-ctl subscription-url` и `subscription-import` — перенос ответа сервера в настройки
//! профиля и secrets.json, заявка на применение, «ничего не изменилось — ничего не пишется», отказ без изменений.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::*;

struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("sub-{}", rand_hex(6)));
        std::fs::create_dir_all(d.join("run")).unwrap();
        Dir(d)
    }
    fn p(&self, n: &str) -> String {
        self.0.join(n).to_string_lossy().into_owned()
    }
    fn run(&self, args: &[&str]) -> (i32, Value, String) {
        let o = Command::new(ctl()).args(args).env("MI_TT_RUN_DIR", self.p("run")).output().unwrap();
        (o.status.code().unwrap(), serde_json::from_slice(&o.stdout).unwrap_or(Value::Null), String::from_utf8_lossy(&o.stdout).into_owned())
    }
    fn json(&self, n: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(self.0.join(n)).unwrap()).unwrap()
    }
}

fn setup(endpoint: Option<Value>) -> Dir {
    let d = Dir::new();
    let mut p = json!({ "id": "tt", "name": "Мой сервер", "kind": "trusttunnel", "on_failure": "block" });
    if let Some(e) = endpoint {
        p["endpoint"] = e;
    }
    let cfg = json!({ "version": 1, "profiles": [p], "networks": [], "devices": [], "groups": [], "rules": [], "default_action": { "type": "direct" } });
    std::fs::write(d.0.join("config.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    std::fs::write(d.0.join("secrets.json"), json!({ "version": 1, "profiles": { "tt": { "subscription_url": "https://alice:pw@vpn.example.com/subscription" } } }).to_string()).unwrap();
    d
}

const SUB: &str = r#"{"version":1,"hostname":"vpn.example.com","address":"203.0.113.1:443","username":"alice","password":"s3cret-pw","has_ipv6":true,"upstream_protocol":"http2","anti_dpi":true,"skip_verification":false,"client_random_prefix":"a0b0/f0f0","name":"Acme VPN"}"#; // secret-scan: allow тестовый ответ подписки

#[test]
fn subscription_only_profile_gets_endpoint_and_password() {
    let d = setup(None);
    let (rc, _, out) = d.run(&["subscription-url", &d.p("config.json"), "tt"]);
    assert_eq!((rc, out.trim()), (0, "https://alice:pw@vpn.example.com/subscription"));
    assert_eq!(d.run(&["subscription-url", &d.p("config.json"), "other"]).0, 1);

    std::fs::write(d.0.join("sub.json"), SUB).unwrap();
    let (rc, v, _) = d.run(&["subscription-import", &d.p("config.json"), "tt", &d.p("sub.json")]);
    assert_eq!(rc, 0, "{v}");
    assert_eq!((&v["changed"], &v["endpoint"], &v["password"]), (&json!(true), &json!(true), &json!(true)), "{v}");
    let c = d.json("config.json");
    let e = &c["profiles"][0]["endpoint"];
    assert_eq!((&e["server"], &e["port"], &e["sni"], &e["username"], &e["anti_dpi"], &e["client_random"]),
        (&json!("203.0.113.1"), &json!(443), &json!("vpn.example.com"), &json!("alice"), &json!(true), &json!("a0b0/f0f0")), "{c}");
    let s = d.json("secrets.json");
    assert_eq!((&s["profiles"]["tt"]["password"], &s["profiles"]["tt"]["subscription_url"]),
        (&json!("s3cret-pw"), &json!("https://alice:pw@vpn.example.com/subscription")), "{s}"); // secret-scan: allow тестовый пароль
    assert!(d.0.join("run").join("apply.request").exists());

    // тот же ответ ещё раз — ничего не меняется и не пишется
    std::fs::remove_file(d.0.join("run").join("apply.request")).unwrap();
    let before = std::fs::read(d.0.join("config.json")).unwrap();
    let (rc, v, _) = d.run(&["subscription-import", &d.p("config.json"), "tt", &d.p("sub.json")]);
    assert_eq!((rc, &v["changed"]), (0, &json!(false)), "{v}");
    assert_eq!(std::fs::read(d.0.join("config.json")).unwrap(), before);
    assert!(!d.0.join("run").join("apply.request").exists());
}

#[test]
fn subscription_keeps_tls_profile_and_rejects_garbage() {
    let d = setup(Some(json!({ "server": "198.51.100.1", "port": 443, "username": "old", "quic": false, "anti_dpi": false, "tls_profile": "firefox" })));
    std::fs::write(d.0.join("sub.json"), SUB.replace("203.0.113.1:443", "vpn.example.com:8443")).unwrap();
    let (rc, v, _) = d.run(&["subscription-import", &d.p("config.json"), "tt", &d.p("sub.json")]);
    assert_eq!(rc, 0, "{v}");
    let e = &d.json("config.json")["profiles"][0]["endpoint"];
    assert_eq!((&e["server"], &e["port"], &e["tls_profile"], &e["sni"]), (&json!("vpn.example.com"), &json!(8443), &json!("firefox"), &Value::Null), "{e}");

    let before = std::fs::read(d.0.join("config.json")).unwrap();
    for bad in ["<html>login</html>", r#"{"hostname":"h","address":"x","username":"u","password":"p"}"#, r#"{"hostname":"h","address":"203.0.113.1:443","username":"bad:name","password":"p"}"#] {
        std::fs::write(d.0.join("bad.json"), bad).unwrap();
        let (rc, v, _) = d.run(&["subscription-import", &d.p("config.json"), "tt", &d.p("bad.json")]);
        assert_ne!(rc, 0, "{bad}: {v}");
        assert_eq!(std::fs::read(d.0.join("config.json")).unwrap(), before, "{bad}");
    }
}
