//! Этап 7: профиль Hysteria2 — проверка, сохранение через защищённый API и рендер для Mihomo;
//! совместимость TrustTunnel-конфигураций; проверка TLS не отключается.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::*;

fn tmp(name: &str, content: &str) -> String {
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s7-{}-{name}", rand_hex(6)));
    std::fs::write(&p, content).unwrap();
    p.to_string_lossy().into_owned()
}

fn run(args: &[&str]) -> (i32, Value) {
    let o = Command::new(ctl()).args(args).output().unwrap();
    (o.status.code().unwrap(), serde_json::from_slice(&o.stdout).unwrap_or(Value::Null))
}

fn codes(v: &Value) -> Vec<String> {
    v["issues"].as_array().unwrap().iter().map(|i| format!("{}:{}", i["path"].as_str().unwrap(), i["code"].as_str().unwrap())).collect()
}

fn lab(rule_profile: &str) -> Value {
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(fixture("lab/config.hy2.json")).unwrap()).unwrap();
    c["rules"] = json!([{ "id": "r1", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "video" },
        "action": { "type": "profile", "id": rule_profile } }]);
    c
}

fn render(cfg: &Value, secrets: &Value) -> (i32, Value, Option<Value>) {
    let c = tmp("config.json", &cfg.to_string());
    let s = tmp("secrets.json", &secrets.to_string());
    let l = tmp("leases", "1999999999 02:00:00:00:0a:02 10.10.1.2 tv *\n");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s7-out-{}", rand_hex(6)));
    let (code, v) = run(&["render", &c, &s, &l, out.to_str().unwrap()]);
    let mh = std::fs::read(out.join("config.yaml")).ok().map(|b| serde_json::from_slice(&b).unwrap());
    (code, v, mh)
}

fn secret() -> String {
    format!("s-{}", rand_hex(20))
}

#[test]
fn hysteria2_endpoint_validation() {
    let bad = json!({ "version": 1, "default_action": { "type": "direct" }, "profiles": [
        { "id": "h1", "name": "H1", "kind": "hysteria2", "endpoint": { "server": "10.0.0.1", "port": 443, "username": "u", "quic": true } },
        { "id": "h2", "name": "H2", "kind": "hysteria2", "endpoint": { "server": "hy.example.com", "port": 0, "sni": "*.x" } },
        { "id": "t1", "name": "T1", "kind": "trusttunnel", "endpoint": { "server": "10.0.0.1", "port": 443, "username": "u", "obfs": "salamander" } },
        { "id": "t2", "name": "T2", "kind": "trusttunnel", "endpoint": { "server": "10.0.0.1", "port": 443 } }
    ]});
    let (code, v) = run(&["validate", &tmp("bad.json", &bad.to_string())]);
    assert_eq!(code, 1);
    assert_eq!(
        codes(&v),
        [
            "profiles[0].endpoint.username:not_applicable",
            "profiles[0].endpoint.quic:not_applicable",
            "profiles[0].endpoint:tls_unverifiable",
            "profiles[1].endpoint.port:bad_port",
            "profiles[1].endpoint.sni:bad_sni",
            "profiles[2].endpoint.obfs:not_applicable",
            "profiles[3].endpoint.username:bad_username",
        ]
    );
    // допустимые варианты проверки TLS: IP + SNI, IP + закреплённый сертификат, доменное имя
    let ok = json!({ "version": 1, "default_action": { "type": "direct" }, "profiles": [
        { "id": "a", "name": "A", "kind": "hysteria2", "endpoint": { "server": "10.0.0.1", "port": 443, "sni": "hy.example.com" } },
        { "id": "b", "name": "B", "kind": "hysteria2", "endpoint": { "server": "10.0.0.1", "port": 443, "cert_sha256": "ab".repeat(32) } },
        { "id": "c", "name": "C", "kind": "hysteria2", "endpoint": { "server": "hy.example.com", "port": 8443, "obfs": "salamander" } }
    ]});
    let (code, v) = run(&["validate", &tmp("ok.json", &ok.to_string())]);
    assert_eq!(code, 0, "{v}");
    // в ответе API у Hysteria2 нет пустого username
    assert!(v["config"]["profiles"][0]["endpoint"].get("username").is_none());
}

#[test]
fn hysteria2_render_keeps_tls_verification_and_secrets_out_of_api() {
    let (pw, ob) = (secret(), secret());
    let (code, v, mh) = render(&lab("hy2-lab"), &json!({ "version": 1, "profiles": { "hy2-lab": { "password": pw, "obfs_password": ob } } }));
    assert_eq!(code, 0, "{v}");
    let mh = mh.unwrap();
    let p = &mh["proxies"][0];
    assert_eq!(p["type"], "hysteria2");
    assert_eq!(p["skip-cert-verify"], false);
    assert_eq!(p["fingerprint"], "ee".repeat(32)  /* заглушка фикстуры: лаборатории ставят отпечаток эфемерного сертификата */);
    assert_eq!(p["sni"], "vpn.lab.test");
    assert_eq!((p["obfs"].as_str(), p["obfs-password"].as_str(), p["password"].as_str()), (Some("salamander"), Some(ob.as_str()), Some(pw.as_str())));
    assert_eq!(p["alpn"], json!(["h3"]));
    assert!(p.get("username").is_none() && p.get("quic").is_none());
    assert_eq!(mh["proxies"].as_array().unwrap().len(), 1, "неиспользуемый TrustTunnel-профиль не попадает в Mihomo");
    assert!(v["rules"].as_array().unwrap().iter().any(|r| r.as_str().unwrap().ends_with(",hy2-lab")));
    // пароль и obfs не попадают в ответ CLI (он же уходит в журналы)
    assert!(!v.to_string().contains(&pw) && !v.to_string().contains(&ob));

    // obfs без пароля обфускации и пароль без obfs — отказ, ничего не записывается
    let (code, v, mh) = render(&lab("hy2-lab"), &json!({ "version": 1, "profiles": { "hy2-lab": { "password": pw } } }));
    assert_eq!((code, mh.is_none()), (1, true));
    assert_eq!(codes(&v), ["rules[0].action:obfs_secret_mismatch"]);
    let mut c = lab("hy2-lab");
    c["profiles"][1]["endpoint"].as_object_mut().unwrap().remove("obfs");
    let (code, v, _) = render(&c, &json!({ "version": 1, "profiles": { "hy2-lab": { "password": pw, "obfs_password": ob } } }));
    assert_eq!((code, codes(&v)), (1, vec!["rules[0].action:obfs_secret_mismatch".to_string()]));
    let (code, v, _) = render(&c, &json!({ "version": 1, "profiles": { "hy2-lab": { "password": "" } } }));
    assert_eq!((code, codes(&v)), (1, vec!["rules[0].action:bad_secret".to_string()]));
    // без obfs — валидно, ключей obfs нет
    let (code, _, mh) = render(&c, &json!({ "version": 1, "profiles": { "hy2-lab": { "password": pw } } }));
    assert_eq!(code, 0);
    assert!(mh.unwrap()["proxies"][0].get("obfs").is_none());
}

#[test]
fn trusttunnel_render_is_unchanged() {
    // существующая TrustTunnel-конфигурация этапов 2–6 формируется тем же набором ключей
    let pw = secret();
    let (code, v, mh) = render(&lab("tt-lab"), &json!({ "version": 1, "profiles": { "tt-lab": { "password": pw } } }));
    assert_eq!(code, 0, "{v}");
    let p = mh.unwrap()["proxies"][0].clone();
    let mut keys: Vec<&str> = p.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, ["fingerprint", "name", "password", "port", "quic", "server", "sni", "type", "udp", "username"]);
    assert_eq!((p["type"].as_str(), p["username"].as_str(), p["quic"].as_bool()), (Some("trusttunnel"), Some("tv-user"), Some(false)));
    // прежний secrets.json (только password) принимается
    let (code, _, _) = render(&lab("tt-lab"), &json!({ "version": 1, "profiles": { "tt-lab": { "password": pw } } }));
    assert_eq!(code, 0);
    // obfs_password у TrustTunnel — несогласованность, а не тихое игнорирование
    let (code, v, _) = render(&lab("tt-lab"), &json!({ "version": 1, "profiles": { "tt-lab": { "password": pw, "obfs_password": "x" } } }));
    assert_eq!((code, codes(&v)), (1, vec!["rules[0].action:obfs_secret_mismatch".to_string()]));
}

#[test]
fn unready_profiles_refused_and_flagged_in_preview() {
    let mut c = lab("hy2-lab");
    c["profiles"].as_array_mut().unwrap().push(json!({ "id": "vl", "name": "VLESS", "kind": "vless" }));
    c["rules"][0]["action"]["id"] = json!("vl");
    let (code, v, _) = render(&c, &json!({ "version": 1, "profiles": {} }));
    // с этапа 8 VLESS формируется, но профиль без точки подключения применить нельзя
    assert_eq!((code, codes(&v)), (1, vec!["rules[0].action:no_endpoint".to_string()]));
    let req = json!({ "rule": c["rules"][0], "probes": [] });
    let (_, v) = run(&["preview", &tmp("c.json", &c.to_string()), &tmp("r.json", &req.to_string())]);
    assert!(v["preview"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "profile_not_ready"), "{v}");
    let req = json!({ "rule": lab("hy2-lab")["rules"][0], "probes": [] });
    let (_, v) = run(&["preview", &tmp("c2.json", &lab("hy2-lab").to_string()), &tmp("r2.json", &req.to_string())]);
    assert!(!v["preview"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "profile_not_ready"), "{v}");
}

#[test]
fn hysteria2_rule_saved_only_through_authenticated_api() {
    let mut a = Auth::new("hy2");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s7-save-{}", rand_hex(6)));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::copy(fixture("lab/config.hy2.json"), &cfg).unwrap();
    a.config = cfg.to_string_lossy().into_owned();
    let t = T0 + 60;
    let body = |rev: &str| json!({ "base_revision": rev, "rule": lab("hy2-lab")["rules"][0] }).to_string().into_bytes();
    assert_eq!(a.cgi("GET", "/config", None, t, &[]).code(), "auth_required");
    let s = a.login(t);
    let o = a.api(&s, "GET", "/config", None, t + 1);
    let rev = o.body["revision"].as_str().unwrap().to_string();
    assert_eq!(o.body["config"]["profiles"][1]["kind"], "hysteria2");
    // без CSRF запись отклоняется
    let o = a.cgi("POST", "/rules", Some(&body(&rev)), t + 2, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", &s.cookie)]);
    assert_eq!(o.code(), "csrf_failed");
    let o = a.api(&s, "POST", "/rules", Some(&body(&rev)), t + 3);
    assert_eq!(o.status, 200, "{}", o.body);
    let saved: Value = serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
    assert_eq!(saved["rules"][0]["action"]["id"], "hy2-lab");
    assert_eq!(saved["profiles"][0]["endpoint"]["username"], "tv-user", "TrustTunnel-профиль сохранён без изменений");
}
