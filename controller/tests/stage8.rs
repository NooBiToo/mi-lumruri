//! Этап 8: профили VLESS (TLS и REALITY, XTLS vision) и WireGuard/AmneziaWG — проверка, секреты, рендер Mihomo.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::*;

fn tmp(name: &str, content: &str) -> String {
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s8-{}-{name}", rand_hex(6)));
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

// Ключи и uuid() — случайные на каждый прогон тестов (без постоянного ключевого материала в исходниках).
fn once(c: &'static std::sync::OnceLock<String>, f: fn() -> String) -> &'static str {
    c.get_or_init(f).as_str()
}
fn b64_32() -> String {
    data_encoding::BASE64.encode(&random_bytes::<32>())
}
fn key() -> &'static str {
    static C: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    once(&C, b64_32)
}
fn rpub() -> &'static str {
    static C: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    once(&C, || data_encoding::BASE64URL_NOPAD.encode(&random_bytes::<32>()))
}
fn uuid() -> &'static str {
    static C: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    once(&C, || {
        let h = rand_hex(32);
        format!("{}-{}-4{}-a{}-{}", &h[0..8], &h[8..12], &h[13..16], &h[17..20], &h[20..32])
    })
}

fn awg() -> Value {
    json!({ "jc": 4, "jmin": 40, "jmax": 70, "s1": 37, "s2": 61, "h1": 1361409513u32, "h2": 2016328541u32, "h3": 726101713u32, "h4": 1919296617u32 })
}

fn cfg(profiles: Value, rule_profile: &str) -> Value {
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(fixture("lab/config.json")).unwrap()).unwrap();
    c["profiles"] = profiles;
    c["rules"] = json!([{ "id": "r1", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "video" },
        "action": { "type": "profile", "id": rule_profile } }]);
    c
}

fn render(c: &Value, s: &Value) -> (i32, Value, Option<Value>) {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s8-out-{}", rand_hex(6)));
    let (code, v) = run(&["render", &tmp("c.json", &c.to_string()), &tmp("s.json", &s.to_string()),
        &tmp("l", "1999999999 02:00:00:00:0a:02 10.10.1.2 tv *\n"), out.to_str().unwrap()]);
    (code, v, std::fs::read(out.join("config.yaml")).ok().map(|b| serde_json::from_slice(&b).unwrap()))
}

#[test]
fn vless_and_wireguard_validation() {
    let bad = json!({ "version": 1, "default_action": { "type": "direct" }, "profiles": [
        { "id": "v1", "name": "V1", "kind": "vless", "endpoint": { "server": "10.0.0.1", "port": 443 } },
        { "id": "v2", "name": "V2", "kind": "vless", "endpoint": { "server": "10.0.0.1", "port": 443, "security": "tls" } },
        { "id": "v3", "name": "V3", "kind": "vless", "endpoint": { "server": "10.0.0.1", "port": 443, "security": "reality", "cert_sha256": "ab".repeat(32),
            "reality": { "public_key": "short", "short_id": "xyz" }, "client_fingerprint": "netscape", "public_key": key() } },
        { "id": "w1", "name": "W1", "kind": "wireguard", "endpoint": { "server": "10.0.0.1", "port": 51820, "sni": "a.b", "public_key": "bad", "address": "10.66.66.2/24", "mtu": 9000,
            "awg": { "jc": 200, "jmin": 80, "jmax": 70, "s1": 10, "s2": 66, "h1": 1, "h2": 7, "h3": 7, "h4": 9 } } },
        { "id": "w2", "name": "W2", "kind": "wireguard", "endpoint": { "server": "wg.example.com", "port": 51820, "security": "tls" } },
        { "id": "t1", "name": "T1", "kind": "trusttunnel", "endpoint": { "server": "10.0.0.1", "port": 443, "username": "u", "awg": awg() } }
    ]});
    let (code, v) = run(&["validate", &tmp("bad.json", &bad.to_string())]);
    assert_eq!(code, 1);
    assert_eq!(
        codes(&v),
        [
            "profiles[0].endpoint.security:required",
            "profiles[1].endpoint:tls_unverifiable",
            "profiles[2].endpoint.public_key:not_applicable",
            "profiles[2].endpoint.cert_sha256:not_applicable",
            "profiles[2].endpoint.reality.public_key:bad_key",
            "profiles[2].endpoint.reality.short_id:bad_short_id",
            "profiles[2].endpoint.sni:required",
            "profiles[2].endpoint.client_fingerprint:bad_fingerprint",
            "profiles[3].endpoint.sni:not_applicable",
            "profiles[3].endpoint.public_key:bad_key",
            "profiles[3].endpoint.address:bad_address",
            "profiles[3].endpoint.mtu:bad_mtu",
            "profiles[3].endpoint.awg.jc:bad_awg",
            "profiles[3].endpoint.awg.jmax:bad_awg",
            "profiles[3].endpoint.awg.s2:bad_awg",
            "profiles[3].endpoint.awg.h1:bad_awg",
            "profiles[4].endpoint.security:not_applicable",
            "profiles[4].endpoint.public_key:required",
            "profiles[4].endpoint.address:required",
            "profiles[5].endpoint.awg:not_applicable",
        ]
    );
}

#[test]
fn vless_reality_and_tls_render() {
    let reality = json!([{ "id": "vl", "name": "VL", "kind": "vless", "endpoint": { "server": "vpn.example.com", "port": 443, "sni": "www.example.org",
        "security": "reality", "flow": "xtls-rprx-vision", "reality": { "public_key": rpub(), "short_id": "0123abcd" } } }]);
    let s = json!({ "version": 1, "profiles": { "vl": { "uuid": uuid() } } });
    let (code, v, mh) = render(&cfg(reality, "vl"), &s);
    assert_eq!(code, 0, "{v}");
    let p = &mh.unwrap()["proxies"][0];
    assert_eq!((p["type"].as_str(), p["uuid"].as_str(), p["tls"].as_bool(), p["skip-cert-verify"].as_bool()), (Some("vless"), Some(uuid()), Some(true), Some(false)));
    assert_eq!(p["reality-opts"], json!({ "public-key": rpub(), "short-id": "0123abcd" }));
    assert_eq!((p["servername"].as_str(), p["flow"].as_str(), p["client-fingerprint"].as_str()), (Some("www.example.org"), Some("xtls-rprx-vision"), Some("chrome")));
    assert!(!v.to_string().contains(uuid()), "UUID не попадает в ответ CLI");

    let tls = json!([{ "id": "vl", "name": "VL", "kind": "vless", "endpoint": { "server": "10.0.0.1", "port": 443, "sni": "vpn.example.com",
        "security": "tls", "cert_sha256": "AB:".repeat(31) + "AB", "client_fingerprint": "firefox" } }]);
    let (code, _, mh) = render(&cfg(tls, "vl"), &s);
    assert_eq!(code, 0);
    let p = &mh.unwrap()["proxies"][0];
    assert_eq!((p["fingerprint"].as_str(), p["client-fingerprint"].as_str()), (Some("ab".repeat(32).as_str()), Some("firefox")));
    assert!(p.get("reality-opts").is_none() && p.get("flow").is_none());

    // секреты: нужен uuid, password к VLESS не относится
    for (sec, why) in [(json!({}), "без uuid"), (json!({ "uuid": "not-a-uuid" }), "кривой uuid"), (json!({ "uuid": uuid(), "password": rand_hex(16) }), "лишний password")] {  // secret-scan: allow заведомо неверный uuid для отрицательной проверки
        let (code, v, mh) = render(&cfg(json!([{ "id": "vl", "name": "VL", "kind": "vless", "endpoint": { "server": "vpn.example.com", "port": 443, "security": "tls" } }]), "vl"),
            &json!({ "version": 1, "profiles": { "vl": sec } }));
        assert_eq!((code, codes(&v), mh.is_none()), (1, vec!["rules[0].action:bad_secret".to_string()], true), "{why}");
    }
}

#[test]
fn amneziawg_render_and_secrets() {
    let wg = json!([{ "id": "aw", "name": "AW", "kind": "wireguard", "endpoint": { "server": "wg.example.com", "port": 51820, "public_key": key(),
        "address": "10.66.66.2/32", "mtu": 1380, "awg": awg() } }]);
    let (pk, psk) = (b64_32(), b64_32());
    let (pk, psk) = (pk.as_str(), psk.as_str());
    let (code, v, mh) = render(&cfg(wg.clone(), "aw"), &json!({ "version": 1, "profiles": { "aw": { "private_key": pk, "preshared_key": psk } } }));
    assert_eq!(code, 0, "{v}");
    let p = &mh.unwrap()["proxies"][0];
    assert_eq!((p["type"].as_str(), p["ip"].as_str(), p["mtu"].as_u64()), (Some("wireguard"), Some("10.66.66.2"), Some(1380)));
    assert_eq!((p["private-key"].as_str(), p["public-key"].as_str(), p["pre-shared-key"].as_str()), (Some(pk), Some(key()), Some(psk)));
    assert_eq!(p["allowed-ips"], json!(["0.0.0.0/0"]));
    assert_eq!(p["amnezia-wg-option"], json!({ "jc": 4, "jmin": 40, "jmax": 70, "s1": 37, "s2": 61, "h1": "1361409513", "h2": "2016328541", "h3": "726101713", "h4": "1919296617" }));
    assert!(!v.to_string().contains(pk) && !v.to_string().contains(psk));
    // обычный WireGuard — без amnezia-wg-option
    let mut plain = wg.clone();
    plain[0]["endpoint"].as_object_mut().unwrap().remove("awg");
    let (_, _, mh) = render(&cfg(plain, "aw"), &json!({ "version": 1, "profiles": { "aw": { "private_key": pk } } }));
    assert!(mh.unwrap()["proxies"][0].get("amnezia-wg-option").is_none());
    for sec in [json!({}), json!({ "private_key": "short" }), json!({ "private_key": pk, "preshared_key": "x" }), json!({ "private_key": pk, "uuid": uuid() })] {  // secret-scan: allow заведомо короткий ключ для отрицательной проверки
        let (code, v, _) = render(&cfg(wg.clone(), "aw"), &json!({ "version": 1, "profiles": { "aw": sec } }));
        assert_eq!((code, codes(&v)), (1, vec!["rules[0].action:bad_secret".to_string()]));
    }
}

#[test]
fn two_profiles_device_and_ssid_rules_render_in_order() {
    let mut c = cfg(json!([
        { "id": "vl", "name": "VL", "kind": "vless", "endpoint": { "server": "vpn.example.com", "port": 443, "security": "tls" } },
        { "id": "aw", "name": "AW", "kind": "wireguard", "endpoint": { "server": "wg.example.com", "port": 51820, "public_key": key(), "address": "10.66.66.2/32", "awg": awg() } }
    ]), "vl");
    c["groups"].as_array_mut().unwrap().push(json!({ "id": "wide", "name": "Широкая", "destinations": [{ "type": "cidr", "value": "10.96.0.0/14" }] }));
    c["rules"] = json!([
        { "id": "r-tv-video", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "video" }, "action": { "type": "profile", "id": "vl" } },
        { "id": "r-tv-wide", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "wide" }, "action": { "type": "block" } },
        { "id": "r-guest", "source": { "type": "network", "id": "guest" }, "destination": { "type": "group", "id": "video" }, "action": { "type": "profile", "id": "aw" } }
    ]);
    let s = json!({ "version": 1, "profiles": { "vl": { "uuid": uuid() }, "aw": { "private_key": key() } } });
    let (code, v, mh) = render(&c, &s);
    assert_eq!(code, 0, "{v}");
    let mh = mh.unwrap();
    assert_eq!(mh["proxies"].as_array().unwrap().len(), 2);
    let rules: Vec<&str> = mh["rules"].as_array().unwrap().iter().map(|r| r.as_str().unwrap()).collect();
    let pos = |needle: &str| rules.iter().position(|r| r.contains(needle)).unwrap_or(usize::MAX);
    assert!(pos(",vl") < pos("10.96.0.0/14"), "{rules:?}");
    assert!(rules.iter().any(|r| r.contains("10.10.2.0/24") && r.ends_with(",aw")), "{rules:?}");
    assert_eq!(v["capture"]["networks"][0]["id"], "guest");
}
