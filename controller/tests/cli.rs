//! Сквозные проверки собранного бинарника: CLI и CGI-режим на корректном и ошибочном вводе.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

mod common;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mi-tt-ctl")
}

fn fixture(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("fixtures").join(name);
    p.to_string_lossy().into_owned()
}

fn tmp(name: &str, content: &str) -> String {
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&p, content).unwrap();
    p.to_string_lossy().into_owned()
}

fn run(args: &[&str]) -> (i32, Value) {
    let o = Command::new(bin()).args(args).output().unwrap();
    let v: Value = serde_json::from_slice(&o.stdout).unwrap_or(Value::Null);
    (o.status.code().unwrap(), v)
}

fn codes(v: &Value) -> Vec<String> {
    v["issues"].as_array().unwrap().iter().map(|i| format!("{}:{}", i["path"].as_str().unwrap(), i["code"].as_str().unwrap())).collect()
}

fn cgi(method: &str, path: &str, ctype: Option<&str>, body: Option<&[u8]>, length: Option<&str>, config: &str) -> (u16, Value, String) {
    let mut c = Command::new(bin());
    c.arg("cgi")
        .env_clear()
        .env("MI_TT_CONFIG", config)
        .env("REQUEST_METHOD", method)
        .env("PATH_INFO", path)
        .envs(common::shared_env(true))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    if let Some(t) = ctype {
        c.env("CONTENT_TYPE", t);
    }
    let len = length.map(str::to_string).or(body.map(|b| b.len().to_string()));
    if let Some(l) = len {
        c.env("CONTENT_LENGTH", l);
    }
    let mut child = c.spawn().unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        if let Some(b) = body {
            let _ = stdin.write_all(b);
        }
    }
    let Output { stdout, status, .. } = child.wait_with_output().unwrap();
    assert!(status.success());
    let text = String::from_utf8(stdout).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("CGI headers");
    let code: u16 = head.strip_prefix("Status: ").unwrap()[..3].parse().unwrap();
    assert!(head.contains("Content-Type: application/json"));
    assert!(head.contains(&format!("Content-Length: {}", body.len())));
    (code, serde_json::from_str(body).unwrap(), head.to_string())
}

#[test]
fn version_and_usage() {
    let o = Command::new(bin()).arg("--version").output().unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("mi-tt-ctl 0.1.0"));
    let o = Command::new(bin()).arg("apply").output().unwrap();
    assert_eq!(o.status.code(), Some(2), "неизвестная команда, в том числе apply, не поддерживается");
}

#[test]
fn valid_config_reads_and_normalizes_nothing_destructive() {
    let (code, v) = run(&["validate", &fixture("config.valid.json")]);
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(v["ok"], true);
    assert_eq!(v["config"]["rules"].as_array().unwrap().len(), 2);
}

#[test]
fn tv_trusttunnel_preview_acceptance_example() {
    let (code, v) = run(&["preview", &fixture("config.valid.json"), &fixture("request.tv-video-trusttunnel.json")]);
    assert_eq!(code, 0, "{v:#}");
    let p = &v["preview"];
    assert_eq!(p["applied"], false);
    assert_eq!(p["mode"], "add");
    assert_eq!(p["level"], 1);
    assert_eq!(p["position"], 1, "правило устройства вычисляется раньше правил сетей");
    assert_eq!(p["order"].as_array().unwrap().len(), 3);
    assert_eq!(p["affected_devices"][0]["mac"], "a4:77:33:10:20:30");
    assert_eq!(p["on_failure"], "блокировать трафик правила");
    assert_eq!(p["match_entries"].as_array().unwrap().len(), 4);
    let f: Vec<&str> = p["findings"].as_array().unwrap().iter().map(|x| x["code"].as_str().unwrap()).collect();
    assert!(f.contains(&"overrides"), "должно показать, что VLESS-правило сети больше не действует на ТВ: {f:?}");
    assert!(f.contains(&"fail_closed"));
    assert!(!f.contains(&"shadowed_by"));
    let probes = p["probes"].as_array().unwrap();
    // ТВ: было VLESS по правилу сети, стало TrustTunnel по правилу устройства
    assert_eq!(probes[0]["before"]["rule_id"], "r-home-video");
    assert_eq!(probes[0]["after"]["rule_id"], "r-tv-video");
    assert!(probes[0]["after"]["exit"].as_str().unwrap().contains("TrustTunnel"));
    assert_eq!(probes[0]["changed"], true);
    // соседний телефон продолжает идти через VLESS
    assert_eq!(probes[1]["after"]["rule_id"], "r-home-video");
    assert_eq!(probes[1]["changed"], false);
    // гости — напрямую
    assert_eq!(probes[2]["after"]["rule_id"], "r-guest-direct");
    // IP из подсети группы
    assert_eq!(probes[3]["after"]["rule_id"], "r-tv-video");
    // посторонний домен — маршрут по умолчанию
    assert_eq!(probes[4]["after"]["rule_id"], Value::Null);
}

#[test]
fn replace_and_shadowing() {
    let req = r#"{"rule":{"id":"r-guest-direct","source":{"type":"lan"},"destination":{"type":"domain","value":"WWW.YouTube.com."},"action":{"type":"block"}}}"#;
    let (code, v) = run(&["preview", &fixture("config.valid.json"), &tmp("shadow.json", req)]);
    assert_eq!(code, 0, "{v:#}");
    let p = &v["preview"];
    assert_eq!(p["mode"], "replace");
    assert_eq!(p["rule"]["destination"]["value"], "www.youtube.com", "домен нормализован");
    assert_eq!(p["position"], 2);
    let f: Vec<&str> = p["findings"].as_array().unwrap().iter().map(|x| x["code"].as_str().unwrap()).collect();
    assert!(f.contains(&"partially_shadowed_by"), "{f:?}");
}

#[test]
fn fully_shadowed_rule_is_reported() {
    let req = r#"{"rule":{"id":"r-yt","source":{"type":"network","id":"home"},"destination":{"type":"domain_suffix","value":"m.youtube.com"},"action":{"type":"profile","id":"tt-home"}}}"#;
    let (code, v) = run(&["preview", &fixture("config.valid.json"), &tmp("full.json", req)]);
    assert_eq!(code, 0, "{v:#}");
    let f: Vec<&str> = v["preview"]["findings"].as_array().unwrap().iter().map(|x| x["code"].as_str().unwrap()).collect();
    assert!(f.contains(&"shadowed_by") && f.contains(&"never_matches"), "{f:?}");
}

#[test]
fn unknown_references_are_rejected() {
    let (code, v) = run(&["preview", &fixture("config.valid.json"), &fixture("invalid/request.unknown-refs.json")]);
    assert_eq!(code, 1);
    assert_eq!(v["error"]["code"], "rule_invalid");
    assert_eq!(codes(&v), ["rule.source.id:unknown_device", "rule.destination.id:unknown_group", "rule.action.id:unknown_profile"]);
}

#[test]
fn host_bits_in_cidr_are_rejected_with_hint() {
    let (code, v) = run(&["preview", &fixture("config.valid.json"), &fixture("invalid/request.bad-destination.json")]);
    assert_eq!(code, 1);
    assert_eq!(codes(&v), ["rule.destination.value:bad_cidr"]);
    assert!(v["issues"][0]["message"].as_str().unwrap().contains("203.0.113.0/24"));
}

#[test]
fn unknown_fields_are_rejected_with_path() {
    let (code, v) = run(&["preview", &fixture("config.valid.json"), &fixture("invalid/request.unknown-field.json")]);
    assert_eq!(code, 1);
    assert_eq!(v["error"]["code"], "bad_request");
    assert_eq!(v["issues"][0]["code"], "parse");
    assert_eq!(v["issues"][0]["path"], "rule.source");
    assert!(v["issues"][0]["message"].as_str().unwrap().contains("mac"));
}

#[test]
fn malformed_and_trailing_json_are_rejected() {
    for (name, body) in [("trailing.json", r#"{"rule":{"id":"x","source":{"type":"lan"},"destination":{"type":"domain","value":"a.com"},"action":{"type":"direct"}}} {}"#),
                         ("comma.json", r#"{"rule":{"id":"x",}}"#),
                         ("empty.json", ""),
                         ("wildcard.json", r#"{"rule":{"id":"x","source":{"type":"lan"},"destination":{"type":"domain","value":"*.a.com"},"action":{"type":"direct"}}}"#),
                         ("badtype.json", r#"{"rule":{"id":"x","source":{"type":"router"},"destination":{"type":"domain","value":"a.com"},"action":{"type":"direct"}}}"#)] {
        let (code, v) = run(&["preview", &fixture("config.valid.json"), &tmp(name, body)]);
        assert_eq!(code, 1, "{name}: {v:#}");
        assert_eq!(v["ok"], false, "{name}");
        assert!(!v["issues"].as_array().unwrap().is_empty(), "{name}");
    }
}

#[test]
fn bad_probes_are_rejected() {
    let req = r#"{"rule":{"id":"x","source":{"type":"lan"},"destination":{"type":"domain","value":"a.com"},"action":{"type":"direct"}},
                  "probes":[{"host":"a.com"},{"device":"tv","network":"home","host":"a.com"},{"device":"tv","host":"bad host"}]}"#;
    let (code, v) = run(&["preview", &fixture("config.valid.json"), &tmp("probes.json", req)]);
    assert_eq!(code, 1);
    assert_eq!(codes(&v), ["probes[0]:bad_probe", "probes[1]:bad_probe", "probes[2].host:bad_host"]);
}

#[test]
fn broken_config_lists_every_problem() {
    let (code, v) = run(&["validate", &fixture("invalid/config.broken.json")]);
    assert_eq!(code, 1);
    assert_eq!(
        codes(&v),
        [
            "networks[1].ssid:ambiguous_ssid",
            "devices[1].mac:duplicate_mac",
            "devices[1].network:unknown_network",
            "groups[0].destinations[0].value:bad_domain",
            "rules[0].action.id:unknown_profile",
        ]
    );
    // предпросмотр поверх сломанных настроек не строится
    let (code, v) = run(&["preview", &fixture("invalid/config.broken.json"), &fixture("request.tv-video-trusttunnel.json")]);
    assert_eq!(code, 1);
    assert_eq!(v["error"]["code"], "config_invalid");
}

#[test]
fn version_and_missing_config() {
    let (code, v) = run(&["validate", &tmp("v2.json", r#"{"version":2,"default_action":{"type":"direct"}}"#)]);
    assert_eq!(code, 1);
    assert_eq!(codes(&v), ["version:unsupported_version"]);
    let (code, v) = run(&["validate", "no-such-config.json"]);
    assert_eq!(code, 2);
    assert_eq!(v["error"]["code"], "config_unreadable");
}

#[test]
fn oversized_config_is_refused() {
    let big = format!(r#"{{"version":1,"default_action":{{"type":"direct"}},"x":"{}"}}"#, "a".repeat(1024 * 1024));
    let (code, v) = run(&["validate", &tmp("big.json", &big)]);
    assert_eq!(code, 2);
    assert!(v["error"]["message"].as_str().unwrap().contains("больше"));
}

#[test]
fn cgi_paths() {
    let cfg = fixture("config.valid.json");
    let (s, v, head) = cgi("GET", "/config", None, None, None, &cfg);
    assert_eq!(s, 200);
    assert_eq!(v["ok"], true);
    assert!(head.contains("Cache-Control: no-store"));

    let body = std::fs::read(fixture("request.tv-video-trusttunnel.json")).unwrap();
    let (s, v, _) = cgi("POST", "/preview", Some("application/json"), Some(&body), None, &cfg);
    assert_eq!(s, 200);
    assert_eq!(v["preview"]["probes"][0]["changed"], true);

    let bad = std::fs::read(fixture("invalid/request.unknown-refs.json")).unwrap();
    assert_eq!(cgi("POST", "/preview", Some("application/json"), Some(&bad), None, &cfg).0, 422);
    assert_eq!(cgi("POST", "/preview", Some("application/json"), Some(b"{oops"), None, &cfg).0, 400);
    assert_eq!(cgi("POST", "/preview", Some("text/plain"), Some(&body), None, &cfg).0, 415);
    assert_eq!(cgi("POST", "/preview", Some("application/json"), None, None, &cfg).0, 411);
    assert_eq!(cgi("POST", "/preview", Some("application/json"), Some(b"{}"), Some("70000"), &cfg).0, 413);
    assert_eq!(cgi("POST", "/preview", Some("application/json"), Some(b"{}"), Some("10"), &cfg).0, 400, "короткое тело");
    assert_eq!(cgi("DELETE", "/config", None, None, None, &cfg).0, 405);
    assert_eq!(cgi("POST", "/apply", Some("application/json"), Some(b"{}"), None, &cfg).0, 404);
    assert_eq!(cgi("GET", "/config", None, None, None, "missing.json").0, 500);
    let broken = fixture("invalid/config.broken.json");
    assert_eq!(cgi("POST", "/preview", Some("application/json"), Some(&body), None, &broken).0, 409);
}
