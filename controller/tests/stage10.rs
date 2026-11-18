//! Этап 10: шифрованный DNS (DoH/DoT/DoQ/DoH3, ODoH), блокировка рекламы — проверка настроек, файлы службы,
//! атомарное обновление списка.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::*;

fn dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s10-{}", rand_hex(8)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> (i32, Value) {
    let o = Command::new(ctl()).args(args).output().unwrap();
    (o.status.code().unwrap(), serde_json::from_slice(&o.stdout).unwrap_or(Value::Null))
}

fn codes(v: &Value) -> Vec<String> {
    v["issues"].as_array().unwrap().iter().map(|i| format!("{}:{}", i["path"].as_str().unwrap(), i["code"].as_str().unwrap())).collect()
}

fn base(dns: Value) -> Value {
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(fixture("lab/config.json")).unwrap()).unwrap();
    c["dns"] = dns;
    c
}

fn render(d: &PathBuf, c: &Value) -> (i32, Value) {
    let cfg = d.join("config.json");
    std::fs::write(&cfg, c.to_string()).unwrap();
    std::fs::write(d.join("s.json"), r#"{"version":1,"profiles":{}}"#).unwrap();
    std::fs::write(d.join("l"), "").unwrap();
    run(&["render", cfg.to_str().unwrap(), d.join("s.json").to_str().unwrap(), d.join("l").to_str().unwrap(), d.join("out").to_str().unwrap()])
}

#[test]
fn dns_settings_validation() {
    let d = dir();
    let bad = base(json!({ "transport": "doh", "servers": [{ "host": "dns", "ip": "dns.example" , "path": "dns-query" }], "odoh": { "target": { "host": "t.example", "ip": "1.1.1.1", "path": "/q" }, "relays": [] } }));
    std::fs::write(d.join("bad.json"), bad.to_string()).unwrap();
    let (code, v) = run(&["validate", d.join("bad.json").to_str().unwrap()]);
    assert_eq!(code, 1);
    assert_eq!(codes(&v), ["dns.odoh:not_applicable", "dns.servers[0].host:bad_host", "dns.servers[0].ip:bad_ip", "dns.servers[0].path:bad_path"]);
    let bad = base(json!({ "transport": "odoh", "servers": [{ "host": "dns.example", "ip": "1.1.1.1" }],
        "odoh": { "target": { "host": "t.example", "ip": "1.1.1.1", "path": "/dns-query" }, "relays": [{ "host": "t.example", "ip": "1.1.1.2", "path": "/proxy?x" }] },
        "adblock": { "enabled": true, "exceptions": ["bad domain"] } }));
    std::fs::write(d.join("bad2.json"), bad.to_string()).unwrap();
    let (_, v) = run(&["validate", d.join("bad2.json").to_str().unwrap()]);
    assert_eq!(codes(&v), ["dns.servers:not_applicable", "dns.odoh.relays[0].path:bad_path", "dns.odoh.relays:relay_is_target", "dns.adblock.exceptions[0]:bad_domain"]);
    let bad = base(json!({ "transport": "dot", "servers": [{ "host": "dns.example", "ip": "1.1.1.1", "path": "/x" }] }));
    std::fs::write(d.join("bad3.json"), bad.to_string()).unwrap();
    let (_, v) = run(&["validate", d.join("bad3.json").to_str().unwrap()]);
    assert_eq!(codes(&v), ["dns.servers[0].path:not_applicable"]);
}

#[test]
fn render_writes_dnsmasq_and_mihomo_dns_without_open_resolvers() {
    let d = dir();
    std::fs::write(d.join("list.txt"), "ads.example\n0.0.0.0 tracker.example\n").unwrap();
    let (code, v) = run(&["adblock-update", d.join("config.json").to_str().unwrap(), d.join("list.txt").to_str().unwrap()]);
    assert_eq!((code, v["domains"].as_u64()), (0, Some(2)), "{v}");
    let (code, v) = render(&d, &base(json!({ "transport": "doq", "servers": [{ "host": "dns.example", "ip": "9.9.9.9" }],
        "adblock": { "enabled": true, "exceptions": ["ok.ads.example"] } })));
    assert_eq!(code, 0, "{v}");
    let conf = std::fs::read_to_string(d.join("out/dnsmasq-mitt.conf")).unwrap();
    assert!(conf.contains("no-resolv\nserver=127.0.0.1#1053\n") && conf.contains("address=/ads.example/\naddress=/tracker.example/\n")
        && conf.contains("server=/ok.ads.example/127.0.0.1#1053\n"), "{conf}");
    let mh: Value = serde_json::from_slice(&std::fs::read(d.join("out/config.yaml")).unwrap()).unwrap();
    assert_eq!(mh["dns"]["nameserver"], json!(["quic://9.9.9.9:853#name-cert-verify=dns.example"]));
    assert_eq!(mh["dns"]["default-nameserver"], json!(["127.0.0.1:9"]));
    assert_eq!(mh["dns"]["proxy-server-nameserver"], mh["dns"]["nameserver"]);
    assert!(!d.join("out/dnscrypt-proxy.toml").exists());

    // ODoH: dnscrypt-proxy.toml с relay, hosts Mihomo для target и relay
    let (code, _) = render(&d, &base(json!({ "transport": "odoh", "odoh": { "target": { "host": "t.example", "ip": "1.1.1.1", "path": "/dns-query" },
        "relays": [{ "host": "r.example", "ip": "2.2.2.2", "path": "/proxy" }] } })));
    assert_eq!(code, 0);
    let toml = std::fs::read_to_string(d.join("out/dnscrypt-proxy.toml")).unwrap();
    assert!(toml.contains("odoh_servers = true") && toml.contains("bootstrap_resolvers = ['127.0.0.1:1053']") && toml.contains("via = ['sdns://"), "{toml}");
    let mh: Value = serde_json::from_slice(&std::fs::read(d.join("out/config.yaml")).unwrap()).unwrap();
    assert_eq!(mh["hosts"], json!({ "t.example": "1.1.1.1", "r.example": "2.2.2.2" }));
    assert_eq!(mh["dns"]["nameserver"], json!(["127.0.0.1:5300"]));

    // без раздела dns файлов DNS нет
    let (code, _) = render(&d, &serde_json::from_str::<Value>(&std::fs::read_to_string(fixture("lab/config.json")).unwrap()).unwrap());
    assert_eq!(code, 0);
    assert!(!d.join("out/dnsmasq-mitt.conf").exists() && !d.join("out/dnscrypt-proxy.toml").exists());
}

#[test]
fn adblock_update_is_atomic_and_keeps_previous_on_error() {
    let d = dir();
    let cfg = d.join("config.json");
    std::fs::write(d.join("a.txt"), "a.example\n").unwrap();
    assert_eq!(run(&["adblock-update", cfg.to_str().unwrap(), d.join("a.txt").to_str().unwrap()]).0, 0);
    std::fs::write(d.join("b.txt"), "b.example\nc.example\n").unwrap();
    assert_eq!(run(&["adblock-update", cfg.to_str().unwrap(), d.join("b.txt").to_str().unwrap()]).0, 0);
    assert_eq!(std::fs::read_to_string(d.join("adblock.list")).unwrap(), "b.example\nc.example\n");
    assert_eq!(std::fs::read_to_string(d.join("adblock.list.prev")).unwrap(), "a.example\n");
    for bad in ["ok.example\nnot a domain\n", "", "# только комментарий\n", "-x-.example\n"] {
        std::fs::write(d.join("bad.txt"), bad).unwrap();
        let (code, v) = run(&["adblock-update", cfg.to_str().unwrap(), d.join("bad.txt").to_str().unwrap()]);
        assert_eq!(code, 1, "{bad:?}: {v}");
        assert_eq!(std::fs::read_to_string(d.join("adblock.list")).unwrap(), "b.example\nc.example\n", "действующий список сохранён");
    }
    // ошибочный действующий список не даёт сформировать DNS (а не тихо отключает блокировку)
    std::fs::write(d.join("adblock.list"), "broken entry here\n").unwrap();
    let (code, v) = render(&d, &base(json!({ "transport": "dot", "servers": [{ "host": "dns.example", "ip": "9.9.9.9" }], "adblock": { "enabled": true } })));
    assert_eq!(code, 2, "{v}");
}
