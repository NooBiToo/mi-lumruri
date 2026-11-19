//! Этап 10: DNS роутера — резолвер туннельных доменов и блокировка рекламы через штатный dnsmasq: проверка настроек,
//! файл dnsmasq-mitt.conf, атомарное обновление списка рекламы.

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
    run(&["render", cfg.to_str().unwrap(), d.join("s.json").to_str().unwrap(), d.join("out").to_str().unwrap()])
}

fn validate(d: &PathBuf, name: &str, c: &Value) -> (i32, Value) {
    std::fs::write(d.join(name), c.to_string()).unwrap();
    run(&["validate", d.join(name).to_str().unwrap()])
}

#[test]
fn dns_settings_validation() {
    let d = dir();
    // резолвер туннеля — только публичный IPv4: имя, частный, loopback, IPv6 и пустой адрес отклоняются
    for r in ["dns.example", "192.168.1.1", "10.0.0.53", "127.0.0.1", "0.0.0.0", "2606:4700:4700::1111", "224.0.0.1", ""] {
        let (code, v) = validate(&d, "bad.json", &base(json!({ "tunnel_resolver": r })));
        assert_eq!((code, codes(&v)), (1, vec!["dns.tunnel_resolver:bad_resolver".to_string()]), "{r}");
    }
    let (_, v) = validate(&d, "bad2.json", &base(json!({ "adblock": { "enabled": true, "exceptions": ["bad domain", "ok.example", "com"] } })));
    assert_eq!(codes(&v), ["dns.adblock.exceptions[0]:bad_domain", "dns.adblock.exceptions[2]:bad_domain"]);
    // прежние поля (транспорт шифрованного DNS, серверы, ODoH) схема не принимает
    for old in [json!({ "transport": "doh" }), json!({ "servers": [] }), json!({ "odoh": {} })] {
        let (_, v) = validate(&d, "old.json", &base(old.clone()));
        assert_eq!(v["ok"], false, "{old}: {v}");
        assert_eq!(v["issues"][0]["code"], "parse", "{v}");
    }
    let (code, v) = validate(&d, "ok.json", &base(json!({ "tunnel_resolver": "9.9.9.9", "adblock": { "enabled": false } })));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["config"]["dns"]["tunnel_resolver"], "9.9.9.9");
}

#[test]
fn render_writes_dnsmasq_adblock_without_open_resolvers() {
    let d = dir();
    std::fs::write(d.join("list.txt"), "ads.example
0.0.0.0 tracker.example
").unwrap();
    let (code, v) = run(&["adblock-update", d.join("config.json").to_str().unwrap(), d.join("list.txt").to_str().unwrap()]);
    assert_eq!((code, v["domains"].as_u64()), (0, Some(2)), "{v}");
    let (code, v) = render(&d, &base(json!({ "adblock": { "enabled": true, "exceptions": ["ok.ads.example"] } })));
    assert_eq!(code, 0, "{v}");
    let conf = std::fs::read_to_string(d.join("out/dnsmasq-mitt.conf")).unwrap();
    assert!(conf.contains("address=/ads.example/
address=/tracker.example/
") && conf.contains("server=/ok.ads.example/#
"), "{conf}");
    // провайдерский DNS остаётся для остальных доменов: dnsmasq не переключается целиком и не слушает новых адресов
    for no in ["no-resolv", "listen-address", "interface=", "ipset="] {
        assert!(!conf.contains(no), "{no}: {conf}");
    }
    // без туннельных правил резолвер туннеля не используется
    assert!(!conf.lines().any(|l| l.starts_with("server=/") && !l.ends_with("/#")), "{conf}");
    assert!(v["policy"].get("dns_resolver").is_none(), "{v}");
    assert_eq!(v["tunnel"], false);
    // прежних файлов службы DNS нет
    for f in ["config.yaml", "dnscrypt-proxy.toml", "client.toml"] {
        assert!(!d.join("out").join(f).exists(), "{f}");
    }

    // выключенная блокировка и раздел без правил — файла нет (и прежний удаляется)
    let (code, _) = render(&d, &base(json!({ "adblock": { "enabled": false, "exceptions": ["ok.ads.example"] } })));
    assert_eq!(code, 0);
    assert!(!d.join("out/dnsmasq-mitt.conf").exists());
    let (code, _) = render(&d, &base(json!({ "adblock": { "enabled": true } })));
    assert_eq!(code, 0);
    assert!(d.join("out/dnsmasq-mitt.conf").exists());
    let (code, _) = render(&d, &serde_json::from_str::<Value>(&std::fs::read_to_string(fixture("lab/config.json")).unwrap()).unwrap());
    assert_eq!(code, 0);
    assert!(!d.join("out/dnsmasq-mitt.conf").exists());
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
    let (code, v) = render(&d, &base(json!({ "adblock": { "enabled": true } })));
    assert_eq!(code, 2, "{v}");
}
