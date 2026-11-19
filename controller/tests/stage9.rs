//! Этап 9: действие «напрямую с Zapret» — правило политики с очередью NFQUEUE для mi-tt-admin (порты Zapret),
//! аргументы nfqws2 из каталога стратегий.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::*;

fn tmp(name: &str, content: &str) -> String {
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s9-{}-{name}", rand_hex(6)));
    std::fs::write(&p, content).unwrap();
    p.to_string_lossy().into_owned()
}

fn cfg(zapret: Option<Value>) -> Value {
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(fixture("lab/config.json")).unwrap()).unwrap();
    c["groups"].as_array_mut().unwrap().push(json!({ "id": "z", "name": "Zapret", "destinations": [{ "type": "domain_suffix", "value": "blocked.example" }] }));
    c["rules"] = json!([{ "id": "r-z", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "z" }, "action": { "type": "direct_zapret" } }]);
    if let Some(z) = zapret {
        c["zapret"] = z;
    }
    c
}

fn render(c: &Value) -> (i32, Value, PathBuf) {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s9-out-{}", rand_hex(6)));
    let o = Command::new(ctl())
        .args(["render", &tmp("c.json", &c.to_string()), &tmp("s.json", r#"{"version":1,"profiles":{}}"#), out.to_str().unwrap()])
        .output()
        .unwrap();
    (o.status.code().unwrap(), serde_json::from_slice(&o.stdout).unwrap_or(Value::Null), out)
}

#[test]
fn direct_zapret_renders_queue_policy_and_nfqws2_args() {
    let (code, v, out) = render(&cfg(None));
    assert_eq!(code, 0, "{v}");
    // туннель не нужен: client.toml нет, трафик Zapret идёт напрямую через очередь nfqws2
    assert_eq!(v["tunnel"], false);
    assert!(!out.join("client.toml").exists());
    let pol: Value = serde_json::from_slice(&std::fs::read(out.join("policy.json")).unwrap()).unwrap();
    assert_eq!(pol, v["policy"]);
    assert_eq!(pol["zapret_ports"], json!([443, 2053, 2083, 2087, 2096, 8443]));
    let rules = pol["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1, "{pol}");
    assert_eq!((rules[0]["from"].as_str(), rules[0]["act"].as_str()), (Some("r-z"), Some("zapret")));
    assert_eq!(rules[0]["src"], json!({ "type": "mac", "bridge": "br-lan", "mac": "02:00:00:00:0a:02" }));
    assert!(pol.get("dns_resolver").is_none(), "без туннеля резолвер туннеля не нужен");
    // домены Zapret заносит в набор dnsmasq, но без перенаправления вопросов
    let dns = std::fs::read_to_string(out.join("dnsmasq-mitt.conf")).unwrap();
    assert!(dns.contains(&format!("ipset=/blocked.example/{}
", rules[0]["set"].as_str().unwrap())) && !dns.contains("server="), "{dns}");
    // план: очередь NFQUEUE для портов Zapret, без маршрута через TUN
    let plan: Vec<&str> = v["plan"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert!(plan.iter().any(|x| x.contains("-p tcp -m multiport --dports 443,2053,2083,2087,2096,8443 -j NFQUEUE --queue-num 200 --queue-bypass")), "{plan:#?}");
    assert!(!plan.iter().any(|x| x.contains("mitt0") || x.contains("table 3100")), "{plan:#?}");
    // по умолчанию — круговой режим каталога: общий профиль, YouTube, Discord и YouTube по QUIC
    let args = std::fs::read_to_string(out.join("nfqws2.args")).unwrap();
    let lines: Vec<&str> = args.lines().collect();
    assert_eq!(
        lines[..6],
        ["--qnum=200", "--fwmark=0x40000000", "--chdir", "--lua-init=@zapret-lib.lua.gz", "--lua-init=@zapret-antidpi.lua.gz", "--lua-init=@zapret-auto.lua.gz"]
    );
    assert_eq!(lines.iter().filter(|x| **x == "--new").count(), 5, "{args}");
    assert!(lines.contains(&"--lua-desync=circular:fails=3:maxtime=20") && lines.contains(&"--blob=blob_stun:@stun.bin"), "{args}");
    assert_eq!(v["nfqws2_args"].as_array().unwrap().len(), lines.len());

    let (code, v, out) = render(&cfg(Some(json!({ "strategy": "v3", "youtube": "yv1" }))));
    assert_eq!(code, 0, "{v}");
    let args = std::fs::read_to_string(out.join("nfqws2.args")).unwrap();
    assert!(args.contains("
--lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-600000:tcp_md5:repeats=4
") && args.contains("
--lua-desync=hostfakesplit:host=google.com:tcp_ts=-600000
"), "{args}");
    assert_eq!(args.matches("circular").count(), 1, "круговой режим остаётся только у Discord: {args}");
}

#[test]
fn zapret_settings_are_validated_and_no_free_form_args() {
    let (code, v, _) = render(&cfg(Some(json!({ "strategy": "nope", "youtube": "v1" }))));
    assert_eq!(code, 1);
    let codes: Vec<String> = v["issues"].as_array().unwrap().iter().map(|i| format!("{}:{}", i["path"].as_str().unwrap(), i["code"].as_str().unwrap())).collect();
    assert_eq!(codes, ["config.zapret.strategy:unknown_strategy", "config.zapret.youtube:wrong_kind"]);
    // произвольные аргументы nfqws2 и прежние поля не принимаются схемой
    for z in [json!({ "strategy": "auto", "args": ["--lua-init=@/etc/shadow"] }), json!({ "strategy": "auto", "pos": 2 }), json!({ "tcp_ports": [443] })] {
        let (code, v, _) = render(&cfg(Some(z)));
        assert_eq!(code, 1, "{v}");
    }
    // без правил с Zapret — нет портов очереди и файла аргументов
    let mut c = cfg(None);
    c["rules"][0]["action"] = json!({ "type": "direct" });
    let (code, v, out) = render(&c);
    assert_eq!(code, 0);
    assert!(v["policy"].get("zapret_ports").is_none() && v["nfqws2_args"].as_array().unwrap().is_empty(), "{v}");
    assert!(!v["plan"].as_array().unwrap().iter().any(|x| x.as_str().unwrap().contains("NFQUEUE")));
    assert!(!out.join("nfqws2.args").exists());
}
