//! Этап 9: действие «напрямую с Zapret» — выход Mihomo с меткой сокета, спецификация очереди для mi-tt-admin,
//! аргументы nfqws2 из проверенного набора стратегий.

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
        .args(["render", &tmp("c.json", &c.to_string()), &tmp("s.json", r#"{"version":1,"profiles":{}}"#), &tmp("l", "1999999999 02:00:00:00:0a:02 10.10.1.2 tv *\n"), out.to_str().unwrap()])
        .output()
        .unwrap();
    (o.status.code().unwrap(), serde_json::from_slice(&o.stdout).unwrap_or(Value::Null), out)
}

#[test]
fn direct_zapret_renders_marked_direct_queue_spec_and_nfqws2_args() {
    let (code, v, out) = render(&cfg(None));
    assert_eq!(code, 0, "{v}");
    let mh: Value = serde_json::from_slice(&std::fs::read(out.join("config.yaml")).unwrap()).unwrap();
    assert_eq!(mh["proxies"], json!([{ "name": "mitt-zapret", "type": "direct", "udp": true, "routing-mark": 16384 }]));
    assert!(mh["rules"].as_array().unwrap().iter().any(|r| r.as_str().unwrap().ends_with(",mitt-zapret")));
    assert_eq!(v["capture"]["zapret"], json!({ "qnum": 200, "mark": 16384, "tcp_ports": [80, 443] }));
    let args = std::fs::read_to_string(out.join("nfqws2.args")).unwrap();
    assert_eq!(
        args.lines().collect::<Vec<_>>(),
        ["--qnum=200", "--fwmark=0x40000000", "--chdir", "--lua-init=@zapret-lib.lua.gz", "--lua-init=@zapret-antidpi.lua.gz", "--filter-tcp=80,443",
            "--payload=tls_client_hello,http_req", "--lua-desync=multisplit:pos=2"]
    );
    // план mi-tt-admin (netfilter строится в admin; здесь — что спецификация передана)
    assert!(v["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("nfqws2")));

    let (code, _, out) = render(&cfg(Some(json!({ "strategy": "multidisorder", "pos": 5, "tcp_ports": [443] }))));
    assert_eq!(code, 0);
    let args = std::fs::read_to_string(out.join("nfqws2.args")).unwrap();
    assert!(args.contains("--filter-tcp=443\n") && args.contains("--lua-desync=multidisorder:pos=5"));
}

#[test]
fn zapret_settings_are_validated_and_no_free_form_args() {
    let (code, v, _) = render(&cfg(Some(json!({ "strategy": "multisplit", "pos": 0, "tcp_ports": [] }))));
    assert_eq!(code, 1);
    let codes: Vec<String> = v["issues"].as_array().unwrap().iter().map(|i| format!("{}:{}", i["path"].as_str().unwrap(), i["code"].as_str().unwrap())).collect();
    assert_eq!(codes, ["config.zapret.pos:bad_pos", "config.zapret.tcp_ports:bad_ports"]);
    // произвольные аргументы nfqws2 и неизвестные стратегии не принимаются схемой
    for z in [json!({ "strategy": "multisplit", "args": ["--lua-init=@/etc/shadow"] }), json!({ "strategy": "custom" })] {
        let (code, v, _) = render(&cfg(Some(z)));
        assert_eq!(code, 1, "{v}");
    }
    // без правил с Zapret — нет выхода mitt-zapret, очереди и файла аргументов
    let mut c = cfg(None);
    c["rules"][0]["action"] = json!({ "type": "direct" });
    let (code, v, out) = render(&c);
    assert_eq!(code, 0);
    assert!(v["capture"].get("zapret").is_none());
    assert!(!out.join("nfqws2.args").exists());
}
