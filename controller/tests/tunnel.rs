//! TrustTunnel — единственный VPN: проверка точки подключения, client.toml для официального клиента,
//! секреты вне API, порядок правил политики, режим «при отказе — напрямую», DNS доменов туннеля.
//! Перенесено из этапов 7 и 8 (Hysteria2, VLESS, WireGuard удалены) то, что относится к TrustTunnel.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

mod common;
use common::*;

fn tmp(name: &str, content: &str) -> String {
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("tt-{}-{name}", rand_hex(6)));
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

fn secret() -> String {
    format!("s-{}", rand_hex(20))
}

fn secrets(pw: &str) -> Value {
    json!({ "version": 1, "profiles": { "tt-lab": { "password": pw } } })
}

/// Лабораторные настройки с правилом «телевизор → видео через TrustTunnel».
fn lab() -> Value {
    let mut c: Value = serde_json::from_str(&std::fs::read_to_string(fixture("lab/config.json")).unwrap()).unwrap();
    c["rules"] = json!([{ "id": "r1", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "video" },
        "action": { "type": "profile", "id": "tt-lab" } }]);
    c
}

/// render в отдельный каталог: (код, ответ, каталог вывода).
fn render_to(out: &PathBuf, cfg: &Value, sec: &Value) -> (i32, Value) {
    run(&["render", &tmp("config.json", &cfg.to_string()), &tmp("secrets.json", &sec.to_string()), out.to_str().unwrap()])
}

fn render(cfg: &Value, sec: &Value) -> (i32, Value, PathBuf) {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("tt-out-{}", rand_hex(6)));
    let (code, v) = render_to(&out, cfg, sec);
    (code, v, out)
}

fn validate(c: &Value) -> (i32, Value) {
    run(&["validate", &tmp("v.json", &c.to_string())])
}

fn with_endpoint(e: Value) -> Value {
    json!({ "version": 1, "default_action": { "type": "direct" }, "profiles": [{ "id": "t", "name": "T", "kind": "trusttunnel", "endpoint": e }] })
}

const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUZm9yLXRlc3RzLW9ubHk=\n-----END CERTIFICATE-----\n";

#[test]
fn endpoint_validation_ip_username_certificate() {
    let ok = json!({ "server": "10.0.0.1", "port": 443, "username": "u" });
    let case = |patch: Value| {
        let mut e = ok.clone();
        for (k, v) in patch.as_object().unwrap() {
            if v.is_null() {
                e.as_object_mut().unwrap().remove(k);
            } else {
                e[k] = v.clone();
            }
        }
        codes(&validate(&with_endpoint(e)).1)
    };
    let p = "profiles[0].endpoint";
    // сервер — IP или доменное имя (домен разрешает клиент TrustTunnel); адрес с портом и пробелы — ошибка
    for s in ["bad host", "a..com", "", "10.0.0.1:443"] {
        assert_eq!(case(json!({ "server": s })), [format!("{p}.server:bad_server")], "{s:?}");
    }
    assert!(case(json!({ "server": "vpn.example.com" })).is_empty());
    assert_eq!(case(json!({ "port": 0 })), [format!("{p}.port:bad_port")]);
    assert_eq!(case(json!({ "sni": "*.example.com" })), [format!("{p}.sni:bad_sni")]);
    // имя пользователя обязательно: 1–64 символа без «:», кавычек, «\» и управляющих
    for u in [json!(null), json!(""), json!("a:b"), json!("a\"b"), json!("a\\b"), json!("a\nb"), json!("x".repeat(65))] {
        assert_eq!(case(json!({ "username": u.clone() })), [format!("{p}.username:bad_username")], "{u}");
    }
    // сертификат — только PEM CERTIFICATE без апострофов (в client.toml он записывается строкой '''…''')
    // заголовок закрытого ключа собран из частей, чтобы tools/secret-scan.py не считал отрицательный пример ключом
    for c in ["zz", concat!("-----BEGIN PRIVATE", " KEY-----\nAAAA\n-----END PRIVATE KEY-----"),&PEM.replace("MIIB", "MI'IB"), &PEM.replace("MIIB", "MIIB\u{7}")] {
        assert_eq!(case(json!({ "certificate": c })), [format!("{p}.certificate:bad_certificate")], "{c:?}");
    }
    assert_eq!(case(json!({ "certificate": format!("{PEM}{}", "A".repeat(16 * 1024)) })), [format!("{p}.certificate:bad_certificate")], "больше 16 КиБ");
    // допустимо: IPv6-адрес, имя из 64 символов, sni, QUIC, anti_dpi, сертификат PEM
    let (code, v) = validate(&with_endpoint(json!({ "server": "2001:db8::1", "port": 8443, "sni": "vpn.example.com", "username": "u".repeat(64),
        "quic": true, "anti_dpi": true, "certificate": PEM })));
    assert_eq!(code, 0, "{v}");
    // поля удалённых протоколов схема не принимает
    for f in [json!({ "cert_sha256": "ab".repeat(32) }), json!({ "obfs": "salamander" }), json!({ "security": "tls" }), json!({ "public_key": "x" })] {
        let mut e = ok.clone();
        e.as_object_mut().unwrap().extend(f.as_object().unwrap().clone());
        let (_, v) = validate(&with_endpoint(e));
        assert_eq!((v["ok"].as_bool(), v["issues"][0]["code"].as_str()), (Some(false), Some("parse")), "{f}");
    }
    for kind in ["hysteria2", "vless", "wireguard"] {
        let (_, v) = validate(&json!({ "version": 1, "default_action": { "type": "direct" }, "profiles": [{ "id": "x", "name": "X", "kind": kind }] }));
        assert_eq!(v["issues"][0]["code"], "parse", "{kind}");
    }
}

#[test]
fn single_profile_limit() {
    let mut c = lab();
    c["profiles"].as_array_mut().unwrap().push(json!({ "id": "tt2", "name": "Второй", "kind": "trusttunnel",
        "endpoint": { "server": "10.0.0.2", "port": 443, "username": "u" } }));
    let (code, v) = validate(&c);
    assert_eq!((code, codes(&v)), (1, vec!["profiles:too_many_profiles".to_string()]));
    let (code, v, out) = render(&c, &secrets(&secret()));
    assert_eq!((code, codes(&v)), (1, vec!["config.profiles:too_many_profiles".to_string()]));
    assert!(!out.exists(), "ничего не записано");
}

#[test]
fn ipv6_via_vpn_only_for_all_via_vpn_sources() {
    let pw = format!("p-{}", rand_hex(8));
    // выборочные сайты: IPv6 через VPN включён, но источников «весь интернет» нет — has_ipv6 выключен, предупреждение
    let mut c = lab();
    c["ipv6_via_vpn"] = json!(true);
    let (code, v, out) = render(&c, &secrets(&pw));
    assert_eq!(code, 0, "{v}");
    assert!(std::fs::read_to_string(out.join("client.toml")).unwrap().contains("has_ipv6 = false\n"));
    assert!(v["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("IPv6 через VPN")), "{v}");
    let pol: Value = serde_json::from_str(&std::fs::read_to_string(out.join("policy.json")).unwrap()).unwrap();
    assert!(pol.get("v6_tunnel").is_none(), "{pol}");
    // правило ТВ → весь интернет (0.0.0.0/1 и 128.0.0.0/1) через туннель: IPv6 ТВ — в туннель, клиент с IPv6
    c["groups"] = json!([{ "id": "all", "name": "Весь интернет", "destinations": [{ "type": "cidr", "value": "0.0.0.0/1" }, { "type": "cidr", "value": "128.0.0.0/1" }] }]);
    c["rules"][0]["destination"] = json!({ "type": "group", "id": "all" });
    let (code, v, out) = render(&c, &secrets(&pw));
    assert_eq!(code, 0, "{v}");
    assert!(std::fs::read_to_string(out.join("client.toml")).unwrap().contains("has_ipv6 = true\n"));
    let pol: Value = serde_json::from_str(&std::fs::read_to_string(out.join("policy.json")).unwrap()).unwrap();
    assert_eq!(pol["v6_tunnel"].as_array().map(Vec::len), Some(1), "{pol}");
    // выключено — как раньше
    c["ipv6_via_vpn"] = json!(false);
    let (_, _, out) = render(&c, &secrets(&pw));
    assert!(std::fs::read_to_string(out.join("client.toml")).unwrap().contains("has_ipv6 = false\n"));
}

#[test]
fn render_writes_backup_client_toml_with_its_password() {
    let mut c = lab();
    c["profiles"][0]["backup"] = json!({ "server": "backup.example.com", "port": 8443, "username": "tv-backup", "quic": true, "anti_dpi": false });
    let pw = format!("main-{}", rand_hex(8));
    let bpw = format!("backup-{}", rand_hex(8));
    // без пароля запасного сервера — только основной
    let (code, v, out) = render(&c, &secrets(&pw));
    assert_eq!(code, 0, "{v}");
    assert!(out.join("client.toml").exists() && !out.join("client-backup.toml").exists() && !out.join("primary.addr").exists());
    let mut s = secrets(&pw);
    s["profiles"]["tt-lab"]["backup_password"] = json!(bpw);
    let (code, v, out) = render(&c, &s);
    assert_eq!(code, 0, "{v}");
    let b = std::fs::read_to_string(out.join("client-backup.toml")).unwrap();
    assert!(b.contains("addresses = [\"backup.example.com:8443\"]\n") && b.contains(&format!("password = \"{bpw}\"\n")) && b.contains("upstream_protocol = \"http3\""), "{b}");
    assert!(std::fs::read_to_string(out.join("client.toml")).unwrap().contains(&format!("password = \"{pw}\"\n")));
    assert_eq!(std::fs::read_to_string(out.join("primary.addr")).unwrap(), "10.30.0.2 443\n");
    // запасной без основного — ошибка проверки
    let mut nb = with_endpoint(json!({ "server": "10.0.0.1", "port": 443, "username": "u" }));
    nb["profiles"][0].as_object_mut().unwrap().remove("endpoint");
    nb["profiles"][0]["backup"] = json!({ "server": "10.0.0.2", "port": 443, "username": "u" });
    let (code, v) = validate(&nb);
    assert_ne!(code, 0, "{v}");
    assert!(codes(&v).iter().any(|c| c.ends_with(":backup_without_primary")), "{v}");
}

#[test]
fn render_writes_client_toml_and_removes_it_without_tunnel_rules() {
    let pw = format!("p\"a\\ss-{}", rand_hex(12));
    let (code, v, out) = render(&lab(), &secrets(&pw));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["tunnel"], true);
    let t = std::fs::read_to_string(out.join("client.toml")).unwrap();
    let escaped = pw.replace('\\', "\\\\").replace('"', "\\\"");
    for want in [
        "hostname = \"vpn.lab.test\"\n".to_string(),
        "addresses = [\"10.30.0.2:443\"]\n".into(),
        "username = \"tv-user\"\n".into(),
        format!("password = \"{escaped}\"\n"),
        "skip_verification = false\n".into(),
        "certificate = \"\"\n".into(),
        "upstream_protocol = \"http2\"\n".into(),
        "anti_dpi = false\n".into(),
        "device_name = \"mitt0\"\n".into(),
        "included_routes = []\n".into(),
        "change_system_dns = false\n".into(),
    ] {
        assert!(t.contains(&want), "нет {want:?}:\n{t}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(out.join("client.toml")).unwrap().permissions().mode() & 0o777, 0o600, "client.toml с паролем — только владельцу");
    }

    // без sni имя — адрес сервера; QUIC — HTTP/3; закреплённый сертификат записывается в client.toml
    let mut c = lab();
    let e = &mut c["profiles"][0]["endpoint"];
    e.as_object_mut().unwrap().remove("sni");
    e["server"] = json!("2001:db8::7");
    e["quic"] = json!(true);
    e["anti_dpi"] = json!(true);
    e["certificate"] = json!(PEM);
    let (code, v) = render_to(&out, &c, &secrets(&pw));
    assert_eq!(code, 0, "{v}");
    let t = std::fs::read_to_string(out.join("client.toml")).unwrap();
    for want in ["hostname = \"2001:db8::7\"\n", "addresses = [\"[2001:db8::7]:443\"]\n", "upstream_protocol = \"http3\"\n", "anti_dpi = true\n",
        &format!("certificate = '''\n{}\n'''\n", PEM.trim())] {
        assert!(t.contains(want), "нет {want:?}:\n{t}");
    }

    // правило без туннеля: client.toml не нужен, прежний удаляется
    let mut c = lab();
    c["rules"][0]["action"] = json!({ "type": "direct" });
    let (code, v) = render_to(&out, &c, &json!({ "version": 1, "profiles": {} }));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["tunnel"], false);
    assert!(!out.join("client.toml").exists());
    assert!(v["policy"].get("dns_resolver").is_none());
    assert!(!v["plan"].as_array().unwrap().iter().any(|x| x.as_str().unwrap().contains("table 3100")), "{v}");
}

#[test]
fn unready_profiles_refused_and_flagged_in_preview() {
    // профиль без точки подключения сохранить можно, применить — нет
    let mut c = lab();
    c["profiles"][0].as_object_mut().unwrap().remove("endpoint");
    let (code, v, out) = render(&c, &secrets(&secret()));
    assert_eq!((code, codes(&v)), (1, vec!["rules[0].action:no_endpoint".to_string()]));
    assert!(!out.exists());
    let req = json!({ "rule": c["rules"][0], "probes": [] });
    let (_, v) = run(&["preview", &tmp("c.json", &c.to_string()), &tmp("r.json", &req.to_string())]);
    assert!(v["preview"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "profile_not_ready"), "{v}");
    let req = json!({ "rule": lab()["rules"][0], "probes": [] });
    let (_, v) = run(&["preview", &tmp("c2.json", &lab().to_string()), &tmp("r2.json", &req.to_string())]);
    assert!(!v["preview"]["findings"].as_array().unwrap().iter().any(|f| f["code"] == "profile_not_ready"), "{v}");
    // нет пароля, пустой пароль, поля прежних протоколов в secrets.json
    let (code, v, _) = render(&lab(), &json!({ "version": 1, "profiles": {} }));
    assert_eq!((code, codes(&v)), (1, vec!["rules[0].action:no_secret".to_string()]));
    let (code, v, _) = render(&lab(), &secrets(""));
    assert_eq!((code, codes(&v)), (1, vec!["rules[0].action:bad_secret".to_string()]));
    let (code, v, _) = render(&lab(), &json!({ "version": 1, "profiles": { "tt-lab": { "password": "x", "obfs_password": "y" } } }));
    assert_eq!((code, v["error"]["code"].as_str()), (1, Some("secrets_invalid")), "{v}");
}

#[test]
fn secrets_never_appear_in_api_or_cgi_responses() {
    let pw = secret();
    let (code, v, _) = render(&lab(), &secrets(&pw));
    assert_eq!(code, 0);
    assert!(!v.to_string().contains(&pw), "пароль не попадает в ответ CLI (он же уходит в журналы)");

    let mut a = Auth::new("tt-secrets");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("tt-cgi-{}", rand_hex(6)));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), lab().to_string()).unwrap();
    std::fs::write(dir.join("secrets.json"), secrets(&pw).to_string()).unwrap();
    a.config = dir.join("config.json").to_string_lossy().into_owned();
    let t = T0 + 60;
    let s = a.login(t);
    let preview = json!({ "rule": lab()["rules"][0], "probes": [{ "device": "tv", "host": "video.lab.test" }] }).to_string();
    for (m, path, body) in [("GET", "/config", None), ("GET", "/secrets", None), ("GET", "/status", None), ("POST", "/preview", Some(preview.as_bytes()))] {
        let o = a.api(&s, m, path, body, t + 1);
        assert_eq!(o.status, 200, "{path}: {}", o.body);
        assert!(!o.body.to_string().contains(&pw), "{path}: пароль в ответе");
    }
    assert_eq!(a.api(&s, "GET", "/secrets", None, t + 1).body["profiles"]["tt-lab"], true);
    // запись нового пароля: ответ без значения
    let pw2 = secret();
    let o = a.api(&s, "POST", "/secrets", Some(json!({ "profile_id": "tt-lab", "secret": { "password": pw2 } }).to_string().as_bytes()), t + 2);
    assert_eq!(o.status, 200, "{}", o.body);
    assert!(!o.body.to_string().contains(&pw2));
}

#[test]
fn policy_rules_follow_device_network_lan_order() {
    let mut c = lab();
    let cidr = |v: &str| json!({ "type": "cidr", "value": v });
    let r = |id: &str, src: Value, dst: Value, act: Value| json!({ "id": id, "source": src, "destination": dst, "action": act });
    let tt = json!({ "type": "profile", "id": "tt-lab" });
    let (tv, phone, guest, lan) =
        (json!({ "type": "device", "id": "tv" }), json!({ "type": "device", "id": "phone" }), json!({ "type": "network", "id": "guest" }), json!({ "type": "lan" }));
    // в настройках порядок перемешан: LAN, сеть, устройства; внутри уровня — порядок пользователя
    c["rules"] = json!([
        r("r-lan", lan, cidr("10.97.0.0/16"), json!({ "type": "block" })),
        r("r-guest", guest, cidr("10.98.0.0/16"), tt.clone()),
        r("r-tv-wide", tv.clone(), cidr("10.96.0.0/14"), json!({ "type": "block" })),
        r("r-phone", phone, cidr("10.99.0.0/24"), json!({ "type": "direct_zapret" })),
        r("r-tv-video", tv, cidr("10.99.0.0/24"), tt),
        json!({ "id": "r-off", "source": { "type": "lan" }, "destination": cidr("10.95.0.0/16"), "action": { "type": "block" }, "enabled": false }),
    ]);
    let (code, v, out) = render(&c, &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    let order: Vec<(&str, &str)> = v["policy"]["rules"].as_array().unwrap().iter().map(|x| (x["from"].as_str().unwrap(), x["src"]["type"].as_str().unwrap())).collect();
    assert_eq!(
        order,
        [("r-tv-wide", "mac"), ("r-phone", "mac"), ("r-tv-video", "mac"), ("r-guest", "network"), ("r-lan", "bridge"), ("r-lan", "bridge")],
        "устройства, затем сети, затем вся LAN; выключенное правило не попадает"
    );
    let rules = v["policy"]["rules"].as_array().unwrap();
    assert_eq!(rules[3]["src"], json!({ "type": "network", "bridge": "br-guest", "ports": ["r-gst"] }));
    assert_eq!((rules[4]["src"]["bridge"].as_str(), rules[5]["src"]["bridge"].as_str()), (Some("br-guest"), Some("br-lan")));
    let acts: Vec<&str> = rules.iter().map(|x| x["act"].as_str().unwrap()).collect();
    assert_eq!(acts, ["block", "zapret", "tunnel", "tunnel", "block", "block"]);
    // одно назначение в разных правилах — один набор
    assert_eq!(rules[1]["set"], rules[2]["set"]);
    assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(out.join("policy.json")).unwrap()).unwrap(), v["policy"]);
    // в цепочке запретов (filter FORWARD) первое совпадение: правила по тому же порядку, совпадение без запрета — RETURN
    let plan: Vec<&str> = v["plan"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    let block = plan.iter().find(|x| x.starts_with("iptables -t filter MITT_F")).unwrap();
    let rows: Vec<&str> = block.split(" | ").collect();
    let pos = |needle: &str| rows.iter().position(|r| r.contains(needle)).unwrap_or_else(|| panic!("нет {needle}: {rows:#?}"));
    let tv_mac = "-i br-lan -m mac --mac-source 02:00:00:00:0A:02";
    let tv_block = rows.iter().position(|r| r.starts_with(tv_mac) && r.ends_with("-j REJECT --reject-with icmp-port-unreachable")).unwrap();
    let tv_tunnel = rows.iter().rposition(|r| r.starts_with(tv_mac) && r.ends_with("-j RETURN")).unwrap();
    assert!(pos("-o mitt0 -j ACCEPT") < tv_block && tv_block < tv_tunnel, "{rows:#?}");
    assert!(tv_tunnel < pos("--physdev-in r-gst") && pos("--physdev-in r-gst") < pos("-i br-guest -m set") && pos("-i br-guest -m set") < pos("-i br-lan -m set"), "{rows:#?}");
    // в цепочке туннеля хвост без действий отбрасывается: правила LAN (запрет) туда не попадают
    let classify = plan.iter().find(|x| x.starts_with("iptables -t mangle MITT_C")).unwrap();
    assert!(classify.rsplit(" | ").next().unwrap().contains("-g MITT_T"), "{classify}");
    assert!(!block.contains("10.95.0.0") && !classify.contains("10.95.0.0"));
}

#[test]
fn fail_open_profile_has_no_guard_route() {
    let guard = "ip route unreachable default metric 4096 table 3100";
    let tun = "ip route default dev mitt0 metric 1 table 3100";
    let plan = |v: &Value| v["plan"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect::<Vec<_>>();
    // по умолчанию — блокировать: запасной unreachable в таблице 3100
    let (code, v, _) = render(&lab(), &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["policy"]["fail_open"], false);
    assert!(plan(&v).iter().any(|x| x == guard) && plan(&v).iter().any(|x| x == tun), "{v}");
    // при отказе — напрямую: без unreachable, маршрут через TUN остаётся
    let mut c = lab();
    c["profiles"][0]["on_failure"] = json!("direct");
    let (code, v, out) = render(&c, &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["policy"]["fail_open"], true);
    let p = plan(&v);
    assert!(!p.iter().any(|x| x == guard || x.contains("route unreachable")), "{p:#?}");
    assert!(p.iter().any(|x| x == tun), "{p:#?}");
    assert_eq!(serde_json::from_slice::<Value>(&std::fs::read(out.join("policy.json")).unwrap()).unwrap()["fail_open"], true);
    assert!(out.join("client.toml").exists());
}

#[test]
fn domain_rules_feed_dnsmasq_and_tunnel_resolver_override() {
    let mut c = lab();
    c["groups"].as_array_mut().unwrap().push(json!({ "id": "plain", "name": "Напрямую", "destinations": [{ "type": "domain", "value": "Direct.Example.com" }] }));
    c["rules"].as_array_mut().unwrap().push(json!({ "id": "r2", "source": { "type": "device", "id": "phone" }, "destination": { "type": "group", "id": "plain" },
        "action": { "type": "direct" } }));
    let (code, v, out) = render(&c, &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    let set = |from: &str| v["policy"]["rules"].as_array().unwrap().iter().find(|r| r["from"] == from && r["set"].as_str().unwrap().ends_with('d')).unwrap()["set"].as_str().unwrap().to_string();
    let conf = std::fs::read_to_string(out.join("dnsmasq-mitt.conf")).unwrap();
    assert!(conf.contains(&format!("ipset=/video.lab.test/{}\n", set("r1"))), "{conf}");
    assert!(conf.contains(&format!("ipset=/direct.example.com/{}\n", set("r2"))), "{conf}");
    // через резолвер туннеля разрешаются только домены правил туннеля
    assert!(conf.contains("server=/video.lab.test/1.1.1.1\n") && !conf.contains("server=/direct.example.com/"), "{conf}");
    assert_eq!(v["policy"]["dns_resolver"], "1.1.1.1");
    // точный домен сопоставляется вместе с поддоменами — предупреждение
    assert!(v["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("точный домен")), "{v}");
    // вопросы роутера к резолверу помечаются и уходят в туннель
    assert!(v["plan"].as_array().unwrap().iter().any(|x| x.as_str().unwrap().contains("-d 1.1.1.1/32 -p udp -m udp --dport 53 -j MARK")), "{v}");

    // свой резолвер туннеля
    c["dns"] = json!({ "tunnel_resolver": "9.9.9.9" });
    let (code, v) = render_to(&out, &c, &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    let conf = std::fs::read_to_string(out.join("dnsmasq-mitt.conf")).unwrap();
    assert!(conf.contains("server=/video.lab.test/9.9.9.9\n") && !conf.contains("1.1.1.1"), "{conf}");
    assert_eq!(v["policy"]["dns_resolver"], "9.9.9.9");
    let plan = v["plan"].to_string();
    assert!(plan.contains("-d 9.9.9.9/32 -p tcp -m tcp --dport 53") && !plan.contains("1.1.1.1"), "{plan}");
    // исключение из блокировки рекламы внутри домена туннеля разрешается через резолвер туннеля
    c["dns"] = json!({ "tunnel_resolver": "9.9.9.9", "adblock": { "enabled": true, "exceptions": ["cdn.video.lab.test", "ok.ads.example"] } });
    let (code, v) = render_to(&out, &c, &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    let conf = std::fs::read_to_string(out.join("dnsmasq-mitt.conf")).unwrap();
    assert!(conf.contains("server=/cdn.video.lab.test/9.9.9.9\n") && conf.contains("server=/ok.ads.example/#\n"), "{conf}");
}
