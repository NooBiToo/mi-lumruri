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
    for kind in ["wireguard", "vmess"] {
        let (_, v) = validate(&json!({ "version": 1, "default_action": { "type": "direct" }, "profiles": [{ "id": "x", "name": "X", "kind": kind }] }));
        assert_eq!(v["issues"][0]["code"], "parse", "{kind}");
    }
}

#[test]
fn profiles_limit_and_tunnel_numbers() {
    let mut c = lab();
    c["profiles"].as_array_mut().unwrap().push(json!({ "id": "tt2", "name": "Второй", "kind": "trusttunnel", "tunnel": 1,
        "endpoint": { "server": "10.0.0.2", "port": 443, "username": "u" } }));
    let (code, v) = validate(&c);
    assert_eq!(code, 0, "{v}");
    c["profiles"][1]["tunnel"] = json!(0);
    let (code, v) = validate(&c);
    assert_eq!((code, codes(&v)), (1, vec!["profiles[1].tunnel:duplicate_tunnel".to_string()]));
    c["profiles"][1]["tunnel"] = json!(16);
    assert_eq!(codes(&validate(&c).1), vec!["profiles[1].tunnel:bad_tunnel".to_string()]);
    c["profiles"][1]["tunnel"] = json!(1);
    c["dns"] = json!({ "tunnel_profile": "nope" });
    assert_eq!(codes(&validate(&c).1), vec!["dns.tunnel_profile:unknown_profile".to_string()]);
    c["dns"] = json!({ "tunnel_profile": "tt2" });
    assert_eq!(validate(&c).0, 0);
    let profiles: Vec<serde_json::Value> = (0..17).map(|i| json!({ "id": format!("p{i}"), "name": format!("P{i}"), "kind": "trusttunnel", "tunnel": i % 16 })).collect();
    c["profiles"] = json!(profiles);
    c["dns"] = json!({});
    assert!(codes(&validate(&c).1).contains(&"profiles:too_many_profiles".to_string()));
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

#[test]
fn render_two_tunnels_writes_per_tunnel_files_and_list() {
    let mut c = lab();
    c["profiles"].as_array_mut().unwrap().push(json!({ "id": "tt2", "name": "Второй", "kind": "trusttunnel", "tunnel": 2,
        "endpoint": { "server": "10.30.0.9", "port": 443, "username": "u2" } }));
    c["groups"].as_array_mut().unwrap().push(json!({ "id": "music", "name": "Музыка", "destinations": [{ "type": "domain_suffix", "value": "music.lab.test" }] }));
    c["rules"].as_array_mut().unwrap().push(json!({ "id": "r2", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "music" },
        "action": { "type": "profile", "id": "tt2" } }));
    let sec = json!({ "version": 1, "profiles": { "tt-lab": { "password": secret() }, "tt2": { "password": secret() } } });
    let (code, v, out) = render(&c, &sec);
    assert_eq!(code, 0, "{v}");
    assert_eq!(std::fs::read_to_string(out.join("tunnels.list")).unwrap(), "0 mitt0 tt-lab trusttunnel\n2 mitt2 tt2 trusttunnel\n");
    let t2 = std::fs::read_to_string(out.join("tun2/client.toml")).unwrap();
    assert!(t2.contains("device_name = \"mitt2\"\n") && t2.contains("username = \"u2\"\n"), "{t2}");
    assert!(std::fs::read_to_string(out.join("client.toml")).unwrap().contains("device_name = \"mitt0\"\n"));
    assert_eq!(v["policy"]["extra"][0]["dev"], "mitt2");
    let rules = v["policy"]["rules"].as_array().unwrap();
    assert!(rules.iter().any(|r| r["from"] == "r2" && r["tun"] == 2), "{v}");
    assert!(rules.iter().any(|r| r["from"] == "r1" && r.get("tun").is_none()), "{v}");
    // сервер 2 убран из правил — его каталог и строка в списке исчезают
    c["rules"].as_array_mut().unwrap().pop();
    let (code, v) = render_to(&out, &c, &sec);
    assert_eq!(code, 0, "{v}");
    assert!(!out.join("tun2").exists());
    assert_eq!(std::fs::read_to_string(out.join("tunnels.list")).unwrap(), "0 mitt0 tt-lab trusttunnel\n");
    // DNS-туннель — выбранный профиль; при нескольких туннелях без метки, только привязка к TUN
    c["rules"].as_array_mut().unwrap().push(json!({ "id": "r2", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "music" },
        "action": { "type": "profile", "id": "tt2" } }));
    c["dns"] = json!({ "tunnel_profile": "tt2", "tunnel_secure": "doh" });
    let (code, v) = render_to(&out, &c, &sec);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["policy"]["dns_tun"], 2);
    let args = std::fs::read_to_string(out.join("dns-tunnel.args")).unwrap();
    assert!(args.contains("--device\nmitt2\n") && !args.contains("--mark"), "{args}");
}

#[test]
fn render_singbox_profile_writes_config_not_client_toml() {
    let mut c = lab();
    c["profiles"].as_array_mut().unwrap().push(json!({ "id": "vl", "name": "VLESS", "kind": "vless", "tunnel": 1,
        "proxy": { "server": "203.0.113.5", "port": 443, "security": "reality", "transport": "tcp" } }));
    c["rules"][0]["action"] = json!({ "type": "profile", "id": "vl" });
    let link = "vless://bf000d23-0752-40b4-affe-68f7707a9661@203.0.113.5:443?security=reality&sni=www.example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=01ab&flow=xtls-rprx-vision"; // secret-scan: allow тестовая ссылка
    let sec = json!({ "version": 1, "profiles": { "tt-lab": { "password": secret() }, "vl": { "link": link } } });
    let (code, v, out) = render(&c, &sec);
    assert_eq!(code, 0, "{v}");
    assert_eq!(std::fs::read_to_string(out.join("tunnels.list")).unwrap(), "1 mitt1 vl sing-box\n");
    assert!(!out.join("tun1/client.toml").exists());
    let j: Value = serde_json::from_str(&std::fs::read_to_string(out.join("tun1/sing-box.json")).unwrap()).unwrap();
    assert_eq!(j["inbounds"][0]["interface_name"], "mitt1");
    assert_eq!(j["outbounds"][0]["type"], "vless");
    assert_eq!(j["outbounds"][0]["tls"]["reality"]["short_id"], "01ab");
    assert_eq!(std::fs::read_to_string(out.join("tun1/servers.addr")).unwrap(), "primary 203.0.113.5 443\n");
    // единственный туннель с номером 1: прежний бит метки, своя таблица
    assert!(v["plan"].as_array().unwrap().iter().any(|e| e == "ip rule priority 3006 fwmark 0x4000/0x4000 lookup 3101"), "{v}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(out.join("tun1/sing-box.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // ссылки нет — рендер отклоняется
    let sec = json!({ "version": 1, "profiles": { "tt-lab": { "password": secret() } } });
    let (code, v, _) = render(&c, &sec);
    assert_eq!(code, 1, "{v}");
    assert!(codes(&v).iter().any(|x| x.ends_with(":no_secret")), "{v}");
}

#[test]
fn proxy_subscription_import_picks_and_keeps_choice() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("tt-sub-{}", rand_hex(6)));
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = lab();
    c["profiles"].as_array_mut().unwrap().push(json!({ "id": "vl", "name": "Подписка", "kind": "vless", "tunnel": 1 }));
    c["rules"][0]["action"] = json!({ "type": "profile", "id": "vl" });
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, c.to_string()).unwrap();
    let sub_url = "https://user:pw@sub.example.com/list"; // secret-scan: allow тестовая подписка
    std::fs::write(dir.join("secrets.json"), json!({ "version": 1, "profiles": { "tt-lab": { "password": secret() }, "vl": { "subscription_url": sub_url } } }).to_string()).unwrap();
    // подписка ещё не скачана: рендер проходит, правило — по политике отказа (block)
    let out = dir.join("render");
    let (code, v) = run(&["render", cfg.to_str().unwrap(), dir.join("secrets.json").to_str().unwrap(), out.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    assert!(v["warnings"].to_string().contains("подписка ещё не скачана"), "{v}");
    assert!(!out.join("tunnels.list").exists() || !std::fs::read_to_string(out.join("tunnels.list")).unwrap().contains("vl"));
    let (code, v) = run(&["subscription-list", cfg.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    let list = "vless://bf000d23-0752-40b4-affe-68f7707a9661@a.example.com:443?security=tls#Амстердам\nhy2://pw2@b.example.com:443#Франкфурт\nvmess://zzz\n"; // secret-scan: allow тестовые ссылки
    let body = dir.join("sub.txt");
    std::fs::write(&body, data_encoding::BASE64.encode(list.as_bytes())).unwrap();
    let (code, v) = run(&["proxy-sub-import", cfg.to_str().unwrap(), "vl", body.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    assert_eq!((v["changed"].as_bool(), v["count"].as_u64(), v["skipped"].as_u64(), v["picked"].as_str()), (Some(true), Some(2), Some(1), Some("Амстердам")));
    let secrets: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("secrets.json")).unwrap()).unwrap();
    assert!(secrets["profiles"]["vl"]["link"].as_str().unwrap().contains("a.example.com"));
    let c2: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    assert_eq!(c2["profiles"][1]["proxy"]["server"], "a.example.com");
    assert!(dir.join("sub/vl.json").exists());
    // повтор без изменений — ничего не пишется
    let (_, v) = run(&["proxy-sub-import", cfg.to_str().unwrap(), "vl", body.to_str().unwrap()]);
    assert_eq!(v["changed"], false, "{v}");
    // выбор другого сервера (как POST /subscription/pick): вид профиля меняется на hysteria2 и сохраняется при обновлении
    let mut c3 = c2.clone();
    c3["profiles"][1]["sub_pick"] = json!("Франкфурт");
    std::fs::write(&cfg, c3.to_string()).unwrap();
    let (_, v) = run(&["proxy-sub-import", cfg.to_str().unwrap(), "vl", body.to_str().unwrap()]);
    assert_eq!((v["changed"].as_bool(), v["picked"].as_str()), (Some(true), Some("Франкфурт")), "{v}");
    let c4: Value = serde_json::from_str(&std::fs::read_to_string(&cfg).unwrap()).unwrap();
    assert_eq!(c4["profiles"][1]["kind"], "hysteria2");
    // пустой или чужой ответ — отказ, прежнее не тронуто
    std::fs::write(&body, "<html>").unwrap();
    let (code, v) = run(&["proxy-sub-import", cfg.to_str().unwrap(), "vl", body.to_str().unwrap()]);
    assert_eq!((code, v["error"]["code"].as_str()), (1, Some("subscription_empty")), "{v}");
}

#[test]
fn render_amneziawg_writes_uapi_and_addr() {
    let mut c = lab();
    c["profiles"].as_array_mut().unwrap().push(json!({ "id": "aw", "name": "AWG", "kind": "amneziawg", "tunnel": 4,
        "proxy": { "server": "awg.example.com", "port": 51820, "security": "awg", "transport": "udp" } }));
    c["rules"][0]["action"] = json!({ "type": "profile", "id": "aw" });
    let conf = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.8.0.2/32\nJc = 4\nH1 = 1-2\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = awg.example.com:51820\n"; // secret-scan: allow тестовый ключ
    let sec = json!({ "version": 1, "profiles": { "tt-lab": { "password": secret() }, "aw": { "link": conf } } });
    let (code, v, out) = render(&c, &sec);
    assert_eq!(code, 0, "{v}");
    assert_eq!(std::fs::read_to_string(out.join("tunnels.list")).unwrap(), "4 mitt4 aw amneziawg\n");
    let u = std::fs::read_to_string(out.join("tun4/awg.uapi")).unwrap();
    assert!(u.contains("jc=4\n") && u.contains("h1=1-2\n") && u.contains("endpoint=awg.example.com:51820\n") && u.contains("allowed_ip=0.0.0.0/0\n"), "{u}");
    assert_eq!(std::fs::read_to_string(out.join("tun4/awg.addr")).unwrap(), "10.8.0.2/32\nmtu 1280\n");
    // конфигурация для другого вида профиля — отказ
    c["profiles"][1]["kind"] = json!("vless");
    let (code, _, _) = render(&c, &sec);
    assert_eq!(code, 1);
}

#[test]
fn telegram_websocket_rule_redirects_and_keeps_vpn_fallback() {
    // правило tg_ws без VPN-правил: запасной путь через tt-lab — туннель нужен плану и программе (tgws.args)
    let mut c = lab();
    c["rules"] = json!([{ "id": "tg", "source": { "type": "device", "id": "tv" }, "destination": { "type": "group", "id": "video" }, "action": { "type": "tg_ws" } }]);
    c["tgws"] = json!({ "via": "tt-lab" });
    let (code, v, out) = render(&c, &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["policy"]["tgws_via"], json!(0), "{v}");
    assert!(v["policy"]["rules"].as_array().unwrap().iter().any(|r| r["act"] == "tg_ws"), "{v}");
    assert!(v["plan"].as_array().unwrap().iter().any(|e| e.as_str().unwrap().contains("REDIRECT")), "{v}");
    let args = std::fs::read_to_string(out.join("tgws.args")).unwrap();
    assert_eq!(args, "--listen\n0.0.0.0:18443\n--via-device\nmitt0\n--via-mark\n0x4000\n");
    // напрямую: без туннеля и без привязки
    c["tgws"] = json!({});
    let (code, v, out) = render(&c, &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["tunnels"], json!([]), "{v}");
    assert_eq!(std::fs::read_to_string(out.join("tgws.args")).unwrap(), "--listen\n0.0.0.0:18443\n");
    // неизвестный профиль запасного пути — ошибка проверки; tg_ws в default_action — тоже
    c["tgws"] = json!({ "via": "nope" });
    assert!(codes(&validate(&c).1).contains(&"tgws.via:unknown_profile".to_string()));
    c["tgws"] = json!({});
    c["default_action"] = json!({ "type": "tg_ws" });
    assert!(codes(&validate(&c).1).contains(&"default_action:tg_ws_default".to_string()));
}

#[test]
fn domain_sets_beat_subnets_of_other_rules() {
    // Discord с обходом блокировок: его подсети — целиком Cloudflare; сайт из списка VPN на Cloudflare должен идти в VPN
    let mut c = lab();
    c["groups"] = json!([
        { "id": "zap", "name": "Z", "destinations": [{ "type": "domain_suffix", "value": "discord.com" }, { "type": "cidr", "value": "104.16.0.0/12" }] },
        { "id": "vpn", "name": "V", "destinations": [{ "type": "domain_suffix", "value": "ifconfig.co" }, { "type": "cidr", "value": "91.108.4.0/22" }] }
    ]);
    c["rules"] = json!([
        { "id": "zapret-lan", "source": { "type": "lan" }, "destination": { "type": "group", "id": "zap" }, "action": { "type": "direct_zapret" } },
        { "id": "vpn-lan", "source": { "type": "lan" }, "destination": { "type": "group", "id": "vpn" }, "action": { "type": "profile", "id": "tt-lab" } }
    ]);
    let (code, v, _) = render(&c, &secrets(&secret()));
    assert_eq!(code, 0, "{v}");
    let order: Vec<(String, String)> = v["policy"]["rules"].as_array().unwrap().iter()
        .filter(|r| r["src"]["bridge"] == "br-lan")
        .map(|r| (r["act"].as_str().unwrap().to_string(), r["set"].as_str().unwrap_or("").chars().last().unwrap_or('-').to_string())).collect();
    // домены обоих правил (в прежнем порядке), затем подсети
    assert_eq!(order, [("zapret".into(), "d".into()), ("tunnel".into(), "d".into()), ("zapret".into(), "n".into()), ("tunnel".into(), "n".into())], "{v}");
}
