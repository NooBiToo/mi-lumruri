//! Этап 2: сохранение правила, защита записи, гонка записей, формирование действующей конфигурации (политика, client.toml).

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

mod common;

const ORIGIN: &str = "http://127.0.0.1:8787";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_mi-tt-ctl")
}

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("fixtures").join(name).to_string_lossy().into_owned()
}

fn tmp(name: &str, content: &str) -> String {
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&p, content).unwrap();
    p.to_string_lossy().into_owned()
}

fn run(args: &[&str]) -> (i32, Value) {
    let o = Command::new(bin()).args(args).output().unwrap();
    (o.status.code().unwrap(), serde_json::from_slice(&o.stdout).unwrap_or(Value::Null))
}

fn codes(v: &Value) -> Vec<String> {
    v["issues"].as_array().unwrap().iter().map(|i| format!("{}:{}", i["path"].as_str().unwrap(), i["code"].as_str().unwrap())).collect()
}

fn lab_copy(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(fixture("lab/config.json"), dir.join("config.json")).unwrap();
    dir
}

fn cgi(method: &str, path: &str, body: Option<&[u8]>, config: &str, extra: &[(&str, &str)]) -> (u16, Value) {
    let mut c = Command::new(bin());
    c.arg("cgi").env_clear().env("MI_TT_CONFIG", config).env("REQUEST_METHOD", method).env("PATH_INFO", path);
    // действующая сессия (пароль + TOTP) и CSRF; Origin задают сами тесты, как на этапе 2
    c.envs(common::shared_env(false));
    c.stdin(Stdio::piped()).stdout(Stdio::piped());
    if let Some(b) = body {
        c.env("CONTENT_TYPE", "application/json").env("CONTENT_LENGTH", b.len().to_string());
    }
    for (k, v) in extra {
        c.env(k, v);
    }
    let mut child = c.spawn().unwrap();
    {
        let mut stdin = child.stdin.take().unwrap();
        if let Some(b) = body {
            stdin.write_all(b).unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    (head[8..11].parse().unwrap(), serde_json::from_str(body).unwrap())
}

fn rev_of(cfg: &str) -> String {
    let (s, v) = cgi("GET", "/config", None, cfg, &[]);
    assert_eq!(s, 200);
    v["revision"].as_str().unwrap().to_string()
}

fn save_body(rev: &str, rule_id: &str, device: &str) -> Vec<u8> {
    format!(
        r#"{{"base_revision":"{rev}","rule":{{"id":"{rule_id}","source":{{"type":"device","id":"{device}"}},"destination":{{"type":"group","id":"video"}},"action":{{"type":"profile","id":"tt-lab"}}}}}}"#
    )
    .into_bytes()
}

const ALLOW: [(&str, &str); 3] = [("MI_TT_ALLOWED_ORIGINS", ORIGIN), ("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "same-origin")];

#[test]
fn save_via_cgi_is_atomic_versioned_and_reread() {
    let dir = lab_copy("save-ok");
    let cfg = dir.join("config.json").to_string_lossy().into_owned();
    let before = std::fs::read(&cfg).unwrap();
    let rev = rev_of(&cfg);
    let (s, v) = cgi("POST", "/rules", Some(&save_body(&rev, "r-tv-video", "tv")), &cfg, &ALLOW);
    assert_eq!(s, 200, "{v:#}");
    assert_eq!(v["mode"], "add");
    assert_eq!(v["previous_revision"], rev.as_str());
    assert_ne!(v["revision"], rev.as_str());
    // предыдущая версия сохранена рядом; новая читается отдельным процессом, как после перезапуска
    assert_eq!(std::fs::read(dir.join("config.json.prev")).unwrap(), before);
    let (s, again) = cgi("GET", "/config", None, &cfg, &[]);
    assert_eq!(s, 200);
    assert_eq!(again["revision"], v["revision"]);
    assert_eq!(again["config"]["rules"][0]["id"], "r-tv-video");
    // устаревшая ревизия → конфликт, файл не меняется
    let after = std::fs::read(&cfg).unwrap();
    let (s, c) = cgi("POST", "/rules", Some(&save_body(&rev, "r-other", "phone")), &cfg, &ALLOW);
    assert_eq!(s, 409);
    assert_eq!(c["error"]["code"], "revision_conflict");
    assert_eq!(c["current_revision"], v["revision"]);
    assert_eq!(std::fs::read(&cfg).unwrap(), after);
    // замена того же правила на актуальной ревизии
    let (s, r) = cgi("POST", "/rules", Some(&save_body(v["revision"].as_str().unwrap(), "r-tv-video", "phone")), &cfg, &ALLOW);
    assert_eq!(s, 200);
    assert_eq!(r["mode"], "replace");
    assert_eq!(r["config"]["rules"].as_array().unwrap().len(), 1);
    let leftovers = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains(".tmp.")).count();
    assert_eq!(leftovers, 0, "временные файлы не остаются");
}

#[test]
fn write_requires_allowed_origin() {
    let dir = lab_copy("save-origin");
    let cfg = dir.join("config.json").to_string_lossy().into_owned();
    let before = std::fs::read(&cfg).unwrap();
    let body = save_body(&rev_of(&cfg), "r-tv-video", "tv");
    let cases: [(&[(&str, &str)], &str); 5] = [
        (&[("HTTP_ORIGIN", ORIGIN)], "write_disabled"),
        (&[("MI_TT_ALLOWED_ORIGINS", ORIGIN)], "origin_required"),
        (&[("MI_TT_ALLOWED_ORIGINS", ORIGIN), ("HTTP_ORIGIN", "http://evil.example")], "origin_forbidden"),
        (&[("MI_TT_ALLOWED_ORIGINS", ORIGIN), ("HTTP_ORIGIN", "http://127.0.0.1:8787.evil.example")], "origin_forbidden"),
        (&[("MI_TT_ALLOWED_ORIGINS", ORIGIN), ("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "cross-site")], "cross_site"),
    ];
    for (env, code) in cases {
        let (s, v) = cgi("POST", "/rules", Some(&body), &cfg, env);
        assert_eq!((s, v["error"]["code"].as_str().unwrap()), (403, code));
    }
    assert_eq!(std::fs::read(&cfg).unwrap(), before, "отклонённые запросы не меняют файл");
    assert!(!dir.join("config.json.prev").exists());
}

#[test]
fn invalid_save_changes_nothing() {
    let dir = lab_copy("save-bad");
    let cfg = dir.join("config.json").to_string_lossy().into_owned();
    let before = std::fs::read(&cfg).unwrap();
    let rev = rev_of(&cfg);
    let (s, v) = cgi("POST", "/rules", Some(&save_body(&rev, "r-x", "fridge")), &cfg, &ALLOW);
    assert_eq!(s, 422);
    assert_eq!(v["issues"][0]["code"], "unknown_device");
    assert_eq!(cgi("POST", "/rules", Some(b"{\"base_revision\":1}"), &cfg, &ALLOW).0, 400);
    let bad_cidr = format!(
        r#"{{"base_revision":"{rev}","rule":{{"id":"r-x","source":{{"type":"lan"}},"destination":{{"type":"cidr","value":"10.0.0.1/8"}},"action":{{"type":"block"}}}}}}"#
    );
    assert_eq!(cgi("POST", "/rules", Some(bad_cidr.as_bytes()), &cfg, &ALLOW).0, 422);
    assert_eq!(cgi("GET", "/rules", None, &cfg, &ALLOW).0, 405);
    assert_eq!(std::fs::read(&cfg).unwrap(), before);
}

#[test]
fn concurrent_saves_on_one_revision_admit_exactly_one() {
    let dir = lab_copy("save-race");
    let cfg = dir.join("config.json").to_string_lossy().into_owned();
    let rev = rev_of(&cfg);
    let children: Vec<_> = (0..8)
        .map(|i| {
            let req = tmp(&format!("race{i}.json"), &String::from_utf8(save_body(&rev, &format!("r-race-{i}"), "phone")).unwrap());
            Command::new(bin()).args(["save", &cfg, &req]).stdout(Stdio::piped()).spawn().unwrap()
        })
        .collect();
    let (mut ok, mut conflicts) = (0, 0);
    for c in children {
        let v: Value = serde_json::from_slice(&c.wait_with_output().unwrap().stdout).unwrap();
        if v["ok"] == true {
            ok += 1
        } else if v["error"]["code"] == "revision_conflict" {
            conflicts += 1
        }
    }
    assert_eq!((ok, conflicts), (1, 7));
    let (code, v) = run(&["validate", &cfg]);
    assert_eq!(code, 0);
    assert_eq!(v["config"]["rules"].as_array().unwrap().len(), 1);
}

fn saved_lab(name: &str) -> (PathBuf, String, String) {
    let dir = lab_copy(name);
    let cfg = dir.join("config.json").to_string_lossy().into_owned();
    let req = tmp(&format!("{name}-save.json"), &String::from_utf8(save_body(&rev_of(&cfg), "r-tv-video", "tv")).unwrap());
    assert_eq!(run(&["save", &cfg, &req]).0, 0);
    // пароль профиля — случайный на прогон теста, не постоянное значение в исходниках
    let pw = format!("tt-{}", common::rand_hex(24));
    std::fs::write(dir.join("secrets.json"), serde_json::json!({ "version": 1, "profiles": { "tt-lab": { "password": pw } } }).to_string()).unwrap();
    (dir, cfg, pw)
}

fn p(dir: &std::path::Path, f: &str) -> String {
    dir.join(f).to_string_lossy().into_owned()
}

#[test]
fn render_policy_and_client_for_saved_trusttunnel_rule() {
    let (dir, cfg, pw) = saved_lab("render-ok");
    let out = dir.join("state");
    let o = Command::new(bin()).args(["render", &cfg, &p(&dir, "secrets.json"), &p(&dir, "state")]).output().unwrap();
    let stdout = String::from_utf8(o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(0), "{stdout}");
    assert!(!stdout.contains(&pw), "пароль не печатается");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["tunnel"], true);
    // источник — MAC на входе моста (аренда DHCP не нужна), назначения — наборы ipset: домены и подсети
    let mac = json!({ "type": "mac", "bridge": "br-lan", "mac": "02:00:00:00:0a:02" });
    let rules = v["policy"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2, "{rules:#?}");
    for r in rules {
        assert_eq!((&r["from"], &r["src"], r["act"].as_str()), (&json!("r-tv-video"), &mac, Some("tunnel")));
    }
    let sets: Vec<(&str, &str)> = v["policy"]["sets"].as_array().unwrap().iter().map(|s| (s["name"].as_str().unwrap(), s["kind"].as_str().unwrap())).collect();
    assert_eq!(sets.iter().map(|s| s.1).collect::<Vec<_>>(), ["dns", "static"]);
    assert_eq!(rules[0]["set"], sets[0].0);
    assert_eq!(rules[1]["set"], sets[1].0);
    assert_eq!(v["policy"]["lan_subnets"], json!(["10.10.1.0/24", "10.10.2.0/24"]));
    assert_eq!((v["policy"]["tun"].as_str(), v["policy"]["fail_open"].as_bool()), (Some("mitt0"), Some(false)));
    assert_eq!(v["policy"]["dns_resolver"], "1.1.1.1");
    assert_eq!(v["policy"]["v6_block"], json!([mac]), "IPv6 устройства с правилом туннеля наружу не идёт");
    // те же данные — в policy.json для mi-tt-admin
    let saved: Value = serde_json::from_slice(&std::fs::read(out.join("policy.json")).unwrap()).unwrap();
    assert_eq!(saved, v["policy"]);
    // client.toml официального клиента: адрес сервера, имя из sni, пароль из secrets.json
    let toml = std::fs::read_to_string(out.join("client.toml")).unwrap();
    for want in ["hostname = \"vpn.lab.test\"
", "addresses = [\"10.30.0.2:443\"]
", "username = \"tv-user\"
", "upstream_protocol = \"http2\"
",
        "device_name = \"mitt0\"
", "included_routes = []
", "skip_verification = false
"] {
        assert!(toml.contains(want), "нет {want:?}: {toml}");
    }
    assert!(toml.contains(&format!("password = \"{pw}\"
")));
    // dnsmasq: адреса доменов правила — в набор, сами вопросы — к резолверу туннеля
    let dns = std::fs::read_to_string(out.join("dnsmasq-mitt.conf")).unwrap();
    assert!(dns.contains(&format!("ipset=/video.lab.test/{}
", sets[0].0)) && dns.contains("server=/video.lab.test/1.1.1.1
"), "{dns}");
    assert!(!out.join("nfqws2.args").exists(), "без Zapret аргументов nfqws2 нет");
    let routes: Value = serde_json::from_slice(&std::fs::read(out.join("routes.json")).unwrap()).unwrap();
    let apply: Vec<String> =
        routes["apply"].as_array().unwrap().iter().map(|c| c.as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect::<Vec<_>>().join(" ")).collect();
    // порядок: наборы, запасной unreachable, TUN, обходы LAN, метка, цепочки и только затем переходы в них
    assert!(apply.first().unwrap().starts_with("ipset create mitt"), "{apply:#?}");
    let pos = |want: &str| apply.iter().position(|x| x == want).unwrap_or_else(|| panic!("нет {want}: {apply:#?}"));
    let guard = pos("ip route add unreachable default metric 4096 table 3100");
    let tun = pos("ip route add default dev mitt0 metric 1 table 3100");
    let mark = pos("ip rule add priority 3005 fwmark 0x4000/0x4000 lookup 3100");
    assert!(guard < tun && tun < pos("ip rule add priority 3000 to 10.10.1.0/24 lookup main") && tun < mark, "{apply:#?}");
    assert!(apply.last().unwrap().contains(" -I ") && apply.iter().any(|x| x.contains("--mac-source 02:00:00:00:0A:02 -m set --match-set")), "{apply:#?}");
    assert!(routes["revert"][0][0].as_str().unwrap().ends_with("tables"), "снятие начинается с переходов в наши цепочки");
}

#[test]
fn config_from_0_2_0_with_old_zapret_section_loads_and_renders() {
    // 0.2.0 сохраняла zapret: {strategy: multisplit|multidisorder, pos, tcp_ports}; после обновления такой файл
    // должен читаться (как auto/auto), иначе панель его не покажет и не сможет исправить
    let dir = lab_copy("render-zapret-020");
    let cfg = dir.join("config.json").to_string_lossy().into_owned();
    let mut c: Value = serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
    c["zapret"] = json!({ "strategy": "multidisorder", "pos": 2, "tcp_ports": [80, 443] });
    c["default_action"] = json!({ "type": "direct_zapret" });
    std::fs::write(&cfg, serde_json::to_vec_pretty(&c).unwrap()).unwrap();
    std::fs::write(dir.join("secrets.json"), json!({ "version": 1, "profiles": {} }).to_string()).unwrap();
    let (s, v) = cgi("GET", "/config", None, &cfg, &[]);
    assert_eq!((s, &v["ok"]), (200, &json!(true)), "{v}");
    assert_eq!(v["config"]["zapret"], json!({ "strategy": "auto", "youtube": "auto" }));
    let o = Command::new(bin()).args(["render", &cfg, &p(&dir, "secrets.json"), &p(&dir, "state")]).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stdout));
    let args = std::fs::read_to_string(dir.join("state").join("nfqws2.args")).unwrap();
    assert!(args.contains("=circular:"), "{args}");
}

#[test]
fn render_refuses_when_rule_cannot_be_applied_exactly() {
    let (dir, cfg, _pw) = saved_lab("render-bad");
    let out = p(&dir, "state");
    // сеть без моста: политику по источнику выразить нельзя — ничего не пишется
    let nob = std::fs::read_to_string(&cfg).unwrap().replace("\"bridge\": \"br-lan\",", "");
    let (code, v) = run(&["render", &tmp("render-nobridge.json", &nob), &p(&dir, "secrets.json"), &out]);
    assert_eq!(code, 1, "{v:#}");
    assert_eq!(codes(&v)[0], "config.networks[0].ports:ports_without_bridge");
    assert!(!dir.join("state").exists());
    // нет пароля профиля
    let empty = tmp("render-empty-secrets.json", r#"{"version":1,"profiles":{}}"#);
    let (code, v) = run(&["render", &cfg, &empty, &out]);
    assert_eq!(code, 1);
    assert_eq!(codes(&v), ["rules[0].action:no_secret"]);
    assert!(!dir.join("state").exists());
}

#[test]
fn endpoint_validation() {
    let bad = r#"{"version":1,"profiles":[{"id":"t","name":"T","kind":"trusttunnel","endpoint":{"server":"vpn.example.com","port":0,"sni":"*.x","username":"a:b","certificate":"zz"}}],
                  "networks":[{"id":"h","name":"H","ssid":"H","subnet":"10.0.0.1/24"}],"default_action":{"type":"direct"}}"#;
    let (code, v) = run(&["validate", &tmp("bad-endpoint.json", bad)]);
    assert_eq!(code, 1);
    assert_eq!(
        codes(&v),
        [
            "networks[0].subnet:bad_cidr",
            "profiles[0].endpoint.server:bad_server",
            "profiles[0].endpoint.port:bad_port",
            "profiles[0].endpoint.sni:bad_sni",
            "profiles[0].endpoint.username:bad_username",
            "profiles[0].endpoint.certificate:bad_certificate"
        ]
    );
}
