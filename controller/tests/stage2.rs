//! Этап 2: сохранение правила, защита записи, гонка записей, формирование конфигурации Mihomo.

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
fn render_mihomo_for_saved_trusttunnel_rule() {
    let (dir, cfg, pw) = saved_lab("render-ok");
    std::fs::write(dir.join("leases"), "1999999999 02:00:00:00:0a:02 10.10.1.2 tv *\n").unwrap();
    let out = dir.join("mihomo");
    let o = Command::new(bin()).args(["render", &cfg, &p(&dir, "secrets.json"), &p(&dir, "leases"), &p(&dir, "mihomo")]).output().unwrap();
    let stdout = String::from_utf8(o.stdout).unwrap();
    assert_eq!(o.status.code(), Some(0), "{stdout}");
    assert!(!stdout.contains(&pw), "пароль не печатается");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    // этап 4: источник для маршрутизации — MAC на входе моста (метка), IP нужен только Mihomo
    assert_eq!(v["capture"]["devices"], json!([{"id": "tv", "mac": "02:00:00:00:0a:02", "ipv4": "10.10.1.2", "bridge": "br-lan", "mark": 0x0a01_0000u32}]));
    assert_eq!(
        v["rules"],
        json!([
            "AND,((SRC-IP-CIDR,10.10.1.2/32),(DOMAIN-SUFFIX,video.lab.test)),tt-lab",
            "AND,((SRC-IP-CIDR,10.10.1.2/32),(IP-CIDR,10.99.0.0/24)),tt-lab",
            // этап 4: источник, неизвестный этой конфигурации, не уходит в MATCH/DIRECT
            "NOT,((SRC-IP-CIDR,10.10.1.2/32)),REJECT",
            "MATCH,DIRECT"
        ])
    );
    let m: Value = serde_json::from_slice(&std::fs::read(out.join("config.yaml")).unwrap()).unwrap();
    let px = &m["proxies"][0];
    assert_eq!((px["type"].as_str(), px["server"].as_str(), px["port"].as_u64()), (Some("trusttunnel"), Some("10.30.0.2"), Some(443)));
    assert_eq!(px["password"], pw.as_str());
    assert_eq!(px["fingerprint"], "ee".repeat(32)  /* заглушка фикстуры: лаборатории ставят отпечаток эфемерного сертификата */);
    assert_eq!(m["tun"]["auto-route"], false);
    let routes: Value = serde_json::from_slice(&std::fs::read(out.join("routes.json")).unwrap()).unwrap();
    let apply: Vec<String> =
        routes["apply"].as_array().unwrap().iter().map(|c| c.as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect::<Vec<_>>().join(" ")).collect();
    assert_eq!(m["ipv6"], false, "TUN без IPv6: sing-tun не добавляет своё правило oif mitt0");
    // порядок: запасной unreachable, TUN, обходы, запреты, захват, затем дисциплина и фильтр, ставящий метку
    assert_eq!(apply.first().unwrap(), "ip route add unreachable default metric 4096 table 3100");
    assert_eq!(
        apply.last().unwrap(),
        "tc filter add dev br-lan ingress pref 1001 protocol all flower src_mac 02:00:00:00:0a:02 action skbedit mark 0xa010000/0xfff0000 continue"
    );
    for want in [
        "ip rule add priority 3100 from 10.10.1.2 fwmark 0xa010000/0xfff0000 lookup 3100",
        "ip rule add priority 3105 fwmark 0xa000000/0xf800000 unreachable",
        "ip -6 rule add priority 3120 fwmark 0xa000000/0xf000000 unreachable",
        "ip -6 rule add priority 3000 to fe80::/10 lookup main",
        "tc qdisc add dev br-lan clsact",
    ] {
        assert!(apply.iter().any(|x| x == want), "нет {want}: {apply:#?}");
    }
    assert_eq!(routes["revert"][0][0], "tc", "снятие начинается с меток");
}

#[test]
fn render_refuses_when_rule_cannot_be_applied_exactly() {
    let (dir, cfg, _pw) = saved_lab("render-bad");
    let out = p(&dir, "mihomo");
    // этап 4: нет аренды для MAC телевизора — не ошибка: устройство защищается по MAC (метка → unreachable),
    // в Mihomo его правило не попадает, в предупреждениях это видно
    std::fs::write(dir.join("leases"), "1999999999 02:00:00:00:0b:02 10.10.1.3 phone *\n").unwrap();
    let (code, v) = run(&["render", &cfg, &p(&dir, "secrets.json"), &p(&dir, "leases"), &format!("{out}-nolease")]);
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(v["capture"]["devices"][0]["ipv4"], Value::Null);
    assert_eq!(v["rules"], json!(["MATCH,REJECT", "MATCH,DIRECT"]), "без известных источников весь трафик TUN отклоняется");
    assert!(v["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("без аренды")));
    let plan: Vec<&str> = v["plan"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
    assert!(plan.contains(&"ip rule priority 3105 fwmark 0xa000000/0xf800000 unreachable"));
    assert!(!plan.iter().any(|x| x.contains("priority 3100 ")));
    // сеть без моста: политику по источнику выразить нельзя — ничего не пишется
    let nob = std::fs::read_to_string(&cfg).unwrap().replace("\"bridge\": \"br-lan\",", "");
    let (code, v) = run(&["render", &tmp("render-nobridge.json", &nob), &p(&dir, "secrets.json"), &p(&dir, "leases"), &out]);
    assert_eq!(code, 1, "{v:#}");
    assert_eq!(codes(&v)[0], "config.networks[0].ports:ports_without_bridge");
    assert!(!dir.join("mihomo").exists());
    // нет пароля профиля
    std::fs::write(dir.join("leases"), "1999999999 02:00:00:00:0a:02 10.10.1.2 tv *\n").unwrap();
    let empty = tmp("render-empty-secrets.json", r#"{"version":1,"profiles":{}}"#);
    let (code, v) = run(&["render", &cfg, &empty, &p(&dir, "leases"), &out]);
    assert_eq!(code, 1);
    assert_eq!(codes(&v), ["rules[0].action:no_secret"]);
    assert!(!dir.join("mihomo").exists());
}

#[test]
fn endpoint_validation() {
    let bad = r#"{"version":1,"profiles":[{"id":"t","name":"T","kind":"trusttunnel","endpoint":{"server":"bad host","port":0,"sni":"*.x","username":"a:b","cert_sha256":"zz"}}],
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
            "profiles[0].endpoint.cert_sha256:bad_fingerprint"
        ]
    );
}
