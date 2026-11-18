//! Этап 12: управление устройствами и сетями (SSID) из панели под 2FA и выбор устройства из аренд DHCP.
//! Всё через настоящий CGI после пароля и TOTP.

use std::path::PathBuf;

use serde_json::{Value, json};

mod common;
use common::*;

struct Panel {
    a: Auth,
    s: Sess,
    t: u64,
    dir: PathBuf,
}

impl Panel {
    fn new(name: &str) -> Panel {
        let mut a = Auth::new(name);
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("s12-{name}-{}", rand_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(fixture("lab/config.json"), dir.join("config.json")).unwrap();
        a.config = dir.join("config.json").to_string_lossy().into_owned();
        let t = T0 + 60;
        let s = a.login(t);
        Panel { a, s, t, dir }
    }
    fn rev(&self) -> String {
        self.a.api(&self.s, "GET", "/config", None, self.t).body["revision"].as_str().unwrap().to_string()
    }
    fn post(&self, path: &str, body: Value) -> Out {
        self.a.api(&self.s, "POST", path, Some(body.to_string().as_bytes()), self.t + 1)
    }
    fn config(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.dir.join("config.json")).unwrap()).unwrap()
    }
}

#[test]
fn networks_and_devices_crud_with_validation() {
    let p = Panel::new("netdev");
    // без сессии — отказ
    let o = p.a.cgi("POST", "/devices", Some(b"{}"), p.t, &[("HTTP_ORIGIN", ORIGIN), ("HTTP_SEC_FETCH_SITE", "same-origin")]);
    assert_eq!(o.code(), "auth_required");
    assert_eq!(p.a.cgi("GET", "/leases", None, p.t, &[]).code(), "auth_required");

    // новая сеть (SSID гостевой 5 ГГц) и устройство в ней
    let net = json!({ "id": "iot", "name": "Умный дом", "ssid": "Home-IoT", "subnet": "10.10.3.0/24", "bridge": "br-iot", "ports": ["wl2"] });
    let o = p.post("/networks", json!({ "base_revision": p.rev(), "network": net }));
    assert_eq!(o.status, 200, "{}", o.body);
    let dev = json!({ "id": "lamp", "name": "Лампа", "mac": "02:00:00:00:1C:02", "network": "iot" });
    let o = p.post("/devices", json!({ "base_revision": p.rev(), "device": dev }));
    assert_eq!(o.status, 200, "{}", o.body);
    let c = p.config();
    assert!(c["networks"].as_array().unwrap().iter().any(|n| n["id"] == "iot" && n["ssid"] == "Home-IoT"));
    assert!(c["devices"].as_array().unwrap().iter().any(|d| d["id"] == "lamp" && d["network"] == "iot"));

    // правило для нового устройства и правило для новой сети (SSID)
    for (id, src) in [("lamp-vpn", json!({ "type": "device", "id": "lamp" })), ("iot-vpn", json!({ "type": "network", "id": "iot" }))] {
        let r = json!({ "id": id, "source": src, "destination": { "type": "cidr", "value": "10.99.0.0/24" }, "action": { "type": "profile", "id": "tt-lab" } });
        let o = p.a.api(&p.s, "POST", "/rules", Some(json!({ "base_revision": p.rev(), "rule": r }).to_string().as_bytes()), p.t);
        assert_eq!(o.status, 200, "{}", o.body);
    }

    // ошибки: неверный MAC, устройство в несуществующей сети, порт уже занят другой сетью — ничего не записано
    let before = std::fs::read(p.dir.join("config.json")).unwrap();
    let o = p.post("/devices", json!({ "base_revision": p.rev(), "device": { "id": "bad", "name": "x", "mac": "zz:00", "network": "iot" } }));
    assert_eq!(o.status, 422, "{}", o.body);
    let o = p.post("/devices", json!({ "base_revision": p.rev(), "device": { "id": "bad", "name": "x", "mac": "02:00:00:00:0d:02", "network": "nope" } }));
    assert_eq!(o.status, 422, "{}", o.body);
    let o = p.post("/networks", json!({ "base_revision": p.rev(), "network": { "id": "dup", "name": "x", "ssid": "x", "bridge": "br-lan", "ports": ["r-tv"] } }));
    assert_eq!(o.status, 422, "порт r-tv уже в сети home: {}", o.body);
    assert_eq!(std::fs::read(p.dir.join("config.json")).unwrap(), before, "отклонённые изменения не записаны");

    // удалить сеть с устройствами и правилом нельзя; устройство с правилом — тоже
    assert_eq!(p.post("/networks/delete", json!({ "base_revision": p.rev(), "id": "iot" })).status, 422);
    assert_eq!(p.post("/devices/delete", json!({ "base_revision": p.rev(), "id": "lamp" })).status, 422);
    // после удаления правил — можно
    for id in ["lamp-vpn", "iot-vpn"] {
        assert_eq!(p.post("/rules/delete", json!({ "base_revision": p.rev(), "id": id })).status, 200);
    }
    assert_eq!(p.post("/devices/delete", json!({ "base_revision": p.rev(), "id": "lamp" })).status, 200);
    let o = p.post("/networks/delete", json!({ "base_revision": p.rev(), "id": "iot" }));
    assert_eq!(o.status, 200, "{}", o.body);
    let c = p.config();
    assert!(!c["networks"].as_array().unwrap().iter().any(|n| n["id"] == "iot"));
    // GET на изменяющий адрес — 405
    assert_eq!(p.a.api(&p.s, "GET", "/devices", None, p.t).status, 405);
}

#[test]
fn csrf_via_authorization_only_behind_trusted_proxy() {
    // штатный uhttpd не передаёт X-MITT-CSRF; nginx перекладывает токен в Authorization: MITT-CSRF <токен>
    let p = Panel::new("csrf-proxy");
    let auth = format!("MITT-CSRF {}", p.s.csrf);
    let base = [("HTTP_ORIGIN", ORIGIN), ("HTTP_COOKIE", p.s.cookie.as_str()), ("HTTP_AUTHORIZATION", auth.as_str())];
    let o = p.a.cgi("POST", "/apply-request", Some(b"{}"), p.t, &base);
    assert_eq!(o.code(), "csrf_failed", "без доверенного прокси Authorization не заменяет X-MITT-CSRF");
    let lo = [("MI_TT_TRUST_PROXY", "1"), ("REMOTE_ADDR", "127.0.0.1"), ("SERVER_ADDR", "127.0.0.1")];
    let o = p.a.cgi("POST", "/apply-request", Some(b"{}"), p.t, &[base[0], base[1], base[2], lo[0], lo[1], ("REMOTE_ADDR", "10.10.1.2"), lo[2]]);
    assert_eq!(o.code(), "csrf_failed", "клиент LAN не доверенный прокси");
    let bad = format!("MITT-CSRF {}x", p.s.csrf);
    let o = p.a.cgi("POST", "/apply-request", Some(b"{}"), p.t, &[base[0], base[1], ("HTTP_AUTHORIZATION", bad.as_str()), lo[0], lo[1], lo[2]]);
    assert_eq!(o.code(), "csrf_failed", "неверный токен");
    let o = p.a.cgi("POST", "/apply-request", Some(b"{}"), p.t, &[base[0], base[1], ("HTTP_AUTHORIZATION", "MITT-CSRF "), lo[0], lo[1], lo[2]]);
    assert_eq!(o.code(), "csrf_failed", "пустой токен (клиент не прислал X-MITT-CSRF)");
    let o = p.a.cgi("POST", "/apply-request", Some(b"{}"), p.t, &[base[0], base[1], base[2], lo[0], lo[1], lo[2]]);
    assert_eq!(o.status, 202, "{}", o.body);
}

#[test]
fn leases_list_for_device_picker() {
    let p = Panel::new("leases");
    let lf = p.dir.join("dhcp.leases");
    // формат dnsmasq; имя клиента — данные из LAN: управляющие символы убираются, длина ограничена
    std::fs::write(
        &lf,
        format!(
            "1795000000 02:00:00:00:0a:02 10.10.1.2 tv-box *\n1795000000 02:00:00:00:0e:02 10.10.1.77 {} 01:02\n1795000000 02:00:00:00:0f:02 10.10.1.78 * *\nmusor\n",
            "x".repeat(100)
        ),
    )
    .unwrap();
    let lfs = lf.to_string_lossy().into_owned();
    let o = p.a.cgi("GET", "/leases", None, p.t, &[("HTTP_COOKIE", &p.s.cookie), ("MI_TT_LEASES", &lfs)]);
    assert_eq!(o.status, 200, "{}", o.body);
    let l = o.body["leases"].as_array().unwrap();
    assert_eq!(l.len(), 3, "{}", o.body);
    assert_eq!((l[0]["mac"].as_str(), l[0]["ip"].as_str(), l[0]["device"].as_str()), (Some("02:00:00:00:0a:02"), Some("10.10.1.2"), Some("tv")), "известное устройство помечено");
    assert!(l[1]["device"].is_null());
    assert_eq!(l[1]["hostname"].as_str().unwrap().len(), 64);
    assert_eq!(l[2]["hostname"], "");
    // файла аренд нет — пустой список, не ошибка
    let o = p.a.cgi("GET", "/leases", None, p.t, &[("HTTP_COOKIE", &p.s.cookie), ("MI_TT_LEASES", "/nonexistent/dhcp.leases")]);
    assert_eq!((o.status, o.body["leases"].as_array().map(Vec::len)), (200, Some(0)));
}
