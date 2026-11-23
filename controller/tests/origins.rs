//! Панель по своему домену: домен из «Своих DNS-записей», указывающий на адрес роутера в LAN (и его поддомены), допущен
//! к записи; домен на другой адрес и похожие имена — нет.

use std::path::PathBuf;

use serde_json::Value;

mod common;
use common::*;

#[test]
fn custom_dns_domain_pointing_to_router_is_allowed() {
    let mut a = Auth::new("origins");
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("or-{}", rand_hex(6)));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg: Value = serde_json::from_slice(&std::fs::read(fixture("lab/config.json")).unwrap()).unwrap();
    cfg["dns"] = serde_json::json!({ "hosts": [
        { "domain": "panel.home.test", "address": "127.0.0.1" },
        { "domain": "nas.home.test", "address": "192.168.31.10" },
    ] });
    std::fs::write(dir.join("config.json"), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
    a.config = dir.join("config.json").to_string_lossy().into_owned();
    // LAN роутера — 127.0.0.1 (как у ORIGIN стенда тестов https://127.0.0.1:8787)
    let uci = dir.join("network");
    std::fs::write(&uci, "config interface 'lan'\n\toption ipaddr '127.0.0.1'\n\toption netmask '255.0.0.0'\n").unwrap();
    let uci = uci.to_string_lossy().into_owned();
    let t = T0 + 60;
    let s = a.login(t);
    let post = |origin: &str| {
        a.cgi("POST", "/apply-request", Some(b"{}"), t + 1, &[("HTTP_COOKIE", &s.cookie), ("HTTP_ORIGIN", origin), ("HTTP_SEC_FETCH_SITE", "same-origin"),
            ("HTTP_X_MITT_CSRF", &s.csrf), ("MI_TT_UCI_NETWORK", &uci)])
    };
    for ok in ["https://panel.home.test:8787", "https://panel.home.test", "https://ui.panel.home.test:8787", ORIGIN] {
        assert_eq!(post(ok).status, 202, "{ok}: {}", post(ok).body);
    }
    for bad in ["https://nas.home.test:8787", "https://evilpanel.home.test:8787", "http://panel.home.test:8787", "https://panel.home.test:9999", "https://a/b.panel.home.test:8787"] {
        assert_eq!(post(bad).code(), "origin_forbidden", "{bad}");
    }
}
