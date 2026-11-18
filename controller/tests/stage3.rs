//! Этап 3: разделение привилегий. Применение к сети есть только в mi-tt-admin; из CGI он не запускается.
//! Реальное применение проверяется в лаборатории Linux (tools/lab), здесь — то, что не требует ядра.

use std::process::Command;

use serde_json::Value;

fn run(bin: &str, args: &[&str], env: &[(&str, &str)]) -> (i32, Value) {
    let mut c = Command::new(bin);
    c.args(args).env_remove("GATEWAY_INTERFACE").env_remove("REQUEST_METHOD").env_remove("SERVER_SOFTWARE").env_remove("HTTP_HOST");
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    (o.status.code().unwrap(), serde_json::from_slice(&o.stdout).unwrap_or(Value::Null))
}

const ADMIN: &str = env!("CARGO_BIN_EXE_mi-tt-admin");
const CTL: &str = env!("CARGO_BIN_EXE_mi-tt-ctl");

#[test]
fn admin_refuses_cgi_environment() {
    for (k, v) in [("GATEWAY_INTERFACE", "CGI/1.1"), ("REQUEST_METHOD", "POST"), ("SERVER_SOFTWARE", "uhttpd"), ("HTTP_HOST", "127.0.0.1")] {
        let (code, out) = run(ADMIN, &["revert", "--state-dir", "nowhere"], &[(k, v)]);
        assert_eq!(code, 77, "{k}");
        assert_eq!(out["error"]["code"], "cgi_forbidden");
    }
}

#[test]
fn admin_usage_errors_change_nothing() {
    let (code, out) = run(ADMIN, &["apply"], &[]);
    assert_eq!((code, out["error"]["code"].as_str()), (2, Some("usage")));
    let (code, out) = run(ADMIN, &["apply", "--state-dir", "x"], &[]);
    assert_eq!((code, out["error"]["code"].as_str()), (2, Some("usage")), "без --config ничего не применяется");
    let (code, _) = run(ADMIN, &["frobnicate", "--state-dir", "x"], &[]);
    assert_eq!(code, 2);
}

#[test]
fn cgi_binary_has_no_apply_commands() {
    for cmd in ["apply", "revert", "status", "plan"] {
        let o = Command::new(CTL).arg(cmd).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "mi-tt-ctl {cmd} не существует");
    }
    // и через CGI нет адресов применения
    let o = Command::new(CTL)
        .arg("cgi")
        .env("REQUEST_METHOD", "POST")
        .env("PATH_INFO", "/apply")
        .env("CONTENT_TYPE", "application/json")
        .env("CONTENT_LENGTH", "0")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("Status: 404"));
}
