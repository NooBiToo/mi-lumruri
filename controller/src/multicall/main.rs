//! mi-tt — одна программа вместо трёх (как BusyBox): общий код (serde, TLS, SHA-256, std) хранится один раз, пакет
//! меньше на ~0,5 МБ, в RAM — на ~1,2 МБ. Что выполнять — по имени, под которым программа запущена (ссылки mi-tt-ctl,
//! mi-tt-admin, mi-tt-dns и их копии вида mi-tt-admin.run, verify-admin). Для разработки и тестов остаются и
//! отдельные программы.
#![allow(dead_code)]

#[path = "../main.rs"]
mod ctl;
#[path = "../admin/main.rs"]
mod admin;
#[path = "../dnsproxy/main.rs"]
mod dns;

use std::process::ExitCode;

/// Какую программу выполнять по имени файла: admin, dns или ctl (порядок важен: «mi-tt-admin» содержит и «mi-tt»).
fn applet(name: &str) -> Option<&'static str> {
    if name.contains("admin") {
        Some("admin")
    } else if name.contains("-dns") || name == "dns" {
        Some("dns")
    } else if name.contains("ctl") {
        Some("ctl")
    } else {
        None
    }
}

fn run(which: &str) -> ExitCode {
    match which {
        "admin" => admin::main(),
        "dns" => {
            dns::main();
            ExitCode::SUCCESS
        }
        _ => ctl::main(),
    }
}

fn main() -> ExitCode {
    let argv0 = std::env::args_os().next().unwrap_or_default();
    let name = std::path::Path::new(&argv0).file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
    if let Some(a) = applet(&name) {
        return run(a);
    }
    eprintln!("mi-tt: запускайте через ссылки mi-tt-ctl, mi-tt-admin или mi-tt-dns");
    ExitCode::from(2)
}
