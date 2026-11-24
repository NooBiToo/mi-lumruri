//! mi-tt-ctl — контроллер Mi Lumruri, срез «чтение, проверка и предпросмотр правила».
//! Ничего не применяет к сети и не записывает настройки.

use mi_tt::{api, auth, gate, model, render, store, zapret};

use std::io::{self, Read, Write};
use std::process::ExitCode;

use api::{MAX_BODY_BYTES, MAX_CONFIG_BYTES, Response, WriteAccess, check_origin, handle, read_limited, reason};

const DEFAULT_CONFIG: &str = "/data/mi-lumruri/config.json";
const USAGE: &str = "mi-tt-ctl — чтение, проверка и предпросмотр правил (срез без применения)

  mi-tt-ctl validate <config.json>
  mi-tt-ctl preview <config.json> <request.json>
  mi-tt-ctl save <config.json> <request.json>        # {\"base_revision\", \"rule\"}: атомарно, с блокировкой
  mi-tt-ctl render <config.json> <secrets.json> <out-dir>   # client.toml TrustTunnel, policy.json, dnsmasq, nfqws2.args
  mi-tt-ctl adblock-update <config.json> <list>      # проверить и атомарно заменить adblock.list рядом с настройками
  mi-tt-ctl category-update <config.json> <id> <list> # проверить и атомарно заменить categories/<id>.list
  mi-tt-ctl category-check <domain|ip> <list>        # проверить файл списка по виду, ничего не записывая
  mi-tt-ctl zapret-list <general|youtube>            # кандидаты подбора стратегии Zapret (без auto), по строке
  mi-tt-ctl zapret-args <strategy-id>                # аргументы nfqws2 для проверки одной стратегии на очереди 201
  mi-tt-ctl zapret-set <config.json> <general|youtube> <id>   # атомарно сменить выбор стратегии Zapret
  mi-tt-ctl zapret-get <config.json>                 # текущий выбор: строки «general <id>» и «youtube <id>»
  mi-tt-ctl cgi            # CGI для uhttpd (HTTPS): вход паролем и TOTP, затем /config, /preview, /rules
                           # MI_TT_CONFIG, MI_TT_ALLOWED_ORIGINS, MI_TT_AUTH_DIR, MI_TT_SESSION_DIR
  mi-tt-ctl --version

Код выхода: 0 — проверка пройдена, 1 — найдены ошибки, 2 — ошибка запуска или чтения.";

pub fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["--version"] => {
            println!("mi-tt-ctl {} (schema v{})", env!("CARGO_PKG_VERSION"), model::SCHEMA_VERSION);
            ExitCode::SUCCESS
        }
        ["validate", cfg] => cli(handle("GET", "/config", None, cfg)),
        ["preview", cfg, req] => match read_limited(req, MAX_BODY_BYTES as u64) {
            Ok(body) => cli(handle("POST", "/preview", Some(&body), cfg)),
            Err(m) => cli(Response::error(500, "request_unreadable", m)),
        },
        ["save", cfg, req] => match read_limited(req, MAX_BODY_BYTES as u64) {
            Ok(body) => cli(handle("POST", "/rules", Some(&body), cfg)),
            Err(m) => cli(Response::error(500, "request_unreadable", m)),
        },
        ["render", cfg, secrets, out] => cli(render_cmd(cfg, secrets, out)),
        ["adblock-update", cfg, list] => cli(adblock_update(cfg, list)),
        ["category-update", cfg, id, list] => cli(category_update(cfg, id, list)),
        ["category-check", kind, list] => cli(category_check(kind, list)),
        ["adblock-check", list] => cli(adblock_check(list)),
        // подписка TrustTunnel: ссылка для mitt-sub.sh (печать, без JSON) и перенос скачанного ответа в настройки
        ["subscription-url", cfg, profile] => match mi_tt::manage::subscription_url(cfg, profile) {
            Some(u) => {
                println!("{u}");
                ExitCode::SUCCESS
            }
            None => ExitCode::from(1),
        },
        ["subscription-import", cfg, profile, json] => cli(mi_tt::manage::subscription_import(cfg, profile, json)),
        // подписка сервера модуля sing-box: список ссылок
        ["proxy-sub-import", cfg, profile, file] => cli(mi_tt::proxysub::import(cfg, profile, file)),
        // серверы с подпиской: строки «id вид»
        ["subscription-list", cfg] => match mi_tt::manage::subscription_list(cfg) {
            Ok(v) => lines(v),
            Err(m) => { eprintln!("mi-tt-ctl: {m}"); ExitCode::from(2) }
        },
        ["zapret-list", kind] => match zapret_kind(kind) {
            Some(k) => lines(zapret::candidates(k).into_iter().map(str::to_string)),
            None => usage(),
        },
        ["zapret-args", id] => match zapret::test_args(id, mi_tt::plan::ZAPRET_TEST_QNUM) {
            Ok(a) => lines(a),
            Err(m) => {
                eprintln!("mi-tt-ctl: {m}");
                ExitCode::from(1)
            }
        },
        ["zapret-get", cfg] => match read_limited(cfg, MAX_CONFIG_BYTES).map_err(|m| m.to_string()).and_then(|b| api::parse_json::<model::Config>(&b, "config").map_err(|_| "настройки не разобраны".into())) {
            Ok(c) => {
                let z = c.zapret.unwrap_or_default();
                lines([format!("general {}", z.strategy), format!("youtube {}", z.youtube)])
            }
            Err(m) => {
                eprintln!("mi-tt-ctl: {m}");
                ExitCode::from(2)
            }
        },
        ["zapret-set", cfg, kind, id] => match zapret_kind(kind) {
            Some(k) => cli(zapret_set(cfg, k, id)),
            None => usage(),
        },
        ["cgi"] => cgi(),
        // параметры уведомлений для mitt-notify.sh; код 1 — не настроены
        // показания счётчиков для статистики трафика (служба, раз в несколько минут)
        ["stats-sample", file, vpn, wan, rest @ ..] if rest.len() <= 1 => match mi_tt::stats::sample_cmd(file, vpn, wan, rest.first().copied(), auth::now()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(m) => { eprintln!("{m}"); ExitCode::from(2) }
        },
        // модули: каталог и установленные (служба, mitt-module.sh)
        ["module-info" | "module-list" | "module-record", ..] => match mi_tt::modules::cli(&a, auth::now()) {
            Ok(t) => { print!("{t}"); ExitCode::SUCCESS }
            Err(m) => { eprintln!("{m}"); ExitCode::from(2) }
        },
        // AmneziaWG: команды UAPI в сокет amneziawg-go (служба, после запуска программы)
        ["awg-set", dev, file] => match mi_tt::awg::set_cmd(dev, file) {
            Ok(()) => ExitCode::SUCCESS,
            Err(m) => { eprintln!("mi-tt-ctl: {m}"); ExitCode::from(2) }
        },
        // накопители: /proc/mounts и df -k от службы → storage.json для панели
        ["storage-scan", mounts, df, out] => match mi_tt::storage::scan_cmd(mounts, df, out, auth::now()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(m) => { eprintln!("{m}"); ExitCode::from(2) }
        },
        // решения о клиенте TrustTunnel (сторож, запасной сервер, выбор по задержке) — см. tunnel.rs
        ["tunnel", cmd @ ("due" | "step"), "--dir", dir, rest @ ..] => match mi_tt::tunnel::cli(cmd, dir, rest, auth::now()) {
            Ok(t) => { print!("{t}"); ExitCode::SUCCESS }
            Err(m) => { eprintln!("{m}"); ExitCode::from(2) }
        },
        // ожидание условия с шагом 200 мс (BusyBox стока не умеет дробный sleep): код 0 — дождались, 1 — нет
        ["wait", ms, cond @ ..] => match ms.parse::<u64>().map_err(|e| e.to_string()).and_then(|ms| mi_tt::tunnel::wait(ms, cond)) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(1),
            Err(m) => { eprintln!("{m}"); ExitCode::from(2) }
        },
        // имена, которые устройства объявляют в LAN (mDNS, SSDP) — служба, раз в несколько минут
        ["names-scan", "--from", from, "--out", out, rest @ ..] => {
            let wait = match rest { ["--wait", ms] => ms.parse().unwrap_or(3000), _ => 3000 };
            match mi_tt::discover::scan_cmd(from, out, wait, auth::now()) {
                Ok(n) => { println!("{n}"); ExitCode::SUCCESS }
                Err(m) => { eprintln!("{m}"); ExitCode::from(2) }
            }
        }
        ["notify-conf", secrets] => match read_limited(secrets, 256 * 1024).ok().and_then(|b| serde_json::from_slice::<render::Secrets>(&b).ok()).and_then(|s| mi_tt::notify::conf_lines(&s)) {
            Some(l) => { print!("{l}"); ExitCode::SUCCESS }
            None => ExitCode::from(1),
        },
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// Аргументы по одному в строке (как nfqws2.args): их читает сценарий подбора на роутере.
fn lines(v: impl IntoIterator<Item = String>) -> ExitCode {
    let mut out = io::stdout().lock();
    for l in v {
        let _ = writeln!(out, "{l}");
    }
    ExitCode::SUCCESS
}

fn zapret_kind(k: &str) -> Option<zapret::Kind> {
    match k {
        "general" => Some(zapret::Kind::General),
        "youtube" => Some(zapret::Kind::Youtube),
        _ => None,
    }
}

/// Смена выбора стратегии Zapret сценарием подбора: через `store::update_config` (блокировка, проверка всей
/// конфигурации, копия .prev, атомарная запись) по текущей ревизии. Ответ — прежний id для отката.
fn zapret_set(cfg: &str, kind: zapret::Kind, id: &str) -> Response {
    use serde_json::json;
    let p = std::path::Path::new(cfg);
    let rev = match read_limited(cfg, MAX_CONFIG_BYTES) {
        Ok(b) => store::revision(&b),
        Err(m) => return Response::error(500, "unreadable", m),
    };
    let field = if kind == zapret::Kind::General { "general" } else { "youtube" };
    let mut previous = String::new();
    let r = store::update_config(p, &rev, MAX_CONFIG_BYTES, |c| {
        let z = c.zapret.get_or_insert_with(Default::default);
        let slot = if kind == zapret::Kind::General { &mut z.strategy } else { &mut z.youtube };
        previous = std::mem::replace(slot, id.to_string());
        Ok("set")
    });
    match r {
        Ok(s) => Response { status: 200, body: json!({ "ok": true, "field": field, "previous": previous, "id": id, "revision": s.revision, "issues": [] }) },
        Err(store::SaveError::RuleInvalid(i)) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "invalid", "message": "стратегия не принята; настройки не изменены" }, "issues": i }) },
        Err(store::SaveError::ConfigInvalid(i)) => Response { status: 409, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "сохранённые настройки не проходят проверку" }, "issues": i }) },
        Err(store::SaveError::Conflict { .. }) => Response::error(409, "revision_conflict", "настройки изменились во время записи; повторите"),
        Err(store::SaveError::Busy(m)) => Response::error(503, "busy", m),
        Err(store::SaveError::Io(m)) => Response::error(500, "write_failed", m),
    }
}

fn cli(r: Response) -> ExitCode {
    let out = serde_json::to_string_pretty(&r.body).unwrap_or_default();
    println!("{out}");
    let ok = r.body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    match r.status {
        200 if ok => ExitCode::SUCCESS,
        200 | 409 | 422 | 400 | 403 => ExitCode::from(1),
        _ => ExitCode::from(2),
    }
}

fn render_cmd(cfg: &str, secrets: &str, out: &str) -> Response {
    use serde_json::json;
    let read = |p: &str, max: u64| read_limited(p, max).map_err(|m| Response::error(500, "unreadable", m));
    let (c, s) = match (read(cfg, MAX_CONFIG_BYTES), read(secrets, 64 * 1024)) {
        (Ok(c), Ok(s)) => (c, s),
        (Err(r), _) | (_, Err(r)) => return r,
    };
    let config: model::Config = match api::parse_json(&c, "config") {
        Ok(v) => v,
        Err(i) => return Response { status: 422, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки не разобраны" }, "issues": i }) },
    };
    let sec: render::Secrets = match api::parse_json(&s, "secrets") {
        Ok(v) => v,
        Err(i) => return Response { status: 422, body: json!({ "ok": false, "error": { "code": "secrets_invalid", "message": "secrets.json не разобран" }, "issues": i }) },
    };
    let mut warnings = Vec::new();
    #[cfg(unix)]
    if let Ok(m) = std::fs::metadata(secrets) {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            warnings.push(format!("{secrets} доступен не только владельцу (режим {:o})", m.permissions().mode() & 0o777));
        }
    }
    let cfg_path = std::path::Path::new(cfg);
    let lists = match render::load_lists(&config, cfg_path) {
        Ok(l) => l,
        Err(m) => return Response { status: 422, body: json!({ "ok": false, "error": { "code": "list_invalid", "message": m }, "issues": [] }) },
    };
    match render::render(&config, &sec, &lists) {
        Err(i) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "not_renderable", "message": "действующую конфигурацию нельзя сформировать точно; ничего не записано" }, "issues": i }) },
        Ok(r) => {
            let dir = std::path::Path::new(out);
            let policy = serde_json::to_vec_pretty(&r.policy).unwrap_or_default();
            let routes = serde_json::to_vec_pretty(&r.routes).unwrap_or_default();
            let opt = |name: &str, body: Option<String>, private: bool| -> Result<(), String> {
                let f = dir.join(name);
                match body {
                    None => {
                        let _ = std::fs::remove_file(&f);
                        Ok(())
                    }
                    Some(b) => {
                        store::write_atomic(&f, b.as_bytes())?;
                        #[cfg(unix)]
                        if private {
                            use std::os::unix::fs::PermissionsExt;
                            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("{}: {e}", f.display()))?;
                        }
                        let _ = private;
                        Ok(())
                    }
                }
            };
            if let Err(m) = std::fs::create_dir_all(dir)
                .map_err(|e| format!("не удалось создать каталог {}: {e}", dir.display()))
                .and_then(|_| store::write_atomic(&dir.join("policy.json"), &policy))
                .and_then(|_| store::write_atomic(&dir.join("routes.json"), &routes))
                .and_then(|_| write_tunnels(dir, &r.tunnels))
                .and_then(|_| write_dns_file(&config, &r.dns, cfg_path, dir, tunnel_dns_args(&config, &r).is_some()))
                // параметры mi-tt-dns по одному в строке; нет файла — защищённый DNS выключен
                .and_then(|_| opt("dns-proxy.args", config.dns.as_ref().and_then(|d| d.secure.as_ref()).and_then(|s| s.proxy_args())
                    .map(|a| a.join("\n") + "\n"), false))
                // второй mi-tt-dns — для доменов туннеля; нужен, только когда туннель есть и в него идут домены
                .and_then(|_| opt("dns-tunnel.args", tunnel_dns_args(&config, &r).map(|a| a.join("\n") + "\n"), false))
                .and_then(|_| opt("schedule", Some(config.schedule.unwrap_or_default().file()), false))
                // журнал трафика: файл и срок для службы (stats_sample); нет файла — журнал выключен
                .and_then(|_| opt("history", config.history.as_ref().map(|h| format!("file={}\nmonths={}\n", mi_tt::history::file_for(&h.target), h.months)), false))
                // откуда служба скачивает список рекламы; нет файла — блокировка выключена
                .and_then(|_| opt("adblock.url", config.dns.as_ref().and_then(|d| d.adblock.as_ref()).filter(|a| a.enabled)
                    .and_then(|a| a.list_url()).map(|u| format!("{u}\n")), false))
                .and_then(|_| opt("nfqws2.args", (!r.nfqws2_args.is_empty()).then(|| format!("{}\n", r.nfqws2_args.join("\n"))), false))
            {
                return Response::error(500, "write_failed", m);
            }
            warnings.extend(r.warnings.iter().cloned());
            Response { status: 200, body: json!({ "ok": true, "source_revision": store::revision(&c), "tunnel": !r.tunnels.is_empty(), "tunnels": r.tunnels.iter().map(|t| json!({ "index": t.index, "dev": t.dev, "profile": t.profile, "engine": t.engine.name() })).collect::<Vec<_>>(),
                "policy": r.policy, "plan": r.plan.iter().map(|e| e.label()).collect::<Vec<_>>(), "routes": r.routes,
                "nfqws2_args": r.nfqws2_args, "warnings": warnings, "issues": [] }) }
        }
    }
}

/// Файл dnsmasq: наборы ipset доменов правил, резолвер туннеля и блокировка рекламы. Список рекламы — скачанный службой
/// (`MI_TT_ADBLOCK_LIST`, копия в RAM), иначе `adblock.list` рядом с настройками (загрузка через CLI/API).
/// Пустой — файла нет. Ошибочный список рекламы — отказ (действующие файлы не меняются).
fn tunnel_dns_args(config: &model::Config, r: &render::Rendered) -> Option<Vec<String>> {
    let dev = r.dns_dev.as_deref()?;
    if r.tunnels.is_empty() || r.dns.tunnel_domains.is_empty() {
        return None;
    }
    let mark = (!r.policy.needs_field()).then_some(mi_tt::plan::NF_MARK);
    config.dns.as_ref()?.tunnel_proxy_args(dev, mark)?.ok()
}

/// Файлы клиентов туннелей: туннель 0 — в каталоге рендера (прежние пути), n>0 — в `tun<n>/`; `tunnels.list` —
/// строки «номер TUN профиль» для службы. Файлы исчезнувших туннелей удаляются.
fn write_tunnels(dir: &std::path::Path, tunnels: &[render::TunRender]) -> Result<(), String> {
    let put = |d: &std::path::Path, name: &str, body: Option<&str>, private: bool| -> Result<(), String> {
        let f = d.join(name);
        match body {
            None => {
                let _ = std::fs::remove_file(&f);
                Ok(())
            }
            Some(b) => {
                store::write_atomic(&f, b.as_bytes())?;
                #[cfg(unix)]
                if private {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).map_err(|e| format!("{}: {e}", f.display()))?;
                }
                let _ = private;
                Ok(())
            }
        }
    };
    let files = |d: &std::path::Path, t: Option<&render::TunRender>| -> Result<(), String> {
        // конфигурация программы туннеля; файл другой программы (сервер сменил вид) удаляется
        for e in [render::Engine::TrustTunnel, render::Engine::SingBox, render::Engine::AmneziaWg] {
            put(d, e.config_file(), t.filter(|t| t.engine == e).map(|t| t.config.as_str()), true)?;
        }
        put(d, "awg.addr", t.and_then(|t| t.addr.as_deref()), false)?;
        // запасной сервер: его client.toml и адрес основного для проверки возврата (служба, mitt-lib.sh)
        put(d, "client-backup.toml", t.and_then(|t| t.client_backup_toml.as_deref()), true)?;
        put(d, "primary.addr", t.and_then(|t| t.primary_addr.as_deref()), false)?;
        put(d, "servers.addr", t.map(|t| t.servers_addr.as_str()), false)?;
        put(d, "fastest", t.filter(|t| t.fastest).map(|_| "1\n"), false)
    };
    files(dir, tunnels.iter().find(|t| t.index == 0))?;
    for n in 1..=mi_tt::plan::MAX_TUN {
        let d = dir.join(render::tun_subdir(n));
        match tunnels.iter().find(|t| t.index == n) {
            Some(t) => {
                std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
                files(&d, Some(t))?;
            }
            None if d.exists() => {
                let _ = std::fs::remove_dir_all(&d);
            }
            None => {}
        }
    }
    let list: String = tunnels.iter().map(|t| format!("{} {} {} {}\n", t.index, t.dev, t.profile, t.engine.name())).collect();
    put(dir, "tunnels.list", (!list.is_empty()).then_some(list.as_str()), false)
}

fn write_dns_file(config: &model::Config, plan: &mi_tt::dns::DnsPlan, cfg: &std::path::Path, dir: &std::path::Path, tunnel_secure: bool) -> Result<(), String> {
    use mi_tt::dns;
    let conf = dir.join("dnsmasq-mitt.conf");
    let adblock = config.dns.as_ref().and_then(|d| d.adblock.as_ref());
    let mut blocked = Vec::new();
    if adblock.is_some_and(|a| a.enabled) {
        let list = std::env::var("MI_TT_ADBLOCK_LIST").ok().filter(|s| !s.is_empty()).map(std::path::PathBuf::from)
            .filter(|p| p.exists()).unwrap_or_else(|| cfg.with_file_name("adblock.list"));
        if list.exists() {
            let text = read_limited(&list.to_string_lossy(), dns::ADBLOCK_MAX_BYTES as u64)?;
            blocked = dns::parse_adblock_list(&String::from_utf8_lossy(&text))
                .map_err(|i| format!("adblock.list не прошёл проверку: {}", i.iter().map(|x| format!("{} {}", x.path, x.message)).collect::<Vec<_>>().join("; ")))?
                .0;
        }
    }
    let hosts = config.dns.as_ref().map(|d| d.hosts.as_slice()).unwrap_or_default();
    let secure = config.dns.as_ref().and_then(|d| d.secure.as_ref()).and_then(|s| s.proxy_args()).is_some();
    // DoH/DoT поверх туннеля: домены туннеля dnsmasq спрашивает у второго прокси, а не у резолвера напрямую
    let mut plan = plan.clone();
    if tunnel_secure {
        plan.resolver = format!("127.0.0.1#{}", model::DNS_TUNNEL_PORT);
    }
    let text = dns::dnsmasq_conf(&plan, adblock, &blocked, hosts, secure);
    if text.is_empty() {
        let _ = std::fs::remove_file(&conf);
        return Ok(());
    }
    store::write_atomic(&conf, text.as_bytes())
}

/// Проверка файла списка без записи: непустой список в формате `parse_category_list` (HTML и прочий мусор не проходит).
/// Проверка скачанного списка рекламы (mitt-adblock.sh): тот же разбор, что при рендере.
fn adblock_check(list: &str) -> Response {
    use serde_json::json;
    let text = match read_limited(list, mi_tt::dns::ADBLOCK_MAX_BYTES as u64) {
        Ok(t) => t,
        Err(m) => return Response::error(500, "unreadable", m),
    };
    match mi_tt::dns::parse_adblock_list(&String::from_utf8_lossy(&text)) {
        Ok((d, skipped)) => Response { status: 200, body: json!({ "ok": true, "domains": d.len(), "skipped": skipped, "issues": [] }) },
        Err(i) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "adblock_invalid", "message": "список рекламы не прошёл проверку" }, "issues": i }) },
    }
}

fn category_check(kind: &str, list: &str) -> Response {
    use serde_json::json;
    let kind = match kind {
        "domain" => model::CategoryKind::Domain,
        "ip" => model::CategoryKind::Ip,
        _ => return Response::error(400, "bad_kind", "вид списка: domain или ip"),
    };
    let text = match read_limited(list, 8 * 1024 * 1024) {
        Ok(t) => t,
        Err(m) => return Response::error(500, "unreadable", m),
    };
    match render::parse_category_list(kind, &String::from_utf8_lossy(&text)) {
        Ok(e) => Response { status: 200, body: json!({ "ok": true, "entries": e.len(), "issues": [] }) },
        Err(i) => Response { status: 422, body: json!({ "ok": false, "error": { "code": "category_invalid", "message": "список не прошёл проверку" }, "issues": i }) },
    }
}

/// Обновление списка категории: проверка по виду категории (домены или IP-префиксы), атомарная замена
/// categories/<id>.list (предыдущий — .prev). Ошибочный список не применяется.
fn category_update(cfg: &str, id: &str, list: &str) -> Response {
    use serde_json::json;
    let config: model::Config = match read_limited(cfg, MAX_CONFIG_BYTES).map_err(|m| Response::error(500, "unreadable", m)).and_then(|b| {
        api::parse_json(&b, "config").map_err(|i| Response { status: 422, body: json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки не разобраны" }, "issues": i }) })
    }) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let Some(c) = config.categories.iter().find(|c| c.id == id) else {
        return Response::error(404, "unknown_category", format!("категория «{id}» не найдена в настройках"));
    };
    let text = match read_limited(list, 8 * 1024 * 1024) {
        Ok(t) => t,
        Err(m) => return Response::error(500, "unreadable", m),
    };
    let entries = match render::parse_category_list(c.kind, &String::from_utf8_lossy(&text)) {
        Ok(e) => e,
        Err(i) => return Response { status: 422, body: json!({ "ok": false, "error": { "code": "category_invalid", "message": "список не прошёл проверку; действующий список сохранён" }, "issues": i }) },
    };
    let dir = std::path::Path::new(cfg).with_file_name("categories");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return Response::error(500, "write_failed", e.to_string());
    }
    let target = dir.join(format!("{id}.list"));
    let _g = match store::lock(&target) {
        Ok(g) => g,
        Err(m) => return Response::error(503, "busy", m),
    };
    if target.exists() {
        let _ = std::fs::copy(&target, store::sidecar(&target, ".prev"));
    }
    let body = format!("{}\n", entries.iter().map(|e| e.trim_start_matches("+.")).collect::<Vec<_>>().join("\n"));
    match store::write_atomic(&target, body.as_bytes()) {
        Ok(()) => Response { status: 200, body: json!({ "ok": true, "category": id, "entries": entries.len(), "sha256": store::revision(body.as_bytes()), "issues": [] }) },
        Err(m) => Response::error(500, "write_failed", m),
    }
}

/// Обновление списка блокировки: новый список проверяется целиком и атомарно заменяет прежний (копия — .prev).
/// Ошибочный или пустой список не применяется, действующий остаётся.
fn adblock_update(cfg: &str, list: &str) -> Response {
    use mi_tt::dns;
    use serde_json::json;
    let text = match read_limited(list, dns::ADBLOCK_MAX_BYTES as u64 + 1) {
        Ok(t) => t,
        Err(m) => return Response::error(500, "unreadable", m),
    };
    let domains = match dns::parse_adblock_list(&String::from_utf8_lossy(&text)) {
        Ok((d, _)) if !d.is_empty() => d,
        Ok(_) => return Response::error(422, "adblock_empty", "пустой список не применяется; действующий список сохранён"),
        Err(i) => {
            return Response { status: 422, body: json!({ "ok": false, "error": { "code": "adblock_invalid", "message": "список не прошёл проверку; действующий список сохранён" }, "issues": i }) };
        }
    };
    let target = std::path::Path::new(cfg).with_file_name("adblock.list");
    let _g = match store::lock(&target) {
        Ok(g) => g,
        Err(m) => return Response::error(503, "busy", m),
    };
    if target.exists() {
        if let Err(e) = std::fs::copy(&target, store::sidecar(&target, ".prev")) {
            return Response::error(500, "write_failed", e.to_string());
        }
    }
    let body = format!("{}\n", domains.join("\n"));
    match store::write_atomic(&target, body.as_bytes()) {
        Ok(()) => Response { status: 200, body: json!({ "ok": true, "domains": domains.len(), "sha256": store::revision(body.as_bytes()), "issues": [] }) },
        Err(m) => Response::error(500, "write_failed", m),
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn cgi_request() -> gate::Reply {
    let config = env("MI_TT_CONFIG").unwrap_or_else(|| DEFAULT_CONFIG.into());
    let method = env("REQUEST_METHOD").unwrap_or_default();
    let path = env("PATH_INFO").unwrap_or_else(|| "/".into());
    let mut body = None;
    if method == "POST" {
        let ctype = env("CONTENT_TYPE").unwrap_or_default();
        if !ctype.to_ascii_lowercase().starts_with("application/json") {
            return Response::error(415, "unsupported_media_type", "ожидается Content-Type: application/json").into();
        }
        let Some(len) = env("CONTENT_LENGTH") else {
            return Response::error(411, "length_required", "нужен заголовок Content-Length").into();
        };
        let Ok(len) = len.parse::<usize>() else {
            return Response::error(400, "bad_length", "некорректный Content-Length").into();
        };
        let max = if mi_tt::manage::is_list_upload(&path) || path.trim_end_matches('/') == "/backup/restore" { mi_tt::manage::MAX_LIST_BODY } else if path.trim_end_matches('/') == "/config" { MAX_CONFIG_BYTES as usize } else { MAX_BODY_BYTES };
        if len > max {
            return Response::error(413, "too_large", format!("тело запроса больше {max} байт")).into();
        }
        let mut buf = vec![0u8; len];
        if io::stdin().lock().read_exact(&mut buf).is_err() {
            return Response::error(400, "short_body", "тело запроса короче Content-Length").into();
        }
        body = Some(buf);
    }
    let origin = if method == "GET" {
        WriteAccess::Denied(Response::error(405, "method_not_allowed", "чтение"))
    } else {
        // и домены своих DNS-записей, указывающие на роутер (панель по своему домену) — см. manage::host_origins
        let mut allowed = env("MI_TT_ALLOWED_ORIGINS").unwrap_or_default();
        if let Some(cfg) = env("MI_TT_CONFIG") {
            for o in mi_tt::manage::host_origins(&allowed, &cfg) {
                allowed.push(',');
                allowed.push_str(&o);
            }
        }
        check_origin(&allowed, env("HTTP_ORIGIN").as_deref(), env("HTTP_SEC_FETCH_SITE").as_deref())
    };
    let cookie = env("HTTP_COOKIE");
    // HTTPS от самого веб-сервера (uhttpd с TLS) или от локального TLS-терминатора: на стоке 1.1.38 uhttpd без ustream-ssl,
    // TLS завершает свой экземпляр штатного nginx и проксирует на отдельный uhttpd, слушающий только 127.0.0.1.
    // Штатный uhttpd передаёт CGI лишь фиксированный набор заголовков (X-Forwarded-Proto среди них нет), поэтому
    // признак HTTPS — сам этот экземпляр: CGI-обёртка установщика задаёт MI_TT_TRUST_PROXY=1, а соединение должно прийти
    // с loopback на loopback-слушатель (единственный клиент — nginx с TLS). Если X-Forwarded-Proto всё же передан — он https.
    let direct = matches!(env("HTTPS").as_deref().map(str::to_ascii_lowercase).as_deref(), Some("on" | "1"));
    let lo = |k: &str| matches!(env(k).as_deref(), Some("127.0.0.1" | "::1"));
    let proxied = env("MI_TT_TRUST_PROXY").as_deref() == Some("1")
        && lo("REMOTE_ADDR")
        && lo("SERVER_ADDR")
        && env("HTTP_X_FORWARDED_PROTO").is_none_or(|v| v.eq_ignore_ascii_case("https"));
    let https = direct || proxied;
    // CSRF-токен: заголовок X-MITT-CSRF. Штатный uhttpd его не передаёт, поэтому за доверенным nginx токен приходит
    // в Authorization: MITT-CSRF <токен> (nginx всегда перезаписывает этот заголовок значением из X-MITT-CSRF клиента).
    let csrf = env("HTTP_X_MITT_CSRF")
        .or_else(|| proxied.then(|| env("HTTP_AUTHORIZATION").and_then(|v| v.strip_prefix("MITT-CSRF ").map(str::to_string))).flatten());
    let req = gate::Request { method: &method, path: &path, body: body.as_deref(), cookie: cookie.as_deref(), csrf: csrf.as_deref(), origin, https };
    gate::serve(&auth::Paths::from_env(), req, &config)
}

fn cgi() -> ExitCode {
    let gate::Reply { resp: r, headers } = cgi_request();
    let body = serde_json::to_vec(&r.body).unwrap_or_default();
    let mut out = io::stdout().lock();
    let head = format!(
        "Status: {} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n{}\r\n",
        r.status,
        reason(r.status),
        body.len(),
        headers.iter().map(|h| format!("{h}\r\n")).collect::<String>()
    );
    let _ = out.write_all(head.as_bytes()).and_then(|_| out.write_all(&body)).and_then(|_| out.flush());
    ExitCode::SUCCESS
}
