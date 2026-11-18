//! mi-tt-admin — административный CLI: план, применение, статус и снятие собственных правил маршрутизации
//! и правил определения источника. Требует CAP_NET_ADMIN, запускается оператором или службой загрузки; из CGI не работает.
//!
//! Два механизма определения источника на входе (выбор — `--marker auto|tc|netfilter`, auto: tc, если доступен):
//!  - tc: clsact + flower src_mac / matchall + skbedit (этап 4);
//!  - netfilter (сток RC06 1.1.38: tc-actions в ядре нет): привязка MAC↔IP в FORWARD, iif для сети на своём мосту,
//!    physdev + MARK 0x4000 для сети на части моста.
//! До любых изменений: проверка возможностей ядра и утилит (только чтение), интерфейсов, коллизий; при отказе — ничего.
//!
//! Гарантии: блокировка <state>/apply.lock; журнал <state>/applied.json с pending до изменений; откат выполненных
//! шагов при ошибке; чужие записи и чужие хуки не удаляются.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod auth_cmd;

use mi_tt::api::{MAX_CONFIG_BYTES, parse_json, read_limited};
use mi_tt::caps::{self, Caps, Item, check_kernel, help_has, parse_kconfig};
use mi_tt::model::Config;
use mi_tt::plan::{
    CaptureSpec, Entry, Live, Marker, NfNeeds, TABLE, TC_PREF_MAX, TC_PREF_MIN, TcDev, build_plan, build_plan_netfilter, iptables_mark_collisions,
    ipt_tables, our_mark_mask, parse_ipt, parse_link, parse_routes, parse_rules, parse_tc_filters, parse_tc_hook, parse_v6_prefixes, reconcile,
    tc_devices,
};
use mi_tt::render::{self, Secrets, TUN_DEVICE};
use mi_tt::store::{lock, revision, write_atomic};

const USAGE: &str = "mi-tt-admin — применение собственных правил маршрутизации и определения источника (нужен CAP_NET_ADMIN)

  mi-tt-admin caps   [--marker auto|tc|netfilter]                     # только чтение: возможности ядра и утилит
  mi-tt-admin plan   --state-dir D --config C --secrets S --leases L [--guard-only] [--marker M]
  mi-tt-admin apply  --state-dir D --config C --secrets S --leases L [--guard-only] [--marker M]
  mi-tt-admin status --state-dir D
  mi-tt-admin revert --state-dir D
  mi-tt-admin auth …                                                   # вход в панель: см. mi-tt-admin auth help
  mi-tt-admin release verify <пакет> [--pinned K] [--unpacked D]       # подпись и хэши пакета релиза
  mi-tt-admin sha256 <файл>…                                           # SHA-256 (на стоке нет sha256sum)

--guard-only: правила источника и запреты без маршрута через TUN — для старта до запуска Mihomo или при его отсутствии.
Коды выхода: 0 — готово/согласовано, 1 — расхождение, 2 — ошибка входных данных, интерфейсов или возможностей,
3 — чужие записи или коллизии, 4 — ошибка применения (выполненные шаги откатаны), 5 — откат не завершён,
6 — занято другим процессом, 77 — запуск из CGI запрещён.
Окружение: MI_TT_IP, MI_TT_TC, MI_TT_IPTABLES, MI_TT_IP6TABLES, MI_TT_IPTABLES_SAVE — пути утилит;
MI_TT_KCONFIG — файл конфигурации ядра вместо /proc/config.gz; MI_TT_MODULES_DIR — каталог модулей.";

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    /// none | guard | applied | reverted | pending | dirty
    phase: String,
    config_revision: Option<String>,
    plan_sha256: Option<String>,
    owned: BTreeSet<Entry>,
    pending: BTreeSet<Entry>,
    #[serde(default)]
    capture: Option<CaptureSpec>,
    #[serde(default)]
    marker: Option<Marker>,
    updated_unix: u64,
    last_error: Option<String>,
}

struct Args {
    cmd: String,
    state_dir: PathBuf,
    config: Option<String>,
    secrets: Option<String>,
    leases: Option<String>,
    guard_only: bool,
    marker: Option<Marker>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn out(code: u8, v: Value) -> ExitCode {
    println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    ExitCode::from(code)
}

fn fail(code: u8, err: &str, msg: impl Into<String>) -> ExitCode {
    out(code, json!({ "ok": false, "error": { "code": err, "message": msg.into() } }))
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().ok_or("нет команды")?;
    let mut a = Args { cmd, state_dir: PathBuf::new(), config: None, secrets: None, leases: None, guard_only: false, marker: None };
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or(format!("{k}: нужно значение"));
        match k.as_str() {
            "--state-dir" => a.state_dir = PathBuf::from(val()?),
            "--config" => a.config = Some(val()?),
            "--secrets" => a.secrets = Some(val()?),
            "--leases" => a.leases = Some(val()?),
            "--guard-only" => a.guard_only = true,
            "--marker" => {
                a.marker = match val()?.as_str() {
                    "auto" => None,
                    "tc" => Some(Marker::Tc),
                    "netfilter" => Some(Marker::Netfilter),
                    x => return Err(format!("--marker: неизвестное значение {x}")),
                }
            }
            _ => return Err(format!("неизвестный аргумент {k}")),
        }
    }
    if a.state_dir.as_os_str().is_empty() && a.cmd != "caps" {
        return Err("нужен --state-dir".into());
    }
    Ok(a)
}

// ---------- системные утилиты (отдельные аргументы, без оболочки) ----------

fn bin(prog: &str) -> String {
    let var = match prog {
        "ip" => "MI_TT_IP",
        "tc" => "MI_TT_TC",
        "iptables" => "MI_TT_IPTABLES",
        "ip6tables" => "MI_TT_IP6TABLES",
        "iptables-save" => "MI_TT_IPTABLES_SAVE",
        _ => "",
    };
    std::env::var(var).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| prog.into())
}

fn run(prog: &str, args: &[String]) -> Result<String, String> {
    let o = Command::new(bin(prog)).args(args).output().map_err(|e| format!("не удалось запустить {}: {e}", bin(prog)))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(format!("{prog} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()))
    }
}

fn run_s(prog: &str, args: &[&str]) -> Result<String, String> {
    run(prog, &args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

/// Вывод справки (stdout+stderr) независимо от кода возврата.
fn help(prog: &str, args: &[&str]) -> String {
    Command::new(bin(prog))
        .args(args)
        .output()
        .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
        .unwrap_or_default()
}

fn table_routes(v6: bool) -> Result<String, String> {
    let t = TABLE.to_string();
    let args: Vec<&str> = if v6 { vec!["-6", "route", "show", "table", &t] } else { vec!["route", "show", "table", &t] };
    match run_s("ip", &args) {
        Err(e) if e.contains("does not exist") => Ok(String::new()),
        r => r,
    }
}

fn read_live(devs: &BTreeSet<String>, tables: &BTreeSet<(bool, String)>, warnings: &mut Vec<String>) -> Result<Live, String> {
    let mut l = Live { rules: parse_rules(&run_s("ip", &["rule", "show"])?, false), routes: parse_routes(&table_routes(false)?, false), ..Default::default() };
    match (run_s("ip", &["-6", "rule", "show"]), table_routes(true)) {
        (Ok(r), Ok(rt)) => {
            l.rules.extend(parse_rules(&r, true));
            l.routes.extend(parse_routes(&rt, true));
        }
        (Err(e), _) | (_, Err(e)) => warnings.push(format!("IPv6 в ядре недоступен или не читается: {e}")),
    }
    for dev in devs {
        match run_s("tc", &["qdisc", "show", "dev", dev]) {
            Ok(q) => {
                let hook = parse_tc_hook(&q);
                let filters = if hook { parse_tc_filters(&run_s("tc", &["filter", "show", "dev", dev, "ingress"])?, dev) } else { Vec::new() };
                l.tc.push(TcDev { dev: dev.clone(), hook, filters });
            }
            Err(e) => warnings.push(format!("tc на {dev} не читается (интерфейс исчез?): {e}")),
        }
    }
    for (v6, table) in tables {
        let prog = if *v6 { "ip6tables" } else { "iptables" };
        let t = run_s(prog, &["-w", "-t", table, "-S"])?;
        l.ipt.push(parse_ipt(&t, *v6, table));
    }
    Ok(l)
}

fn tun_present() -> bool {
    run_s("ip", &["link", "show", "dev", TUN_DEVICE]).is_ok()
}

// ---------- возможности (только чтение) ----------

fn kernel_release() -> String {
    std::env::var("MI_TT_KERNEL_RELEASE").ok().or_else(|| fs::read_to_string("/proc/sys/kernel/osrelease").ok()).unwrap_or_default().trim().to_string()
}

fn module_names(dir: &Path, out: &mut BTreeSet<String>, depth: u8) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() && depth < 6 {
            module_names(&p, out, depth + 1);
        } else if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
            if let Some(stem) = n.split(".ko").next().filter(|_| n.contains(".ko")) {
                out.insert(stem.to_string());
            }
        }
    }
}

fn gather_caps() -> Caps {
    let release = kernel_release();
    let (kconfig, source) = match std::env::var("MI_TT_KCONFIG").ok().filter(|s| !s.is_empty()) {
        Some(f) => (fs::read_to_string(&f).ok(), f),
        None => match Command::new("zcat").arg("/proc/config.gz").output() {
            Ok(o) if o.status.success() => (Some(String::from_utf8_lossy(&o.stdout).into_owned()), "/proc/config.gz".to_string()),
            _ => (None, "недоступна (нет /proc/config.gz)".to_string()),
        },
    };
    let k = kconfig.as_deref().map(parse_kconfig);
    let mdir = std::env::var("MI_TT_MODULES_DIR").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| format!("/lib/modules/{release}"));
    let mut mods = BTreeSet::new();
    module_names(Path::new(&mdir), &mut mods, 0);
    let tool = |what: &str, ok: bool, detail: String| Item { what: what.into(), ok, detail };
    let mut c = Caps {
        kconfig_source: source,
        kernel_release: release,
        common: check_kernel(caps::COMMON, k.as_ref(), &mods),
        tc: check_kernel(caps::TC, k.as_ref(), &mods),
        netfilter: check_kernel(caps::NF, k.as_ref(), &mods),
        netfilter_mark: check_kernel(caps::NF_MARK, k.as_ref(), &mods),
        netfilter_queue: check_kernel(caps::NF_QUEUE, k.as_ref(), &mods),
        ..Default::default()
    };
    let tcv = run_s("tc", &["-V"]);
    c.tc.push(tool("утилита tc", tcv.is_ok(), tcv.unwrap_or_else(|e| e).trim().to_string()));
    for (prog, rej) in [("iptables", "icmp-port-unreachable"), ("ip6tables", "icmp6-port-unreachable")] {
        let v = run_s(prog, &["-V"]);
        c.netfilter.push(tool(&format!("утилита {prog}"), v.is_ok(), v.unwrap_or_else(|e| e).trim().to_string()));
        c.netfilter.push(tool(&format!("{prog} -m mac --mac-source"), help_has(&help(prog, &["-m", "mac", "-h"]), "--mac-source"), "расширение mac".into()));
        c.netfilter.push(tool(&format!("{prog} -m comment"), help_has(&help(prog, &["-m", "comment", "-h"]), "--comment"), "расширение comment".into()));
        c.netfilter.push(tool(&format!("{prog} -j REJECT"), help_has(&help(prog, &["-j", "REJECT", "-h"]), "--reject-with"), format!("цель REJECT ({rej})")));
        c.netfilter_mark.push(tool(&format!("{prog} -m physdev"), help_has(&help(prog, &["-m", "physdev", "-h"]), "--physdev-in"), "расширение physdev".into()));
        c.netfilter_mark
            .push(tool(&format!("{prog} -j MARK --set-xmark"), help_has(&help(prog, &["-j", "MARK", "-h"]), "--set-xmark"), "MARK ревизии 2 (ядро отдаёт xt_mark)".into()));
    }
    c.netfilter_queue.push(tool("iptables -j NFQUEUE --queue-bypass", help_has(&help("iptables", &["-j", "NFQUEUE", "-h"]), "--queue-bypass"), "цель NFQUEUE".into()));
    c.netfilter_queue.push(tool("iptables -m multiport", help_has(&help("iptables", &["-m", "multiport", "-h"]), "--dports"), "расширение multiport".into()));
    c.netfilter_queue.push(tool("iptables -m mark", help_has(&help("iptables", &["-m", "mark", "-h"]), "--mark"), "расширение mark".into()));
    for (f, name) in [("bridge-nf-call-iptables", "IPv4"), ("bridge-nf-call-ip6tables", "IPv6")] {
        let v = fs::read_to_string(format!("/proc/sys/net/bridge/{f}")).unwrap_or_default();
        c.netfilter_mark.push(tool(&format!("net.bridge.{f}=1"), v.trim() == "1", format!("{name}: physdev на маршрутизируемом трафике моста видит порт только при 1 (сейчас «{}»)", v.trim())));
    }
    c.finish()
}

// ---------- журнал ----------

fn state_path(d: &Path) -> PathBuf {
    d.join("applied.json")
}

fn load_state(d: &Path) -> Result<State, String> {
    let p = state_path(d);
    if !p.exists() {
        return Ok(State { version: 1, phase: "none".into(), ..Default::default() });
    }
    let b = read_limited(&p.to_string_lossy(), MAX_CONFIG_BYTES)?;
    parse_json::<State>(&b, "state").map_err(|i| format!("журнал {} повреждён: {}", p.display(), i.iter().map(|x| x.message.clone()).collect::<Vec<_>>().join("; ")))
}

fn save_state(d: &Path, s: &mut State) -> Result<(), String> {
    s.version = 1;
    s.updated_unix = now();
    let mut b = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    b.push(b'\n');
    write_atomic(&state_path(d), &b)
}

// ---------- желаемое состояние ----------

struct Desired {
    spec: CaptureSpec,
    config_revision: String,
    warnings: Vec<String>,
}

fn render_spec(a: &Args) -> Result<Desired, ExitCode> {
    let need = |o: &Option<String>, k: &str| o.clone().ok_or_else(|| fail(2, "usage", format!("нужен {k}")));
    let (c, s, l) = (need(&a.config, "--config")?, need(&a.secrets, "--secrets")?, need(&a.leases, "--leases")?);
    let rd = |p: &str| read_limited(p, MAX_CONFIG_BYTES).map_err(|m| fail(2, "unreadable", m));
    let (cb, sb, lb) = (rd(&c)?, rd(&s)?, rd(&l)?);
    let cfg: Config = parse_json(&cb, "config").map_err(|i| out(2, json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки не разобраны" }, "issues": i })))?;
    let sec: Secrets = parse_json(&sb, "secrets").map_err(|i| out(2, json!({ "ok": false, "error": { "code": "secrets_invalid", "message": "secrets.json не разобран" }, "issues": i })))?;
    let r = render::render(&cfg, &sec, &render::parse_leases(&String::from_utf8_lossy(&lb))).map_err(|i| {
        out(2, json!({ "ok": false, "error": { "code": "not_renderable", "message": "план нельзя построить точно; текущее состояние сети не меняется" }, "issues": i }))
    })?;
    Ok(Desired { spec: r.capture, config_revision: revision(&cb), warnings: r.warnings })
}

fn check_interfaces(spec: &CaptureSpec) -> Vec<String> {
    let mut errs = Vec::new();
    for (ifname, master) in spec.interfaces() {
        match run_s("ip", &["-d", "link", "show", "dev", &ifname]) {
            Err(e) => errs.push(format!("интерфейс «{ifname}» не найден: {e}")),
            Ok(t) => {
                let (is_bridge, m) = parse_link(&t);
                match &master {
                    None if !is_bridge => errs.push(format!("«{ifname}» не является мостом")),
                    Some(br) if m.as_deref() != Some(br.as_str()) => {
                        errs.push(format!("порт «{ifname}» не входит в мост «{br}» (master: {})", m.unwrap_or_else(|| "нет".into())))
                    }
                    _ => {}
                }
            }
        }
    }
    errs
}

fn bridges(spec: &CaptureSpec) -> BTreeSet<String> {
    spec.devices.iter().map(|d| d.bridge.clone()).chain(spec.networks.iter().map(|n| n.bridge.clone())).chain(spec.lanwide.iter().map(|l| l.bridge.clone())).collect()
}

fn v6_prefixes(spec: &CaptureSpec) -> Vec<String> {
    let mut v: BTreeSet<String> = BTreeSet::new();
    for b in bridges(spec) {
        if let Ok(t) = run_s("ip", &["-6", "addr", "show", "dev", &b, "scope", "global"]) {
            v.extend(parse_v6_prefixes(&t));
        }
    }
    v.into_iter().collect()
}

/// Живой состав мостов (`ip -o link show master <мост>`).
fn bridge_ports(spec: &CaptureSpec) -> BTreeMap<String, BTreeSet<String>> {
    bridges(spec)
        .into_iter()
        .map(|b| {
            let ports = run_s("ip", &["-o", "link", "show", "master", &b])
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.split(':').nth(1).map(|n| n.trim().split('@').next().unwrap_or("").to_string()))
                .filter(|n| !n.is_empty())
                .collect();
            (b, ports)
        })
        .collect()
}

/// Метки в firewall для tc-механизма (iptables-save -t mangle), если утилита есть.
fn firewall_mark_check(mask: u32, warnings: &mut Vec<String>) -> Vec<String> {
    if mask == 0 {
        return Vec::new();
    }
    match Command::new(bin("iptables-save")).args(["-t", "mangle"]).output() {
        Ok(o) if o.status.success() => iptables_mark_collisions(&String::from_utf8_lossy(&o.stdout))
            .into_iter()
            .map(|l| format!("iptables-save: правило firewall меняет/читает биты наших меток: {l}"))
            .collect(),
        _ => {
            warnings.push("iptables-save не найден: пересечение меток с firewall (mangle) не проверено".into());
            Vec::new()
        }
    }
}

struct Built {
    set: BTreeSet<Entry>,
    marker: Marker,
    caps: Caps,
    needs: NfNeeds,
    pre_conflicts: Vec<String>,
}

/// Проверки до мутаций и построение желаемого набора. Ошибка — готовый ответ (ничего не изменено).
fn build(a: &Args, d: &Desired, owned: &BTreeSet<Entry>, prev_marker: Option<Marker>, warnings: &mut Vec<String>) -> Result<Built, ExitCode> {
    let errs = check_interfaces(&d.spec);
    if !errs.is_empty() {
        return Err(out(2, json!({ "ok": false, "error": { "code": "interfaces", "message": "интерфейсы не соответствуют настройкам; ничего не изменено" }, "issues": errs })));
    }
    let caps = gather_caps();
    let requested = a.marker.or(prev_marker);
    let marker = match caps.choose(requested) {
        Ok(m) => m,
        Err(missing) if !d.spec.is_empty() => {
            return Err(out(2, json!({ "ok": false, "error": { "code": "capabilities", "message": "нет нужных возможностей ядра или утилит; ничего не изменено" },
                "requested": requested, "missing": missing, "caps": caps })));
        }
        Err(_) => requested.unwrap_or(Marker::Netfilter),
    };
    let mut needs = NfNeeds::default();
    let mut pre_conflicts = Vec::new();
    if marker == Marker::Tc && d.spec.zapret.is_some() && !a.guard_only {
        return Err(out(2, json!({ "ok": false, "error": { "code": "capabilities",
            "message": "Zapret (NFQUEUE по метке сокета движка) реализован только на netfilter-пути; ничего не изменено" } })));
    }
    let set = match marker {
        Marker::Tc => {
            let hook_devs = tc_devices(&build_plan(&d.spec, &[], &BTreeSet::new(), owned, a.guard_only));
            let foreign_hooks: BTreeSet<String> = hook_devs
                .iter()
                .filter(|dev| run_s("tc", &["qdisc", "show", "dev", dev]).map(|q| parse_tc_hook(&q)).unwrap_or(false) && !owned.contains(&Entry::Qdisc { dev: (*dev).clone() }))
                .cloned()
                .collect();
            let set = build_plan(&d.spec, &v6_prefixes(&d.spec), &foreign_hooks, owned, a.guard_only);
            pre_conflicts = firewall_mark_check(our_mark_mask(&set), warnings);
            set
        }
        Marker::Netfilter => {
            let (set, n) = build_plan_netfilter(&d.spec, &v6_prefixes(&d.spec), &bridge_ports(&d.spec), a.guard_only);
            if n.mark && !caps.netfilter_mark_ok {
                return Err(out(2, json!({ "ok": false, "error": { "code": "capabilities",
                    "message": "политика сети на части моста требует physdev + MARK и bridge-nf-call=1; ничего не изменено" },
                    "missing": Caps::missing(&caps.netfilter_mark), "caps": caps })));
            }
            if n.queue && n.mark {
                return Err(out(2, json!({ "ok": false, "error": { "code": "mark_conflict",
                    "message": "Zapret и политика сети на части моста используют один свободный бит метки 0x4000; ничего не изменено" } })));
            }
            if n.queue && !caps.netfilter_queue_ok {
                return Err(out(2, json!({ "ok": false, "error": { "code": "capabilities",
                    "message": "Zapret требует NFQUEUE, multiport и mark в ядре и iptables; ничего не изменено" },
                    "missing": Caps::missing(&caps.netfilter_queue), "caps": caps })));
            }
            needs = n;
            set
        }
    };
    Ok(Built { set, marker, caps, needs, pre_conflicts })
}

fn nf_tables_to_read(marker: Option<Marker>, set: &BTreeSet<Entry>, owned: &BTreeSet<Entry>) -> BTreeSet<(bool, String)> {
    let mut t = ipt_tables(set.iter().chain(owned.iter()));
    if marker == Some(Marker::Netfilter) {
        for v6 in [false, true] {
            for table in ["filter", "mangle"] {
                t.insert((v6, table.to_string()));
            }
        }
    }
    t
}

// ---------- применение ----------

#[derive(Serialize)]
struct Step {
    op: &'static str,
    entry: String,
    ok: bool,
    error: Option<String>,
}

fn exec(e: &Entry, op: &'static str) -> Step {
    let (prog, args) = e.cmd(op);
    match run(prog, &args) {
        Ok(_) => Step { op, entry: e.label(), ok: true, error: None },
        Err(m) => Step { op, entry: e.label(), ok: false, error: Some(m) },
    }
}

fn foreign_filters_on(live: &Live, dev: &str) -> usize {
    live.tc.iter().filter(|t| t.dev == dev).flat_map(|t| t.filters.iter()).filter(|(p, _)| !(TC_PREF_MIN..=TC_PREF_MAX).contains(p)).count()
}

fn change(a: &Args, target: Option<Desired>) -> ExitCode {
    if let Err(e) = fs::create_dir_all(&a.state_dir) {
        return fail(2, "state_dir", format!("{}: {e}", a.state_dir.display()));
    }
    let _guard = match lock(&a.state_dir.join("apply")) {
        Ok(g) => g,
        Err(m) => return fail(6, "busy", m),
    };
    let mut st = match load_state(&a.state_dir) {
        Ok(s) => s,
        Err(m) => return fail(2, "state_corrupt", m),
    };
    let owned: BTreeSet<Entry> = st.owned.union(&st.pending).cloned().collect();
    let reverting = target.is_none();
    let mut warnings = Vec::new();
    let (set, spec, rev, marker, pre_conflicts, needs) = match target {
        Some(d) => {
            warnings.extend(d.warnings.clone());
            let b = match build(a, &d, &owned, st.marker, &mut warnings) {
                Ok(b) => b,
                Err(code) => return code,
            };
            (b.set, Some(d.spec), Some(d.config_revision), Some(b.marker), b.pre_conflicts, b.needs)
        }
        None => (BTreeSet::new(), st.capture.clone(), st.config_revision.clone(), st.marker, Vec::new(), NfNeeds::default()),
    };
    let devs = tc_devices(set.iter().chain(owned.iter()));
    let tables = nf_tables_to_read(marker, &set, &owned);
    let live = match read_live(&devs, &tables, &mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let mut d = reconcile(&set, &owned, &live);
    d.conflicts.extend(pre_conflicts);
    if reverting {
        warnings.extend(d.conflicts.iter().cloned());
    } else if !d.conflicts.is_empty() {
        return out(3, json!({ "ok": false, "error": { "code": "conflict", "message": "чужие записи или коллизии; ничего не изменено" },
            "conflicts": d.conflicts, "phase": st.phase, "marker": marker, "warnings": warnings }));
    }
    let mut keep_qdisc: BTreeSet<String> = BTreeSet::new();
    let mut del: Vec<Entry> = Vec::new();
    for e in &d.del {
        if let Entry::Qdisc { dev } = e {
            if foreign_filters_on(&live, dev) > 0 {
                warnings.push(format!("на {dev} появились чужие фильтры: дисциплина clsact оставлена, сняты только наши фильтры"));
                keep_qdisc.insert(dev.clone());
                for o in owned.iter().filter(|o| matches!(o, Entry::Filter { dev: fd, .. } if fd == dev)) {
                    if live.tc.iter().any(|t| t.filters.iter().any(|(_, f)| f.as_ref() == Ok(o))) {
                        del.insert(0, o.clone());
                    }
                }
                continue;
            }
        }
        del.push(e.clone());
    }
    let new_phase = if reverting { "reverted" } else if set.iter().any(Entry::is_tun_route) || set.is_empty() { "applied" } else { "guard" };
    let steps: Vec<(&Entry, &'static str)> = d.add.iter().map(|e| (e, "add")).chain(del.iter().map(|e| (e, "del"))).collect();
    let prev_phase = st.phase.clone();
    if !steps.is_empty() {
        st.phase = "pending".into();
        st.pending = d.add.iter().cloned().collect();
        st.last_error = None;
        if let Err(m) = save_state(&a.state_dir, &mut st) {
            return fail(2, "state_write", m);
        }
    }
    let mut done: Vec<Step> = Vec::new();
    let mut failed: Option<usize> = None;
    for (i, (e, op)) in steps.iter().enumerate() {
        let s = exec(e, op);
        let ok = s.ok;
        done.push(s);
        if !ok {
            failed = Some(i);
            break;
        }
    }
    if let Some(i) = failed {
        let mut rollback = Vec::new();
        for (e, op) in steps[..i].iter().rev() {
            rollback.push(exec(e, if *op == "add" { "del" } else { "add" }));
        }
        let clean = rollback.iter().all(|s| s.ok);
        let err = done.last().and_then(|s| s.error.clone()).unwrap_or_default();
        st.last_error = Some(err.clone());
        if clean {
            st.phase = prev_phase;
            st.pending.clear();
        } else {
            st.phase = "dirty".into();
        }
        let _ = save_state(&a.state_dir, &mut st);
        return out(if clean { 4 } else { 5 }, json!({ "ok": false,
            "error": { "code": if clean { "apply_failed" } else { "rollback_incomplete" }, "message": err },
            "steps": done, "rollback": rollback, "phase": st.phase, "marker": marker, "warnings": warnings }));
    }
    st.owned = set.iter().filter(|e| !matches!(e, Entry::Qdisc { dev } if keep_qdisc.contains(dev))).cloned().collect();
    st.pending.clear();
    st.phase = new_phase.into();
    st.config_revision = rev;
    st.plan_sha256 = Some(revision(&serde_json::to_vec(&set).unwrap_or_default()));
    st.capture = if reverting { None } else { spec };
    st.marker = if reverting { st.marker } else { marker };
    if let Err(m) = save_state(&a.state_dir, &mut st) {
        return fail(2, "state_write", m);
    }
    let mut w2 = Vec::new();
    let verified = read_live(&tc_devices(set.iter()), &ipt_tables(set.iter()), &mut w2).map(|l| {
        let v = reconcile(&set, &set, &l);
        v.is_noop() && v.conflicts.is_empty()
    });
    out(
        if verified == Ok(true) { 0 } else { 1 },
        json!({ "ok": verified == Ok(true), "noop": steps.is_empty(), "phase": st.phase, "marker": st.marker, "needs": needs,
            "config_revision": st.config_revision, "plan_sha256": st.plan_sha256, "steps": done, "verified": verified.unwrap_or(false),
            "tun_present": tun_present(), "owned": st.owned.iter().map(Entry::label).collect::<Vec<_>>(), "warnings": warnings }),
    )
}

fn observed_addrs() -> BTreeMap<String, BTreeSet<String>> {
    let mut m: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for fam in ["-4", "-6"] {
        if let Ok(t) = run_s("ip", &[fam, "neigh", "show"]) {
            for line in t.lines() {
                let w: Vec<&str> = line.split_whitespace().collect();
                let (Some(addr), Some(i)) = (w.first(), w.iter().position(|x| *x == "lladdr")) else { continue };
                if addr.starts_with("fe80") {
                    continue;
                }
                if let Some(mac) = w.get(i + 1) {
                    m.entry(mac.to_ascii_lowercase()).or_default().insert(addr.to_string());
                }
            }
        }
    }
    m
}

fn status(a: &Args) -> ExitCode {
    let st = match load_state(&a.state_dir) {
        Ok(s) => s,
        Err(m) => return fail(2, "state_corrupt", m),
    };
    let mut warnings = Vec::new();
    let owned: BTreeSet<Entry> = st.owned.union(&st.pending).cloned().collect();
    let live = match read_live(&tc_devices(owned.iter()), &nf_tables_to_read(st.marker, &BTreeSet::new(), &owned), &mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let d = reconcile(&st.owned, &owned, &live);
    let tun = tun_present();
    let tun_route_live = d.live_in_zone.iter().any(Entry::is_tun_route);
    let source_rules = |e: &Entry| matches!(e, Entry::Filter { .. } | Entry::Ipt { .. });
    let sources_owned = st.owned.iter().any(source_rules);
    let sources_live = st.owned.iter().filter(|e| source_rules(e)).all(|e| d.live_in_zone.contains(e));
    let protection = if st.owned.is_empty() {
        "нет защиты"
    } else if sources_owned && !sources_live {
        "правила определения источника неполные: защита не действует полностью"
    } else if tun && tun_route_live {
        "захваченный трафик идёт в TUN Mihomo; адреса вне плана и внешний IPv6 блокируются"
    } else {
        "движок не работает: захваченный трафик блокируется (unreachable)"
    };
    let seen = observed_addrs();
    let sources: Vec<Value> = st
        .capture
        .iter()
        .flat_map(|c| c.devices.iter())
        .map(|dv| {
            let addrs = seen.get(&dv.mac).cloned().unwrap_or_default();
            let unplanned: Vec<&String> = addrs.iter().filter(|x| Some(*x) != dv.ipv4.as_ref()).collect();
            json!({ "device": dv.id, "mac": dv.mac, "planned_ipv4": dv.ipv4, "observed": addrs,
                "note": if unplanned.is_empty() { "адреса совпадают с планом".to_string() }
                        else { format!("адреса вне плана {unplanned:?}: их внешний трафик блокируется до apply") } })
        })
        .collect();
    let consistent = d.conflicts.is_empty() && d.missing.is_empty() && st.pending.is_empty() && st.phase != "dirty";
    out(
        if consistent { 0 } else { 1 },
        json!({ "ok": consistent, "phase": st.phase, "marker": st.marker, "config_revision": st.config_revision, "plan_sha256": st.plan_sha256,
            "protection": protection, "tun_present": tun, "sources": sources,
            "owned": st.owned.iter().map(Entry::label).collect::<Vec<_>>(),
            "missing": d.missing.iter().map(Entry::label).collect::<Vec<_>>(),
            "pending": st.pending.iter().map(Entry::label).collect::<Vec<_>>(),
            "conflicts": d.conflicts, "last_error": st.last_error, "warnings": warnings }),
    )
}

fn plan(a: &Args) -> ExitCode {
    let dsr = match render_spec(a) {
        Ok(d) => d,
        Err(c) => return c,
    };
    let mut warnings = dsr.warnings.clone();
    let st = load_state(&a.state_dir).unwrap_or_default();
    let owned: BTreeSet<Entry> = st.owned.union(&st.pending).cloned().collect();
    let b = match build(a, &dsr, &owned, st.marker, &mut warnings) {
        Ok(b) => b,
        Err(code) => return code,
    };
    let live = match read_live(&tc_devices(b.set.iter().chain(owned.iter())), &nf_tables_to_read(Some(b.marker), &b.set, &owned), &mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let d = reconcile(&b.set, &owned, &live);
    let mut conflicts = b.pre_conflicts.clone();
    conflicts.extend(d.conflicts.clone());
    out(
        if conflicts.is_empty() { 0 } else { 3 },
        json!({ "ok": conflicts.is_empty(), "marker": b.marker, "needs": b.needs, "config_revision": dsr.config_revision, "capture": dsr.spec,
            "desired": b.set.iter().map(Entry::label).collect::<Vec<_>>(),
            "add": d.add.iter().map(Entry::label).collect::<Vec<_>>(), "del": d.del.iter().map(Entry::label).collect::<Vec<_>>(),
            "conflicts": conflicts, "caps": { "tc_ok": b.caps.tc_ok, "netfilter_ok": b.caps.netfilter_ok, "netfilter_mark_ok": b.caps.netfilter_mark_ok },
            "warnings": warnings }),
    )
}

fn caps_cmd(a: &Args) -> ExitCode {
    let c = gather_caps();
    let choice = c.choose(a.marker);
    out(
        if choice.is_ok() { 0 } else { 2 },
        json!({ "ok": choice.is_ok(), "chosen": choice.as_ref().ok(), "missing": choice.err(), "caps": c }),
    )
}

/// `release verify <пакет> [--pinned <файл ключа>] [--unpacked <каталог>]` — подпись, файлы пакета и распакованные файлы.
fn release_cmd(args: &[String]) -> ExitCode {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let (dir, rest) = match a.as_slice() {
        ["verify", dir, rest @ ..] => (*dir, rest),
        _ => return fail(2, "usage", "mi-tt-admin release verify <каталог пакета> [--pinned <release.pub>] [--unpacked <каталог>]"),
    };
    let mut pinned = None;
    let mut unpacked = None;
    let mut it = rest.iter();
    while let Some(k) = it.next() {
        match (*k, it.next()) {
            ("--pinned", Some(v)) => match fs::read_to_string(v) {
                Ok(s) => pinned = Some(s.trim().to_string()),
                Err(e) => return fail(2, "pinned_unreadable", format!("{v}: {e}")),
            },
            ("--unpacked", Some(v)) => unpacked = Some(v.to_string()),
            _ => return fail(2, "usage", format!("неизвестный аргумент {k}")),
        }
    }
    let v = match mi_tt::release::verify_package(Path::new(dir), pinned.as_deref()) {
        Ok(v) => v,
        Err(m) => return fail(3, "release_rejected", m),
    };
    let mut unpacked_bytes = None;
    if let Some(u) = unpacked {
        match mi_tt::release::verify_unpacked(&v.manifest, Path::new(&u)) {
            Ok(n) => unpacked_bytes = Some(n),
            Err(m) => return fail(3, "release_rejected", m),
        }
    }
    out(0, json!({ "ok": true, "version": v.manifest.version, "target": v.manifest.target, "key_fingerprint": v.key_fingerprint,
        "pinned": pinned.is_some(), "files": v.manifest.files.len(), "data_bytes": v.manifest.data_bytes, "tmp_bytes": v.manifest.tmp_bytes,
        "unpacked_bytes": unpacked_bytes }))
}

fn main() -> ExitCode {
    for v in ["GATEWAY_INTERFACE", "REQUEST_METHOD", "SERVER_SOFTWARE", "HTTP_HOST"] {
        if std::env::var_os(v).is_some() {
            return fail(77, "cgi_forbidden", "mi-tt-admin не запускается из CGI");
        }
    }
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.first().map(String::as_str) == Some("auth") {
        return auth_cmd::run(&argv[1..]);
    }
    if argv.first().map(String::as_str) == Some("release") {
        return release_cmd(&argv[1..]);
    }
    if argv.first().map(String::as_str) == Some("sha256") {
        // на стоке нет sha256sum: установщик и загрузчик считают хэши этой командой
        let mut rc = 0;
        for f in &argv[1..] {
            match mi_tt::release::sha256_file(Path::new(f)) {
                Ok((h, _)) => println!("{h}  {f}"),
                Err(e) => {
                    eprintln!("{e}");
                    rc = 1;
                }
            }
        }
        return ExitCode::from(rc);
    }
    let a = match parse_args() {
        Ok(a) => a,
        Err(m) => {
            eprintln!("{USAGE}");
            return fail(2, "usage", m);
        }
    };
    match a.cmd.as_str() {
        "caps" => caps_cmd(&a),
        "plan" => plan(&a),
        "apply" => match render_spec(&a) {
            Ok(d) => change(&a, Some(d)),
            Err(c) => c,
        },
        "revert" => change(&a, None),
        "status" => status(&a),
        _ => {
            eprintln!("{USAGE}");
            fail(2, "usage", format!("неизвестная команда {}", a.cmd))
        }
    }
}
