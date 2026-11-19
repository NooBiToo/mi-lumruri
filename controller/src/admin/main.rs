//! mi-tt-admin — административный CLI: план, применение, статус и снятие собственных правил выбора маршрута.
//! Требует CAP_NET_ADMIN, запускается оператором или службой загрузки; из CGI не работает.
//!
//! Что применяется (сток RC06 1.1.38): наборы ipset, цепочки классификации iptables (метка «через TrustTunnel»,
//! запрет, очередь Zapret, запрет IPv6), `ip rule fwmark 0x4000 lookup 3100` и маршруты таблицы 3100 (TUN клиента
//! TrustTunnel и запасной unreachable). Статические наборы (IP-префиксы) заполняются после применения заменой целиком.
//! До любых изменений: проверка возможностей ядра и утилит (только чтение), интерфейсов, коллизий; при отказе — ничего.
//!
//! Гарантии: блокировка <state>/apply.lock; журнал <state>/applied.json с pending до изменений; откат выполненных
//! шагов при ошибке; чужие записи не удаляются.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod auth_cmd;

use mi_tt::api::{MAX_CONFIG_BYTES, parse_json, read_limited};
use mi_tt::caps::{self, Caps, Item, check_kernel, help_has, parse_kconfig};
use mi_tt::model::Config;
use mi_tt::plan::{
    Act, Entry, Live, PolicySpec, SetKind, TABLE, build_plan, ipt_tables, needs_physdev, parse_ipsets, parse_ipt, parse_link, parse_routes, parse_rules, parse_v6_prefixes, reconcile,
};
use mi_tt::render::{self, Secrets, TUN_DEVICE};
use mi_tt::store::{lock, revision, write_atomic};

const USAGE: &str = "mi-tt-admin — применение собственных правил выбора маршрута (нужен CAP_NET_ADMIN)

  mi-tt-admin caps                                                     # только чтение: возможности ядра и утилит
  mi-tt-admin plan   --state-dir D --config C --secrets S [--guard-only]
  mi-tt-admin apply  --state-dir D --config C --secrets S [--guard-only]
  mi-tt-admin status --state-dir D
  mi-tt-admin revert --state-dir D
  mi-tt-admin auth …                                                   # вход в панель: см. mi-tt-admin auth help
  mi-tt-admin release verify <пакет> [--pinned K] [--unpacked D]       # подпись и хэши пакета релиза
  mi-tt-admin sha256 <файл>…                                           # SHA-256 (на стоке нет sha256sum)

--guard-only: правила и запреты без маршрута через TUN — для старта до запуска клиента TrustTunnel или при его отсутствии.
Коды выхода: 0 — готово/согласовано, 1 — расхождение, 2 — ошибка входных данных, интерфейсов или возможностей,
3 — чужие записи или коллизии, 4 — ошибка применения (выполненные шаги откатаны), 5 — откат не завершён,
6 — занято другим процессом, 77 — запуск из CGI запрещён.
Окружение: MI_TT_IP, MI_TT_IPTABLES, MI_TT_IP6TABLES, MI_TT_IPTABLES_SAVE, MI_TT_IPSET — пути утилит;
MI_TT_KCONFIG — файл конфигурации ядра вместо /proc/config.gz; MI_TT_MODULES_DIR — каталог модулей.";

const STATE_VERSION: u32 = 2;

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    version: u32,
    /// none | guard | applied | reverted | pending | dirty
    phase: String,
    config_revision: Option<String>,
    plan_sha256: Option<String>,
    owned: BTreeSet<Entry>,
    pending: BTreeSet<Entry>,
    #[serde(default)]
    policy: Option<PolicySpec>,
    updated_unix: u64,
    last_error: Option<String>,
}

struct Args {
    cmd: String,
    state_dir: PathBuf,
    config: Option<String>,
    secrets: Option<String>,
    guard_only: bool,
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
    let mut a = Args { cmd, state_dir: PathBuf::new(), config: None, secrets: None, guard_only: false };
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or(format!("{k}: нужно значение"));
        match k.as_str() {
            "--state-dir" => a.state_dir = PathBuf::from(val()?),
            "--config" => a.config = Some(val()?),
            "--secrets" => a.secrets = Some(val()?),
            "--guard-only" => a.guard_only = true,
            // прежние аргументы службы: аренды DHCP больше не нужны, механизм один
            "--leases" | "--marker" => {
                val()?;
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
        "iptables" => "MI_TT_IPTABLES",
        "ip6tables" => "MI_TT_IP6TABLES",
        "iptables-save" => "MI_TT_IPTABLES_SAVE",
        "ipset" => "MI_TT_IPSET",
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

/// Запуск с данными на stdin (ipset restore).
fn run_stdin(prog: &str, args: &[&str], input: &str) -> Result<(), String> {
    let mut c = Command::new(bin(prog)).args(args).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().map_err(|e| format!("не удалось запустить {}: {e}", bin(prog)))?;
    if let Some(mut si) = c.stdin.take() {
        si.write_all(input.as_bytes()).map_err(|e| e.to_string())?;
    }
    let o = c.wait_with_output().map_err(|e| e.to_string())?;
    if o.status.success() { Ok(()) } else { Err(format!("{prog} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim())) }
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

fn read_live(warnings: &mut Vec<String>) -> Result<Live, String> {
    let mut l = Live { rules: parse_rules(&run_s("ip", &["rule", "show"])?, false), routes: parse_routes(&table_routes(false)?, false), ..Default::default() };
    match (run_s("ip", &["-6", "rule", "show"]), table_routes(true)) {
        (Ok(r), Ok(rt)) => {
            l.rules.extend(parse_rules(&r, true));
            l.routes.extend(parse_routes(&rt, true));
        }
        (Err(e), _) | (_, Err(e)) => warnings.push(format!("IPv6 в ядре недоступен или не читается: {e}")),
    }
    for (v6, table) in ipt_tables() {
        let prog = if v6 { "ip6tables" } else { "iptables" };
        let t = run_s(prog, &["-w", "-t", &table, "-S"])?;
        l.ipt.push(parse_ipt(&t, v6, &table));
    }
    match run_s("ipset", &["list", "-t"]) {
        Ok(t) => l.ipsets = parse_ipsets(&t),
        Err(e) => warnings.push(format!("ipset не читается: {e}")),
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
        netfilter: check_kernel(caps::NF, k.as_ref(), &mods),
        netfilter_physdev: check_kernel(caps::NF_PHYSDEV, k.as_ref(), &mods),
        netfilter_queue: check_kernel(caps::NF_QUEUE, k.as_ref(), &mods),
        ..Default::default()
    };
    for (prog, rej) in [("iptables", "icmp-port-unreachable"), ("ip6tables", "icmp6-port-unreachable")] {
        let v = run_s(prog, &["-V"]);
        c.netfilter.push(tool(&format!("утилита {prog}"), v.is_ok(), v.unwrap_or_else(|e| e).trim().to_string()));
        c.netfilter.push(tool(&format!("{prog} -m mac --mac-source"), help_has(&help(prog, &["-m", "mac", "-h"]), "--mac-source"), "расширение mac".into()));
        c.netfilter.push(tool(&format!("{prog} -m comment"), help_has(&help(prog, &["-m", "comment", "-h"]), "--comment"), "расширение comment".into()));
        c.netfilter.push(tool(&format!("{prog} -j REJECT"), help_has(&help(prog, &["-j", "REJECT", "-h"]), "--reject-with"), format!("цель REJECT ({rej})")));
        c.netfilter_physdev.push(tool(&format!("{prog} -m physdev"), help_has(&help(prog, &["-m", "physdev", "-h"]), "--physdev-in"), "расширение physdev".into()));
    }
    c.netfilter.push(tool("iptables -j MARK --set-xmark", help_has(&help("iptables", &["-j", "MARK", "-h"]), "--set-xmark"), "MARK ревизии 2 (ядро отдаёт xt_mark)".into()));
    c.netfilter.push(tool("iptables -m set --match-set", help_has(&help("iptables", &["-m", "set", "-h"]), "--match-set"), "расширение set".into()));
    let v = run_s("ipset", &["-v"]);
    c.netfilter.push(tool("утилита ipset", v.is_ok(), v.unwrap_or_else(|e| e).trim().to_string()));
    c.netfilter_queue.push(tool("iptables -j NFQUEUE --queue-bypass", help_has(&help("iptables", &["-j", "NFQUEUE", "-h"]), "--queue-bypass"), "цель NFQUEUE".into()));
    c.netfilter_queue.push(tool("iptables -m multiport", help_has(&help("iptables", &["-m", "multiport", "-h"]), "--dports"), "расширение multiport".into()));
    c.netfilter_queue.push(tool("iptables -m connbytes", help_has(&help("iptables", &["-m", "connbytes", "-h"]), "--connbytes"), "расширение connbytes".into()));
    for (f, name) in [("bridge-nf-call-iptables", "IPv4"), ("bridge-nf-call-ip6tables", "IPv6")] {
        let v = fs::read_to_string(format!("/proc/sys/net/bridge/{f}")).unwrap_or_default();
        c.netfilter_physdev.push(tool(&format!("net.bridge.{f}=1"), v.trim() == "1", format!("{name}: physdev на маршрутизируемом трафике моста видит порт только при 1 (сейчас «{}»)", v.trim())));
    }
    c.finish()
}

// ---------- журнал ----------

fn state_path(d: &Path) -> PathBuf {
    d.join("applied.json")
}

/// Журнал прежней версии (другой формат записей) не переносится: начинаем с чистого журнала, а сверка с ядром
/// найдёт оставшиеся записи в зоне и откажет без изменений.
fn load_state(d: &Path, warnings: &mut Vec<String>) -> Result<State, String> {
    let p = state_path(d);
    let fresh = State { version: STATE_VERSION, phase: "none".into(), ..Default::default() };
    if !p.exists() {
        return Ok(fresh);
    }
    let b = read_limited(&p.to_string_lossy(), MAX_CONFIG_BYTES)?;
    match serde_json::from_slice::<State>(&b) {
        Ok(s) if s.version == STATE_VERSION => Ok(s),
        Ok(s) if s.owned.is_empty() && s.pending.is_empty() => Ok(fresh),
        _ if serde_json::from_slice::<Value>(&b).is_ok_and(|v| v["version"] != json!(STATE_VERSION)) => {
            warnings.push(format!("журнал {} прежней версии не используется", p.display()));
            Ok(fresh)
        }
        Ok(_) => Err(format!("журнал {} другой версии", p.display())),
        Err(e) => Err(format!("журнал {} повреждён: {e}", p.display())),
    }
}

fn save_state(d: &Path, s: &mut State) -> Result<(), String> {
    s.version = STATE_VERSION;
    s.updated_unix = now();
    let mut b = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    b.push(b'\n');
    write_atomic(&state_path(d), &b)
}

// ---------- желаемое состояние ----------

struct Desired {
    spec: PolicySpec,
    config_revision: String,
    warnings: Vec<String>,
}

fn render_spec(a: &Args) -> Result<Desired, ExitCode> {
    let need = |o: &Option<String>, k: &str| o.clone().ok_or_else(|| fail(2, "usage", format!("нужен {k}")));
    let (c, s) = (need(&a.config, "--config")?, need(&a.secrets, "--secrets")?);
    let rd = |p: &str| read_limited(p, MAX_CONFIG_BYTES).map_err(|m| fail(2, "unreadable", m));
    let (cb, sb) = (rd(&c)?, rd(&s)?);
    let cfg: Config = parse_json(&cb, "config").map_err(|i| out(2, json!({ "ok": false, "error": { "code": "config_invalid", "message": "настройки не разобраны" }, "issues": i })))?;
    let sec: Secrets = parse_json(&sb, "secrets").map_err(|i| out(2, json!({ "ok": false, "error": { "code": "secrets_invalid", "message": "secrets.json не разобран" }, "issues": i })))?;
    let lists = render::load_lists(&cfg, Path::new(&c)).map_err(|m| fail(2, "list_invalid", m))?;
    let r = render::render(&cfg, &sec, &lists).map_err(|i| {
        out(2, json!({ "ok": false, "error": { "code": "not_renderable", "message": "план нельзя построить точно; текущее состояние сети не меняется" }, "issues": i }))
    })?;
    Ok(Desired { spec: r.policy, config_revision: revision(&cb), warnings: r.warnings })
}

fn check_interfaces(spec: &PolicySpec) -> Vec<String> {
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

fn v6_prefixes(spec: &PolicySpec) -> Vec<String> {
    let mut v: BTreeSet<String> = BTreeSet::new();
    for b in spec.bridges() {
        if let Ok(t) = run_s("ip", &["-6", "addr", "show", "dev", &b, "scope", "global"]) {
            v.extend(parse_v6_prefixes(&t));
        }
    }
    v.into_iter().collect()
}

/// Живой состав мостов (`ip -o link show master <мост>`).
fn bridge_ports(spec: &PolicySpec) -> BTreeMap<String, BTreeSet<String>> {
    spec.bridges()
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

struct Built {
    set: BTreeSet<Entry>,
    caps: Caps,
}

/// Проверки до мутаций и построение желаемого набора. Ошибка — готовый ответ (ничего не изменено).
fn build(a: &Args, d: &Desired) -> Result<Built, ExitCode> {
    let errs = check_interfaces(&d.spec);
    if !errs.is_empty() {
        return Err(out(2, json!({ "ok": false, "error": { "code": "interfaces", "message": "интерфейсы не соответствуют настройкам; ничего не изменено" }, "issues": errs })));
    }
    let caps = gather_caps();
    if d.spec.is_empty() {
        return Ok(Built { set: BTreeSet::new(), caps });
    }
    if !caps.netfilter_ok {
        return Err(out(2, json!({ "ok": false, "error": { "code": "capabilities", "message": "нет нужных возможностей ядра или утилит; ничего не изменено" },
            "missing": caps.missing_base(), "caps": caps })));
    }
    let bp = bridge_ports(&d.spec);
    if needs_physdev(&d.spec, &bp) && !caps.netfilter_physdev_ok {
        return Err(out(2, json!({ "ok": false, "error": { "code": "capabilities",
            "message": "сеть на части моста требует physdev и bridge-nf-call=1; ничего не изменено" },
            "missing": Caps::missing(&caps.netfilter_physdev), "caps": caps })));
    }
    if (!d.spec.zapret_queue.is_empty() || d.spec.uses(Act::Zapret)) && !a.guard_only && !caps.netfilter_queue_ok {
        return Err(out(2, json!({ "ok": false, "error": { "code": "capabilities", "message": "Zapret требует NFQUEUE, multiport и connbytes в ядре и iptables; ничего не изменено" },
            "missing": Caps::missing(&caps.netfilter_queue), "caps": caps })));
    }
    Ok(Built { set: build_plan(&d.spec, &v6_prefixes(&d.spec), &bp, a.guard_only), caps })
}

// ---------- применение ----------

#[derive(Serialize)]
struct Step {
    op: &'static str,
    entry: String,
    ok: bool,
    error: Option<String>,
}

/// Все команды записи; при ошибке добавления — попытка убрать частично созданное.
fn exec(e: &Entry, op: &'static str) -> Step {
    for (prog, args) in e.cmds(op) {
        if let Err(m) = run(prog, &args) {
            if op == "add" {
                for (p, a) in e.cmds("del") {
                    let _ = run(p, &a);
                }
            }
            return Step { op, entry: e.label(), ok: false, error: Some(m) };
        }
    }
    Step { op, entry: e.label(), ok: true, error: None }
}

/// Статические наборы: новый состав во временном наборе, затем `ipset swap` — правила не видят промежуточного состояния.
fn sync_static_sets(spec: &PolicySpec) -> Vec<String> {
    let mut errs = Vec::new();
    for s in spec.sets.iter().filter(|s| s.kind == SetKind::Static) {
        let tmp = format!("{}t", &s.name[..s.name.len().min(30)]);
        let _ = run_s("ipset", &["destroy", &tmp]);
        let mut input = format!("create {tmp} hash:net family inet maxelem {}\n", (s.entries.len() * 2).max(65536));
        for e in &s.entries {
            input.push_str(&format!("add {tmp} {e} -exist\n"));
        }
        let r = run_stdin("ipset", &["restore"], &input).and_then(|_| run_s("ipset", &["swap", &tmp, &s.name]).map(|_| ()));
        let _ = run_s("ipset", &["destroy", &tmp]);
        if let Err(m) = r {
            errs.push(format!("набор {}: {m}", s.name));
        }
    }
    errs
}

fn change(a: &Args, target: Option<Desired>) -> ExitCode {
    if let Err(e) = fs::create_dir_all(&a.state_dir) {
        return fail(2, "state_dir", format!("{}: {e}", a.state_dir.display()));
    }
    let _guard = match lock(&a.state_dir.join("apply")) {
        Ok(g) => g,
        Err(m) => return fail(6, "busy", m),
    };
    let mut warnings = Vec::new();
    let mut st = match load_state(&a.state_dir, &mut warnings) {
        Ok(s) => s,
        Err(m) => return fail(2, "state_corrupt", m),
    };
    let owned: BTreeSet<Entry> = st.owned.union(&st.pending).cloned().collect();
    let reverting = target.is_none();
    let (set, spec, rev) = match target {
        Some(d) => {
            warnings.extend(d.warnings.clone());
            let b = match build(a, &d) {
                Ok(b) => b,
                Err(code) => return code,
            };
            let _ = b.caps;
            (b.set, Some(d.spec), Some(d.config_revision))
        }
        None => (BTreeSet::new(), st.policy.clone(), st.config_revision.clone()),
    };
    let live = match read_live(&mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let d = reconcile(&set, &owned, &live);
    if reverting {
        warnings.extend(d.conflicts.iter().cloned());
    } else if !d.conflicts.is_empty() {
        return out(3, json!({ "ok": false, "error": { "code": "conflict", "message": "чужие записи или коллизии; ничего не изменено" },
            "conflicts": d.conflicts, "phase": st.phase, "warnings": warnings }));
    }
    let new_phase = if reverting { "reverted" } else if set.iter().any(Entry::is_tun_route) || !set.iter().any(|e| matches!(e, Entry::Route { .. })) { "applied" } else { "guard" };
    let steps: Vec<(&Entry, &'static str)> = d.add.iter().map(|e| (e, "add")).chain(d.del.iter().map(|e| (e, "del"))).collect();
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
            "steps": done, "rollback": rollback, "phase": st.phase, "warnings": warnings }));
    }
    let set_errors = match (&spec, reverting) {
        (Some(sp), false) => sync_static_sets(sp),
        _ => Vec::new(),
    };
    st.owned = set.clone();
    st.pending.clear();
    st.phase = new_phase.into();
    st.config_revision = rev;
    st.plan_sha256 = Some(revision(&serde_json::to_vec(&set).unwrap_or_default()));
    st.policy = if reverting { None } else { spec };
    st.last_error = set_errors.first().cloned();
    if let Err(m) = save_state(&a.state_dir, &mut st) {
        return fail(2, "state_write", m);
    }
    let mut w2 = Vec::new();
    let verified = read_live(&mut w2).map(|l| {
        let v = reconcile(&set, &set, &l);
        v.is_noop() && v.conflicts.is_empty()
    });
    let ok = verified == Ok(true) && set_errors.is_empty();
    out(
        if ok { 0 } else { 1 },
        json!({ "ok": ok, "noop": steps.is_empty(), "phase": st.phase,
            "config_revision": st.config_revision, "plan_sha256": st.plan_sha256, "steps": done, "verified": verified.unwrap_or(false),
            "set_errors": set_errors, "tun_present": tun_present(), "owned": st.owned.iter().map(Entry::label).collect::<Vec<_>>(), "warnings": warnings }),
    )
}

fn status(a: &Args) -> ExitCode {
    let mut warnings = Vec::new();
    let st = match load_state(&a.state_dir, &mut warnings) {
        Ok(s) => s,
        Err(m) => return fail(2, "state_corrupt", m),
    };
    let owned: BTreeSet<Entry> = st.owned.union(&st.pending).cloned().collect();
    let live = match read_live(&mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let d = reconcile(&st.owned, &owned, &live);
    let tun = tun_present();
    let tun_route_live = d.live_in_zone.iter().any(Entry::is_tun_route);
    let tunnel_used = st.owned.iter().any(|e| matches!(e, Entry::Rule { fwmark: Some(_), .. }));
    let fail_open = st.policy.as_ref().is_some_and(|p| p.fail_open);
    let protection = if st.owned.is_empty() {
        "правил нет: весь трафик идёт напрямую"
    } else if !d.missing.is_empty() {
        "правила неполные: политика действует не полностью"
    } else if !tunnel_used || (tun && tun_route_live) {
        "правила действуют; трафик «через TrustTunnel» идёт в туннель"
    } else if fail_open {
        "туннель не работает: трафик «через TrustTunnel» идёт напрямую (обход при отказе)"
    } else {
        "туннель не работает: трафик «через TrustTunnel» блокируется (unreachable)"
    };
    let consistent = d.conflicts.is_empty() && d.missing.is_empty() && st.pending.is_empty() && st.phase != "dirty";
    out(
        if consistent { 0 } else { 1 },
        json!({ "ok": consistent, "phase": st.phase, "config_revision": st.config_revision, "plan_sha256": st.plan_sha256,
            "protection": protection, "tun_present": tun,
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
    let st = load_state(&a.state_dir, &mut warnings).unwrap_or_default();
    let owned: BTreeSet<Entry> = st.owned.union(&st.pending).cloned().collect();
    let b = match build(a, &dsr) {
        Ok(b) => b,
        Err(code) => return code,
    };
    let live = match read_live(&mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let d = reconcile(&b.set, &owned, &live);
    out(
        if d.conflicts.is_empty() { 0 } else { 3 },
        json!({ "ok": d.conflicts.is_empty(), "config_revision": dsr.config_revision, "policy": dsr.spec,
            "desired": b.set.iter().map(Entry::label).collect::<Vec<_>>(),
            "add": d.add.iter().map(Entry::label).collect::<Vec<_>>(), "del": d.del.iter().map(Entry::label).collect::<Vec<_>>(),
            "conflicts": d.conflicts, "caps": { "netfilter_ok": b.caps.netfilter_ok, "netfilter_physdev_ok": b.caps.netfilter_physdev_ok, "netfilter_queue_ok": b.caps.netfilter_queue_ok },
            "warnings": warnings }),
    )
}

fn caps_cmd(_a: &Args) -> ExitCode {
    let c = gather_caps();
    let missing = c.missing_base();
    out(if c.netfilter_ok { 0 } else { 2 }, json!({ "ok": c.netfilter_ok, "missing": missing, "caps": c }))
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
