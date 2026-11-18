//! mi-tt-admin — административный CLI: план, применение, статус и снятие собственных правил маршрутизации
//! и меток источника. Требует CAP_NET_ADMIN, запускается оператором или службой загрузки; из CGI не работает.
//!
//! Источник защищённого трафика определяется на входе (tc на мосту/порту ставит метку), поэтому смена
//! DHCP-адреса или новый IPv6 не дают прямого выхода до повторного apply: метка без известного адреса → unreachable.
//!
//! Гарантии:
//!  - до изменений проверяются интерфейсы (мост — мост, порт принадлежит своему мосту), наличие tc и коллизии меток;
//!  - одновременно меняет сеть только один процесс (блокировка <state>/apply.lock);
//!  - журнал (<state>/applied.json) получает список намеченных записей до изменений;
//!  - чужие записи в зоне, чужие фильтры раньше наших, чужие правила/метки на наших битах → отказ без изменений;
//!  - ошибка на шаге → откат выполненных шагов в обратном порядке;
//!  - чужую ingress/clsact используем, но не удаляем; нашу не удаляем, если на ней появились чужие фильтры.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use mi_tt::api::{MAX_CONFIG_BYTES, parse_json, read_limited};
use mi_tt::model::Config;
use mi_tt::plan::{
    CaptureSpec, Entry, Live, TABLE, TC_PREF_MAX, TC_PREF_MIN, TcDev, build_plan, iptables_mark_collisions, parse_link, parse_routes, parse_rules,
    parse_tc_filters, parse_tc_hook, parse_v6_prefixes, reconcile, tc_devices,
};
use mi_tt::render::{self, Secrets, TUN_DEVICE};
use mi_tt::store::{lock, revision, write_atomic};

const USAGE: &str = "mi-tt-admin — применение собственных правил маршрутизации и меток источника (нужен CAP_NET_ADMIN)

  mi-tt-admin plan   --state-dir D --config C --secrets S --leases L [--guard-only]
  mi-tt-admin apply  --state-dir D --config C --secrets S --leases L [--guard-only]
  mi-tt-admin status --state-dir D
  mi-tt-admin revert --state-dir D

--guard-only: метки и запреты без маршрута через TUN — для старта до запуска Mihomo или при его отсутствии.
Коды выхода: 0 — готово/согласовано, 1 — расхождение, 2 — ошибка входных данных или интерфейсов, 3 — чужие записи
или коллизии, 4 — ошибка применения (выполненные шаги откатаны), 5 — откат не завершён, 6 — занято другим процессом,
77 — запуск из CGI запрещён. Утилиты: MI_TT_IP (ip), MI_TT_TC (tc), MI_TT_IPTABLES_SAVE (iptables-save).";

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
    let mut a = Args { cmd, state_dir: PathBuf::new(), config: None, secrets: None, leases: None, guard_only: false };
    while let Some(k) = it.next() {
        let mut val = || it.next().ok_or(format!("{k}: нужно значение"));
        match k.as_str() {
            "--state-dir" => a.state_dir = PathBuf::from(val()?),
            "--config" => a.config = Some(val()?),
            "--secrets" => a.secrets = Some(val()?),
            "--leases" => a.leases = Some(val()?),
            "--guard-only" => a.guard_only = true,
            _ => return Err(format!("неизвестный аргумент {k}")),
        }
    }
    if a.state_dir.as_os_str().is_empty() {
        return Err("нужен --state-dir".into());
    }
    Ok(a)
}

// ---------- системные утилиты (отдельные аргументы, без оболочки) ----------

fn bin(prog: &str) -> String {
    let var = match prog {
        "ip" => "MI_TT_IP",
        "tc" => "MI_TT_TC",
        _ => "MI_TT_IPTABLES_SAVE",
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

/// Пустая таблица в новых ядрах/iproute2 даёт ошибку «FIB table does not exist» — это не сбой, а отсутствие записей.
fn table_routes(v6: bool) -> Result<String, String> {
    let t = TABLE.to_string();
    let args: Vec<&str> = if v6 { vec!["-6", "route", "show", "table", &t] } else { vec!["route", "show", "table", &t] };
    match run_s("ip", &args) {
        Err(e) if e.contains("does not exist") => Ok(String::new()),
        r => r,
    }
}

fn read_live(devs: &BTreeSet<String>, warnings: &mut Vec<String>) -> Result<Live, String> {
    let mut l = Live { rules: parse_rules(&run_s("ip", &["rule", "show"])?, false), routes: parse_routes(&table_routes(false)?, false), tc: Vec::new() };
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
    Ok(l)
}

fn tun_present() -> bool {
    run_s("ip", &["link", "show", "dev", TUN_DEVICE]).is_ok()
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

/// Проверка интерфейсов до любых изменений: мосты существуют и являются мостами, порты — порты своих мостов.
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

fn v6_prefixes(spec: &CaptureSpec) -> Vec<String> {
    let bridges: BTreeSet<&str> =
        spec.devices.iter().map(|d| d.bridge.as_str()).chain(spec.networks.iter().map(|n| n.bridge.as_str())).chain(spec.lanwide.iter().map(|l| l.bridge.as_str())).collect();
    let mut v: BTreeSet<String> = BTreeSet::new();
    for b in bridges {
        if let Ok(t) = run_s("ip", &["-6", "addr", "show", "dev", b, "scope", "global"]) {
            v.extend(parse_v6_prefixes(&t));
        }
    }
    v.into_iter().collect()
}

/// Метки в firewall: iptables-save/ip6tables-save, если есть. Без них коллизия с firewall не проверена.
fn firewall_mark_check(warnings: &mut Vec<String>) -> Vec<String> {
    let mut conflicts = Vec::new();
    let mut found = false;
    for (prog, var_default) in [("iptables-save", "iptables-save"), ("ip6tables-save", "ip6tables-save")] {
        let b = if prog == "iptables-save" { bin("iptables-save") } else { var_default.to_string() };
        if let Ok(o) = Command::new(&b).args(["-t", "mangle"]).output() {
            if o.status.success() {
                found = true;
                conflicts.extend(iptables_mark_collisions(&String::from_utf8_lossy(&o.stdout)).into_iter().map(|l| format!("{prog}: правило firewall меняет/читает биты наших меток: {l}")));
            }
        }
    }
    if !found {
        warnings.push("iptables-save не найден: пересечение меток с firewall (mangle) не проверено".into());
    }
    conflicts
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
    let mut pre_conflicts = Vec::new();
    let (set, spec, rev) = match target {
        Some(d) => {
            warnings.extend(d.warnings);
            let errs = check_interfaces(&d.spec);
            if !errs.is_empty() {
                return out(2, json!({ "ok": false, "error": { "code": "interfaces", "message": "интерфейсы не соответствуют настройкам; ничего не изменено" }, "issues": errs, "phase": st.phase }));
            }
            if !d.spec.is_empty() {
                if let Err(e) = run_s("tc", &["-V"]) {
                    return fail(2, "tc_missing", format!("нужна утилита tc: {e}"));
                }
            }
            pre_conflicts = firewall_mark_check(&mut warnings);
            let hook_devs = tc_devices(&build_plan(&d.spec, &[], &BTreeSet::new(), &owned, a.guard_only));
            let foreign_hooks: BTreeSet<String> = hook_devs
                .iter()
                .filter(|dev| run_s("tc", &["qdisc", "show", "dev", dev]).map(|q| parse_tc_hook(&q)).unwrap_or(false) && !owned.contains(&Entry::Qdisc { dev: (*dev).clone() }))
                .cloned()
                .collect();
            let set = build_plan(&d.spec, &v6_prefixes(&d.spec), &foreign_hooks, &owned, a.guard_only);
            (set, Some(d.spec), Some(d.config_revision))
        }
        None => (BTreeSet::new(), st.capture.clone(), st.config_revision.clone()),
    };
    let devs = tc_devices(set.iter().chain(owned.iter()));
    let live = match read_live(&devs, &mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let mut d = reconcile(&set, &owned, &live);
    d.conflicts.extend(pre_conflicts);
    if reverting {
        warnings.extend(d.conflicts.iter().cloned()); // снятие трогает только своё
    } else if !d.conflicts.is_empty() {
        return out(3, json!({ "ok": false, "error": { "code": "conflict", "message": "чужие записи или коллизии меток; ничего не изменено" },
            "conflicts": d.conflicts, "phase": st.phase, "warnings": warnings }));
    }
    // нашу дисциплину с чужими фильтрами не удаляем: снимаем только свои фильтры
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
    let new_phase = if reverting { "reverted" } else if set.iter().any(Entry::is_tun_route) { "applied" } else if set.is_empty() { "applied" } else { "guard" };
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
            "steps": done, "rollback": rollback, "phase": st.phase, "warnings": warnings }));
    }
    st.owned = set.iter().filter(|e| !matches!(e, Entry::Qdisc { dev } if keep_qdisc.contains(dev))).cloned().collect();
    st.pending.clear();
    st.phase = new_phase.into();
    st.config_revision = rev;
    st.plan_sha256 = Some(revision(&serde_json::to_vec(&set).unwrap_or_default()));
    st.capture = if reverting { None } else { spec };
    if let Err(m) = save_state(&a.state_dir, &mut st) {
        return fail(2, "state_write", m);
    }
    let mut w2 = Vec::new();
    let verified = read_live(&tc_devices(set.iter()), &mut w2).map(|l| {
        let v = reconcile(&set, &set, &l);
        v.is_noop() && v.conflicts.is_empty()
    });
    out(
        if verified == Ok(true) { 0 } else { 1 },
        json!({ "ok": verified == Ok(true), "noop": steps.is_empty(), "phase": st.phase, "config_revision": st.config_revision,
            "plan_sha256": st.plan_sha256, "steps": done, "verified": verified.unwrap_or(false), "tun_present": tun_present(),
            "owned": st.owned.iter().map(Entry::label).collect::<Vec<_>>(), "warnings": warnings }),
    )
}

/// Наблюдаемые адреса MAC в таблице соседей (ip neigh): mac → адреса IPv4/IPv6 (без link-local).
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
    let live = match read_live(&tc_devices(owned.iter()), &mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let d = reconcile(&st.owned, &owned, &live);
    let tun = tun_present();
    let tun_route_live = d.live_in_zone.iter().any(Entry::is_tun_route);
    let marks_live = d.live_in_zone.iter().any(|e| matches!(e, Entry::Filter { .. }));
    let protection = if st.owned.is_empty() {
        "нет защиты"
    } else if !marks_live {
        "метки не ставятся: защита не действует"
    } else if tun && tun_route_live {
        "помеченный трафик идёт в TUN Mihomo; адреса вне плана и внешний IPv6 блокируются"
    } else {
        "движок не работает: помеченный трафик блокируется (unreachable)"
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
        json!({ "ok": consistent, "phase": st.phase, "config_revision": st.config_revision, "plan_sha256": st.plan_sha256,
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
    let iface = check_interfaces(&dsr.spec);
    let mut conflicts = firewall_mark_check(&mut warnings);
    let hook_devs = tc_devices(&build_plan(&dsr.spec, &[], &BTreeSet::new(), &owned, a.guard_only));
    let foreign_hooks: BTreeSet<String> = hook_devs
        .iter()
        .filter(|dev| run_s("tc", &["qdisc", "show", "dev", dev]).map(|q| parse_tc_hook(&q)).unwrap_or(false) && !owned.contains(&Entry::Qdisc { dev: (*dev).clone() }))
        .cloned()
        .collect();
    let set = build_plan(&dsr.spec, &v6_prefixes(&dsr.spec), &foreign_hooks, &owned, a.guard_only);
    let live = match read_live(&tc_devices(set.iter().chain(owned.iter())), &mut warnings) {
        Ok(l) => l,
        Err(m) => return fail(2, "read_failed", m),
    };
    let d = reconcile(&set, &owned, &live);
    conflicts.extend(d.conflicts.clone());
    let ok = conflicts.is_empty() && iface.is_empty();
    out(
        if !iface.is_empty() { 2 } else if conflicts.is_empty() { 0 } else { 3 },
        json!({ "ok": ok, "config_revision": dsr.config_revision, "capture": dsr.spec, "foreign_hooks": foreign_hooks,
            "desired": set.iter().map(Entry::label).collect::<Vec<_>>(),
            "add": d.add.iter().map(Entry::label).collect::<Vec<_>>(), "del": d.del.iter().map(Entry::label).collect::<Vec<_>>(),
            "interfaces": iface, "conflicts": conflicts, "warnings": warnings }),
    )
}

fn main() -> ExitCode {
    // CGI-окружение означает вызов из веб-сервера без аутентификации: привилегированные действия запрещены.
    for v in ["GATEWAY_INTERFACE", "REQUEST_METHOD", "SERVER_SOFTWARE", "HTTP_HOST"] {
        if std::env::var_os(v).is_some() {
            return fail(77, "cgi_forbidden", "mi-tt-admin не запускается из CGI");
        }
    }
    let a = match parse_args() {
        Ok(a) => a,
        Err(m) => {
            eprintln!("{USAGE}");
            return fail(2, "usage", m);
        }
    };
    match a.cmd.as_str() {
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
