//! Решения службы о клиенте TrustTunnel: сторож туннеля, запасной сервер и выбор по задержке. Раньше — в mitt-lib.sh;
//! здесь — чистая логика со счётчиками и сроками (проверяется тестами), сеть по-прежнему трогает сценарий: он делает
//! пробы (curl, задержка) и выполняет действия (остановить клиент, уведомление, журнал).
//!
//! Два шага за проход службы:
//!   `mi-tt-ctl tunnel due  --dir <STATE> ключ=значение…` — какие пробы пора сделать (watch, failback, fastest);
//!   `mi-tt-ctl tunnel step --dir <STATE> ключ=значение…` — итог проб → действия по строке: `restart`,
//!   `notify <событие> <ключ> [параметр]`, `log <текст>`.
//! Состояние — `<STATE>/tunnel.json`; для службы и панели как раньше: `endpoint` (primary|backup), `watch.json`,
//! `fastest.json`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub watch_fails: u32,
    pub watch_restart: u64,
    pub watch_next: u64,
    pub down_since: Option<u64>,
    pub failback_next: u64,
    pub failback_ok: u32,
    pub fastest_next: u64,
    pub fastest_ok: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ep {
    Primary,
    Backup,
}

impl Ep {
    pub fn name(self) -> &'static str {
        match self {
            Ep::Primary => "primary",
            Ep::Backup => "backup",
        }
    }
    fn other(self) -> Ep {
        match self {
            Ep::Primary => Ep::Backup,
            Ep::Backup => Ep::Primary,
        }
    }
    fn ru(self) -> &'static str {
        match self {
            Ep::Primary => "основной",
            Ep::Backup => "запасной",
        }
    }
}

/// Пороги (из переменных MITT_* сценария; по умолчанию — как раньше в mitt-lib.sh).
#[derive(Debug, Clone, Copy)]
pub struct Cfg {
    pub watch_interval: u64,
    pub watch_fails: u32,
    pub watch_gap: u64,
    pub failover_after: u64,
    pub failback_every: u64,
    pub fastest_every: u64,
    pub fastest_margin: u64,
}

impl Default for Cfg {
    fn default() -> Self {
        Cfg { watch_interval: 60, watch_fails: 3, watch_gap: 300, failover_after: 120, failback_every: 300, fastest_every: 1800, fastest_margin: 20 }
    }
}

/// Наблюдения за проход: состояние клиента и итоги проб (None — проба не делалась).
#[derive(Debug, Clone, Default)]
pub struct Obs {
    pub now: u64,
    /// Клиент сообщает VPN_SS_CONNECTED.
    pub connected: bool,
    /// TUN поднят и с адресом.
    pub tun: bool,
    /// Запасной сервер задан (client-backup.toml).
    pub backup: bool,
    /// Выбор по задержке включён (рендер: fastest).
    pub fastest: bool,
    pub endpoint: Option<Ep>,
    pub watch: Option<bool>,
    pub failback: Option<bool>,
    /// Задержка, мс: Some(None) — замер был, сервер не ответил.
    pub ping_primary: Option<Option<u64>>,
    pub ping_backup: Option<Option<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Restart,
    Notify(String, String, String),
    Log(String),
}

impl Action {
    pub fn line(&self) -> String {
        match self {
            Action::Restart => "restart".into(),
            Action::Notify(e, k, p) if p.is_empty() => format!("notify {e} {k}"),
            Action::Notify(e, k, p) => format!("notify {e} {k} {p}"),
            Action::Log(t) => format!("log {t}"),
        }
    }
}

/// Итог шага: новое состояние, сервер, файлы для службы и панели, действия.
#[derive(Debug, Default)]
pub struct Out {
    pub endpoint: Option<Ep>,
    pub watch_json: Option<String>,
    /// Some(None) — удалить fastest.json.
    pub fastest_json: Option<Option<String>>,
    pub actions: Vec<Action>,
}

/// Какие пробы пора сделать; сроки следующих сдвигаются сразу (как раньше: срок ставится до пробы).
pub fn due(st: &mut State, o: &Obs, c: &Cfg) -> Vec<&'static str> {
    let mut v = Vec::new();
    if o.now >= st.watch_next {
        st.watch_next = o.now + c.watch_interval;
        // клиент переподключается сам или TUN не готов — сторож не вмешивается
        if o.connected && o.tun { v.push("watch") } else { st.watch_fails = 0 }
    }
    let cur = o.endpoint.unwrap_or(Ep::Primary);
    if o.backup && !o.fastest && cur == Ep::Backup && o.connected && o.now >= st.failback_next {
        st.failback_next = o.now + c.failback_every;
        v.push("failback");
    }
    if o.backup && o.fastest && o.now >= st.fastest_next {
        st.fastest_next = o.now + c.fastest_every;
        v.push("fastest");
    }
    v
}

pub fn step(st: &mut State, o: &Obs, c: &Cfg) -> Out {
    let mut out = Out { endpoint: o.endpoint, ..Default::default() };
    let now = o.now;
    // сторож
    if let Some(ok) = o.watch {
        if ok {
            st.watch_fails = 0;
            out.watch_json = Some(format!("{{\"ok\":true,\"checked\":{now},\"fails\":0,\"restarted\":{}}}\n", st.watch_restart));
        } else {
            st.watch_fails += 1;
            out.watch_json = Some(format!("{{\"ok\":false,\"checked\":{now},\"fails\":{},\"restarted\":{}}}\n", st.watch_fails, st.watch_restart));
            if st.watch_fails >= c.watch_fails && now.saturating_sub(st.watch_restart) >= c.watch_gap {
                out.actions.push(Action::Log(format!("сторож: клиент «подключён», но трафик через туннель не идёт ({} проверки подряд) — перезапуск клиента", st.watch_fails)));
                out.watch_json = Some(format!("{{\"ok\":false,\"checked\":{now},\"fails\":{},\"restarted\":{now}}}\n", st.watch_fails));
                st.watch_restart = now;
                st.watch_fails = 0;
                out.actions.push(Action::Notify("tunnel".into(), "watch_restart".into(), String::new()));
                out.actions.push(Action::Restart);
            }
        }
    }
    // запасной сервер
    if !o.backup {
        st.down_since = None;
        st.failback_ok = 0;
        st.fastest_ok = 0;
        out.endpoint = None;
        out.fastest_json = Some(None);
        return out;
    }
    let cur = o.endpoint.unwrap_or(Ep::Primary);
    if o.connected {
        st.down_since = None;
    } else {
        let since = *st.down_since.get_or_insert(now);
        if now.saturating_sub(since) >= c.failover_after {
            let next = cur.other();
            out.endpoint = Some(next);
            st.down_since = None;
            st.failback_ok = 0;
            out.actions.push(Action::Log(format!("сервер: нет связи {} с — переключение на {}", now - since, next.ru())));
            out.actions.push(Action::Notify("failover".into(), format!("failover_{}", next.name()), String::new()));
            push_restart(&mut out);
            return out;
        }
    }
    if !o.fastest {
        st.fastest_ok = 0;
        out.fastest_json = Some(None);
        if let Some(ok) = o.failback {
            if ok && cur == Ep::Backup {
                st.failback_ok += 1;
                if st.failback_ok >= 2 {
                    out.endpoint = Some(Ep::Primary);
                    st.failback_ok = 0;
                    out.actions.push(Action::Log("сервер: основной снова отвечает — возврат на основной".into()));
                    out.actions.push(Action::Notify("failover".into(), "failover_primary".into(), String::new()));
                    push_restart(&mut out);
                }
            } else {
                st.failback_ok = 0;
            }
        }
        return out;
    }
    // выбор по задержке: другой быстрее на 30 % и не меньше чем на margin мс (или текущий не ответил), два замера подряд
    if let (Some(pp), Some(pb)) = (o.ping_primary, o.ping_backup) {
        let js = |v: Option<u64>| v.map_or("null".to_string(), |x| x.to_string());
        out.fastest_json = Some(Some(format!("{{\"at\":{now},\"primary\":{},\"backup\":{}}}\n", js(pp), js(pb))));
        let (pc, po) = if cur == Ep::Primary { (pp, pb) } else { (pb, pp) };
        let better = match (pc, po) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(c_), Some(o_)) => o_ * 10 <= c_ * 7 && c_.saturating_sub(o_) >= c.fastest_margin,
        };
        if better {
            st.fastest_ok += 1;
            if st.fastest_ok >= 2 {
                let other = cur.other();
                out.endpoint = Some(other);
                st.fastest_ok = 0;
                st.down_since = None;
                st.failback_ok = 0;
                let pcs = pc.map_or("нет ответа".to_string(), |x| x.to_string());
                out.actions.push(Action::Log(format!("сервер: {} быстрее ({} мс против {pcs} мс) — переключение", other.ru(), po.unwrap_or(0))));
                out.actions.push(Action::Notify("failover".into(), format!("failover_{}", other.name()), String::new()));
                push_restart(&mut out);
            }
        } else {
            st.fastest_ok = 0;
        }
    }
    out
}

fn push_restart(out: &mut Out) {
    if !out.actions.contains(&Action::Restart) {
        out.actions.push(Action::Restart);
    }
}

// ---------- CLI ----------

fn kv(args: &[&str]) -> BTreeMap<String, String> {
    args.iter().filter_map(|a| a.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn parse(dir: &Path, args: &[&str], now: u64) -> (State, Obs, Cfg) {
    let m = kv(args);
    let b = |k: &str| m.get(k).is_some_and(|v| v == "1" || v == "ok");
    let n = |k: &str, d: u64| m.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let d = Cfg::default();
    let c = Cfg {
        watch_interval: n("watch_interval", d.watch_interval),
        watch_fails: n("watch_fails", d.watch_fails as u64) as u32,
        watch_gap: n("watch_gap", d.watch_gap),
        failover_after: n("failover_after", d.failover_after),
        failback_every: n("failback_every", d.failback_every),
        fastest_every: n("fastest_every", d.fastest_every),
        fastest_margin: n("fastest_margin", d.fastest_margin),
    };
    let endpoint = match std::fs::read_to_string(dir.join("endpoint")).unwrap_or_default().trim() {
        "backup" => Some(Ep::Backup),
        "primary" => Some(Ep::Primary),
        _ => None,
    };
    let ping = |k: &str| m.get(k).map(|v| v.parse::<u64>().ok());
    let o = Obs {
        now,
        connected: b("connected"),
        tun: b("tun"),
        backup: b("backup"),
        fastest: b("fastest"),
        endpoint,
        watch: m.get("watch").map(|v| v == "ok"),
        failback: m.get("failback").map(|v| v == "ok"),
        ping_primary: ping("ping_primary"),
        ping_backup: ping("ping_backup"),
    };
    let st = std::fs::read(dir.join("tunnel.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    (st, o, c)
}

fn save(dir: &Path, st: &State) -> Result<(), String> {
    crate::store::write_atomic(&dir.join("tunnel.json"), &serde_json::to_vec(st).map_err(|e| e.to_string())?)
}

/// `due` → строки с именами проб; `step` → строки действий. `now` — секунды (MI_TT_TEST_NOW в тестах).
pub fn cli(cmd: &str, dir: &str, args: &[&str], now: u64) -> Result<String, String> {
    let dir = Path::new(dir);
    let (mut st, o, c) = parse(dir, args, now);
    let text = match cmd {
        "due" => due(&mut st, &o, &c).iter().map(|s| format!("{s}\n")).collect(),
        "step" => {
            let r = step(&mut st, &o, &c);
            match r.endpoint {
                Some(e) if r.endpoint != o.endpoint => crate::store::write_atomic(&dir.join("endpoint"), format!("{}\n", e.name()).as_bytes())?,
                None if o.endpoint.is_some() => {
                    let _ = std::fs::remove_file(dir.join("endpoint"));
                }
                _ => {}
            }
            if let Some(w) = &r.watch_json {
                crate::store::write_atomic(&dir.join("watch.json"), w.as_bytes())?;
            }
            match &r.fastest_json {
                Some(Some(f)) => crate::store::write_atomic(&dir.join("fastest.json"), f.as_bytes())?,
                Some(None) => {
                    let _ = std::fs::remove_file(dir.join("fastest.json"));
                }
                None => {}
            }
            r.actions.iter().map(|a| format!("{}\n", a.line())).collect()
        }
        _ => return Err(format!("неизвестная команда tunnel {cmd}")),
    };
    save(dir, &st)?;
    Ok(text)
}

/// `mi-tt-ctl wait <мс> <условие>`: ждать условие с шагом 200 мс (BusyBox стока не умеет дробный sleep).
/// Условия: `tun-up <dev>` (поднят и с IPv4-адресом), `tun-gone <dev>`, `ok -- <команда…>` (команда завершилась с 0).
pub fn wait(ms: u64, cond: &[&str]) -> Result<bool, String> {
    let run = |prog: &str, args: &[&str]| -> Option<String> {
        let o = std::process::Command::new(prog).args(args).stderr(std::process::Stdio::null()).output().ok()?;
        o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let check: Box<dyn Fn() -> bool> = match cond {
        ["tun-up", dev] => {
            let dev = dev.to_string();
            Box::new(move || {
                run("ip", &["link", "show", &dev]).is_some_and(|l| l.contains(",UP") || l.contains("<UP"))
                    && run("ip", &["-4", "addr", "show", "dev", &dev]).is_some_and(|a| a.contains("inet "))
            })
        }
        ["tun-gone", dev] => {
            let dev = dev.to_string();
            Box::new(move || run("ip", &["link", "show", &dev]).is_none())
        }
        ["ok", "--", prog, rest @ ..] => {
            let prog = prog.to_string();
            let rest: Vec<String> = rest.iter().map(|s| s.to_string()).collect();
            Box::new(move || {
                let a: Vec<&str> = rest.iter().map(String::as_str).collect();
                std::process::Command::new(&prog).args(&a).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
            })
        }
        _ => return Err("условие: tun-up <dev> | tun-gone <dev> | ok -- <команда…>".into()),
    };
    let start = std::time::Instant::now();
    loop {
        if check() {
            return Ok(true);
        }
        if start.elapsed().as_millis() as u64 >= ms {
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(now: u64) -> Obs {
        Obs { now, connected: true, tun: true, ..Default::default() }
    }

    #[test]
    fn watchdog_restarts_after_three_fails_with_gap() {
        let (mut st, c) = (State::default(), Cfg { watch_interval: 0, ..Default::default() });
        let mut o = obs(1000);
        assert_eq!(due(&mut st, &o, &c), vec!["watch"]);
        o.watch = Some(true);
        let r = step(&mut st, &o, &c);
        assert!(r.actions.is_empty() && r.watch_json.unwrap().contains("\"ok\":true"));
        o.watch = Some(false);
        step(&mut st, &o, &c);
        let r = step(&mut st, &o, &c);
        assert!(r.actions.is_empty() && st.watch_fails == 2);
        let r = step(&mut st, &o, &c);
        assert!(r.actions.contains(&Action::Restart) && r.actions.iter().any(|a| matches!(a, Action::Log(t) if t.starts_with("сторож:"))));
        assert_eq!((st.watch_fails, st.watch_restart), (0, 1000));
        // повторный сбой раньше 5 минут — без перезапуска
        for _ in 0..4 {
            assert!(!step(&mut st, &o, &c).actions.contains(&Action::Restart));
        }
        o.now = 1300;
        assert!(step(&mut st, &o, &c).actions.contains(&Action::Restart));
    }

    #[test]
    fn watch_not_due_while_reconnecting_and_interval() {
        let (mut st, c) = (State { watch_fails: 2, ..Default::default() }, Cfg::default());
        let o = Obs { now: 100, connected: false, tun: true, ..Default::default() };
        assert!(due(&mut st, &o, &c).is_empty());
        assert_eq!(st.watch_fails, 0);
        let o = obs(110);
        assert!(due(&mut st, &o, &c).is_empty(), "интервал 60 с");
        assert_eq!(due(&mut st, &obs(160), &c), vec!["watch"]);
    }

    #[test]
    fn failover_and_failback() {
        let c = Cfg { failover_after: 120, failback_every: 0, ..Default::default() };
        let mut st = State::default();
        let mut o = Obs { now: 1000, connected: false, backup: true, ..Default::default() };
        assert!(step(&mut st, &o, &c).actions.is_empty());
        o.now = 1119;
        assert!(step(&mut st, &o, &c).actions.is_empty());
        o.now = 1120;
        let r = step(&mut st, &o, &c);
        assert_eq!(r.endpoint, Some(Ep::Backup));
        assert!(r.actions.contains(&Action::Restart) && r.actions.contains(&Action::Notify("failover".into(), "failover_backup".into(), String::new())));
        // на запасном и подключён: проба основного; два ответа подряд — возврат
        o = Obs { now: 1200, connected: true, backup: true, endpoint: Some(Ep::Backup), ..Default::default() };
        assert_eq!(due(&mut st, &o, &c), vec!["failback"]);
        o.failback = Some(true);
        assert_eq!(step(&mut st, &o, &c).endpoint, Some(Ep::Backup));
        o.failback = Some(false);
        step(&mut st, &o, &c);
        assert_eq!(st.failback_ok, 0, "неудача сбрасывает счёт");
        o.failback = Some(true);
        step(&mut st, &o, &c);
        let r = step(&mut st, &o, &c);
        assert_eq!(r.endpoint, Some(Ep::Primary));
        // запасной убран — состояние снято
        let r = step(&mut st, &Obs { now: 1300, backup: false, endpoint: Some(Ep::Backup), ..Default::default() }, &c);
        assert_eq!(r.endpoint, None);
    }

    #[test]
    fn fastest_switches_after_two_clear_wins() {
        let c = Cfg { fastest_every: 0, ..Default::default() };
        let mut st = State::default();
        let mut o = Obs { now: 1, connected: true, backup: true, fastest: true, ping_primary: Some(Some(120)), ping_backup: Some(Some(40)), ..Default::default() };
        assert_eq!(due(&mut st, &o, &c), vec!["fastest"], "при выборе по задержке failback не делается");
        assert!(step(&mut st, &o, &c).actions.is_empty());
        let r = step(&mut st, &o, &c);
        assert_eq!(r.endpoint, Some(Ep::Backup));
        assert!(r.fastest_json.unwrap().unwrap().contains("\"primary\":120"));
        // разница меньше порога — без переключения
        let mut st = State::default();
        o.ping_primary = Some(Some(50));
        for _ in 0..3 {
            assert!(step(&mut st, &o, &c).actions.is_empty());
        }
        // текущий не ответил на замер — тоже повод
        o.ping_primary = Some(None);
        step(&mut st, &o, &c);
        assert_eq!(step(&mut st, &o, &c).endpoint, Some(Ep::Backup));
    }
}
