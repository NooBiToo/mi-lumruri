//! Статистика трафика: через VPN (счётчики интерфейса туннеля), весь интернет (счётчики WAN) и по устройствам
//! (штатный trafficd прошивки: `ubus call trafficd ip`, байты по IP). Служба раз в несколько минут передаёт
//! показания `mi-tt-ctl stats-sample`; приращения складываются по часам, хранятся последние 7 суток.
//! Счётчики интерфейсов обнуляются при перезапуске клиента и перезагрузке — приращение тогда равно новому значению.
//! Сеть не меняется: только чтение счётчиков.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::{Response, read_limited};
use crate::manage::{leases_path, read_config, run_dir};
use crate::validate::normalize_mac;

pub const KEEP_SECS: u64 = 7 * 86_400;
/// Устройств в одном часе — не больше (защита от мусора в ответе trafficd).
const MAX_DEVICES: usize = 256;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct Raw {
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan: Option<u64>,
    #[serde(default)]
    pub dev: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hour {
    /// Начало часа (unix).
    pub t: u64,
    pub vpn: u64,
    pub wan: u64,
    #[serde(default)]
    pub dev: BTreeMap<String, u64>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct Stats {
    #[serde(default)]
    pub last: Raw,
    #[serde(default)]
    pub hours: Vec<Hour>,
}

fn delta(cur: u64, prev: Option<u64>) -> u64 {
    match prev {
        Some(p) if cur >= p => cur - p,
        // счётчик обнулился (перезапуск клиента, перезагрузка) или первое показание после него
        Some(_) => cur,
        None => 0,
    }
}

/// Новое показание: приращения с прошлого — в час `now`. Первое показание только запоминается.
pub fn sample(st: &mut Stats, now: u64, vpn: Option<u64>, wan: Option<u64>, dev: BTreeMap<String, u64>) -> Hour {
    let mut out = Hour { t: now / 3600 * 3600, ..Default::default() };
    let first = st.last.at == 0;
    // показание старше прошлого (часы роутера ушли назад) или пауза больше суток — без приращений
    let stale = !first && (now < st.last.at || now - st.last.at > 86_400);
    if !first && !stale {
        let t = now / 3600 * 3600;
        if st.hours.last().is_none_or(|h| h.t != t) {
            st.hours.push(Hour { t, ..Default::default() });
        }
        let h = st.hours.last_mut().expect("час добавлен выше");
        if let Some(v) = vpn {
            out.vpn = delta(v, st.last.vpn);
            h.vpn += out.vpn;
        }
        if let Some(w) = wan {
            out.wan = delta(w, st.last.wan);
            h.wan += out.wan;
        }
        for (k, v) in &dev {
            if h.dev.len() >= MAX_DEVICES && !h.dev.contains_key(k) {
                continue;
            }
            let d = delta(*v, st.last.dev.get(k).copied());
            *h.dev.entry(k.clone()).or_default() += d;
            out.dev.insert(k.clone(), d);
        }
    }
    st.hours.retain(|h| h.t + KEEP_SECS > now);
    st.last = Raw { at: now, vpn, wan, dev };
    out
}

/// Байты по устройствам из ответа trafficd: объекты с rx_bytes и tx_bytes; ключ — поле ip или ключ объекта (IPv4).
pub fn parse_trafficd(v: &Value) -> BTreeMap<String, u64> {
    fn walk(v: &Value, key: Option<&str>, out: &mut BTreeMap<String, u64>) {
        match v {
            Value::Object(m) => {
                let rx = m.get("rx_bytes").and_then(num);
                let tx = m.get("tx_bytes").and_then(num);
                let ip = m.get("ip").and_then(Value::as_str).or(key).filter(|s| s.parse::<std::net::Ipv4Addr>().is_ok());
                if let (Some(rx), Some(tx), Some(ip)) = (rx, tx, ip) {
                    *out.entry(ip.to_string()).or_default() += rx.saturating_add(tx);
                    return;
                }
                for (k, x) in m {
                    walk(x, Some(k), out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, None, out)),
            _ => {}
        }
    }
    fn num(v: &Value) -> Option<u64> {
        v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).or_else(|| v.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
    }
    let mut out = BTreeMap::new();
    walk(v, None, &mut out);
    out
}

/// IP → MAC по арендам DHCP (устройство узнаётся и после смены адреса).
pub fn ip_to_mac(leases: &str) -> BTreeMap<String, String> {
    leases
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let mac = normalize_mac(f.get(1)?).ok()?;
            let ip = f.get(2)?.parse::<std::net::Ipv4Addr>().ok()?;
            Some((ip.to_string(), mac))
        })
        .collect()
}

pub fn load(p: &std::path::Path) -> Stats {
    read_limited(&p.to_string_lossy(), 4 * 1024 * 1024).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// `mi-tt-ctl stats-sample <stats.json> <vpn|-> <wan|-> [trafficd.json]`
pub fn sample_cmd(path: &str, vpn: &str, wan: &str, trafficd: Option<&str>, now: u64) -> Result<(), String> {
    let p = std::path::Path::new(path);
    let mut st = load(p);
    let n = |s: &str| s.trim().parse::<u64>().ok();
    let macs = ip_to_mac(&String::from_utf8_lossy(&read_limited(&leases_path().to_string_lossy(), 1024 * 1024).unwrap_or_default()));
    let dev = trafficd
        .and_then(|f| read_limited(f, 2 * 1024 * 1024).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .map(|v| parse_trafficd(&v))
        .unwrap_or_default()
        .into_iter()
        .map(|(ip, b)| (macs.get(&ip).cloned().unwrap_or(ip), b))
        .fold(BTreeMap::new(), |mut m: BTreeMap<String, u64>, (k, b)| {
            *m.entry(k).or_default() += b;
            m
        });
    let d = sample(&mut st, now, n(vpn), n(wan), dev);
    let b = serde_json::to_vec(&st).map_err(|e| e.to_string())?;
    crate::store::write_atomic(p, &b)?;
    // журнал трафика по дням (служба: MI_TT_HISTORY — файл, MI_TT_HISTORY_MONTHS, MI_TT_UTC_OFFSET — секунды)
    if let Some(hf) = std::env::var("MI_TT_HISTORY").ok().filter(|s| !s.is_empty()) {
        let months = std::env::var("MI_TT_HISTORY_MONTHS").ok().and_then(|s| s.parse::<u8>().ok()).unwrap_or(1);
        let offset = std::env::var("MI_TT_UTC_OFFSET").ok().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
        let hp = std::path::Path::new(&hf);
        let mut j = crate::history::load(hp);
        crate::history::add(&mut j, now, offset, &d, months);
        if let Some(dir) = hp.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        crate::store::write_atomic(hp, &serde_json::to_vec(&j).map_err(|e| e.to_string())?)?;
    }
    Ok(())
}

fn sum(h: &[&Hour], f: impl Fn(&Hour) -> u64) -> u64 {
    h.iter().map(|x| f(x)).sum()
}

/// GET /stats: итоги за сутки и неделю, по часам за сутки, по устройствам (имя из настроек или аренды).
pub fn get(config_path: &str) -> Response {
    let st = load(&run_dir().join("stats.json"));
    let now = crate::auth::now();
    let day: Vec<&Hour> = st.hours.iter().filter(|h| h.t + 86_400 > now).collect();
    let week: Vec<&Hour> = st.hours.iter().collect();
    let cfg = read_config(config_path).ok();
    // имя устройства — как на экране «Устройства»: ваше переименование, устройство из настроек, имя, найденное в сети
    // (mDNS/SSDP), затем имя при подключении (DHCP) и производитель по MAC
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let extra = crate::devices::Extra::load();
    for (mac, f) in &extra.names {
        if !f.name.trim().is_empty() {
            names.insert(mac.clone(), f.name.clone());
        }
    }
    for d in cfg.iter().flat_map(|c| c.devices.iter()) {
        if let Ok(m) = normalize_mac(&d.mac) {
            names.insert(m, d.name.clone());
        }
    }
    for (mac, n) in cfg.iter().flat_map(|c| c.device_names.iter()) {
        if let Ok(m) = normalize_mac(mac) {
            names.insert(m, n.clone());
        }
    }
    let leases = String::from_utf8_lossy(&read_limited(&leases_path().to_string_lossy(), 1024 * 1024).unwrap_or_default()).into_owned();
    let hosts: BTreeMap<String, String> = leases
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let mac = normalize_mac(f.get(1)?).ok()?;
            let h = f.get(3).filter(|h| **h != "*")?;
            Some((mac, h.chars().filter(|c| !c.is_control()).take(64).collect()))
        })
        .collect();
    let mut keys: Vec<&String> = week.iter().flat_map(|h| h.dev.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut devices: Vec<Value> = keys
        .into_iter()
        .map(|k| {
            let d = sum(&day, |h| h.dev.get(k).copied().unwrap_or(0));
            let w = sum(&week, |h| h.dev.get(k).copied().unwrap_or(0));
            let vendor = extra.oui.get(k.get(0..8).unwrap_or("")).map(|(v, _)| v.clone()).filter(|v| !v.is_empty());
            json!({ "key": k, "name": names.get(k).or(hosts.get(k)), "vendor": vendor, "known": names.contains_key(k), "day": d, "week": w })
        })
        .collect();
    devices.sort_by(|a, b| b["week"].as_u64().cmp(&a["week"].as_u64()));
    // журнал по дням, если включён: итоги по дням и по устройствам за 30, 90 и 365 дней
    let history = cfg.as_ref().and_then(|c| c.history.as_ref()).map(|h| {
        let j = crate::history::load(std::path::Path::new(&crate::history::file_for(&h.target)));
        let (days, dev) = crate::history::view(&j, now);
        let mut devs: Vec<Value> = dev.iter().map(|(k, v)| {
            let vendor = extra.oui.get(k.get(0..8).unwrap_or("")).map(|(x, _)| x.clone()).filter(|x| !x.is_empty());
            json!({ "key": k, "name": names.get(k).or(hosts.get(k)), "vendor": vendor, "month": v[0], "quarter": v[1], "year": v[2] })
        }).collect();
        devs.sort_by(|a, b| b["year"].as_u64().cmp(&a["year"].as_u64()));
        json!({ "months": h.months, "target": h.target, "days": days.iter().map(|(t, v, w)| json!({ "t": t, "vpn": v, "wan": w })).collect::<Vec<_>>(), "devices": devs })
    });
    Response {
        status: 200,
        body: json!({
            "ok": true, "since": st.hours.first().map(|h| h.t), "sampled": (st.last.at > 0).then_some(st.last.at),
            "per_device": !st.last.dev.is_empty() || !devices.is_empty(),
            "vpn": { "day": sum(&day, |h| h.vpn), "week": sum(&week, |h| h.vpn) },
            "wan": { "day": sum(&day, |h| h.wan), "week": sum(&week, |h| h.wan) },
            "hours": day.iter().map(|h| json!({ "t": h.t, "vpn": h.vpn, "wan": h.wan })).collect::<Vec<_>>(),
            "devices": devices, "history": history, "issues": [],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(v: &[(&str, u64)]) -> BTreeMap<String, u64> {
        v.iter().map(|(k, b)| (k.to_string(), *b)).collect()
    }

    #[test]
    fn deltas_resets_and_hours() {
        let mut s = Stats::default();
        let t0 = 1_800_000_000 / 3600 * 3600;
        sample(&mut s, t0 + 10, Some(1000), Some(5000), dev(&[("aa", 100)]));
        assert!(s.hours.is_empty(), "первое показание только запоминается");
        sample(&mut s, t0 + 310, Some(1500), Some(7000), dev(&[("aa", 400), ("bb", 50)]));
        assert_eq!(s.hours, vec![Hour { t: t0, vpn: 500, wan: 2000, dev: dev(&[("aa", 300), ("bb", 0)]) }]);
        // клиент перезапущен: счётчик туннеля обнулился — приращение = новое значение
        sample(&mut s, t0 + 3700, Some(200), Some(9000), dev(&[("aa", 500), ("bb", 80)]));
        assert_eq!(s.hours.len(), 2);
        assert_eq!((s.hours[1].vpn, s.hours[1].wan, s.hours[1].dev["aa"], s.hours[1].dev["bb"]), (200, 2000, 100, 30));
        // туннеля нет — его счётчик не учитывается
        sample(&mut s, t0 + 4000, None, Some(9100), dev(&[]));
        assert_eq!((s.hours[1].vpn, s.hours[1].wan), (200, 2100));
        // пауза больше суток — без приращений; старше 7 суток — удаляется
        sample(&mut s, t0 + 8 * 86_400, Some(10), Some(10), dev(&[]));
        assert!(s.hours.is_empty());
    }

    #[test]
    fn trafficd_shapes() {
        let a = json!({ "192.168.31.10": { "hw": "AA:BB:CC:DD:EE:01", "rx_bytes": 100, "tx_bytes": 20 }, "192.168.31.11": { "rx_bytes": "5", "tx_bytes": "6" } });
        assert_eq!(parse_trafficd(&a), dev(&[("192.168.31.10", 120), ("192.168.31.11", 11)]));
        let b = json!({ "list": [ { "ip": "10.0.0.2", "rx_bytes": 1, "tx_bytes": 2 }, { "ip": "fe80::1", "rx_bytes": 9, "tx_bytes": 9 } ] });
        assert_eq!(parse_trafficd(&b), dev(&[("10.0.0.2", 3)]));
        assert!(parse_trafficd(&json!({ "x": 1 })).is_empty());
    }

    #[test]
    fn leases_map() {
        let m = ip_to_mac("1700000000 aa:bb:cc:dd:ee:01 192.168.31.10 tv *\nbad line\n");
        assert_eq!(m.get("192.168.31.10").map(String::as_str), Some("aa:bb:cc:dd:ee:01"));
    }
}
