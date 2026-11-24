//! Состояние роутера для панели (`GET /health`): загрузка процессора, память, температура, время работы, соединения
//! и счётчики байт WAN и туннелей (скорость считает панель по двум ответам). Только чтение /proc и /sys; корни
//! подменяются `MI_TT_PROC` и `MI_TT_SYS` (тесты, лаборатория).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::api::Response;

fn root(env: &str, def: &str) -> PathBuf {
    PathBuf::from(std::env::var(env).ok().filter(|s| !s.is_empty()).unwrap_or_else(|| def.into()))
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Суммы времени процессора из строки `cpu…` /proc/stat: (всего, простой).
pub fn cpu_times(stat: &str) -> Vec<(String, u64, u64)> {
    stat.lines()
        .filter(|l| l.starts_with("cpu"))
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let n: Vec<u64> = f.get(1..)?.iter().take(8).filter_map(|x| x.parse().ok()).collect();
            if n.len() < 4 {
                return None;
            }
            let idle = n[3] + n.get(4).copied().unwrap_or(0);
            Some((f[0].to_string(), n.iter().sum(), idle))
        })
        .collect()
}

/// Загрузка в процентах между двумя снимками /proc/stat: всего и по ядрам.
pub fn cpu_load(a: &str, b: &str) -> (Option<f64>, Vec<f64>) {
    let (x, y) = (cpu_times(a), cpu_times(b));
    let pct = |name: &str| {
        let (_, t0, i0) = x.iter().find(|c| c.0 == name)?;
        let (_, t1, i1) = y.iter().find(|c| c.0 == name)?;
        let (dt, di) = (t1.saturating_sub(*t0), i1.saturating_sub(*i0));
        (dt > 0).then(|| ((dt - di.min(dt)) as f64 / dt as f64 * 1000.0).round() / 10.0)
    };
    let cores = y.iter().filter(|c| c.0 != "cpu").filter_map(|c| pct(&c.0)).collect();
    (pct("cpu"), cores)
}

/// /proc/meminfo → (всего, доступно) в байтах.
pub fn mem(meminfo: &str) -> Option<(u64, u64)> {
    let kb = |k: &str| meminfo.lines().find(|l| l.starts_with(k)).and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u64>().ok());
    let total = kb("MemTotal:")?;
    let avail = kb("MemAvailable:").or_else(|| Some(kb("MemFree:")? + kb("Buffers:").unwrap_or(0) + kb("Cached:").unwrap_or(0)))?;
    Some((total * 1024, avail.min(total) * 1024))
}

/// Интерфейс маршрута по умолчанию из /proc/net/route.
pub fn wan_dev(route: &str) -> Option<String> {
    route.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.get(1) == Some(&"00000000") && f.get(7) == Some(&"00000000")).then(|| f[0].to_string())
    })
}

/// Датчики температуры: thermal_zone*/{type,temp} (милли°C) — (имя, °C), правдоподобные значения.
pub fn temps(sys: &Path) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(sys.join("class/thermal")) else { return out };
    let mut zones: Vec<PathBuf> = rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("thermal_zone"))).collect();
    zones.sort();
    for z in zones.into_iter().take(16) {
        let Ok(v) = read(&z.join("temp")).trim().parse::<i64>() else { continue };
        let c = if v.abs() > 1000 { v as f64 / 1000.0 } else { v as f64 };
        if !(-40.0..=150.0).contains(&c) {
            continue;
        }
        let name: String = read(&z.join("type")).trim().chars().filter(|c| !c.is_control()).take(32).collect();
        out.push((if name.is_empty() { z.file_name().unwrap_or_default().to_string_lossy().into_owned() } else { name }, (c * 10.0).round() / 10.0));
    }
    out
}

fn if_bytes(sys: &Path, dev: &str) -> Option<(u64, u64)> {
    let d = sys.join("class/net").join(dev).join("statistics");
    Some((read(&d.join("rx_bytes")).trim().parse().ok()?, read(&d.join("tx_bytes")).trim().parse().ok()?))
}

/// `GET /health`. Загрузка процессора — по двум снимкам /proc/stat через 0,3 с.
pub fn get() -> Response {
    let proc_ = root("MI_TT_PROC", "/proc");
    let sys = root("MI_TT_SYS", "/sys");
    let s0 = read(&proc_.join("stat"));
    std::thread::sleep(std::time::Duration::from_millis(300));
    let s1 = read(&proc_.join("stat"));
    let (cpu, cores) = cpu_load(&s0, &s1);
    let load: Vec<f64> = read(&proc_.join("loadavg")).split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
    let uptime = read(&proc_.join("uptime")).split_whitespace().next().and_then(|x| x.parse::<f64>().ok()).map(|x| x as u64);
    let m = mem(&read(&proc_.join("meminfo")));
    let ct = read(&proc_.join("sys/net/netfilter/nf_conntrack_count")).trim().parse::<u64>().ok();
    let ct_max = read(&proc_.join("sys/net/netfilter/nf_conntrack_max")).trim().parse::<u64>().ok();
    let wan = wan_dev(&read(&proc_.join("net/route")));
    let (mut vrx, mut vtx, mut tuns) = (0u64, 0u64, 0usize);
    if let Ok(rd) = std::fs::read_dir(sys.join("class/net")) {
        for e in rd.filter_map(|e| e.ok()) {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("mitt") && n[4..].bytes().all(|c| c.is_ascii_digit()) {
                if let Some((r, t)) = if_bytes(&sys, &n) {
                    vrx += r;
                    vtx += t;
                    tuns += 1;
                }
            }
        }
    }
    let wb = wan.as_deref().and_then(|d| if_bytes(&sys, d));
    let ts: Vec<Value> = temps(&sys).into_iter().map(|(n, c)| json!({ "name": n, "c": c })).collect();
    let at_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    Response {
        status: 200,
        body: json!({
            "ok": true, "at_ms": at_ms,
            "cpu": cpu, "cores": cores, "load": load, "uptime": uptime,
            "mem": m.map(|(t, a)| json!({ "total": t, "available": a })),
            "temps": ts,
            "conntrack": ct.map(|c| json!({ "count": c, "max": ct_max })),
            "net": {
                "wan": wb.map(|(r, t)| json!({ "dev": wan, "rx": r, "tx": t })),
                "vpn": (tuns > 0).then(|| json!({ "rx": vrx, "tx": vtx, "tunnels": tuns })),
            },
            "issues": [],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_mem_route() {
        let a = "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0\ncpu1 50 0 50 400 0 0 0 0\nintr 1\n";
        let b = "cpu  200 0 200 1000 0 0 0 0 0 0\ncpu0 150 0 50 400 0 0 0 0\ncpu1 50 0 150 600 0 0 0 0\n";
        let (c, cores) = cpu_load(a, b);
        assert_eq!(c, Some(50.0));
        assert_eq!(cores, vec![100.0, 33.3]);
        assert_eq!(mem("MemTotal:  1000 kB\nMemFree: 100 kB\nMemAvailable:  400 kB\n"), Some((1_024_000, 409_600)));
        assert_eq!(mem("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 150 kB\n"), Some((1_024_000, 307_200)));
        let route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nbr-lan\t001FA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\neth4\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\n";
        assert_eq!(wan_dev(route).as_deref(), Some("eth4"));
    }

    #[test]
    fn thermal() {
        let d = std::env::temp_dir().join(format!("mitt-th-{}", std::process::id()));
        for (z, ty, t) in [("thermal_zone0", "cpu-thermal", "54321"), ("thermal_zone1", "", "48"), ("thermal_zone2", "bad", "999999")] {
            std::fs::create_dir_all(d.join("class/thermal").join(z)).unwrap();
            std::fs::write(d.join("class/thermal").join(z).join("type"), ty).unwrap();
            std::fs::write(d.join("class/thermal").join(z).join("temp"), t).unwrap();
        }
        assert_eq!(temps(&d), vec![("cpu-thermal".to_string(), 54.3), ("thermal_zone1".to_string(), 48.0)]);
        let _ = std::fs::remove_dir_all(d);
    }
}
