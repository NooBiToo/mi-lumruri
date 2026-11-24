//! Накопители роутера: внутренняя память `/data` и подключённые USB-накопители (флешки, диски). Только разбор:
//! служба раз в минуту отдаёт `/proc/mounts` и вывод `df -k` (`mi-tt-ctl storage-scan`), итог — `$STATE/storage.json`,
//! панель читает его через `GET /storage`. Модули (0.11) ставятся на `/data` или на накопитель с местом.
//!
//! Прошивка монтирует USB в `/mnt/usb-XXXX` (или `/extdisks/sdXN`); файловая система — FAT/exFAT/NTFS/ext4.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

/// Строка `/proc/mounts`, относящаяся к USB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    pub path: String,
    pub fs: String,
    pub opts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Storage {
    pub path: String,
    pub device: String,
    pub fs: String,
    /// Байты.
    pub total: u64,
    pub free: u64,
    pub writable: bool,
    /// Можно ли запускать программы прямо с накопителя (без `noexec`; на FAT модули всё равно копируются в RAM).
    pub exec: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// `\040` и подобные восьмеричные escape в путях `/proc/mounts`.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// USB-накопители из `/proc/mounts`: блочные `/dev/sd*` под `/mnt/` или `/extdisks/`.
pub fn parse_mounts(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (dev, path, fs, opts) = (f.first()?, unescape(f.get(1)?), f.get(2)?, f.get(3)?);
            let usb_dev = dev.starts_with("/dev/sd");
            let usb_path = path.starts_with("/mnt/") || path.starts_with("/extdisks/");
            (usb_dev && usb_path).then(|| Mount { device: dev.to_string(), path, fs: fs.to_string(), opts: opts.split(',').map(String::from).collect() })
        })
        .collect()
}

/// `df -k` (BusyBox и GNU): точка монтирования → (всего, свободно) в байтах. Длинное имя устройства GNU переносит на
/// отдельную строку; точка монтирования — всё после пятого поля (в ней бывают пробелы).
pub fn parse_df(text: &str) -> BTreeMap<String, (u64, u64)> {
    let mut out = BTreeMap::new();
    let mut carry: Vec<String> = Vec::new();
    for l in text.lines().skip(1) {
        let mut f: Vec<String> = carry.drain(..).collect();
        f.extend(l.split_whitespace().map(String::from));
        if f.len() < 6 {
            carry = f;
            continue;
        }
        let (Ok(total), Ok(avail)) = (f[1].parse::<u64>(), f[3].parse::<u64>()) else { continue };
        out.insert(f[5..].join(" "), (total * 1024, avail * 1024));
    }
    out
}

/// Самая длинная точка монтирования из df, содержащая путь.
fn df_for<'a>(df: &'a BTreeMap<String, (u64, u64)>, path: &str) -> Option<&'a (u64, u64)> {
    df.iter()
        .filter(|(m, _)| path == m.as_str() || m.as_str() == "/" || path.starts_with(&format!("{}/", m.trim_end_matches('/'))))
        .max_by_key(|(m, _)| m.len())
        .map(|(_, v)| v)
}

fn sys_attr(sys: &Path, device: &str, attr: &str) -> Option<String> {
    // /dev/sda1 → sda
    let name = device.trim_start_matches("/dev/");
    let disk: String = name.trim_end_matches(|c: char| c.is_ascii_digit()).to_string();
    let v = std::fs::read_to_string(sys.join("block").join(disk).join("device").join(attr)).ok()?;
    let v: String = v.trim().chars().filter(|c| !c.is_control()).take(64).collect();
    (!v.is_empty()).then_some(v)
}

/// Итог для панели: `{"at": …, "data": Storage|null, "usb": [Storage]}`.
pub fn scan(mounts: &str, df: &str, sys: &Path, data_path: &str, now: u64) -> Value {
    let df = parse_df(df);
    let data = df_for(&df, data_path).map(|(t, f)| Storage {
        path: data_path.into(),
        device: String::new(),
        fs: String::new(),
        total: *t,
        free: *f,
        writable: true,
        exec: true,
        vendor: None,
        model: None,
    });
    let usb: Vec<Storage> = parse_mounts(mounts)
        .into_iter()
        .filter_map(|m| {
            let (t, f) = df.get(&m.path)?;
            Some(Storage {
                writable: !m.opts.iter().any(|o| o == "ro"),
                exec: !m.opts.iter().any(|o| o == "noexec"),
                vendor: sys_attr(sys, &m.device, "vendor"),
                model: sys_attr(sys, &m.device, "model"),
                path: m.path,
                device: m.device,
                fs: m.fs,
                total: *t,
                free: *f,
            })
        })
        .collect();
    json!({ "at": now, "data": data, "usb": usb })
}

/// `mi-tt-ctl storage-scan <mounts> <df> <out>`: `MI_TT_SYS` — корень sysfs (лаборатория), `MI_TT_DATA` — путь
/// внутренней памяти пакета (по умолчанию /data).
pub fn scan_cmd(mounts: &str, df: &str, out: &str, now: u64) -> Result<(), String> {
    let rd = |p: &str| std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"));
    let sys = std::env::var("MI_TT_SYS").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/sys".into());
    let data = std::env::var("MI_TT_DATA").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| "/data".into());
    let v = scan(&rd(mounts)?, &rd(df)?, Path::new(&sys), &data, now);
    crate::store::write_atomic(Path::new(out), format!("{v}\n").as_bytes())
}

/// `GET /storage`: последний итог службы; служба ещё не сканировала — пустой список.
pub fn get() -> crate::api::Response {
    let p = crate::manage::run_dir().join("storage.json");
    let v: Value = std::fs::read(&p).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_else(|| json!({ "at": null, "data": null, "usb": [] }));
    crate::api::Response { status: 200, body: json!({ "ok": true, "storage": v, "issues": [] }) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &str = "ubi0_1 /data ubifs rw,relatime 0 0\n\
/dev/sda1 /mnt/usb-1a2b vfat rw,relatime,fmask=0022,dmask=0022 0 0\n\
/dev/sdb1 /mnt/usb\\040disk ntfs3 ro,noexec 0 0\n\
/dev/sdc1 /extdisks/sdc1 ext4 rw 0 0\n\
/dev/mmcblk0p1 /mnt/sd vfat rw 0 0\n\
tmpfs /tmp tmpfs rw 0 0\n";

    const DF: &str = "Filesystem           1K-blocks      Used Available Use% Mounted on\n\
ubi0_1                   40000     22000     18000  55% /data\n\
/dev/sda1             15000000   1000000  14000000   7% /mnt/usb-1a2b\n\
/dev/sdb1                 2000      1000      1000  50% /mnt/usb disk\n\
/dev/very-long-device-name-that-wraps\n\
                         5000      1000      4000  20% /extdisks/sdc1\n";

    #[test]
    fn mounts_only_usb_and_unescaped() {
        let m = parse_mounts(MOUNTS);
        assert_eq!(m.iter().map(|x| x.path.as_str()).collect::<Vec<_>>(), ["/mnt/usb-1a2b", "/mnt/usb disk", "/extdisks/sdc1"]);
        assert_eq!(m[1].fs, "ntfs3");
        assert!(m[1].opts.contains(&"noexec".to_string()));
    }

    #[test]
    fn df_wrapped_and_spaces() {
        let d = parse_df(DF);
        assert_eq!(d["/data"], (40000 * 1024, 18000 * 1024));
        assert_eq!(d["/mnt/usb disk"], (2000 * 1024, 1000 * 1024));
        assert_eq!(d["/extdisks/sdc1"], (5000 * 1024, 4000 * 1024));
    }

    #[test]
    fn scan_flags_and_sys_attrs() {
        let sys = std::env::temp_dir().join(format!("mitt-sys-{}", std::process::id()));
        std::fs::create_dir_all(sys.join("block/sda/device")).unwrap();
        std::fs::write(sys.join("block/sda/device/vendor"), "SanDisk \n").unwrap();
        std::fs::write(sys.join("block/sda/device/model"), "Ultra Fit\n").unwrap();
        let v = scan(MOUNTS, DF, &sys, "/data", 7);
        assert_eq!(v["data"]["free"], 18000 * 1024);
        let u = v["usb"].as_array().unwrap();
        assert_eq!(u.len(), 3);
        assert_eq!((u[0]["vendor"].as_str(), u[0]["model"].as_str(), u[0]["writable"].as_bool(), u[0]["exec"].as_bool()), (Some("SanDisk"), Some("Ultra Fit"), Some(true), Some(true)));
        assert_eq!((u[1]["writable"].as_bool(), u[1]["exec"].as_bool()), (Some(false), Some(false)));
        assert!(u[1].get("vendor").is_none());
        // /data не отдельная точка монтирования — по корню
        let v = scan("", "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/root 100 50 50 50% /\n", &sys, "/data", 7);
        assert_eq!(v["data"]["total"], 100 * 1024);
        let _ = std::fs::remove_dir_all(sys);
    }
}
