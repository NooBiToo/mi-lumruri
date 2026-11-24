//! Журнал трафика: итоги по дням (весь интернет, через VPN, по устройствам) за 1–24 месяца — для динамики на
//! «Обзоре». Включается в настройках (`Config.history`): срок и накопитель (флешка или внутренняя память). Служба при
//! каждом показании статистики (`stats-sample`) добавляет приращения в день по местному времени роутера; файл —
//! `<накопитель>/mi-lumruri-history/traffic-days.json` (флешка) или `<данные пакета>/history/traffic-days.json`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::stats::Hour;

/// День: `t` — начало дня по местному времени (unix), поля — как у часа статистики.
pub type Day = Hour;

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct Journal {
    #[serde(default)]
    pub days: Vec<Day>,
}

/// Устройств в одном дне — не больше.
const MAX_DEVICES: usize = 256;

/// Файл журнала для накопителя `target` (путь из GET /storage): внутренняя память — путь пакета на /data.
pub fn file_for(target: &str) -> String {
    let t = target.trim_end_matches('/');
    if t.starts_with("/data") { format!("{t}/history/traffic-days.json") } else { format!("{t}/mi-lumruri-history/traffic-days.json") }
}

pub fn load(p: &Path) -> Journal {
    crate::api::read_limited(&p.to_string_lossy(), 16 * 1024 * 1024).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Приращения одного показания — в день `now` (смещение местного времени `offset` секунд); старше `months` — убрать.
pub fn add(j: &mut Journal, now: u64, offset: i64, delta: &Hour, months: u8) {
    let local = now as i64 + offset;
    let t = (local - local.rem_euclid(86_400) - offset).max(0) as u64;
    if delta.vpn > 0 || delta.wan > 0 || !delta.dev.is_empty() {
        if j.days.last().is_none_or(|d| d.t != t) {
            j.days.push(Day { t, ..Default::default() });
            j.days.sort_by_key(|d| d.t);
        }
        let d = j.days.iter_mut().find(|d| d.t == t).expect("день добавлен выше");
        d.vpn += delta.vpn;
        d.wan += delta.wan;
        for (k, v) in &delta.dev {
            if *v == 0 || (d.dev.len() >= MAX_DEVICES && !d.dev.contains_key(k)) {
                continue;
            }
            *d.dev.entry(k.clone()).or_default() += v;
        }
    }
    let keep = u64::from(months.clamp(1, 24)) * 31 * 86_400;
    j.days.retain(|d| d.t + keep > now);
}

/// Итоги журнала для панели: по дням (без устройств) и по устройствам за 30, 90 и 365 дней.
pub fn view(j: &Journal, now: u64) -> (Vec<(u64, u64, u64)>, BTreeMap<String, [u64; 3]>) {
    let days = j.days.iter().map(|d| (d.t, d.vpn, d.wan)).collect();
    let mut dev: BTreeMap<String, [u64; 3]> = BTreeMap::new();
    for d in &j.days {
        for (i, span) in [30u64, 90, 365].iter().enumerate() {
            if d.t + span * 86_400 > now {
                for (k, v) in &d.dev {
                    dev.entry(k.clone()).or_default()[i] += v;
                }
            }
        }
    }
    (days, dev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(vpn: u64, wan: u64, dev: &[(&str, u64)]) -> Hour {
        Hour { t: 0, vpn, wan, dev: dev.iter().map(|(k, v)| (k.to_string(), *v)).collect() }
    }

    #[test]
    fn days_local_time_and_retention() {
        let mut j = Journal::default();
        let day0 = 20_000 * 86_400u64; // полночь UTC
        // 23:30 UTC = 02:30 MSK следующего дня
        add(&mut j, day0 + 23 * 3600 + 1800, 3 * 3600, &h(10, 100, &[("aa", 5)]), 3);
        add(&mut j, day0 + 12 * 3600, 3 * 3600, &h(1, 2, &[("aa", 1), ("bb", 0)]), 3);
        assert_eq!(j.days.len(), 2);
        assert_eq!(j.days[0].t, day0 - 3 * 3600);
        assert_eq!(j.days[1].t, day0 + 86_400 - 3 * 3600);
        assert_eq!((j.days[1].vpn, j.days[1].wan, j.days[1].dev["aa"]), (10, 100, 5));
        assert!(!j.days[0].dev.contains_key("bb"));
        // через 100 дней при сроке 3 месяца (93 дня) старые дни убраны
        add(&mut j, day0 + 100 * 86_400, 0, &h(1, 1, &[]), 3);
        assert_eq!(j.days.len(), 1);
        let (days, dev) = view(&j, day0 + 100 * 86_400);
        assert_eq!(days.len(), 1);
        assert!(dev.is_empty());
        assert_eq!(file_for("/mnt/usb-1a/"), "/mnt/usb-1a/mi-lumruri-history/traffic-days.json");
        assert_eq!(file_for("/data/mi-lumruri"), "/data/mi-lumruri/history/traffic-days.json");
    }
}
