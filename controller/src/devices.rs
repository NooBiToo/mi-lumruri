//! Сведения об устройствах LAN для экрана «Устройства»: производитель по MAC (таблица OUI прошивки Xiaomi —
//! служба распаковывает /usr/share/xiaoqiang/oui.tar.gz в `oui.txt`), случайный (приватный) MAC, подключение по
//! данным штатного trafficd (`trafficd-hw.json`: ubus call trafficd hw) и имена, которые устройства сами объявили
//! в сети (`names.json`, см. discover). Всё — только чтение файлов каталога службы.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::api::read_limited;
use crate::discover::{Found, Names, clean};
use crate::manage::run_dir;
use crate::validate::normalize_mac;

/// Таблица OUI: «3C-D9-2B Hewlett Packard ICON:device_list_hp.png» → «3c:d9:2b» → (производитель, значок).
pub fn parse_oui(text: &str) -> BTreeMap<String, (String, String)> {
    text.lines()
        .take(20_000)
        .filter_map(|l| {
            let (pfx, rest) = l.trim().split_once(char::is_whitespace)?;
            let key = pfx.replace('-', ":").to_ascii_lowercase();
            if key.len() != 8 || !key.split(':').all(|h| h.len() == 2 && h.bytes().all(|b| b.is_ascii_hexdigit())) {
                return None;
            }
            let (name, icon) = rest.split_once("ICON:").map_or((rest, ""), |(n, i)| (n, i));
            let icon = icon.trim().trim_start_matches("device_list_").trim_end_matches(".png");
            Some((key, (clean(name.trim().trim_end_matches(',')), clean(icon))))
        })
        .collect()
}

/// Локально администрируемый адрес (второй бит первого байта): так телефоны и ноутбуки скрывают настоящий MAC.
pub fn random_mac(mac: &str) -> bool {
    u8::from_str_radix(mac.get(0..2).unwrap_or("00"), 16).is_ok_and(|b| b & 0x02 != 0)
}

fn is_mac(s: &str) -> Option<String> {
    normalize_mac(s).ok()
}

/// Подключение по ответу trafficd hw: объекты с MAC (поле hw/mac или ключ) → ifname, сигнал, Wi‑Fi, имя.
pub fn parse_hw(v: &Value) -> BTreeMap<String, Value> {
    fn walk(v: &Value, key: Option<&str>, out: &mut BTreeMap<String, Value>) {
        match v {
            Value::Object(m) => {
                let mac = m.get("hw").or_else(|| m.get("mac")).and_then(Value::as_str).and_then(is_mac).or_else(|| key.and_then(is_mac));
                let interesting = ["ifname", "signal", "wifi", "assoc", "type", "hostname"].iter().any(|k| m.contains_key(*k));
                if let (Some(mac), true) = (mac, interesting) {
                    let s = |k: &str| m.get(k).and_then(|x| x.as_str().map(clean).or_else(|| (x.is_number() || x.is_boolean()).then(|| x.to_string())));
                    let mut o = serde_json::Map::new();
                    for k in ["ifname", "signal", "wifi", "assoc", "type", "hostname"] {
                        if let Some(x) = s(k).filter(|x| !x.is_empty()) {
                            o.insert(k.into(), Value::String(x));
                        }
                    }
                    out.insert(mac, Value::Object(o));
                }
                for (k, x) in m {
                    walk(x, Some(k), out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, None, out)),
            _ => {}
        }
    }
    let mut out = BTreeMap::new();
    walk(v, None, &mut out);
    out
}

pub struct Extra {
    pub oui: BTreeMap<String, (String, String)>,
    pub hw: BTreeMap<String, Value>,
    pub names: BTreeMap<String, Found>,
}

fn file(env: &str, name: &str) -> PathBuf {
    std::env::var(env).ok().filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| run_dir().join(name))
}

impl Extra {
    pub fn load() -> Extra {
        let text = |p: PathBuf, max: u64| read_limited(&p.to_string_lossy(), max).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let oui = parse_oui(&text(file("MI_TT_OUI", "oui.txt"), 2 * 1024 * 1024));
        let hw = serde_json::from_str::<Value>(&text(file("MI_TT_TRAFFICD_HW", "trafficd-hw.json"), 2 * 1024 * 1024)).map(|v| parse_hw(&v)).unwrap_or_default();
        let names = serde_json::from_str::<Names>(&text(file("MI_TT_NAMES", "names.json"), 512 * 1024)).map(|n| n.devices).unwrap_or_default();
        Extra { oui, hw, names }
    }

    /// Поля для строки устройства (MAC уже нормализован).
    pub fn info(&self, mac: &str) -> Value {
        let (vendor, icon) = self.oui.get(mac.get(0..8).unwrap_or("")).cloned().unwrap_or_default();
        json!({
            "vendor": (!vendor.is_empty()).then_some(vendor),
            "icon": (!icon.is_empty()).then_some(icon),
            "random": random_mac(mac),
            "found": self.names.get(mac).map(|f| json!({ "name": f.name, "kind": f.kind, "model": f.model, "source": f.source, "seen": f.seen })),
            "link": self.hw.get(mac),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oui_lines() {
        let m = parse_oui("3C-D9-2B Hewlett Packard ICON:device_list_hp.png\n48-AD-08 HUAWEI TECHNOLOGIES CO.,LTD ICON:device_list_huawei.png\n24-DF-6A \nbad\n");
        assert_eq!(m.get("3c:d9:2b"), Some(&("Hewlett Packard".to_string(), "hp".to_string())));
        assert_eq!(m.get("48:ad:08").unwrap().1, "huawei");
        assert!(!m.contains_key("24:df:6a") || m["24:df:6a"].0.is_empty());
    }

    #[test]
    fn random_bit() {
        assert!(random_mac("a2:61:34:76:10:68"));
        assert!(random_mac("26:e8:01:74:bc:31"));
        assert!(!random_mac("f4:3b:d8:ca:c8:1c"));
    }

    #[test]
    fn hw_shapes() {
        let v = json!({ "AA:BB:CC:DD:EE:01": { "ifname": "wl1", "signal": -52, "wifi": 1, "hostname": "tv" }, "list": [ { "hw": "aa-bb-cc-dd-ee-02", "ifname": "eth1" } ] });
        let m = parse_hw(&v);
        assert_eq!(m["aa:bb:cc:dd:ee:01"]["signal"], "-52");
        assert_eq!(m["aa:bb:cc:dd:ee:02"]["ifname"], "eth1");
    }
}
