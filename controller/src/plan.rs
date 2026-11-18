//! План собственных правил маршрутизации и сверка с текущим состоянием ядра. Только чистая логика:
//! построение плана по спецификации захвата, разбор вывода `ip rule/route show`, `tc qdisc/filter show`,
//! `ip -6 addr`, поиск чужих записей и коллизий, порядок шагов. Исполняет — mi-tt-admin.
//!
//! Источник защищённого трафика определяется на входе, а не по адресу:
//!  - устройство — MAC на входе моста (tc flower src_mac → метка устройства);
//!  - сеть (SSID) — порт моста (tc matchall на интерфейсе SSID → метка сети);
//!  - вся LAN — интерфейс моста (ip rule iif).
//! Метка без совпадающего адреса (новый DHCP, статический адрес, новый IPv6) → unreachable, а не прямой выход.
//!
//! Зона владения: приоритеты правил 3000–3199 (IPv4 и IPv6), таблица 3100, метки 0x0a??0000/0x0fff0000,
//! фильтры tc с pref 1000–1399 на входе наших мостов и портов. Чужое в зоне → отказ без изменений.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub const TABLE: u32 = 3100;
pub const PRIO_MIN: u32 = 3000;
pub const PRIO_MAX: u32 = 3199;
pub const PRIO_LAN: u32 = 3000;
pub const PRIO_LOCAL: u32 = 3010;
pub const PRIO_DEV: u32 = 3100;
pub const PRIO_DEV_CATCH: u32 = 3105;
pub const PRIO_NET: u32 = 3110;
pub const PRIO_NET_CATCH: u32 = 3115;
pub const PRIO_V6_BLOCK: u32 = 3120;
pub const PRIO_LANWIDE: u32 = 3130;
pub const PRIO_LANWIDE_CATCH: u32 = 3135;
pub const METRIC_TUN: u32 = 1;
pub const METRIC_GUARD: u32 = 4096;

/// Маска одной метки и классы: 0x0a?????? — наши; бит 0x00800000 — метка сети, иначе устройства.
pub const MARK_MASK: u32 = 0x0fff_0000;
pub const MARK_OURS: u32 = 0x0a00_0000;
pub const MARK_OURS_MASK: u32 = 0x0f00_0000;
pub const MARK_CLASS_MASK: u32 = 0x0f80_0000;
pub const MARK_NET_FLAG: u32 = 0x0080_0000;
pub const MAX_MARKS: u32 = 127;
pub const TC_PREF_MIN: u32 = 1000;
pub const TC_PREF_MAX: u32 = 1399;
pub const TC_PREF_DEV: u32 = 1000;
pub const TC_PREF_NET: u32 = 1200;

/// Путь для стока BE7000 (нет NET_CLS_ACT/flower/matchall): iptables/ip6tables.
/// Биты skb mark стока заняты (по miqosd_init.sh: QoS 0xffff8000, mwan3 0x3f00, родконтроль 0xf, uu 0xf0) —
/// свободен только 0x4000; он нужен лишь для политики сети на части моста (physdev) и проверяется на коллизии.
pub const NF_MARK: u32 = 0x4000;
pub const NF_FWD_CHAIN: &str = "MITT_FWD";
pub const NF_MARK_CHAIN: &str = "MITT_MARK";
pub const NF_COMMENT: &str = "mi-trusttunnel";

/// Механизм определения источника на входе.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Marker {
    /// tc clsact + flower/matchall + skbedit (этап 4; на стоке RC06 1.1.38 недоступен).
    Tc,
    /// iptables/ip6tables: привязка MAC↔IP в FORWARD, iif для сети на своём мосту, physdev+MARK для части моста.
    Netfilter,
}

pub fn device_mark(k: u32) -> u32 {
    MARK_OURS | (k << 16)
}
pub fn network_mark(k: u32) -> u32 {
    MARK_OURS | MARK_NET_FLAG | (k << 16)
}
/// Как печатает `ip rule`: 0xa010000/0xfff0000.
pub fn fmt_mark(v: u32, m: u32) -> String {
    format!("{v:#x}/{m:#x}")
}
fn parse_hex_or_dec(s: &str) -> Option<u32> {
    match s.strip_prefix("0x") {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}
/// Нормализует «значение[/маска]» (десятичное или 0x) в вид fmt_mark.
pub fn norm_mark(s: &str) -> Option<String> {
    let (v, m) = s.split_once('/').unwrap_or((s, "0xffffffff"));
    Some(fmt_mark(parse_hex_or_dec(v)?, parse_hex_or_dec(m)?))
}
fn mark_parts(s: &str) -> Option<(u32, u32)> {
    let (v, m) = s.split_once('/')?;
    Some((parse_hex_or_dec(v)?, parse_hex_or_dec(m)?))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Entry {
    /// Маршрут по умолчанию в таблице 3100: через устройство (TUN) или unreachable (dev = None).
    Route { v6: bool, dev: Option<String>, metric: u32 },
    /// Правило выбора таблицы; lookup = None — правило типа unreachable.
    Rule {
        v6: bool,
        prio: u32,
        from: Option<String>,
        to: Option<String>,
        iif: Option<String>,
        #[serde(default)]
        fwmark: Option<String>,
        lookup: Option<String>,
    },
    /// Дисциплина clsact, созданная нами (существующую чужую ingress/clsact используем, но не владеем ею).
    Qdisc { dev: String },
    /// Фильтр на входе: mac = Some — flower src_mac (устройство), None — matchall (порт/SSID).
    Filter { dev: String, pref: u32, mac: Option<String>, mark: String },
    /// Наша цепочка iptables/ip6tables (MITT_FWD в filter, MITT_MARK в mangle).
    IptChain { v6: bool, table: String, chain: String },
    /// Правило iptables/ip6tables в каноническом виде `iptables -S` (без `-A CHAIN`).
    Ipt { v6: bool, table: String, chain: String, spec: Vec<String> },
}

/// Адрес или подсеть в том виде, как их печатает `ip`: хост без /32 и /128.
pub fn norm_prefix(s: &str) -> String {
    let (a, len) = match s.split_once('/') {
        Some((a, l)) => (a, l.parse::<u8>().ok()),
        None => (s, None),
    };
    match a.parse::<IpAddr>() {
        Ok(ip) => {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            match len {
                Some(l) if l != max => format!("{ip}/{l}"),
                _ => ip.to_string(),
            }
        }
        Err(_) => s.to_string(),
    }
}

fn rule(v6: bool, prio: u32) -> Entry {
    Entry::Rule { v6, prio, from: None, to: None, iif: None, fwmark: None, lookup: None }
}
fn with(mut e: Entry, f: impl FnOnce(&mut Option<String>, &mut Option<String>, &mut Option<String>, &mut Option<String>, &mut Option<String>)) -> Entry {
    if let Entry::Rule { from, to, iif, fwmark, lookup, .. } = &mut e {
        f(from, to, iif, fwmark, lookup);
    }
    e
}

impl Entry {
    pub fn guard_route(v6: bool) -> Self {
        Entry::Route { v6, dev: None, metric: METRIC_GUARD }
    }
    pub fn tun_route(v6: bool, dev: &str) -> Self {
        Entry::Route { v6, dev: Some(dev.into()), metric: METRIC_TUN }
    }
    pub fn lan_bypass(prefix: &str) -> Self {
        with(rule(prefix.contains(':'), PRIO_LAN), |_, to, _, _, l| {
            *to = Some(norm_prefix(prefix));
            *l = Some("main".into())
        })
    }
    pub fn local_bypass(v6: bool) -> Self {
        with(rule(v6, PRIO_LOCAL), |_, _, iif, _, l| {
            *iif = Some("lo".into());
            *l = Some("main".into())
        })
    }
    pub fn dev_capture(ip: &str, mark: u32) -> Self {
        with(rule(false, PRIO_DEV), |f, _, _, m, l| {
            *f = Some(norm_prefix(ip));
            *m = Some(fmt_mark(mark, MARK_MASK));
            *l = Some(TABLE.to_string())
        })
    }
    pub fn dev_catch() -> Self {
        with(rule(false, PRIO_DEV_CATCH), |_, _, _, m, _| *m = Some(fmt_mark(MARK_OURS, MARK_CLASS_MASK)))
    }
    pub fn net_capture(subnet: &str, mark: u32) -> Self {
        with(rule(false, PRIO_NET), |f, _, _, m, l| {
            *f = Some(norm_prefix(subnet));
            *m = Some(fmt_mark(mark, MARK_MASK));
            *l = Some(TABLE.to_string())
        })
    }
    pub fn net_catch() -> Self {
        with(rule(false, PRIO_NET_CATCH), |_, _, _, m, _| *m = Some(fmt_mark(MARK_OURS | MARK_NET_FLAG, MARK_CLASS_MASK)))
    }
    /// Внешний IPv6 всех помеченных источников (устройства и сети) — запрет: IPv6 пока не туннелируется.
    pub fn v6_block_marked() -> Self {
        with(rule(true, PRIO_V6_BLOCK), |_, _, _, m, _| *m = Some(fmt_mark(MARK_OURS, MARK_OURS_MASK)))
    }
    pub fn lanwide_capture(bridge: &str, subnet: &str) -> Self {
        with(rule(false, PRIO_LANWIDE), |f, _, iif, _, l| {
            *f = Some(norm_prefix(subnet));
            *iif = Some(bridge.into());
            *l = Some(TABLE.to_string())
        })
    }
    pub fn lanwide_catch(bridge: &str, v6: bool) -> Self {
        with(rule(v6, PRIO_LANWIDE_CATCH), |_, _, iif, _, _| *iif = Some(bridge.into()))
    }
    pub fn filter_mac(dev: &str, pref: u32, mac: &str, mark: u32) -> Self {
        Entry::Filter { dev: dev.into(), pref, mac: Some(mac.to_ascii_lowercase()), mark: fmt_mark(mark, MARK_MASK) }
    }
    pub fn filter_port(dev: &str, pref: u32, mark: u32) -> Self {
        Entry::Filter { dev: dev.into(), pref, mac: None, mark: fmt_mark(mark, MARK_MASK) }
    }
    pub fn is_tun_route(&self) -> bool {
        matches!(self, Entry::Route { dev: Some(_), .. })
    }

    /// Порядок добавления: запасной unreachable, TUN, обходы (роутер, LAN), запреты, захват, и только потом
    /// дисциплина и фильтры, которые ставят метки: когда метка появляется, правила для неё уже есть.
    /// Удаление — в обратном порядке: сначала перестают ставиться метки, последним уходит запасной unreachable.
    pub fn rank(&self) -> u8 {
        match self {
            Entry::Route { dev: None, .. } => 0,
            Entry::Route { dev: Some(_), .. } => 1,
            Entry::Rule { iif: Some(i), lookup: Some(_), .. } if i == "lo" => 2,
            Entry::Rule { to: Some(_), .. } => 3,
            Entry::Rule { lookup: None, .. } => 4,
            Entry::Rule { lookup: Some(_), .. } => 5,
            Entry::Qdisc { .. } => 6,
            Entry::Filter { .. } => 7,
            Entry::IptChain { .. } => 6,
            Entry::Ipt { spec, .. } if is_jump(spec) => 8,
            Entry::Ipt { .. } => 7,
        }
    }

    /// Программа и аргументы для add/del.
    pub fn cmd(&self, op: &str) -> (&'static str, Vec<String>) {
        let s = |x: &str| x.to_string();
        match self {
            Entry::Route { v6, dev, metric } => {
                let mut a = Vec::new();
                if *v6 {
                    a.push(s("-6"));
                }
                a.extend([s("route"), s(op)]);
                match dev {
                    None => a.extend([s("unreachable"), s("default")]),
                    Some(d) => a.extend([s("default"), s("dev"), d.clone()]),
                }
                a.extend([s("metric"), metric.to_string(), s("table"), TABLE.to_string()]);
                ("ip", a)
            }
            Entry::Rule { v6, prio, from, to, iif, fwmark, lookup } => {
                let mut a = Vec::new();
                if *v6 {
                    a.push(s("-6"));
                }
                a.extend([s("rule"), s(op), s("priority"), prio.to_string()]);
                for (k, v) in [("from", from), ("to", to), ("iif", iif), ("fwmark", fwmark)] {
                    if let Some(v) = v {
                        a.extend([s(k), v.clone()]);
                    }
                }
                match lookup {
                    Some(t) => a.extend([s("lookup"), t.clone()]),
                    None => a.push(s("unreachable")),
                }
                ("ip", a)
            }
            Entry::Qdisc { dev } => ("tc", vec![s("qdisc"), s(op), s("dev"), dev.clone(), s("clsact")]),
            Entry::Filter { dev, pref, mac, mark } => {
                let mut a = vec![s("filter"), s(op), s("dev"), dev.clone(), s("ingress"), s("pref"), pref.to_string()];
                if op == "add" {
                    a.extend([s("protocol"), s("all")]);
                    match mac {
                        Some(m) => a.extend([s("flower"), s("src_mac"), m.clone()]),
                        None => a.push(s("matchall")),
                    }
                    // continue: после нашей метки классификация продолжается — чужие фильтры дальше работают
                    a.extend([s("action"), s("skbedit"), s("mark"), mark.clone(), s("continue")]);
                }
                ("tc", a)
            }
            Entry::IptChain { v6, table, chain } => {
                (if *v6 { "ip6tables" } else { "iptables" }, vec![s("-w"), s("-t"), table.clone(), s(if op == "add" { "-N" } else { "-X" }), chain.clone()])
            }
            Entry::Ipt { v6, table, chain, spec } => {
                let mut a = vec![s("-w"), s("-t"), table.clone()];
                match op {
                    // RETURN для LAN и переходы — в начало цепочки, остальное — в конец
                    "add" if is_top(spec) => a.extend([s("-I"), chain.clone(), s("1")]),
                    "add" => a.extend([s("-A"), chain.clone()]),
                    _ => a.extend([s("-D"), chain.clone()]),
                }
                a.extend(spec.iter().cloned());
                (if *v6 { "ip6tables" } else { "iptables" }, a)
            }
        }
    }

    pub fn label(&self) -> String {
        let (prog, args) = self.cmd("add");
        format!("{prog} {}", args.into_iter().filter(|x| x != "add").collect::<Vec<_>>().join(" "))
    }

    pub fn ipt(v6: bool, table: &str, chain: &str, spec: &[&str]) -> Self {
        Entry::Ipt { v6, table: table.into(), chain: chain.into(), spec: norm_spec(&spec.iter().map(|x| x.to_string()).collect::<Vec<_>>()) }
    }
    pub fn ipt_chain(v6: bool, table: &str, chain: &str) -> Self {
        Entry::IptChain { v6, table: table.into(), chain: chain.into() }
    }
    /// Захват по IPv4 источника (путь стока: привязку MAC и IP обеспечивает FORWARD).
    pub fn ip_capture(ip: &str) -> Self {
        with(rule(false, PRIO_DEV), |f, _, _, _, l| {
            *f = Some(norm_prefix(ip));
            *l = Some(TABLE.to_string())
        })
    }
    pub fn iif_capture(bridge: &str, subnet: &str, prio: u32) -> Self {
        with(rule(false, prio), |f, _, iif, _, l| {
            *f = Some(norm_prefix(subnet));
            *iif = Some(bridge.into());
            *l = Some(TABLE.to_string())
        })
    }
    pub fn iif_block(bridge: &str, v6: bool, prio: u32) -> Self {
        with(rule(v6, prio), |_, _, iif, _, _| *iif = Some(bridge.into()))
    }
    pub fn mark_rule(v6: bool, prio: u32, from: Option<&str>, mark: u32, mask: u32, lookup: bool) -> Self {
        with(rule(v6, prio), |f, _, _, m, l| {
            *f = from.map(norm_prefix);
            *m = Some(fmt_mark(mark, mask));
            *l = lookup.then(|| TABLE.to_string())
        })
    }

    fn tc_dev(&self) -> Option<&str> {
        match self {
            Entry::Qdisc { dev } | Entry::Filter { dev, .. } => Some(dev),
            _ => None,
        }
    }
}

// ---------- iptables: канонический вид правил ----------

/// Переход в нашу цепочку из встроенной (цель MITT_*).
pub fn is_jump(spec: &[String]) -> bool {
    spec.windows(2).any(|w| w[0] == "-j" && w[1].starts_with("MITT_"))
}
fn is_top(spec: &[String]) -> bool {
    is_jump(spec) || spec.ends_with(&["-j".to_string(), "RETURN".to_string()])
}
/// Нормализация для сравнения с выводом `iptables -S`: MAC в нижнем регистре, без кавычек.
pub fn norm_spec(spec: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(spec.len());
    for t in spec {
        let t = t.trim_matches('"').to_string();
        let lower = out.last().is_some_and(|p| p == "--mac-source");
        out.push(if lower { t.to_ascii_lowercase() } else { t });
    }
    out
}

#[derive(Debug, Default, Clone)]
pub struct IptLive {
    pub v6: bool,
    pub table: String,
    pub chains: BTreeSet<String>,
    /// (цепочка, спецификация) для всех правил таблицы.
    pub rules: Vec<(String, Vec<String>)>,
}

/// Разбор `iptables -S` (одна таблица).
pub fn parse_ipt(text: &str, v6: bool, table: &str) -> IptLive {
    let mut l = IptLive { v6, table: table.into(), ..Default::default() };
    for line in text.lines() {
        let t: Vec<String> = line.split_whitespace().map(String::from).collect();
        match t.first().map(String::as_str) {
            Some("-N") if t.len() >= 2 => {
                l.chains.insert(t[1].clone());
            }
            Some("-A") if t.len() >= 2 => l.rules.push((t[1].clone(), norm_spec(&t[2..]))),
            _ => {}
        }
    }
    l
}

/// Маски меток в спецификации правила iptables (MARK и mark): значение не важно, важны затрагиваемые биты.
pub fn spec_mark_masks(spec: &[String]) -> Vec<u32> {
    let mut v = Vec::new();
    for (i, w) in spec.iter().enumerate() {
        if matches!(w.as_str(), "--set-xmark" | "--set-mark" | "--or-mark" | "--and-mark" | "--xor-mark" | "--mark") {
            if let Some(val) = spec.get(i + 1) {
                let mask = match val.split_once('/') {
                    Some((_, m)) => parse_hex_or_dec(m).unwrap_or(0xffff_ffff),
                    None => 0xffff_ffff,
                };
                v.push(mask);
            }
        }
    }
    v
}

/// Маска всех меток, которые использует план (fwmark в правилах, MARK в iptables, метки tc).
pub fn our_mark_mask<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> u32 {
    let mut m = 0;
    for e in entries {
        match e {
            Entry::Rule { fwmark: Some(f), .. } | Entry::Filter { mark: f, .. } => m |= mark_parts(f).map(|(_, mask)| mask).unwrap_or(0),
            Entry::Ipt { spec, .. } => m |= spec_mark_masks(spec).into_iter().fold(0, |a, b| a | b),
            _ => {}
        }
    }
    m
}

/// Что нужно netfilter-плану от ядра и окружения.
#[derive(Debug, Default, Clone, Serialize, PartialEq, Eq)]
pub struct NfNeeds {
    /// physdev + MARK (политика сети на части моста).
    pub mark: bool,
    pub v6: bool,
    /// NFQUEUE для Zapret (mangle OUTPUT, метка сокета движка).
    pub queue: bool,
}

/// План для стока, без tc. Устройство: `from <IPv4> lookup 3100` и привязка MAC к IP в FORWARD (MAC с чужим IPv4
/// или любой внешний IPv6 этого MAC → REJECT; трафик к самому роутеру FORWARD не проходит). Сеть на своём мосту:
/// `iif`. Сеть на части моста: physdev + MARK 0x4000 + fwmark. `bridge_ports` — живой состав мостов.
pub fn build_plan_netfilter(
    spec: &CaptureSpec,
    v6_lan_prefixes: &[String],
    bridge_ports: &BTreeMap<String, BTreeSet<String>>,
    guard_only: bool,
) -> (BTreeSet<Entry>, NfNeeds) {
    let mut p = BTreeSet::new();
    let mut needs = NfNeeds::default();
    if spec.is_empty() {
        return (p, needs);
    }
    p.insert(Entry::guard_route(false));
    if !guard_only {
        p.insert(Entry::tun_route(false, &spec.tun));
    }
    p.insert(Entry::local_bypass(false));
    p.insert(Entry::local_bypass(true));
    for s in &spec.lan_subnets {
        p.insert(Entry::lan_bypass(s));
    }
    for s in v6_lan_prefixes.iter().map(String::as_str).chain(["fe80::/10", "ff00::/8"]) {
        p.insert(Entry::lan_bypass(s));
    }
    let (f, m) = ("filter", "mangle");
    let (mut fwd4, mut fwd6) = (false, false);
    for d in &spec.devices {
        if let Some(ip) = &d.ipv4 {
            p.insert(Entry::ip_capture(ip));
            let src = format!("{}/32", norm_prefix(ip));
            p.insert(Entry::ipt(false, f, NF_FWD_CHAIN, &["!", "-s", &src, "-i", &d.bridge, "-m", "mac", "--mac-source", &d.mac, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]));
        } else {
            p.insert(Entry::ipt(false, f, NF_FWD_CHAIN, &["-i", &d.bridge, "-m", "mac", "--mac-source", &d.mac, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"]));
        }
        p.insert(Entry::ipt(true, f, NF_FWD_CHAIN, &["-i", &d.bridge, "-m", "mac", "--mac-source", &d.mac, "-j", "REJECT", "--reject-with", "icmp6-port-unreachable"]));
        fwd4 = true;
        fwd6 = true;
    }
    for n in &spec.networks {
        let ports: BTreeSet<String> = n.ports.iter().cloned().collect();
        let whole = bridge_ports.get(&n.bridge).is_some_and(|live| !live.is_empty() && live.is_subset(&ports));
        if whole {
            // сеть занимает мост целиком: источник — интерфейс моста, метки не нужны
            p.insert(Entry::iif_capture(&n.bridge, &n.subnet, PRIO_NET));
            p.insert(Entry::iif_block(&n.bridge, false, PRIO_NET_CATCH));
            p.insert(Entry::iif_block(&n.bridge, true, PRIO_V6_BLOCK));
        } else {
            needs.mark = true;
            for port in &n.ports {
                for v6 in [false, true] {
                    p.insert(Entry::ipt(v6, m, NF_MARK_CHAIN, &["-m", "physdev", "--physdev-in", port, "-j", "MARK", "--set-xmark", &fmt_mark(NF_MARK, NF_MARK)]));
                }
            }
            p.insert(Entry::mark_rule(false, PRIO_NET, Some(&n.subnet), NF_MARK, NF_MARK, true));
            p.insert(Entry::mark_rule(false, PRIO_NET_CATCH, None, NF_MARK, NF_MARK, false));
            p.insert(Entry::mark_rule(true, PRIO_V6_BLOCK, None, NF_MARK, NF_MARK, false));
        }
    }
    for l in &spec.lanwide {
        p.insert(Entry::lanwide_capture(&l.bridge, &l.subnet));
        p.insert(Entry::lanwide_catch(&l.bridge, false));
        p.insert(Entry::lanwide_catch(&l.bridge, true));
    }
    let jump = |chain: &str| vec!["-m".to_string(), "comment".into(), "--comment".into(), NF_COMMENT.into(), "-j".into(), chain.into()];
    if fwd4 {
        p.insert(Entry::ipt_chain(false, f, NF_FWD_CHAIN));
        for s in &spec.lan_subnets {
            p.insert(Entry::ipt(false, f, NF_FWD_CHAIN, &["-d", s, "-j", "RETURN"]));
        }
        // fw3 стока может отклонять пересылку на интерфейс вне зон: захваченный трафик к TUN разрешаем явно
        p.insert(Entry::ipt(false, f, NF_FWD_CHAIN, &["-o", &spec.tun, "-j", "ACCEPT"]));
        p.insert(Entry::Ipt { v6: false, table: f.into(), chain: "FORWARD".into(), spec: jump(NF_FWD_CHAIN) });
    }
    if fwd6 {
        needs.v6 = true;
        p.insert(Entry::ipt_chain(true, f, NF_FWD_CHAIN));
        for s in v6_lan_prefixes {
            p.insert(Entry::ipt(true, f, NF_FWD_CHAIN, &["-d", s, "-j", "RETURN"]));
        }
        p.insert(Entry::Ipt { v6: true, table: f.into(), chain: "FORWARD".into(), spec: jump(NF_FWD_CHAIN) });
    }
    if needs.mark {
        needs.v6 = true;
        for v6 in [false, true] {
            p.insert(Entry::ipt_chain(v6, m, NF_MARK_CHAIN));
            p.insert(Entry::Ipt { v6, table: m.into(), chain: "PREROUTING".into(), spec: jump(NF_MARK_CHAIN) });
        }
    }
    if let (Some(z), false) = (&spec.zapret, guard_only) {
        // только IPv4: Mihomo работает с ipv6: false; при guard-only движок не запущен и очередь не нужна
        needs.queue = true;
        let ports = z.tcp_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
        let qnum = z.qnum.to_string();
        p.insert(Entry::ipt_chain(false, m, NF_ZAPRET_CHAIN));
        p.insert(Entry::ipt(false, m, NF_ZAPRET_CHAIN, &["-p", "tcp", "-m", "multiport", "--dports", &ports, "-m", "mark", "--mark", &fmt_mark(z.mark, z.mark),
            "-j", "NFQUEUE", "--queue-num", &qnum, "--queue-bypass"]));
        p.insert(Entry::Ipt { v6: false, table: m.into(), chain: "OUTPUT".into(), spec: jump(NF_ZAPRET_CHAIN) });
    }
    (p, needs)
}

/// Таблицы iptables, состояние которых нужно прочитать.
pub fn ipt_tables<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> BTreeSet<(bool, String)> {
    entries
        .into_iter()
        .filter_map(|e| match e {
            Entry::Ipt { v6, table, .. } | Entry::IptChain { v6, table, .. } => Some((*v6, table.clone())),
            _ => None,
        })
        .collect()
}

// ---------- спецификация захвата и построение плана ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevCap {
    pub id: String,
    pub mac: String,
    pub ipv4: Option<String>,
    pub bridge: String,
    pub mark: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetCap {
    pub id: String,
    pub bridge: String,
    pub ports: Vec<String>,
    pub subnet: String,
    pub mark: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LanCap {
    pub bridge: String,
    pub subnet: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaptureSpec {
    pub devices: Vec<DevCap>,
    pub networks: Vec<NetCap>,
    pub lanwide: Vec<LanCap>,
    pub lan_subnets: Vec<String>,
    pub tun: String,
    /// Очередь Zapret для прямых соединений движка с меткой сокета (действие «напрямую с Zapret»).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zapret: Option<ZapretSpec>,
}

/// Исходящие соединения Mihomo через выход `mitt-zapret` несут метку сокета `mark`; их TCP-пакеты к `tcp_ports`
/// уходят в NFQUEUE `qnum` (с `--queue-bypass`: без nfqws2 пакеты идут дальше без обработки, это прямой выход).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZapretSpec {
    pub qnum: u16,
    pub mark: u32,
    pub tcp_ports: Vec<u16>,
}

pub const ZAPRET_QNUM: u16 = 200;
pub const NF_ZAPRET_CHAIN: &str = "MITT_ZQ";
/// Метка пакетов, которые генерирует nfqws2 (`--fwmark`): без бита `NF_MARK`, чтобы они не попадали в очередь повторно.
pub const ZAPRET_DESYNC_MARK: u32 = 0x4000_0000;

impl CaptureSpec {
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty() && self.networks.is_empty() && self.lanwide.is_empty()
    }
    /// Мосты и порты, которые должны существовать до применения: (интерфейс, мост, если это порт).
    pub fn interfaces(&self) -> Vec<(String, Option<String>)> {
        let mut v: BTreeSet<(String, Option<String>)> = BTreeSet::new();
        for d in &self.devices {
            v.insert((d.bridge.clone(), None));
        }
        for n in &self.networks {
            v.insert((n.bridge.clone(), None));
            for p in &n.ports {
                v.insert((p.clone(), Some(n.bridge.clone())));
            }
        }
        for l in &self.lanwide {
            v.insert((l.bridge.clone(), None));
        }
        v.into_iter().collect()
    }
}

/// Строит желаемый набор записей. `v6_lan_prefixes` — живые глобальные/ULA префиксы мостов;
/// `foreign_hooks` — интерфейсы, где уже есть чужая ingress/clsact (её используем, но не создаём и не удаляем).
pub fn build_plan(spec: &CaptureSpec, v6_lan_prefixes: &[String], foreign_hooks: &BTreeSet<String>, owned: &BTreeSet<Entry>, guard_only: bool) -> BTreeSet<Entry> {
    let mut p = BTreeSet::new();
    if spec.is_empty() {
        return p;
    }
    p.insert(Entry::guard_route(false));
    if !guard_only {
        p.insert(Entry::tun_route(false, &spec.tun));
    }
    p.insert(Entry::local_bypass(false));
    p.insert(Entry::local_bypass(true));
    for s in &spec.lan_subnets {
        p.insert(Entry::lan_bypass(s));
    }
    // IPv6: локальные адреса роутера (NDP, DHCPv6, управление) обслуживает таблица local; сюда — префиксы LAN,
    // link-local и multicast, чтобы прямой обмен внутри сети не попадал под запрет
    for s in v6_lan_prefixes.iter().map(String::as_str).chain(["fe80::/10", "ff00::/8"]) {
        p.insert(Entry::lan_bypass(s));
    }
    let mut tc_devs: BTreeSet<String> = BTreeSet::new();
    let mut marked = false;
    for (k, d) in spec.devices.iter().enumerate() {
        if let Some(ip) = &d.ipv4 {
            p.insert(Entry::dev_capture(ip, d.mark));
        }
        p.insert(Entry::filter_mac(&d.bridge, TC_PREF_DEV + k as u32 + 1, &d.mac, d.mark));
        tc_devs.insert(d.bridge.clone());
        marked = true;
    }
    if !spec.devices.is_empty() {
        p.insert(Entry::dev_catch());
    }
    for (k, n) in spec.networks.iter().enumerate() {
        p.insert(Entry::net_capture(&n.subnet, n.mark));
        for port in &n.ports {
            p.insert(Entry::filter_port(port, TC_PREF_NET + k as u32 + 1, n.mark));
            tc_devs.insert(port.clone());
        }
        marked = true;
    }
    if !spec.networks.is_empty() {
        p.insert(Entry::net_catch());
    }
    if marked {
        p.insert(Entry::v6_block_marked());
    }
    for l in &spec.lanwide {
        p.insert(Entry::lanwide_capture(&l.bridge, &l.subnet));
        p.insert(Entry::lanwide_catch(&l.bridge, false));
        p.insert(Entry::lanwide_catch(&l.bridge, true));
    }
    for dev in tc_devs {
        let q = Entry::Qdisc { dev: dev.clone() };
        if owned.contains(&q) || !foreign_hooks.contains(&dev) {
            p.insert(q);
        }
    }
    p
}

// ---------- разбор живого состояния ----------

/// Разбор `ip [-6] rule show`: (приоритет, запись или исходная строка, если в ней есть то, чего мы не создаём).
pub fn parse_rules(text: &str, v6: bool) -> Vec<(u32, Result<Entry, String>)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((p, rest)) = line.split_once(':') else { continue };
        let Ok(prio) = p.trim().parse::<u32>() else { continue };
        let t: Vec<&str> = rest.split_whitespace().collect();
        let (mut from, mut to, mut iif, mut fwmark, mut lookup, mut unreach, mut extra) = (None, None, None, None, None, false, false);
        let mut i = 0;
        while i < t.len() {
            match (t[i], t.get(i + 1)) {
                ("from", Some(v)) => {
                    from = if *v == "all" { None } else { Some(norm_prefix(v)) };
                    i += 2
                }
                ("to", Some(v)) => {
                    to = Some(norm_prefix(v));
                    i += 2
                }
                ("iif", Some(v)) => {
                    iif = Some(v.to_string());
                    i += 2
                }
                ("fwmark", Some(v)) => {
                    fwmark = norm_mark(v);
                    extra |= fwmark.is_none();
                    i += 2
                }
                ("lookup", Some(v)) => {
                    lookup = Some(v.to_string());
                    i += 2
                }
                ("unreachable", _) => {
                    unreach = true;
                    i += 1
                }
                _ => {
                    extra = true;
                    i += 1
                }
            }
        }
        let e = if extra || (lookup.is_some() == unreach) {
            Err(line.trim().to_string())
        } else {
            Ok(Entry::Rule { v6, prio, from, to, iif, fwmark, lookup })
        };
        out.push((prio, e));
    }
    out
}

/// Разбор `ip [-6] route show table 3100`.
pub fn parse_routes(text: &str, v6: bool) -> Vec<Result<Entry, String>> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let t: Vec<&str> = line.split_whitespace().collect();
        let (mut unreach, mut dev, mut metric, mut extra, mut default) = (false, None, None, false, false);
        let mut i = 0;
        while i < t.len() {
            match (t[i], t.get(i + 1)) {
                ("unreachable", _) => {
                    unreach = true;
                    i += 1
                }
                ("default", _) => {
                    default = true;
                    i += 1
                }
                ("dev", Some(v)) => {
                    dev = Some(v.to_string());
                    i += 2
                }
                ("metric", Some(v)) => {
                    metric = v.parse::<u32>().ok();
                    i += 2
                }
                ("scope", Some(_)) | ("pref", Some(_)) => i += 2,
                ("proto", Some(v)) if *v == "boot" => i += 2,
                _ => {
                    extra = true;
                    i += 1
                }
            }
        }
        if unreach && dev.as_deref() == Some("lo") {
            dev = None;
        }
        out.push(match (extra, default, metric) {
            (false, true, Some(m)) if unreach && dev.is_none() => Ok(Entry::Route { v6, dev: None, metric: m }),
            (false, true, Some(m)) if !unreach && dev.is_some() => Ok(Entry::Route { v6, dev, metric: m }),
            _ => Err(line.trim().to_string()),
        });
    }
    out
}

/// Есть ли на интерфейсе входной хук (clsact или ingress) — по выводу `tc qdisc show dev X`.
pub fn parse_tc_hook(text: &str) -> bool {
    text.lines().any(|l| l.starts_with("qdisc clsact") || l.starts_with("qdisc ingress"))
}

/// Разбор `tc filter show dev X ingress`: (pref, наш вид фильтра или исходный текст блока).
pub fn parse_tc_filters(text: &str, dev: &str) -> Vec<(u32, Result<Entry, String>)> {
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    for line in text.lines() {
        if line.starts_with("filter ") {
            if line.contains(" handle ") {
                blocks.push(vec![line]);
            }
            continue; // заголовок цепочки/приоритета без handle
        }
        if let Some(b) = blocks.last_mut() {
            b.push(line);
        }
    }
    let mut out = Vec::new();
    for b in blocks {
        let head: Vec<&str> = b[0].split_whitespace().collect();
        let pos = |k: &str| head.iter().position(|x| *x == k);
        let pref = pos("pref").and_then(|i| head.get(i + 1)).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0);
        let kind = pos("pref").and_then(|i| head.get(i + 2)).copied().unwrap_or("");
        let proto_all = pos("protocol").and_then(|i| head.get(i + 1)) == Some(&"all");
        let (mut mac, mut mark, mut control, mut actions, mut extra) = (None, None, None, 0, false);
        for l in &b[1..] {
            let t: Vec<&str> = l.split_whitespace().collect();
            match t.first().copied() {
                Some("src_mac") => mac = t.get(1).map(|m| m.to_ascii_lowercase()),
                Some("not_in_hw") | Some("in_hw") | Some("index") | Some("Action") | Some("Sent") | Some("backlog") | Some("eth_type") | None => {
                    if t.first() == Some(&"eth_type") && t.get(1) != Some(&"all") {
                        extra = true;
                    }
                }
                Some("action") => {
                    actions += 1;
                    if let Some(i) = t.iter().position(|x| *x == "skbedit") {
                        if let (Some("mark"), Some(v)) = (t.get(i + 1).copied(), t.get(i + 2)) {
                            mark = norm_mark(v);
                            control = t.get(i + 3).map(|s| s.to_string());
                        } else {
                            extra = true;
                        }
                    } else {
                        extra = true;
                    }
                }
                _ => extra = true,
            }
        }
        let ours = !extra
            && proto_all
            && actions == 1
            && control.as_deref() == Some("continue")
            && mark.is_some()
            && ((kind == "flower" && mac.is_some()) || (kind == "matchall" && mac.is_none()));
        out.push((
            pref,
            if ours { Ok(Entry::Filter { dev: dev.into(), pref, mac, mark: mark.unwrap() }) } else { Err(b.join(" | ").split_whitespace().collect::<Vec<_>>().join(" ")) },
        ));
    }
    out
}

/// Глобальные и ULA префиксы из `ip -6 addr show dev X` (link-local не нужен: он покрыт fe80::/10).
pub fn parse_v6_prefixes(text: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.first() != Some(&"inet6") {
            continue;
        }
        let Some((a, l)) = t.get(1).and_then(|s| s.split_once('/')) else { continue };
        let (Ok(addr), Ok(len)) = (a.parse::<std::net::Ipv6Addr>(), l.parse::<u32>()) else { continue };
        if (addr.segments()[0] & 0xffc0) == 0xfe80 || len > 128 {
            continue;
        }
        let bits = u128::from(addr) & if len == 0 { 0 } else { !0u128 << (128 - len) };
        out.insert(format!("{}/{len}", std::net::Ipv6Addr::from(bits)));
    }
    out.into_iter().collect()
}

/// `ip -d link show dev X`: (это мост?, master-мост, если интерфейс — порт).
pub fn parse_link(text: &str) -> (bool, Option<String>) {
    let t: Vec<&str> = text.split_whitespace().collect();
    let master = t.iter().position(|x| *x == "master").and_then(|i| t.get(i + 1)).map(|s| s.to_string());
    let is_bridge = text.lines().any(|l| l.trim_start().starts_with("bridge ") || l.trim() == "bridge");
    (is_bridge, master)
}

/// Метки MARK в выводе iptables-save/ip6tables-save, пересекающиеся с нашей маской.
pub fn iptables_mark_collisions(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| l.starts_with("-A ")) {
        let t: Vec<&str> = line.split_whitespace().collect();
        for (i, w) in t.iter().enumerate() {
            let val = match *w {
                "--set-xmark" | "--set-mark" | "--or-mark" | "--and-mark" | "--xor-mark" | "--mark" => t.get(i + 1),
                _ => None,
            };
            if let Some(v) = val {
                let (m, mask) = match v.split_once('/') {
                    Some((a, b)) => (parse_hex_or_dec(a), parse_hex_or_dec(b)),
                    None => (parse_hex_or_dec(v), Some(0xffff_ffff)),
                };
                // маска без указания — все биты: правило читает или пишет и наши биты
                if m.is_some() && mask.unwrap_or(0xffff_ffff) & MARK_MASK != 0 {
                    out.push(line.to_string());
                    break;
                }
            }
        }
    }
    out
}

#[derive(Debug, Default, Clone)]
pub struct TcDev {
    pub dev: String,
    pub hook: bool,
    pub filters: Vec<(u32, Result<Entry, String>)>,
}

#[derive(Debug, Default, Clone)]
pub struct Live {
    pub rules: Vec<(u32, Result<Entry, String>)>,
    pub routes: Vec<Result<Entry, String>>,
    pub tc: Vec<TcDev>,
    pub ipt: Vec<IptLive>,
}

#[derive(Debug, Default, Serialize)]
pub struct Diff {
    pub add: Vec<Entry>,
    pub del: Vec<Entry>,
    pub conflicts: Vec<String>,
    /// Наши (по журналу) записи, которых в ядре нет: например, после перезагрузки.
    pub missing: Vec<Entry>,
    pub live_in_zone: Vec<Entry>,
}

impl Diff {
    pub fn is_noop(&self) -> bool {
        self.add.is_empty() && self.del.is_empty()
    }
}

pub fn reconcile(desired: &BTreeSet<Entry>, owned: &BTreeSet<Entry>, live: &Live) -> Diff {
    let known: BTreeSet<&Entry> = desired.iter().chain(owned.iter()).collect();
    let mut d = Diff::default();
    let mut live_set: BTreeSet<Entry> = BTreeSet::new();
    let table = TABLE.to_string();
    // биты меток, которые реально использует план (tc: 0x0fff0000; netfilter: 0x4000 только для части моста; иначе 0)
    let ours_mask = our_mark_mask(known.iter().copied());
    let mark_overlaps = |m: &Option<String>| m.as_deref().and_then(mark_parts).is_some_and(|(_, mask)| mask & ours_mask != 0);
    for (prio, r) in &live.rules {
        let in_zone = (PRIO_MIN..=PRIO_MAX).contains(prio);
        match r {
            Ok(e) => {
                let (refs_table, uses_marks) = match e {
                    Entry::Rule { lookup, fwmark, .. } => (lookup.as_deref() == Some(table.as_str()), mark_overlaps(fwmark)),
                    _ => (false, false),
                };
                if in_zone || refs_table || uses_marks {
                    if in_zone && known.contains(e) {
                        live_set.insert(e.clone());
                    } else if uses_marks && !in_zone {
                        d.conflicts.push(format!("чужое правило использует биты наших меток ({ours_mask:#x}): {}", e.label()));
                    } else {
                        d.conflicts.push(format!("чужое правило в зоне mi-trusttunnel: {}", e.label()));
                    }
                }
            }
            Err(line) if in_zone || line.split_whitespace().any(|w| w == table) => d.conflicts.push(format!("чужое правило: {line}")),
            Err(line) if line.contains("fwmark") && line.split_whitespace().skip_while(|w| *w != "fwmark").nth(1).and_then(|v| norm_mark(v)).as_deref().and_then(mark_parts).is_some_and(|(_, m)| m & ours_mask != 0) => {
                d.conflicts.push(format!("чужое правило использует биты наших меток: {line}"))
            }
            Err(_) => {}
        }
    }
    for r in &live.routes {
        match r {
            Ok(e) if known.contains(e) => {
                live_set.insert(e.clone());
            }
            Ok(e) => d.conflicts.push(format!("чужой маршрут в таблице {TABLE}: {}", e.label())),
            Err(line) => d.conflicts.push(format!("чужой маршрут в таблице {TABLE}: {line}")),
        }
    }
    for t in &live.ipt {
        let tool = if t.v6 { "ip6tables" } else { "iptables" };
        for c in t.chains.iter().filter(|c| c.starts_with("MITT_")) {
            let e = Entry::IptChain { v6: t.v6, table: t.table.clone(), chain: c.clone() };
            if known.contains(&e) {
                live_set.insert(e);
            } else {
                d.conflicts.push(format!("неучтённая цепочка {tool} -t {} {c} (не в плане и не в журнале)", t.table));
            }
        }
        for (chain, spec) in &t.rules {
            let e = Entry::Ipt { v6: t.v6, table: t.table.clone(), chain: chain.clone(), spec: spec.clone() };
            let ours_chain = chain.starts_with("MITT_");
            if ours_chain || is_jump(spec) {
                if known.contains(&e) {
                    live_set.insert(e);
                } else {
                    d.conflicts.push(format!("чужое или неучтённое правило {tool} -t {}: -A {chain} {}", t.table, spec.join(" ")));
                }
            } else if ours_mask != 0 && spec_mark_masks(spec).iter().any(|m| m & ours_mask != 0) {
                d.conflicts.push(format!("правило firewall {tool} -t {} задевает биты наших меток ({ours_mask:#x}): -A {chain} {}", t.table, spec.join(" ")));
            }
        }
    }
    let mut min_pref: BTreeMap<&str, u32> = BTreeMap::new();
    for e in desired.iter().chain(owned.iter()) {
        if let Entry::Filter { dev, pref, .. } = e {
            let m = min_pref.entry(dev.as_str()).or_insert(*pref);
            *m = (*m).min(*pref);
        }
    }
    for t in &live.tc {
        let q = Entry::Qdisc { dev: t.dev.clone() };
        if t.hook && known.contains(&q) {
            live_set.insert(q);
        }
        for (pref, f) in &t.filters {
            let in_zone = (TC_PREF_MIN..=TC_PREF_MAX).contains(pref);
            match f {
                Ok(e) if in_zone && known.contains(e) => {
                    live_set.insert(e.clone());
                }
                _ if in_zone => d.conflicts.push(format!("чужой фильтр tc в зоне mi-trusttunnel на {} (pref {pref})", t.dev)),
                _ if min_pref.get(t.dev.as_str()).is_some_and(|m| pref < m) => d.conflicts.push(format!(
                    "чужой фильтр tc на {} (pref {pref}) выполняется раньше наших: он может прервать классификацию до установки метки",
                    t.dev
                )),
                _ => {}
            }
        }
    }
    let mut add: Vec<Entry> = desired.difference(&live_set).cloned().collect();
    add.sort_by_key(|e| (e.rank(), e.clone()));
    let mut del: Vec<Entry> = owned.intersection(&live_set).filter(|e| !desired.contains(*e)).cloned().collect();
    del.sort_by_key(|e| (std::cmp::Reverse(e.rank()), e.clone()));
    // наш фильтр на дисциплине, которую мы удаляем, уходит вместе с ней — отдельная команда не нужна
    let dropped_qdiscs: BTreeSet<String> = del.iter().filter_map(|e| if let Entry::Qdisc { dev } = e { Some(dev.clone()) } else { None }).collect();
    del.retain(|e| !matches!(e, Entry::Filter { dev, .. } if dropped_qdiscs.contains(dev)));
    d.missing = owned.difference(&live_set).cloned().collect();
    d.live_in_zone = live_set.into_iter().collect();
    d.add = add;
    d.del = del;
    d
}

/// Интерфейсы tc, состояние которых нужно прочитать: из плана и журнала.
pub fn tc_devices<'a>(sets: impl IntoIterator<Item = &'a Entry>) -> BTreeSet<String> {
    sets.into_iter().filter_map(|e| e.tc_dev().map(String::from)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOWER: &str = "filter protocol all pref 1001 flower chain 0 \nfilter protocol all pref 1001 flower chain 0 handle 0x1 \n  src_mac 02:00:00:00:0A:02\n  not_in_hw\n\taction order 1: skbedit  mark 167837696/0xfff0000 continue\n\t index 1 ref 1 bind 1\n";
    const MATCHALL: &str = "filter protocol all pref 1201 matchall chain 0 \nfilter protocol all pref 1201 matchall chain 0 handle 0x1 \n  not_in_hw\n\taction order 1: skbedit  mark 176226304/0xfff0000 continue\n\t index 1 ref 1 bind 1\n";

    fn spec() -> CaptureSpec {
        CaptureSpec {
            devices: vec![DevCap { id: "tv".into(), mac: "02:00:00:00:0a:02".into(), ipv4: Some("10.10.1.2".into()), bridge: "br-lan".into(), mark: device_mark(1) }],
            networks: vec![NetCap { id: "guest".into(), bridge: "br-guest".into(), ports: vec!["r-gst".into()], subnet: "10.10.2.0/24".into(), mark: network_mark(1) }],
            lanwide: vec![],
            lan_subnets: vec!["10.10.1.0/24".into(), "10.10.2.0/24".into()],
            tun: "mitt0".into(),
            zapret: None,
        }
    }

    #[test]
    fn marks_and_formats() {
        assert_eq!(device_mark(1), 0x0a01_0000);
        assert_eq!(network_mark(1), 0x0a81_0000);
        assert_eq!(norm_mark("167837696/0xfff0000").unwrap(), "0xa010000/0xfff0000");
        assert_eq!(norm_mark("0xa010000/0xfff0000").unwrap(), fmt_mark(device_mark(1), MARK_MASK));
    }

    #[test]
    fn tc_output_parses_into_our_filters() {
        let f = parse_tc_filters(FLOWER, "br-lan");
        assert_eq!(f, vec![(1001, Ok(Entry::filter_mac("br-lan", 1001, "02:00:00:00:0a:02", device_mark(1))))]);
        let m = parse_tc_filters(MATCHALL, "r-gst");
        assert_eq!(m, vec![(1201, Ok(Entry::filter_port("r-gst", 1201, network_mark(1))))]);
        let foreign = parse_tc_filters("filter protocol ip pref 1 u32 chain 0 handle 800::800 order 2048 key ht 800 bkt 0 \n  match 00000000/00000000 at 0\n\taction order 1: gact action pass\n", "br-lan");
        assert!(foreign[0].1.is_err());
        assert!(parse_tc_hook("qdisc noqueue 0: root refcnt 2 \nqdisc clsact ffff: parent ffff:fff1 \n"));
    }

    #[test]
    fn plan_is_mark_based_with_catch_alls() {
        let p = build_plan(&spec(), &["fd00:10::/64".into()], &BTreeSet::new(), &BTreeSet::new(), false);
        let labels: BTreeSet<String> = p.iter().map(Entry::label).collect();
        for want in [
            "ip rule priority 3100 from 10.10.1.2 fwmark 0xa010000/0xfff0000 lookup 3100",
            "ip rule priority 3105 fwmark 0xa000000/0xf800000 unreachable",
            "ip rule priority 3110 from 10.10.2.0/24 fwmark 0xa810000/0xfff0000 lookup 3100",
            "ip rule priority 3115 fwmark 0xa800000/0xf800000 unreachable",
            "ip -6 rule priority 3120 fwmark 0xa000000/0xf000000 unreachable",
            "ip -6 rule priority 3000 to fd00:10::/64 lookup main",
            "ip -6 rule priority 3000 to fe80::/10 lookup main",
            "tc qdisc dev br-lan clsact",
            "tc filter dev br-lan ingress pref 1001 protocol all flower src_mac 02:00:00:00:0a:02 action skbedit mark 0xa010000/0xfff0000 continue",
            "tc filter dev r-gst ingress pref 1201 protocol all matchall action skbedit mark 0xa810000/0xfff0000 continue",
        ] {
            assert!(labels.contains(want), "нет {want}\n{labels:#?}");
        }
        // устройство без аренды: метка и запрет есть, захвата по адресу нет
        let mut s = spec();
        s.devices[0].ipv4 = None;
        let p2 = build_plan(&s, &[], &BTreeSet::new(), &BTreeSet::new(), true);
        assert!(!p2.iter().any(|e| matches!(e, Entry::Rule { prio: PRIO_DEV, .. })));
        assert!(p2.contains(&Entry::dev_catch()) && !p2.iter().any(Entry::is_tun_route));
        // чужой хук: дисциплину не создаём
        let p3 = build_plan(&spec(), &[], &["br-lan".to_string()].into(), &BTreeSet::new(), false);
        assert!(!p3.contains(&Entry::Qdisc { dev: "br-lan".into() }));
    }

    #[test]
    fn rules_with_fwmark_parse_back() {
        let r = parse_rules("3100:\tfrom 10.10.1.2 fwmark 0xa010000/0xfff0000 lookup 3100\n3105:\tfrom all fwmark 0xa000000/0xf800000 unreachable\n", false);
        assert_eq!(r[0].1.as_ref().unwrap(), &Entry::dev_capture("10.10.1.2", device_mark(1)));
        assert_eq!(r[1].1.as_ref().unwrap(), &Entry::dev_catch());
    }

    #[test]
    fn order_add_marks_last_remove_marks_first() {
        let p = build_plan(&spec(), &[], &BTreeSet::new(), &BTreeSet::new(), false);
        let d = reconcile(&p, &BTreeSet::new(), &Live::default());
        let ranks: Vec<u8> = d.add.iter().map(Entry::rank).collect();
        assert!(ranks.windows(2).all(|w| w[0] <= w[1]));
        assert!(matches!(d.add.last().unwrap(), Entry::Filter { .. }));
        assert_eq!(d.add[0], Entry::guard_route(false));
    }

    #[test]
    fn collisions_are_conflicts() {
        let p = build_plan(&spec(), &[], &BTreeSet::new(), &BTreeSet::new(), false);
        let mut l = Live::default();
        l.rules = parse_rules("2000:\tfrom all fwmark 0x10000/0xff0000 lookup 200\n5000:\tfrom all fwmark 0x1 lookup 201\n3150:\tfrom 10.9.9.9 lookup 300\n", false);
        l.tc = vec![TcDev { dev: "br-lan".into(), hook: true, filters: vec![(1, Err("foreign".into())), (1001, Err("foreign".into()))] }];
        let d = reconcile(&p, &BTreeSet::new(), &l);
        // 2000 и 5000 (точное значение без маски тоже читает наши биты), 3150 в зоне, tc pref 1 раньше нашего, tc pref 1001 в зоне
        assert_eq!(d.conflicts.len(), 5, "{:#?}", d.conflicts);
        assert!(d.conflicts.iter().any(|c| c.contains("биты наших меток")));
        assert!(d.conflicts.iter().any(|c| c.contains("раньше наших")));
    }

    #[test]
    fn revert_drops_filters_with_owned_qdisc() {
        let p = build_plan(&spec(), &[], &BTreeSet::new(), &BTreeSet::new(), false);
        let mut l = Live::default();
        l.rules = p.iter().filter_map(|e| if let Entry::Rule { prio, .. } = e { Some((*prio, Ok(e.clone()))) } else { None }).collect();
        l.routes = p.iter().filter(|e| matches!(e, Entry::Route { .. })).map(|e| Ok(e.clone())).collect();
        for dev in tc_devices(&p) {
            let filters = p.iter().filter_map(|e| match e { Entry::Filter { dev: d, pref, .. } if *d == dev => Some((*pref, Ok(e.clone()))), _ => None }).collect();
            l.tc.push(TcDev { dev, hook: true, filters });
        }
        let d = reconcile(&p, &p, &l);
        assert!(d.is_noop() && d.conflicts.is_empty(), "{d:#?}");
        let r = reconcile(&BTreeSet::new(), &p, &l);
        assert!(!r.del.iter().any(|e| matches!(e, Entry::Filter { .. })), "фильтры уходят вместе с нашей дисциплиной");
        assert!(matches!(r.del[0], Entry::Qdisc { .. }));
        assert_eq!(*r.del.last().unwrap(), Entry::guard_route(false));
    }

    #[test]
    fn v6_prefixes_and_links() {
        let t = "4: br-lan: <BROADCAST> mtu 1500\n    inet6 fd00:10::1/64 scope global \n    inet6 fe80::1/64 scope link \n    inet6 2001:db8:1:2::5/56 scope global dynamic\n";
        assert_eq!(parse_v6_prefixes(t), vec!["2001:db8:1::/56".to_string(), "fd00:10::/64".to_string()]);
        let port = "5: r-tv@if2: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue master br-lan state UP\n    link/ether 02:aa brd ff\n    veth \n    bridge_slave state forwarding\n";
        assert_eq!(parse_link(port), (false, Some("br-lan".into())));
        let br = "4: br-lan: <BROADCAST> mtu 1500\n    link/ether 02 brd ff\n    bridge forward_delay 1500 hello_time 200\n";
        assert_eq!(parse_link(br), (true, None));
    }

    #[test]
    fn iptables_marks_overlapping_ours() {
        let t = "*mangle\n-A PREROUTING -i br-lan -j MARK --set-xmark 0x10000/0xff0000\n-A PREROUTING -j MARK --set-xmark 0x1/0xff\nCOMMIT\n";
        assert_eq!(iptables_mark_collisions(t).len(), 1);
    }

    // ---------- netfilter (сток) ----------

    fn ports(v: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
        v.iter().map(|(b, ps)| (b.to_string(), ps.iter().map(|x| x.to_string()).collect())).collect()
    }

    #[test]
    fn netfilter_plan_device_and_whole_bridge_network_needs_no_marks() {
        let bp = ports(&[("br-lan", &["r-tv", "r-ph"]), ("br-guest", &["r-gst"])]);
        let (p, needs) = build_plan_netfilter(&spec(), &["fd00:10::/64".into()], &bp, false);
        assert!(!needs.mark && needs.v6);
        assert_eq!(our_mark_mask(&p), 0, "меток нет: биты QoS/mwan3 стока не затрагиваются");
        let labels: BTreeSet<String> = p.iter().map(Entry::label).collect();
        for want in [
            "ip rule priority 3100 from 10.10.1.2 lookup 3100",
            "ip rule priority 3110 from 10.10.2.0/24 iif br-guest lookup 3100",
            "ip rule priority 3115 iif br-guest unreachable",
            "ip -6 rule priority 3120 iif br-guest unreachable",
            "iptables -w -t filter -A MITT_FWD ! -s 10.10.1.2/32 -i br-lan -m mac --mac-source 02:00:00:00:0a:02 -j REJECT --reject-with icmp-port-unreachable",
            "ip6tables -w -t filter -A MITT_FWD -i br-lan -m mac --mac-source 02:00:00:00:0a:02 -j REJECT --reject-with icmp6-port-unreachable",
            "iptables -w -t filter -I MITT_FWD 1 -d 10.10.1.0/24 -j RETURN",
            "ip6tables -w -t filter -I MITT_FWD 1 -d fd00:10::/64 -j RETURN",
            "iptables -w -t filter -A MITT_FWD -o mitt0 -j ACCEPT",
            "iptables -w -t filter -I FORWARD 1 -m comment --comment mi-trusttunnel -j MITT_FWD",
            "iptables -w -t filter -N MITT_FWD",
        ] {
            assert!(labels.contains(want), "нет {want}\n{labels:#?}");
        }
        // порядок: цепочка до правил, переход последним; снятие — переход первым, цепочка последней
        let d = reconcile(&p, &BTreeSet::new(), &Live::default());
        let idx = |f: &dyn Fn(&Entry) -> bool| d.add.iter().position(|e| f(e)).unwrap();
        assert!(idx(&|e| matches!(e, Entry::IptChain { .. })) < idx(&|e| matches!(e, Entry::Ipt { spec, .. } if !is_jump(spec))));
        assert!(matches!(d.add.last().unwrap(), Entry::Ipt { spec, .. } if is_jump(spec)));
    }

    #[test]
    fn netfilter_zapret_queue_only_for_marked_engine_sockets() {
        let mut sp = spec();
        sp.zapret = Some(ZapretSpec { qnum: ZAPRET_QNUM, mark: NF_MARK, tcp_ports: vec![80, 443] });
        let ports: BTreeMap<String, BTreeSet<String>> = [("br-guest".to_string(), ["r-gst".to_string()].into())].into();
        let (p, n) = build_plan_netfilter(&sp, &[], &ports, false);
        assert!(n.queue && !n.mark);
        let labels: Vec<String> = p.iter().map(Entry::label).collect();
        assert!(labels.contains(&"iptables -w -t mangle -A MITT_ZQ -p tcp -m multiport --dports 80,443 -m mark --mark 0x4000/0x4000 -j NFQUEUE --queue-num 200 --queue-bypass".to_string()), "{labels:#?}");
        assert!(labels.iter().any(|l| l.contains("-I OUTPUT 1") && l.contains("-j MITT_ZQ")), "{labels:#?}");
        assert_eq!(our_mark_mask(&p) & NF_MARK, NF_MARK, "бит Zapret учитывается при поиске коллизий меток");
        // при загрузке (guard-only) движок не запущен — очередь не создаётся
        let (p, n) = build_plan_netfilter(&sp, &[], &ports, true);
        assert!(!n.queue && !p.iter().any(|e| e.label().contains("MITT_ZQ")));
    }

    #[test]
    fn netfilter_partial_bridge_network_uses_physdev_mark() {
        let mut sp = spec();
        sp.networks[0].bridge = "br-lan".into();
        sp.networks[0].ports = vec!["r-kid".into()];
        let bp = ports(&[("br-lan", &["r-tv", "r-ph", "r-kid"])]);
        let (p, needs) = build_plan_netfilter(&sp, &[], &bp, false);
        assert!(needs.mark);
        assert_eq!(our_mark_mask(&p), NF_MARK);
        let labels: BTreeSet<String> = p.iter().map(Entry::label).collect();
        assert!(labels.contains("iptables -w -t mangle -A MITT_MARK -m physdev --physdev-in r-kid -j MARK --set-xmark 0x4000/0x4000"));
        assert!(labels.contains("ip6tables -w -t mangle -I PREROUTING 1 -m comment --comment mi-trusttunnel -j MITT_MARK"));
        assert!(labels.contains("ip rule priority 3110 from 10.10.2.0/24 fwmark 0x4000/0x4000 lookup 3100"));
        assert!(labels.contains("ip -6 rule priority 3120 fwmark 0x4000/0x4000 unreachable"));
    }

    /// Вывод iptables -S, как его печатает iptables (легаси 1.8.11 в лаборатории; формат 1.6.2 стока тот же).
    const IPT_S: &str = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-N MITT_FWD\n-A FORWARD -m comment --comment mi-trusttunnel -j MITT_FWD\n-A MITT_FWD -d 10.10.1.0/24 -j RETURN\n-A MITT_FWD ! -s 10.10.1.2/32 -i br-lan -m mac --mac-source 02:00:00:00:0A:02 -j REJECT --reject-with icmp-port-unreachable\n-A MITT_FWD -o mitt0 -j ACCEPT\n";

    #[test]
    fn ipt_output_round_trip_and_foreign_rules() {
        let mut sp = spec();
        sp.networks.clear();
        sp.lan_subnets = vec!["10.10.1.0/24".into()];
        let (p, _) = build_plan_netfilter(&sp, &[], &BTreeMap::new(), false);
        let v4: BTreeSet<Entry> = p.iter().filter(|e| matches!(e, Entry::Ipt { v6: false, .. } | Entry::IptChain { v6: false, .. })).cloned().collect();
        let live = Live { ipt: vec![parse_ipt(IPT_S, false, "filter")], ..Default::default() };
        let d = reconcile(&v4, &v4, &live);
        assert!(d.conflicts.is_empty() && d.is_noop(), "{d:#?}");
        // чужое правило в нашей цепочке и неучтённый переход — конфликты
        let bad = format!("{IPT_S}-A MITT_FWD -j ACCEPT\n-A INPUT -j MITT_FWD\n-N MITT_OLD\n");
        let d = reconcile(&v4, &v4, &Live { ipt: vec![parse_ipt(&bad, false, "filter")], ..Default::default() });
        assert_eq!(d.conflicts.len(), 3, "{:#?}", d.conflicts);
    }

    #[test]
    fn stock_firewall_marks_conflict_only_when_we_use_marks() {
        // реальные правила стока: mwan3 sticky (0xfc00 задевает 0x4000), QoS (0xff000000, не задевает)
        let fw = "-N mwan3_rule_x\n-A mwan3_rule_x -m mark ! --mark 0xfc00/0xfc00 -j SET --del-set mwan3_sticky_x src,src\n-A PREROUTING -m mac --mac-source 02:aa:bb:cc:dd:ee -j MARK --set-xmark 0x5000000/0xff000000\n";
        let mangle = parse_ipt(fw, false, "mangle");
        let (plain, _) = build_plan_netfilter(&spec(), &[], &ports(&[("br-guest", &["r-gst"])]), false);
        let d = reconcile(&plain, &BTreeSet::new(), &Live { ipt: vec![mangle.clone()], ..Default::default() });
        assert!(d.conflicts.is_empty(), "без меток коллизий нет: {:#?}", d.conflicts);
        let mut sp = spec();
        sp.networks[0].bridge = "br-lan".into();
        sp.networks[0].ports = vec!["r-kid".into()];
        let (marked, _) = build_plan_netfilter(&sp, &[], &ports(&[("br-lan", &["r-tv", "r-kid"])]), false);
        let d = reconcile(&marked, &BTreeSet::new(), &Live { ipt: vec![mangle], ..Default::default() });
        assert_eq!(d.conflicts.len(), 1, "mwan3 0xfc00 задевает 0x4000: {:#?}", d.conflicts);
        assert!(d.conflicts[0].contains("0xfc00"));
    }
}

