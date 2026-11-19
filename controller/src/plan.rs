//! План собственных правил маршрутизации и сверка с текущим состоянием ядра. Только чистая логика:
//! построение плана по спецификации политики, разбор вывода `ip rule/route show`, `iptables -S`, `ipset list -t`,
//! поиск чужих записей и коллизий, порядок шагов. Исполняет — mi-tt-admin.
//!
//! Как выбирается маршрут (сток RC06 1.1.38: iptables 1.6.2, ipset, без tc-actions):
//!  - mangle PREROUTING → цепочка классификации: правила по порядку, первое совпадение. Источник — MAC на входе моста
//!    (устройство), порт моста через physdev или мост целиком (сеть), мост (вся LAN); назначение — набор ipset
//!    (адреса доменов заносит dnsmasq, IP-префиксы — статический набор). «Через TrustTunnel» ставит бит 0x4000,
//!    `ip rule fwmark 0x4000 lookup 3100` ведёт в TUN клиента; при отказе туннеля — unreachable (или обход).
//!  - filter FORWARD → та же классификация: «блокировать» — REJECT; выход в TUN разрешается явно.
//!  - mangle FORWARD → та же классификация: «напрямую с Zapret» — первые пакеты соединений к портам профилей
//!    (TCP 25, UDP 5, connbytes) в NFQUEUE для nfqws2; mangle OUTPUT — проверочный трафик подбора стратегии.
//!  - mangle OUTPUT: DNS-вопросы роутера к резолверу туннеля тоже идут в туннель.
//!  - IPv6 защищаемых источников наружу запрещён (IPv6 не туннелируется, а домены сопоставляются только по IPv4).
//!
//! Цепочки называются по хэшу содержимого: изменение порядка или состава правил — новая цепочка, затем переход на неё,
//! затем снятие прежней. Зона владения: приоритеты правил 3000–3199, таблица 3100, цепочки MITT_*, наборы mitt*,
//! бит метки 0x4000. Чужое в зоне → отказ без изменений.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TABLE: u32 = 3100;
pub const PRIO_MIN: u32 = 3000;
pub const PRIO_MAX: u32 = 3199;
pub const PRIO_LAN: u32 = 3000;
pub const PRIO_MARK: u32 = 3005;
pub const METRIC_TUN: u32 = 1;
pub const METRIC_GUARD: u32 = 4096;

/// Биты skb mark стока заняты (по miqosd_init.sh: QoS 0xffff8000, mwan3 0x3f00, родконтроль 0xf, uu 0xf0) —
/// свободен только 0x4000: им помечается трафик «через TrustTunnel». Коллизии проверяются при каждом применении.
pub const NF_MARK: u32 = 0x4000;
pub const NF_COMMENT: &str = "mi-trusttunnel";
pub const CHAIN_PREFIX: &str = "MITT_";
pub const SET_PREFIX: &str = "mitt";
/// Наборы, которые заполняет dnsmasq: запись живёт сутки после последнего ответа.
pub const SET_DNS_TIMEOUT: u32 = 86400;
pub const ZAPRET_QNUM: u16 = 200;
/// Метка пакетов, которые генерирует nfqws2 (`--fwmark`): вне бита `NF_MARK`.
pub const ZAPRET_DESYNC_MARK: u32 = 0x4000_0000;
/// Очередь проверочного трафика подбора стратегии: исходящие соединения роутера с портов `ZAPRET_TEST_SPORTS`.
pub const ZAPRET_TEST_QNUM: u16 = 201;
/// Выше эфемерных портов Linux (32768–60999): обычные соединения роутера (клиент TrustTunnel, вопросы dnsmasq)
/// сюда не попадают, иначе они ушли бы в очередь 201, а принятый очередью пакет покидает mangle OUTPUT раньше
/// цепочки O с меткой туннеля. Проверка привязывает порт явно (curl --local-port 61000-61099).
pub const ZAPRET_TEST_SPORTS: &str = "61000:61099";
/// Сколько первых пакетов соединения (в сторону сервера) уходит в очередь: TCP и UDP, как в Zapret-Manager.
const QUEUE_PACKETS_TCP: u32 = 25;
const QUEUE_PACKETS_UDP: u32 = 5;

/// Как печатает `ip rule`: 0x4000/0x4000.
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
    let (v, m) = mark_parts(s)?;
    Some(fmt_mark(v, m))
}
fn mark_parts(s: &str) -> Option<(u32, u32)> {
    match s.split_once('/') {
        Some((v, m)) => Some((parse_hex_or_dec(v)?, parse_hex_or_dec(m)?)),
        None => Some((parse_hex_or_dec(s)?, 0xffff_ffff)),
    }
}

// ---------- спецификация политики ----------

/// Источник правила, как он виден на входе.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SrcMatch {
    /// Устройство: MAC на входе моста.
    Mac { bridge: String, mac: String },
    /// Сеть (SSID): её порты моста. Если сеть занимает мост целиком — достаточно моста.
    Network { bridge: String, ports: Vec<String> },
    /// Вся LAN: мост.
    Bridge { bridge: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Act {
    Tunnel,
    Direct,
    Zapret,
    Block,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Откуда правило (id правила или default_action) — для обзора.
    pub from: String,
    pub src: SrcMatch,
    /// Набор назначения; None — любое назначение.
    pub set: Option<String>,
    pub act: Act,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetKind {
    /// Адреса доменов, заносит dnsmasq.
    Dns,
    /// IP-префиксы из настроек и категорий.
    Static,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetSpec {
    pub name: String,
    pub kind: SetKind,
    /// Префиксы статического набора (в журнал не пишутся: могут быть большими).
    #[serde(default, skip_serializing)]
    pub entries: Vec<String>,
}

/// Порты очереди Zapret одного протокола: `proto` — tcp|udp, `ports` — через запятую, диапазоны «a-b» или «a:b».
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueRule {
    pub proto: String,
    pub ports: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySpec {
    pub rules: Vec<PolicyRule>,
    pub sets: Vec<SetSpec>,
    /// IPv4-подсети LAN: трафик к ним не классифицируется.
    pub lan_subnets: Vec<String>,
    pub tun: String,
    /// При отказе туннеля трафик «через TrustTunnel» идёт напрямую (иначе блокируется).
    pub fail_open: bool,
    /// Порты очереди Zapret по протоколам; пусто — Zapret не используется.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zapret_queue: Vec<QueueRule>,
    /// Резолвер туннеля: DNS-вопросы роутера к нему идут в туннель.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_resolver: Option<String>,
    /// Источники, внешний IPv6 которых запрещён.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub v6_block: Vec<SrcMatch>,
}

impl PolicySpec {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.v6_block.is_empty() && self.dns_resolver.is_none()
    }
    pub fn uses(&self, a: Act) -> bool {
        self.rules.iter().any(|r| r.act == a)
    }
    /// Мосты и порты, которые должны существовать до применения: (интерфейс, мост, если это порт).
    pub fn interfaces(&self) -> Vec<(String, Option<String>)> {
        let mut v: BTreeSet<(String, Option<String>)> = BTreeSet::new();
        for s in self.rules.iter().map(|r| &r.src).chain(self.v6_block.iter()) {
            match s {
                SrcMatch::Mac { bridge, .. } | SrcMatch::Bridge { bridge } => {
                    v.insert((bridge.clone(), None));
                }
                SrcMatch::Network { bridge, ports } => {
                    v.insert((bridge.clone(), None));
                    for p in ports {
                        v.insert((p.clone(), Some(bridge.clone())));
                    }
                }
            }
        }
        v.into_iter().collect()
    }
    pub fn bridges(&self) -> BTreeSet<String> {
        self.interfaces().into_iter().filter(|(_, m)| m.is_none()).map(|(i, _)| i).collect()
    }
}

// ---------- записи плана ----------

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "entry", rename_all = "snake_case", deny_unknown_fields)]
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
    /// Набор ipset (IPv4). timeout — у наборов, которые заполняет dnsmasq.
    Ipset { name: String, kind: String, timeout: Option<u32> },
    /// Наша цепочка целиком: правила по порядку (порядок значим — первое совпадение).
    Chain { v6: bool, table: String, chain: String, rows: Vec<Vec<String>> },
    /// Переход из встроенной цепочки в нашу (в начало встроенной).
    Jump { v6: bool, table: String, from: String, chain: String },
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

/// Префикс в том виде, как его печатает `iptables -S`: всегда с длиной.
fn ipt_prefix(s: &str) -> String {
    let p = norm_prefix(s);
    if p.contains('/') { p } else if p.contains(':') { format!("{p}/128") } else { format!("{p}/32") }
}

fn ipt_prog(v6: bool) -> &'static str {
    if v6 { "ip6tables" } else { "iptables" }
}

fn jump_spec(chain: &str) -> Vec<String> {
    ["-m", "comment", "--comment", NF_COMMENT, "-j", chain].iter().map(|s| s.to_string()).collect()
}

impl Entry {
    pub fn guard_route() -> Self {
        Entry::Route { v6: false, dev: None, metric: METRIC_GUARD }
    }
    pub fn tun_route(dev: &str) -> Self {
        Entry::Route { v6: false, dev: Some(dev.into()), metric: METRIC_TUN }
    }
    pub fn lan_bypass(prefix: &str) -> Self {
        Entry::Rule { v6: false, prio: PRIO_LAN, from: None, to: Some(norm_prefix(prefix)), iif: None, fwmark: None, lookup: Some("main".into()) }
    }
    pub fn mark_rule() -> Self {
        Entry::Rule { v6: false, prio: PRIO_MARK, from: None, to: None, iif: None, fwmark: Some(fmt_mark(NF_MARK, NF_MARK)), lookup: Some(TABLE.to_string()) }
    }
    pub fn is_tun_route(&self) -> bool {
        matches!(self, Entry::Route { dev: Some(_), .. })
    }

    /// Порядок добавления: наборы, маршруты, правила выбора таблицы, цепочки-листья (метка, очередь), цепочки
    /// классификации и только потом переходы в них: когда трафик попадает в цепочку, всё, на что она ссылается, уже есть.
    /// Удаление — в обратном порядке.
    pub fn rank(&self) -> u8 {
        match self {
            Entry::Ipset { .. } => 0,
            Entry::Route { dev: None, .. } => 1,
            Entry::Route { dev: Some(_), .. } => 2,
            Entry::Rule { lookup: Some(l), .. } if l == "main" => 3,
            Entry::Rule { .. } => 4,
            Entry::Chain { rows, .. } if rows.iter().all(|r| !r.iter().any(|w| w.starts_with(CHAIN_PREFIX))) => 5,
            Entry::Chain { .. } => 6,
            Entry::Jump { .. } => 7,
        }
    }

    /// Команды для add/del (программа и аргументы), по порядку.
    pub fn cmds(&self, op: &str) -> Vec<(&'static str, Vec<String>)> {
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
                vec![("ip", a)]
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
                vec![("ip", a)]
            }
            Entry::Ipset { name, kind, timeout } => {
                if op == "add" {
                    let mut a = vec![s("create"), name.clone(), kind.clone(), s("family"), s("inet")];
                    if let Some(t) = timeout {
                        a.extend([s("timeout"), t.to_string()]);
                    }
                    vec![("ipset", a)]
                } else {
                    vec![("ipset", vec![s("destroy"), name.clone()])]
                }
            }
            Entry::Chain { v6, table, chain, rows } => {
                let base = |c: &str| vec![s("-w"), s("-t"), table.clone(), s(c), chain.clone()];
                if op == "add" {
                    let mut v = vec![(ipt_prog(*v6), base("-N"))];
                    for r in rows {
                        let mut a = base("-A");
                        a.extend(r.iter().cloned());
                        v.push((ipt_prog(*v6), a));
                    }
                    v
                } else {
                    vec![(ipt_prog(*v6), base("-F")), (ipt_prog(*v6), base("-X"))]
                }
            }
            Entry::Jump { v6, table, from, chain } => {
                let mut a = vec![s("-w"), s("-t"), table.clone()];
                if op == "add" {
                    a.extend([s("-I"), from.clone(), s("1")]);
                } else {
                    a.extend([s("-D"), from.clone()]);
                }
                a.extend(jump_spec(chain));
                vec![(ipt_prog(*v6), a)]
            }
        }
    }

    pub fn label(&self) -> String {
        match self {
            Entry::Chain { v6, table, chain, rows } => {
                let body = rows.iter().map(|r| r.join(" ")).collect::<Vec<_>>().join(" | ");
                format!("{} -t {table} {chain}: {body}", ipt_prog(*v6))
            }
            _ => {
                let (prog, args) = self.cmds("add").into_iter().next().unwrap_or(("", Vec::new()));
                format!("{prog} {}", args.into_iter().filter(|x| x != "add").collect::<Vec<_>>().join(" "))
            }
        }
    }
}

// ---------- построение плана ----------

fn hash8(v: &impl Serialize) -> String {
    let h = Sha256::digest(serde_json::to_vec(v).unwrap_or_default());
    h.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Цепочка с именем по содержимому: MITT_<буква><8 hex>.
fn chain(v6: bool, table: &str, letter: char, rows: Vec<Vec<String>>) -> Entry {
    let name = format!("{CHAIN_PREFIX}{letter}{}", hash8(&(v6, table, &rows)));
    Entry::Chain { v6, table: table.into(), chain: name, rows }
}

fn chain_name(e: &Entry) -> String {
    match e {
        Entry::Chain { chain, .. } => chain.clone(),
        _ => String::new(),
    }
}

/// Отбор источника в правиле iptables. Сеть: мост целиком (`-i`) или по порту (physdev).
fn src_variants(s: &SrcMatch, bridge_ports: &BTreeMap<String, BTreeSet<String>>) -> Vec<Vec<String>> {
    let v = |x: &[&str]| x.iter().map(|w| w.to_string()).collect::<Vec<String>>();
    match s {
        SrcMatch::Mac { bridge, mac } => vec![v(&["-i", bridge, "-m", "mac", "--mac-source", &mac.to_ascii_uppercase()])],
        SrcMatch::Bridge { bridge } => vec![v(&["-i", bridge])],
        SrcMatch::Network { bridge, ports } => {
            let mine: BTreeSet<String> = ports.iter().cloned().collect();
            if bridge_ports.get(bridge).is_some_and(|live| !live.is_empty() && live.is_subset(&mine)) {
                vec![v(&["-i", bridge])]
            } else {
                ports.iter().map(|p| v(&["-m", "physdev", "--physdev-in", p])).collect()
            }
        }
    }
}

/// Нужен ли physdev (сеть на части моста).
pub fn needs_physdev(spec: &PolicySpec, bridge_ports: &BTreeMap<String, BTreeSet<String>>) -> bool {
    spec.rules.iter().map(|r| &r.src).chain(spec.v6_block.iter()).any(|s| src_variants(s, bridge_ports).iter().any(|v| v.iter().any(|w| w == "physdev")))
}

/// Классификация: правила по порядку, у каждого — цель в этой цепочке или RETURN (совпадение без действия здесь
/// останавливает разбор: первое совпадение). Хвост из одних RETURN отбрасывается; нет действий — цепочки нет.
fn classify(spec: &PolicySpec, bridge_ports: &BTreeMap<String, BTreeSet<String>>, target: impl Fn(Act) -> Option<Vec<String>>) -> Option<Vec<Vec<String>>> {
    let mut rows: Vec<(Vec<String>, bool)> = Vec::new();
    for s in &spec.lan_subnets {
        rows.push((vec!["-d".into(), ipt_prefix(s), "-j".into(), "RETURN".into()], false));
    }
    for r in &spec.rules {
        let t = target(r.act);
        for src in src_variants(&r.src, bridge_ports) {
            let mut row = src;
            if let Some(set) = &r.set {
                row.extend(["-m", "set", "--match-set", set, "dst"].iter().map(|w| w.to_string()));
            }
            let effective = t.is_some();
            row.extend(t.clone().unwrap_or_else(|| vec!["-j".into(), "RETURN".into()]));
            rows.push((row, effective));
        }
    }
    let last = rows.iter().rposition(|(_, e)| *e)?;
    Some(rows.into_iter().take(last + 1).map(|(r, _)| r).collect())
}

/// Желаемый набор записей. `v6_lan_prefixes` — живые глобальные/ULA префиксы мостов; `bridge_ports` — живой состав мостов.
pub fn build_plan(spec: &PolicySpec, v6_lan_prefixes: &[String], bridge_ports: &BTreeMap<String, BTreeSet<String>>, guard_only: bool) -> BTreeSet<Entry> {
    let mut p = BTreeSet::new();
    if spec.is_empty() {
        return p;
    }
    let (f, m) = ("filter", "mangle");
    let s = |x: &str| x.to_string();
    for set in &spec.sets {
        let (kind, timeout) = match set.kind {
            SetKind::Dns => ("hash:ip", Some(SET_DNS_TIMEOUT)),
            SetKind::Static => ("hash:net", None),
        };
        p.insert(Entry::Ipset { name: set.name.clone(), kind: kind.into(), timeout });
    }
    let tunnel = spec.uses(Act::Tunnel) || spec.dns_resolver.is_some();
    if tunnel {
        if !spec.fail_open {
            p.insert(Entry::guard_route());
        }
        if !guard_only {
            p.insert(Entry::tun_route(&spec.tun));
        }
        for sub in &spec.lan_subnets {
            p.insert(Entry::lan_bypass(sub));
        }
        p.insert(Entry::mark_rule());
        let leaf = chain(false, m, 'T', vec![vec![s("-j"), s("MARK"), s("--set-xmark"), fmt_mark(NF_MARK, NF_MARK)]]);
        let tt = chain_name(&leaf);
        p.insert(leaf);
        if let Some(rows) = classify(spec, bridge_ports, |a| (a == Act::Tunnel).then(|| vec![s("-g"), tt.clone()])) {
            let c = chain(false, m, 'C', rows);
            p.insert(Entry::Jump { v6: false, table: m.into(), from: "PREROUTING".into(), chain: chain_name(&c) });
            p.insert(c);
        }
        if let Some(r) = &spec.dns_resolver {
            let rows = ["udp", "tcp"]
                .iter()
                .map(|proto| vec![s("-d"), ipt_prefix(r), s("-p"), s(proto), s("-m"), s(proto), s("--dport"), s("53"), s("-j"), s("MARK"), s("--set-xmark"), fmt_mark(NF_MARK, NF_MARK)])
                .collect();
            let c = chain(false, m, 'O', rows);
            p.insert(Entry::Jump { v6: false, table: m.into(), from: "OUTPUT".into(), chain: chain_name(&c) });
            p.insert(c);
        }
    }
    // filter FORWARD: выход в TUN разрешён явно (fw3 стока отклоняет пересылку на интерфейс вне зон), затем запреты
    let block = classify(spec, bridge_ports, |a| (a == Act::Block).then(|| vec![s("-j"), s("REJECT"), s("--reject-with"), s("icmp-port-unreachable")]));
    if tunnel || block.is_some() {
        let mut rows = Vec::new();
        if tunnel {
            rows.push(vec![s("-o"), spec.tun.clone(), s("-j"), s("ACCEPT")]);
        }
        rows.extend(block.unwrap_or_default());
        let c = chain(false, f, 'F', rows);
        p.insert(Entry::Jump { v6: false, table: f.into(), from: "FORWARD".into(), chain: chain_name(&c) });
        p.insert(c);
    }
    if spec.uses(Act::Zapret) && !guard_only {
        // первые пакеты соединений в сторону сервера: по ним nfqws2 видит рукопожатие, остальное идёт мимо очереди
        let rows: Vec<Vec<String>> = spec
            .zapret_queue
            .iter()
            .map(|q| {
                let n = if q.proto == "udp" { QUEUE_PACKETS_UDP } else { QUEUE_PACKETS_TCP };
                vec![
                    s("-p"), q.proto.clone(), s("-m"), s("multiport"), s("--dports"), q.ports.replace('-', ":"),
                    s("-m"), s("connbytes"), s("--connbytes"), format!("1:{n}"), s("--connbytes-mode"), s("packets"), s("--connbytes-dir"), s("original"),
                    s("-j"), s("NFQUEUE"), s("--queue-num"), ZAPRET_QNUM.to_string(), s("--queue-bypass"),
                ]
            })
            .collect();
        if !rows.is_empty() {
            let leaf = chain(false, m, 'Q', rows);
            let q = chain_name(&leaf);
            if let Some(rows) = classify(spec, bridge_ports, |a| (a == Act::Zapret).then(|| vec![s("-g"), q.clone()])) {
                p.insert(leaf);
                let c = chain(false, m, 'Z', rows);
                p.insert(Entry::Jump { v6: false, table: m.into(), from: "FORWARD".into(), chain: chain_name(&c) });
                p.insert(c);
            }
        }
        // проверочный трафик подбора стратегии: соединения роутера с выделенных портов, кроме пакетов самого nfqws2
        let rows = ["tcp", "udp"]
            .iter()
            .map(|proto| {
                vec![
                    s("-p"), s(proto), s("-m"), s(proto), s("--sport"), s(ZAPRET_TEST_SPORTS), s("-m"), s("mark"), s("!"), s("--mark"),
                    fmt_mark(ZAPRET_DESYNC_MARK, ZAPRET_DESYNC_MARK), s("-j"), s("NFQUEUE"), s("--queue-num"), ZAPRET_TEST_QNUM.to_string(), s("--queue-bypass"),
                ]
            })
            .collect();
        let c = chain(false, m, 'P', rows);
        p.insert(Entry::Jump { v6: false, table: m.into(), from: "OUTPUT".into(), chain: chain_name(&c) });
        p.insert(c);
    }
    if !spec.v6_block.is_empty() {
        let mut rows: Vec<Vec<String>> = v6_lan_prefixes.iter().map(|x| vec![s("-d"), ipt_prefix(x), s("-j"), s("RETURN")]).collect();
        for src in &spec.v6_block {
            for mut v in src_variants(src, bridge_ports) {
                v.extend([s("-j"), s("REJECT"), s("--reject-with"), s("icmp6-port-unreachable")]);
                rows.push(v);
            }
        }
        let c = chain(true, f, '6', rows);
        p.insert(Entry::Jump { v6: true, table: f.into(), from: "FORWARD".into(), chain: chain_name(&c) });
        p.insert(c);
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
        let e = if extra || (lookup.is_some() == unreach) { Err(line.trim().to_string()) } else { Ok(Entry::Rule { v6, prio, from, to, iif, fwmark, lookup }) };
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

/// Глобальные и ULA префиксы из `ip -6 addr show dev X` (link-local не нужен: он не маршрутизируется).
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

/// Нормализация для сравнения с выводом `iptables -S`: без кавычек, MAC в верхнем регистре (так печатает iptables).
pub fn norm_spec(spec: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(spec.len());
    for t in spec {
        let t = t.trim_matches('"').to_string();
        let upper = out.last().is_some_and(|p| p == "--mac-source");
        out.push(if upper { t.to_ascii_uppercase() } else { t });
    }
    out
}

#[derive(Debug, Default, Clone)]
pub struct IptLive {
    pub v6: bool,
    pub table: String,
    pub chains: BTreeSet<String>,
    /// (цепочка, спецификация) для всех правил таблицы, по порядку.
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

/// Разбор `ipset list -t`: наши наборы (имя mitt*) как записи; набор с незнакомыми свойствами — исходный текст.
pub fn parse_ipsets(text: &str) -> Vec<(String, Result<Entry, String>)> {
    let mut out = Vec::new();
    for block in text.split("Name: ").skip(1) {
        let name = block.lines().next().unwrap_or_default().trim().to_string();
        if !name.starts_with(SET_PREFIX) {
            continue;
        }
        let field = |k: &str| block.lines().find_map(|l| l.strip_prefix(k)).map(|v| v.trim().to_string()).unwrap_or_default();
        let kind = field("Type:");
        let header: Vec<String> = field("Header:").split_whitespace().map(String::from).collect();
        let pos = |k: &str| header.iter().position(|w| w == k);
        let family = pos("family").and_then(|i| header.get(i + 1)).cloned();
        let timeout = pos("timeout").and_then(|i| header.get(i + 1)).and_then(|v| v.parse::<u32>().ok());
        let e = if family.as_deref() == Some("inet") && (kind == "hash:ip" || kind == "hash:net") {
            Ok(Entry::Ipset { name: name.clone(), kind, timeout })
        } else {
            Err(format!("{name}: {kind} {}", header.join(" ")))
        };
        out.push((name, e));
    }
    out
}

/// Маски меток в спецификации правила iptables (MARK и mark): значение не важно, важны затрагиваемые биты.
pub fn spec_mark_masks(spec: &[String]) -> Vec<u32> {
    let mut v = Vec::new();
    for (i, w) in spec.iter().enumerate() {
        if matches!(w.as_str(), "--set-xmark" | "--set-mark" | "--or-mark" | "--and-mark" | "--xor-mark" | "--mark") {
            if let Some(val) = spec.get(i + 1) {
                v.push(mark_parts(val).map(|(_, m)| m).unwrap_or(0xffff_ffff));
            }
        }
    }
    v
}

/// Маска всех меток, которые использует план (fwmark в правилах, MARK в цепочках). Отбор
/// `--mark 0x40000000/0x40000000` в цепочке P только читает метку nfqws2 и в маску не входит.
pub fn our_mark_mask<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> u32 {
    let mut m = 0;
    for e in entries {
        match e {
            Entry::Rule { fwmark: Some(f), .. } => m |= mark_parts(f).map(|(_, mask)| mask).unwrap_or(0),
            Entry::Chain { rows, .. } => {
                let desync = fmt_mark(ZAPRET_DESYNC_MARK, ZAPRET_DESYNC_MARK);
                for r in rows {
                    let skip = r.windows(2).position(|w| w[0] == "--mark" && w[1] == desync);
                    let r: Vec<String> = r.iter().enumerate().filter(|(i, _)| skip.is_none_or(|k| *i != k && *i != k + 1)).map(|(_, w)| w.clone()).collect();
                    m |= spec_mark_masks(&r).into_iter().fold(0, |a, b| a | b);
                }
            }
            _ => {}
        }
    }
    m
}

/// Метки MARK в выводе iptables-save, пересекающиеся с нашей маской.
pub fn iptables_mark_collisions(text: &str, ours: u32) -> Vec<String> {
    text.lines()
        .filter(|l| l.starts_with("-A ") && !l.contains(CHAIN_PREFIX))
        .filter(|l| {
            let t: Vec<String> = l.split_whitespace().map(String::from).collect();
            spec_mark_masks(&t).iter().any(|m| m & ours != 0)
        })
        .map(String::from)
        .collect()
}

#[derive(Debug, Default, Clone)]
pub struct Live {
    pub rules: Vec<(u32, Result<Entry, String>)>,
    pub routes: Vec<Result<Entry, String>>,
    pub ipt: Vec<IptLive>,
    pub ipsets: Vec<(String, Result<Entry, String>)>,
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
            Err(line)
                if line.contains("fwmark")
                    && line.split_whitespace().skip_while(|w| *w != "fwmark").nth(1).and_then(mark_parts).is_some_and(|(_, m)| m & ours_mask != 0) =>
            {
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
        let tool = ipt_prog(t.v6);
        for c in t.chains.iter().filter(|c| c.starts_with(CHAIN_PREFIX)) {
            let rows: Vec<Vec<String>> = t.rules.iter().filter(|(ch, _)| ch == c).map(|(_, s)| s.clone()).collect();
            let e = Entry::Chain { v6: t.v6, table: t.table.clone(), chain: c.clone(), rows };
            if known.contains(&e) {
                live_set.insert(e);
            } else {
                d.conflicts.push(format!("неучтённая или изменённая цепочка {tool} -t {} {c}", t.table));
            }
        }
        for (chain, spec) in t.rules.iter().filter(|(ch, _)| !ch.starts_with(CHAIN_PREFIX)) {
            let target = spec.windows(2).find(|w| (w[0] == "-j" || w[0] == "-g") && w[1].starts_with(CHAIN_PREFIX)).map(|w| w[1].clone());
            if let Some(target) = target {
                let e = Entry::Jump { v6: t.v6, table: t.table.clone(), from: chain.clone(), chain: target };
                if *spec == jump_spec(&chain_name_of(&e)) && known.contains(&e) {
                    live_set.insert(e);
                } else {
                    d.conflicts.push(format!("чужое или неучтённое правило {tool} -t {}: -A {chain} {}", t.table, spec.join(" ")));
                }
            } else if ours_mask != 0 && spec_mark_masks(spec).iter().any(|m| m & ours_mask != 0) {
                d.conflicts.push(format!("правило firewall {tool} -t {} задевает биты наших меток ({ours_mask:#x}): -A {chain} {}", t.table, spec.join(" ")));
            }
        }
    }
    for (name, s) in &live.ipsets {
        match s {
            Ok(e) if known.contains(e) => {
                live_set.insert(e.clone());
            }
            _ => d.conflicts.push(format!("неучтённый или изменённый набор ipset {name}")),
        }
    }
    let mut add: Vec<Entry> = desired.difference(&live_set).cloned().collect();
    add.sort_by_key(|e| (e.rank(), e.clone()));
    let mut del: Vec<Entry> = owned.intersection(&live_set).filter(|e| !desired.contains(*e)).cloned().collect();
    del.sort_by_key(|e| (std::cmp::Reverse(e.rank()), e.clone()));
    d.missing = owned.difference(&live_set).cloned().collect();
    d.live_in_zone = live_set.into_iter().collect();
    d.add = add;
    d.del = del;
    d
}

fn chain_name_of(e: &Entry) -> String {
    match e {
        Entry::Jump { chain, .. } | Entry::Chain { chain, .. } => chain.clone(),
        _ => String::new(),
    }
}

/// Таблицы iptables, состояние которых нужно прочитать (наши цепочки и переходы бывают только в них).
pub fn ipt_tables() -> BTreeSet<(bool, String)> {
    [(false, "filter"), (false, "mangle"), (true, "filter")].iter().map(|(v6, t)| (*v6, t.to_string())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> PolicySpec {
        PolicySpec {
            rules: vec![
                PolicyRule { from: "tv-video".into(), src: SrcMatch::Mac { bridge: "br-lan".into(), mac: "02:00:00:00:0a:02".into() }, set: Some("mitt0001d".into()), act: Act::Tunnel },
                PolicyRule { from: "guest-block".into(), src: SrcMatch::Network { bridge: "br-guest".into(), ports: vec!["r-gst".into()] }, set: Some("mitt0002n".into()), act: Act::Block },
                PolicyRule { from: "lan-zapret".into(), src: SrcMatch::Bridge { bridge: "br-lan".into() }, set: Some("mitt0003d".into()), act: Act::Zapret },
                PolicyRule { from: "lan-direct".into(), src: SrcMatch::Bridge { bridge: "br-lan".into() }, set: Some("mitt0004d".into()), act: Act::Direct },
            ],
            sets: vec![
                SetSpec { name: "mitt0001d".into(), kind: SetKind::Dns, entries: vec![] },
                SetSpec { name: "mitt0002n".into(), kind: SetKind::Static, entries: vec!["203.0.113.0/24".into()] },
                SetSpec { name: "mitt0003d".into(), kind: SetKind::Dns, entries: vec![] },
                SetSpec { name: "mitt0004d".into(), kind: SetKind::Dns, entries: vec![] },
            ],
            lan_subnets: vec!["10.10.1.0/24".into(), "10.10.2.0/24".into()],
            tun: "mitt0".into(),
            fail_open: false,
            zapret_queue: vec![QueueRule { proto: "tcp".into(), ports: "80,443".into() }, QueueRule { proto: "udp".into(), ports: "443".into() }],
            dns_resolver: Some("1.1.1.1".into()),
            v6_block: vec![SrcMatch::Mac { bridge: "br-lan".into(), mac: "02:00:00:00:0a:02".into() }],
        }
    }

    fn whole() -> BTreeMap<String, BTreeSet<String>> {
        [("br-lan".to_string(), ["r-tv".to_string()].into()), ("br-guest".to_string(), ["r-gst".to_string()].into())].into()
    }

    fn chain_rows<'a>(p: &'a BTreeSet<Entry>, table: &str, letter: char) -> &'a Vec<Vec<String>> {
        p.iter()
            .find_map(|e| match e {
                Entry::Chain { table: t, chain, rows, .. } if t == table && chain.starts_with(&format!("{CHAIN_PREFIX}{letter}")) => Some(rows),
                _ => None,
            })
            .unwrap_or_else(|| panic!("нет цепочки {letter} в {table}"))
    }

    #[test]
    fn plan_marks_tunnel_blocks_and_queues_in_rule_order() {
        let p = build_plan(&spec(), &["fd00:10::/64".into()], &whole(), false);
        let labels: BTreeSet<String> = p.iter().map(Entry::label).collect();
        for want in [
            "ip rule priority 3005 fwmark 0x4000/0x4000 lookup 3100",
            "ip rule priority 3000 to 10.10.1.0/24 lookup main",
            "ip route default dev mitt0 metric 1 table 3100",
            "ip route unreachable default metric 4096 table 3100",
            "ipset create mitt0001d hash:ip family inet timeout 86400",
            "ipset create mitt0002n hash:net family inet",
        ] {
            assert!(labels.contains(want), "нет {want}\n{labels:#?}");
        }
        let c = chain_rows(&p, "mangle", 'C');
        assert_eq!(c[0].join(" "), "-d 10.10.1.0/24 -j RETURN");
        assert!(c[2].join(" ").starts_with("-i br-lan -m mac --mac-source 02:00:00:00:0A:02 -m set --match-set mitt0001d dst -g MITT_T"), "{c:#?}");
        // хвост из RETURN после последнего туннельного правила отброшен
        assert_eq!(c.len(), 3, "{c:#?}");
        let f = chain_rows(&p, "filter", 'F');
        assert_eq!(f[0].join(" "), "-o mitt0 -j ACCEPT");
        assert!(f.iter().any(|r| r.join(" ") == "-i br-guest -m set --match-set mitt0002n dst -j REJECT --reject-with icmp-port-unreachable"), "{f:#?}");
        let z = chain_rows(&p, "mangle", 'Z');
        // туннельное и блокирующее правила стоят раньше и останавливают разбор (RETURN), Zapret — goto в очередь
        assert!(z.iter().any(|r| r.join(" ").starts_with("-i br-lan -m set --match-set mitt0003d dst -g MITT_Q")), "{z:#?}");
        assert!(z.iter().any(|r| r.join(" ").ends_with("mitt0001d dst -j RETURN")), "{z:#?}");
        let o = chain_rows(&p, "mangle", 'O');
        assert_eq!(o[0].join(" "), "-d 1.1.1.1/32 -p udp -m udp --dport 53 -j MARK --set-xmark 0x4000/0x4000");
        let v6 = chain_rows(&p, "filter", '6');
        assert_eq!(v6[0].join(" "), "-d fd00:10::/64 -j RETURN");
        assert!(p.iter().any(|e| matches!(e, Entry::Jump { v6: true, from, .. } if from == "FORWARD")));
        assert_eq!(our_mark_mask(&p), NF_MARK);
    }

    #[test]
    fn guard_only_and_fail_open() {
        let p = build_plan(&spec(), &[], &whole(), true);
        assert!(!p.iter().any(Entry::is_tun_route) && p.contains(&Entry::guard_route()));
        assert!(!p.iter().any(|e| e.label().contains("MITT_Q") || e.label().contains("MITT_Z")), "при загрузке очереди нет");
        let mut s = spec();
        s.fail_open = true;
        let p = build_plan(&s, &[], &whole(), false);
        assert!(!p.contains(&Entry::guard_route()), "обход при отказе: без unreachable");
    }

    #[test]
    fn zapret_queue_tcp_udp_with_connbytes() {
        let p = build_plan(&spec(), &[], &whole(), false);
        // вид `iptables -S` (iptables 1.6.2/1.8): --connbytes-mode печатается перед --connbytes-dir
        let q: Vec<String> = chain_rows(&p, "mangle", 'Q').iter().map(|r| r.join(" ")).collect();
        assert_eq!(q, [
            "-p tcp -m multiport --dports 80,443 -m connbytes --connbytes 1:25 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 200 --queue-bypass",
            "-p udp -m multiport --dports 443 -m connbytes --connbytes 1:5 --connbytes-mode packets --connbytes-dir original -j NFQUEUE --queue-num 200 --queue-bypass",
        ]);
        // диапазоны каталога (a-b) — в записи multiport (a:b)
        let mut s = spec();
        s.zapret_queue = vec![QueueRule { proto: "udp".into(), ports: "443,19294-19344,50000-50100".into() }];
        let q = chain_rows(&build_plan(&s, &[], &whole(), false), "mangle", 'Q')[0].join(" ");
        assert!(q.starts_with("-p udp -m multiport --dports 443,19294:19344,50000:50100 -m connbytes --connbytes 1:5 "), "{q}");
    }

    #[test]
    fn test_queue_only_router_sports() {
        let p = build_plan(&spec(), &[], &whole(), false);
        let rows: Vec<String> = chain_rows(&p, "mangle", 'P').iter().map(|r| r.join(" ")).collect();
        assert_eq!(rows, [
            "-p tcp -m tcp --sport 61000:61099 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 201 --queue-bypass",
            "-p udp -m udp --sport 61000:61099 -m mark ! --mark 0x40000000/0x40000000 -j NFQUEUE --queue-num 201 --queue-bypass",
        ]);
        // диапазон выше эфемерных портов Linux (32768–60999): случайные соединения роутера в очередь 201 не попадают
        let (lo, hi) = ZAPRET_TEST_SPORTS.split_once(':').map(|(a, b)| (a.parse::<u16>().unwrap(), b.parse::<u16>().unwrap())).unwrap();
        assert!(lo > 60999 && lo <= hi, "{ZAPRET_TEST_SPORTS}");
        assert!(p.iter().any(|e| matches!(e, Entry::Jump { v6: false, table, from, chain } if table == "mangle" && from == "OUTPUT" && chain.starts_with("MITT_P"))), "{p:#?}");
        // без правил Zapret нет ни очереди, ни проверочной цепочки
        let mut s = spec();
        s.rules.retain(|r| r.act != Act::Zapret);
        let p = build_plan(&s, &[], &whole(), false);
        assert!(!p.iter().any(|e| ["MITT_Q", "MITT_Z", "MITT_P"].iter().any(|x| e.label().contains(x))), "{p:#?}");
    }

    #[test]
    fn mark_mask_ignores_only_desync_mark_match() {
        let p = build_plan(&spec(), &[], &whole(), false);
        assert_eq!(our_mark_mask(&p), NF_MARK, "отбор метки nfqws2 в P — не наша метка");
        // любой другой отбор --mark в наших цепочках входит в маску
        let other = chain(false, "mangle", 'X', vec![vec!["-m".into(), "mark".into(), "--mark".into(), "0x100/0x100".into(), "-j".into(), "RETURN".into()]]);
        assert_eq!(our_mark_mask(&[other]), 0x100);
        let neg = chain(false, "mangle", 'X', vec![vec!["-m".into(), "mark".into(), "!".into(), "--mark".into(), "0x40000000/0x40000001".into(), "-j".into(), "RETURN".into()]]);
        assert_eq!(our_mark_mask(&[neg]), 0x4000_0001);
    }

    #[test]
    fn guard_only_has_no_queues() {
        let p = build_plan(&spec(), &[], &whole(), true);
        assert!(!p.iter().any(|e| e.label().contains("NFQUEUE") || ["MITT_Q", "MITT_Z", "MITT_P"].iter().any(|x| e.label().contains(x))), "{p:#?}");
    }

    #[test]
    fn partial_bridge_network_uses_physdev() {
        let bp: BTreeMap<String, BTreeSet<String>> = [("br-guest".to_string(), ["r-gst".to_string(), "r-kid".to_string()].into())].into();
        assert!(needs_physdev(&spec(), &bp));
        let p = build_plan(&spec(), &[], &bp, false);
        let f = chain_rows(&p, "filter", 'F');
        assert!(f.iter().any(|r| r.join(" ").starts_with("-m physdev --physdev-in r-gst -m set --match-set mitt0002n dst -j REJECT")), "{f:#?}");
        assert!(!needs_physdev(&spec(), &whole()));
    }

    #[test]
    fn chain_names_follow_content() {
        let a = build_plan(&spec(), &[], &whole(), false);
        let mut s = spec();
        s.rules.swap(0, 1);
        let b = build_plan(&s, &[], &whole(), false);
        let names = |p: &BTreeSet<Entry>| p.iter().filter_map(|e| if let Entry::Chain { chain, .. } = e { Some(chain.clone()) } else { None }).collect::<BTreeSet<_>>();
        assert_ne!(names(&a), names(&b), "другой порядок — другие цепочки классификации");
        assert!(names(&a).intersection(&names(&b)).any(|n| n.starts_with("MITT_T")), "лист с меткой не меняется");
        let d = reconcile(&b, &a, &Live::default());
        let ranks: Vec<u8> = d.add.iter().map(Entry::rank).collect();
        assert!(ranks.windows(2).all(|w| w[0] <= w[1]));
        assert!(matches!(d.add[0], Entry::Ipset { .. }) && matches!(d.add.last().unwrap(), Entry::Jump { .. }));
    }

    /// Вывод iptables -S, как его печатает iptables.
    fn live_from(p: &BTreeSet<Entry>) -> Live {
        let mut l = Live::default();
        for (v6, table) in ipt_tables() {
            let mut text = String::new();
            for e in p {
                match e {
                    Entry::Chain { v6: v, table: t, chain, .. } if *v == v6 && *t == table => text.push_str(&format!("-N {chain}\n")),
                    _ => {}
                }
            }
            for e in p {
                match e {
                    Entry::Jump { v6: v, table: t, from, chain } if *v == v6 && *t == table => text.push_str(&format!("-A {from} {}\n", jump_spec(chain).join(" "))),
                    Entry::Chain { v6: v, table: t, chain, rows } if *v == v6 && *t == table => {
                        for r in rows {
                            text.push_str(&format!("-A {chain} {}\n", r.join(" ")));
                        }
                    }
                    _ => {}
                }
            }
            l.ipt.push(parse_ipt(&text, v6, &table));
        }
        l.rules = p.iter().filter_map(|e| if let Entry::Rule { prio, .. } = e { Some((*prio, Ok(e.clone()))) } else { None }).collect();
        l.routes = p.iter().filter(|e| matches!(e, Entry::Route { .. })).map(|e| Ok(e.clone())).collect();
        l.ipsets = p.iter().filter_map(|e| if let Entry::Ipset { name, .. } = e { Some((name.clone(), Ok(e.clone()))) } else { None }).collect();
        l
    }

    #[test]
    fn live_round_trip_and_foreign_entries() {
        let p = build_plan(&spec(), &["fd00:10::/64".into()], &whole(), false);
        let d = reconcile(&p, &p, &live_from(&p));
        assert!(d.is_noop() && d.conflicts.is_empty(), "{d:#?}");
        let mut l = live_from(&p);
        l.ipt[0].rules.push(("FORWARD".into(), jump_spec("MITT_OLD")));
        l.ipt[0].chains.insert("MITT_X0".into());
        l.ipsets.push(("mittold".into(), Err("mittold".into())));
        l.rules.push((3150, parse_rules("3150:\tfrom 10.9.9.9 lookup 300\n", false).remove(0).1));
        let d = reconcile(&p, &p, &l);
        assert_eq!(d.conflicts.len(), 4, "{:#?}", d.conflicts);
        // снятие: переходы первыми, наборы последними
        let r = reconcile(&BTreeSet::new(), &p, &live_from(&p));
        assert!(matches!(r.del[0], Entry::Jump { .. }) && matches!(r.del.last().unwrap(), Entry::Ipset { .. }), "{:#?}", r.del);
    }

    #[test]
    fn ipset_listing_parses() {
        let t = "Name: mitt0001d\nType: hash:ip\nRevision: 4\nHeader: family inet hashsize 1024 maxelem 65536 timeout 86400\nSize in memory: 120\nReferences: 1\nNumber of entries: 0\nMembers:\n\nName: other\nType: hash:ip\nHeader: family inet hashsize 1024 maxelem 65536\n\nName: mitt0002n\nType: hash:net\nRevision: 6\nHeader: family inet hashsize 1024 maxelem 65536\n";
        let s = parse_ipsets(t);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].1, Ok(Entry::Ipset { name: "mitt0001d".into(), kind: "hash:ip".into(), timeout: Some(86400) }));
        assert_eq!(s[1].1, Ok(Entry::Ipset { name: "mitt0002n".into(), kind: "hash:net".into(), timeout: None }));
    }

    #[test]
    fn stock_firewall_marks_conflict_with_our_bit() {
        // реальные правила стока: mwan3 sticky (0xfc00 задевает 0x4000), QoS (0xff000000, не задевает)
        let fw = "-N mwan3_rule_x\n-A mwan3_rule_x -m mark ! --mark 0xfc00/0xfc00 -j SET --del-set mwan3_sticky_x src,src\n-A PREROUTING -m mac --mac-source 02:aa:bb:cc:dd:ee -j MARK --set-xmark 0x5000000/0xff000000\n";
        let mut l = live_from(&BTreeSet::new());
        l.ipt[1] = parse_ipt(fw, false, "mangle");
        let p = build_plan(&spec(), &[], &whole(), false);
        let d = reconcile(&p, &BTreeSet::new(), &l);
        assert_eq!(d.conflicts.len(), 1, "{:#?}", d.conflicts);
        assert!(d.conflicts[0].contains("0xfc00"));
        assert_eq!(iptables_mark_collisions(fw, NF_MARK).len(), 1);
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
}
