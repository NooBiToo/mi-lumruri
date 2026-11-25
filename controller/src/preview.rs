//! Предварительный просмотр правила: порядок вычисления, перекрытия, выход при отказе и пробные запросы.
//! Ничего не применяет: результат — описание того, что изменилось бы в выборе маршрута.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::model::*;
use crate::validate::*;

pub const MAX_PROBES: usize = 16;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    pub rule: Rule,
    #[serde(default)]
    pub probes: Vec<Probe>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    pub host: String,
}

#[derive(Debug, Serialize)]
pub struct Preview {
    /// Всегда false: срез только показывает, что изменилось бы.
    pub applied: bool,
    pub mode: &'static str,
    pub rule: Rule,
    pub level: u8,
    pub level_label: &'static str,
    pub position: usize,
    pub order: Vec<OrderEntry>,
    pub destinations: Vec<String>,
    pub affected_devices: Vec<DeviceRef>,
    pub affects_unknown_clients: bool,
    pub exit: String,
    pub on_failure: Option<String>,
    pub findings: Vec<Finding>,
    pub match_entries: Vec<MatchEntry>,
    pub probes: Vec<ProbeResult>,
}

#[derive(Debug, Serialize)]
pub struct OrderEntry {
    pub position: usize,
    pub rule_id: String,
    pub level: u8,
    pub source: String,
    pub destination: String,
    pub exit: String,
    pub draft: bool,
}

#[derive(Debug, Serialize)]
pub struct DeviceRef {
    pub id: String,
    pub name: String,
    pub mac: String,
    pub network: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub severity: &'static str,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct MatchEntry {
    pub position: usize,
    pub source: String,
    pub destination: String,
    pub exit: String,
    pub on_failure: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct Decision {
    pub rule_id: Option<String>,
    pub exit: String,
}

#[derive(Debug, Serialize)]
pub struct ProbeResult {
    pub subject: String,
    pub host: String,
    pub before: Decision,
    pub after: Decision,
    pub changed: bool,
}

// ---------- развёрнутые назначения ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dest {
    Domain(String),
    Suffix(String),
    Net(Cidr),
    /// Категория: записи в отдельном списке; в предпросмотре не раскрывается, пересекается только сама с собой.
    Category(String),
}

impl Dest {
    pub fn label(&self) -> String {
        match self {
            Dest::Domain(d) => format!("домен {d}"),
            Dest::Suffix(s) => format!("*.{s} и {s}"),
            Dest::Net(c) => format!("подсеть {c}"),
            Dest::Category(id) => format!("категория {id}"),
        }
    }
    /// `self` включает все адреса/имена `other`.
    pub fn covers(&self, other: &Dest) -> bool {
        match (self, other) {
            (Dest::Domain(a), Dest::Domain(b)) => a == b,
            (Dest::Suffix(s), Dest::Domain(d) | Dest::Suffix(d)) => under(d, s),
            (Dest::Net(a), Dest::Net(b)) => a.contains(b),
            (Dest::Category(a), Dest::Category(b)) => a == b,
            _ => false,
        }
    }
    pub fn overlaps(&self, other: &Dest) -> bool {
        match (self, other) {
            (Dest::Net(a), Dest::Net(b)) => a.overlaps(b),
            _ => self.covers(other) || other.covers(self),
        }
    }
    fn matches(&self, host: &Host) -> bool {
        match (self, host) {
            (Dest::Domain(d), Host::Name(h)) => d == h,
            (Dest::Suffix(s), Host::Name(h)) => under(h, s),
            (Dest::Net(c), Host::Ip(ip)) => c.contains_ip(*ip),
            _ => false,
        }
    }
}

fn under(name: &str, suffix: &str) -> bool {
    name == suffix || (name.len() > suffix.len() && name.ends_with(suffix) && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

/// Разворачивает назначение (с группами) в нормализованный список. Вызывать после проверки.
pub fn expand(d: &Destination, idx: &Index) -> Vec<Dest> {
    match d {
        Destination::Domain { value } => normalize_domain(value, 2).map(Dest::Domain).into_iter().collect(),
        Destination::DomainSuffix { value } => normalize_domain(value, 1).map(Dest::Suffix).into_iter().collect(),
        Destination::Cidr { value } => parse_cidr(value).map(Dest::Net).into_iter().collect(),
        Destination::Category { id } => vec![Dest::Category(id.clone())],
        Destination::Group { id } => idx
            .groups
            .get(id.as_str())
            .map(|g| g.destinations.iter().flat_map(|x| expand(x, idx)).collect())
            .unwrap_or_default(),
    }
}

pub fn normalize_destination(d: &Destination) -> Destination {
    match d {
        Destination::Domain { value } => Destination::Domain { value: normalize_domain(value, 2).unwrap_or_else(|_| value.clone()) },
        Destination::DomainSuffix { value } => Destination::DomainSuffix { value: normalize_domain(value, 1).unwrap_or_else(|_| value.clone()) },
        Destination::Cidr { value } => Destination::Cidr { value: parse_cidr(value).map(|c| c.to_string()).unwrap_or_else(|_| value.clone()) },
        g @ (Destination::Group { .. } | Destination::Category { .. }) => g.clone(),
    }
}

// ---------- подписи ----------

fn source_label(s: &Source, idx: &Index) -> String {
    match s {
        Source::Device { id } => match idx.devices.get(id.as_str()) {
            Some(d) => format!("устройство «{}» ({})", d.name, normalize_mac(&d.mac).unwrap_or_else(|_| d.mac.clone())),
            None => format!("устройство {id}"),
        },
        Source::Network { id } => match idx.networks.get(id.as_str()) {
            Some(n) => format!("сеть «{}» (SSID {})", n.name, n.ssid),
            None => format!("сеть {id}"),
        },
        Source::Lan => "вся LAN".into(),
    }
}

fn destination_label(d: &Destination, idx: &Index) -> String {
    match d {
        Destination::Group { id } => match idx.groups.get(id.as_str()) {
            Some(g) => format!("группа «{}»", g.name),
            None => format!("группа {id}"),
        },
        Destination::Category { id } => match idx.categories.get(id.as_str()) {
            Some(c) => format!("категория «{}»", c.name),
            None => format!("категория {id}"),
        },
        other => expand(other, idx).first().map(Dest::label).unwrap_or_default(),
    }
}

pub fn action_label(a: &Action, idx: &Index) -> String {
    match a {
        Action::Profile { id } => match idx.profiles.get(id.as_str()) {
            Some(p) => format!("VPN «{}» ({})", p.name, p.kind.label()),
            None => format!("VPN {id}"),
        },
        Action::Direct => "прямой выход".into(),
        Action::DirectZapret => "прямой выход с Zapret".into(),
        Action::Block => "блокировка".into(),
        Action::TgWs => "Telegram через WebSocket".into(),
    }
}

fn failure_label(a: &Action, idx: &Index) -> Option<String> {
    let Action::Profile { id } = a else { return None };
    let p = idx.profiles.get(id.as_str())?;
    Some(match p.on_failure {
        FailurePolicy::Block => "блокировать трафик правила".into(),
        FailurePolicy::Direct => "выпустить напрямую в обход VPN".into(),
    })
}

fn level_label(level: u8) -> &'static str {
    match level {
        1 => "правила устройств",
        2 => "правила сетей",
        _ => "общие правила LAN",
    }
}

// ---------- отношения источников ----------

#[derive(PartialEq, Eq, Clone, Copy)]
enum Rel {
    None,
    Covers,
    Partial,
}

/// Насколько клиенты источника `a` покрывают клиентов источника `b`.
fn source_rel(a: &Source, b: &Source, idx: &Index) -> Rel {
    let net_of = |id: &str| idx.devices.get(id).map(|d| d.network.as_str());
    match (a, b) {
        (Source::Lan, _) => Rel::Covers,
        (Source::Network { .. }, Source::Lan) => Rel::Partial,
        (Source::Network { id: n }, Source::Network { id: m }) => if n == m { Rel::Covers } else { Rel::None },
        (Source::Network { id: n }, Source::Device { id: d }) => if net_of(d) == Some(n.as_str()) { Rel::Covers } else { Rel::None },
        (Source::Device { id: x }, Source::Device { id: y }) => if x == y { Rel::Covers } else { Rel::None },
        (Source::Device { id: x }, Source::Network { id: m }) => if net_of(x) == Some(m.as_str()) { Rel::Partial } else { Rel::None },
        (Source::Device { .. }, Source::Lan) => Rel::Partial,
    }
}

/// Включённые правила в порядке вычисления: уровень, затем порядок пользователя.
pub fn evaluation_order(rules: &[Rule]) -> Vec<&Rule> {
    let mut v: Vec<&Rule> = rules.iter().filter(|r| r.enabled).collect();
    v.sort_by_key(|r| r.source.level()); // устойчивая сортировка сохраняет порядок внутри уровня
    v
}

// ---------- пробные запросы ----------

enum Host {
    Name(String),
    Ip(IpAddr),
}

struct Subject<'a> {
    device: Option<&'a str>,
    network: &'a str,
}

fn decide(cfg: &Config, rules: &[Rule], idx: &Index, s: &Subject, host: &Host) -> Decision {
    for r in evaluation_order(rules) {
        let src_ok = match &r.source {
            Source::Device { id } => s.device == Some(id.as_str()),
            Source::Network { id } => s.network == id,
            Source::Lan => true,
        };
        if src_ok && expand(&r.destination, idx).iter().any(|d| d.matches(host)) {
            return Decision { rule_id: Some(r.id.clone()), exit: action_label(&r.action, idx) };
        }
    }
    Decision { rule_id: None, exit: format!("маршрут по умолчанию: {}", action_label(&cfg.default_action, idx)) }
}

fn check_probes(issues: &mut Vec<Issue>, probes: &[Probe], idx: &Index) {
    if probes.len() > MAX_PROBES {
        issues.push(Issue::new("probes", "too_many", format!("не больше {MAX_PROBES} пробных запросов")));
        return;
    }
    for (i, p) in probes.iter().enumerate() {
        let path = format!("probes[{i}]");
        match (&p.device, &p.network) {
            (Some(d), None) if !idx.devices.contains_key(d.as_str()) => {
                issues.push(Issue::new(format!("{path}.device"), "unknown_device", format!("устройство «{d}» не найдено")))
            }
            (None, Some(n)) if !idx.networks.contains_key(n.as_str()) => {
                issues.push(Issue::new(format!("{path}.network"), "unknown_network", format!("сеть «{n}» не найдена")))
            }
            (Some(_), Some(_)) | (None, None) => {
                issues.push(Issue::new(path.clone(), "bad_probe", "укажите ровно одно из полей device или network"))
            }
            _ => {}
        }
        if p.host.parse::<IpAddr>().is_err() {
            if let Err(e) = normalize_domain(&p.host, 1) {
                issues.push(Issue::new(format!("{path}.host"), "bad_host", e));
            }
        }
    }
}

// ---------- предварительный просмотр ----------

pub fn preview(cfg: &Config, req: &PreviewRequest) -> Result<Preview, Vec<Issue>> {
    let base = validate_config(cfg);
    if !base.is_empty() {
        return Err(base.into_iter().map(|i| Issue { path: format!("config.{}", i.path), ..i }).collect());
    }
    let idx = Index::new(cfg);
    let mut issues = Vec::new();
    check_rule_refs(&mut issues, "rule", &req.rule, &idx);
    check_probes(&mut issues, &req.probes, &idx);
    if !issues.is_empty() {
        return Err(issues);
    }

    let mut draft = req.rule.clone();
    draft.destination = normalize_destination(&draft.destination);

    let mut new_rules = cfg.rules.clone();
    let mode = match new_rules.iter().position(|r| r.id == draft.id) {
        Some(i) => {
            new_rules[i] = draft.clone();
            "replace"
        }
        None => {
            if new_rules.len() >= MAX_RULES {
                return Err(vec![Issue::new("rule", "too_many", format!("не больше {MAX_RULES} правил"))]);
            }
            new_rules.push(draft.clone());
            "add"
        }
    };

    let ordered = evaluation_order(&new_rules);
    let order: Vec<OrderEntry> = ordered
        .iter()
        .enumerate()
        .map(|(i, r)| OrderEntry {
            position: i + 1,
            rule_id: r.id.clone(),
            level: r.source.level(),
            source: source_label(&r.source, &idx),
            destination: destination_label(&r.destination, &idx),
            exit: action_label(&r.action, &idx),
            draft: r.id == draft.id,
        })
        .collect();
    let draft_pos = ordered.iter().position(|r| r.id == draft.id);

    let dests = expand(&draft.destination, &idx);
    let mut findings = Vec::new();

    if !draft.enabled {
        findings.push(Finding { severity: "info", code: "disabled", message: "правило выключено и не участвует в выборе маршрута".into() });
    }
    if let Some(p) = draft_pos {
        // правила выше по порядку, которые перехватывают трафик черновика
        let mut shadowed = vec![false; dests.len()];
        for e in &ordered[..p] {
            let rel = source_rel(&e.source, &draft.source, &idx);
            if rel == Rel::None {
                continue;
            }
            let edests = expand(&e.destination, &idx);
            let mut covered = Vec::new();
            let mut touched = Vec::new();
            for (i, d) in dests.iter().enumerate() {
                if rel == Rel::Covers && edests.iter().any(|x| x.covers(d)) {
                    shadowed[i] = true;
                    covered.push(d.label());
                } else if edests.iter().any(|x| x.overlaps(d)) {
                    touched.push(d.label());
                }
            }
            let exit = action_label(&e.action, &idx);
            if !covered.is_empty() {
                findings.push(Finding { severity: "warning", code: "shadowed_by",
                    message: format!("правило «{}» выше по порядку уже отправляет {} → {exit}", e.id, short(&covered)) });
            }
            if !touched.is_empty() {
                findings.push(Finding { severity: "warning", code: "partially_shadowed_by",
                    message: format!("правило «{}» выше по порядку перехватывает часть трафика ({}) → {exit}", e.id, short(&touched)) });
            }
        }
        if !dests.is_empty() && shadowed.iter().all(|s| *s) {
            findings.push(Finding { severity: "warning", code: "never_matches", message: "правило полностью перекрыто и не сработает".into() });
        }
        // правила ниже по порядку, у которых черновик забирает часть трафика
        for l in &ordered[p + 1..] {
            if source_rel(&l.source, &draft.source, &idx) == Rel::None && source_rel(&draft.source, &l.source, &idx) == Rel::None {
                continue;
            }
            let ldests = expand(&l.destination, &idx);
            let hit: Vec<String> = dests.iter().filter(|d| ldests.iter().any(|x| x.overlaps(d))).map(Dest::label).collect();
            if !hit.is_empty() && l.action != draft.action {
                findings.push(Finding { severity: "info", code: "overrides",
                    message: format!("правило «{}» ({}) больше не применяется к источнику «{}» для назначений: {}",
                        l.id, action_label(&l.action, &idx), source_label(&draft.source, &idx), short(&hit)) });
            }
        }
    }
    if let Action::Profile { id } = &draft.action {
        if let Some(p) = idx.profiles.get(id.as_str()) {
            if p.endpoint.is_none() {
                findings.push(Finding { severity: "warning", code: "profile_not_ready",
                    message: format!("у профиля «{}» не задана точка подключения: правило сохранится, но применить его нельзя", p.name) });
            }
            findings.push(match p.on_failure {
                FailurePolicy::Block => Finding { severity: "info", code: "fail_closed",
                    message: format!("при недоступности {} трафик этого правила блокируется, обход VPN не выполняется", p.kind.label()) },
                FailurePolicy::Direct => Finding { severity: "warning", code: "fail_open",
                    message: format!("при недоступности {} трафик этого правила уйдёт напрямую в обход VPN", p.kind.label()) },
            });
        }
    }
    if dests.iter().any(|d| !matches!(d, Dest::Net(_))) {
        findings.push(Finding { severity: "info", code: "dns_dependency",
            message: "доменные назначения работают, пока клиент спрашивает DNS у роутера; собственный DoH на устройстве обходит фильтр".into() });
    }
    if let Source::Device { .. } = draft.source {
        findings.push(Finding { severity: "info", code: "mac_binding",
            message: "устройство определяется по MAC; при случайном MAC (частный адрес Wi-Fi) правило не сработает".into() });
    }

    let affected_devices = cfg
        .devices
        .iter()
        .filter(|d| source_rel(&draft.source, &Source::Device { id: d.id.clone() }, &idx) == Rel::Covers)
        .map(|d| DeviceRef {
            id: d.id.clone(),
            name: d.name.clone(),
            mac: normalize_mac(&d.mac).unwrap_or_else(|_| d.mac.clone()),
            network: d.network.clone(),
        })
        .collect();

    let position = draft_pos.map(|p| p + 1).unwrap_or(0);
    let exit = action_label(&draft.action, &idx);
    let on_failure = failure_label(&draft.action, &idx);
    let match_entries = if draft.enabled {
        dests
            .iter()
            .map(|d| MatchEntry {
                position,
                source: source_label(&draft.source, &idx),
                destination: d.label(),
                exit: exit.clone(),
                on_failure: on_failure.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };

    let probes = req
        .probes
        .iter()
        .map(|p| {
            let (subject_label, subject) = match (&p.device, &p.network) {
                (Some(d), _) => {
                    let dev = idx.devices[d.as_str()];
                    (format!("устройство «{}»", dev.name), Subject { device: Some(d.as_str()), network: dev.network.as_str() })
                }
                (None, Some(n)) => (format!("новый клиент сети «{}»", idx.networks[n.as_str()].name), Subject { device: None, network: n.as_str() }),
                (None, None) => unreachable!("проверено в check_probes"),
            };
            let host = match p.host.parse::<IpAddr>() {
                Ok(ip) => Host::Ip(ip),
                Err(_) => Host::Name(normalize_domain(&p.host, 1).unwrap_or_default()),
            };
            let before = decide(cfg, &cfg.rules, &idx, &subject, &host);
            let after = decide(cfg, &new_rules, &idx, &subject, &host);
            ProbeResult { subject: subject_label, host: p.host.clone(), changed: before != after, before, after }
        })
        .collect();

    Ok(Preview {
        applied: false,
        mode,
        level: draft.source.level(),
        level_label: level_label(draft.source.level()),
        position,
        order,
        destinations: dests.iter().map(Dest::label).collect(),
        affected_devices,
        affects_unknown_clients: !matches!(draft.source, Source::Device { .. }),
        exit,
        on_failure,
        findings,
        match_entries,
        probes,
        rule: draft,
    })
}

fn short(items: &[String]) -> String {
    const N: usize = 3;
    if items.len() <= N {
        items.join(", ")
    } else {
        format!("{} и ещё {}", items[..N].join(", "), items.len() - N)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_relations() {
        let s = Dest::Suffix("youtube.com".into());
        assert!(s.covers(&Dest::Domain("www.youtube.com".into())));
        assert!(s.covers(&Dest::Domain("youtube.com".into())));
        assert!(!s.covers(&Dest::Domain("notyoutube.com".into())));
        assert!(s.covers(&Dest::Suffix("m.youtube.com".into())));
        assert!(!Dest::Suffix("m.youtube.com".into()).covers(&s));
        assert!(Dest::Suffix("m.youtube.com".into()).overlaps(&s));
        assert!(!Dest::Domain("www.youtube.com".into()).covers(&s));
        assert!(Dest::Domain("www.youtube.com".into()).overlaps(&s));
    }
}
