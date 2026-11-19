//! Хранение настроек: ревизия по SHA-256, межпроцессная блокировка, атомарная запись с копией предыдущей версии.
//! Каждый CGI-запрос — отдельный процесс, поэтому защита от одновременной записи — файловая блокировка
//! плюс оптимистическая проверка ревизии, на которой пользователь видел настройки.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::model::{Config, Rule};
use crate::preview::normalize_destination;
use crate::validate::{Index, Issue, MAX_RULES, check_rule_refs, validate_config};

pub const LOCK_TIMEOUT: Duration = Duration::from_secs(3);

pub fn revision(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(suffix);
    path.with_file_name(name)
}

/// Эксклюзивная блокировка `<config>.lock`; снимается при закрытии файла (в том числе при аварийном завершении).
pub fn lock(path: &Path) -> Result<File, String> {
    let lp = sidecar(path, ".lock");
    let f = OpenOptions::new().create(true).truncate(false).write(true).open(&lp).map_err(|e| format!("не удалось открыть {}: {e}", lp.display()))?;
    let start = Instant::now();
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(f),
            Err(TryLockError::WouldBlock) if start.elapsed() < LOCK_TIMEOUT => std::thread::sleep(Duration::from_millis(15)),
            Err(TryLockError::WouldBlock) => return Err("настройки заняты другой записью".into()),
            Err(TryLockError::Error(e)) => return Err(format!("блокировка не удалась: {e}")),
        }
    }
}

/// Запись через временный файл в том же каталоге, fsync и rename. Читатель видит либо старую, либо новую версию.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.tmp.{}", std::process::id()));
    let res = (|| -> std::io::Result<()> {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            let d = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
            File::open(d)?.sync_all()?;
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(|e| format!("не удалось записать {}: {e}", path.display()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveRequest {
    pub base_revision: String,
    pub rule: Rule,
}

pub enum SaveError {
    Busy(String),
    Io(String),
    Conflict { current: String },
    ConfigInvalid(Vec<Issue>),
    RuleInvalid(Vec<Issue>),
}

pub struct Saved {
    pub mode: &'static str,
    pub previous_revision: String,
    pub revision: String,
    pub config: Config,
}

/// Добавляет или заменяет правило по id. Пишет только если ревизия совпала и вся новая конфигурация проходит проверку.
pub fn save_rule(path: &Path, req: &SaveRequest, max_bytes: u64) -> Result<Saved, SaveError> {
    update_config(path, &req.base_revision, max_bytes, |cfg| {
        let mut issues = Vec::new();
        check_rule_refs(&mut issues, "rule", &req.rule, &Index::new(cfg));
        if !issues.is_empty() {
            return Err(issues);
        }
        let mut rule = req.rule.clone();
        rule.destination = normalize_destination(&rule.destination);
        Ok(match cfg.rules.iter().position(|r| r.id == rule.id) {
            Some(i) => {
                cfg.rules[i] = rule;
                "replace"
            }
            None => {
                if cfg.rules.len() >= MAX_RULES {
                    return Err(vec![Issue::new("rule", "too_many", format!("не больше {MAX_RULES} правил"))]);
                }
                cfg.rules.push(rule);
                "add"
            }
        })
    })
}

/// Общий путь изменения настроек: блокировка, проверка ревизии, проверка текущих настроек, изменение `f`,
/// проверка всей новой конфигурации, копия предыдущей версии и атомарная запись. Ошибка `f` — RuleInvalid (422).
pub fn update_config(path: &Path, base_revision: &str, max_bytes: u64, f: impl FnOnce(&mut Config) -> Result<&'static str, Vec<Issue>>) -> Result<Saved, SaveError> {
    let _guard = lock(path).map_err(SaveError::Busy)?;
    let current = crate::api::read_limited(&path.to_string_lossy(), max_bytes).map_err(SaveError::Io)?;
    let current_rev = revision(&current);
    if !base_revision.eq_ignore_ascii_case(&current_rev) {
        return Err(SaveError::Conflict { current: current_rev });
    }
    let mut cfg: Config = crate::api::parse_json(&current, "").map_err(|i| SaveError::ConfigInvalid(prefix(i)))?;
    let base = validate_config(&cfg);
    if !base.is_empty() {
        return Err(SaveError::ConfigInvalid(prefix(base)));
    }
    let mode = f(&mut cfg).map_err(SaveError::RuleInvalid)?;
    let after = validate_config(&cfg);
    if !after.is_empty() {
        return Err(SaveError::RuleInvalid(after));
    }
    let mut out = serde_json::to_vec_pretty(&cfg).map_err(|e| SaveError::Io(e.to_string()))?;
    out.push(b'\n');
    if out.len() as u64 > max_bytes {
        return Err(SaveError::RuleInvalid(vec![Issue::new("rule", "too_large", "настройки превысят допустимый размер")]));
    }
    write_atomic(&sidecar(path, ".prev"), &current).map_err(SaveError::Io)?;
    write_atomic(path, &out).map_err(SaveError::Io)?;
    Ok(Saved { mode, previous_revision: current_rev, revision: revision(&out), config: cfg })
}

/// Замена настроек целиком (восстановление): блокировка и проверка ревизии текущих байтов (они могут не разбираться
/// или не проходить проверку), полная проверка только НОВОЙ конфигурации, копия предыдущей версии, атомарная запись.
/// Ошибки новой конфигурации — RuleInvalid с путями `config.*`.
pub fn replace_config(path: &Path, base_revision: &str, max_bytes: u64, new: &Config) -> Result<Saved, SaveError> {
    let _guard = lock(path).map_err(SaveError::Busy)?;
    let current = crate::api::read_limited(&path.to_string_lossy(), max_bytes).map_err(SaveError::Io)?;
    let current_rev = revision(&current);
    if !base_revision.eq_ignore_ascii_case(&current_rev) {
        return Err(SaveError::Conflict { current: current_rev });
    }
    let issues = validate_config(new);
    if !issues.is_empty() {
        return Err(SaveError::RuleInvalid(prefix(issues)));
    }
    let mut out = serde_json::to_vec_pretty(new).map_err(|e| SaveError::Io(e.to_string()))?;
    out.push(b'\n');
    if out.len() as u64 > max_bytes {
        return Err(SaveError::RuleInvalid(vec![Issue::new("config", "too_large", "настройки превысят допустимый размер")]));
    }
    write_atomic(&sidecar(path, ".prev"), &current).map_err(SaveError::Io)?;
    write_atomic(path, &out).map_err(SaveError::Io)?;
    Ok(Saved { mode: "replace", previous_revision: current_rev, revision: revision(&out), config: new.clone() })
}

fn prefix(i: Vec<Issue>) -> Vec<Issue> {
    i.into_iter().map(|x| Issue { path: format!("config.{}", x.path), ..x }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(revision(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(revision(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn sidecar_names() {
        assert_eq!(sidecar(Path::new("/data/x/config.json"), ".lock"), Path::new("/data/x/config.json.lock"));
    }
}
