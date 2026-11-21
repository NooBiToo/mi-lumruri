//! Вход в панель: пароль (Argon2id) и второй фактор (TOTP RFC 6238 или одноразовый recovery-код).
//!
//! Хранение:
//!  - `<auth_dir>/auth.json` (вне web root, каталог 0700, файл 0600): PHC-хеш Argon2id, секрет TOTP, хеши recovery-кодов,
//!    последний принятый шаг TOTP, нижняя граница доверенного времени, эпоха сессий. Пишет только административный CLI
//!    (настройка, сброс) и CGI при успешном втором факторе (шаг TOTP, расход recovery-кода, время).
//!  - `<session_dir>` (RAM, 0700): файлы сессий, названные SHA-256 токена, и счётчик неудачных попыток.
//!
//! Свойства: две стадии (пароль → предварительная сессия 5 мин → второй фактор → новая сессия, ротация токена);
//! cookie `__Host-` Secure/HttpOnly/SameSite=Strict; простой 30 мин и предел 8 ч; CSRF-токен в заголовке для POST;
//! лимит попыток (после 5 неудач — пауза 30 с, удваивается до 15 мин); TOTP-шаг принимается только больше последнего
//! принятого, проверка и запись под эксклюзивной блокировкой — повтор и конкурентное использование кода отклоняются;
//! при недоверенных часах (раньше нижней границы) TOTP не принимается, работают recovery-коды.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::store::{lock, write_atomic};

pub const DEFAULT_AUTH_DIR: &str = "/data/mi-lumruri/auth";
pub const DEFAULT_SESSION_DIR: &str = "/tmp/mi-lumruri/sessions";
pub const COOKIE_SESSION: &str = "__Host-mitt_sess";
pub const COOKIE_PENDING: &str = "__Host-mitt_pre";
pub const CSRF_HEADER: &str = "X-MITT-CSRF";
pub const PENDING_TTL: u64 = 300;
pub const SESSION_IDLE: u64 = 30 * 60;
pub const SESSION_MAX: u64 = 8 * 3600;
pub const PENDING_MAX_FAILS: u32 = 5;
pub const LOCK_AFTER: u32 = 5;
pub const LOCK_BASE: u64 = 30;
pub const LOCK_MAX: u64 = 15 * 60;
pub const TOTP_STEP: u64 = 30;
pub const TOTP_DIGITS: u32 = 6;
pub const RECOVERY_CODES: usize = 10;
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Нижняя граница доверенного времени (2026-11-01T00:00:00Z): после холодного старта без NTP часы роутера
/// показывают время сборки прошивки или 1970 год — раньше этой границы TOTP не принимается.
pub const TIME_FLOOR: u64 = 1_793_491_200;
/// Допустимое отставание часов от последнего достоверного времени (секунды).
pub const CLOCK_BACKWARD_TOLERANCE: u64 = 300;

/// Текущее время. Только в отладочной сборке (тесты) его можно подменить MI_TT_TEST_NOW; в release подмена вырезана.
pub fn now() -> u64 {
    #[cfg(debug_assertions)]
    if let Some(t) = std::env::var("MI_TT_TEST_NOW").ok().and_then(|v| v.parse().ok()) {
        return t;
    }
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("ОС не дала случайных байт");
    b
}

pub fn hex(b: &[u8]) -> String {
    HEXLOWER.encode(b)
}

fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub auth_dir: PathBuf,
    pub session_dir: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        let e = |k: &str, d: &str| std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.into());
        Paths { auth_dir: PathBuf::from(e("MI_TT_AUTH_DIR", DEFAULT_AUTH_DIR)), session_dir: PathBuf::from(e("MI_TT_SESSION_DIR", DEFAULT_SESSION_DIR)) }
    }
    pub fn state(&self) -> PathBuf {
        self.auth_dir.join("auth.json")
    }
    fn attempts(&self) -> PathBuf {
        self.session_dir.join("attempts.json")
    }
}

fn ensure_private_dir(d: &Path) -> Result<(), String> {
    fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d, fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    Ok(())
}

// ---------- состояние ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCode {
    pub salt: String,
    pub sha256: String,
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthState {
    pub version: u32,
    pub password_hash: String,
    pub totp_secret_b32: String,
    pub totp_enrolled: bool,
    pub totp_last_step: u64,
    pub last_good_time: u64,
    pub recovery: Vec<RecoveryCode>,
    /// Увеличение отзывает все сессии (сброс пароля, второго фактора, явный отзыв).
    pub sessions_epoch: u64,
}

impl AuthState {
    /// TOTP не включён (пустой секрет): вход в панель только паролем.
    pub fn totp_off(&self) -> bool {
        self.totp_secret_b32.is_empty()
    }

    /// Вход в панель открыт: только паролем или с подтверждённым TOTP. Новый секрет до `confirm` вход закрывает.
    pub fn login_ready(&self) -> bool {
        self.totp_off() || self.totp_enrolled
    }
}

pub fn load_state(p: &Paths) -> Result<Option<AuthState>, String> {
    let f = p.state();
    if !f.exists() {
        return Ok(None);
    }
    let b = fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
    serde_json::from_slice(&b).map(Some).map_err(|e| format!("{} повреждён: {e}", f.display()))
}

pub fn save_state(p: &Paths, s: &AuthState) -> Result<(), String> {
    ensure_private_dir(&p.auth_dir)?;
    let mut b = serde_json::to_vec_pretty(s).map_err(|e| e.to_string())?;
    b.push(b'\n');
    write_atomic(&p.state(), &b)
}

pub fn lock_auth(p: &Paths) -> Result<fs::File, String> {
    ensure_private_dir(&p.auth_dir)?;
    lock(&p.state())
}

// ---------- пароль ----------

#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
}

impl Default for KdfParams {
    /// OWASP: Argon2id m=19 МиБ, t=2, p=1 — подбор на роутере уточняется по времени входа.
    fn default() -> Self {
        KdfParams { m_kib: 19 * 1024, t: 2 }
    }
}

pub fn hash_password(pw: &str, k: KdfParams) -> Result<String, String> {
    let params = Params::new(k.m_kib, k.t, 1, None).map_err(|e| e.to_string())?;
    let salt = SaltString::encode_b64(&random_bytes::<16>()).map_err(|e| e.to_string())?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password(pw.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| e.to_string())
}

pub fn verify_password(pw: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(h) if h.algorithm.as_str() == "argon2id" => Argon2::default().verify_password(pw.as_bytes(), &h).is_ok(),
        _ => false,
    }
}

pub fn check_password_policy(pw: &str) -> Result<(), String> {
    if pw.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("пароль короче {MIN_PASSWORD_CHARS} символов"));
    }
    if pw.chars().any(char::is_control) {
        return Err("пароль содержит управляющие символы".into());
    }
    Ok(())
}

// ---------- TOTP ----------

pub fn new_totp_secret() -> String {
    BASE32_NOPAD.encode(&random_bytes::<20>())
}

pub fn totp_at(secret_b32: &str, time: u64) -> Option<String> {
    let key = BASE32_NOPAD.decode(secret_b32.as_bytes()).ok()?;
    Some(totp_lite::totp_custom::<totp_lite::Sha1>(TOTP_STEP, TOTP_DIGITS, &key, time))
}

pub fn otpauth_uri(secret_b32: &str, label: &str) -> String {
    format!("otpauth://totp/Mi%20Lumruri:{label}?secret={secret_b32}&issuer=Mi%20Lumruri&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}")
}

/// Шаг, которому соответствует код (окно ±1 шаг), без учёта повторов.
pub fn totp_match(secret_b32: &str, code: &str, now: u64) -> Option<u64> {
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let step = now / TOTP_STEP;
    let mut found = None;
    for s in [step.saturating_sub(1), step, step + 1] {
        if let Some(c) = totp_at(secret_b32, s * TOTP_STEP) {
            if ct_eq(&c, code) && found.is_none() {
                found = Some(s);
            }
        }
    }
    found
}

/// Часы доверены: не раньше нижней границы и не заметно раньше последнего достоверного времени.
pub fn clock_trusted(now: u64, last_good: u64) -> bool {
    now >= TIME_FLOOR && now + CLOCK_BACKWARD_TOLERANCE >= last_good
}

// ---------- recovery-коды ----------

/// Код из 16 символов base32 (80 бит) группами по 4. Хранится SHA-256 с солью: энтропии кода достаточно.
pub fn new_recovery_codes() -> (Vec<String>, Vec<RecoveryCode>) {
    let mut plain = Vec::new();
    let mut stored = Vec::new();
    for _ in 0..RECOVERY_CODES {
        let raw = BASE32_NOPAD.encode(&random_bytes::<10>());
        let code = raw.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-");
        let salt = hex(&random_bytes::<16>());
        stored.push(RecoveryCode { sha256: sha256_hex(format!("{salt}:{}", normalize_recovery(&code)).as_bytes()), salt, used: false });
        plain.push(code);
    }
    (plain, stored)
}

pub fn normalize_recovery(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

/// Индекс неиспользованного кода, совпавшего с введённым (сравнение всех кодов за постоянное время).
pub fn recovery_match(stored: &[RecoveryCode], code: &str) -> Option<usize> {
    let n = normalize_recovery(code);
    if n.len() != 16 {
        return None;
    }
    let mut found = None;
    for (i, r) in stored.iter().enumerate() {
        let h = sha256_hex(format!("{}:{n}", r.salt).as_bytes());
        if ct_eq(&h, &r.sha256) && !r.used && found.is_none() {
            found = Some(i);
        }
    }
    found
}

// ---------- лимит попыток ----------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Attempts {
    pub fails: u32,
    pub locked_until: u64,
}

pub fn load_attempts(p: &Paths) -> Attempts {
    fs::read(p.attempts()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn record_failure(p: &Paths, now: u64) -> Attempts {
    let mut a = load_attempts(p);
    a.fails = a.fails.saturating_add(1);
    if a.fails >= LOCK_AFTER {
        let exp = (a.fails - LOCK_AFTER).min(10);
        a.locked_until = now + (LOCK_BASE << exp).min(LOCK_MAX);
    }
    let _ = ensure_private_dir(&p.session_dir).and_then(|_| write_atomic(&p.attempts(), &serde_json::to_vec(&a).unwrap_or_default()));
    a
}

pub fn reset_attempts(p: &Paths) {
    let _ = fs::remove_file(p.attempts());
}

// ---------- сессии ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Пароль подтверждён, ждём второй фактор.
    Pending,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub stage: Stage,
    pub created: u64,
    pub expires: u64,
    pub last_seen: u64,
    pub csrf: String,
    pub epoch: u64,
    pub fails: u32,
}

fn session_path(p: &Paths, token: &str) -> Option<PathBuf> {
    // токен — 64 hex-символа; имя файла — SHA-256 токена, сам токен на диск не попадает
    (token.len() == 64 && token.bytes().all(|c| c.is_ascii_hexdigit())).then(|| p.session_dir.join(sha256_hex(token.as_bytes())))
}

pub fn create_session(p: &Paths, stage: Stage, epoch: u64, now: u64) -> Result<(String, Session), String> {
    ensure_private_dir(&p.session_dir)?;
    let token = hex(&random_bytes::<32>());
    let ttl = if stage == Stage::Pending { PENDING_TTL } else { SESSION_MAX };
    let s = Session { stage, created: now, expires: now + ttl, last_seen: now, csrf: hex(&random_bytes::<32>()), epoch, fails: 0 };
    write_atomic(&session_path(p, &token).ok_or("bad token")?, &serde_json::to_vec(&s).map_err(|e| e.to_string())?)?;
    Ok((token, s))
}

pub fn write_session(p: &Paths, token: &str, s: &Session) {
    if let Some(f) = session_path(p, token) {
        let _ = write_atomic(&f, &serde_json::to_vec(s).unwrap_or_default());
    }
}

pub fn delete_session(p: &Paths, token: &str) {
    if let Some(f) = session_path(p, token) {
        let _ = fs::remove_file(f);
    }
}

/// Действующая сессия нужной стадии: не истекла, не простаивала дольше лимита, эпоха совпадает.
pub fn load_session(p: &Paths, token: &str, stage: Stage, epoch: u64, now: u64) -> Option<Session> {
    let f = session_path(p, token)?;
    let s: Session = serde_json::from_slice(&fs::read(&f).ok()?).ok()?;
    let idle_ok = stage == Stage::Pending || now <= s.last_seen + SESSION_IDLE;
    // сессия из «будущего» (часы ушли назад после холодного старта) тоже недействительна
    if s.stage != stage {
        // не та стадия (например, токен первого этапа под именем полной сессии): отказ, но чужую запись не трогаем
        return None;
    }
    if s.epoch != epoch || now >= s.expires || !idle_ok || now + CLOCK_BACKWARD_TOLERANCE < s.created {
        let _ = fs::remove_file(&f);
        return None;
    }
    Some(s)
}

// ---------- cookie ----------

pub fn cookie_value(header: &str, name: &str) -> Option<String> {
    header.split(';').map(str::trim).filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
}

pub fn set_cookie(name: &str, value: &str, max_age: u64) -> String {
    format!("Set-Cookie: {name}={value}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict")
}

pub fn clear_cookie(name: &str) -> String {
    format!("Set-Cookie: {name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_vectors() {
        // RFC 6238, приложение B: ключ "12345678901234567890", SHA1, 8 цифр
        let key = b"12345678901234567890";
        assert_eq!(totp_lite::totp_custom::<totp_lite::Sha1>(30, 8, key, 59), "94287082");
        assert_eq!(totp_lite::totp_custom::<totp_lite::Sha1>(30, 8, key, 1_111_111_109), "07081804");
        let b32 = BASE32_NOPAD.encode(key);
        assert_eq!(totp_at(&b32, 1_234_567_890).unwrap(), "005924");
    }

    #[test]
    fn totp_window_and_format() {
        let s = new_totp_secret();
        let t = TIME_FLOOR + 1000;
        let c = totp_at(&s, t).unwrap();
        assert_eq!(totp_match(&s, &c, t), Some(t / 30));
        assert_eq!(totp_match(&s, &c, t + 30), Some(t / 30), "окно −1 шаг");
        assert_eq!(totp_match(&s, &c, t + 90), None, "дальше окна — нет");
        assert_eq!(totp_match(&s, "12345", t), None);
        assert_eq!(totp_match(&s, "abcdef", t), None);
    }

    #[test]
    fn clock_trust() {
        assert!(!clock_trusted(0, 0), "1970 после холодного старта");
        assert!(!clock_trusted(TIME_FLOOR - 1, 0));
        assert!(clock_trusted(TIME_FLOOR + 10, TIME_FLOOR));
        assert!(!clock_trusted(TIME_FLOOR + 10, TIME_FLOOR + 10_000), "часы ушли назад от последнего достоверного");
    }

    #[test]
    fn password_hashing_argon2id() {
        let k = KdfParams { m_kib: 1024, t: 1 };
        let pw = hex(&random_bytes::<12>());
        let h = hash_password(&pw, k).unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=1024,t=1,p=1$"));
        assert!(verify_password(&pw, &h));
        assert!(!verify_password(&format!("{pw}x"), &h));
        assert!(!verify_password(&pw, "$argon2i$v=19$m=1024,t=1,p=1$c2FsdHNhbHQ$aGFzaA"));
    }

    #[test]
    fn recovery_codes_one_time() {
        let (plain, mut stored) = new_recovery_codes();
        assert_eq!(plain.len(), RECOVERY_CODES);
        let i = recovery_match(&stored, &plain[3].to_lowercase()).unwrap();
        assert_eq!(i, 3);
        stored[3].used = true;
        assert_eq!(recovery_match(&stored, &plain[3]), None);
        assert_eq!(recovery_match(&stored, "AAAA-BBBB-CCCC-DDDD"), None);
    }

    #[test]
    fn cookies() {
        assert_eq!(cookie_value("a=1; __Host-mitt_sess=abc; b=2", COOKIE_SESSION).as_deref(), Some("abc"));
        assert_eq!(cookie_value("x__Host-mitt_sess=abc", COOKIE_SESSION), None);
        assert!(set_cookie(COOKIE_SESSION, "t", 10).contains("Secure; HttpOnly; SameSite=Strict"));
    }

    #[test]
    fn lockout_backoff() {
        let d = std::env::temp_dir().join(format!("mitt-auth-test-{}", hex(&random_bytes::<6>())));
        let p = Paths { auth_dir: d.join("a"), session_dir: d.join("s") };
        let mut a = Attempts::default();
        for _ in 0..LOCK_AFTER {
            a = record_failure(&p, 1000);
        }
        assert_eq!(a.locked_until, 1000 + LOCK_BASE);
        a = record_failure(&p, 1000);
        assert_eq!(a.locked_until, 1000 + 2 * LOCK_BASE);
        for _ in 0..20 {
            a = record_failure(&p, 1000);
        }
        assert_eq!(a.locked_until, 1000 + LOCK_MAX);
        reset_attempts(&p);
        assert_eq!(load_attempts(&p).fails, 0);
        let _ = fs::remove_dir_all(d);
    }
}
