//! Проверка пакета релиза (этап 12): подпись Ed25519 над `manifest.json`, SHA-256 и размеры файлов пакета,
//! после распаковки — SHA-256 распакованных файлов. Первая установка доверяет ключу из пакета (оператор сверяет
//! отпечаток); последующие обновления проверяются ключом, закреплённым при первой установке.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub target: String,
    pub created: String,
    /// Открытый ключ релиза (hex, 32 байта).
    pub pubkey: String,
    pub files: Vec<FileEntry>,
    /// Место на /data под этот релиз (сжатые файлы) и в /tmp после распаковки.
    pub data_bytes: u64,
    pub tmp_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Путь в пакете (относительно каталога пакета).
    pub path: String,
    pub sha256: String,
    pub size: u64,
    /// Путь после распаковки в каталоге выполнения (для .xz) или null, если файл используется как есть.
    #[serde(default)]
    pub unpacked: Option<String>,
    #[serde(default)]
    pub unpacked_sha256: Option<String>,
    #[serde(default)]
    pub unpacked_size: Option<u64>,
}

pub fn sha256_file(p: &Path) -> Result<(String, u64), String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n = 0u64;
    loop {
        let k = f.read(&mut buf).map_err(|e| format!("{}: {e}", p.display()))?;
        if k == 0 {
            break;
        }
        n += k as u64;
        h.update(&buf[..k]);
    }
    Ok((crate::auth::hex(&h.finalize()), n))
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    data_encoding::HEXLOWER_PERMISSIVE.decode(s.trim().as_bytes()).ok()
}

/// Безопасный относительный путь внутри пакета (без `..`, абсолютных путей и управляющих символов).
pub fn safe_rel(p: &str) -> bool {
    !p.is_empty() && !p.starts_with('/') && !p.contains('\\') && p.split('/').all(|c| !c.is_empty() && c != "." && c != "..") && !p.chars().any(char::is_control)
}

#[derive(Debug)]
pub struct Verified {
    pub manifest: Manifest,
    pub key_fingerprint: String,
}

/// Отпечаток открытого ключа релиза (hex): первые 16 знаков SHA-256 от 32 байт ключа, как в `verify_package`.
pub fn key_fingerprint(key_hex: &str) -> Option<String> {
    let key = unhex(key_hex).and_then(|k| ed25519_compact::PublicKey::from_slice(&k).ok())?;
    Some(crate::auth::hex(&Sha256::digest(key.as_ref()))[..16].to_string())
}

/// Подпись и файлы пакета. `pinned` — закреплённый ключ (hex); без него используется ключ из манифеста.
pub fn verify_package(dir: &Path, pinned: Option<&str>) -> Result<Verified, String> {
    let mbytes = std::fs::read(dir.join("manifest.json")).map_err(|e| format!("manifest.json: {e}"))?;
    let sig = std::fs::read_to_string(dir.join("manifest.sig")).map_err(|e| format!("manifest.sig: {e}"))?;
    let m: Manifest = serde_json::from_slice(&mbytes).map_err(|e| format!("manifest.json не разобран: {e}"))?;
    let key_hex = pinned.unwrap_or(&m.pubkey);
    let key = unhex(key_hex).and_then(|k| ed25519_compact::PublicKey::from_slice(&k).ok()).ok_or("открытый ключ релиза неверен")?;
    let sig = unhex(&sig).and_then(|s| ed25519_compact::Signature::from_slice(&s).ok()).ok_or("подпись манифеста неверного формата")?;
    key.verify(&mbytes, &sig).map_err(|_| "подпись манифеста не совпадает с ключом релиза".to_string())?;
    if pinned.is_some_and(|p| !p.trim().eq_ignore_ascii_case(m.pubkey.trim())) {
        return Err("манифест подписан закреплённым ключом, но объявляет другой ключ: смена ключа релиза не допускается обновлением".into());
    }
    let mut total = 0;
    for f in &m.files {
        if !safe_rel(&f.path) || f.unpacked.as_deref().is_some_and(|u| !safe_rel(u)) {
            return Err(format!("недопустимый путь в манифесте: {}", f.path));
        }
        let (h, n) = sha256_file(&dir.join(&f.path))?;
        if n != f.size || !h.eq_ignore_ascii_case(&f.sha256) {
            return Err(format!("{}: SHA-256 или размер не совпадает с манифестом", f.path));
        }
        total += n;
    }
    if total != m.data_bytes {
        return Err("data_bytes не совпадает с суммой размеров файлов".into());
    }
    let fp = crate::auth::hex(&Sha256::digest(key.as_ref()))[..16].to_string();
    Ok(Verified { manifest: m, key_fingerprint: fp })
}

/// Распакованные файлы (после unxz) в каталоге выполнения.
pub fn verify_unpacked(m: &Manifest, run: &Path) -> Result<u64, String> {
    let mut total = 0;
    for f in &m.files {
        let (Some(u), Some(want)) = (&f.unpacked, &f.unpacked_sha256) else { continue };
        let (h, n) = sha256_file(&run.join(u))?;
        if !h.eq_ignore_ascii_case(want) || f.unpacked_size.is_some_and(|s| s != n) {
            return Err(format!("{u}: распакованный файл не совпадает с манифестом"));
        }
        total += n;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_paths() {
        assert!(safe_rel("payload/bin/mi-tt-ctl.xz"));
        for bad in ["", "/etc/passwd", "../x", "a/../b", "a//b", "a\\b", "./a"] {
            assert!(!safe_rel(bad), "{bad}");
        }
    }

    #[test]
    fn signature_roundtrip_and_tamper() {
        let d = std::env::temp_dir().join(format!("mitt-rel-{}", crate::auth::hex(&crate::auth::random_bytes::<6>())));
        std::fs::create_dir_all(d.join("payload")).unwrap();
        std::fs::write(d.join("payload/a.bin"), b"hello").unwrap();
        let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(crate::auth::random_bytes::<32>()));
        let (h, n) = sha256_file(&d.join("payload/a.bin")).unwrap();
        let m = Manifest { name: "mi-lumruri".into(), version: "1".into(), target: "t".into(), created: "c".into(), pubkey: crate::auth::hex(kp.pk.as_ref()),
            files: vec![FileEntry { path: "payload/a.bin".into(), sha256: h, size: n, unpacked: None, unpacked_sha256: None, unpacked_size: None }], data_bytes: n, tmp_bytes: 0 };
        let mb = serde_json::to_vec(&m).unwrap();
        std::fs::write(d.join("manifest.json"), &mb).unwrap();
        std::fs::write(d.join("manifest.sig"), crate::auth::hex(kp.sk.sign(&mb, None).as_ref())).unwrap();
        assert!(verify_package(&d, None).is_ok());
        assert!(verify_package(&d, Some(&m.pubkey)).is_ok());
        let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(crate::auth::random_bytes::<32>()));
        assert!(verify_package(&d, Some(&crate::auth::hex(other.pk.as_ref()))).unwrap_err().contains("подпись"));
        std::fs::write(d.join("payload/a.bin"), b"hellO").unwrap();
        assert!(verify_package(&d, None).unwrap_err().contains("SHA-256"));
        let _ = std::fs::remove_dir_all(d);
    }
}
