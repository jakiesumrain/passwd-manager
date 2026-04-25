use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::AppError;

// Vault file format: [32-byte salt][AES-GCM encrypted blob].
// The key is never stored on disk — it's derived from the master
// password + salt at runtime.
const SALT_SIZE: usize = 32;

pub struct VaultEntry {
    pub place: String,
    pub ciphertext: Vec<u8>,
}

fn binary_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn vault_path() -> PathBuf {
    binary_dir().join("vault.pm")
}

// Iterated SHA-256 as a poor man's KDF. 10000 rounds is a tradeoff
// between startup delay and brute-force resistance.
pub fn derive_key(password: &str, salt: &[u8; SALT_SIZE]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(password.as_bytes());
    let mut buf = h.finalize();

    for _ in 0..10000 {
        let mut h = Sha256::new();
        h.update(buf);
        buf = h.finalize();
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&buf);
    key
}

pub fn read_vault(path: &Path, password: &str) -> Result<(Vec<VaultEntry>, [u8; SALT_SIZE]), AppError> {
    if !path.exists() {
        let salt = crypto::generate_key();
        return Ok((Vec::new(), salt));
    }

    let data =
        fs::read(path).map_err(|e| AppError::VaultIo(format!("cannot read vault: {}", e)))?;

    if data.len() < SALT_SIZE + 12 + 1 {
        return Err(AppError::InvalidVault("file too short".to_string()));
    }

    let (salt_bytes, encrypted) = data.split_at(SALT_SIZE);
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(salt_bytes);

    let key = derive_key(password, &salt);
    let content = crypto::decrypt(&key, encrypted)?;

    let mut entries = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '|');
        let place = parts.next().ok_or_else(|| {
            AppError::InvalidVault(format!("line {}: missing place", lineno + 1))
        })?;
        let b64 = parts.next().ok_or_else(|| {
            AppError::InvalidVault(format!("line {}: missing ciphertext", lineno + 1))
        })?;

        let ciphertext =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.as_bytes())
                .map_err(|e| {
                    AppError::InvalidVault(format!("line {}: invalid base64: {}", lineno + 1, e))
                })?;

        entries.push(VaultEntry {
            place: place.to_string(),
            ciphertext,
        });
    }

    Ok((entries, salt))
}

pub fn write_vault(
    path: &Path,
    password: &str,
    salt: &[u8; SALT_SIZE],
    entries: &[VaultEntry],
) -> Result<(), AppError> {
    let mut text = String::new();
    for entry in entries {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &entry.ciphertext,
        );
        text.push_str(&entry.place);
        text.push('|');
        text.push_str(&b64);
        text.push('\n');
    }

    let key = derive_key(password, salt);
    let encrypted = crypto::encrypt(&key, &text)?;

    let mut data = Vec::with_capacity(SALT_SIZE + encrypted.len());
    data.extend_from_slice(salt);
    data.extend_from_slice(&encrypted);

    fs::write(path, &data)
        .map_err(|e| AppError::VaultIo(format!("cannot write vault: {}", e)))?;
    Ok(())
}

pub fn find_entry<'a>(entries: &'a [VaultEntry], place: &str) -> Option<&'a VaultEntry> {
    entries.iter().find(|e| e.place == place)
}
