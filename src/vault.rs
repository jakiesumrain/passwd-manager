use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::crypto;
use crate::error::AppError;

// Vault file format (v2):
//   [4-byte magic "PMv2"][32-byte salt][2-byte desc_len LE][desc bytes][AES-GCM encrypted blob]
// Legacy format (v1):
//   [32-byte salt][AES-GCM encrypted blob]
const SALT_SIZE: usize = 32;
const VAULT_MAGIC: &[u8; 4] = b"PMv2";

pub struct VaultEntry {
    pub place: String,
    pub ciphertext: Vec<u8>,
}

pub struct VaultHeader {
    pub description: String,
}

fn binary_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn vault_path(name: Option<&str>) -> PathBuf {
    let filename = match name {
        Some(n) if !n.is_empty() => format!("{}.pm", n),
        _ => "vault.pm".to_string(),
    };
    binary_dir().join(filename)
}

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

pub fn read_vault_header(path: &Path) -> Result<VaultHeader, AppError> {
    let data = fs::read(path).map_err(|e| AppError::VaultIo(format!("cannot read vault: {}", e)))?;
    if data.starts_with(VAULT_MAGIC) {
        let offset = VAULT_MAGIC.len();
        if data.len() < offset + SALT_SIZE + 2 {
            return Err(AppError::InvalidVault("file too short".to_string()));
        }
        let desc_len = u16::from_le_bytes([data[offset + SALT_SIZE], data[offset + SALT_SIZE + 1]]) as usize;
        let desc = if desc_len > 0 {
            String::from_utf8_lossy(&data[offset + SALT_SIZE + 2..offset + SALT_SIZE + 2 + desc_len]).to_string()
        } else {
            String::new()
        };
        Ok(VaultHeader { description: desc })
    } else {
        Ok(VaultHeader { description: String::new() })
    }
}

fn parse_entries(content: &str) -> Result<Vec<VaultEntry>, AppError> {
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
    Ok(entries)
}

pub fn read_vault(path: &Path, password: &str) -> Result<(Vec<VaultEntry>, [u8; SALT_SIZE], String), AppError> {
    if !path.exists() {
        let salt = crypto::generate_key();
        return Ok((Vec::new(), salt, String::new()));
    }

    let data = fs::read(path).map_err(|e| AppError::VaultIo(format!("cannot read vault: {}", e)))?;

    let (salt, description, encrypted_start) = if data.starts_with(VAULT_MAGIC) {
        let offset = VAULT_MAGIC.len();
        if data.len() < offset + SALT_SIZE + 2 + 12 + 1 {
            return Err(AppError::InvalidVault("file too short".to_string()));
        }
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&data[offset..offset + SALT_SIZE]);
        let desc_len = u16::from_le_bytes([data[offset + SALT_SIZE], data[offset + SALT_SIZE + 1]]) as usize;
        let desc = if desc_len > 0 {
            String::from_utf8_lossy(&data[offset + SALT_SIZE + 2..offset + SALT_SIZE + 2 + desc_len]).to_string()
        } else {
            String::new()
        };
        let es = offset + SALT_SIZE + 2 + desc_len;
        (salt, desc, es)
    } else {
        if data.len() < SALT_SIZE + 12 + 1 {
            return Err(AppError::InvalidVault("file too short".to_string()));
        }
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&data[..SALT_SIZE]);
        (salt, String::new(), SALT_SIZE)
    };

    let key = derive_key(password, &salt);
    let content = crypto::decrypt(&key, &data[encrypted_start..])?;
    let entries = parse_entries(&content)?;

    Ok((entries, salt, description))
}

pub fn write_vault(
    path: &Path,
    password: &str,
    salt: &[u8; SALT_SIZE],
    entries: &[VaultEntry],
    description: &str,
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

    let desc_bytes = description.as_bytes();
    let desc_len = desc_bytes.len() as u16;

    let mut data = Vec::with_capacity(VAULT_MAGIC.len() + SALT_SIZE + 2 + desc_bytes.len() + encrypted.len());
    data.extend_from_slice(VAULT_MAGIC);
    data.extend_from_slice(salt);
    data.extend_from_slice(&desc_len.to_le_bytes());
    data.extend_from_slice(desc_bytes);
    data.extend_from_slice(&encrypted);

    fs::write(path, &data)
        .map_err(|e| AppError::VaultIo(format!("cannot write vault: {}", e)))?;
    Ok(())
}

pub fn find_entry<'a>(entries: &'a [VaultEntry], place: &str) -> Option<&'a VaultEntry> {
    entries.iter().find(|e| e.place == place)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pm-test-{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = [1u8; 32];
        let k1 = derive_key("mypass", &salt);
        let k2 = derive_key("mypass", &salt);
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_differs_with_salt() {
        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];
        assert_ne!(derive_key("mypass", &salt1), derive_key("mypass", &salt2));
    }

    #[test]
    fn derive_key_differs_with_password() {
        let salt = [1u8; 32];
        assert_ne!(derive_key("pass1", &salt), derive_key("pass2", &salt));
    }

    #[test]
    fn find_entry_found() {
        let entries = vec![
            VaultEntry { place: "a.com".into(), ciphertext: vec![1] },
            VaultEntry { place: "b.com".into(), ciphertext: vec![2] },
        ];
        assert_eq!(find_entry(&entries, "a.com").unwrap().ciphertext, vec![1]);
    }

    #[test]
    fn find_entry_not_found() {
        let entries = vec![VaultEntry { place: "a.com".into(), ciphertext: vec![] }];
        assert!(find_entry(&entries, "missing").is_none());
    }

    #[test]
    fn find_entry_empty_entries() {
        assert!(find_entry(&[], "anything").is_none());
    }

    #[test]
    fn parse_entries_normal() {
        let input = "example.com|aGVsbG8=\nanother.com|d29ybGQ=\n";
        let entries = parse_entries(input).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].place, "example.com");
        assert_eq!(entries[1].place, "another.com");
    }

    #[test]
    fn parse_entries_skips_empty_lines() {
        let input = "a.com|bGlucw==\n\nb.com|Zm9v\n";
        let entries = parse_entries(input).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn parse_entries_empty_place_accepted() {
        // splitn on "|aGVsbG8=" returns ["", "aGVsbG8="] — empty place, not an error
        let entries = parse_entries("|aGVsbG8=\n").unwrap();
        assert_eq!(entries[0].place, "");
    }

    #[test]
    fn parse_entries_missing_ciphertext() {
        assert!(parse_entries("example.com\n").is_err());
    }

    #[test]
    fn parse_entries_bad_base64() {
        assert!(parse_entries("x|!!!\n").is_err());
    }

    #[test]
    fn write_then_read_vault_roundtrip() {
        let dir = test_dir("roundtrip");
        let path = dir.join("test.pm");
        let password = "mypassword";
        let salt = [42u8; 32];

        let entries = vec![
            VaultEntry { place: "example.com".into(), ciphertext: vec![1, 2, 3] },
            VaultEntry { place: "another.org".into(), ciphertext: vec![10, 20] },
        ];

        write_vault(&path, password, &salt, &entries, "my desc").unwrap();

        let (read_entries, read_salt, desc) = read_vault(&path, password).unwrap();
        assert_eq!(read_entries.len(), 2);
        assert_eq!(read_entries[0].place, "example.com");
        assert_eq!(read_entries[0].ciphertext, vec![1, 2, 3]);
        assert_eq!(read_entries[1].place, "another.org");
        assert_eq!(read_entries[1].ciphertext, vec![10, 20]);
        assert_eq!(read_salt, salt);
        assert_eq!(desc, "my desc");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_then_read_empty_entries() {
        let dir = test_dir("empty");
        let path = dir.join("empty.pm");
        let password = "pass";
        let salt = [0u8; 32];

        write_vault(&path, password, &salt, &[], "").unwrap();
        let (entries, read_salt, desc) = read_vault(&path, password).unwrap();
        assert!(entries.is_empty());
        assert_eq!(read_salt, salt);
        assert_eq!(desc, "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_vault_wrong_password_fails() {
        let dir = test_dir("wrong-pw");
        let path = dir.join("test.pm");
        let salt = [99u8; 32];

        write_vault(&path, "correct", &salt, &[], "").unwrap();
        assert!(read_vault(&path, "wrong").is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_vault_missing_file_returns_empty() {
        let path = Path::new("/nonexistent/path/for/test.pm");
        let (entries, _salt, desc) = read_vault(path, "any").unwrap();
        assert!(entries.is_empty());
        assert_eq!(desc, "");
    }

    #[test]
    fn read_vault_header_v2() {
        let dir = test_dir("header-v2");
        let path = dir.join("test.pm");
        let salt = [7u8; 32];
        write_vault(&path, "p", &salt, &[], "hello world").unwrap();

        let header = read_vault_header(&path).unwrap();
        assert_eq!(header.description, "hello world");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_vault_header_v2_empty_desc() {
        let dir = test_dir("header-v2-empty");
        let path = dir.join("test.pm");
        let salt = [7u8; 32];
        write_vault(&path, "p", &salt, &[], "").unwrap();

        let header = read_vault_header(&path).unwrap();
        assert_eq!(header.description, "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_vault_header_v1_legacy() {
        let dir = test_dir("header-v1");
        let path = dir.join("legacy.pm");
        // Write raw bytes: 32 bytes of salt + random data (no magic header)
        let mut data = vec![0u8; 32 + 50];
        data[0] = 0xFF; // guaranteed not "PMv2"
        fs::write(&path, &data).unwrap();

        let header = read_vault_header(&path).unwrap();
        assert_eq!(header.description, "");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_path_default() {
        let p = vault_path(None);
        assert!(p.to_string_lossy().ends_with("vault.pm"));
    }

    #[test]
    fn vault_path_named() {
        let p = vault_path(Some("work"));
        assert!(p.to_string_lossy().ends_with("work.pm"));
        let p2 = vault_path(Some(""));
        assert!(p2.to_string_lossy().ends_with("vault.pm"));
    }

    #[test]
    fn write_vault_creates_file() {
        let dir = test_dir("create");
        let path = dir.join("new.pm");
        let salt = [1u8; 32];
        write_vault(&path, "p", &salt, &[], "desc").unwrap();
        assert!(path.exists());
        assert!(path.metadata().unwrap().len() > 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unicode_place_name() {
        let dir = test_dir("unicode");
        let path = dir.join("uni.pm");
        let salt = [5u8; 32];
        let entries = vec![VaultEntry {
            place: "日本語.example".into(),
            ciphertext: vec![1, 2, 3],
        }];
        write_vault(&path, "p", &salt, &entries, "").unwrap();
        let (read, _, _) = read_vault(&path, "p").unwrap();
        assert_eq!(read[0].place, "日本語.example");
        let _ = fs::remove_dir_all(&dir);
    }
}

pub fn list_vaults() -> Vec<(String, String)> {
    let dir = binary_dir();
    let mut vaults = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "pm")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
            {
                let desc = read_vault_header(&path)
                    .ok()
                    .map(|h| h.description)
                    .unwrap_or_default();
                vaults.push((stem.to_string(), desc));
            }
        }
    }
    vaults.sort_by(|a, b| a.0.cmp(&b.0));
    vaults
}
