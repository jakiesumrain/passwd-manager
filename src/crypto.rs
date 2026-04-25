use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use crate::error::AppError;

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

// Output format: [12-byte nonce][ciphertext][16-byte tag] — all
// concatenated into a single Vec. decrypt() splits the nonce off.
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> Result<Vec<u8>, AppError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| AppError::CryptoError(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| AppError::CryptoError(e.to_string()))?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<String, AppError> {
    if data.len() < 12 {
        return Err(AppError::CryptoError(
            "ciphertext too short".to_string(),
        ));
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| AppError::CryptoError(e.to_string()))?;

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AppError::CryptoError(e.to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| AppError::CryptoError(format!("invalid UTF-8: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = "hello world";
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_string_roundtrip() {
        let key = generate_key();
        let ciphertext = encrypt(&key, "").unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let ciphertext = encrypt(&key1, "secret").unwrap();
        assert!(decrypt(&key2, &ciphertext).is_err());
    }

    #[test]
    fn decrypt_too_short() {
        let key = generate_key();
        let result = decrypt(&key, &[0u8; 3]);
        assert!(result.is_err());
    }

    #[test]
    fn different_nonces() {
        let key = generate_key();
        let ct1 = encrypt(&key, "same").unwrap();
        let ct2 = encrypt(&key, "same").unwrap();
        // First 12 bytes are the nonce — should differ each time
        assert_ne!(ct1[..12], ct2[..12]);
    }

    #[test]
    fn key_is_32_bytes() {
        let key = generate_key();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn multiple_keys_differ() {
        let k1 = generate_key();
        let k2 = generate_key();
        assert_ne!(k1, k2);
    }
}
