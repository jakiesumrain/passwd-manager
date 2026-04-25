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
