use std::fmt;

// Exit codes: 1 for user-correctable errors (bad input),
// 2 for internal errors (IO, crypto, corrupt vault).
#[derive(Debug)]
pub enum AppError {
    PlaceExists(String),
    PlaceNotFound(String),
    VaultIo(String),
    CryptoError(String),
    InvalidVault(String),
}

impl AppError {
    pub fn exit_code(&self) -> i32 {
        match self {
            AppError::PlaceExists(_) | AppError::PlaceNotFound(_) => 1,
            AppError::VaultIo(_) | AppError::CryptoError(_) | AppError::InvalidVault(_) => 2,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::PlaceExists(place) => {
                write!(f, "passwd-manager: error: place '{}' already exists", place)
            }
            AppError::PlaceNotFound(place) => {
                write!(f, "passwd-manager: error: place '{}' not found", place)
            }
            AppError::VaultIo(msg) => {
                write!(f, "passwd-manager: error: {}", msg)
            }
            AppError::CryptoError(msg) => {
                write!(f, "passwd-manager: error: {}", msg)
            }
            AppError::InvalidVault(msg) => {
                write!(f, "passwd-manager: error: invalid vault: {}", msg)
            }
        }
    }
}

impl std::error::Error for AppError {}
