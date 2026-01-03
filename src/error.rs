use core::fmt;
use hmac::digest::InvalidLength;

/// Ошибки верхнего уровня, возникающие во всех подсистемах Gatekeeper.
#[derive(Debug, Clone, Copy)]
pub enum IdentityError {
    /// Аппаратная или программная энтропия недоступна.
    EntropyUnavailable,
    /// HKDF не смог завершиться.
    DerivationFailed,
    /// Ошибка внутренняя подсистемы хранения.
    StorageError,
    StorageUnavailable,
    StorageCorrupted,
    StorageMacMismatch,
    StorageVersionMismatch,
    StorageNotFound,
    FlashWriteFailed,
    /// Переданный challenge некорректен.
    InvalidChallenge,
    ReplayDetected,
    ChallengeNotRegistered,
    ChallengeStoreFull,
    InvalidPublicKey,
    VerificationFailed,
    InvalidSeed,
    ContactListFull,
    ContactNotFound,
    ContactAlreadyExists,
    SecureBootFailure,
    NetworkUnavailable,
    NetworkStackError,
    NonceExhausted,
    /// Инициализация криптографического примитива завершилась ошибкой.
    CryptoBackend {
        /// Источник ошибки из криптобиблиотеки.
        source: InvalidLength,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::EntropyUnavailable => f.write_str("entropy unavailable"),
            IdentityError::DerivationFailed => f.write_str("key derivation failed"),
            IdentityError::StorageError => f.write_str("storage error"),
            IdentityError::StorageUnavailable => f.write_str("storage unavailable"),
            IdentityError::StorageCorrupted => f.write_str("storage is corrupted"),
            IdentityError::StorageMacMismatch => f.write_str("storage MAC mismatch"),
            IdentityError::StorageVersionMismatch => f.write_str("storage version mismatch"),
            IdentityError::StorageNotFound => f.write_str("storage entry not found"),
            IdentityError::FlashWriteFailed => f.write_str("flash write failed"),
            IdentityError::InvalidChallenge => f.write_str("invalid challenge"),
            IdentityError::ReplayDetected => f.write_str("challenge already used"),
            IdentityError::ChallengeNotRegistered => f.write_str("challenge not registered"),
            IdentityError::ChallengeStoreFull => f.write_str("challenge store full"),
            IdentityError::InvalidPublicKey => f.write_str("invalid public key"),
            IdentityError::VerificationFailed => f.write_str("verification failed"),
            IdentityError::InvalidSeed => f.write_str("seed verification failed"),
            IdentityError::ContactListFull => f.write_str("contact list is full"),
            IdentityError::ContactNotFound => f.write_str("contact not found"),
            IdentityError::ContactAlreadyExists => f.write_str("contact already exists"),
            IdentityError::SecureBootFailure => f.write_str("secure boot failure"),
            IdentityError::NetworkUnavailable => f.write_str("network unavailable"),
            IdentityError::NetworkStackError => f.write_str("network stack error"),
            IdentityError::NonceExhausted => f.write_str("nonce space exhausted"),
            IdentityError::CryptoBackend { .. } => f.write_str("cryptographic backend init failed"),
        }
    }
}

impl From<InvalidLength> for IdentityError {
    fn from(source: InvalidLength) -> Self {
        IdentityError::CryptoBackend { source }
    }
}

impl IdentityError {
    /// Возвращает внутреннюю криптографическую ошибку, если она присутствует.
    pub fn crypto_source(&self) -> Option<&InvalidLength> {
        match self {
            IdentityError::CryptoBackend { source } => Some(source),
            _ => None,
        }
    }
}
