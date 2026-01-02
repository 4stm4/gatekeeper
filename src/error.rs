use hmac::digest::InvalidLength;
use thiserror::Error;

/// Ошибки верхнего уровня, возникающие во всех подсистемах Gatekeeper.
#[derive(Debug, Error, Clone, Copy)]
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
    /// Инициализация криптографического примитива завершилась ошибкой.
    #[error("cryptographic backend init failed")]
    CryptoBackend {
        /// Источник ошибки из криптобиблиотеки.
        #[source]
        source: InvalidLength,
    },
}

impl From<InvalidLength> for IdentityError {
    fn from(source: InvalidLength) -> Self {
        IdentityError::CryptoBackend { source }
    }
}
