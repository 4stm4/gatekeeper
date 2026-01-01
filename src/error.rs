use core::fmt;

#[derive(Debug)]
pub enum IdentityError {
    EntropyUnavailable,
    DerivationFailed,
    StorageError,
    StorageUnavailable,
    StorageCorrupted,
    StorageMacMismatch,
    StorageVersionMismatch,
    StorageNotFound,
    FlashWriteFailed,
    InvalidChallenge,
    ReplayDetected,
    ChallengeNotRegistered,
    ChallengeStoreFull,
    InvalidPublicKey,
    VerificationFailed,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IdentityError {}
