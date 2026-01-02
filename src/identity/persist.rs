use crate::error::IdentityError;
use crate::identity::types::{IdentityState, RootKey};
use crate::platform::secure_boot::FirmwareGuard;
use crate::storage::flash::FlashStorage;

/// Обёртка над `FlashStorage::seal`.
pub fn seal_identity(storage: &FlashStorage, state: &IdentityState) -> Result<(), IdentityError> {
    storage.seal(state)
}

/// Вспомогательный метод для `FlashStorage::unseal`.
pub fn unseal_identity(
    storage: &FlashStorage,
    root_key: &RootKey,
) -> Result<IdentityState, IdentityError> {
    storage.unseal(root_key)
}

/// Как и `unseal_identity`, но с проверкой хэша прошивки.
pub fn unseal_identity_guarded(
    storage: &FlashStorage,
    root_key: &RootKey,
    guard: &FirmwareGuard,
) -> Result<IdentityState, IdentityError> {
    storage.unseal_with_guard(root_key, guard)
}
