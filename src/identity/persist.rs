use crate::error::IdentityError;
use crate::identity::types::{IdentityState, RootKey};
use crate::storage::flash::FlashStorage;
use crate::platform::secure_boot::FirmwareGuard;

pub fn seal_identity(storage: &FlashStorage, state: &IdentityState) -> Result<(), IdentityError> {
    storage.seal(state)
}

pub fn unseal_identity(
    storage: &FlashStorage,
    root_key: &RootKey,
) -> Result<IdentityState, IdentityError> {
    storage.unseal(root_key)
}

pub fn unseal_identity_guarded(
    storage: &FlashStorage,
    root_key: &RootKey,
    guard: &FirmwareGuard,
) -> Result<IdentityState, IdentityError> {
    storage.unseal_with_guard(root_key, guard)
}
