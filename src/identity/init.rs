use crate::error::IdentityError;
use crate::identity::entropy::EntropySource;
use crate::identity::hkdf::derive_user_key;
use crate::identity::seed::SeedPhrase;
use crate::identity::types::*;

/// Генерирует новое состояние личности, используя энтропию.
pub fn init_identity<E: EntropySource>(
    entropy: &mut E,
    device_id: DeviceId,
) -> Result<IdentityState, IdentityError> {
    let mut root_bytes = [0u8; 32];
    entropy.fill_bytes(&mut root_bytes)?;
    let root_key = RootKey(root_bytes);
    let derived = derive_user_key(&root_key, &device_id)?;

    Ok(IdentityState {
        root_key,
        device_id,
        sk_user: UserSecret(derived),
    })
}

/// Возвращает пару `(IdentityState, SeedPhrase)` для цифрового рождения.
pub fn init_identity_with_seed<E: EntropySource>(
    entropy: &mut E,
    device_id: DeviceId,
) -> Result<(IdentityState, SeedPhrase), IdentityError> {
    let state = init_identity(entropy, device_id)?;
    let seed = SeedPhrase::from_root(&state.root_key);
    Ok((state, seed))
}

/// Восстанавливает состояние для конкретного `device_id` из seed-фразы.
pub fn recover_identity_from_seed(
    phrase: &SeedPhrase,
    device_id: DeviceId,
) -> Result<IdentityState, IdentityError> {
    let root_key = phrase.recover_root()?;
    IdentityState::from_root(root_key, device_id)
}
