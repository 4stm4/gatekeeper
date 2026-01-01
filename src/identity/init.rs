use crate::error::IdentityError;
use crate::identity::entropy::EntropySource;
use crate::identity::hkdf::derive_user_key;
use crate::identity::types::*;

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
