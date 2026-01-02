use crate::error::IdentityError;
use crate::identity::hkdf::derive_user_key;
use crate::identity::keys;
use crate::identity::types::{
    DeviceId, IdentityIdentifier, IdentityState, RootKey, UserPublicKey, UserSecret,
};

#[derive(Clone)]
pub struct DeviceEnrollment {
    pub device_id: DeviceId,
    pub user_secret: UserSecret,
    pub public_key: UserPublicKey,
    pub identifier: IdentityIdentifier,
}

impl DeviceEnrollment {
    pub fn from_root(root: &RootKey, device_id: DeviceId) -> Result<Self, IdentityError> {
        let secret = derive_user_key(root, &device_id)?;
        let user_secret = UserSecret(secret);
        let pk_bytes = keys::public_key_from_secret(&user_secret.0);
        let public_key = UserPublicKey(pk_bytes);
        let identifier = public_key.into_identifier();
        Ok(Self {
            device_id,
            user_secret,
            public_key,
            identifier,
        })
    }
}

impl IdentityState {
    pub fn from_root(root_key: RootKey, device_id: DeviceId) -> Result<Self, IdentityError> {
        let sk_bytes = derive_user_key(&root_key, &device_id)?;
        let state = IdentityState {
            root_key,
            device_id,
            sk_user: UserSecret(sk_bytes),
        };
        Ok(state)
    }

    pub fn enroll_device(&self, device_id: DeviceId) -> Result<DeviceEnrollment, IdentityError> {
        DeviceEnrollment::from_root(&self.root_key, device_id)
    }
}

pub struct RevocationRegistry<const N: usize> {
    ids: [DeviceId; N],
    used: [bool; N],
}

impl<const N: usize> RevocationRegistry<N> {
    pub const fn new() -> Self {
        Self {
            ids: [DeviceId([0u8; 16]); N],
            used: [false; N],
        }
    }

    pub fn revoke(&mut self, id: DeviceId) -> Result<(), IdentityError> {
        if let Some(idx) = self.position(id) {
            self.used[idx] = true;
            return Ok(());
        }
        if let Some(idx) = self.free_slot() {
            self.ids[idx] = id;
            self.used[idx] = true;
            Ok(())
        } else {
            Err(IdentityError::StorageUnavailable)
        }
    }

    pub fn is_revoked(&self, id: &DeviceId) -> bool {
        self.ids
            .iter()
            .zip(self.used.iter())
            .any(|(known, used)| *used && known.0 == id.0)
    }

    fn position(&self, id: DeviceId) -> Option<usize> {
        self.ids
            .iter()
            .zip(self.used.iter())
            .position(|(candidate, used)| *used && candidate.0 == id.0)
    }

    fn free_slot(&mut self) -> Option<usize> {
        self.used.iter().position(|slot| !*slot)
    }
}
