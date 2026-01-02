use crate::identity::keys;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct RootKey(pub(crate) [u8; 32]);
#[derive(Clone)]
pub struct UserSecret(pub(crate) [u8; 32]);
#[derive(Clone, Copy)]
pub struct DeviceId(pub [u8; 16]);

#[derive(Clone, Copy)]
pub struct UserPublicKey(pub [u8; 32]);
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IdentityIdentifier(pub [u8; 32]);

pub struct IdentityState {
    pub(crate) root_key: RootKey,
    pub(crate) device_id: DeviceId,
    pub(crate) sk_user: UserSecret,
}

impl IdentityState {
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn public_key(&self) -> UserPublicKey {
        let bytes = keys::public_key_from_secret(&self.sk_user.0);
        UserPublicKey(bytes)
    }

    pub fn identifier(&self) -> IdentityIdentifier {
        self.public_key().into_identifier()
    }
}

impl UserPublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn into_identifier(self) -> IdentityIdentifier {
        IdentityIdentifier::from_public_key(&self.0)
    }
}

impl IdentityIdentifier {
    pub fn from_public_key(pk: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"zk-gatekeeper-identity");
        hasher.update(pk);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        IdentityIdentifier(out)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn matches(&self, pk: &[u8; 32]) -> bool {
        let derived = IdentityIdentifier::from_public_key(pk);
        derived.0 == self.0
    }
}
