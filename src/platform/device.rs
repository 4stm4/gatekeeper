use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::IdentityError;

use super::rom;

pub const DEVICE_UID_LEN: usize = 8;

#[derive(Clone, Copy)]
pub struct DeviceUid {
    bytes: [u8; DEVICE_UID_LEN],
}

pub struct DeviceBindingKey {
    bytes: [u8; 32],
}

impl DeviceUid {
    pub fn new() -> Result<Self, IdentityError> {
        let mut raw = [0u8; DEVICE_UID_LEN];
        unsafe { rom::flash_unique_id(&mut raw) };
        if raw.iter().all(|b| *b == 0) {
            return Err(IdentityError::StorageUnavailable);
        }
        Ok(Self { bytes: raw })
    }

    pub fn as_bytes(&self) -> &[u8; DEVICE_UID_LEN] {
        &self.bytes
    }
}

impl DeviceBindingKey {
    pub fn new() -> Result<Self, IdentityError> {
        let uid = DeviceUid::new()?;
        Ok(Self::from_uid(&uid))
    }

    pub fn from_uid(uid: &DeviceUid) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"zk-gatekeeper-device-binding");
        hasher.update(uid.as_bytes());

        let mut reversed = *uid.as_bytes();
        reversed.reverse();
        hasher.update(&reversed);

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        reversed.fill(0);
        Self { bytes: out }
    }

    pub fn mix_into(&self, enc_key: &mut [u8; 32], mac_key: &mut [u8; 32]) {
        for (dst, mask) in enc_key.iter_mut().zip(self.bytes.iter()) {
            *dst ^= *mask;
        }
        for (idx, dst) in mac_key.iter_mut().enumerate() {
            let mask = self.bytes[(idx + 11) & 31].rotate_left((idx as u32) & 7);
            *dst ^= mask;
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for DeviceBindingKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
