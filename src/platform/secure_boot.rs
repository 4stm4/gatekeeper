use core::cmp::min;
use core::slice;

use sha2::{Digest, Sha256};

use crate::error::IdentityError;

pub const FLASH_BASE: usize = 0x1000_0000;

#[derive(Clone, Copy)]
pub struct FirmwareRegion {
    pub start: usize,
    pub length: usize,
}

impl FirmwareRegion {
    pub const fn rp2040_flash(length: usize) -> Self {
        Self {
            start: FLASH_BASE,
            length,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let mut offset = 0usize;
        while offset < self.length {
            let take = min(256, self.length - offset);
            let ptr = (self.start + offset) as *const u8;
            let chunk = unsafe { slice::from_raw_parts(ptr, take) };
            hasher.update(chunk);
            offset += take;
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

pub struct FirmwareGuard {
    region: FirmwareRegion,
    expected_hash: [u8; 32],
}

impl FirmwareGuard {
    pub const fn new(region: FirmwareRegion, expected_hash: [u8; 32]) -> Self {
        Self {
            region,
            expected_hash,
        }
    }

    pub fn verify(&self) -> Result<(), IdentityError> {
        let actual = self.region.hash();
        if actual == self.expected_hash {
            Ok(())
        } else {
            Err(IdentityError::SecureBootFailure)
        }
    }

    pub fn expected(&self) -> &[u8; 32] {
        &self.expected_hash
    }
}
