use core::cmp::min;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::IdentityError;

pub trait EntropySource {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError>;
}

pub struct DummyEntropy;

impl EntropySource for DummyEntropy {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        Ok(())
    }
}

pub struct MockEntropy<'a> {
    data: &'a [u8],
    cursor: usize,
    error: Option<IdentityError>,
}

impl<'a> MockEntropy<'a> {
    pub const fn from_slice(data: &'a [u8]) -> Self {
        Self {
            data,
            cursor: 0,
            error: None,
        }
    }

    pub const fn unavailable() -> Self {
        Self::with_error(IdentityError::EntropyUnavailable)
    }

    pub const fn with_error(error: IdentityError) -> Self {
        Self {
            data: &[],
            cursor: 0,
            error: Some(error),
        }
    }
}

impl<'a> EntropySource for MockEntropy<'a> {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        if let Some(err) = self.error {
            return Err(err);
        }

        if self.data.is_empty() {
            return Err(IdentityError::EntropyUnavailable);
        }

        for (i, byte) in out.iter_mut().enumerate() {
            let idx = (self.cursor + i) % self.data.len();
            *byte = self.data[idx];
        }
        self.cursor = (self.cursor + out.len()) % self.data.len();
        Ok(())
    }
}

pub struct PseudoEntropy {
    state: [u8; 32],
    counter: u64,
}

impl PseudoEntropy {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            state: seed,
            counter: 0,
        }
    }
}

impl EntropySource for PseudoEntropy {
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        let mut produced = 0usize;
        while produced < out.len() {
            let mut hasher = Sha256::new();
            hasher.update(b"zk-gatekeeper-pseudo-entropy");
            hasher.update(&self.state);
            hasher.update(&self.counter.to_le_bytes());
            let digest = hasher.finalize();
            let mut block = [0u8; 32];
            block.copy_from_slice(&digest);
            let take = min(block.len(), out.len() - produced);
            out[produced..produced + take].copy_from_slice(&block[..take]);
            self.state.copy_from_slice(&block);
            self.counter = self.counter.wrapping_add(1);
            block.zeroize();
            produced += take;
        }
        Ok(())
    }
}

impl Drop for PseudoEntropy {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

pub struct FallbackEntropy<P, S> {
    primary: P,
    secondary: S,
}

impl<P, S> FallbackEntropy<P, S> {
    pub const fn new(primary: P, secondary: S) -> Self {
        Self { primary, secondary }
    }
}

impl<P, S> EntropySource for FallbackEntropy<P, S>
where
    P: EntropySource,
    S: EntropySource,
{
    fn fill_bytes(&mut self, out: &mut [u8]) -> Result<(), IdentityError> {
        match self.primary.fill_bytes(out) {
            Ok(()) => Ok(()),
            Err(IdentityError::EntropyUnavailable) => self.secondary.fill_bytes(out),
            Err(err) => Err(err),
        }
    }
}
